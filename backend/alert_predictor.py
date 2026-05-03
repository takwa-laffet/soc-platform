import numpy as np
import pandas as pd
from config import CONFIDENCE_THRESHOLD
import ml_loader


# ── Feature Extraction ──────────────────────────────────

def _extract_flat(alert, feature_list):
    """Extract a dict of features from a nested Wazuh alert."""
    row = {}
    for feat in feature_list:
        parts = feat.replace(".", "__").split("__") if "." in feat else feat.split("__")
        # walk into nested dict
        val = alert
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p, 0)
            else:
                val = 0
                break
        # convert to numeric
        if isinstance(val, (int, float)):
            row[feat] = val
        elif isinstance(val, str):
            try:
                row[feat] = float(val)
            except ValueError:
                row[feat] = 0
        elif isinstance(val, list):
            row[feat] = len(val)
        else:
            row[feat] = 0
    return row


def _get_path(alert, *paths, default=""):
    """Read value from nested dict paths or flattened dotted keys."""
    for path in paths:
        # Try flattened key first (e.g., "_source.agent.ip" / "agent.ip").
        if path in alert:
            val = alert.get(path)
            if val not in (None, ""):
                return val

        # Try nested traversal (e.g., "agent.ip").
        parts = path.split(".")
        cur = alert
        for p in parts:
            if isinstance(cur, dict):
                cur = cur.get(p)
            else:
                cur = None
                break
        if cur not in (None, ""):
            return cur

    return default


def _has_mitre(alert):
    """Check if alert has MITRE tactic info."""
    rule = alert.get("rule", {})
    mitre = rule.get("mitre", {})
    tactic = mitre.get("tactic", None)
    if tactic and tactic != "" and tactic != []:
        return True
    return False


# ── Hybrid Override ─────────────────────────────────────

def _hybrid_override(severity, confidence, rule_level):
    """Apply rule-level based override logic."""
    level = rule_level if isinstance(rule_level, (int, float)) else 0

    # Low confidence → map from rule_level
    if confidence < CONFIDENCE_THRESHOLD:
        if level >= 12:
            return "Critical"
        elif level >= 10:
            return "High"
        elif level >= 7:
            return "Medium"
        elif level >= 4:
            return "Low"
        else:
            return "Normal"

    # High confidence overrides
    if level <= 3 and severity in ("Critical", "High"):
        return "Normal"
    if level <= 5 and severity in ("Critical", "High"):
        return "Low"
    if level >= 10 and severity in ("Normal", "Low"):
        return "High"

    return severity


def _rule_level_severity(level):
    """Fallback severity from rule level."""
    if level >= 12:
        return "Critical"
    elif level >= 10:
        return "High"
    elif level >= 7:
        return "Medium"
    elif level >= 4:
        return "Low"
    return "Normal"


def _soc_level_context(rule_level):
    """Map Wazuh rule level to SOC triage tiers and operational guidance."""
    level = rule_level if isinstance(rule_level, (int, float)) else 0

    if level <= 0:
        return {
            "soc_level_tier": "L1",
            "soc_level_label": "Low",
            "soc_level_range": "0-4",
            "soc_level_band": "Level 0 (Ignored)",
            "soc_level_description": "Very common logs for statistics; no action required.",
            "soc_immediate_action": False,
        }
    if level <= 4:
        return {
            "soc_level_tier": "L1",
            "soc_level_label": "Low",
            "soc_level_range": "0-4",
            "soc_level_band": "Levels 2-3 (Routine)",
            "soc_level_description": "Routine events or minor anomalies; monitor trends only.",
            "soc_immediate_action": False,
        }
    if level <= 7:
        return {
            "soc_level_tier": "L2",
            "soc_level_label": "Medium",
            "soc_level_range": "5-9",
            "soc_level_band": "Levels 5-7 (Monitor)",
            "soc_level_description": "System errors or suspicious behavior that requires monitoring.",
            "soc_immediate_action": False,
        }
    if level <= 9:
        return {
            "soc_level_tier": "L2",
            "soc_level_label": "Medium",
            "soc_level_range": "5-9",
            "soc_level_band": "Levels 8-9 (Suspicious)",
            "soc_level_description": "Likely probes or known attack attempts; investigate quickly.",
            "soc_immediate_action": False,
        }
    if level <= 12:
        return {
            "soc_level_tier": "L3",
            "soc_level_label": "High",
            "soc_level_range": "10-15",
            "soc_level_band": "Levels 10-12 (Confirmed Attack)",
            "soc_level_description": "Confirmed exploit activity; immediate intervention required.",
            "soc_immediate_action": True,
        }
    return {
        "soc_level_tier": "L3",
        "soc_level_label": "High",
        "soc_level_range": "10-15",
        "soc_level_band": "Levels 13-15 (Critical Threat)",
        "soc_level_description": "Critical compromise risk (ransomware/root breach/data breach).",
        "soc_immediate_action": True,
    }


# ── Batch Prediction ────────────────────────────────────

def predict_alerts(alerts):
    """
    Vectorized batch prediction for a list of Wazuh alerts.
    Returns list of result dicts.
    """
    if not alerts:
        return []

    mitre_feats = ml_loader.mitre_features()
    behav_feats = ml_loader.behavioral_features()
    attack_feats = ml_loader.attack_features()

    m_model = ml_loader.mitre_model()
    b_model = ml_loader.behavioral_model()
    a_model = ml_loader.attack_model()

    sev_le = ml_loader.alerts_le()
    atk_le = ml_loader.attack_le()

    # ── Split alerts into MITRE vs Behavioral ───────────
    mitre_indices = []
    behav_indices = []
    for i, alert in enumerate(alerts):
        if _has_mitre(alert):
            mitre_indices.append(i)
        else:
            behav_indices.append(i)

    results = [None] * len(alerts)

    # ── Batch predict MITRE alerts ──────────────────────
    if mitre_indices:
        rows = [_extract_flat(alerts[i], mitre_feats) for i in mitre_indices]
        df = pd.DataFrame(rows, columns=mitre_feats).fillna(0)
        probas = m_model.predict_proba(df)
        preds = np.argmax(probas, axis=1)
        confs = np.max(probas, axis=1) * 100

        for j, idx in enumerate(mitre_indices):
            sev = sev_le.inverse_transform([preds[j]])[0]
            results[idx] = {
                "model_used": "mitre",
                "severity_pred": sev,
                "confidence": round(float(confs[j]), 2),
            }

    # ── Batch predict Behavioral alerts ─────────────────
    if behav_indices:
        rows = [_extract_flat(alerts[i], behav_feats) for i in behav_indices]
        df = pd.DataFrame(rows, columns=behav_feats).fillna(0)
        probas = b_model.predict_proba(df)
        preds = np.argmax(probas, axis=1)
        confs = np.max(probas, axis=1) * 100

        for j, idx in enumerate(behav_indices):
            sev = sev_le.inverse_transform([preds[j]])[0]
            results[idx] = {
                "model_used": "behavioral",
                "severity_pred": sev,
                "confidence": round(float(confs[j]), 2),
            }

    # ── Batch predict Attack Category (all alerts) ──────
    atk_rows = [_extract_flat(alerts[i], attack_feats) for i in range(len(alerts))]
    atk_df = pd.DataFrame(atk_rows, columns=attack_feats).fillna(0)
    atk_probas = a_model.predict_proba(atk_df)
    atk_preds = np.argmax(atk_probas, axis=1)
    atk_confs = np.max(atk_probas, axis=1) * 100

    # ── Assemble final results ──────────────────────────
    for i, alert in enumerate(alerts):
        rule = alert.get("rule", {})
        rule_level = rule.get("level", 0)
        if isinstance(rule_level, str):
            try:
                rule_level = int(rule_level)
            except ValueError:
                rule_level = 0

        r = results[i]
        raw_sev = r["severity_pred"]
        conf = r["confidence"]
        final_sev = _hybrid_override(raw_sev, conf, rule_level)

        attack_cat = atk_le.inverse_transform([atk_preds[i]])[0]

        r["severity_final"] = final_sev
        r["hybrid_override"] = final_sev != raw_sev
        r["needs_review"] = conf < CONFIDENCE_THRESHOLD
        r["attack_category"] = attack_cat
        r["attack_confidence"] = round(float(atk_confs[i]), 2)
        r["rule_level"] = rule_level
        r.update(_soc_level_context(rule_level))
        r["rule_id"] = _get_path(alert, "rule.id", "_source.rule.id", default=rule.get("id", ""))
        r["rule_description"] = _get_path(alert, "rule.description", "_source.rule.description", default=rule.get("description", ""))
        r["title"] = r["rule_description"] or "Security Alert"
        r["agent_name"] = _get_path(alert, "agent.name", "_source.agent.name")
        r["agent_id"] = _get_path(alert, "agent.id", "_source.agent.id")
        r["agent_ip"] = _get_path(alert, "agent.ip", "_source.agent.ip")
        r["source_ip"] = _get_path(alert, "data.srcip", "data.src_ip", "_source.data.srcip", "_source.data.src_ip")
        r["timestamp"] = _get_path(alert, "timestamp", "@timestamp", "_source.@timestamp")
        r["decoder_name"] = _get_path(alert, "decoder.name", "_source.decoder.name")
        r["firedtimes"] = rule.get("firedtimes", 0)
        r["alert_id"] = alert.get("id", "")
        r["source_tool"] = _get_path(alert, "source_tool", "source", "_source.source_tool", default="")

        # Preserve file/path context for syscheck-style rules in the persisted alert description.
        file_path = _get_path(
            alert,
            "syscheck.path",
            "_source.syscheck.path",
            "syscheck.file",
            "_source.syscheck.file",
            "data.path",
            "_source.data.path",
            default="",
        )
        full_log = _get_path(alert, "full_log", "_source.full_log", default="")
        if file_path:
            r["description"] = f"{r['rule_description']} | path={file_path}" if r["rule_description"] else f"path={file_path}"
        elif full_log:
            r["description"] = full_log
        else:
            r["description"] = r["rule_description"]

        # MITRE info
        mitre = rule.get("mitre", {})
        r["mitre_tactic"] = mitre.get("tactic", [])
        r["mitre_technique"] = mitre.get("technique", [])
        r["mitre_id"] = mitre.get("id", [])

    return results


def get_summary(results):
    """Generate severity_summary and category_summary from results."""
    sev_summary = {}
    cat_summary = {}
    soc_level_summary = {}
    needs_review_count = 0

    for r in results:
        s = r.get("severity_final", "Unknown")
        sev_summary[s] = sev_summary.get(s, 0) + 1

        c = r.get("attack_category", "Unknown")
        cat_summary[c] = cat_summary.get(c, 0) + 1

        soc_level = r.get("soc_level_tier", "Unknown")
        soc_level_summary[soc_level] = soc_level_summary.get(soc_level, 0) + 1

        if r.get("needs_review"):
            needs_review_count += 1

    return {
        "total": len(results),
        "severity_summary": sev_summary,
        "category_summary": cat_summary,
        "soc_level_summary": soc_level_summary,
        "needs_review": needs_review_count,
    }
