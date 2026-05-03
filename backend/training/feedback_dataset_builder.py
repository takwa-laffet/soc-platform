from datetime import datetime

import pandas as pd

import ml_loader
import supabase_client


_TEXT_TRUE = ("true", "1", "yes", "on")


def _to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in _TEXT_TRUE


def _to_int(value, default=0):
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except Exception:
        return default


def _hour_from_alert(alert):
    for key in ("created_at", "event_timestamp", "timestamp"):
        value = alert.get(key)
        if not value:
            continue
        try:
            text = str(value).replace("Z", "+00:00")
            return datetime.fromisoformat(text).hour
        except Exception:
            continue
    return 0


def _contains_any(text, words):
    if not text:
        return False
    lowered = str(text).lower()
    return any(w in lowered for w in words)


def _extract_attack_features(alert):
    description = alert.get("rule_description") or alert.get("description") or ""
    decoder = alert.get("decoder_name") or ""

    fired = _to_int(alert.get("firedtimes"), default=0)
    level = _to_int(alert.get("rule_level"), default=0)

    is_auth = _contains_any(description, ["auth", "login", "password", "credential", "ssh"])
    is_web = _contains_any(description, ["http", "web", "xss", "sql", "path traversal", "csrf"])
    is_audit = _contains_any(decoder, ["audit"])
    is_syscheck = _contains_any(decoder, ["syscheck", "integrity", "fim"])

    return {
        "hour_of_day": _hour_from_alert(alert),
        "rule.firedtimes": fired,
        "rule.level": level,
        # Inference path currently coerces categorical strings to numeric 0.
        "agent.name": 0,
        "decoder.name": 0,
        "is_auth_failure": 1 if is_auth else 0,
        "is_web_attack": 1 if is_web else 0,
        "is_audit": 1 if is_audit else 0,
        "is_syscheck": 1 if is_syscheck else 0,
        "event_frequency_per_ip": fired,
        "consecutive_failures": fired if is_auth else 0,
    }


def _target_label(feedback_row):
    if _to_bool(feedback_row.get("is_wrong")):
        return (feedback_row.get("correct_label") or "").strip()
    return (feedback_row.get("ml_prediction") or "").strip()


def build_attack_feedback_dataset(limit=5000):
    """Build (X, y) from analyst feedback rows for attack-category retraining."""
    rows = supabase_client.get_feedback_rows(limit=limit, model_name="attack_category")
    if not rows:
        return pd.DataFrame(), pd.Series(dtype="int64"), {"rows": 0, "used": 0, "dropped": 0}

    attack_le = ml_loader.attack_le()
    feature_cols = ml_loader.attack_features()

    x_rows = []
    y_rows = []
    dropped = 0

    for fb in rows:
        label = _target_label(fb)
        if not label:
            dropped += 1
            continue

        try:
            encoded = int(attack_le.transform([label])[0])
        except Exception:
            dropped += 1
            continue

        alert_id = fb.get("alert_id")
        alert = supabase_client.get_alert_by_id(alert_id)
        if not alert:
            dropped += 1
            continue

        feats = _extract_attack_features(alert)
        x_rows.append({k: feats.get(k, 0) for k in feature_cols})
        y_rows.append(encoded)

    if not x_rows:
        return pd.DataFrame(), pd.Series(dtype="int64"), {
            "rows": len(rows),
            "used": 0,
            "dropped": dropped,
        }

    X = pd.DataFrame(x_rows, columns=feature_cols).fillna(0)
    y = pd.Series(y_rows, dtype="int64")

    meta = {
        "rows": len(rows),
        "used": len(y_rows),
        "dropped": dropped,
    }
    return X, y, meta
