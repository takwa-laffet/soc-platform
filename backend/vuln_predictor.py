import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from config import CONFIDENCE_THRESHOLD
import ml_loader


def _extract_vuln_features(vuln, feature_list):
    """Extract structured features from a vulnerability/CVE object."""
    row = {}
    for feat in feature_list:
        val = vuln.get(feat, 0)
        if isinstance(val, (int, float)):
            row[feat] = val
        elif isinstance(val, str):
            try:
                row[feat] = float(val)
            except ValueError:
                row[feat] = 0
        else:
            row[feat] = 0
    return row


def _get_description(vuln):
    """Extract description text from CVE object."""
    return vuln.get("description", vuln.get("desc", vuln.get("summary", "")))


def predict_vulnerabilities(vulns):
    """
    Batch predict using 2 models:
      1. Vulnerability Priority Model (xgb_vuln_model)
      2. Attack Type Description Model (xgb_attack_type_desc + TF-IDF + CVSS)
    """
    if not vulns:
        return {"results": [], "models_used": []}

    models_used = []

    # ── Model 1: Vulnerability Priority ─────────────────
    vuln_feats = ml_loader.vuln_features()
    vuln_model = ml_loader.vuln_model()
    vuln_le = ml_loader.vuln_le()

    rows = [_extract_vuln_features(v, vuln_feats) for v in vulns]
    df = pd.DataFrame(rows, columns=vuln_feats).fillna(0)

    probas = vuln_model.predict_proba(df)
    preds = np.argmax(probas, axis=1)
    confs = np.max(probas, axis=1) * 100
    models_used.append("vuln_priority")

    results = []
    for i, vuln in enumerate(vulns):
        priority = vuln_le.inverse_transform([preds[i]])[0]
        conf = round(float(confs[i]), 2)
        results.append({
            "cve_id": vuln.get("cve_id", vuln.get("CVE_ID", vuln.get("id", ""))),
            "priority": priority,
            "priority_confidence": conf,
            "needs_review": conf < CONFIDENCE_THRESHOLD,
            "description": _get_description(vuln)[:200],
        })

    # ── Model 2: Attack Type (TF-IDF + CVSS features) ──
    try:
        atk_model = ml_loader.attack_type_model()
        tfidf = ml_loader.tfidf_vectorizer()
        atk_le = ml_loader.attack_type_le()
        atk_feats = ml_loader.attack_type_features()
        feat_enc = ml_loader.attack_type_feat_enc()

        # TF-IDF on descriptions
        descriptions = [_get_description(v) for v in vulns]
        tfidf_matrix = tfidf.transform(descriptions)

        # Structured features (CVSS scores etc.)
        struct_rows = []
        for v in vulns:
            row = {}
            for feat in atk_feats:
                val = v.get(feat, 0)
                if feat in feat_enc:
                    le = feat_enc[feat]
                    if isinstance(val, str):
                        try:
                            val = le.transform([val])[0]
                        except ValueError:
                            val = 0
                    else:
                        val = 0
                elif isinstance(val, (int, float)):
                    pass
                elif isinstance(val, str):
                    try:
                        val = float(val)
                    except ValueError:
                        val = 0
                else:
                    val = 0
                row[feat] = val
            struct_rows.append(row)

        struct_df = pd.DataFrame(struct_rows, columns=atk_feats).fillna(0)

        # Combine: TF-IDF + structured
        combined = hstack([tfidf_matrix, csr_matrix(struct_df.values)])

        atk_probas = atk_model.predict_proba(combined)
        atk_preds = np.argmax(atk_probas, axis=1)
        atk_confs = np.max(atk_probas, axis=1) * 100

        for i in range(len(vulns)):
            results[i]["attack_type"] = atk_le.inverse_transform([atk_preds[i]])[0]
            results[i]["attack_type_confidence"] = round(float(atk_confs[i]), 2)

        models_used.append("attack_type_desc")

    except Exception as e:
        print(f"Attack Type model skipped: {e}")
        for r in results:
            r["attack_type"] = "N/A"
            r["attack_type_confidence"] = 0

    return {"results": results, "models_used": models_used}
