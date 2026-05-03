from flask import request, jsonify
from alert_predictor import predict_alerts, get_summary
from vuln_predictor import predict_vulnerabilities
import supabase_client


def _detect_type(items):
    """
    Auto-detect if data is alerts or vulnerabilities.
    Returns 'alerts', 'vulnerabilities', or 'unknown'.
    """
    if not items:
        return "unknown"

    sample = items[0] if isinstance(items, list) else items

    # Vulnerability indicators
    vuln_keys = {"cve_id", "CVE_ID", "cvss_base_score", "epss_score",
                 "cvss_exploitability_score", "cisa_kev", "vendor", "product"}
    if any(k in sample for k in vuln_keys):
        return "vulnerabilities"

    # Alert indicators
    alert_keys = {"rule", "agent", "decoder", "full_log", "predecoder",
                  "manager", "location", "input"}
    if any(k in sample for k in alert_keys):
        return "alerts"

    return "unknown"


def register_routes(app):

    # ── Health ──────────────────────────────────────────
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok",
            "supabase": supabase_client.is_enabled(),
            "models": {
                "alert_severity": ["mitre_classifier", "behavioral_classifier"],
                "alert_category": ["attack_category"],
                "vuln_priority": ["vuln_priority"],
                "vuln_attack_type": ["attack_type_desc (TF-IDF + CVSS)"],
            }
        })

    # ── Smart Auto-Detect Endpoint ──────────────────────
    @app.route("/api/predict/auto", methods=["POST"])
    def auto_predict():
        """
        Smart endpoint: auto-detects file type and routes to correct models.
        - Alerts → 3 models (MITRE/Behavioral + Attack Category)
        - Vulns  → 2 models (Priority + Attack Type)
        """
        data = request.get_json(force=True)

        if isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = data
        else:
            return jsonify({"error": "Invalid input — send object or array"}), 400

        file_type = _detect_type(items)

        if file_type == "alerts":
            results = predict_alerts(items)
            summary = get_summary(results)
            models_used = _get_alert_models_used(results)

            supabase_client.save_alerts(results)
            low_conf = [r for r in results if r.get("needs_review")]
            if low_conf:
                supabase_client.save_low_confidence(low_conf)

            return jsonify({
                "type": "alerts",
                "results": results,
                "summary": summary,
                "models_used": models_used,
            })

        elif file_type == "vulnerabilities":
            vuln_data = predict_vulnerabilities(items)
            supabase_client.save_vulnerabilities(vuln_data["results"])

            return jsonify({
                "type": "vulnerabilities",
                "results": vuln_data["results"],
                "models_used": vuln_data["models_used"],
                "summary": {
                    "total": len(vuln_data["results"]),
                    "needs_review": sum(1 for r in vuln_data["results"] if r.get("needs_review")),
                },
            })

        else:
            return jsonify({"error": "Cannot detect file type. Expected Wazuh alerts or CVE data."}), 400

    # ── Alert Prediction (direct) ───────────────────────
    @app.route("/api/alerts/predict", methods=["POST"])
    def alerts_predict():
        data = request.get_json(force=True)

        if isinstance(data, dict):
            alerts = [data]
        elif isinstance(data, list):
            alerts = data
        else:
            return jsonify({"error": "Invalid input — send object or array"}), 400

        results = predict_alerts(alerts)
        summary = get_summary(results)
        models_used = _get_alert_models_used(results)

        supabase_client.save_alerts(results)
        low_conf = [r for r in results if r.get("needs_review")]
        if low_conf:
            supabase_client.save_low_confidence(low_conf)

        return jsonify({
            "type": "alerts",
            "results": results,
            "summary": summary,
            "models_used": models_used,
        })

    # ── Vulnerability Prediction (direct) ───────────────
    @app.route("/api/vulnerabilities/predict", methods=["POST"])
    def vuln_predict():
        data = request.get_json(force=True)

        if isinstance(data, dict):
            vulns = [data]
        elif isinstance(data, list):
            vulns = data
        else:
            return jsonify({"error": "Invalid input"}), 400

        vuln_data = predict_vulnerabilities(vulns)
        supabase_client.save_vulnerabilities(vuln_data["results"])

        return jsonify({
            "type": "vulnerabilities",
            "results": vuln_data["results"],
            "models_used": vuln_data["models_used"],
        })

    # ── Dashboard Stats ─────────────────────────────────
    @app.route("/api/dashboard/stats", methods=["GET"])
    def dashboard_stats():
        stats = supabase_client.get_dashboard_stats()
        return jsonify(stats)

    # ── Low Confidence Items ────────────────────────────
    @app.route("/api/dashboard/low-confidence", methods=["GET"])
    def low_confidence():
        items = supabase_client.get_low_confidence()
        return jsonify({"items": items})

    # ── Threat Intel Lookup ─────────────────────────────
    @app.route("/api/threat-intel/lookup", methods=["POST"])
    def threat_intel_lookup():
        data = request.get_json(force=True)
        ip = data.get("ip", "")
        if not ip:
            return jsonify({"error": "IP required"}), 400

        return jsonify({
            "ip": ip,
            "found": False,
            "source": None,
            "details": "Threat intel integration pending",
        })

    # ── Suricata Alerts ─────────────────────────────────
    @app.route("/api/suricata/alerts", methods=["GET"])
    def suricata_alerts():
        return jsonify({"alerts": []})

    # ── Models Info ─────────────────────────────────────
    @app.route("/api/models/info", methods=["GET"])
    def models_info():
        """Return all model metadata for Dashboard display."""
        import ml_loader
        thresholds = ml_loader.confidence_thresholds()
        m_info = ml_loader.models_info()
        v_info = ml_loader.vuln_model_info()
        a_info = ml_loader.attack_model_info()

        return jsonify({
            "models": [
                {
                    "name": "MITRE Alert Classifier",
                    "file": "xgb_mitre_model.pkl",
                    "accuracy": m_info.get("mitre_model", {}).get("accuracy", 0),
                    "features": m_info.get("mitre_model", {}).get("features", []),
                    "use_case": m_info.get("mitre_model", {}).get("use_case", ""),
                    "classes": ["Critical", "High", "Medium", "Low", "Normal"],
                    "type": "alert",
                },
                {
                    "name": "Behavioral Alert Classifier",
                    "file": "xgb_behavioral_model.pkl",
                    "accuracy": m_info.get("behavioral_model", {}).get("accuracy", 0),
                    "features": m_info.get("behavioral_model", {}).get("features", []),
                    "use_case": m_info.get("behavioral_model", {}).get("use_case", ""),
                    "classes": ["Critical", "High", "Medium", "Low", "Normal"],
                    "type": "alert",
                },
                {
                    "name": a_info.get("model_name", "Attack Category Classifier"),
                    "file": "xgb_attack_model.pkl",
                    "accuracy": a_info.get("test_accuracy", ""),
                    "features": a_info.get("features", []),
                    "use_case": "Classify attack type per alert",
                    "classes": a_info.get("classes", []),
                    "smote": a_info.get("smote", False),
                    "type": "alert",
                },
                {
                    "name": v_info.get("model_name", "Vulnerability Prioritization"),
                    "file": "xgb_vuln_model.pkl",
                    "accuracy": v_info.get("test_accuracy", ""),
                    "features": v_info.get("features", []),
                    "use_case": "Prioritize vulnerabilities",
                    "classes": v_info.get("classes", []),
                    "smote": v_info.get("smote", False),
                    "type": "vulnerability",
                },
                {
                    "name": "Attack Type Classifier (TF-IDF + CVSS)",
                    "file": "xgb_attack_type_desc_model.pkl",
                    "accuracy": "86.53%",
                    "features": ["TF-IDF (description)", "CVSS features"],
                    "use_case": "Classify attack type from description",
                    "classes": [],
                    "type": "vulnerability",
                },
            ],
            "confidence_thresholds": thresholds,
            "total_files": 20,
        })


def _get_alert_models_used(results):
    """Extract which models were actually used from results."""
    models = set()
    for r in results:
        m = r.get("model_used", "")
        if m:
            models.add(m)
        if r.get("attack_category"):
            models.add("attack_category")
    return list(models)
