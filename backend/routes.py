import json
import logging
from datetime import datetime, timezone
from flask import request, jsonify, g, send_file, Response
from functools import wraps
from flask_jwt_extended import jwt_required, get_jwt, verify_jwt_in_request
from extensions import limiter
from alert_predictor import predict_alerts, get_summary
from vuln_predictor import predict_vulnerabilities
from threat_intel import enrich_log, extract_indicators, enrich_indicator
import supabase_client
from integration_api_keys import validate_api_key
from services.ollama_report_service import generate_soc_report, generate_rapport_with_qwen
from threat_intel import enrich_log, extract_indicators, enrich_indicator, extract_indicators


logger = logging.getLogger(__name__)


def _detect_type(items):
    """
    Auto-detect if data is alerts or vulnerabilities.
    Returns 'alerts', 'vulnerabilities', or 'unknown'.
    """
    if not items:
        return "unknown"

    sample = items[0] if isinstance(items, list) else items

    if not isinstance(sample, dict):
        return "unknown"

    sample_keys = set(sample.keys())

    # Vulnerability indicators
    vuln_keys = {"cve_id", "CVE_ID", "cvss_base_score", "epss_score",
                 "cvss_exploitability_score", "cisa_kev", "vendor", "product"}
    if any(k in sample_keys for k in vuln_keys):
        return "vulnerabilities"

    # Alert indicators
    alert_keys = {"rule", "agent", "decoder", "syscheck", "event", "full_log", "predecoder",
                  "manager", "location", "input", "changed_attributes"}
    flattened_alert_keys = {
        "rule.level", "rule.id", "rule.description", "rule.firedtimes",
        "agent.name", "agent.id", "agent.ip",
        "decoder.name", "full_log", "predecoder", "manager",
        "location", "input", "timestamp", "@timestamp",
        "data.srcip", "data.src_ip", "_source.rule.id", "_source.agent.ip",
    }
    if any(k in sample_keys for k in alert_keys | flattened_alert_keys):
        return "alerts"

    return "unknown"


def _unwrap_items(payload):
    """Normalize common n8n payload wrappers into a list of records."""
    if payload is None:
        return []

    if isinstance(payload, str):
        text = payload.strip()
        if not text:
            return []
        try:
            payload = json.loads(text)
        except Exception:
            return []

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        # Direct record.
        alert_keys = {"rule", "agent", "decoder", "syscheck", "event", "full_log", "predecoder", "manager", "location", "input", "changed_attributes"}
        flattened_alert_keys = {
            "rule.level", "rule.id", "rule.description", "rule.firedtimes",
            "agent.name", "agent.id", "agent.ip",
            "decoder.name", "full_log", "predecoder", "manager",
            "location", "input", "timestamp", "@timestamp",
            "data.srcip", "data.src_ip", "_source.rule.id", "_source.agent.ip",
        }
        vuln_keys = {"cve_id", "CVE_ID", "cvss_base_score", "epss_score", "cvss_exploitability_score", "cisa_kev", "vendor", "product"}
        if any(k in payload for k in alert_keys | flattened_alert_keys | vuln_keys):
            return [payload]

        # Common n8n/body wrappers.
        for key in ("body", "json", "data", "payload", "alert"):
            value = payload.get(key)
            if isinstance(value, str):
                nested = _unwrap_items(value)
                if nested:
                    return nested
            if isinstance(value, dict):
                if any(k in value for k in alert_keys | flattened_alert_keys | vuln_keys):
                    return [value]
                nested = _unwrap_items(value)
                if nested:
                    return nested
            elif isinstance(value, list):
                nested = [item for item in value if isinstance(item, dict)]
                if nested:
                    return nested

        for key in ("alerts", "items", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                nested = [item for item in value if isinstance(item, dict)]
                if nested:
                    return nested

    return []


def _coerce_json_payload():
    """Read JSON from normal request bodies, raw text bodies, or JSON strings."""
    data = request.get_json(silent=True)
    if data is not None:
        return data

    raw_body = (request.get_data(as_text=True) or "").strip()
    if not raw_body:
        return None

    # Try direct JSON parse first
    try:
        return json.loads(raw_body)
    except Exception:
        pass

    # If raw_body looks like a stringified Python/JS object (e.g., starts with {{ or {), try to eval/parse it
    # This handles n8n expressions that evaluate to objects
    if raw_body.startswith(('{', '[', '"')):
        # Try once more with different parsing approach
        try:
            return json.loads(raw_body)
        except Exception:
            # Return as-is; let unwrap handle it
            return raw_body
    
    return raw_body


def register_routes(app):
    auto_response_feed = []
    max_auto_response_feed = 300

    def _source_label():
        if getattr(g, "api_key_auth", None):
            return "n8n"
        return "dashboard"

    def _record_auto_response(response_type, results, summary, models_used):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": _source_label(),
            "type": response_type,
            "models_used": models_used or [],
            "summary": summary or {},
            "results": results or [],
        }
        auto_response_feed.append(entry)
        if len(auto_response_feed) > max_auto_response_feed:
            del auto_response_feed[:-max_auto_response_feed]

    def _tag_machine_source(rows):
        """Mark predictions submitted via API key as n8n source for dashboard visibility."""
        if not getattr(g, "api_key_auth", None):
            return rows
        tagged = []
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            copied = dict(row)
            if not copied.get("source_tool"):
                copied["source_tool"] = "n8n"
            if not copied.get("source"):
                copied["source"] = "n8n"
            tagged.append(copied)
        return tagged

    def _jwt_or_api_key_required(required_scope="n8n_predict"):
        """Allow either normal JWT cookie auth or machine API key auth."""
        def decorator(fn):
            @wraps(fn)
            def wrapped(*args, **kwargs):
                try:
                    verify_jwt_in_request()
                    return fn(*args, **kwargs)
                except Exception:
                    pass

                # Prefer validated API key context produced by middleware.
                if getattr(g, "api_key_auth", None):
                    return fn(*args, **kwargs)

                raw_key = (request.headers.get("X-API-Key") or "").strip()
                if not raw_key:
                    auth_header = (request.headers.get("Authorization") or "").strip()
                    if auth_header.lower().startswith("bearer "):
                        raw_key = auth_header.split(" ", 1)[1].strip()

                raw_key = raw_key.strip().strip('"').strip("'")

                if not raw_key:
                    return jsonify({"error": "Missing authentication. Use JWT cookie or API key."}), 401

                key_meta = validate_api_key(raw_key, required_scope=required_scope)
                if not key_meta:
                    return jsonify({"error": "Invalid or expired API key."}), 401

                # Preserve key metadata for downstream logic (source tagging, auditing).
                g.api_key_auth = key_meta

                return fn(*args, **kwargs)

            return wrapped
        return decorator

    def _parse_uploaded_json(file_storage):
        """Parse uploaded JSON file content as array or NDJSON lines."""
        raw = file_storage.read()
        text = raw.decode("utf-8", errors="ignore")

        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except Exception:
            pass

        items = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    items.append(parsed)
            except Exception:
                continue
        return items

    def _soc_access_allowed():
        role = get_jwt().get("role", "")
        return role in {"SOC_MANAGER", "SOC_ANALYST"}

    # ── Health ──────────────────────────────────────────
    @app.route("/api/health", methods=["GET"])
    def health():
        # Check Ollama service status (lightweight check)
        ollama_status = {"status": "unknown", "error": None}
        try:
            # Quick connectivity check - just get the list of running models
            resp = requests.get(
                f"{OLLAMA_BASE_URL.rstrip('/')}/api/tags",
                timeout=2
            )
            if resp.status_code == 200:
                data = resp.json()
                available_models = [m["name"] for m in data.get("models", [])]
                ollama_status = {
                    "status": "ok",
                    "available_models": available_models,
                    "configured_model": OLLAMA_MODEL,
                    "model_available": OLLAMA_MODEL in available_models
                }
            else:
                ollama_status = {
                    "status": "error",
                    "error": f"HTTP {resp.status_code}",
                    "details": resp.text[:200]
                }
        except Exception as e:
            ollama_status = {
                "status": "unavailable",
                "error": str(e)[:200]
            }
        
        return jsonify({
            "status": "ok" if ollama_status["status"] == "ok" else "degraded",
            "supabase": supabase_client.is_enabled(),
            "ollama": ollama_status,
            "models": {
                "alert_severity": ["mitre_classifier", "behavioral_classifier"],
                "alert_category": ["attack_category"],
                "vuln_priority": ["vuln_priority"],
                "vuln_attack_type": ["attack_type_desc (TF-IDF + CVSS)"],
            }
        })

    # ── Smart Auto-Detect Endpoint ──────────────────────
    @app.route("/api/predict/auto", methods=["POST"])
    @_jwt_or_api_key_required(required_scope="n8n_predict")
    @limiter.limit("10000 per minute")
    def auto_predict():
        """
        Smart endpoint: auto-detects file type and routes to correct models.
        - Alerts → 3 models (MITRE/Behavioral + Attack Category)
        - Vulns  → 2 models (Priority + Attack Type)
        """
        data = _coerce_json_payload()
        items = _unwrap_items(data)

        # Debug: if items is empty, return detailed error with payload info
        if not items:
            import sys
            error_detail = {
                "error": "Invalid input — send object or array",
                "debug": {
                    "payload_type": type(data).__name__,
                    "payload_value": str(data)[:500] if data else None,
                    "raw_body_sample": (request.get_data(as_text=True) or "")[:200],
                    "content_type": request.content_type,
                    "content_length": request.content_length,
                }
            }
            print(f"[DEBUG] auto_predict empty items: {json.dumps(error_detail, indent=2)}", file=sys.stderr)
            return jsonify(error_detail), 400

        file_type = _detect_type(items)

        if file_type == "unknown" and len(items) == 1:
            # Retry one level deeper for wrappers around a single alert.
            nested = _unwrap_items(items[0])
            if nested:
                items = nested
                file_type = _detect_type(items)

        if file_type == "alerts":
            results = _tag_machine_source(predict_alerts(items))
            
            summary = get_summary(results)
            models_used = _get_alert_models_used(results)

            supabase_client.save_alerts(results)
            low_conf = [r for r in results if r.get("needs_review")]
            if low_conf:
                supabase_client.save_low_confidence(low_conf)

            _record_auto_response("alerts", results, summary, models_used)

            return jsonify({
                "type": "alerts",
                "results": results,
                "summary": summary,
                "models_used": models_used,
            })

        elif file_type == "vulnerabilities":
            vuln_data = predict_vulnerabilities(items)
            supabase_client.save_vulnerabilities(vuln_data["results"])

            vuln_summary = {
                "total": len(vuln_data["results"]),
                "needs_review": sum(1 for r in vuln_data["results"] if r.get("needs_review")),
            }
            _record_auto_response("vulnerabilities", vuln_data["results"], vuln_summary, vuln_data["models_used"])

            return jsonify({
                "type": "vulnerabilities",
                "results": vuln_data["results"],
                "models_used": vuln_data["models_used"],
                "summary": vuln_summary,
            })

        else:
            return jsonify({"error": "Cannot detect file type. Expected Wazuh alerts or CVE data."}), 400

    # ── Upload JSON File Analysis ───────────────────────
    @app.route("/api/analysis/upload-json", methods=["POST"])
    @_jwt_or_api_key_required(required_scope="n8n_predict")
    @limiter.limit("120 per minute")
    def upload_json_analysis():
        """
        Analyze uploaded JSON/NDJSON file using the same auto-detect logic.
        Expected multipart/form-data with 'file'.
        """
        upload = request.files.get("file")
        if not upload:
            return jsonify({"error": "Missing file field. Use multipart/form-data with key 'file'."}), 400

        filename = (upload.filename or "").strip()
        if not filename:
            return jsonify({"error": "File name is empty"}), 400

        items = _parse_uploaded_json(upload)
        if not items:
            return jsonify({"error": "No valid JSON objects found in file"}), 400

        file_type = _detect_type(items)

        if file_type == "alerts":
            results = _tag_machine_source(predict_alerts(items))
            summary = get_summary(results)
            models_used = _get_alert_models_used(results)

            supabase_client.save_alerts(results)
            low_conf = [r for r in results if r.get("needs_review")]
            if low_conf:
                supabase_client.save_low_confidence(low_conf)

            return jsonify({
                "type": "alerts",
                "file_name": filename,
                "total_items": len(items),
                "results": results,
                "summary": summary,
                "models_used": models_used,
            })

        if file_type == "vulnerabilities":
            vuln_data = predict_vulnerabilities(items)
            supabase_client.save_vulnerabilities(vuln_data["results"])

            return jsonify({
                "type": "vulnerabilities",
                "file_name": filename,
                "total_items": len(items),
                "results": vuln_data["results"],
                "models_used": vuln_data["models_used"],
                "summary": {
                    "total": len(vuln_data["results"]),
                    "needs_review": sum(1 for r in vuln_data["results"] if r.get("needs_review")),
                },
            })

        return jsonify({"error": "Cannot detect file type. Expected Wazuh alerts or CVE data."}), 400

    # ── Alert Prediction (direct) ───────────────────────
    @app.route("/api/alerts/predict", methods=["POST"])
    @_jwt_or_api_key_required(required_scope="n8n_predict")
    @limiter.limit("1000 per minute")
    def alerts_predict():
        data = _coerce_json_payload()

        if isinstance(data, dict):
            alerts = [data]
        elif isinstance(data, list):
            alerts = data
        else:
            return jsonify({"error": "Invalid input — send object or array"}), 400

        results = _tag_machine_source(predict_alerts(alerts))
        
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
    @_jwt_or_api_key_required(required_scope="n8n_predict")
    @limiter.limit("1000 per minute")
    def vuln_predict():
        data = _coerce_json_payload()

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
    @limiter.limit("120 per minute")
    def dashboard_stats():
        try:
            verify_jwt_in_request(optional=True)
        except Exception:
            return jsonify({"alerts": 0, "vulnerabilities": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}), 200

        stats = supabase_client.get_dashboard_stats()
        return jsonify(stats)

    # ── Live /api/predict/auto Output Feed ─────────────
    @app.route("/api/dashboard/auto-output", methods=["GET"])
    @limiter.limit("240 per minute")
    def dashboard_auto_output():
        try:
            verify_jwt_in_request(optional=True)
        except Exception:
            return jsonify({"items": [], "total": 0}), 200

        limit = request.args.get("limit", default=50, type=int)
        if limit <= 0:
            limit = 50
        limit = min(limit, 300)

        feed = list(reversed(auto_response_feed[-limit:]))
        return jsonify({
            "items": feed,
            "total": len(feed),
        })

    # ── Generate SOC Report (Ollama) ──────────────────────
    @app.route("/api/dashboard/report", methods=["POST"])
    @_jwt_or_api_key_required(required_scope="n8n_predict")
    @limiter.limit("30 per minute")
    def dashboard_report():
        """
        Generate an AI-powered SOC incident report using qwen model (LM Studio).
        Collects ALL alert and vulnerability data from ML predictions and
        generates comprehensive executive report.
        """
        try:
            verify_jwt_in_request(optional=True)
        except Exception:
            pass

        data = request.get_json(force=True, silent=True) or {}
        # Optional: allow custom filtering, otherwise get ALL data
        limit = data.get("limit", 10000)

        try:
            # Collect ALL alerts and vulnerabilities for comprehensive report
            all_alerts = supabase_client.get_alerts(limit=limit)
            all_vulns = supabase_client.get_vulnerabilities(limit=limit)
            low_conf = supabase_client.get_low_confidence(limit=limit)

            # Combine all items for the report
            all_rows = []
            for alert in all_alerts:
                alert["responseType"] = "alerts"
                alert["responseSource"] = alert.get("source", "n8n")
                all_rows.append(alert)

            for vuln in all_vulns:
                vuln["responseType"] = "vulnerabilities"
                vuln["responseSource"] = vuln.get("source", "n8n")
                all_rows.append(vuln)

            # Build summary statistics
            critical = sum(1 for r in all_rows if r.get("severity_final") == "Critical" or r.get("priority") == "Critical")
            high = sum(1 for r in all_rows if r.get("severity_final") == "High" or r.get("priority") == "High")
            medium = sum(1 for r in all_rows if r.get("severity_final") == "Medium" or r.get("priority") == "Medium")
            needs_review = sum(1 for r in all_rows if r.get("needs_review"))
            sla_breached = sum(1 for r in all_rows if r.get("sla_breached"))

            # Calculate average confidence
            confidences = [r.get("confidence") or r.get("priority_confidence") or r.get("attack_confidence") or 0 for r in all_rows]
            confidences = [c for c in confidences if isinstance(c, (int, float)) and c > 0]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0

            payload = {
                "summary": {
                    "total_alerts": len(all_alerts),
                    "total_vulnerabilities": len(all_vulns),
                    "total_items": len(all_rows),
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "needs_review": needs_review,
                    "sla_breached": sla_breached,
                    "avg_confidence": round(avg_confidence, 1),
                    "low_confidence_items": len(low_conf),
                },
                "feedback": {},
                "rows": all_rows,
            }

            # Perform deep threat intel enrichment
            all_indicators={"ips":[],"domains":[],"hashes":[]}
            enriched_intel_results=[]
            for row in all_rows:
                for lt in [row.get("full_log"),row.get("rule_description"),row.get("description"),row.get("raw_log")]:
                    if lt:
                        ext=extract_indicators(str(lt))
                        for k in all_indicators:all_indicators[k].extend(ext.get(k,[]))
            for k in all_indicators:all_indicators[k]=list(dict.fromkeys(all_indicators[k]))[:100]
            intel_summary={"total_indicators":0,"critical":0,"high":0,"medium":0,"low":0}
            itypes=["ip","domain","hash"]
            for idx,key in enumerate(all_indicators.keys()):
                for v in all_indicators[key]:
                    try:
                        enr=enrich_indicator(itypes[idx],v)
                        enriched_intel_results.append(enr)
                        rl=enr.get("context",{}).get("risk_level","low")
                        intel_summary["total_indicators"]+=1
                        if rl in ["critical","high"]:intel_summary["critical"]+=1
                        elif rl=="medium":intel_summary["medium"]+=1
                        else: intel_summary["low"]+=1
                    except Exception as e:
                        logger.warning(f"Failed:{e}")
            elines=[]
            for r in enriched_intel_results[:30]:
                ctx=r.get("context",{})
                elines.append(f"{r.get('indicator_type','unknown')}:{r.get('value','unknown')} - Risk:{ctx.get('risk_level','unknown').upper()}(score:{ctx.get('risk_score',0)})")
            enriched_summary_str="\n".join(elines) if elines else "No indicators"
            payload["threat_intel_summary"]=enriched_summary_str
            payload["total_indicators_analyzed"]=intel_summary["total_indicators"]
            payload["summary"]["indicators_analyzed"]=intel_summary["total_indicators"]

            try:
                report = generate_rapport_with_qwen(payload)
            except RuntimeError as e:
                logger.warning(f"Qwen fallback:{e}")
                report={"title":"SOC Fallback","executive_summary":f"Items:{len(all_rows)} Indicators:{intel_summary['total_indicators']}","key_findings":[f"Alerts:{len(all_alerts)}",f"Vulns:{len(all_vulns)}",f"Critical/High:{critical+high}"],"priority_actions":["Review critical","Investigate intel"],"analyst_advice":["Focus needs_review","Correlate intel"],"risk_level":"High" if critical+high>5 else "Medium" if critical+high>0 else "Low","report_markdown":f"# SOC\\nItems:{len(all_rows)},Crit:{critical},High:{high},Indicators:{intel_summary['total_indicators']}","meta":{"generated_at":datetime.now(timezone.utc).isoformat(),"model":"fallback","engine":"fallback"}}
            if getattr(g, "api_key_auth", None):
                report["meta"]["source"]="n8n"
            return jsonify({"report": report, "total_rows": len(all_rows),"threat_intel":{"indicators_analyzed": intel_summary["total_indicators"],"critical_high":intel_summary["critical"]}})

        except RuntimeError as e:
            logger.error(f"Report generation failed: {e}")
            return jsonify({"error": str(e)}), 503
        except ValueError as e:
            logger.error(f"Report content error: {e}")
            return jsonify({"error": str(e)}), 500
        except Exception as e:
            logger.error(f"Unexpected error during report generation: {e}")
            return jsonify({"error": "Internal server error during report generation"}), 500

    # ── All Alerts (from DB) ──────────────────────────────
    @app.route("/api/dashboard/alerts", methods=["GET"])
    @limiter.limit("120 per minute")
    def dashboard_alerts():
        try:
            verify_jwt_in_request(optional=True)
        except Exception:
            return jsonify({"alerts": []}), 200

        alerts = supabase_client.get_alerts(limit=1000)
        return jsonify({"alerts": alerts})

    # ── All Vulnerabilities (from DB) ─────────────────────
    @app.route("/api/dashboard/vulnerabilities", methods=["GET"])
    @limiter.limit("120 per minute")
    def dashboard_vulnerabilities():
        try:
            verify_jwt_in_request(optional=True)
        except Exception:
            return jsonify({"vulnerabilities": []}), 200

        vulns = supabase_client.get_vulnerabilities(limit=1000)
        return jsonify({"vulnerabilities": vulns})

    # ── Low Confidence Items ────────────────────────────
    @app.route("/api/dashboard/low-confidence", methods=["GET"])
    @limiter.limit("120 per minute")
    def low_confidence():
        try:
            verify_jwt_in_request(optional=True)
        except Exception:
            return jsonify({"items": []}), 200

        items = supabase_client.get_low_confidence()
        return jsonify({"items": items})

    # ── Threat Intel Lookup ─────────────────────────────
    @app.route("/api/threat-intel/lookup", methods=["POST"])
    @jwt_required()
    @limiter.limit("60 per minute")
    def threat_intel_lookup():
        if not _soc_access_allowed():
            return jsonify({"error": "Access denied. SOC Manager or SOC Analyst only."}), 403

        data = request.get_json(force=True)
        ip = data.get("ip", "")
        if not ip:
            return jsonify({"error": "IP required"}), 400

        payload = enrich_log("", {"ips": [ip]})
        match = payload.get("results", [{}])[0] if payload.get("results") else None
        return jsonify({"ip": ip, "result": match})

    # ── Threat Intel Enrichment ─────────────────────────
    @app.route("/api/threat-intel/enrich", methods=["POST"])
    @jwt_required()
    @limiter.limit("30 per minute")
    def threat_intel_enrich():
        if not _soc_access_allowed():
            return jsonify({"error": "Access denied. SOC Manager or SOC Analyst only."}), 403

        data = request.get_json(force=True) or {}
        log_text = data.get("log", "")
        manual = data.get("indicators", {})

        if not isinstance(log_text, str):
            return jsonify({"error": "log must be a string"}), 400
        if manual and not isinstance(manual, dict):
            return jsonify({"error": "indicators must be an object"}), 400

        result = enrich_log(log_text, manual)
        return jsonify(result)

    # ── Suricata Alerts ─────────────────────────────────
    @app.route("/api/suricata/alerts", methods=["GET"])
    @jwt_required()
    @limiter.limit("120 per minute")
    def suricata_alerts():
        return jsonify({"alerts": []})

    # ── Models Info ─────────────────────────────────────
    @app.route("/api/models/info", methods=["GET"])
    @jwt_required()
    @limiter.limit("120 per minute")
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



    # -- Generate PDF Report --------------------------------
    @app.route("/api/dashboard/report/pdf", methods=["POST"])
    @_jwt_or_api_key_required(required_scope="n8n_predict")
    @limiter.limit("10 per minute")
    def dashboard_report_pdf():
        try:
            verify_jwt_in_request(optional=True)
        except Exception:
            pass
        data = request.get_json(force=True, silent=True) or {}
        limit = data.get("limit", 10000)
        try:
            all_alerts = supabase_client.get_alerts(limit=limit)
            all_vulns = supabase_client.get_vulnerabilities(limit=limit)
            all_rows = []
            for a in all_alerts:
                a["responseType"] = "alerts"
                a["responseSource"] = a.get("source", "n8n")
                all_rows.append(a)
            for v in all_vulns:
                v["responseType"] = "vulnerabilities"
                v["responseSource"] = v.get("source", "n8n")
                all_rows.append(v)
            all_indicators = {"ips": [], "domains": [], "hashes": []}
            enriched_intel_results = []
            for row in all_rows:
                for lt in [row.get("full_log"), row.get("rule_description"), row.get("description")]:
                    if lt:
                        ext = extract_indicators(str(lt))
                        for k in all_indicators:
                            all_indicators[k].extend(ext.get(k, []))
            for k in all_indicators:
                all_indicators[k] = list(dict.fromkeys(all_indicators[k]))[:100]
            it_sum = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            itypes = ["ip", "domain", "hash"]
            for idx, k in enumerate(all_indicators.keys()):
                for v in all_indicators[k]:
                    try:
                        enr = enrich_indicator(itypes[idx], v)
                        enriched_intel_results.append(enr)
                        rl = enr.get("context", {}).get("risk_level", "low")
                        it_sum["total"] += 1
                        if rl in ["critical", "high"]: it_sum["critical"] += 1
                        elif rl == "medium": it_sum["medium"] += 1
                        else: it_sum["low"] += 1
                    except:
                        pass
            crit = sum(1 for r in all_rows if r.get("severity_final") == "Critical" or r.get("priority") == "Critical")
            high_c = sum(1 for r in all_rows if r.get("severity_final") == "High" or r.get("priority") == "High")
            med = sum(1 for r in all_rows if r.get("severity_final") == "Medium" or r.get("priority") == "Medium")
            nr = sum(1 for r in all_rows if r.get("needs_review"))
            elines = []
            for r in enriched_intel_results[:30]:
                ctx = r.get("context", {})
                elines.append(r.get("indicator_type", "unknown") + ":" + r.get("value", "unknown"))
            ets = "\n".join(elines) if elines else "No indicators"
            qp = {"summary": {"total_alerts": len(all_alerts), "total_vulnerabilities": len(all_vulns),
                    "total_items": len(all_rows), "critical": crit, "high": high_c, "medium": med,
                    "needs_review": nr, "indicators_analyzed": it_sum["total"]},
                "feedback": {}, "rows": all_rows, "threat_intel_summary": ets}
            report = generate_rapport_with_qwen(qp)
            try:
                from jspdf import jsPDF
                import base64
                doc = jsPDF()
                yp = 14
                def wb(t, sp=7, sz=11, b=False):
                    nonlocal yp
                    doc.setFont("helvetica", "bold" if b else "normal")
                    doc.setFontSize(sz)
                    for ln in doc.splitTextToSize(str(t or ""), doc.internal.pageSize.getWidth() - 24):
                        if yp > 280: doc.addPage(); yp = 14
                        doc.text(ln, 12, yp); yp += sp
                wb(report.get("title", "SOC Report"), 8, 16, True); yp += 4
                wb("Risk:" + str(report.get("risk_level", "Unknown")), 6, 10, True)
                wb("Generated:" + str(report.get("meta", {}).get("generated_at", "")), 6, 9)
                wb("Items:" + str(len(all_rows)), 6, 9)
                if it_sum["total"] > 0: wb("Indicators:" + str(it_sum["total"]), 6, 9)
                yp += 8; wb("Executive Summary", 7, 12, True)
                wb(report.get("executive_summary", "No."), 6, 10); yp += 6
                wb("Key Findings", 7, 12, True)
                for it in report.get("key_findings", []): wb("- " + it, 6, 10)
                yp += 6; wb("Priority Actions", 7, 12, True)
                for it in report.get("priority_actions", []): wb("- " + it, 6, 10)
                yp += 6; wb("Analyst Advice", 7, 12, True)
                for it in report.get("analyst_advice", []): wb("- " + it, 6, 10)
                yp += 6
                wb("AI Analyst POV - ML Analysis", 7, 12, True)
                wb(report.get("ml_analysis_pov", "No POV provided."), 6, 10); yp += 6
                wb("AI Analyst POV - Threat Intel", 7, 12, True)
                wb(report.get("threat_intel_pov", "No POV provided."), 6, 10); yp += 6
                wb("Team Advice", 7, 12, True)
                wb(report.get("team_advice", "No team advice provided."), 6, 10); yp += 6
                if enriched_intel_results: wb("Threat Intel Details", 7, 12, True); wb(ets, 6, 9); yp += 6
                if report.get("report_markdown"): wb("Details", 7, 12, True); wb(report.get("report_markdown"), 6, 9)
                if yp > 270: doc.addPage(); yp = 14
                doc.setFontSize(8); doc.text("SOC ML | qwen", 12, yp)
                pdf_b64 = base64.b64encode(doc.output()).decode("ascii")
                return jsonify({"report": report, "pdf_base64": pdf_b64, "pdf_filename": "soc-report.pdf",
                    "total_rows": len(all_rows), "threat_intel": {"indicators_analyzed": it_sum["total"]}})
            except ImportError:
                return jsonify({"error": "PDF needs jspdf", "report": report, "total_rows": len(all_rows)}), 500
            except Exception as e:
                logger.error("PDF error:" + str(e)); return jsonify({"error": "PDF failed"}), 500
        except RuntimeError as e:
            logger.error("PDF fail:" + str(e)); return jsonify({"error": str(e)}), 503
        except Exception as e:
            logger.error("Err:" + str(e)); return jsonify({"error": "Internal"}), 500

    # ── Download PDF Report ───────────────────────────────
    @app.route("/api/dashboard/report/download/<filename>", methods=["GET"])
    @_jwt_or_api_key_required(required_scope="n8n_predict")
    @limiter.limit("10 per minute")
    def download_report_pdf(filename):
        """
        Download the SOC report as a PDF file directly.
        This endpoint expects the PDF to be generated first via POST /api/dashboard/report/pdf
        and stored temporarily, but for now returns a placeholder.
        """
        try:
            verify_jwt_in_request(optional=True)
        except Exception:
            pass

        # For now, return a placeholder response
        # In production, this would serve a stored PDF file
        return jsonify({
            "error": "Direct PDF download not yet implemented. Use POST /api/dashboard/report/pdf and decode base64 on frontend.",
            "filename": filename
        }), 501

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
