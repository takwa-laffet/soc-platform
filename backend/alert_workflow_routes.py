from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required
from datetime import datetime, timezone

import ml_loader
import supabase_client
from model_registry import list_model_versions as registry_list_model_versions
from model_registry import rollback_model
from services.feedback_service import FeedbackService
from services.alert_workflow_service import AlertWorkflowService
from services.incident_service import IncidentService
from services.ollama_report_service import generate_soc_report
from training.training_jobs import get_training_status, start_feedback_training_job
from config import OLLAMA_BASE_URL

alert_workflow_bp = Blueprint("alert_workflow", __name__)


def _build_local_soc_report(payload, reason=None):
    summary = payload.get("summary") or {}
    feedback = payload.get("feedback") or {}
    rows = payload.get("rows") or []

    total_rows = int(summary.get("total_rows") or len(rows) or 0)
    critical = int(summary.get("critical") or 0)
    high = int(summary.get("high") or 0)
    medium = int(summary.get("medium") or 0)
    needs_review = int(summary.get("needs_review") or 0)
    sla_breached = int(summary.get("sla_breached") or 0)
    avg_confidence = float(summary.get("avg_confidence") or 0)

    reviewed = int(feedback.get("reviewed") or 0)
    approved = int(feedback.get("approved") or 0)
    rejected = int(feedback.get("rejected") or 0)

    if critical > 0 or sla_breached > 0:
        risk_level = "Critical"
    elif high > 0 or needs_review > max(3, total_rows // 4):
        risk_level = "High"
    elif medium > 0:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    key_findings = [
        f"Processed {total_rows} alerts in the current dashboard snapshot.",
        f"Severity distribution: Critical={critical}, High={high}, Medium={medium}.",
        f"Needs review={needs_review}, SLA breached={sla_breached}.",
        f"Average model confidence is {avg_confidence:.1f}%.",
    ]

    if reviewed > 0:
        key_findings.append(
            f"Human feedback: reviewed={reviewed}, approved={approved}, rejected={rejected}."
        )

    priority_actions = []
    if critical > 0:
        priority_actions.append("Escalate all critical alerts immediately and assign an incident owner.")
    if sla_breached > 0:
        priority_actions.append("Resolve SLA-breached alerts first and document delay reasons.")
    if needs_review > 0:
        priority_actions.append("Triage pending analyst-review alerts and close false positives.")
    if avg_confidence < 60:
        priority_actions.append("Increase analyst validation because model confidence is currently low.")
    if not priority_actions:
        priority_actions.append("Continue routine monitoring and periodic triage checks.")

    analyst_advice = [
        "Use enrichment (threat intel, asset criticality, user context) before final escalation.",
        "Capture feedback on disputed classifications to improve future model retraining.",
        "Verify repeat offenders and correlate by source IP, user account, and host.",
    ]

    now = datetime.now(timezone.utc).isoformat()
    report_markdown = "\n".join([
        "# SOC ML Incident Report (Fallback)",
        "",
        f"- Risk level: **{risk_level}**",
        f"- Processed alerts: **{total_rows}**",
        f"- Critical/High/Medium: **{critical}/{high}/{medium}**",
        f"- Needs review: **{needs_review}**",
        f"- SLA breached: **{sla_breached}**",
    ])

    return {
        "title": "SOC ML Incident Report (Fallback)",
        "executive_summary": (
            "This report was generated using local deterministic rules because Ollama could not "
            "produce a live report for this request."
        ),
        "key_findings": key_findings,
        "priority_actions": priority_actions,
        "analyst_advice": analyst_advice,
        "risk_level": risk_level,
        "report_markdown": report_markdown,
        "meta": {
            "generated_at": now,
            "model": "local-fallback",
            "base_url": OLLAMA_BASE_URL,
            "fallback": True,
            "fallback_reason": reason or "unknown",
        },
    }


def _soc_access_allowed():
    role = get_jwt().get("role", "")
    return role in {"SOC_MANAGER", "SOC_ANALYST"}


def _manager_only():
    return get_jwt().get("role", "") == "SOC_MANAGER"


@alert_workflow_bp.route("/alerts", methods=["GET"])
@jwt_required()
def list_alerts():
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    filters = {
        "status": request.args.get("status"),
        "severity": request.args.get("severity"),
        "assigned_to": request.args.get("assigned_to"),
        "source": request.args.get("source"),
        "start_date": request.args.get("start_date"),
        "end_date": request.args.get("end_date"),
        "search": request.args.get("search"),
        "limit": request.args.get("limit", type=int),
    }
    alerts = AlertWorkflowService.list_alerts(filters)
    return jsonify({"alerts": alerts}), 200


@alert_workflow_bp.route("/alerts/<alert_id>", methods=["GET"])
@jwt_required()
def get_alert(alert_id):
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    alert = AlertWorkflowService.get_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found", "details": f"id={alert_id}"}), 404
    return jsonify({"alert": alert}), 200


@alert_workflow_bp.route("/alerts/<alert_id>/status", methods=["PUT"])
@jwt_required()
def update_alert_status(alert_id):
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    data = request.get_json(silent=True) or {}
    updated, error, code = AlertWorkflowService.update_status(alert_id, data.get("status"))
    if error:
        return jsonify(error), code
    return jsonify({"alert": updated}), code


@alert_workflow_bp.route("/alerts/<alert_id>/assign", methods=["PUT"])
@jwt_required()
def assign_alert(alert_id):
    if not _manager_only():
        return jsonify({"error": "Access denied", "details": "SOC_MANAGER role required"}), 403

    data = request.get_json(silent=True) or {}
    updated, error, code = AlertWorkflowService.assign_alert(alert_id, data.get("assigned_to"))
    if error:
        return jsonify(error), code
    return jsonify({"alert": updated}), code


@alert_workflow_bp.route("/alerts/<alert_id>/comments", methods=["GET"])
@jwt_required()
def get_alert_comments(alert_id):
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    comments = AlertWorkflowService.get_comments(alert_id)
    return jsonify({"comments": comments}), 200


@alert_workflow_bp.route("/alerts/<alert_id>/comments", methods=["POST"])
@jwt_required()
def add_alert_comment(alert_id):
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    data = request.get_json(silent=True) or {}
    created, error, code = AlertWorkflowService.create_comment(
        alert_id=alert_id,
        user_id=get_jwt_identity(),
        comment=data.get("comment"),
    )
    if error:
        return jsonify(error), code
    return jsonify({"comment": created}), code


@alert_workflow_bp.route("/comments/<comment_id>", methods=["DELETE"])
@jwt_required()
def delete_comment(comment_id):
    requester_id = get_jwt_identity()
    requester_role = get_jwt().get("role", "")

    payload, error, code = AlertWorkflowService.delete_comment(
        comment_id=comment_id,
        requester_id=requester_id,
        requester_role=requester_role,
    )
    if error:
        return jsonify(error), code
    return jsonify(payload), code


@alert_workflow_bp.route("/incidents", methods=["GET"])
@jwt_required()
def list_incidents():
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    filters = {
        "status": request.args.get("status"),
        "severity": request.args.get("severity"),
        "assigned_to": request.args.get("assigned_to"),
        "source": request.args.get("source"),
        "start_date": request.args.get("start_date"),
        "end_date": request.args.get("end_date"),
        "search": request.args.get("search"),
        "alert_limit": request.args.get("alert_limit", type=int),
        "incident_limit": request.args.get("incident_limit", type=int),
        "window_seconds": request.args.get("window_seconds", type=int),
        "incident_status": request.args.get("incident_status"),
    }

    incidents = IncidentService.list_incidents(filters)
    return jsonify({"incidents": incidents, "total": len(incidents)}), 200


@alert_workflow_bp.route("/incidents/<incident_id>/status", methods=["PUT"])
@jwt_required()
def update_incident_status(incident_id):
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    data = request.get_json(silent=True) or {}
    updated, error, code = IncidentService.update_incident_status(
        incident_id=incident_id,
        new_status=data.get("status"),
    )
    if error:
        return jsonify(error), code
    return jsonify({"incident": updated}), code


@alert_workflow_bp.route("/feedback", methods=["POST"])
@jwt_required()
def submit_feedback():
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    data = request.get_json(silent=True) or {}
    created, error, code = FeedbackService.submit_feedback(
        payload=data,
        analyst_id=get_jwt_identity(),
    )
    if error:
        return jsonify(error), code
    return jsonify({"feedback": created}), code


@alert_workflow_bp.route("/feedback", methods=["GET"])
@jwt_required()
def list_feedback():
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    limit = request.args.get("limit", type=int) or 200
    model_name = request.args.get("model_name")
    rows = supabase_client.get_feedback_rows(limit=limit, model_name=model_name)
    return jsonify({"feedback": rows, "total": len(rows)}), 200


@alert_workflow_bp.route("/ml/train/feedback", methods=["POST"])
@jwt_required()
def trigger_feedback_training():
    if not _manager_only():
        return jsonify({"error": "Access denied", "details": "SOC_MANAGER role required"}), 403

    actor = get_jwt_identity() or "soc_manager"
    job_id, reason = start_feedback_training_job(triggered_by=str(actor))
    if reason == "already_running":
        return jsonify({"error": "Training already running", "details": get_training_status()}), 409

    return jsonify({"message": "Training job started", "job_id": job_id}), 202


@alert_workflow_bp.route("/ml/train/feedback/status", methods=["GET"])
@jwt_required()
def feedback_training_status():
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    return jsonify(get_training_status()), 200


@alert_workflow_bp.route("/ml/models/versions", methods=["GET"])
@jwt_required()
def list_model_versions():
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    model_name = request.args.get("model_name", "xgb_attack_model.pkl")
    versions = registry_list_model_versions(model_name)
    db_versions = supabase_client.list_model_versions(model_name=model_name, limit=100)
    return jsonify({"model_name": model_name, "versions": versions, "db_versions": db_versions}), 200


@alert_workflow_bp.route("/ml/models/rollback", methods=["POST"])
@jwt_required()
def rollback_model_version():
    if not _manager_only():
        return jsonify({"error": "Access denied", "details": "SOC_MANAGER role required"}), 403

    data = request.get_json(silent=True) or {}
    model_name = data.get("model_name") or "xgb_attack_model.pkl"
    target_version = data.get("target_version")

    rolled = rollback_model(model_name, target_version=target_version)
    if not rolled:
        return jsonify({"error": "Rollback failed", "details": "No suitable version found"}), 400

    warmed = ml_loader.hot_reload_models()
    actor = get_jwt_identity() or "soc_manager"
    supabase_client.record_audit_event(
        event_type="model_rollback",
        actor_id=actor,
        details={
            "model_name": model_name,
            "target_version": rolled.get("version"),
            "warmed_models": warmed,
        },
    )

    supabase_client.record_model_version(
        {
            "model_name": model_name,
            "version": int(rolled.get("version", 0)),
            "filename": rolled.get("filename"),
            "accuracy": (rolled.get("metrics") or {}).get("accuracy"),
            "precision": (rolled.get("metrics") or {}).get("precision_weighted"),
            "training_date": rolled.get("trained_at"),
            "dataset_size": rolled.get("dataset_size"),
            "is_active": True,
            "metadata": {"rollback": True},
            "created_by": str(actor),
        }
    )

    return jsonify({"message": "Rollback successful", "active_version": rolled, "warmed_models": warmed}), 200


@alert_workflow_bp.route("/ml/models/reload", methods=["POST"])
@jwt_required()
def hot_reload_model_cache():
    if not _manager_only():
        return jsonify({"error": "Access denied", "details": "SOC_MANAGER role required"}), 403

    warmed = ml_loader.hot_reload_models()
    supabase_client.record_audit_event(
        event_type="model_hot_reload",
        actor_id=get_jwt_identity() or "soc_manager",
        details={"warmed_models": warmed},
    )
    return jsonify({"message": "Model cache reloaded", "warmed_models": warmed}), 200


@alert_workflow_bp.route("/dashboard/report", methods=["POST"])
@jwt_required()
def generate_dashboard_report():
    if not _soc_access_allowed():
        return jsonify({"error": "Access denied", "details": "SOC role required"}), 403

    data = request.get_json(silent=True) or {}
    try:
        report = generate_soc_report(data)
    except Exception as exc:
        error_message = str(exc)
        error_type = type(exc).__name__
        
        # Log the full error for debugging
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to generate SOC report: {error_type}: {error_message}", exc_info=True)
        
        fallback_report = _build_local_soc_report(data, reason=error_message)
        return jsonify({
            "report": fallback_report,
            "warning": "Ollama unavailable. Returned local fallback report.",
            "details": error_message,
            "error_type": error_type,
            "ollama_url": OLLAMA_BASE_URL,
            "degraded": True,
        }), 200

    return jsonify({"report": report}), 200
