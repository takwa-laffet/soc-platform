from datetime import datetime

import supabase_client

_ALLOWED_MODELS = {"attack_category", "severity"}


class FeedbackService:
    @staticmethod
    def _normalize_bool(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def validate_payload(payload):
        if not isinstance(payload, dict):
            return None, {"error": "Invalid payload", "details": "JSON object expected"}, 400

        alert_id = str(payload.get("alert_id") or "").strip()
        if not alert_id:
            return None, {"error": "Invalid payload", "details": "alert_id is required"}, 400

        ml_prediction = str(payload.get("ml_prediction") or "").strip()
        if not ml_prediction:
            return None, {"error": "Invalid payload", "details": "ml_prediction is required"}, 400

        is_wrong = FeedbackService._normalize_bool(payload.get("is_wrong", False))
        correct_label = (payload.get("correct_label") or "").strip() or None
        model_name = str(payload.get("model_name") or "attack_category").strip().lower()
        if model_name not in _ALLOWED_MODELS:
            return None, {
                "error": "Invalid payload",
                "details": "model_name must be one of: attack_category, severity",
            }, 400

        if is_wrong and not correct_label:
            return None, {
                "error": "Invalid payload",
                "details": "correct_label is required when is_wrong is true",
            }, 400

        normalized = {
            "alert_id": alert_id,
            "ml_prediction": ml_prediction,
            "correct_label": correct_label,
            "is_wrong": is_wrong,
            "model_name": model_name,
            "created_at": datetime.utcnow().isoformat(),
        }
        return normalized, None, 200

    @staticmethod
    def submit_feedback(payload, analyst_id):
        normalized, err, code = FeedbackService.validate_payload(payload)
        if err:
            return None, err, code

        alert = supabase_client.get_alert_by_id(normalized["alert_id"])
        if not alert:
            return None, {"error": "Alert not found", "details": f"id={normalized['alert_id']}"}, 404

        normalized["analyst_id"] = analyst_id
        created = supabase_client.add_feedback(normalized)
        if not created:
            return None, {"error": "Save failed", "details": "Could not persist feedback"}, 500

        supabase_client.record_audit_event(
            event_type="feedback_submitted",
            actor_id=analyst_id,
            details={
                "alert_id": normalized["alert_id"],
                "model_name": normalized["model_name"],
                "is_wrong": normalized["is_wrong"],
                "ml_prediction": normalized["ml_prediction"],
                "correct_label": normalized["correct_label"],
            },
        )
        return created, None, 201
