from datetime import datetime

import supabase_client
from models.alert_workflow import can_transition, is_valid_status, normalize_status


class AlertWorkflowService:
    @staticmethod
    def get_alert(alert_id):
        return supabase_client.get_alert_by_id(alert_id)

    @staticmethod
    def list_alerts(filters):
        return supabase_client.get_alerts_filtered(filters)

    @staticmethod
    def update_status(alert_id, new_status):
        status = normalize_status(new_status)
        if not is_valid_status(status):
            return None, {
                "error": "Invalid status",
                "details": "Allowed values: OPEN, IN_PROGRESS, RESOLVED",
            }, 400

        alert = supabase_client.get_alert_by_id(alert_id)
        if not alert:
            return None, {"error": "Alert not found", "details": f"id={alert_id}"}, 404

        current = normalize_status(alert.get("status", "OPEN"))
        if current == status:
            return alert, None, 200

        if not can_transition(current, status):
            return None, {
                "error": "Invalid transition",
                "details": f"Cannot transition from {current} to {status}",
            }, 400

        updated = supabase_client.update_alert_fields(alert_id, {"status": status})
        if not updated:
            return None, {"error": "Update failed", "details": "Could not update alert status"}, 500
        return updated, None, 200

    @staticmethod
    def assign_alert(alert_id, assigned_to):
        if not assigned_to:
            return None, {"error": "Invalid payload", "details": "assigned_to is required"}, 400

        alert = supabase_client.get_alert_by_id(alert_id)
        if not alert:
            return None, {"error": "Alert not found", "details": f"id={alert_id}"}, 404

        user = supabase_client.get_user_by_id(assigned_to)
        if not user:
            return None, {"error": "User not found", "details": f"user_id={assigned_to}"}, 404

        updated = supabase_client.update_alert_fields(alert_id, {"assigned_to": assigned_to})
        if not updated:
            return None, {"error": "Update failed", "details": "Could not assign alert"}, 500
        return updated, None, 200

    @staticmethod
    def get_comments(alert_id):
        return supabase_client.get_comments_by_alert_id(alert_id)

    @staticmethod
    def create_comment(alert_id, user_id, comment):
        text = (comment or "").strip()
        if not text:
            return None, {"error": "Invalid payload", "details": "comment is required"}, 400

        alert = supabase_client.get_alert_by_id(alert_id)
        if not alert:
            return None, {"error": "Alert not found", "details": f"id={alert_id}"}, 404

        payload = {
            "alert_id": alert_id,
            "user_id": user_id,
            "comment": text,
            "created_at": datetime.utcnow().isoformat(),
        }
        created = supabase_client.add_comment(payload)
        if not created:
            return None, {"error": "Create failed", "details": "Could not save comment"}, 500
        return created, None, 201

    @staticmethod
    def delete_comment(comment_id, requester_id, requester_role):
        comment = supabase_client.get_comment_by_id(comment_id)
        if not comment:
            return None, {"error": "Comment not found", "details": f"id={comment_id}"}, 404

        if requester_role != "SOC_MANAGER" and comment.get("user_id") != requester_id:
            return None, {"error": "Access denied", "details": "Only SOC Manager or comment author can delete"}, 403

        deleted = supabase_client.delete_comment(comment_id)
        if not deleted:
            return None, {"error": "Delete failed", "details": "Could not delete comment"}, 500
        return {"message": "Comment deleted successfully"}, None, 200
