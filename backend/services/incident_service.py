import hashlib
from datetime import datetime, timedelta, timezone

import supabase_client
from models.incident_workflow import (
    can_transition_incident,
    is_valid_incident_status,
    normalize_incident_status,
)


class IncidentService:
    @staticmethod
    def _parse_dt(value):
        if not value:
            return None
        if isinstance(value, datetime):
            dt = value
        else:
            text = str(value).strip()
            if not text:
                return None
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(text)
            except ValueError:
                return None

        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @staticmethod
    def _normalize_str(value, fallback="unknown"):
        text = str(value or "").strip().lower()
        return text if text else fallback

    @staticmethod
    def _rule_family(alert):
        rule_id = str(alert.get("rule_id") or "").strip()
        rule_text = " ".join(
            [
                str(alert.get("rule_description") or ""),
                str(alert.get("title") or ""),
                str(alert.get("description") or ""),
            ]
        ).lower()

        auth_markers = ("failed", "login", "authentication", "brute", "password", "ssh")
        malware_markers = ("malware", "trojan", "ransom", "backdoor", "payload")
        web_markers = ("sql", "xss", "path traversal", "web shell", "http")

        if any(marker in rule_text for marker in auth_markers):
            return "AUTH_FAILURE"
        if any(marker in rule_text for marker in malware_markers):
            return "MALWARE_ACTIVITY"
        if any(marker in rule_text for marker in web_markers):
            return "WEB_ATTACK"
        if rule_id:
            return f"RULE_{rule_id}"
        return "GENERIC_ALERT"

    @staticmethod
    def _event_time(alert):
        return (
            IncidentService._parse_dt(alert.get("event_timestamp"))
            or IncidentService._parse_dt(alert.get("created_at"))
            or datetime.now(timezone.utc)
        )

    @staticmethod
    def _dedup_key(alert):
        parts = [
            str(alert.get("external_alert_id") or alert.get("alert_id") or ""),
            str(alert.get("rule_id") or ""),
            str(alert.get("agent_id") or alert.get("agent_name") or ""),
            str(alert.get("source_ip") or ""),
            str(alert.get("event_timestamp") or alert.get("created_at") or ""),
        ]
        raw = "|".join(parts)
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _correlation_key(alert):
        host = IncidentService._normalize_str(alert.get("agent_name") or alert.get("agent_id"))
        user = IncidentService._normalize_str(
            alert.get("user")
            or alert.get("username")
            or alert.get("dstuser")
            or alert.get("srcuser")
        )
        source_ip = IncidentService._normalize_str(alert.get("source_ip"))
        rule_family = IncidentService._rule_family(alert)
        return host, user, source_ip, rule_family

    @staticmethod
    def _severity_rank(severity):
        mapping = {"NORMAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return mapping.get(str(severity or "").upper(), 0)

    @staticmethod
    def _incident_title(incident):
        dims = incident["dimensions"]
        return (
            f"{dims['rule_family']} on host={dims['host']} "
            f"user={dims['user']} source_ip={dims['source_ip']}"
        )

    @staticmethod
    def _build_incident_payload(raw, window_seconds):
        dims = raw["dimensions"]
        dedup_set = raw["dedup_keys"]
        alerts = raw["alerts"]

        first_seen = raw["first_seen"]
        last_seen = raw["last_seen"]
        max_sev = raw["max_severity"]
        avg_conf = (sum(raw["confidences"]) / len(raw["confidences"])) if raw["confidences"] else 0.0

        stable_source = (
            f"{dims['host']}|{dims['user']}|{dims['source_ip']}|{dims['rule_family']}|{first_seen.isoformat()}"
        )
        incident_id = "inc_" + hashlib.sha1(stable_source.encode("utf-8")).hexdigest()[:16]

        correlation_reason = "Grouped by host, user, source IP, and rule family in sliding window"
        if dims["rule_family"] == "AUTH_FAILURE" and len(dedup_set) >= 10:
            correlation_reason = (
                f"Potential password spray/brute force: {len(dedup_set)} unique auth-failure alerts "
                f"within {window_seconds // 60} minutes"
            )

        return {
            "id": incident_id,
            "status": "NEW",
            "title": IncidentService._incident_title(raw),
            "severity": max_sev,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "window_seconds": window_seconds,
            "alerts_count": len(raw["alert_ids"]),
            "unique_events": len(dedup_set),
            "needs_review_count": raw["needs_review_count"],
            "avg_confidence": round(avg_conf, 2),
            "correlation_reason": correlation_reason,
            "dimensions": dims,
            "alert_ids": raw["alert_ids"][:200],
            "sample_alerts": alerts[:5],
        }

    @staticmethod
    def list_incidents(filters=None):
        filters = filters or {}
        window_seconds = int(filters.get("window_seconds") or 300)
        if window_seconds < 60:
            window_seconds = 60
        if window_seconds > 3600:
            window_seconds = 3600

        alert_limit = int(filters.get("alert_limit") or 1000)
        if alert_limit < 50:
            alert_limit = 50
        if alert_limit > 5000:
            alert_limit = 5000

        incident_limit = int(filters.get("incident_limit") or 300)
        if incident_limit < 10:
            incident_limit = 10
        if incident_limit > 1000:
            incident_limit = 1000

        alert_filters = {
            "status": filters.get("status"),
            "severity": filters.get("severity"),
            "assigned_to": filters.get("assigned_to"),
            "source": filters.get("source"),
            "start_date": filters.get("start_date"),
            "end_date": filters.get("end_date"),
            "search": filters.get("search"),
            "limit": alert_limit,
        }

        alerts = supabase_client.get_alerts_filtered(alert_filters) or []
        normalized = [a for a in alerts if isinstance(a, dict)]
        normalized.sort(key=IncidentService._event_time)

        active = []
        closed = []
        for alert in normalized:
            event_time = IncidentService._event_time(alert)
            key = IncidentService._correlation_key(alert)
            dedup_key = IncidentService._dedup_key(alert)

            matched = None
            for group in active:
                if group["key"] != key:
                    continue
                if event_time - group["last_seen"] <= timedelta(seconds=window_seconds):
                    matched = group
                    break

            if not matched:
                matched = {
                    "key": key,
                    "dimensions": {
                        "host": key[0],
                        "user": key[1],
                        "source_ip": key[2],
                        "rule_family": key[3],
                    },
                    "first_seen": event_time,
                    "last_seen": event_time,
                    "dedup_keys": set(),
                    "alert_ids": [],
                    "alerts": [],
                    "confidences": [],
                    "needs_review_count": 0,
                    "max_severity": "NORMAL",
                }
                active.append(matched)

            matched["last_seen"] = max(matched["last_seen"], event_time)
            if dedup_key not in matched["dedup_keys"]:
                matched["dedup_keys"].add(dedup_key)
                alert_id = alert.get("id") or alert.get("external_alert_id") or alert.get("alert_id")
                if alert_id:
                    matched["alert_ids"].append(str(alert_id))
                matched["alerts"].append({
                    "id": alert_id,
                    "rule_id": alert.get("rule_id"),
                    "rule_description": alert.get("rule_description") or alert.get("title"),
                    "severity_final": alert.get("severity_final") or alert.get("severity"),
                    "source_ip": alert.get("source_ip"),
                    "agent_name": alert.get("agent_name"),
                    "created_at": alert.get("created_at") or alert.get("event_timestamp"),
                })

            confidence = alert.get("confidence")
            if isinstance(confidence, (int, float)):
                matched["confidences"].append(float(confidence))

            if alert.get("needs_review"):
                matched["needs_review_count"] += 1

            severity = str(alert.get("severity_final") or alert.get("severity") or "NORMAL").upper()
            if IncidentService._severity_rank(severity) > IncidentService._severity_rank(matched["max_severity"]):
                matched["max_severity"] = severity

            still_active = []
            for group in active:
                if event_time - group["last_seen"] <= timedelta(seconds=window_seconds):
                    still_active.append(group)
                else:
                    closed.append(group)
            active = still_active

        all_groups = closed + active
        incidents = [IncidentService._build_incident_payload(group, window_seconds) for group in all_groups]
        if incidents:
            state_map = supabase_client.get_incident_state_map([inc.get("id") for inc in incidents])
            for incident in incidents:
                incident_id = incident.get("id")
                incident["status"] = state_map.get(incident_id, "NEW")

        incidents.sort(
            key=lambda x: (
                IncidentService._severity_rank(x.get("severity")),
                x.get("unique_events", 0),
                x.get("last_seen", ""),
            ),
            reverse=True,
        )

        status_filter = normalize_incident_status(filters.get("incident_status"))
        if status_filter:
            incidents = [inc for inc in incidents if normalize_incident_status(inc.get("status")) == status_filter]

        return incidents[:incident_limit]

    @staticmethod
    def update_incident_status(incident_id, new_status):
        incident_id = str(incident_id or "").strip()
        if not incident_id:
            return None, {"error": "Invalid incident id"}, 400

        target = normalize_incident_status(new_status)
        if not is_valid_incident_status(target):
            return None, {
                "error": "Invalid incident status",
                "details": "Allowed values: NEW, TRIAGED, CONTAINED, RESOLVED",
            }, 400

        state_map = supabase_client.get_incident_state_map([incident_id])
        current = state_map.get(incident_id, "NEW")

        if current == target:
            return {"id": incident_id, "status": current}, None, 200
        if not can_transition_incident(current, target):
            return None, {
                "error": "Invalid transition",
                "details": f"Cannot transition incident from {current} to {target}",
            }, 400

        persisted = supabase_client.set_incident_state(incident_id, target)
        if not persisted:
            return None, {"error": "Persistence failed", "details": "Could not update incident status"}, 500

        return {"id": incident_id, "status": target}, None, 200
