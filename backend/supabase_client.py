from config import SUPABASE_URL, SUPABASE_KEY, SUPABASE_SERVICE_KEY
import json
import os
import uuid
from datetime import datetime
from threading import Lock
from flask_bcrypt import Bcrypt
from flask import current_app

# _bcrypt will be set when app is initialized
_bcrypt = None

_client = None
_service_client = None
_enabled = False
_init_lock = Lock()

# In-memory user store for development (when Supabase is not configured)
_dev_users_db = {}
_dev_users_by_email = {}
_dev_comments_db = []
_dev_alerts_db = {}
_dev_api_keys_db = {}
_dev_feedback_db = []
_dev_model_versions_db = []
_dev_audit_logs_db = []
_last_api_key_db_error = ""
_runtime_alerts_cache = []
_runtime_vulns_cache = []
_MAX_RUNTIME_CACHE = 2000
_RUNTIME_CACHE_DIR = os.path.join(os.path.dirname(__file__), ".runtime_cache")
_RUNTIME_ALERTS_FILE = os.path.join(_RUNTIME_CACHE_DIR, "alerts.jsonl")
_RUNTIME_VULNS_FILE = os.path.join(_RUNTIME_CACHE_DIR, "vulns.jsonl")
_RUNTIME_INCIDENT_STATES_FILE = os.path.join(_RUNTIME_CACHE_DIR, "incident_states.jsonl")
_RUNTIME_FEEDBACK_FILE = os.path.join(_RUNTIME_CACHE_DIR, "feedback.jsonl")
_RUNTIME_MODEL_VERSIONS_FILE = os.path.join(_RUNTIME_CACHE_DIR, "model_versions.jsonl")
_RUNTIME_AUDIT_LOGS_FILE = os.path.join(_RUNTIME_CACHE_DIR, "audit_logs.jsonl")

def _init_dev_alerts():
    """Initialize development sample alerts"""
    global _dev_alerts_db
    if _dev_alerts_db:
        return
    
    sample_alerts = [
        {
            "id": "1775458515.0",
            "rule": "Citrix ADC Remote Code Execution (CVE-2023-4966)",
            "description": "Possible Citrix ADC Buffer Overflow Exploit Attempt",
            "full_log": "2023 Oct 24 14:32:15 172.17.0.1->172.17.0.2 Alert: CVE-2023-4966: Buffer overflow in Citrix ADC",
            "severity_final": "High",
            "status": "OPEN",
            "source": "wazuh",
            "manager": "test-manager",
            "agent": "test-agent",
            "created_at": "2023-10-24T14:32:15.000Z",
        },
        {
            "id": "1775458516.0",
            "rule": "SSH Brute Force Attempt",
            "description": "Multiple failed SSH login attempts detected",
            "full_log": "2023 Oct 24 14:35:22 192.168.1.100->10.0.0.5 Failed SSH login: user=root attempts=50",
            "severity_final": "Medium",
            "status": "OPEN",
            "source": "wazuh",
            "manager": "test-manager",
            "agent": "test-agent",
            "created_at": "2023-10-24T14:35:22.000Z",
        },
        {
            "id": "1775458517.0",
            "rule": "Potential DDoS Attack",
            "description": "Abnormal traffic volume detected",
            "full_log": "2023 Oct 24 14:40:00 10.0.0.1 -> 10.0.0.2 High traffic: 5000 packets/sec",
            "severity_final": "Critical",
            "status": "OPEN",
            "source": "wazuh",
            "manager": "test-manager",
            "agent": "test-agent",
            "created_at": "2023-10-24T14:40:00.000Z",
        },
    ]
    for alert in sample_alerts:
        _dev_alerts_db[alert["id"]] = alert
    print("Development alerts initialized")

def _init_dev_users():
    """Initialize fallback users from environment variables or defaults."""
    global _dev_users_db, _dev_users_by_email
    if _dev_users_db:  # Already initialized
        return

    dev_manager_email = (os.getenv("DEV_MANAGER_EMAIL") or "admin@soc.local").strip().lower()
    dev_manager_password = os.getenv("DEV_MANAGER_PASSWORD") or "Admin@SOC2024!"
    dev_manager_name = (os.getenv("DEV_MANAGER_NAME") or "SOC Manager").strip() or "SOC Manager"

    dev_analyst_email = (os.getenv("DEV_ANALYST_EMAIL") or "analyst@soc.local").strip().lower()
    dev_analyst_password = os.getenv("DEV_ANALYST_PASSWORD") or "Analyst@SOC2024!"
    dev_analyst_name = (os.getenv("DEV_ANALYST_NAME") or "SOC Analyst").strip() or "SOC Analyst"

    users_to_seed = [
        {
            "name": dev_manager_name,
            "email": dev_manager_email,
            "password": dev_manager_password,
            "role": "SOC_MANAGER",
            "soc_level_tier": "MANAGER",
        },
        {
            "name": dev_analyst_name,
            "email": dev_analyst_email,
            "password": dev_analyst_password,
            "role": "SOC_ANALYST",
            "soc_level_tier": "L1",
        },
    ]

    _dev_users_db = {}
    _dev_users_by_email = {}

    for idx, seeded_user in enumerate(users_to_seed, start=1):
        user_id = str(idx)
        user_row = {
            "id": user_id,
            "name": seeded_user["name"],
            "email": seeded_user["email"],
            "password": _bcrypt.generate_password_hash(seeded_user["password"]).decode("utf-8") if _bcrypt else seeded_user["password"],
            "role": seeded_user["role"],
            "soc_level_tier": seeded_user["soc_level_tier"],
            "is_active": True,
            "created_at": datetime.now().isoformat(),
        }
        _dev_users_db[user_id] = user_row
        _dev_users_by_email[user_row["email"]] = user_id

    print(f"Fallback users initialized: {[u['email'] for u in users_to_seed]}")


def init_bcrypt(app):
    global _bcrypt
    _bcrypt = Bcrypt(app)

def _init():
    global _client, _service_client, _enabled
    if _client is not None or _enabled:
        return

    with _init_lock:
        if _client is not None or _enabled:
            return

        if (
            SUPABASE_URL
            and SUPABASE_KEY
            and "xxxx" not in SUPABASE_URL
            and "xxxx" not in SUPABASE_KEY
        ):
            try:
                from supabase import create_client

                url = SUPABASE_URL.strip()
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url

                _client = create_client(url, SUPABASE_KEY)

                service_key = (SUPABASE_SERVICE_KEY or "").strip()
                if service_key and not service_key.startswith("sb_publishable_") and service_key != SUPABASE_KEY:
                    _service_client = create_client(url, service_key)
                    print("Supabase connected with write access")
                else:
                    _service_client = None
                    if service_key.startswith("sb_publishable_"):
                        print("Supabase connected without service_role key; writes will use SUPABASE_KEY and may fail if RLS blocks them. Use a service_role key for guaranteed server writes.")
                    else:
                        print("Supabase connected without SUPABASE_SERVICE_KEY; writes will use SUPABASE_KEY and may fail if RLS blocks them")

                _enabled = True
            except OSError as e:
                if 'getaddrinfo' in str(e) or 'Name or service not known' in str(e):
                    print(f"Supabase connection failed: Unable to resolve hostname. Check SUPABASE_URL. Error: {e}")
                else:
                    print(f"Supabase connection failed: Network error - {e}")
                _enabled = False
            except Exception as e:
                print(f"Supabase init failed: {e}")
                _enabled = False
        else:
            print("Supabase not configured — running without DB")


def is_enabled():
    _init()
    return _enabled


def _safe_float(value):
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value):
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_alert_row(row):
    """Map predictor output into the alerts table schema."""
    severity = (row.get("severity_final") or row.get("severity_pred") or row.get("severity") or "").upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        severity = None

    status = (row.get("status") or "OPEN").upper()
    if status not in {"OPEN", "IN_PROGRESS", "RESOLVED"}:
        status = "OPEN"

    source_tool = row.get("source_tool") or row.get("source")
    title = row.get("title") or row.get("rule_description") or row.get("rule") or "Security Alert"
    description = row.get("description") or row.get("full_log") or row.get("rule_description")

    return {
        "title": title,
        "description": description,
        "source_tool": source_tool,
        "severity": severity,
        "status": status,
        "risk_score": _safe_float(row.get("risk_score")),
        "model_used": row.get("model_used"),
        "severity_pred": row.get("severity_pred") or row.get("severity"),
        "severity_final": row.get("severity_final") or row.get("severity"),
        "confidence": _safe_float(row.get("confidence")),
        "hybrid_override": bool(row.get("hybrid_override", False)),
        "needs_review": bool(row.get("needs_review", False)),
        "attack_category": row.get("attack_category"),
        "attack_confidence": _safe_float(row.get("attack_confidence")),
        "rule_level": _safe_int(row.get("rule_level")),
        "rule_id": row.get("rule_id"),
        "rule_description": row.get("rule_description") or row.get("rule"),
        "agent_name": row.get("agent_name") or row.get("agent"),
        "agent_id": row.get("agent_id"),
        "agent_ip": row.get("agent_ip"),
        "source_ip": row.get("source_ip"),
        "event_timestamp": row.get("event_timestamp"),
        "decoder_name": row.get("decoder_name"),
        "firedtimes": _safe_int(row.get("firedtimes")),
        # Keep original external source identifier for traceability.
        "external_alert_id": row.get("alert_id") or row.get("id"),
        "mitre_tactic": row.get("mitre_tactic"),
        "mitre_technique": row.get("mitre_technique"),
        "mitre_id": row.get("mitre_id"),
        "soc_level_tier": row.get("soc_level_tier"),
        "soc_level_label": row.get("soc_level_label"),
        "soc_level_range": row.get("soc_level_range"),
        "soc_level_band": row.get("soc_level_band"),
        "soc_level_description": row.get("soc_level_description"),
        "soc_immediate_action": bool(row.get("soc_immediate_action", False)),
    }


def _present_alert_row(row):
    if not row:
        return row
    external_id = row.get("external_alert_id")
    if external_id and not row.get("alert_id"):
        row["alert_id"] = external_id
    return row


def _cache_runtime_alerts(rows):
    if not rows:
        return
    prepared = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        entry = dict(row)
        if not entry.get("id"):
            entry["id"] = entry.get("external_alert_id") or entry.get("alert_id") or str(uuid.uuid4())
        prepared.append(_present_alert_row(entry))

    if not prepared:
        return

    _runtime_alerts_cache.extend(prepared)
    if len(_runtime_alerts_cache) > _MAX_RUNTIME_CACHE:
        del _runtime_alerts_cache[:-_MAX_RUNTIME_CACHE]
    _append_runtime_rows(_RUNTIME_ALERTS_FILE, prepared)


def _cache_runtime_vulns(rows):
    if not rows:
        return

    prepared = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        entry = dict(row)
        if not entry.get("id"):
            entry["id"] = str(uuid.uuid4())
        prepared.append(entry)

    if not prepared:
        return

    _runtime_vulns_cache.extend(prepared)
    if len(_runtime_vulns_cache) > _MAX_RUNTIME_CACHE:
        del _runtime_vulns_cache[:-_MAX_RUNTIME_CACHE]
    _append_runtime_rows(_RUNTIME_VULNS_FILE, prepared)


def _ensure_runtime_cache_dir():
    try:
        os.makedirs(_RUNTIME_CACHE_DIR, exist_ok=True)
    except Exception:
        return False
    return True


def _append_runtime_rows(file_path, rows):
    if not rows:
        return
    if not _ensure_runtime_cache_dir():
        return
    try:
        with open(file_path, "a", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=True, default=str))
                handle.write("\n")
    except Exception:
        return


def _read_runtime_rows(file_path, limit=500):
    if limit <= 0:
        return []
    if not os.path.exists(file_path):
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except Exception:
        return []

    rows = []
    for line in reversed(lines):
        text = line.strip()
        if not text:
            continue
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                rows.append(parsed)
            if len(rows) >= limit:
                break
        except Exception:
            continue
    return rows


def _read_runtime_incident_state_map():
    rows = _read_runtime_rows(_RUNTIME_INCIDENT_STATES_FILE, limit=5000)
    state_map = {}
    for row in reversed(rows):
        incident_id = str(row.get("incident_id") or "").strip()
        status = str(row.get("status") or "").strip().upper()
        if incident_id and status:
            state_map[incident_id] = status
    return state_map


def _merge_alert_rows(primary_rows, fallback_rows, limit):
    seen = set()
    merged = []

    for row in (primary_rows or []):
        key = row.get("id") or row.get("external_alert_id") or row.get("alert_id")
        key = key or str(uuid.uuid4())
        if key in seen:
            continue
        seen.add(key)
        merged.append(_present_alert_row(dict(row)))
        if len(merged) >= limit:
            return merged

    for row in reversed(fallback_rows or []):
        key = row.get("id") or row.get("external_alert_id") or row.get("alert_id")
        key = key or str(uuid.uuid4())
        if key in seen:
            continue
        seen.add(key)
        merged.append(_present_alert_row(dict(row)))
        if len(merged) >= limit:
            break

    return merged


def _merge_vuln_rows(primary_rows, fallback_rows, limit):
    seen = set()
    merged = []

    for row in (primary_rows or []):
        key = row.get("id") or row.get("cve_id")
        key = key or str(uuid.uuid4())
        if key in seen:
            continue
        seen.add(key)
        merged.append(dict(row))
        if len(merged) >= limit:
            return merged

    for row in reversed(fallback_rows or []):
        key = row.get("id") or row.get("cve_id")
        key = key or str(uuid.uuid4())
        if key in seen:
            continue
        seen.add(key)
        merged.append(dict(row))
        if len(merged) >= limit:
            break

    return merged


def save_alerts(results):
    _init()
    payload = [_normalize_alert_row(r) for r in (results or []) if isinstance(r, dict)]
    if not payload:
        return

    # Always keep a runtime cache so /api/dashboard can show recent n8n analyses
    # even when Supabase writes fail or service-role is not configured.
    _cache_runtime_alerts(payload)

    writer = _service_client or _client
    if not _enabled or not writer:
        if _enabled and not _service_client:
            print("Supabase save_alerts fallback: no service key, using runtime cache only")
        return

    try:
        writer.table("alerts").insert(payload).execute()
    except Exception as e:
        print(f"Supabase save_alerts error: {e}")


def save_vulnerabilities(results):
    _init()
    payload = [r for r in (results or []) if isinstance(r, dict)]
    if not payload:
        return

    _cache_runtime_vulns(payload)

    writer = _service_client or _client
    if not _enabled or not writer:
        if _enabled and not _service_client:
            print("Supabase save_vulnerabilities fallback: no service key, using runtime cache only")
        return

    try:
        writer.table("vulnerabilities").insert(payload).execute()
    except Exception as e:
        print(f"Supabase save_vulnerabilities error: {e}")


def save_low_confidence(items):
    _init()
    if not _enabled or not _service_client:
        if _enabled and not _service_client:
            print("Supabase save_low_confidence skipped: SUPABASE_SERVICE_KEY is not configured")
        return
    try:
        _service_client.table("low_confidence_items").insert(items).execute()
    except Exception as e:
        print(f"Supabase save_low_confidence error: {e}")


def get_alerts(limit=500):
    _init()
    file_rows = _read_runtime_rows(_RUNTIME_ALERTS_FILE, limit=limit)
    if not _enabled:
        return _merge_alert_rows([], [*file_rows, *_runtime_alerts_cache], limit)

    try:
        res = _client.table("alerts").select("*").limit(limit).execute()
        return _merge_alert_rows(res.data or [], [*file_rows, *_runtime_alerts_cache], limit)
    except Exception:
        return _merge_alert_rows([], [*file_rows, *_runtime_alerts_cache], limit)


def get_vulnerabilities(limit=500):
    _init()
    file_rows = _read_runtime_rows(_RUNTIME_VULNS_FILE, limit=limit)
    if not _enabled:
        return _merge_vuln_rows([], [*file_rows, *_runtime_vulns_cache], limit)

    try:
        res = _client.table("vulnerabilities").select("*").limit(limit).execute()
        return _merge_vuln_rows(res.data or [], [*file_rows, *_runtime_vulns_cache], limit)
    except Exception:
        return _merge_vuln_rows([], [*file_rows, *_runtime_vulns_cache], limit)


def get_low_confidence(limit=200):
    _init()
    if not _enabled:
        return []
    try:
        res = _client.table("low_confidence_items").select("*").limit(limit).execute()
        return res.data or []
    except Exception:
        return []


def get_dashboard_stats():
    _init()
    if not _enabled:
        return {}
    try:
        alerts = _client.table("alerts").select("severity_final", count="exact").execute()
        return {"total_alerts": alerts.count or 0}
    except Exception:
        return {}


def create_user(user_data):
    _init()
    if not _enabled:
        # Development mode: store in memory
        _init_dev_users()
        user_id = str(uuid.uuid4())
        user_record = {
            "id": user_id,
            "name": user_data.get("name", ""),
            "email": user_data.get("email", ""),
            "password": user_data.get("password", ""),
            "role": user_data.get("role", "SOC_ANALYST"),
            "soc_level_tier": user_data.get("soc_level_tier", "L1"),
            "is_active": True,
            "created_at": datetime.now().isoformat()
        }
        _dev_users_db[user_id] = user_record
        _dev_users_by_email[user_data.get("email", "")] = user_id
        print(f"User created in dev mode: {user_data.get('email')}")
        return [user_record]
    try:
        # Use service client to bypass RLS
        if _service_client:
            res = _service_client.table("users").insert(user_data).execute()
        else:
            res = _client.table("users").insert(user_data).execute()
        return res.data
    except OSError as e:
        if 'getaddrinfo' in str(e):
            raise Exception("Failed to create user: Unable to connect to Supabase. Check your internet connection and SUPABASE_URL configuration.")
        raise Exception(f"Failed to create user: Network error - {str(e)}")
    except Exception as e:
        raise Exception(f"Failed to create user: {str(e)}")


def get_user_by_email(email):
    _init()
    if not _enabled:
        # Development mode: look up in memory
        _init_dev_users()
        user_id = _dev_users_by_email.get(email)
        if user_id and user_id in _dev_users_db:
            return _dev_users_db[user_id]
        return None
    try:
        if _service_client:
            res = _service_client.table("users").select("*").eq("email", email).execute()
        else:
            res = _client.table("users").select("*").eq("email", email).execute()
        if res.data:
            return res.data[0]
        # Dev fallback if Supabase user does not exist.
        _init_dev_users()
        dev_user_id = _dev_users_by_email.get(email)
        if dev_user_id and dev_user_id in _dev_users_db:
            return _dev_users_db[dev_user_id]
        return None
    except Exception:
        _init_dev_users()
        dev_user_id = _dev_users_by_email.get(email)
        if dev_user_id and dev_user_id in _dev_users_db:
            return _dev_users_db[dev_user_id]
        return None


def get_user_by_id(user_id):
    _init()
    if not _enabled:
        # Development mode: look up in memory
        _init_dev_users()
        if user_id in _dev_users_db:
            user = _dev_users_db[user_id]
            return {
                "id": str(user.get("id")),
                "name": user.get("name"),
                "email": user.get("email"),
                "role": user.get("role"),
                "soc_level_tier": user.get("soc_level_tier")
            }
        return None
    try:
        if _service_client:
            res = _service_client.table("users").select("id", "name", "email", "role", "soc_level_tier").eq("id", user_id).execute()
        else:
            res = _client.table("users").select("id", "name", "email", "role", "soc_level_tier").eq("id", user_id).execute()
        if res.data:
            return res.data[0]
        # Dev fallback for stale tokens/local development.
        _init_dev_users()
        if user_id in _dev_users_db:
            user = _dev_users_db[user_id]
            return {
                "id": str(user.get("id")),
                "name": user.get("name"),
                "email": user.get("email"),
                "role": user.get("role"),
                "soc_level_tier": user.get("soc_level_tier")
            }
        return None
    except Exception:
        _init_dev_users()
        if user_id in _dev_users_db:
            user = _dev_users_db[user_id]
            return {
                "id": user.get("id"),
                "name": user.get("name"),
                "email": user.get("email"),
                "role": user.get("role"),
                "soc_level_tier": user.get("soc_level_tier")
            }
        return None


def get_users_by_role(role):
    _init()
    if not _enabled:
        return []
    try:
        if _service_client:
            res = _service_client.table("users").select("id", "name", "email", "role", "created_at").eq("role", role).execute()
        else:
            res = _client.table("users").select("id", "name", "email", "role", "created_at").eq("role", role).execute()
        return res.data or []
    except Exception:
        return []


def get_all_soc_users():
    _init()
    if not _enabled:
        # Development mode: return all users from memory
        _init_dev_users()
        users = []
        for user_id, user in _dev_users_db.items():
            if user.get("role") in ["SOC_MANAGER", "SOC_ANALYST"]:
                users.append({
                    "id": user.get("id"),
                    "name": user.get("name"),
                    "email": user.get("email"),
                    "role": user.get("role"),
                    "soc_level_tier": user.get("soc_level_tier"),
                    "is_active": user.get("is_active"),
                    "created_at": user.get("created_at")
                })
        return users
    try:
        if _service_client:
            res = _service_client.table("users").select("id", "name", "email", "role", "soc_level_tier", "is_active", "created_at").in_("role", ["SOC_MANAGER", "SOC_ANALYST"]).execute()
        else:
            res = _client.table("users").select("id", "name", "email", "role", "soc_level_tier", "is_active", "created_at").in_("role", ["SOC_MANAGER", "SOC_ANALYST"]).execute()
        if res.data:
            return res.data
        _init_dev_users()
        return [
            {
                "id": u.get("id"),
                "name": u.get("name"),
                "email": u.get("email"),
                "role": u.get("role"),
                "soc_level_tier": u.get("soc_level_tier"),
                "is_active": u.get("is_active"),
                "created_at": u.get("created_at"),
            }
            for u in _dev_users_db.values()
            if u.get("role") in ["SOC_MANAGER", "SOC_ANALYST"]
        ]
    except Exception:
        _init_dev_users()
        return [
            {
                "id": u.get("id"),
                "name": u.get("name"),
                "email": u.get("email"),
                "role": u.get("role"),
                "soc_level_tier": u.get("soc_level_tier"),
                "is_active": u.get("is_active"),
                "created_at": u.get("created_at"),
            }
            for u in _dev_users_db.values()
            if u.get("role") in ["SOC_MANAGER", "SOC_ANALYST"]
        ]


def delete_user(user_id):
    _init()
    if not _enabled:
        raise Exception("Supabase not configured")
    try:
        if _service_client:
            res = _service_client.table("users").delete().eq("id", user_id).execute()
        else:
            res = _client.table("users").delete().eq("id", user_id).execute()
        return res.data
    except Exception as e:
        raise Exception(f"Failed to delete user: {str(e)}")


def update_user_status(user_id, is_active):
    _init()
    if not _enabled:
        raise Exception("Supabase not configured")
    try:
        if _service_client:
            res = _service_client.table("users").update({"is_active": is_active}).eq("id", user_id).execute()
        else:
            res = _client.table("users").update({"is_active": is_active}).eq("id", user_id).execute()
        return res.data
    except Exception as e:
        raise Exception(f"Failed to update user status: {str(e)}")


def _get_db_client():
    if _service_client is not None:
        return _service_client
    return _client


def _user_name_map(user_ids):
    _init()
    ids = [uid for uid in set(user_ids or []) if uid]
    if not ids:
        return {}

    if not _enabled:
        _init_dev_users()
        return {uid: _dev_users_db.get(uid, {}).get("name", "Unknown") for uid in ids}

    try:
        db = _get_db_client()
        res = db.table("users").select("id,name").in_("id", ids).execute()
        return {u.get("id"): u.get("name", "Unknown") for u in (res.data or [])}
    except Exception:
        return {}


def get_alert_by_id(alert_id):
    _init()
    if not _enabled:
        _init_dev_alerts()
        alert = _dev_alerts_db.get(str(alert_id))
        if alert:
            assigned_to = alert.get("assigned_to")
            if assigned_to:
                alert["assigned_analyst_name"] = _user_name_map([assigned_to]).get(assigned_to)
        return alert

    try:
        db = _get_db_client()
        res = db.table("alerts").select("*").eq("id", alert_id).limit(1).execute()
        alert = res.data[0] if res.data else None
        if not alert:
            res = db.table("alerts").select("*").eq("external_alert_id", str(alert_id)).limit(1).execute()
            alert = res.data[0] if res.data else None
        if not alert:
            return None
        alert = _present_alert_row(alert)

        assigned_to = alert.get("assigned_to")
        if assigned_to:
            name_map = _user_name_map([assigned_to])
            alert["assigned_analyst_name"] = name_map.get(assigned_to)
        return alert
    except Exception:
        return None


def get_alerts_filtered(filters=None):
    _init()
    if not _enabled:
        _init_dev_alerts()
        filters = filters or {}
        status = filters.get("status")
        severity = filters.get("severity")
        
        alerts = list(_dev_alerts_db.values())
        
        if status:
            alerts = [a for a in alerts if a.get("status") == status.upper()]
        if severity:
            alerts = [a for a in alerts if a.get("severity_final") == severity]
        
        return alerts[: filters.get("limit", 200)]

    filters = filters or {}

    try:
        db = _get_db_client()
        query = db.table("alerts").select("*")

        status = filters.get("status")
        severity = filters.get("severity")
        assigned_to = filters.get("assigned_to")
        source = filters.get("source")
        start_date = filters.get("start_date")
        end_date = filters.get("end_date")
        search = filters.get("search")
        limit = filters.get("limit") or 200

        if status:
            query = query.eq("status", str(status).upper())
        if severity:
            query = query.eq("severity_final", severity)
        if assigned_to:
            query = query.eq("assigned_to", assigned_to)
        if source:
            query = query.ilike("source_tool", f"%{source}%")
        if start_date:
            query = query.gte("created_at", start_date)
        if end_date:
            query = query.lte("created_at", end_date)
        if search:
            # Search over common SOC fields (fallback to rule description only if DB policy blocks OR).
            query = query.or_(
                f"rule_description.ilike.%{search}%,"
                f"external_alert_id.ilike.%{search}%,"
                f"source_ip.ilike.%{search}%,"
                f"agent_name.ilike.%{search}%"
            )

        res = query.order("created_at", desc=True).limit(limit).execute()
        alerts = res.data or []
        alerts = [_present_alert_row(a) for a in alerts]

        assigned_ids = [a.get("assigned_to") for a in alerts if a.get("assigned_to")]
        name_map = _user_name_map(assigned_ids)
        for alert in alerts:
            aid = alert.get("assigned_to")
            if aid:
                alert["assigned_analyst_name"] = name_map.get(aid)

        return alerts
    except Exception:
        return []


def update_alert_fields(alert_id, fields):
    _init()
    if not _enabled:
        _init_dev_alerts()
        alert_id_str = str(alert_id)
        if alert_id_str in _dev_alerts_db:
            _dev_alerts_db[alert_id_str].update(fields)
            alert = _dev_alerts_db[alert_id_str]
            if alert.get("assigned_to"):
                alert["assigned_analyst_name"] = _user_name_map([alert["assigned_to"]]).get(alert["assigned_to"])
            return alert
        return None

    try:
        db = _get_db_client()
        res = db.table("alerts").update(fields).eq("id", alert_id).execute()
        if not res.data:
            res = db.table("alerts").update(fields).eq("external_alert_id", str(alert_id)).execute()
        if res.data:
            return res.data[0]
        return get_alert_by_id(alert_id)
    except Exception:
        return None


def get_comments_by_alert_id(alert_id):
    _init()
    if not _enabled:
        _init_dev_users()
        comments = [c for c in _dev_comments_db if c.get("alert_id") == alert_id]
        name_map = _user_name_map([c.get("user_id") for c in comments])
        for c in comments:
            c["user_name"] = name_map.get(c.get("user_id"), "Unknown")
        return comments

    try:
        db = _get_db_client()
        res = db.table("alert_comments").select("*").eq("alert_id", alert_id).order("created_at", desc=False).execute()
        comments = res.data or []
        name_map = _user_name_map([c.get("user_id") for c in comments])
        for c in comments:
            c["user_name"] = name_map.get(c.get("user_id"), "Unknown")
        return comments
    except Exception:
        return []


def add_comment(payload):
    _init()
    if not _enabled:
        record = {
            "id": str(uuid.uuid4()),
            "alert_id": payload.get("alert_id"),
            "user_id": payload.get("user_id"),
            "comment": payload.get("comment"),
            "created_at": payload.get("created_at") or datetime.utcnow().isoformat(),
        }
        _dev_comments_db.append(record)
        record["user_name"] = _user_name_map([record.get("user_id")]).get(record.get("user_id"), "Unknown")
        return record

    try:
        db = _get_db_client()
        res = db.table("alert_comments").insert(payload).execute()
        if not res.data:
            return None
        record = res.data[0]
        record["user_name"] = _user_name_map([record.get("user_id")]).get(record.get("user_id"), "Unknown")
        return record
    except Exception:
        return None


def get_comment_by_id(comment_id):
    _init()
    if not _enabled:
        for c in _dev_comments_db:
            if c.get("id") == comment_id:
                return c
        return None

    try:
        db = _get_db_client()
        res = db.table("alert_comments").select("*").eq("id", comment_id).limit(1).execute()
        return res.data[0] if res.data else None
    except Exception:
        return None


def delete_comment(comment_id):
    _init()
    if not _enabled:
        idx = next((i for i, c in enumerate(_dev_comments_db) if c.get("id") == comment_id), None)
        if idx is None:
            return False
        _dev_comments_db.pop(idx)
        return True

    try:
        db = _get_db_client()
        db.table("alert_comments").delete().eq("id", comment_id).execute()
        return True
    except Exception:
        return False


def get_incident_state_map(incident_ids=None):
    _init()
    ids = [str(i).strip() for i in (incident_ids or []) if str(i).strip()]
    fallback_map = _read_runtime_incident_state_map()

    if not _enabled:
        if not ids:
            return fallback_map
        return {incident_id: fallback_map.get(incident_id, "NEW") for incident_id in ids}

    try:
        db = _get_db_client()
        query = db.table("incident_states").select("incident_id,status")
        if ids:
            query = query.in_("incident_id", ids)
        else:
            query = query.limit(5000)

        res = query.execute()
        data = res.data or []
        db_map = {}
        for row in data:
            incident_id = str(row.get("incident_id") or "").strip()
            status = str(row.get("status") or "").strip().upper()
            if incident_id and status:
                db_map[incident_id] = status

        # Merge runtime fallback for entries not yet persisted.
        merged = {**fallback_map, **db_map}
        if not ids:
            return merged
        return {incident_id: merged.get(incident_id, "NEW") for incident_id in ids}
    except Exception:
        if not ids:
            return fallback_map
        return {incident_id: fallback_map.get(incident_id, "NEW") for incident_id in ids}


def set_incident_state(incident_id, status):
    _init()
    incident_id = str(incident_id or "").strip()
    status = str(status or "").strip().upper()
    if not incident_id or not status:
        return False

    payload = {
        "incident_id": incident_id,
        "status": status,
        "updated_at": datetime.utcnow().isoformat(),
    }

    # Always write runtime fallback so status survives restarts without DB.
    _append_runtime_rows(_RUNTIME_INCIDENT_STATES_FILE, [payload])

    if not _enabled:
        return True

    try:
        db = _get_db_client()
        db.table("incident_states").upsert(payload, on_conflict="incident_id").execute()
        return True
    except Exception:
        return True


def create_integration_api_key(record):
    """Persist a hashed integration API key record."""
    global _last_api_key_db_error
    _init()
    if not _enabled:
        _dev_api_keys_db[record.get("id")] = dict(record)
        _last_api_key_db_error = ""
        return _dev_api_keys_db[record.get("id")]

    try:
        db = _get_db_client()
        res = db.table("integration_api_keys").insert(record).execute()
        if res.data:
            _last_api_key_db_error = ""
            return res.data[0]
        _last_api_key_db_error = "insert returned no rows (likely blocked by RLS policy or missing INSERT privilege on integration_api_keys)"
        if _service_client is None:
            _last_api_key_db_error += "; backend is not using a service_role key"
        print(f"Supabase create_integration_api_key error: {_last_api_key_db_error}")
        return None
    except Exception as e:
        _last_api_key_db_error = str(e)

        # Some environments authenticate with a non-UUID local user id.
        # Retry without created_by to satisfy UUID/FK constraints.
        lowered = _last_api_key_db_error.lower()
        created_by = record.get("created_by")
        should_retry_without_creator = bool(created_by) and (
            "created_by" in lowered
            or "integration_api_keys_created_by_fkey" in lowered
            or "invalid input syntax for type uuid" in lowered
        )

        if should_retry_without_creator:
            try:
                retry_record = dict(record)
                retry_record["created_by"] = None
                db = _get_db_client()
                retry_res = db.table("integration_api_keys").insert(retry_record).execute()
                if retry_res.data:
                    _last_api_key_db_error = ""
                    return retry_res.data[0]
            except Exception as retry_error:
                _last_api_key_db_error = str(retry_error)

        if _service_client is None and "service_role" not in _last_api_key_db_error.lower():
            _last_api_key_db_error += " (hint: set SUPABASE_SERVICE_ROLE_KEY/SUPABASE_SERVICE_KEY to a service_role secret and verify RLS policy for integration_api_keys)"

        print(f"Supabase create_integration_api_key error: {_last_api_key_db_error}")
        return None


def get_last_api_key_db_error():
    return _last_api_key_db_error


def get_integration_api_key_by_id(key_id):
    _init()
    if not _enabled:
        return _dev_api_keys_db.get(key_id)

    try:
        db = _get_db_client()
        res = db.table("integration_api_keys").select("*").eq("id", key_id).limit(1).execute()
        return res.data[0] if res.data else None
    except Exception:
        return None


def list_integration_api_keys(limit=200):
    _init()
    if not _enabled:
        rows = []
        for r in _dev_api_keys_db.values():
            rows.append({
                "id": r.get("id"),
                "name": r.get("name"),
                "scope": r.get("scope"),
                "created_by": r.get("created_by"),
                "created_at": r.get("created_at"),
                "expires_at": r.get("expires_at"),
                "revoked": r.get("revoked", False),
                "last_used_at": r.get("last_used_at"),
                "key_prefix": r.get("key_prefix"),
            })
        rows.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return rows[:limit]

    try:
        db = _get_db_client()
        res = (
            db.table("integration_api_keys")
            .select("id,name,scope,created_by,created_at,expires_at,revoked,last_used_at,key_prefix")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return res.data or []
    except Exception:
        return []


def update_integration_api_key_last_used(key_id, last_used_at):
    _init()
    if not _enabled:
        row = _dev_api_keys_db.get(key_id)
        if not row:
            return False
        row["last_used_at"] = last_used_at
        return True

    try:
        db = _get_db_client()
        db.table("integration_api_keys").update({"last_used_at": last_used_at}).eq("id", key_id).execute()
        return True
    except Exception as e:
        print(f"Supabase update_integration_api_key_last_used error: {e}")
        return False


def update_integration_api_key_secret_hash(key_id, secret_hash):
    _init()
    if not _enabled:
        row = _dev_api_keys_db.get(key_id)
        if not row:
            return False
        row["secret_hash"] = secret_hash
        return True

    try:
        db = _get_db_client()
        db.table("integration_api_keys").update({"secret_hash": secret_hash}).eq("id", key_id).execute()
        return True
    except Exception as e:
        print(f"Supabase update_integration_api_key_secret_hash error: {e}")
        return False


def revoke_integration_api_key(key_id):
    _init()
    if not _enabled:
        row = _dev_api_keys_db.get(key_id)
        if not row:
            return False
        row["revoked"] = True
        row["revoked_at"] = datetime.utcnow().isoformat()
        return True

    try:
        db = _get_db_client()
        res = db.table("integration_api_keys").update({"revoked": True, "revoked_at": datetime.utcnow().isoformat()}).eq("id", key_id).execute()
        return bool(res.data)
    except Exception as e:
        print(f"Supabase revoke_integration_api_key error: {e}")
        return False


def _safe_iso(value):
    if not value:
        return datetime.utcnow().isoformat()
    return str(value)


def add_feedback(payload):
    _init()
    record = {
        "id": str(uuid.uuid4()),
        "alert_id": str(payload.get("alert_id") or "").strip(),
        "ml_prediction": str(payload.get("ml_prediction") or "").strip(),
        "correct_label": (payload.get("correct_label") or "").strip() or None,
        "is_wrong": bool(payload.get("is_wrong", False)),
        "analyst_id": str(payload.get("analyst_id") or "").strip() or None,
        "model_name": str(payload.get("model_name") or "attack_category").strip(),
        "created_at": _safe_iso(payload.get("created_at")),
    }

    _append_runtime_rows(_RUNTIME_FEEDBACK_FILE, [record])

    if not _enabled:
        _dev_feedback_db.append(dict(record))
        return record

    try:
        db = _get_db_client()
        insert_payload = {
            "alert_id": record["alert_id"],
            "ml_prediction": record["ml_prediction"],
            "correct_label": record["correct_label"],
            "is_wrong": record["is_wrong"],
            "analyst_id": record["analyst_id"],
            "model_name": record["model_name"],
            "created_at": record["created_at"],
        }
        res = db.table("feedback").insert(insert_payload).execute()
        if res.data:
            return res.data[0]
        return record
    except Exception:
        return record


def get_feedback_rows(limit=5000, model_name=None):
    _init()
    limit = int(limit or 5000)
    limit = max(1, min(limit, 20000))

    runtime_rows = _read_runtime_rows(_RUNTIME_FEEDBACK_FILE, limit=limit)
    if model_name:
        runtime_rows = [r for r in runtime_rows if str(r.get("model_name") or "") == str(model_name)]

    if not _enabled:
        rows = list(_dev_feedback_db)
        rows.extend(runtime_rows)
        if model_name:
            rows = [r for r in rows if str(r.get("model_name") or "") == str(model_name)]
        rows.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return rows[:limit]

    try:
        db = _get_db_client()
        query = db.table("feedback").select("*").order("created_at", desc=True).limit(limit)
        if model_name:
            query = query.eq("model_name", str(model_name))
        res = query.execute()
        rows = res.data or []
        merged = rows + runtime_rows
        merged.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return merged[:limit]
    except Exception:
        runtime_rows.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return runtime_rows[:limit]


def record_model_version(payload):
    _init()
    record = {
        "id": str(uuid.uuid4()),
        "model_name": str(payload.get("model_name") or "").strip(),
        "version": int(payload.get("version") or 0),
        "filename": payload.get("filename"),
        "accuracy": _safe_float(payload.get("accuracy")),
        "precision": _safe_float(payload.get("precision")),
        "training_date": _safe_iso(payload.get("training_date")),
        "dataset_size": _safe_int(payload.get("dataset_size")),
        "is_active": bool(payload.get("is_active", False)),
        "metadata": payload.get("metadata") or {},
        "created_by": str(payload.get("created_by") or "system"),
    }

    _append_runtime_rows(_RUNTIME_MODEL_VERSIONS_FILE, [record])

    if not _enabled:
        _dev_model_versions_db.append(dict(record))
        return record

    try:
        db = _get_db_client()
        try:
            if record["is_active"]:
                db.table("model_versions").update({"is_active": False}).eq("model_name", record["model_name"]).execute()
        except Exception:
            pass
        res = db.table("model_versions").insert(record).execute()
        if res.data:
            return res.data[0]
        return record
    except Exception:
        return record


def list_model_versions(model_name=None, limit=50):
    _init()
    limit = max(1, min(int(limit or 50), 500))
    runtime_rows = _read_runtime_rows(_RUNTIME_MODEL_VERSIONS_FILE, limit=limit)

    if not _enabled:
        rows = list(_dev_model_versions_db) + runtime_rows
        if model_name:
            rows = [r for r in rows if str(r.get("model_name") or "") == str(model_name)]
        rows.sort(key=lambda x: (x.get("model_name", ""), int(x.get("version", 0))), reverse=True)
        return rows[:limit]

    try:
        db = _get_db_client()
        query = db.table("model_versions").select("*").order("training_date", desc=True).limit(limit)
        if model_name:
            query = query.eq("model_name", str(model_name))
        res = query.execute()
        rows = (res.data or []) + runtime_rows
        if model_name:
            rows = [r for r in rows if str(r.get("model_name") or "") == str(model_name)]
        rows.sort(key=lambda x: (x.get("model_name", ""), int(x.get("version", 0))), reverse=True)
        return rows[:limit]
    except Exception:
        if model_name:
            runtime_rows = [r for r in runtime_rows if str(r.get("model_name") or "") == str(model_name)]
        runtime_rows.sort(key=lambda x: (x.get("model_name", ""), int(x.get("version", 0))), reverse=True)
        return runtime_rows[:limit]


def record_audit_event(event_type, actor_id, details=None):
    _init()
    record = {
        "id": str(uuid.uuid4()),
        "event_type": str(event_type or "unknown"),
        "actor_id": str(actor_id or "system"),
        "details": details or {},
        "created_at": datetime.utcnow().isoformat(),
    }

    _append_runtime_rows(_RUNTIME_AUDIT_LOGS_FILE, [record])

    if not _enabled:
        _dev_audit_logs_db.append(dict(record))
        return record

    try:
        db = _get_db_client()
        alert_id = (details or {}).get("alert_id")
        if alert_id:
            db.table("alert_events").insert({
                "alert_id": str(alert_id),
                "event_type": str(event_type or "unknown"),
                "old_value": None,
                "new_value": None,
                "actor_user_id": str(actor_id or "") or None,
                "event_note": json.dumps(details or {}, ensure_ascii=True, default=str),
                "created_at": datetime.utcnow().isoformat(),
            }).execute()
        else:
            db.table("audit_logs").insert(record).execute()
        return record
    except Exception:
        return record
