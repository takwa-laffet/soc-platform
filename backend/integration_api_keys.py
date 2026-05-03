import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from threading import Lock
import supabase_client
from config import API_KEY_DB_STRICT


_api_keys = {}
_api_lock = Lock()
_PBKDF2_ALGO = "sha256"
_PBKDF2_ITERATIONS = 260000
_PBKDF2_SALT_BYTES = 16


def _utcnow():
    return datetime.now(timezone.utc)


def _hash_secret(secret):
    salt = secrets.token_bytes(_PBKDF2_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        _PBKDF2_ALGO,
        secret.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_{_PBKDF2_ALGO}${_PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_secret(secret, stored_hash):
    if not stored_hash:
        return False

    # Legacy support: old unsalted sha256 hash.
    if "$" not in stored_hash:
        legacy = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        return hmac.compare_digest(stored_hash, legacy)

    try:
        method, iterations, salt_hex, digest_hex = stored_hash.split("$", 3)
        if method != f"pbkdf2_{_PBKDF2_ALGO}":
            return False
        derived = hashlib.pbkdf2_hmac(
            _PBKDF2_ALGO,
            secret.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        ).hex()
        return hmac.compare_digest(digest_hex, derived)
    except (TypeError, ValueError):
        return False


def _parse_dt(value):
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value))
        except ValueError:
            return None

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _safe_uuid_or_none(value):
    if not value:
        return None
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


def generate_api_key(created_by, name="n8n", scope="n8n_predict", expires_days=180):
    """
    Generate a new API key and return the raw key only once.

    Raw format:
      sk_<key_id>.<secret>
    """
    key_id = secrets.token_urlsafe(12)
    secret = secrets.token_urlsafe(32)
    raw_key = f"sk_{key_id}.{secret}"

    now = _utcnow()
    expires_at = now + timedelta(days=expires_days)

    record = {
        "id": key_id,
        "name": name,
        "scope": scope,
        "created_by": _safe_uuid_or_none(created_by),
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "revoked": False,
        "last_used_at": None,
        "secret_hash": _hash_secret(secret),
        "key_prefix": raw_key[:14],
    }

    with _api_lock:
        _api_keys[key_id] = record

    persisted = supabase_client.create_integration_api_key(record)
    if not persisted and API_KEY_DB_STRICT:
        with _api_lock:
            _api_keys.pop(key_id, None)

        detail = supabase_client.get_last_api_key_db_error()
        if detail:
            raise RuntimeError(f"Failed to persist API key to database: {detail}")
        raise RuntimeError("Failed to persist API key to database.")

    if not persisted and not API_KEY_DB_STRICT:
        detail = supabase_client.get_last_api_key_db_error()
        if detail:
            print(f"API key persistence fallback active (in-memory only): {detail}")
        else:
            print("API key persistence fallback active (in-memory only)")

    public_record = {
        "id": record["id"],
        "name": record["name"],
        "scope": record["scope"],
        "created_by": record["created_by"],
        "created_at": record["created_at"],
        "expires_at": record["expires_at"],
        "revoked": record["revoked"],
        "last_used_at": record["last_used_at"],
        "key_prefix": record["key_prefix"],
        "persisted_to_db": bool(persisted),
    }

    return raw_key, public_record


def validate_api_key(raw_key, required_scope=None):
    if not raw_key or not isinstance(raw_key, str) or not raw_key.startswith("sk_"):
        return None

    try:
        key_part, secret = raw_key.split(".", 1)
        key_id = key_part[3:]
    except ValueError:
        return None

    record = supabase_client.get_integration_api_key_by_id(key_id)
    if record:
        with _api_lock:
            _api_keys[key_id] = record

    with _api_lock:
        record = _api_keys.get(key_id)
        if not record:
            return None
        if record.get("revoked"):
            return None

        expires_at = _parse_dt(record.get("expires_at"))
        if expires_at and expires_at <= _utcnow():
            return None

        if required_scope and record.get("scope") != required_scope:
            return None

        expected = record.get("secret_hash", "")
        if not _verify_secret(secret, expected):
            return None

        # Upgrade legacy hashes in-place after successful authentication.
        if "$" not in expected:
            upgraded = _hash_secret(secret)
            record["secret_hash"] = upgraded
            supabase_client.update_integration_api_key_secret_hash(key_id, upgraded)

        record["last_used_at"] = _utcnow().isoformat()
        supabase_client.update_integration_api_key_last_used(key_id, record["last_used_at"])

        return {
            "id": record.get("id"),
            "name": record.get("name"),
            "scope": record.get("scope"),
            "created_by": record.get("created_by"),
            "created_at": record.get("created_at"),
            "expires_at": record.get("expires_at"),
            "last_used_at": record.get("last_used_at"),
            "key_prefix": record.get("key_prefix"),
        }


def list_api_keys():
    rows = supabase_client.list_integration_api_keys(limit=500)
    if rows:
        return rows

    with _api_lock:
        records = []
        for record in _api_keys.values():
            records.append({
                "id": record.get("id"),
                "name": record.get("name"),
                "scope": record.get("scope"),
                "created_by": record.get("created_by"),
                "created_at": record.get("created_at"),
                "expires_at": record.get("expires_at"),
                "revoked": record.get("revoked", False),
                "last_used_at": record.get("last_used_at"),
                "key_prefix": record.get("key_prefix"),
            })

    records.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return records


def revoke_api_key(key_id):
    with _api_lock:
        record = _api_keys.get(key_id)
        if not record:
            db_record = supabase_client.get_integration_api_key_by_id(key_id)
            if db_record:
                _api_keys[key_id] = db_record
                record = _api_keys.get(key_id)
            else:
                return False
        if not supabase_client.revoke_integration_api_key(key_id):
            return False

        record["revoked"] = True
        return True
