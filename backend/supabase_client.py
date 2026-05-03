from config import SUPABASE_URL, SUPABASE_KEY

_client = None
_enabled = False


def _init():
    global _client, _enabled
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
            _client = create_client(SUPABASE_URL, SUPABASE_KEY)
            _enabled = True
            print("Supabase connected!")
        except Exception as e:
            print(f"Supabase init failed: {e}")
            _enabled = False
    else:
        print("Supabase not configured — running without DB")


def is_enabled():
    _init()
    return _enabled


def save_alerts(results):
    _init()
    if not _enabled:
        return
    try:
        _client.table("alerts").insert(results).execute()
    except Exception as e:
        print(f"Supabase save_alerts error: {e}")


def save_vulnerabilities(results):
    _init()
    if not _enabled:
        return
    try:
        _client.table("vulnerabilities").insert(results).execute()
    except Exception as e:
        print(f"Supabase save_vulnerabilities error: {e}")


def save_low_confidence(items):
    _init()
    if not _enabled:
        return
    try:
        _client.table("low_confidence_items").insert(items).execute()
    except Exception as e:
        print(f"Supabase save_low_confidence error: {e}")


def get_alerts(limit=500):
    _init()
    if not _enabled:
        return []
    try:
        res = _client.table("alerts").select("*").limit(limit).execute()
        return res.data or []
    except Exception:
        return []


def get_vulnerabilities(limit=500):
    _init()
    if not _enabled:
        return []
    try:
        res = _client.table("vulnerabilities").select("*").limit(limit).execute()
        return res.data or []
    except Exception:
        return []


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
