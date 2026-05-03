import os
from dotenv import load_dotenv

load_dotenv()


def _to_bool(value, default=False):
	if value is None:
		return default
	return str(value).strip().lower() in {"1", "true", "yes", "on"}

ML_MODELS_DIR = os.path.join(os.path.dirname(__file__), "ml_models")
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5001))
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
SUPABASE_SERVICE_KEY = (
	os.getenv("SUPABASE_SERVICE_KEY")
	or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
	or os.getenv("SUPABASE_SECRET_KEY")
	or os.getenv("service_role_key")
	or ""
)
_JWT_INSECURE_DEFAULT = "dev-jwt-secret-change-me"
JWT_SECRET_KEY = (os.getenv("JWT_SECRET_KEY") or "").strip()
_JWT_INSECURE_VALUES = {
	"changeme",
	"change-me",
	"dev",
	"development",
	"secret",
	"jwt-secret",
	"your-secret-key",
	"replace-with-a-long-random-secret",
	_JWT_INSECURE_DEFAULT,
}
FLASK_DEBUG = _to_bool(os.getenv("FLASK_DEBUG"), default=False)
if not JWT_SECRET_KEY:
	raise RuntimeError(
		"JWT_SECRET_KEY must be set in environment."
	)
if JWT_SECRET_KEY.lower() in _JWT_INSECURE_VALUES:
	raise RuntimeError(
		"JWT_SECRET_KEY uses an insecure placeholder value. Set a strong random value."
	)
if len(JWT_SECRET_KEY) < 32:
	raise RuntimeError(
		"JWT_SECRET_KEY must be at least 32 characters long."
	)
MAX_CONTENT_LENGTH_MB = int(os.getenv("MAX_CONTENT_LENGTH_MB", "25"))
MAX_CONTENT_LENGTH = MAX_CONTENT_LENGTH_MB * 1024 * 1024
JWT_COOKIE_SECURE = _to_bool(os.getenv("JWT_COOKIE_SECURE"), default=True)
JWT_COOKIE_SAMESITE = os.getenv("JWT_COOKIE_SAMESITE", "Lax")
JWT_COOKIE_CSRF_PROTECT = _to_bool(os.getenv("JWT_COOKIE_CSRF_PROTECT"), default=True)
if not FLASK_DEBUG and not JWT_COOKIE_SECURE:
	raise RuntimeError(
		"JWT_COOKIE_SECURE must remain enabled when FLASK_DEBUG is false."
	)
if not JWT_COOKIE_CSRF_PROTECT:
	raise RuntimeError(
		"JWT_COOKIE_CSRF_PROTECT must remain enabled for cookie-based JWT auth."
	)
API_KEY_DB_STRICT = _to_bool(os.getenv("API_KEY_DB_STRICT"), default=True)
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
THREAT_INTEL_TIMEOUT = int(os.getenv("THREAT_INTEL_TIMEOUT", "12"))
THREAT_INTEL_MAX_INDICATORS = int(os.getenv("THREAT_INTEL_MAX_INDICATORS", "20"))
CONFIDENCE_THRESHOLD = 70.0
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://192.168.18.128:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_TIMEOUT_SEC = int(os.getenv("OLLAMA_TIMEOUT_SEC", "90"))

# LM Studio configuration (OpenAI-compatible API)
LM_STUDIO_BASE_URL = os.getenv("LM_STUDIO_BASE_URL", "http://127.0.0.1:1234")
LM_STUDIO_MODEL = os.getenv("LM_STUDIO_MODEL", "phi-3.1-mini-4k-instruct")
LM_STUDIO_API_KEY = os.getenv("LM_STUDIO_API_KEY", "")
LM_STUDIO_TIMEOUT = int(os.getenv("LM_STUDIO_TIMEOUT", "120"))
