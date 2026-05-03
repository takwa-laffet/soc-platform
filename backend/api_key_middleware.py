from flask import g, jsonify, request

from integration_api_keys import validate_api_key


API_KEY_PROTECTED_PATHS = {
    "/api/predict/auto",
    "/api/analysis/upload-json",
    "/api/alerts/predict",
    "/api/vulnerabilities/predict",
}


def _extract_api_key():
    raw_key = (request.headers.get("X-API-Key") or "").strip()

    if not raw_key:
        auth_header = (request.headers.get("Authorization") or "").strip()
        if auth_header.lower().startswith("bearer "):
            raw_key = auth_header.split(" ", 1)[1].strip()

    # n8n and proxies can wrap header values with quotes.
    raw_key = raw_key.strip().strip('"').strip("'")
    return raw_key


def register_api_key_middleware(app):
    @app.before_request
    def api_key_middleware():
        g.api_key_auth = None

        if request.path not in API_KEY_PROTECTED_PATHS:
            return None

        raw_key = _extract_api_key()

        # If no API key is provided, keep JWT flow available.
        if not raw_key:
            return None

        key_meta = validate_api_key(raw_key, required_scope="n8n_predict")
        if not key_meta:
            return jsonify({"error": "Invalid or expired API key."}), 401

        g.api_key_auth = key_meta
        return None
