from flask import Blueprint, request, jsonify, current_app
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import LM_STUDIO_BASE_URL, LM_STUDIO_MODEL, LM_STUDIO_API_KEY, LM_STUDIO_TIMEOUT
from flask_jwt_extended import jwt_required, get_jwt_identity

chat_bp = Blueprint("chat", __name__)

# Configure retry strategy for resilience
RETRY_STRATEGY = Retry(
    total=2,
    backoff_factor=0.5,
    status_forcelist=[502, 503, 504],
    allowed_methods=["POST"],
    raise_on_status=False
)

_session = requests.Session()
_session.mount("http://", HTTPAdapter(max_retries=RETRY_STRATEGY))
_session.mount("https://", HTTPAdapter(max_retries=RETRY_STRATEGY))


@chat_bp.route("/chat", methods=["POST"])
@jwt_required(optional=True)  # Allow optional auth; still works for anon but prefer authenticated
def chat_completion():
    data = request.get_json(silent=True) or {}
    messages = data.get("messages", [])

    if not messages or not isinstance(messages, list):
        return jsonify({"error": "No messages provided"}), 400

    # Sanitize and forward messages to LM Studio
    formatted_messages = []
    for msg in messages:
        role = msg.get("role", "user")
        if role not in {"user", "assistant", "system"}:
            role = "user"
        formatted_messages.append({
            "role": role,
            "content": str(msg.get("content", ""))
        })

    endpoint = f"{LM_STUDIO_BASE_URL.rstrip('/')}/v1/chat/completions"
    payload = {
        "model": LM_STUDIO_MODEL,
        "messages": formatted_messages,
        "temperature": 0.7,
        "max_tokens": 500,
        "stream": False,
    }

    headers = {}
    if LM_STUDIO_API_KEY:
        headers["Authorization"] = f"Bearer {LM_STUDIO_API_KEY}"

    try:
        resp = _session.post(
            endpoint,
            json=payload,
            headers=headers,
            timeout=LM_STUDIO_TIMEOUT,
        )
        resp.raise_for_status()
        result = resp.json()

        choices = result.get("choices", [])
        if not choices:
            return jsonify({"error": "No response from AI model"}), 500

        content = choices[0].get("message", {}).get("content", "").strip()
        if not content:
            return jsonify({"error": "Empty response from AI model"}), 500

        return jsonify({
            "content": content,
            "model": result.get("model", LM_STUDIO_MODEL),
            "usage": result.get("usage", {}),
        })
    except requests.exceptions.ConnectionError as e:
        current_app.logger.error(f"LM Studio connection error: {e}")
        # Fallback to rule-based will be handled by frontend
        return jsonify({"error": "Unable to connect to AI service", "details": str(e)}), 503
    except requests.exceptions.Timeout as e:
        current_app.logger.error(f"LM Studio timeout after {LM_STUDIO_TIMEOUT}s: {e}")
        return jsonify({"error": "AI service request timed out", "details": str(e)}), 504
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else 500
        current_app.logger.error(f"LM Studio HTTP error {status}: {e}")
        return jsonify({"error": f"AI service returned error {status}", "details": str(e)}), status
    except Exception as e:
        current_app.logger.error(f"Unexpected error calling LM Studio: {e}")
        return jsonify({"error": "Unexpected error from AI service", "details": str(e)}), 500
