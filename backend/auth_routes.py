from flask import Blueprint, request, jsonify, make_response, current_app
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_required,
    get_jwt,
    set_access_cookies,
    unset_jwt_cookies,
)
import supabase_client
import math
import secrets
from datetime import datetime, timedelta
from extensions import limiter
from integration_api_keys import generate_api_key, list_api_keys, revoke_api_key

auth_bp = Blueprint("auth", __name__)
bcrypt = Bcrypt()

otp_store = {}


def _server_error(operation):
    current_app.logger.exception("Auth route failed during %s", operation)
    return jsonify({"error": "Internal server error"}), 500

def generate_otp():
    return str(math.floor(100000 + secrets.randbelow(900000)))

def require_soc_manager():
    def wrapper(fn):
        @jwt_required()
        def decorated(*args, **kwargs):
            claims = get_jwt()
            role = claims.get("role", "")
            if role != "SOC_MANAGER":
                return jsonify({"error": "Access denied. SOC Manager only."}), 403
            return fn(*args, **kwargs)
        decorated.__name__ = fn.__name__
        return decorated
    return wrapper

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("8 per minute")
def login():
    data = request.get_json(silent=True) or {}
    remember_me = bool(data.get("rememberMe", False))

    if not data.get("email") or not data.get("password"):
        return jsonify({"error": "Please enter both email and password"}), 400

    try:
        user = supabase_client.get_user_by_email(data["email"])
        current_app.logger.info(f"Login attempt for email: {data['email']}, user found: {user is not None}")

        if not user:
            return jsonify({"error": "Invalid email or password"}), 401

        stored_password = user.get("password", "")
        current_app.logger.info(f"User found: {user['email']}, password type: {type(stored_password)}")

        if isinstance(stored_password, str) and stored_password.startswith("$2"):
            password_ok = bcrypt.check_password_hash(stored_password, data["password"])
        else:
            password_ok = False

        if not password_ok:
            return jsonify({"error": "Invalid email or password"}), 401

        if user.get("is_active") is False:
            return jsonify({"error": "Your account has been blocked by SOC Manager"}), 403

        if remember_me:
            expires_delta = timedelta(days=7)
            cookie_max_age = int(expires_delta.total_seconds())
        else:
            expires_delta = timedelta(minutes=30)
            cookie_max_age = None

        # Ensure user["id"] is a string
        user_id = str(user["id"])

        access_token = create_access_token(
            identity=user_id,
            additional_claims={"role": user["role"]},
            expires_delta=expires_delta
        )

        response = make_response(jsonify({
            "user": {
                "id": user_id,
                "email": user["email"],
                "name": user["name"]
            },
            "role": user["role"],
            "rememberMe": remember_me
        }))
        set_access_cookies(response, access_token, max_age=cookie_max_age)
        return response
    except Exception as e:
        current_app.logger.error(f"Login error for {data.get('email', 'unknown')}: {str(e)}")
        return _server_error("login")


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    
    try:
        user = supabase_client.get_user_by_id(user_id)
        if not user:
            return jsonify({"error": "Session expired. Please login again."}), 401
        return jsonify(user), 200
    except Exception:
        return _server_error("me")


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required()
@limiter.limit("20 per minute")
def refresh_token():
    user_id = get_jwt_identity()
    
    try:
        user = supabase_client.get_user_by_id(user_id)
        if not user:
            return jsonify({"error": "Session expired. Please login again."}), 401
        
        access_token = create_access_token(
            identity=user["id"],
            additional_claims={"role": user["role"]}
        )

        response = make_response(jsonify({"user": user}), 200)
        set_access_cookies(response, access_token)
        return response
    except Exception:
        return _server_error("refresh")


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
@limiter.limit("30 per minute")
def logout():
    response = make_response(jsonify({"message": "Logged out successfully"}), 200)
    unset_jwt_cookies(response)
    return response


@auth_bp.route("/users", methods=["GET"])
@jwt_required()
def get_all_users():
    user_id = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role", "")
    
    try:
        user = supabase_client.get_user_by_id(user_id)
        if not user:
            return jsonify({"error": "Session expired. Please login again."}), 401
        
        if role == "SOC_MANAGER":
            users = supabase_client.get_all_soc_users()
            return jsonify({"users": users}), 200
        else:
            return jsonify({"error": "Access denied"}), 403
    except Exception:
        return _server_error("users_list")


@auth_bp.route("/users/analysts", methods=["POST"])
@jwt_required()
def create_analyst():
    claims = get_jwt()
    role = claims.get("role", "")
    
    if role != "SOC_MANAGER":
        return jsonify({"error": "Access denied. SOC Manager only."}), 403
    
    data = request.json
    
    if not data.get("name") or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Please fill in all fields"}), 400
    
    confirm_pass = data.get("confirm_password") or data.get("confirmPassword")
    if not confirm_pass:
        return jsonify({"error": "Confirm password is required"}), 400
    
    if data.get("password") != confirm_pass:
        return jsonify({"error": "Passwords do not match"}), 400
    
    if len(data.get("password", "")) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    soc_level_tier = (data.get("soc_level_tier") or "L1").upper()
    if soc_level_tier not in {"L1", "L2", "L3"}:
        return jsonify({"error": "Invalid SOC level. Allowed values: L1, L2, L3"}), 400
    
    import re
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, data.get("email", "")):
        return jsonify({"error": "Please enter a valid email address"}), 400
    
    hashed_password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    
    user = {
        "name": data["name"],
        "email": data["email"],
        "password": hashed_password,
        "role": "SOC_ANALYST",
        "soc_level_tier": soc_level_tier,
    }
    
    try:
        result = supabase_client.create_user(user)
        return jsonify({"message": "SOC Analyst created successfully", "user": result}), 201
    except Exception:
        return _server_error("create_analyst")


@auth_bp.route("/users/<user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    claims = get_jwt()
    role = claims.get("role", "")
    
    if role != "SOC_MANAGER":
        return jsonify({"error": "Access denied. SOC Manager only."}), 403
    
    try:
        supabase_client.delete_user(user_id)
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception:
        return _server_error("delete_user")


@auth_bp.route("/users/<user_id>/status", methods=["PUT"])
@jwt_required()
def toggle_user_status(user_id):
    claims = get_jwt()
    role = claims.get("role", "")
    current_user_id = get_jwt_identity()
    
    if role != "SOC_MANAGER":
        return jsonify({"error": "Access denied. SOC Manager only."}), 403
    
    data = request.json
    is_active = data.get("is_active")
    
    if is_active is None:
        return jsonify({"error": "is_active field is required"}), 400
    
    try:
        if user_id == current_user_id:
            return jsonify({"error": "Cannot update your own account status"}), 400

        target_user = supabase_client.get_user_by_id(user_id)
        if not target_user:
            return jsonify({"error": "User not found"}), 404

        if target_user.get("role") != "SOC_ANALYST":
            return jsonify({"error": "Only SOC Analyst accounts can be blocked/activated"}), 400

        supabase_client.update_user_status(user_id, is_active)
        status_text = "activated" if is_active else "deactivated"
        return jsonify({"message": f"User {status_text} successfully"}), 200
    except Exception:
        return _server_error("toggle_user_status")


@auth_bp.route("/api-keys/generate", methods=["POST"])
@jwt_required()
@limiter.limit("20 per hour")
def generate_n8n_api_key():
    claims = get_jwt()
    role = claims.get("role", "")

    if role != "SOC_MANAGER":
        return jsonify({"error": "Access denied. SOC Manager only."}), 403

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "n8n").strip() or "n8n"

    expires_days = data.get("expires_days", 180)
    try:
        expires_days = int(expires_days)
    except (TypeError, ValueError):
        return jsonify({"error": "expires_days must be an integer"}), 400

    if expires_days < 1 or expires_days > 365:
        return jsonify({"error": "expires_days must be between 1 and 365"}), 400

    try:
        raw_key, meta = generate_api_key(
            created_by=get_jwt_identity(),
            name=name,
            scope="n8n_predict",
            expires_days=expires_days,
        )
    except RuntimeError:
        return _server_error("generate_api_key")

    return jsonify({
        "message": "API key generated successfully",
        "api_key": raw_key,
        "one_time_visible": True,
        "meta": meta,
    }), 201


@auth_bp.route("/api-keys", methods=["GET"])
@jwt_required()
def get_api_keys():
    claims = get_jwt()
    role = claims.get("role", "")

    if role != "SOC_MANAGER":
        return jsonify({"error": "Access denied. SOC Manager only."}), 403

    return jsonify({"keys": list_api_keys()}), 200


@auth_bp.route("/api-keys/<key_id>", methods=["DELETE"])
@jwt_required()
def delete_api_key(key_id):
    claims = get_jwt()
    role = claims.get("role", "")

    if role != "SOC_MANAGER":
        return jsonify({"error": "Access denied. SOC Manager only."}), 403

    revoked = revoke_api_key(key_id)
    if not revoked:
        return jsonify({"error": "API key not found"}), 404

    return jsonify({"message": "API key revoked successfully"}), 200