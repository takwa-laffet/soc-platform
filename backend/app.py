from flask import Flask
import re
import warnings
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from extensions import limiter
import supabase_client
from config import (
    FLASK_HOST,
    FLASK_PORT,
    FLASK_DEBUG,
    SUPABASE_URL,
    SUPABASE_KEY,
    JWT_SECRET_KEY,
    MAX_CONTENT_LENGTH,
    JWT_COOKIE_SECURE,
    JWT_COOKIE_SAMESITE,
    JWT_COOKIE_CSRF_PROTECT,
)

app = Flask(__name__)

# Suppress sklearn pickle version noise in dev logs.
warnings.filterwarnings(
    "ignore",
    category=UserWarning,
    message=r"Trying to unpickle estimator .* from version .* when using version .*",
)

app.config['SUPABASE_URL'] = SUPABASE_URL
app.config['SUPABASE_KEY'] = SUPABASE_KEY
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = JWT_COOKIE_SECURE
app.config['JWT_COOKIE_SAMESITE'] = JWT_COOKIE_SAMESITE
app.config['JWT_COOKIE_CSRF_PROTECT'] = JWT_COOKIE_CSRF_PROTECT

CORS(app, 
     origins=[
         "http://localhost:5173",
         "http://127.0.0.1:5173",
         "http://localhost:3000", 
         "http://127.0.0.1:3000",
         "http://localhost:3001",
         "http://127.0.0.1:3001",
         re.compile(r"^http://192\\.168\\.18\\.\\d{1,3}:3000$"),
         re.compile(r"^http://192\\.168\\.18\\.\\d{1,3}:3001$"),
         re.compile(r"^http://192\\.168\\.18\\.\\d{1,3}:5173$"),
         "http://localhost",
         "http://127.0.0.1",
         re.compile(r"^http://192\\.168\\.18\\.\\d{1,3}$"),
     ], 
     supports_credentials=True)

jwt = JWTManager(app)
bcrypt = Bcrypt(app)
limiter.init_app(app)

# Initialize bcrypt for supabase_client
supabase_client.init_bcrypt(app)

# Pre-load models at startup
print("=" * 50)
print("Skipping ML model loading (Windows Defender blocking builds)...")
# # from ml_loader import mitre_model, behavioral_model, vuln_model, attack_model
# # mitre_model()
# # behavioral_model()
# # vuln_model()
# # attack_model()
# # print("All models loaded successfully!")
print("=" * 50)

# Register routes
from routes import register_routes
from auth_routes import auth_bp
from alert_workflow_routes import alert_workflow_bp
from api_key_middleware import register_api_key_middleware
from chat_routes import chat_bp

register_routes(app)
app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(alert_workflow_bp, url_prefix="/api")
app.register_blueprint(chat_bp, url_prefix="/api")
register_api_key_middleware(app)

@app.route("/")
def home():
    return {"message": "SOC Platform Backend Running"}

if __name__ == "__main__":
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
