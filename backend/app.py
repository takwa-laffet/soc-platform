import os
from flask import Flask
from flask_cors import CORS
from config import FLASK_PORT

app = Flask(__name__)
CORS(app)

# Pre-load models at startup
print("=" * 50)
print("Loading ML models...")
from ml_loader import mitre_model, behavioral_model, vuln_model, attack_model
mitre_model()
behavioral_model()
vuln_model()
attack_model()
print("All models loaded successfully!")
print("=" * 50)

from routes import register_routes
register_routes(app)

if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=debug)
