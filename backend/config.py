import os
from dotenv import load_dotenv

load_dotenv()

ML_MODELS_DIR = os.path.join(os.path.dirname(__file__), "ml_models")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5001))
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
CONFIDENCE_THRESHOLD = 70.0
