import os
import json
import joblib
from config import ML_MODELS_DIR

_cache = {}


def _load(filename):
    if filename not in _cache:
        path = os.path.join(ML_MODELS_DIR, filename)
        if filename.endswith(".pkl"):
            _cache[filename] = joblib.load(path)
        else:
            with open(path, "r", encoding="utf-8") as f:
                _cache[filename] = json.load(f)
    return _cache[filename]


# ── Models ──────────────────────────────────────────────
def mitre_model():
    return _load("xgb_mitre_model.pkl")

def behavioral_model():
    return _load("xgb_behavioral_model.pkl")

def vuln_model():
    return _load("xgb_vuln_model.pkl")

def attack_model():
    return _load("xgb_attack_model.pkl")

def attack_type_model():
    return _load("xgb_attack_type_desc_model.pkl")

def tfidf_vectorizer():
    return _load("tfidf_vectorizer.pkl")


# ── Label Encoders ──────────────────────────────────────
def alerts_le():
    return _load("alerts_label_encoder.pkl")

def attack_le():
    return _load("attack_label_encoder.pkl")

def attack_type_le():
    return _load("attack_type_15_label_encoder.pkl")

def attack_type_feat_enc():
    return _load("attack_type_feature_encoders.pkl")

def vuln_le():
    return _load("vuln_label_encoder.pkl")


# ── Feature Lists ───────────────────────────────────────
def mitre_features():
    return _load("mitre_features.json")

def behavioral_features():
    return _load("behavioral_features.json")

def vuln_features():
    return _load("vuln_features.json")

def attack_features():
    return _load("attack_features.json")

def attack_type_features():
    return _load("attack_type_15_features.json")


# ── Thresholds & Info ───────────────────────────────────
def confidence_thresholds():
    return _load("confidence_thresholds.json")

def models_info():
    return _load("models_info.json")

def vuln_model_info():
    return _load("vuln_model_info.json")

def attack_model_info():
    return _load("attack_model_info.json")
