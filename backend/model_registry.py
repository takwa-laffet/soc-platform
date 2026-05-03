import json
import os
from datetime import datetime, timezone
from threading import RLock

import joblib

from config import ML_MODELS_DIR

_REGISTRY_FILE = os.path.join(ML_MODELS_DIR, "model_registry.json")
_VERSIONS_DIR = os.path.join(ML_MODELS_DIR, "versions")
_LOCK = RLock()

_DEFAULT_ACTIVE = {
    "xgb_mitre_model.pkl": "xgb_mitre_model.pkl",
    "xgb_behavioral_model.pkl": "xgb_behavioral_model.pkl",
    "xgb_attack_model.pkl": "xgb_attack_model.pkl",
    "xgb_vuln_model.pkl": "xgb_vuln_model.pkl",
    "xgb_attack_type_desc_model.pkl": "xgb_attack_type_desc_model.pkl",
}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _ensure_dirs():
    os.makedirs(ML_MODELS_DIR, exist_ok=True)
    os.makedirs(_VERSIONS_DIR, exist_ok=True)


def _default_registry():
    return {
        "active": dict(_DEFAULT_ACTIVE),
        "history": {},
    }


def _load_registry():
    _ensure_dirs()
    if not os.path.exists(_REGISTRY_FILE):
        registry = _default_registry()
        _save_registry(registry)
        return registry

    try:
        with open(_REGISTRY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("invalid registry format")
    except Exception:
        data = _default_registry()

    data.setdefault("active", dict(_DEFAULT_ACTIVE))
    data.setdefault("history", {})

    for model_name, fallback in _DEFAULT_ACTIVE.items():
        data["active"].setdefault(model_name, fallback)

    return data


def _save_registry(registry):
    _ensure_dirs()
    with open(_REGISTRY_FILE, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2, ensure_ascii=True)


def get_active_model_filename(model_name):
    with _LOCK:
        registry = _load_registry()
        active_name = registry.get("active", {}).get(model_name, model_name)
        active_path = os.path.join(ML_MODELS_DIR, active_name)
        if os.path.exists(active_path):
            return active_name
        return model_name


def list_model_versions(model_name):
    with _LOCK:
        registry = _load_registry()
        items = registry.get("history", {}).get(model_name, [])
        items = [i for i in items if isinstance(i, dict)]
        return sorted(items, key=lambda x: x.get("version", 0), reverse=True)


def _next_version(model_name):
    history = list_model_versions(model_name)
    if not history:
        return 1
    return max(int(i.get("version", 0)) for i in history) + 1


def _versioned_filename(model_name, version):
    base = os.path.splitext(os.path.basename(model_name))[0]
    return os.path.join("versions", f"{base}_v{version}.pkl")


def register_model_version(model_name, model_object, metrics, dataset_size, trained_by="system", notes=""):
    with _LOCK:
        registry = _load_registry()
        version = _next_version(model_name)
        rel_filename = _versioned_filename(model_name, version)
        abs_filename = os.path.join(ML_MODELS_DIR, rel_filename)
        os.makedirs(os.path.dirname(abs_filename), exist_ok=True)
        joblib.dump(model_object, abs_filename)

        entry = {
            "version": version,
            "filename": rel_filename.replace("\\", "/"),
            "trained_at": _now_iso(),
            "dataset_size": int(dataset_size or 0),
            "metrics": metrics or {},
            "trained_by": trained_by,
            "notes": notes or "",
        }

        registry.setdefault("history", {}).setdefault(model_name, []).append(entry)
        _save_registry(registry)
        return entry


def activate_model_version(model_name, version):
    with _LOCK:
        registry = _load_registry()
        history = registry.get("history", {}).get(model_name, [])

        picked = None
        for item in history:
            if int(item.get("version", 0)) == int(version):
                picked = item
                break

        if not picked:
            return None

        rel = picked.get("filename") or model_name
        abs_path = os.path.join(ML_MODELS_DIR, rel)
        if not os.path.exists(abs_path):
            return None

        registry.setdefault("active", {})[model_name] = rel
        _save_registry(registry)
        return picked


def get_active_model_version(model_name):
    with _LOCK:
        registry = _load_registry()
        active_name = registry.get("active", {}).get(model_name, model_name)
        for item in registry.get("history", {}).get(model_name, []):
            if item.get("filename") == active_name:
                return item
        return {
            "version": 0,
            "filename": active_name,
            "trained_at": None,
            "dataset_size": None,
            "metrics": {},
            "trained_by": "baseline",
            "notes": "baseline model file",
        }


def rollback_model(model_name, target_version=None):
    with _LOCK:
        versions = list_model_versions(model_name)
        if not versions:
            return None

        if target_version is not None:
            return activate_model_version(model_name, target_version)

        active = get_active_model_version(model_name)
        active_version = int((active or {}).get("version", 0))

        for item in versions:
            version = int(item.get("version", 0))
            if active_version and version < active_version:
                return activate_model_version(model_name, version)

        return None
