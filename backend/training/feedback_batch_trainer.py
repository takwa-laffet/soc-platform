from datetime import datetime, timezone

import numpy as np
from sklearn.metrics import accuracy_score, precision_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

import ml_loader
import supabase_client
from model_registry import activate_model_version, get_active_model_version, register_model_version
from training.feedback_dataset_builder import build_attack_feedback_dataset


def _metrics(y_true, y_pred):
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "precision_weighted": round(float(precision_score(y_true, y_pred, average="weighted", zero_division=0)), 6),
    }


def _evaluate_model(model, X_test, y_test):
    proba = model.predict_proba(X_test)
    pred = np.argmax(proba, axis=1)
    return _metrics(y_test, pred)


def run_feedback_training(triggered_by="system", min_rows=30):
    """Run one safe batch-training cycle for attack-category model."""
    X, y, ds_meta = build_attack_feedback_dataset(limit=8000)

    if len(y) < int(min_rows):
        return {
            "status": "skipped",
            "reason": "not_enough_feedback",
            "dataset": ds_meta,
        }

    unique_classes = len(set(int(v) for v in y.tolist()))
    if unique_classes < 2:
        return {
            "status": "skipped",
            "reason": "need_at_least_two_classes",
            "dataset": ds_meta,
        }

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    baseline_model = ml_loader.attack_model()
    baseline_metrics = _evaluate_model(baseline_model, X_test, y_test)

    num_classes = len(ml_loader.attack_le().classes_)
    candidate = XGBClassifier(
        n_estimators=180,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="multi:softprob",
        num_class=num_classes,
        eval_metric="mlogloss",
        random_state=42,
    )

    candidate.fit(X_train, y_train)
    candidate_metrics = _evaluate_model(candidate, X_test, y_test)

    improved = (
        candidate_metrics["accuracy"] > baseline_metrics["accuracy"]
        and candidate_metrics["precision_weighted"] >= baseline_metrics["precision_weighted"]
    )

    payload = {
        "status": "not_promoted",
        "reason": "metrics_not_improved",
        "baseline_metrics": baseline_metrics,
        "candidate_metrics": candidate_metrics,
        "dataset": ds_meta,
    }

    if not improved:
        supabase_client.record_audit_event(
            event_type="model_training_skipped",
            actor_id=triggered_by,
            details={
                "model_name": "xgb_attack_model.pkl",
                "baseline_metrics": baseline_metrics,
                "candidate_metrics": candidate_metrics,
                "dataset": ds_meta,
            },
        )
        return payload

    version_entry = register_model_version(
        model_name="xgb_attack_model.pkl",
        model_object=candidate,
        metrics=candidate_metrics,
        dataset_size=len(y),
        trained_by=triggered_by,
        notes="promoted from human feedback batch trainer",
    )
    activated = activate_model_version("xgb_attack_model.pkl", version_entry["version"])

    ml_loader.hot_reload_models()

    supabase_client.record_model_version(
        {
            "model_name": "xgb_attack_model.pkl",
            "version": int(version_entry["version"]),
            "filename": version_entry.get("filename"),
            "accuracy": candidate_metrics.get("accuracy"),
            "precision": candidate_metrics.get("precision_weighted"),
            "training_date": datetime.now(timezone.utc).isoformat(),
            "dataset_size": len(y),
            "is_active": True,
            "metadata": {
                "baseline_metrics": baseline_metrics,
                "candidate_metrics": candidate_metrics,
            },
            "created_by": triggered_by,
        }
    )

    supabase_client.record_audit_event(
        event_type="model_promoted",
        actor_id=triggered_by,
        details={
            "model_name": "xgb_attack_model.pkl",
            "version": version_entry["version"],
            "candidate_metrics": candidate_metrics,
            "baseline_metrics": baseline_metrics,
            "dataset": ds_meta,
            "active": activated,
        },
    )

    active = get_active_model_version("xgb_attack_model.pkl")
    return {
        "status": "promoted",
        "active_version": active,
        "baseline_metrics": baseline_metrics,
        "candidate_metrics": candidate_metrics,
        "dataset": ds_meta,
    }
