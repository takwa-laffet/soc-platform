import threading
import uuid
from datetime import datetime, timezone

from training.feedback_batch_trainer import run_feedback_training

_LOCK = threading.Lock()
_STATE = {
    "running": False,
    "job_id": None,
    "started_at": None,
    "finished_at": None,
    "result": None,
    "error": None,
    "triggered_by": None,
}


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def get_training_status():
    with _LOCK:
        return dict(_STATE)


def start_feedback_training_job(triggered_by="system"):
    with _LOCK:
        if _STATE["running"]:
            return None, "already_running"

        job_id = str(uuid.uuid4())
        _STATE.update(
            {
                "running": True,
                "job_id": job_id,
                "started_at": _utc_now(),
                "finished_at": None,
                "result": None,
                "error": None,
                "triggered_by": triggered_by,
            }
        )

    def _runner():
        try:
            result = run_feedback_training(triggered_by=triggered_by)
            with _LOCK:
                _STATE["result"] = result
        except Exception as exc:
            with _LOCK:
                _STATE["error"] = str(exc)
        finally:
            with _LOCK:
                _STATE["running"] = False
                _STATE["finished_at"] = _utc_now()

    thread = threading.Thread(target=_runner, name="feedback-batch-training", daemon=True)
    thread.start()
    return job_id, None
