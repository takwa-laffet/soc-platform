ALLOWED_STATUS_TRANSITIONS = {
    "OPEN": {"IN_PROGRESS"},
    "IN_PROGRESS": {"RESOLVED"},
    "RESOLVED": set(),
}

VALID_STATUSES = set(ALLOWED_STATUS_TRANSITIONS.keys())


def normalize_status(value):
    if value is None:
        return ""
    return str(value).strip().upper()


def is_valid_status(status):
    return normalize_status(status) in VALID_STATUSES


def can_transition(current_status, new_status):
    current = normalize_status(current_status)
    target = normalize_status(new_status)
    if current not in ALLOWED_STATUS_TRANSITIONS:
        return False
    return target in ALLOWED_STATUS_TRANSITIONS[current]
