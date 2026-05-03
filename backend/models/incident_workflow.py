ALLOWED_INCIDENT_TRANSITIONS = {
    "NEW": {"TRIAGED", "RESOLVED"},
    "TRIAGED": {"CONTAINED", "RESOLVED"},
    "CONTAINED": {"RESOLVED"},
    "RESOLVED": set(),
}

VALID_INCIDENT_STATUSES = set(ALLOWED_INCIDENT_TRANSITIONS.keys())


def normalize_incident_status(value):
    if value is None:
        return ""
    return str(value).strip().upper()


def is_valid_incident_status(status):
    return normalize_incident_status(status) in VALID_INCIDENT_STATUSES


def can_transition_incident(current_status, new_status):
    current = normalize_incident_status(current_status)
    target = normalize_incident_status(new_status)
    if current not in ALLOWED_INCIDENT_TRANSITIONS:
        return False
    return target in ALLOWED_INCIDENT_TRANSITIONS[current]
