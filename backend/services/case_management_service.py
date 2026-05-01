import time
import uuid

# In a full deployment, this would be a MongoDB or OpenSearch index.
# We use an in-memory dictionary for this prototype.
CASES = {}

def create_case(title: str, description: str, created_by: str = "analyst") -> dict:
    case_id = f"CASE-{str(uuid.uuid4())[:8].upper()}"
    case = {
        "id": case_id,
        "title": title,
        "description": description,
        "status": "open",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "created_by": created_by,
        "alerts": []
    }
    CASES[case_id] = case
    return case

def get_cases() -> list:
    return list(CASES.values())

def get_case(case_id: str) -> dict:
    return CASES.get(case_id)

def update_case_status(case_id: str, status: str) -> dict:
    if case_id in CASES and status in ["open", "investigating", "closed"]:
        CASES[case_id]["status"] = status
        return CASES[case_id]
    return None

def attach_alert_to_case(case_id: str, alert_id: str) -> dict:
    if case_id in CASES:
        if alert_id not in CASES[case_id]["alerts"]:
            CASES[case_id]["alerts"].append(alert_id)
        return CASES[case_id]
    return None
