import time
import uuid

# In a full deployment, this would be a MongoDB or OpenSearch index.
# We use an in-memory dictionary for this prototype.
CASES = {}

def create_case(title: str, description: str, created_by: str = "admin") -> dict:
    case_id = f"CASE-{str(uuid.uuid4())[:8].upper()}"
    case = {
        "id": case_id,
        "title": title,
        "description": description,
        "status": "open",
        "assigned_to": "unassigned",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "created_by": created_by,
        "alerts": [],
        "comments": [],
        "timeline": [
            {"action": "created", "user": created_by, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
        ]
    }
    CASES[case_id] = case
    return case

def get_cases() -> list:
    return list(CASES.values())

def get_case(case_id: str) -> dict:
    return CASES.get(case_id)

def update_case(case_id: str, updates: dict, user: str = "system") -> dict:
    if case_id not in CASES:
        return None
    
    case = CASES[case_id]
    
    if "status" in updates and updates["status"] in ["open", "investigating", "closed"]:
        case["status"] = updates["status"]
        case["timeline"].append({"action": f"status_changed_to_{updates['status']}", "user": user, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")})
        
    if "assigned_to" in updates:
        case["assigned_to"] = updates["assigned_to"]
        case["timeline"].append({"action": f"assigned_to_{updates['assigned_to']}", "user": user, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")})
        
    if "comment" in updates:
        case["comments"].append({"user": user, "text": updates["comment"], "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")})
        case["timeline"].append({"action": "comment_added", "user": user, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")})
        
    return case

def attach_alert_to_case(case_id: str, alert_id: str, user: str = "system") -> dict:
    if case_id in CASES:
        if alert_id not in CASES[case_id]["alerts"]:
            CASES[case_id]["alerts"].append(alert_id)
            CASES[case_id]["timeline"].append({"action": f"attached_alert_{alert_id}", "user": user, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")})
        return CASES[case_id]
    return None
