import os
import requests
import json
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cloudshield.ilm")

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")

# Define indices and their specific retention requirements
INDICES = {
    "suricata-events": {"max_age": "1d", "max_size": "5gb", "delete_age": "5d"},
    "wazuh-alerts": {"max_age": "1d", "max_size": "5gb", "delete_age": "5d"},
    "sandbox-events": {"max_age": "1d", "max_size": "1gb", "delete_age": "7d"},
    "correlated-alerts": {"max_age": "7d", "max_size": "1gb", "delete_age": "14d"}
}

def wait_for_opensearch():
    logger.info("Waiting for OpenSearch to become available...")
    for _ in range(30):
        try:
            res = requests.get(OPENSEARCH_URL, timeout=2)
            if res.status_code == 200:
                logger.info("OpenSearch is online.")
                return True
        except:
            pass
        time.sleep(2)
    logger.error("OpenSearch failed to come online.")
    return False

def create_ilm_policy(name: str, max_age: str, max_size: str, delete_age: str):
    policy = {
        "policy": {
            "phases": {
                "hot": {
                    "actions": {
                        "rollover": {
                            "max_age": max_age,
                            "max_size": max_size
                        }
                    }
                },
                "delete": {
                    "min_age": delete_age,
                    "actions": {
                        "delete": {}
                    }
                }
            }
        }
    }
    res = requests.put(f"{OPENSEARCH_URL}/_plugins/_ism/policies/{name}", json=policy)
    if res.status_code in [200, 201]:
        logger.info(f"ILM Policy '{name}' created/updated.")
    elif res.status_code == 409:
        # Ignore already exists or handle update if needed
        logger.info(f"ILM Policy '{name}' already exists.")
    else:
        logger.error(f"Failed to create ILM policy '{name}': {res.text}")

def create_index_template(alias_name: str, policy_name: str):
    template = {
        "index_patterns": [f"{alias_name}-*"],
        "template": {
            "settings": {
                "plugins.index_state_management.policy_id": policy_name,
                "plugins.index_state_management.rollover_alias": alias_name
            }
        }
    }
    # OpenSearch uses _index_template or _template depending on version. We use legacy _template for broad compatibility or _index_template for newer.
    res = requests.put(f"{OPENSEARCH_URL}/_index_template/{alias_name}-template", json=template)
    if res.status_code in [200, 201]:
        logger.info(f"Index Template '{alias_name}-template' created/updated.")
    else:
        logger.error(f"Failed to create Index Template '{alias_name}-template': {res.text}")

def create_bootstrap_index(alias_name: str):
    # Check if alias exists
    res = requests.head(f"{OPENSEARCH_URL}/_alias/{alias_name}")
    if res.status_code == 200:
        logger.info(f"Alias '{alias_name}' already exists. Skipping bootstrap.")
        return

    first_index = f"{alias_name}-000001"
    index_body = {
        "aliases": {
            alias_name: {
                "is_write_index": True
            }
        }
    }
    res = requests.put(f"{OPENSEARCH_URL}/{first_index}", json=index_body)
    if res.status_code in [200, 201]:
        logger.info(f"Bootstrap index '{first_index}' created with alias '{alias_name}'.")
    else:
        logger.error(f"Failed to create bootstrap index for '{alias_name}': {res.text}")

def main():
    if not wait_for_opensearch():
        return

    for alias, config in INDICES.items():
        policy_name = f"{alias}-policy"
        create_ilm_policy(policy_name, config["max_age"], config["max_size"], config["delete_age"])
        create_index_template(alias, policy_name)
        create_bootstrap_index(alias)
        
    logger.info("ILM setup complete.")

if __name__ == "__main__":
    main()
