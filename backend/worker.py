import os
import json
import time
import requests

import redis

redis_client = redis.Redis.from_url(
    os.environ.get("REDIS_URL", "redis://localhost:6379"),
    decode_responses=True,
    socket_connect_timeout=2,
    socket_timeout=2
)
SLACK_URL = os.environ.get("SLACK_WEBHOOK_URL")

def check_ip_score(ip):
    # Dummy implementation or AbuseIPDB call
    if ip == "8.8.8.8": return 60
    return 0

def process_event(data):
    risk = data.get("risk_score", 0)
    
    if data.get("cpu", 0) > 80:
        risk += 20
        
    if check_ip_score(data.get("ip", "")) > 50:
        risk += 40
        
    result = {
        **data,
        "risk_score": risk,
        "timestamp": time.time()
    }
    
    # Send to UI via pubsub — must match SSE subscriber channel + format
    redis_client.publish("sse_channel", json.dumps({
        "type": "agent_update",
        "data": result
    }))
    
    # Alerting
    if risk > 70 and SLACK_URL:
        try:
            requests.post(SLACK_URL, json={"text": f"🚨 High Risk Alert: {json.dumps(result)}"}, timeout=2)
        except:
            pass

def main():
    print("Worker started. Listening for events...")
    try:
        redis_client.xgroup_create("events", "workers", id="0", mkstream=True)
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            print(f"Group creation error: {e}")

    while True:
        try:
            events = redis_client.xreadgroup(
                groupname="workers",
                consumername="worker-1",
                streams={"events": ">"},
                count=10,
                block=5000
            )
            
            for stream, messages in events:
                for msg_id, msg in messages:
                    try:
                        data = json.loads(msg[b"data"])
                        process_event(data)
                        redis_client.xack("events", "workers", msg_id)
                    except Exception as ex:
                        print(f"Error processing message: {ex}")
        except Exception as e:
            print(f"Worker loop error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
