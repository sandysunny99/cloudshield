import json
import logging
import os
import redis
from mitmproxy import http

# Connect to Redis
REDIS_URL = os.environ.get("REDIS_URL", "redis://cloudshield-redis:6379")
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

logger = logging.getLogger('mitmproxy_traffic')

def request(flow: http.HTTPFlow) -> None:
    """
    Called whenever mitmproxy intercepts a new HTTP request.
    Extracts relevant IOCs and publishes them to Redis.
    """
    req = flow.request
    
    # We extract the sandbox IP to correlate with the analysis ID
    client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
    
    data = {
        "event_type": "sandbox_http_beacon",
        "method": req.method,
        "host": req.host,
        "path": req.path,
        "scheme": req.scheme,
        "port": req.port,
        "user_agent": req.headers.get("User-Agent", ""),
        "timestamp": flow.client_conn.timestamp_start,
        "client_ip": client_ip
    }
    
    try:
        redis_client.publish("sandbox:traffic", json.dumps(data))
    except Exception as e:
        logger.error(f"Failed to publish to redis: {e}")
    
def response(flow: http.HTTPFlow) -> None:
    pass
