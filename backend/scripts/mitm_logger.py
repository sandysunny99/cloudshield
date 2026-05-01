import json
import logging
from mitmproxy import http

# Set up simple logging to file
logger = logging.getLogger('mitmproxy_traffic')
logger.setLevel(logging.INFO)
fh = logging.FileHandler('/logs/proxy_traffic.log')
fh.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(fh)

def request(flow: http.HTTPFlow) -> None:
    """
    Called whenever mitmproxy intercepts a new HTTP request.
    Extracts relevant IOCs and saves them as JSON to be picked up by the Sandbox backend.
    """
    req = flow.request
    
    # We ignore standard docker or proxy heartbeat domains if needed,
    # but here we log everything for the sandbox.
    data = {
        "event_type": "sandbox_http_beacon",
        "method": req.method,
        "host": req.host,
        "path": req.path,
        "scheme": req.scheme,
        "port": req.port,
        "user_agent": req.headers.get("User-Agent", ""),
        "timestamp": flow.client_conn.timestamp_start
    }
    
    logger.info(json.dumps(data))
    
def response(flow: http.HTTPFlow) -> None:
    pass
