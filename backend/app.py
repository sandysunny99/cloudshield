"""
CloudShield Flask API v2.0
Backend API with CORS, rate limiting, and real-time security scanning.
"""

import logging
from logging_config import configure_logging
configure_logging()   # must be first — initialises all child loggers

_log = logging.getLogger("cloudshield.api")

import json
import os
import sys
import time
import tempfile
import threading
import queue
import yaml
import boto3
import re
from botocore.exceptions import ClientError, BotoCoreError
from botocore.config import Config
import hmac
import hashlib
from functools import wraps
from flask import Flask, jsonify, request, abort, Response, stream_with_context

# In-memory agent telemetry cache (keyed by agentId)
# Populated by /api/agent-scan to allow /api/report/unified to read live data
AGENT_CACHE: dict = {}

# SSE event bus — routes push events here, /api/stream reads from it
import redis
redis_client = redis.Redis.from_url(
    os.environ.get("REDIS_URL", "redis://localhost:6379"),
    decode_responses=True,
    socket_connect_timeout=2,
    socket_timeout=2
)

# -------------------------------------------------------------------
# HMAC Signature Verification Decorator
# -------------------------------------------------------------------
# This decorator protects the /api/agent-scan endpoint by ensuring
# that only agents possessing the pre‑shared secret key can submit
# telemetry data. Without this check, an attacker could flood the
# backend with fabricated vulnerability reports or poison the database.
# -------------------------------------------------------------------

def verify_hmac(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Retrieve the signature from the HTTP headers.
        #    The agent sends this as 'x-agent-signature'.
        provided_signature = request.headers.get('x-agent-signature')
        ts = request.headers.get("x-agent-timestamp")
        nonce = request.headers.get("x-agent-nonce")

        if not provided_signature or not ts or not nonce:
            abort(401, description="Missing EDR cryptographic headers")

        # 2. Load the shared secret(s) from environment variables.
        #    NEVER hardcode this value in the source code.
        #    We support multiple keys for seamless rotation.
        agent_keys_env = os.environ.get("AGENT_KEYS") or os.environ.get("CLOUDSHIELD_API_KEY")
        if not agent_keys_env:
            abort(500, description="Server misconfiguration: AGENT_KEYS not set")
            
        active_keys = [k.strip() for k in agent_keys_env.split(',') if k.strip()]

        # 3. Recompute the HMAC‑SHA256 digest using the raw request body.
        #    Using `request.get_data()` (bytes) instead of `request.json` ensures
        #    that any whitespace or formatting changes do not alter the signature.
        raw_data = request.get_data()
        
        # The target string matches the agent's signing format: 
        # "METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY"
        target_str = f"POST\n{request.path}\n{ts}\n{nonce}\n{raw_data.decode('utf-8')}"
        
        valid_signature = False
        for key in active_keys:
            expected_signature = hmac.new(
                key=key.encode('utf-8'),
                msg=target_str.encode('utf-8'),
                digestmod=hashlib.sha256
            ).hexdigest()

            # 4. Compare the provided signature with the expected one.
            #    `hmac.compare_digest()` prevents timing attacks by comparing
            #    the full string in constant time.
            if hmac.compare_digest(expected_signature, provided_signature):
                valid_signature = True
                break

        if not valid_signature:
            # We would normally trigger handle_failed_auth here, 
            # but for the decorator we simply abort with 401.
            abort(401, description="Invalid cryptographic signature")

        return f(*args, **kwargs)
    return decorated_function


# -------------------------------------------------------------------
# Anti‑Replay Nonce Validation
# -------------------------------------------------------------------
# Each payload includes a 'timestamp' field (nonce). This sliding‑window
# cache prevents an attacker from capturing a valid signed payload and
# resending it multiple times (a replay attack). The window is set to
# 60 seconds, which allows for reasonable clock skew between agents
# and the backend while blocking stale or duplicate submissions.
# -------------------------------------------------------------------

# Simple in‑memory cache for seen nonces. In a production multi‑server
# deployment, this would be replaced with a shared Redis instance.
SEEN_NONCES = {} # map nonce -> expiry_timestamp
NONCE_WINDOW_SECONDS = 60

def is_nonce_valid(nonce, timestamp_str):
    """
    Returns True if the nonce is within the allowed time window AND
    has not been observed previously. Also performs garbage collection
    on expired nonces to prevent unbounded memory growth.
    """
    try:
        nonce_timestamp = float(timestamp_str)
    except (ValueError, TypeError):
        return False
        
    current_time = time.time()

    # 1. Check if the nonce is too old or from the future (clock skew).
    if abs(current_time - nonce_timestamp) > NONCE_WINDOW_SECONDS:
        return False

    # 2. Reject if we have already processed this exact nonce recently.
    if nonce in SEEN_NONCES and SEEN_NONCES[nonce] > current_time:
        return False

    # 3. Garbage collection: remove any nonces that have fallen outside
    #    the valid window. This keeps the set size small.
    if len(SEEN_NONCES) > 5000:
        expired = [k for k, v in SEEN_NONCES.items() if v <= current_time]
        for k in expired:
            del SEEN_NONCES[k]

    # 4. Accept the nonce and add it to the seen set with an expiry.
    SEEN_NONCES[nonce] = current_time + (NONCE_WINDOW_SECONDS * 2)
    return True

# -------------------------------------------------------------------
# Open Policy Agent (OPA) Policy Evaluation
# -------------------------------------------------------------------
# OPA is used to enforce security and compliance rules against both
# container telemetry (Trivy results) and cloud configuration data.
# The policies are written in Rego and codify CIS Benchmarks, as well
# as organizational security requirements. This integration enables
# CloudShield to provide a unified risk assessment and compliance
# reporting layer.
# -------------------------------------------------------------------

import subprocess
from flask import current_app

# Path to the directory containing Rego policy files.
# In production, this would be a mounted volume or fetched from a policy bundle.
OPA_POLICY_DIR = os.path.join(os.path.dirname(__file__), "..", "opa", "policies")

# In‑memory cache for compiled OPA policies to avoid re‑compilation on every request.
# Key: policy file path, Value: compiled policy object.
POLICY_CACHE = {}


def load_opa_policy(policy_name):
    """
    Loads and compiles a Rego policy from the policy directory.
    Uses a simple cache to improve performance.
    Returns a compiled policy object that can be queried repeatedly.
    """
    policy_path = os.path.join(OPA_POLICY_DIR, f"{policy_name}.rego")
    
    if policy_path in POLICY_CACHE:
        return POLICY_CACHE[policy_path]
    
    # In a real deployment, OPA runs as a separate service and we would use
    # the opa-py client or HTTP API. For this demonstration, we invoke the
    # OPA command‑line tool to compile the policy and keep it resident.
    try:
        # Compile the Rego policy into an optimized format.
        result = subprocess.run(
            ["opa", "build", policy_path, "-o", "-"],
            capture_output=True,
            text=True,
            check=True
        )
        # Store the compiled policy bundle in the cache.
        compiled = result.stdout
        POLICY_CACHE[policy_path] = compiled
        return compiled
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        _log.error(f"OPA policy compilation failed for {policy_name}: {str(e)}")
        # If opa binary is missing, we fail gracefully for the demo platform
        return None


def evaluate_opa_policy(policy_name, input_data):
    """
    Evaluates a named OPA policy against the provided input data.
    Returns a list of violation objects, each containing:
      - rule_id: The specific CIS benchmark or custom rule identifier.
      - severity: 'Critical', 'High', 'Medium', or 'Low'.
      - description: Human‑readable explanation of the violation.
      - remediation: Suggested fix or command.
    """
    # Ensure the policy directory exists
    if not os.path.exists(OPA_POLICY_DIR):
        return []

    # Construct the OPA query. For the command‑line approach, we use `opa eval`.
    # Input data is passed as a JSON string.
    input_json = json.dumps(input_data)
    query = f"data.{policy_name}.violations"
    
    try:
        # Execute OPA evaluation. In production, use the OPA REST API:
        # POST /v1/data/{policy_name}/violations with the input JSON.
        result = subprocess.run(
            ["opa", "eval", "--input", "-", "--data", f"{OPA_POLICY_DIR}", query],
            input=input_json,
            capture_output=True,
            text=True,
            check=True
        )
        # The output is a JSON array of violation objects.
        data = json.loads(result.stdout)
        # Extract the violations from the evaluation results
        violations = []
        for res in data.get("result", []):
            for v in res.get("expressions", []):
                val = v.get("value")
                if isinstance(val, list):
                    violations.extend(val)
                elif isinstance(val, dict):
                    violations.append(val)
        return violations if violations else []
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        _log.error(f"OPA evaluation failed: {str(e)}")
        # Fail open for ingest demo, but log the event
        return []


def map_violation_to_compliance(violation):
    """
    Maps a policy violation to relevant compliance frameworks.
    This mapping is used to generate audit‑ready reports for HIPAA, NIST 800‑53,
    and ISO 27001. The mapping table is defined below.
    """
    # Compliance mapping table (simplified example)
    COMPLIANCE_MAP = {
        # CIS Docker Benchmark rules
        "cis-docker-5.1": {
            "hipaa": ["164.312(a)(1)"],  # Access Control
            "nist": ["AC-3", "AC-6"],    # Access Enforcement, Least Privilege
            "iso27001": ["A.9.4.2"]      # Secure log‑on procedures
        },
        "cis-docker-5.3": {
            "hipaa": ["164.312(b)"],     # Audit Controls
            "nist": ["AU-2", "AU-3"],    # Audit Events, Content of Audit Records
            "iso27001": ["A.12.4.1"]     # Event Logging
        },
        # CIS AWS Foundations rules (placeholder)
        "cis-aws-2.1": {
            "hipaa": ["164.312(e)(1)"],  # Transmission Security
            "nist": ["SC-8", "SC-13"],   # Transmission Confidentiality, Cryptographic Protection
            "iso27001": ["A.10.1.1"]     # Policy on the use of cryptographic controls
        }
    }
    
    rule_id = violation.get("rule_id")
    mapping = COMPLIANCE_MAP.get(rule_id, {})
    
    # Return a dictionary that can be attached to the violation record.
    return {
        "hipaa_controls": mapping.get("hipaa", []),
        "nist_controls": mapping.get("nist", []),
        "iso27001_controls": mapping.get("iso27001", [])
    }

from datetime import datetime, timezone
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    from main import run_pipeline, run_demo
except Exception as _import_err:
    _log.warning(f"Could not import run_pipeline/run_demo: {_import_err}")
    run_pipeline = None
    run_demo = None
from policy_engine import evaluate_with_python
from correlation import correlate
from risk_engine import compute_risk_scores
from remediation import generate_remediations
from compliance import map_compliance, get_compliance_summary
from scanner import parse_trivy_output, get_scan_summary
from services.storage_service import check_storage_public
from database import db, Agent, FailedAuth, BlockedIP, AttackMetric

CACHE_FILE = os.path.join(os.path.dirname(__file__), "results_cache.json")
CACHE_TTL = 300  # 5 minutes


def create_app():
    app = Flask(__name__)

    # Database setup
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///cloudshield.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    
    with app.app_context():
        db.create_all()

    # ── CORS Hardening: explicit allow-list ──
    _cors_default = "http://localhost:5173,https://cloudshield-vtah.vercel.app"
    ALLOWED_ORIGINS = [
        o.strip() for o in
        os.environ.get("ALLOWED_ORIGINS", _cors_default).split(",")
        if o.strip()
    ]
    CORS(
        app,
        resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
        supports_credentials=False,
        methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "x-agent-signature",
                       "x-agent-timestamp", "x-agent-nonce"]
    )

    def get_cf_ip():
        return request.headers.get("CF-Connecting-IP", get_remote_address())

    limiter = Limiter(get_cf_ip, app=app, default_limits=["200 per day", "50 per hour"])

    # ── SOC Event Timeline (in-memory, last 100 events) ──
    SOC_TIMELINE = []

    # ── Attack Rate Tracker ──
    ATTACK_TRACKER = {"rate_window": [], "peak_rate": 0}

    def add_soc_event(level: str, message: str):
        """Append to SOC timeline and emit structured log."""
        entry = {
            "level": level,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        SOC_TIMELINE.insert(0, entry)
        if len(SOC_TIMELINE) > 100:
            SOC_TIMELINE.pop()
        log_fn = _log.warning if level in ("WARNING", "CRITICAL") else _log.info
        log_fn("[SOC] [%s] %s", level, message)

    @app.before_request
    def log_request_info():
        # Keep OPTIONS bypass clean
        if request.endpoint == 'OPTIONS':
            return

    def _load_cache():
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r") as f:
                    cache = json.load(f)
                ts = cache.get("cached_at", 0)
                if time.time() - ts < CACHE_TTL:
                    return cache.get("data")
            except (json.JSONDecodeError, KeyError):
                pass
        return None

    def _save_cache(data):
        try:
            with open(CACHE_FILE, "w") as f:
                json.dump({"cached_at": time.time(), "data": data}, f, indent=2, default=str)
        except Exception:
            pass  # Render's ephemeral FS may block writes

    # ── Health Check ──
    @app.route("/")
    def health():
        return jsonify({"status": "ok", "service": "cloudshield-api", "timestamp": datetime.now().isoformat()})

    @app.route("/api/results")
    def api_results():
        cached = _load_cache()
        if cached:
            return jsonify({"status": "cached", "data": cached})
        return jsonify({"status": "no_data", "data": None})

    # ── NEW: Real-Time System Agent Endpoints ──
    NONCE_CACHE = {} # map nonce -> expiry_timestamp
    
    CF_API_TOKEN = os.environ.get("CF_API_TOKEN")
    CF_ZONE_ID = os.environ.get("CF_ZONE_ID")
    CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID")
    SAFE_IPS = [ip.strip() for ip in os.environ.get("SAFE_IPS", "").split(",") if ip.strip()]

    def _cleanup_expired_bans():
        with app.app_context():
            while True:
                time.sleep(60)
                now = time.time()
                try:
                    expired = BlockedIP.query.filter(BlockedIP.expires_at < now).all()
                except Exception:
                    continue  # Wait for db init
                
                for b in expired:
                    if b.rule_id and CF_API_TOKEN and CF_ZONE_ID:
                        print(f"[SECURITY] Unblocking IP {b.ip} (Ban expired)")
                        url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/firewall/access_rules/rules/{b.rule_id}"
                        headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
                        try:
                            res = requests.delete(url, headers=headers, timeout=5)
                            if res.status_code == 200:
                                print(f"[CF-API] Lifted block for {b.ip}")
                            else:
                                print(f"[CF-API] Failed to lift block for {b.ip} - {res.status_code}")
                        except Exception as e:
                            print(f"[CF-API] Failed targeting Edge API: {str(e)}")
                    
                    # Cleanup local DB
                    db.session.delete(b)
                    fa = FailedAuth.query.get(b.ip)
                    if fa:
                        db.session.delete(fa)
                        
                if expired:
                    try:
                        db.session.commit()
                    except:
                        db.session.rollback()

    # Start cleanup thread
    threading.Thread(target=_cleanup_expired_bans, daemon=True).start()

    def block_ip_in_cloudflare(ip):
        if not CF_API_TOKEN or not CF_ZONE_ID:
            print(f"[SECURITY][WARNING] Would block IP {ip} in Cloudflare, but CF_API_TOKEN/CF_ZONE_ID is not set.")
            return

        def _block_async():
            print(f"[CRITICAL] Initiating async Cloudflare block for IP: {ip}")
            url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/firewall/access_rules/rules"
            
            headers = {
                "Authorization": f"Bearer {CF_API_TOKEN}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "mode": "block",
                "configuration": {
                    "target": "ip",
                    "value": ip
                },
                "notes": "Auto-blocked by CloudShield due to repeated spoofing attempts"
            }
            
            try:
                res = requests.post(url, headers=headers, json=payload, timeout=5)
                if res.status_code == 200:
                    data = res.json()
                    rule_id = data.get("result", {}).get("id")
                    if rule_id:
                        with app.app_context():
                            b = BlockedIP.query.get(ip)
                            if b:
                                b.rule_id = rule_id
                                db.session.commit()
                    print(f"[SECURITY][SUCCESS] Edge block applied successfully for IP: {ip} (Rule: {rule_id})")
                else:
                    print(f"[SECURITY][ERROR] Failed to block IP at Edge: {res.status_code} - {res.text}")
            except Exception as e:
                print(f"[SECURITY][ERROR] Failed targeting Edge API: {str(e)}")

        # Run async to not hang the flask thread
        threading.Thread(target=_block_async, daemon=True).start()

    def handle_failed_auth(ip):
        if ip in SAFE_IPS:
            print(f"[SECURITY][INFO] Failed auth from SAFE_IP: {ip}. Ignoring.")
            return
            
        now = time.time()
        fa = FailedAuth.query.get(ip)
        if not fa:
            fa = FailedAuth(ip=ip, count=0, first_attempt=now)
            db.session.add(fa)
        
        # Reset counter after 5 minutes
        if now - fa.first_attempt > 300:
            fa.count = 0
            fa.first_attempt = now
            
        fa.count += 1
        db.session.commit()
        
        print(f"[SECURITY][FAILED_AUTH] IP={ip} Attempts={fa.count}/5")
        add_soc_event("WARNING", f"Bad auth attempt from {ip} — attempt {fa.count}/5")

        # Track attack rate
        ATTACK_TRACKER["rate_window"].append(now)
        ATTACK_TRACKER["rate_window"] = [t for t in ATTACK_TRACKER["rate_window"] if now - t < 60]
        cur_rate = len(ATTACK_TRACKER["rate_window"])
        if cur_rate > ATTACK_TRACKER["peak_rate"]:
            ATTACK_TRACKER["peak_rate"] = cur_rate

        if fa.count >= 5:
            existing_block = BlockedIP.query.get(ip)
            if not existing_block:
                print(f"[CRITICAL] Blocking IP {ip} after 5 failed auth attempts")
                new_block = BlockedIP(ip=ip, rule_id=None, banned_at=now, expires_at=now + 3600)
                db.session.add(new_block)
                db.session.commit()
                add_soc_event("CRITICAL", f"IP {ip} auto-blocked for repeated spoofing (5 failed auth attempts).")
                block_ip_in_cloudflare(ip)

    @app.route("/api/security-metrics", methods=["GET"])
    def api_security_metrics():
        try:
            now = time.time()
            active_blocks = []
            for b in BlockedIP.query.all():
                active_blocks.append({
                    "ip": b.ip,
                    "time_remaining_seconds": max(0, int(b.expires_at - now)),
                    "rule_id": b.rule_id
                })

            attacks = []
            for tr in FailedAuth.query.filter(FailedAuth.count > 0).all():
                attacks.append({
                    "ip": tr.ip,
                    "attempts": tr.count,
                    "first_attempt": tr.first_attempt
                })

            # Compute current attack rate (rolling 60s window)
            ATTACK_TRACKER["rate_window"] = [
                t for t in ATTACK_TRACKER.get("rate_window", []) if now - t < 60
            ]
            current_rate = len(ATTACK_TRACKER.get("rate_window", []))

            return jsonify({
                "status": "success",
                "metrics": {
                    "total_blocked": len(active_blocks) or 0,
                    "total_attack_ips": len(attacks) or 0,
                    "attack_rate": current_rate or 0,
                    "peak_attack_rate": ATTACK_TRACKER.get("peak_rate", 0),
                    "blocked_ips": active_blocks,
                    "recent_attacks": attacks
                }
            })
        except Exception as exc:
            return jsonify({"status": "error", "message": "Internal error"}), 500

    @app.route("/api/soc-timeline", methods=["GET"])
    def api_soc_timeline():
        """Return the last N SOC events (default 50)."""
        try:
            limit = min(int(request.args.get("limit", 50)), 100)
            events = SOC_TIMELINE[:limit] if SOC_TIMELINE else []
            return jsonify({"status": "success", "events": events})
        except Exception as exc:
            return jsonify({"status": "error", "message": "Internal error"}), 500

    # -------------------------------------------------------------------
    # Threat Intelligence + External Integrations
    # -------------------------------------------------------------------
    from services.threat_intel_service import enrich_ip, enrich_cve
    from services.alert_service import trigger_alert, get_recent_alerts

    def send_slack_alert(msg):
        webhook = os.environ.get("SLACK_WEBHOOK_URL")
        if webhook:
            try:
                import requests as _req
                _req.post(webhook, json={"text": f"🚨 CloudShield Alert: {msg}"}, timeout=2)
            except Exception: pass
        # Always trigger internal alert system
        trigger_alert("CRITICAL", "agent-scan", msg)

    @app.route("/api/threat-intel/<ip>", methods=["GET"])
    @limiter.limit("30 per minute")
    def api_threat_intel(ip):
        """Real-time IP threat enrichment using Shodan, AbuseIPDB, GreyNoise, OTX, VirusTotal."""
        result = enrich_ip(ip)
        return jsonify({"status": "success", "data": result})

    @app.route("/api/cve/<cve_id>", methods=["GET"])
    @limiter.limit("20 per minute")
    def api_cve_lookup(cve_id):
        """Real-time CVE enrichment from NIST NVD."""
        result = enrich_cve(cve_id)
        return jsonify({"status": "success", "data": result})

    from services.sandbox_service import detonate_target

    from services.opensearch_service import execute_hunt_query

    @app.route("/api/hunt", methods=["POST", "OPTIONS"])
    @limiter.limit("10 per minute")
    def api_threat_hunt():
        """Velociraptor-style Threat Hunting over SIEM"""
        if request.method == "OPTIONS":
            return jsonify({}), 200
        
        body = request.get_json(silent=True) or {}
        query = body.get("query", "").strip()
        if not query:
            return jsonify({"status": "error", "message": "query field is required"}), 400

        results = execute_hunt_query(query)
        
        if results:
            trigger_alert("WARNING", "threat_hunt", f"Threat Hunt query matched {len(results)} endpoints.")

        return jsonify({"status": "success", "results": results})

    from services.auth_service import verify_credentials, generate_token, decode_token

    @app.route("/api/auth/login", methods=["POST", "OPTIONS"])
    @limiter.limit("5 per minute")
    def api_auth_login():
        if request.method == "OPTIONS":
            return jsonify({}), 200
        
        body = request.get_json(silent=True) or {}
        username = body.get("username", "")
        password = body.get("password", "")
        
        user = verify_credentials(username, password)
        if not user:
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401
            
        token = generate_token(username, user["role"])
        return jsonify({"status": "success", "token": token, "user": {"name": user["name"], "role": user["role"]}})

    @app.route("/api/auth/me", methods=["GET"])
    def api_auth_me():
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"status": "error", "message": "Missing token"}), 401
            
        token = auth_header.split(" ")[1]
        decoded = decode_token(token)
        if "error" in decoded:
            return jsonify({"status": "error", "message": decoded["error"]}), 401
            
        return jsonify({"status": "success", "user": {"username": decoded["sub"], "role": decoded["role"]}})

    from services.case_management_service import create_case, get_cases, get_case, update_case

    @app.route("/api/cases", methods=["GET", "POST", "OPTIONS"])
    def api_cases():
        if request.method == "OPTIONS":
            return jsonify({}), 200
        if request.method == "POST":
            body = request.get_json(silent=True) or {}
            title = body.get("title", "New Investigation")
            desc = body.get("description", "")
            # Assuming analyst user for now
            case = create_case(title, desc, created_by="analyst")
            return jsonify({"status": "success", "data": case}), 201
        return jsonify({"status": "success", "data": get_cases()})

    @app.route("/api/cases/<case_id>", methods=["GET", "PUT"])
    def api_case_detail(case_id):
        if request.method == "PUT":
            body = request.get_json(silent=True) or {}
            updated = update_case(case_id, body, user="analyst")
            if not updated:
                return jsonify({"status": "error", "message": "Case not found or invalid update"}), 400
            return jsonify({"status": "success", "data": updated})
        
        case = get_case(case_id)
        if not case:
            return jsonify({"status": "error", "message": "Case not found"}), 404
        return jsonify({"status": "success", "data": case})

    @app.route("/api/sandbox/analyze", methods=["POST", "OPTIONS"])
    @limiter.limit("5 per minute")
    def api_sandbox_analyze():
        """ANY.RUN style interactive sandbox detonation"""
        if request.method == "OPTIONS":
            return jsonify({}), 200
        body = request.get_json(silent=True) or {}
        target = body.get("target", "").strip()
        if not target:
            return jsonify({"status": "error", "message": "target field is required"}), 400

        result = detonate_target(target)
        
        # Correlate Sandbox alert
        if result.get("status") == "completed" and result.get("iocs"):
            trigger_alert("HIGH", "sandbox", f"Malicious execution detected in sandbox for target: {target}")

        return jsonify({"status": "success", "data": result})

    @app.route("/api/alerts", methods=["GET"])
    def api_alerts():
        """Return recent system alerts."""
        limit = min(int(request.args.get("limit", 20)), 50)
        return jsonify({"status": "success", "alerts": get_recent_alerts(limit)})

    @app.route("/api/agent-scan", methods=["POST", "OPTIONS"])
    @limiter.limit("30 per minute")
    @verify_hmac   # <-- Signature check happens first
    def api_agent_scan():
        if request.method == "OPTIONS":
            return jsonify({}), 200

        client_ip = get_cf_ip()

        # Enforce Payload Size Limit (512KB)
        if request.content_length and request.content_length > 512 * 1024:
            return jsonify({"status": "error", "message": "Payload too large"}), 413

        # Anti-Replay Validation
        # The signature verification already passed, now we check the nonce.
        ts = request.headers.get("x-agent-timestamp")
        nonce = request.headers.get("x-agent-nonce")
        
        if not is_nonce_valid(nonce, ts):
            return jsonify({"status": "error", "message": "Duplicate or expired request"}), 409

        try:
            raw_data = request.get_data()
            payload = json.loads(raw_data.decode('utf-8'))
            if not isinstance(payload, dict):
                return jsonify({"status": "error", "message": "Invalid JSON mapping"}), 400

            agent_id = str(payload.get("agentId", "unknown"))
            if not re.match(r"^[a-zA-Z0-9\-]{10,50}$", agent_id):
                return jsonify({"status": "error", "message": "Invalid Agent ID format"}), 400

            # ── [NEW] OPA Policy Engine Integration ──
            # After validating the payload, extract container information for OPA.
            opa_containers = []
            
            # Map running containers from EDR telemetry
            for c in payload.get("docker_containers", []):
                opa_containers.append({
                    "name": c.get("name") or c.get("id"),
                    "image": c.get("image"),
                    "privileged": False,  # EDR could be enhanced to detect true privileged state
                    "readonly_rootfs": False, # EDR could check mount flags
                    "runtime_status": c.get("status")
                })
            
            # Prepare input for OPA evaluation against cis_docker policies
            opa_input = {
                "containers": opa_containers,
                "cloud_resources": payload.get("cloud_resources", [])
            }
            
            # Evaluate the CIS Docker benchmark package
            docker_violations = evaluate_opa_policy("cis_docker", opa_input)
            
            # Attach compliance mappings (HIPAA, NIST, ISO) to each violation
            for v in docker_violations:
                v["compliance"] = map_violation_to_compliance(v)
                
            # Embed policy violations into payload for risk synthesis
            payload["policy_violations"] = docker_violations
            payload["violations_found"] = len(docker_violations)

            # Granular Risk Orchestra (Includes policy risk)
            load = payload.get("cpu_percent", 0)
            ports = payload.get("open_ports", [])
            vulns = payload.get("vulnerabilities", [])
            
            sys_risk = 10 if load > 90 else (5 if load > 75 else 0)
            net_risk = min(50, len(ports) * 2)
            
            # CVE Risk Calculation (based on Trivy findings)
            crit_cves = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
            high_cves = sum(1 for v in vulns if v.get("severity") == "HIGH")
            cve_risk = min(100, (crit_cves * 20) + (high_cves * 10))
            
            # Policy Risk Calculation (based on OPA violations)
            pol_risk = min(100, len(docker_violations) * 15)
            
            # Aggregate risk score (weighted cross-layer)
            risk_score = min(100, sys_risk + net_risk + cve_risk + pol_risk)
            
            if risk_score >= 80: risk_level = "Critical"
            elif risk_score >= 60: risk_level = "High"
            elif risk_score >= 40: risk_level = "Medium"
            else: risk_level = "Low"

            priority_fix = "No immediate action required."
            if pol_risk >= cve_risk and pol_risk > 0:
                priority_fix = f"Remediate {len(docker_violations)} CIS Docker policy violations."
            elif cve_risk >= net_risk and cve_risk > 0:
                priority_fix = "Patch OS vulnerabilities detected by Trivy."
            elif net_risk >= sys_risk and net_risk > 0:
                priority_fix = f"Close {len(ports)} unauthorized listening ports."

            # ── Threat Intelligence Enrichment ──
            # Query real OSINT sources for the agent's source IP
            client_ip = get_cf_ip()
            intel = enrich_ip(client_ip)
            threat_score = intel.get("threat_score", 0)

            # Correlate: threat intel + system risk + network exposure
            is_attack_chain = False
            if threat_score > 50 and sys_risk > 20 and net_risk > 20:
                is_attack_chain = True
                risk_score = min(100, risk_score + 40)
                priority_fix = "CRITICAL ATTACK CHAIN DETECTED: Immediately isolate host and block source IP."

            payload["risk_score"] = risk_score
            payload["risk_level"] = risk_level
            payload["risk_breakdown"] = {
                "system": sys_risk, 
                "network": net_risk, 
                "cve": cve_risk,
                "compliance": pol_risk,
                "threat_intel": threat_score
            }
            payload["threat_intel"] = intel
            payload["priorityFix"] = priority_fix

            # Alerting — fires on high risk or confirmed attack chain
            if risk_score > 80 or is_attack_chain:
                hostname = payload.get("hostname", "unknown")
                send_slack_alert(f"Host {hostname} (IP: {client_ip}) exceeded risk threshold. Score: {risk_score}. {priority_fix}")

            # Persist telemetry to database
            agent = Agent.query.get(agent_id)
            if not agent:
                agent = Agent(agent_id=agent_id)
                db.session.add(agent)
                
            agent.hostname = payload.get("hostname", "unknown")
            agent.cpu = float(payload.get("cpu_percent", 0.0))
            agent.ram = float(payload.get("ram_percent", 0.0))
            agent.last_seen = time.time()
            agent.status = "online"
            agent.set_data(payload)
            
            db.session.commit()

            # Populate in-memory AGENT_CACHE for /api/report/unified
            AGENT_CACHE[agent_id] = {"timestamp": time.time(), "data": payload}

            # Push real-time event to Persistent Stream (Redis Streams)
            try:
                import json as _json
                event_data = {
                    "type": "agent_update",
                    "data": {
                        "agentId": agent_id,
                        "hostname": payload.get("hostname"),
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "cpu": payload.get("cpu_percent"),
                        "ram": payload.get("ram_percent"),
                        "timestamp": time.time()
                    }
                }
                redis_client.xadd('events_stream', {'payload': _json.dumps(event_data)}, maxlen=10000)
                # Broadcast for immediate SSE clients
                redis_client.publish('sse_channel', _json.dumps(event_data))
            except Exception as e:
                print(f"Redis publish/stream error: {e}")

            # Trigger SOC alert on compliance violations
            if len(docker_violations) > 0:
                add_soc_event("WARNING", f"Policy breach: Agent {agent_id} has {len(docker_violations)} compliance violations.")

            return jsonify({
                "status": "success",
                "message": "Telemetry received and analyzed",
                "violations_found": len(docker_violations)
            })

        except Exception as exc:
            add_soc_event("WARNING", f"/api/agent-scan error: {str(exc)}")
            return jsonify({"status": "error", "message": "Internal agent scan error."}), 500

    @app.route("/api/agent-status", methods=["GET"])

    def api_agent_status():
        agents = []
        now = time.time()
        
        for agent in Agent.query.all():
            time_diff = now - agent.last_seen
            
            if time_diff > 300: # TTL 5 minutes to drop
                db.session.delete(agent)
                continue
                
            if time_diff <= 60:
                status = "online"
            elif time_diff <= 180:
                status = "stale"
            else:
                status = "offline"
                
            agent_data = agent.get_data()
            agent_data["connection_status"] = status
            agent_data["last_seen_seconds_ago"] = round(time_diff, 1)
            health = 100 - min(100, (time_diff/60)*10)
            agent_data["healthScore"] = round(health)
            
            agents.append(agent_data)
            
        db.session.commit()
            
        return jsonify({
            "status": "success",
            "agents": agents
        })

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        try:
            body = request.get_json(silent=True) or {}
            image = body.get("image")
            config = body.get("config")
            trivy_output = body.get("trivy_output")

            if not config and not image and not trivy_output:
                now = time.time()
                db_agent = next((a for a in Agent.query.all() if now - a.last_seen <= 180), None)
                active_agent = db_agent.get_data() if db_agent else None
                
                if active_agent:
                    findings = []
                    for vuln in active_agent.get("vulnerabilities", []):
                        findings.append({
                            "id": vuln.get("id"),
                            "type": "Vulnerability",
                            "severity": vuln.get("severity"),
                            "title": vuln.get("title"),
                            "description": f"Found in {vuln.get('pkg')}",
                            "source": "trivy"
                        })
                    
                    risk = compute_risk_scores(findings)
                    remediations = generate_remediations(findings)
                    enriched = map_compliance(findings)
                    comp_summary = get_compliance_summary(enriched)
                    
                    result = {
                        "timestamp": datetime.now().isoformat(),
                        "findings": enriched,
                        "risk": risk,
                        "remediations": remediations,
                        "compliance": comp_summary,
                        "alert_summary": {
                            "total": len(findings),
                            "critical": sum(1 for a in findings if a.get("severity") == "CRITICAL"),
                            "high": sum(1 for a in findings if a.get("severity") == "HIGH"),
                            "medium": sum(1 for a in findings if a.get("severity") == "MEDIUM"),
                            "low": sum(1 for a in findings if a.get("severity") == "LOW")
                        }
                    }
                    _save_cache(result)
                    add_soc_event("INFO", "Full pipeline scan completed using Live Agent data.")
                    return jsonify({"status": "completed", "data": result})
                else:
                    return jsonify({"status": "error", "message": "No active agents connected"}), 400

            if run_pipeline is None:
                return jsonify({"status": "error", "message": "Pipeline not available"}), 503
            result = run_pipeline(image=image, config=config, trivy_output=trivy_output)
            _save_cache(result)
            add_soc_event("INFO", "Full pipeline scan completed via /api/scan.")
            return jsonify({"status": "completed", "data": result})
        except Exception as exc:
            add_soc_event("WARNING", f"/api/scan server error: {str(exc)}")
            return jsonify({"status": "error", "message": "Internal scan error. Check server logs."}), 500


    # /api/demo removed — system operates on real data only


    @app.route("/api/storage/check", methods=["POST", "OPTIONS"])
    def check_storage():
        print("STORAGE CHECK LIVE VERSION", flush=True)
        if request.method == "OPTIONS":
            return jsonify({}), 200
        try:
            data = request.get_json(silent=True) or {}
            provider = (data.get("provider") or "aws").strip().lower()
            bucket   = (data.get("bucket") or "").strip()

            print(f"[STORAGE CHECK] provider={provider} bucket={bucket}", flush=True)

            if not bucket:
                return jsonify({"public": False, "error": "Missing bucket name", "provider": provider, "bucket": bucket}), 200

            result = check_storage_public(provider, bucket)

            # Ensure these keys are always present for frontend + AI pipeline
            result.setdefault("provider", provider)
            result.setdefault("bucket", bucket)
            result.setdefault("public", False)
            result.setdefault("status", "Unknown")

            print(f"[STORAGE CHECK] result={result}", flush=True)
            return jsonify(result), 200

        except Exception as e:
            print(f"[STORAGE CHECK] UNHANDLED ERROR: {e}", flush=True)
            return jsonify({
                "public": False,
                "error": str(e),
                "status": "Error",
                "provider": "unknown",
                "bucket": ""
            }), 500

    # ── NEW: Raw Config Scan Endpoint ──
    @app.route("/api/scan-config", methods=["POST"])
    def api_scan_config():
        """
        Accept raw cloud configuration code (JSON or YAML),
        analyze for misconfigurations, compliance issues, and generate alerts + remediation.
        """
        try:
            body = request.get_json(silent=True) or {}
            raw_config = body.get("config_text", "")
            config_type = body.get("config_type", "json")  # json or yaml

            if not raw_config or not raw_config.strip():
                return jsonify({"status": "error", "message": "No configuration text provided"}), 400

            # Parse the raw config text
            try:
                if config_type == "yaml":
                    config_data = yaml.safe_load(raw_config)
                else:
                    config_data = json.loads(raw_config)
            except (json.JSONDecodeError, yaml.YAMLError) as e:
                return jsonify({
                    "status": "error",
                    "message": f"Failed to parse {config_type.upper()} configuration: {str(e)}",
                    "alerts": [{
                        "severity": "HIGH",
                        "type": "PARSE_ERROR",
                        "title": f"Invalid {config_type.upper()} Syntax",
                        "message": str(e),
                        "remediation": f"Fix the {config_type.upper()} syntax error at the specified location."
                    }]
                }), 400

            if not isinstance(config_data, dict):
                return jsonify({"status": "error", "message": "Configuration must be a JSON/YAML object (not array or scalar)"}), 400

            log = []
            ts = lambda: datetime.now().strftime("%H:%M:%S")

            log.append(f"[{ts()}] Received raw {config_type.upper()} configuration ({len(raw_config)} chars)")

            log.append(f"[{ts()}] Policy Engine — evaluating raw config...")
            policy_findings = evaluate_with_python(config_data)
            pol_crit = sum(1 for f in policy_findings if f.get("severity") == "CRITICAL")
            log.append(f"[{ts()}] ✓ Policy Engine — {len(policy_findings)} violations ({pol_crit} CRITICAL)")

            log.append(f"[{ts()}] Correlation Engine — analyzing...")
            all_findings = correlate([], policy_findings)
            corr_count = sum(1 for f in all_findings if f.get("source") == "correlation")
            log.append(f"[{ts()}] ✓ Correlation — {corr_count} cross-source findings")

            risk = compute_risk_scores(all_findings)
            log.append(f"[{ts()}] ✓ Risk Scoring — Score: {risk['final_score']} ({risk['category']})")

            remediations = generate_remediations(all_findings)
            log.append(f"[{ts()}] ✓ Remediation — {len(remediations)} fix actions generated")

            enriched = map_compliance(all_findings)
            comp_summary = get_compliance_summary(enriched)
            log.append(f"[{ts()}] ✓ Compliance — Mapped to {comp_summary['frameworks_impacted']} frameworks")

            alerts = []
            for f in enriched:
                sev = f.get("severity", "LOW")
                alert = {
                    "severity": sev,
                    "type": f.get("type", "UNKNOWN"),
                    "title": f.get("title", "Unknown Issue"),
                    "message": f.get("message", f.get("description", "")),
                    "id": f.get("id", ""),
                    "policy": f.get("policy", ""),
                }
                if sev in ("CRITICAL", "HIGH"):
                    alert["alert_level"] = "🚨 CRITICAL ALERT" if sev == "CRITICAL" else "⚠️ HIGH ALERT"
                else:
                    alert["alert_level"] = "ℹ️ INFO"
                alerts.append(alert)

            result = {
                "timestamp": datetime.now().isoformat(),
                "config_type": config_type,
                "config_size": len(raw_config),
                "findings": enriched,
                "risk": risk,
                "remediations": remediations,
                "compliance": comp_summary,
                "alerts": alerts,
                "alert_summary": {
                    "total": len(alerts),
                    "critical": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
                    "high": sum(1 for a in alerts if a["severity"] == "HIGH"),
                    "medium": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
                    "low": sum(1 for a in alerts if a["severity"] == "LOW"),
                },
                "execution_log": log,
            }

            _save_cache(result)
            crit_count = result["alert_summary"]["critical"]
            add_soc_event(
                "WARNING" if crit_count > 0 else "INFO",
                f"Config scan complete: {len(enriched)} findings, {crit_count} critical."
            )
            return jsonify({"status": "completed", "data": result})

        except Exception as exc:
            add_soc_event("WARNING", f"/api/scan-config error: {str(exc)}")
            return jsonify({"status": "error", "message": "Internal config scan error."}), 500

    @app.route("/api/download-agent", methods=["GET"])
    def api_download_agent():
        """Serve locally-built CloudShield agent or return error (DevSecOps Locked)."""
        from flask import send_from_directory
        import os
        static_dir = os.path.join(app.root_path, "static")
        agent_file = "cloudshield-agent.exe"
        
        if os.path.exists(os.path.join(static_dir, agent_file)):
            return send_from_directory(static_dir, agent_file, as_attachment=True)
            
        return jsonify({
            "status": "error",
            "message": "Agent binary not built. Please run build_agent.ps1 locally."
        }), 404

    @app.route("/api/agent-keys", methods=["GET"])
    def api_agent_keys():
        """Return primary API key for display in the Deploy Agent modal."""
        agent_keys_env = os.environ.get("AGENT_KEYS")
        if not agent_keys_env:
            return jsonify({"status": "error", "message": "No keys configured"}), 404
            
        primary_key = agent_keys_env.split(',')[0].strip()
        backend_url = os.environ.get("CLOUDSHIELD_API_URL", "http://localhost:5000")
        download_url = f"{backend_url}/api/download-agent"
        return jsonify({
            "status": "success",
            "api_key": primary_key,
            "download_url": download_url,
            "backend_url": backend_url
        })

    # ══════════════════════════════════════════════════════════════════
    #  EXTENDED SERVICES — Phase 2-8 (Trivy, OPA, AI, Compliance, DB)
    #  All routes are ADDITIVE — existing routes are not modified.
    # ══════════════════════════════════════════════════════════════════

    from services.trivy_service      import scan_container_image
    from services.opa_service        import evaluate_cloud_config
    from services.ai_service         import analyze_risk
    from services.correlation_service import correlate_all
    from services.compliance_service  import map_findings_to_compliance
    from services import db_service

    @app.route("/api/scan/container", methods=["POST", "OPTIONS"])
    @limiter.limit("10 per minute")
    def api_scan_container():
        """
        Trivy container image scan.
        POST body: { "image": "nginx:latest" }
        Returns real CVE findings via Trivy Server, Trivy CLI, or OSV.dev fallback.
        """
        print("DEPLOY CHECK: NEW VERSION ACTIVE", flush=True)
        if request.method == "OPTIONS":
            return jsonify({}), 200
        body = request.get_json(silent=True) or {}
        image = body.get("image", "").strip()
        if not image:
            return jsonify({"status": "error", "message": "image field is required"}), 400

        result = scan_container_image(image)

        if result.get("status") == "completed":
            # Persist to DB (async-safe, non-blocking)
            try:
                db_service.save_vulnerability_scan(image, result)
            except Exception:
                pass
            add_soc_event("INFO" if result["summary"]["critical"] == 0 else "WARNING",
                          f"Container scan '{image}': {result['summary']['total']} vulns "
                          f"({result['summary']['critical']} critical, {result['summary']['high']} high).")

        return jsonify({"status": result.get("status", "error"), "data": result})

    from services.aws_service import generate_live_cloud_config

    @app.route("/api/scan/cloud", methods=["POST", "OPTIONS"])
    @limiter.limit("20 per minute")
    def api_scan_cloud():
        """
        OPA/built-in cloud configuration policy scan.
        POST body: JSON cloud config (AWS/GCP/Azure resource definitions)
        Returns policy violations mapped to real rules.
        """
        print("CLOUD FIX VERSION 2 ACTIVE", flush=True)
        if request.method == "OPTIONS":
            return jsonify({}), 200
        
        body = request.get_json(silent=True)
        # Auto-fetch AWS if body is empty or not provided
        if not body or not isinstance(body, dict):
            live_config = generate_live_cloud_config()
            if live_config:
                body = live_config
            else:
                return jsonify({"status": "error", "message": "Valid JSON cloud configuration is required."}), 400

        # Limit payload size
        if len(json.dumps(body)) > 256 * 1024:
            return jsonify({"status": "error", "message": "Config payload exceeds 256KB limit"}), 413

        result = evaluate_cloud_config(body)

        if result.get("status") == "completed":
            try:
                db_service.save_cloud_scan("json", result)
            except Exception:
                pass
            add_soc_event("WARNING" if result["summary"]["CRITICAL"] > 0 else "INFO",
                          f"Cloud scan: {result['summary']['total']} violations "
                          f"({result['summary']['CRITICAL']} critical).")

        return jsonify({"violations": result.get("violations", [])})

    @app.route("/api/scan/aws", methods=["POST", "OPTIONS"])
    @limiter.limit("5 per minute")
    def api_scan_aws():
        """Explicitly trigger a live AWS scan using local credentials."""
        if request.method == "OPTIONS":
            return jsonify({}), 200
            
        live_config = generate_live_cloud_config()
        if not live_config:
            return jsonify({"status": "error", "message": "No valid AWS credentials found locally."}), 400
            
        result = evaluate_cloud_config(live_config)
        
        if result.get("status") == "completed":
            try:
                db_service.save_cloud_scan("aws", result)
            except Exception:
                pass
            add_soc_event("WARNING" if result["summary"]["CRITICAL"] > 0 else "INFO",
                          f"Live AWS scan: {result['summary']['total']} violations "
                          f"({result['summary']['CRITICAL']} critical).")

        return jsonify({"status": result.get("status", "error"), "data": result})


    @app.route("/api/analyze/risk", methods=["POST", "OPTIONS"])
    @limiter.limit("10 per minute")
    def api_analyze_risk():
        """
        AI/LLM-powered risk analysis.
        POST body: { "findings": [...], "risk_score": {...} }
        Returns enriched risk narrative, attack vectors, and remediation steps.
        """
        if request.method == "OPTIONS":
            return jsonify({}), 200
        body = request.get_json(silent=True) or {}
        findings   = body.get("findings", [])
        risk_score = body.get("risk_score", {})

        if not isinstance(findings, list):
            return jsonify({"status": "error", "message": "findings must be a list"}), 400

        analysis = analyze_risk(findings, risk_score)
        add_soc_event("INFO", f"AI risk analysis complete: {analysis.get('overall_risk', 'N/A')} risk "
                              f"(engine: {analysis.get('_source', 'unknown')}).")

        return jsonify({"status": "success", "data": analysis})

    @app.route("/api/report/unified", methods=["POST", "OPTIONS"])
    @limiter.limit("10 per minute")
    def api_report_unified():
        """
        Full unified security report combining:
        - Container CVE scan (Trivy)
        - Cloud config policy scan (OPA)
        - AI risk analysis
        - Cross-source correlation
        - Compliance mapping (CIS, NIST, ISO 27001, HIPAA)

        POST body: {
          "image":        "nginx:latest",    // optional
          "cloud_config": {...},             // optional
          "agent_id":     "uuid"             // optional — pull from AGENT_CACHE
        }
        """
        if request.method == "OPTIONS":
            return jsonify({}), 200
        body = request.get_json(silent=True) or {}
        image        = body.get("image", "").strip()
        cloud_config = body.get("cloud_config", {})
        agent_id     = body.get("agent_id", "")

        # Step 1: Container scan (if image provided)
        container_result = {}
        container_vulns  = []
        if image:
            container_result = scan_container_image(image)
            container_vulns  = container_result.get("vulnerabilities", [])

        # Step 2: Cloud policy scan (if config provided)
        cloud_result    = {}
        policy_violations = []
        if cloud_config and isinstance(cloud_config, dict):
            cloud_result      = evaluate_cloud_config(cloud_config)
            policy_violations = cloud_result.get("violations", [])

        # Step 3: Pull live agent CVEs if agent_id provided or any agent is online
        agent_cve_findings = []
        now = time.time()
        if agent_id and agent_id in AGENT_CACHE:
            agent_cve_findings = AGENT_CACHE[agent_id]["data"].get("vulnerabilities", [])
        elif not agent_id:
            for a_id, entry in AGENT_CACHE.items():
                if now - entry["timestamp"] <= 180:
                    agent_cve_findings = entry["data"].get("vulnerabilities", [])
                    break

        # Step 4: Correlate all streams
        corr_result = correlate_all(
            cve_findings=agent_cve_findings,
            policy_violations=policy_violations,
            container_vulns=container_vulns
        )
        all_findings = corr_result["findings"]
        risk         = corr_result["risk"]

        # Step 5: AI analysis
        ai_analysis = analyze_risk(all_findings, risk)

        # Step 6: Compliance mapping
        compliance = map_findings_to_compliance(all_findings)

        # Step 7: Build unified report
        report = {
            "timestamp":          datetime.now().isoformat(),
            "risk":               risk,
            "ai_analysis":        ai_analysis,
            "compliance":         compliance,
            "correlation_events": corr_result.get("correlation_events", []),
            "stream_counts":      corr_result.get("stream_counts", {}),
            "findings":           all_findings[:100],    # cap for payload size
            "container_scan":     {
                "image":   image,
                "summary": container_result.get("summary", {}),
                "status":  container_result.get("status", "skipped")
            },
            "cloud_scan": {
                "summary": cloud_result.get("summary", {}),
                "status":  cloud_result.get("status", "skipped"),
                "engine":  cloud_result.get("engine", "none")
            },
            "alert_summary": {
                "total":    risk.get("finding_count", 0),
                "critical": sum(1 for f in all_findings if f.get("severity") == "CRITICAL"),
                "high":     sum(1 for f in all_findings if f.get("severity") == "HIGH"),
                "medium":   sum(1 for f in all_findings if f.get("severity") == "MEDIUM"),
                "low":      sum(1 for f in all_findings if f.get("severity") == "LOW"),
            }
        }

        # Persist report
        try:
            db_service.save_risk_report(report)
        except Exception:
            pass

        add_soc_event("WARNING" if risk.get("category") in ("CRITICAL", "HIGH") else "INFO",
                      f"Unified report generated: {risk.get('category', 'N/A')} risk, "
                      f"{risk.get('finding_count', 0)} total findings.")

        return jsonify({"status": "completed", "data": report})

    @app.route("/api/db/health", methods=["GET"])
    def api_db_health():
        """Database connection health check."""
        return jsonify(db_service.health_check())

    # ══════════════════════════════════════════════════════════════════
    #  EXTENDED SERVICES — Phase 9 (Agent telemetry, Alerts, Scheduler)
    # ══════════════════════════════════════════════════════════════════

    from services import alert_service
    from services import scheduler_service

    # Start the continuous scanner
    scheduler_service.start_scheduler()

    @app.route("/api/alerts", methods=["GET"])
    def api_get_alerts():
        """Returns the most recent system alerts."""
        return jsonify({"status": "success", "data": alert_service.get_recent_alerts()})

    @app.route("/api/agent/report", methods=["POST", "OPTIONS"])
    @limiter.limit("60 per minute")
    def api_agent_report():
        """
        Receives advanced agent telemetry including running containers.
        """
        if request.method == "OPTIONS":
            return jsonify({}), 200
            
        data = request.get_json(silent=True) or {}
        agent_id = data.get("agentId", "unknown")
        
        # We store this in the Persistent DB
        agent = Agent.query.get(agent_id)
        if not agent:
            agent = Agent(agent_id=agent_id)
            db.session.add(agent)
            
        agent.hostname = data.get("hostname", "unknown")
        agent.cpu = float(data.get("cpu_percent", 0.0))
        agent.ram = float(data.get("ram_percent", 0.0))
        agent.last_seen = time.time()
        agent.status = "online"
        
        # Merge existing data
        existing = agent.get_data()
        existing.update(data)
        existing["ip"] = request.remote_addr
        agent.set_data(existing)
        db.session.commit()
        
        # Analyze risk of the immediate vulnerabilities posted by the agent
        vulns = data.get("vulnerabilities", [])
        if vulns:
            # We map this into our risk engine
            pass
            
        return jsonify({"status": "success", "message": "Telemetry received"})

    @app.route("/api/risk/score", methods=["GET"])
    def api_risk_score():
        """Returns global aggregated risk score from recent findings."""
        # Pulling from DB
        total_vulns = []
        now = time.time()
        for agent in Agent.query.filter(Agent.last_seen > now - 300).all():
            total_vulns.extend(agent.get_data().get("vulnerabilities", []))
            
        from risk_engine import compute_risk_scores
        score_data = compute_risk_scores(total_vulns)
        return jsonify({"status": "success", "data": score_data})


    @app.route("/api/dashboard-summary", methods=["GET"])
    def api_dashboard_summary():
        """Lightweight consolidated endpoint for dashboard telemetry (<100KB)."""
        now = time.time()
        summary = {
            "agents": [],
            "metrics": {"total_blocked": 0, "attack_rate": 0, "peak_attack_rate": 0, "blocked_ips": []},
            "risk": {"final_score": 0, "category": "LOW"},
            "alerts": [],
            "soc_timeline": [],
            "deploy": {
                "api_key": "N/A",
                "download_url": f"{os.environ.get('CLOUDSHIELD_API_URL', 'http://localhost:5000')}/api/download-agent"
            }
        }

        # 1. Agents
        try:
            all_agents = Agent.query.filter(Agent.last_seen > now - 300).order_by(Agent.last_seen.desc()).limit(20).all()
            for agent in all_agents:
                time_diff = now - agent.last_seen
                status = "online" if time_diff <= 60 else ("stale" if time_diff <= 180 else "offline")
                agent_data = agent.get_data()
                agent_data["connection_status"] = status
                agent_data["last_seen_seconds_ago"] = round(time_diff, 1)
                agent_data["healthScore"] = round(100 - min(100, (time_diff/60)*10))
                # Prune vulnerabilities to 5 items for dashboard list, max 50 for risk score input
                if "vulnerabilities" in agent_data and len(agent_data["vulnerabilities"]) > 5:
                    agent_data["vulnerabilities"] = agent_data["vulnerabilities"][:5]
                summary["agents"].append(agent_data)
        except Exception: pass

        # 2. Metrics
        try:
            active_blocks = []
            all_blocks = BlockedIP.query.all()
            for b in all_blocks[:10]:
                active_blocks.append({
                    "ip": b.ip, 
                    "time_remaining_seconds": max(0, int(b.expires_at - now))
                })
            summary["metrics"] = {
                "total_blocked": len(all_blocks),
                "attack_rate": len([t for t in ATTACK_TRACKER.get("rate_window", []) if now - t < 60]),
                "peak_attack_rate": ATTACK_TRACKER.get("peak_rate", 0),
                "blocked_ips": active_blocks
            }
        except Exception: pass

        # 3. Risk
        try:
            total_vulns = []
            for a in summary["agents"]:
                total_vulns.extend(a.get("vulnerabilities", []))
            # Limit total vulns for processing to keep payload compact
            total_vulns = total_vulns[:50]
            from risk_engine import compute_risk_scores
            summary["risk"] = compute_risk_scores(total_vulns)
        except Exception: pass

        # 4. Alerts
        try:
            from services import alert_service
            summary["alerts"] = alert_service.get_recent_alerts()[:10]
        except Exception: pass

        # 5. Cloud findings (last scan from DB)
        try:
            from services import db_service
            last_cloud = db_service.get_last_cloud_scan()
            summary["cloud_findings"] = last_cloud.get("violations", [])[:10] if last_cloud else []
        except Exception:
            summary["cloud_findings"] = []

        # 6. Timeline & Keys
        try:
            summary["soc_timeline"] = SOC_TIMELINE[:10]
            keys = os.environ.get("AGENT_KEYS", "").split(',')
            summary["deploy"]["api_key"] = keys[0].strip() if keys[0] else "N/A"
        except Exception: pass

        return jsonify({"status": "success", "data": summary})

    # ── SSE Real-Time Stream ──
    @app.route("/api/stream")
    def api_stream():
        """Server-Sent Events endpoint — pushes live agent + alert updates to dashboard."""
        def generate():
            yield "retry: 5000\n\n"  # client reconnects after 5s if disconnected
            pubsub = redis_client.pubsub()
            pubsub.subscribe('sse_channel')
            import json as _json
            
            while True:
                message = pubsub.get_message(ignore_subscribe_messages=True, timeout=15.0)
                if message is not None and message['type'] == 'message':
                    event = _json.loads(message['data'])
                    payload = _json.dumps(event["data"], default=str)
                    yield f"event: {event['type']}\ndata: {payload}\n\n"
                else:
                    yield ": keepalive\n\n"
        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        )

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
