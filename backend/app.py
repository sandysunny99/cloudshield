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
import yaml
import boto3
import re
from botocore.exceptions import ClientError, BotoCoreError
from botocore.config import Config
import hmac
import hashlib
import threading
import requests

# Multi-cloud SDKs
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError
from google.cloud import storage
from google.api_core.exceptions import GoogleAPIError
from google.oauth2 import service_account

from datetime import datetime, timezone
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from main import run_pipeline, run_demo
from policy_engine import evaluate_with_python
from correlation import correlate
from risk_engine import compute_risk_scores
from remediation import generate_remediations
from compliance import map_compliance, get_compliance_summary
from scanner import parse_trivy_output, get_scan_summary

CACHE_FILE = os.path.join(os.path.dirname(__file__), "results_cache.json")
CACHE_TTL = 300  # 5 minutes
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_data")


def create_app():
    app = Flask(__name__)

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
    AGENT_CACHE = {}
    NONCE_CACHE = {} # map nonce -> expiry_timestamp
    
    # Cloudflare Auto-Block Tracking
    FAILED_AUTH_TRACKER = {}  # { ip: { "count": int, "first_attempt": timestamp } }
    BLOCKED_IPS = {}          # { ip: { "rule_id": str, "banned_at": ts, "expires_at": ts } }
    
    CF_API_TOKEN = os.environ.get("CF_API_TOKEN")
    CF_ZONE_ID = os.environ.get("CF_ZONE_ID")
    CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID")
    SAFE_IPS = [ip.strip() for ip in os.environ.get("SAFE_IPS", "").split(",") if ip.strip()]

    def _cleanup_expired_bans():
        while True:
            time.sleep(60)
            now = time.time()
            expired = []
            for ip, data in list(BLOCKED_IPS.items()):
                if now > data["expires_at"]:
                    expired.append((ip, data["rule_id"]))
            
            for ip, rule_id in expired:
                if rule_id and CF_API_TOKEN and CF_ZONE_ID:
                    print(f"[SECURITY] Unblocking IP {ip} (Ban expired)")
                    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/firewall/access_rules/rules/{rule_id}"
                    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
                    try:
                        res = requests.delete(url, headers=headers, timeout=5)
                        if res.status_code == 200:
                            print(f"[CF-API] Lifted block for {ip}")
                        else:
                            print(f"[CF-API] Failed to lift block for {ip} - {res.status_code}")
                    except Exception as e:
                        print(f"[CF-API] Failed targeting Edge API: {str(e)}")
                
                # Cleanup local maps
                if ip in BLOCKED_IPS: del BLOCKED_IPS[ip]
                if ip in FAILED_AUTH_TRACKER: del FAILED_AUTH_TRACKER[ip]

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
                    if rule_id and ip in BLOCKED_IPS:
                        BLOCKED_IPS[ip]["rule_id"] = rule_id
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
            
        if ip in BLOCKED_IPS:
            return  # Already blocked

        now = time.time()
        record = FAILED_AUTH_TRACKER.get(ip, {"count": 0, "first_attempt": now})
        
        # Reset counter after 5 minutes
        if now - record["first_attempt"] > 300:
            record["count"] = 0
            record["first_attempt"] = now
            
        record["count"] += 1
        FAILED_AUTH_TRACKER[ip] = record
        
        print(f"[SECURITY][FAILED_AUTH] IP={ip} Attempts={record['count']}/5")
        add_soc_event("WARNING", f"Bad auth attempt from {ip} — attempt {record['count']}/5")

        # Track attack rate (rolling 60-second window)
        now_ts = time.time()
        ATTACK_TRACKER["rate_window"].append(now_ts)
        ATTACK_TRACKER["rate_window"] = [
            t for t in ATTACK_TRACKER["rate_window"] if now_ts - t < 60
        ]
        current_rate = len(ATTACK_TRACKER["rate_window"])
        if current_rate > ATTACK_TRACKER["peak_rate"]:
            ATTACK_TRACKER["peak_rate"] = current_rate

        if record["count"] >= 5 and ip not in BLOCKED_IPS:
            print(f"[CRITICAL] Blocking IP {ip} after 5 failed auth attempts")
            now = time.time()
            BLOCKED_IPS[ip] = {"rule_id": None, "banned_at": now, "expires_at": now + 3600}
            add_soc_event("CRITICAL", f"IP {ip} auto-blocked for repeated spoofing (5 failed auth attempts).")
            block_ip_in_cloudflare(ip)

    @app.route("/api/security-metrics", methods=["GET"])
    def api_security_metrics():
        try:
            now = time.time()
            active_blocks = []
            for ip, data in BLOCKED_IPS.items():
                active_blocks.append({
                    "ip": ip,
                    "time_remaining_seconds": max(0, int(data.get("expires_at", now) - now)),
                    "rule_id": data.get("rule_id")
                })

            attacks = []
            for ip, tr in FAILED_AUTH_TRACKER.items():
                if tr.get("count", 0) > 0:
                    attacks.append({
                        "ip": ip,
                        "attempts": tr.get("count", 0),
                        "first_attempt": tr.get("first_attempt", now)
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

    @app.route("/api/agent-scan", methods=["POST", "OPTIONS"])
    @limiter.limit("30 per minute")
    def api_agent_scan():
        if request.method == "OPTIONS":
            return jsonify({}), 200

        client_ip = get_cf_ip()

        # Enforce Payload Size Limit (512KB)
        if request.content_length and request.content_length > 512 * 1024:
            return jsonify({"status": "error", "message": "Payload too large"}), 413

        # Security Key Rotation Logic
        agent_keys_env = os.environ.get("AGENT_KEYS", "default-agent-key-123")
        active_keys = [k.strip() for k in agent_keys_env.split(',')]
        
        provided_signature = request.headers.get("x-agent-signature")
        ts = request.headers.get("x-agent-timestamp")
        nonce = request.headers.get("x-agent-nonce")
        
        if not provided_signature or not ts or not nonce:
            return jsonify({"status": "error", "message": "Missing EDR cryptographic headers"}), 403

        raw_data = request.get_data()
        
        # Verify Advanced Signature
        target_str = f"POST\n{request.path}\n{ts}\n{nonce}\n{raw_data.decode('utf-8')}"
        valid_signature = False
        
        for key in active_keys:
            expected = hmac.new(key.encode('utf-8'), target_str.encode('utf-8'), hashlib.sha256).hexdigest()
            if hmac.compare_digest(provided_signature, expected):
                valid_signature = True
                break
                
        if not valid_signature:
            handle_failed_auth(client_ip)
            return jsonify({"status": "error", "message": "Invalid signature. Spoofing detected."}), 403

        try:
            payload = json.loads(raw_data.decode('utf-8'))
            if not isinstance(payload, dict):
                return jsonify({"status": "error", "message": "Invalid JSON mapping"}), 400
            
            # Anti-Replay & Timestamp TTL
            now = time.time()
            if abs(now - float(ts)) > 60:
                return jsonify({"status": "error", "message": "Payload timestamp expired"}), 403

            if nonce in NONCE_CACHE and NONCE_CACHE[nonce] > now:
                 return jsonify({"status": "error", "message": "Replay attack detected"}), 403
            
            NONCE_CACHE[nonce] = now + 120 # Cache nonce for 2 minutes
            
            # TTL Cleanup for NONCE_CACHE
            if len(NONCE_CACHE) > 5000:
                expired = [k for k,v in NONCE_CACHE.items() if v <= now]
                for k in expired: del NONCE_CACHE[k]

            agent_id = str(payload.get("agentId", "unknown"))
            if not re.match(r"^[a-zA-Z0-9\-]{10,50}$", agent_id):
                return jsonify({"status": "error", "message": "Invalid Agent ID format"}), 400

            # Granular Risk Orchestra
            load = payload.get("cpu_percent", 0)
            ports = payload.get("open_ports", [])
            cves = payload.get("cves", {"critical": 0, "high": 0})
            
            sys_risk = 10 if load > 90 else (5 if load > 75 else 0)
            net_risk = min(50, len(ports) * 2)
            cve_risk = (cves.get("critical", 0) * 20) + (cves.get("high", 0) * 10)
            cve_risk = min(100, cve_risk)
            
            risk_score = min(100, sys_risk + net_risk + cve_risk)
            
            if risk_score >= 80: risk_level = "Critical"
            elif risk_score >= 60: risk_level = "High"
            elif risk_score >= 40: risk_level = "Medium"
            else: risk_level = "Low"

            priority_fix = "No immediate action required."
            if cve_risk >= net_risk and cve_risk >= sys_risk and cve_risk > 0:
                priority_fix = "Patch OS vulnerabilities detected by Trivy."
            elif net_risk >= sys_risk and net_risk > 0:
                priority_fix = f"Close {len(ports)} unauthorized listening ports."
            elif sys_risk > 0:
                priority_fix = "Investigate system CPU threshold limits."

            payload["risk_score"] = risk_score
            payload["risk_level"] = risk_level
            payload["risk_breakdown"] = {"system": sys_risk, "network": net_risk, "cve": cve_risk}
            payload["priorityFix"] = priority_fix

            # Store in global cache with timestamp
            AGENT_CACHE[agent_id] = {
                "timestamp": time.time(),
                "data": payload
            }
            
            return jsonify({"status": "success", "message": "Telemetry received"})
        except Exception:
            return jsonify({"status": "error", "message": "Server processing error"}), 500

    @app.route("/api/agent-status", methods=["GET"])
    def api_agent_status():
        # Return all active agents instead of just one
        agents = []
        now = time.time()
        dead_agents = []
        
        for a_id, entry in AGENT_CACHE.items():
            time_diff = now - entry["timestamp"]
            
            if time_diff > 300: # TTL 5 minutes to fully drop
                dead_agents.append(a_id)
                continue
                
            if time_diff <= 60:
                status = "online"
            elif time_diff <= 180:
                status = "stale"
            else:
                status = "offline"
                
            agent_data = dict(entry["data"])
            agent_data["connection_status"] = status
            agent_data["last_seen_seconds_ago"] = round(time_diff, 1)
            # Add health score based on time and metrics
            health = 100 - min(100, (time_diff/60)*10)
            agent_data["healthScore"] = round(health)
            
            agents.append(agent_data)
            
        for a_id in dead_agents:
            del AGENT_CACHE[a_id]
            
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
                active_agent = None
                for a_id, entry in AGENT_CACHE.items():
                    if now - entry["timestamp"] <= 180:
                        active_agent = entry["data"]
                        break
                
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

            result = run_pipeline(image=image, config=config, trivy_output=trivy_output)
            _save_cache(result)
            add_soc_event("INFO", "Full pipeline scan completed via /api/scan.")
            return jsonify({"status": "completed", "data": result})
        except Exception as exc:
            add_soc_event("WARNING", f"/api/scan server error: {str(exc)}")
            return jsonify({"status": "error", "message": "Internal scan error. Check server logs."}), 500

    @app.route("/api/demo", methods=["POST"])
    def api_demo():
        try:
            bad_config = os.path.join(SAMPLE_DIR, "bad_aws_config.json")
            good_config = os.path.join(SAMPLE_DIR, "good_aws_config.json")
            trivy_file = os.path.join(SAMPLE_DIR, "sample_trivy_output.json")

            before = run_pipeline(config=bad_config, trivy_output=trivy_file)
            after = run_pipeline(config=good_config)

            demo_data = {
                "before": before,
                "after": after,
                "timestamp": datetime.now().isoformat(),
            }

            try:
                os.makedirs(REPORTS_DIR, exist_ok=True)
                with open(os.path.join(REPORTS_DIR, "demo_comparison.json"), "w") as f:
                    json.dump(demo_data, f, indent=2, default=str)
            except Exception:
                pass

            _save_cache(before)
            add_soc_event("INFO", "Demo pipeline (before/after) completed via /api/demo.")
            return jsonify({"status": "completed", "data": demo_data})
        except Exception as exc:
            add_soc_event("WARNING", f"/api/demo server error: {str(exc)}")
            return jsonify({"status": "error", "message": "Internal demo error. Check server logs."}), 500

    # ── NEW: Enterprise Storage Check Endpoint ──
    STORAGE_CACHE = {}

    @app.route("/api/check-storage", methods=["POST", "OPTIONS"])
    @limiter.limit("10 per minute")
    @limiter.limit("100 per day")
    def api_check_storage():
        start_time = time.perf_counter()
        scanned_at = datetime.utcnow().isoformat() + "Z"
        
        if request.method == "OPTIONS":
            return jsonify({}), 200

        try:
            body = request.get_json(silent=True)
            if body is None:
                return jsonify({"status": "error", "message": "Failed to parse JSON configuration"}), 400

            provider = body.get("provider", "aws").lower()
            resource_name = body.get("resource", "")
            
            # Input validation
            if not isinstance(resource_name, str) or not re.match(r"^[a-zA-Z0-9.\-_]{3,255}$", resource_name):
                return jsonify({"status": "error", "message": "Invalid resource name format"}), 400

            # Caching check
            cache_key = f"{provider}:{resource_name}"
            if cache_key in STORAGE_CACHE:
                cached_entry = STORAGE_CACHE[cache_key]
                if time.time() - cached_entry['ts'] < 300: # 5 mins TTL
                    # Update dynamic time fields for cached entry
                    c_data = cached_entry['data'].copy()
                    c_data['scanDurationMs'] = round((time.perf_counter() - start_time) * 1000, 2)
                    c_data['scannedAt'] = scanned_at
                    return jsonify(c_data)

            is_public = False
            risk = "Low"
            exposure_type = "None"
            details = "Resource is securely configured and private."
            remediation = "No action required."
            confidence = 100

            boto_config = Config(connect_timeout=3, read_timeout=3, retries={'max_attempts': 1})

            if provider == "aws":
                s3_client = boto3.client('s3', config=boto_config)
                
                blocks_public_acls = False
                public_acl_found = False
                public_policy_found = False
                
                # Check Public Access Block
                try:
                    pab = s3_client.get_public_access_block(Bucket=resource_name)
                    config = pab.get('PublicAccessBlockConfiguration', {})
                    blocks_public_acls = config.get('BlockPublicAcls', False) and config.get('IgnorePublicAcls', False)
                except ClientError as e:
                    code = e.response['Error']['Code']
                    if code == 'NoSuchPublicAccessBlockConfiguration':
                        pass
                    elif code == 'AccessDenied':
                        return jsonify({"status": "error", "message": "Access Denied. Check AWS credentials."}), 403
                    elif code == 'NoSuchBucket':
                        return jsonify({"status": "error", "message": f"Bucket not found."}), 404
                    else:
                        return jsonify({"status": "error", "message": "Cloud Provider Error"}), 500
                except BotoCoreError:
                    return jsonify({"status": "error", "message": "Configuration Error"}), 500

                # Check ACL
                try:
                    acl = s3_client.get_bucket_acl(Bucket=resource_name)
                    for grant in acl.get('Grants', []):
                        uri = grant.get('Grantee', {}).get('URI', '')
                        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                            public_acl_found = True
                            break
                except ClientError:
                    pass

                # Check Policy
                try:
                    policy_str = s3_client.get_bucket_policy(Bucket=resource_name).get('Policy', '{}')
                    policy = json.loads(policy_str)
                    for statement in policy.get('Statement', []):
                        if statement.get('Effect') == 'Allow' and statement.get('Principal') in ['*', {'AWS': '*'}]:
                            public_policy_found = True
                            if statement.get('Condition'):
                                risk = "Medium"
                                exposure_type = "restricted_public"
                                details = "Bucket Policy allows public access but enforces restrictions via conditions (e.g., IP Allowlist/VPC endpoints)."
                                confidence = 85
                            else:
                                risk = "Critical"
                                exposure_type = "Public Bucket Policy"
                                details = "Bucket Policy contains a wildcard Principal (*) with an Allow effect."
                                confidence = 95
                            break
                except ClientError:
                    pass

                if public_acl_found and not blocks_public_acls:
                    is_public = True
                    risk = "Critical"
                    exposure_type = "Public ACL"
                    details = "Bucket ACL explicitly grants access to AllUsers or AuthenticatedUsers."
                    remediation = f"aws s3api put-bucket-acl --bucket {resource_name} --acl private"
                elif public_policy_found:
                    is_public = True
                    # risk, exposure_type, details set above
                    remediation = f"aws s3api delete-bucket-policy --bucket {resource_name}"

            elif provider == "azure":
                azure_conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
                if not azure_conn_str:
                    return jsonify({"status": "error", "message": "Credentials missing"}), 400
                
                try:
                    blob_service_client = BlobServiceClient.from_connection_string(azure_conn_str)
                    container_client = blob_service_client.get_container_client(resource_name)
                    props = container_client.get_container_properties()
                    if props.public_access in ['blob', 'container']:
                        is_public = True
                        risk = "Critical"
                        exposure_type = f"Public {props.public_access.capitalize()} Access"
                        details = f"Container allows unauthenticated {props.public_access} access."
                        remediation = f"az storage container set-permission --name {resource_name} --public-access off"
                except AzureError as e:
                    if 'ContainerNotFound' in str(e):
                        return jsonify({"status": "error", "message": "Container not found."}), 404
                    return jsonify({"status": "error", "message": "Azure Auth/Connection Error"}), 500

            elif provider == "gcp":
                gcp_creds_json = os.environ.get("GCP_CREDENTIALS_JSON")
                try:
                    if gcp_creds_json:
                        creds_dict = json.loads(gcp_creds_json)
                        credentials = service_account.Credentials.from_service_account_info(creds_dict)
                        gcp_client = storage.Client(credentials=credentials)
                    else:
                        return jsonify({"status": "error", "message": "Credentials missing"}), 400

                    bucket = gcp_client.bucket(resource_name)
                    if not bucket.exists():
                        return jsonify({"status": "error", "message": "Bucket not found."}), 404
                        
                    policy = bucket.get_iam_policy(requested_policy_version=3)
                    for binding in policy.bindings:
                        if binding.get('role') in ['roles/storage.objectViewer', 'roles/storage.legacyObjectReader', 'roles/storage.admin']:
                            if 'allUsers' in binding.get('members', []) or 'allAuthenticatedUsers' in binding.get('members', []):
                                is_public = True
                                risk = "Critical"
                                exposure_type = "Public IAM Binding"
                                details = f"IAM policy grants {binding.get('role')} to allUsers."
                                remediation = f"gcloud storage buckets remove-iam-policy-binding gs://{resource_name} --member=allUsers --role={binding.get('role')}"
                                break
                except GoogleAPIError:
                    return jsonify({"status": "error", "message": "GCP Auth/Connection Error"}), 500
                except json.JSONDecodeError:
                    return jsonify({"status": "error", "message": "Credential Parse Error."}), 500

            else:
                return jsonify({"status": "error", "message": "Unsupported provider"}), 400

            response_data = {
                "provider": provider,
                "resource": resource_name,
                "isPublic": is_public,
                "status": "FAIL" if is_public else "PASS",
                "risk": risk,
                "exposureType": exposure_type,
                "details": details,
                "remediation": remediation,
                "confidence": confidence,
                "scannedAt": scanned_at,
                "scanDurationMs": round((time.perf_counter() - start_time) * 1000, 2)
            }

            # Cache the result
            STORAGE_CACHE[cache_key] = {'ts': time.time(), 'data': response_data}

            return jsonify(response_data)
            
        except Exception:
            return jsonify({"status": "error", "message": "Internal Server Error"}), 500

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
        """Serve the packaged CloudShield agent executable."""
        from flask import send_file, redirect
        import pathlib

        # Look for precompiled exe first (built via PyInstaller)
        agent_exe = os.path.join(os.path.dirname(__file__), "dist", "cloudshield-agent.exe")
        if os.path.exists(agent_exe):
            return send_file(
                agent_exe,
                mimetype="application/octet-stream",
                as_attachment=True,
                download_name="cloudshield-agent.exe"
            )

        # If not compiled yet, serve the raw Python agent script
        agent_py = os.path.join(os.path.dirname(__file__), "..", "agent", "agent.py")
        agent_py = str(pathlib.Path(agent_py).resolve())
        if os.path.exists(agent_py):
            return send_file(
                agent_py,
                mimetype="text/x-python",
                as_attachment=True,
                download_name="cloudshield-agent.py"
            )

        return jsonify({"status": "error", "message": "Agent binary not available yet"}), 404

    @app.route("/api/agent-keys", methods=["GET"])
    def api_agent_keys():
        """Return a demo API key for display in the Deploy Agent modal."""
        # In production, this would be per-user auth. For now return the env key.
        agent_keys_env = os.environ.get("AGENT_KEYS", "default-agent-key-123")
        primary_key = agent_keys_env.split(',')[0].strip()
        backend_url = os.environ.get("CLOUDSHIELD_API_URL", "https://cloudshield-tya3.onrender.com")
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
        Returns real CVE findings from Trivy.
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
                return jsonify({"status": "error", "message": "Valid JSON cloud config required, and no live AWS credentials found."}), 400

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
        
        # We can store this in the AGENT_CACHE or MongoDB
        try:
            db_service.db.agent_reports.insert_one({
                "agent_id": agent_id,
                "timestamp": datetime.utcnow(),
                "data": data
            })
        except Exception:
            pass # fallback to memory
            
        AGENT_CACHE[agent_id] = {
            "timestamp": time.time(),
            "data": data,
            "ip": request.remote_addr
        }
        
        # Analyze risk of the immediate vulnerabilities posted by the agent
        vulns = data.get("vulnerabilities", [])
        if vulns:
            # We map this into our risk engine
            pass
            
        return jsonify({"status": "success", "message": "Telemetry received"})

    @app.route("/api/risk/score", methods=["GET"])
    def api_risk_score():
        """Returns global aggregated risk score from recent findings."""
        # Simple aggregated demo calculation: pulling from AGENT_CACHE
        total_vulns = []
        for agent in AGENT_CACHE.values():
            total_vulns.extend(agent["data"].get("vulnerabilities", []))
            
        from risk_engine import compute_risk_scores
        score_data = compute_risk_scores(total_vulns)
        return jsonify({"status": "success", "data": score_data})

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
