"""
CloudShield Automated Scheduler Service
Runs continuous monitoring jobs via APScheduler:
 - Cloud Scans via AWS Service
 - Container image recurring scans
Persists results automatically.
"""

from apscheduler.schedulers.background import BackgroundScheduler
import datetime
import os
import atexit

from services import db_service
from services import trivy_service
from services import aws_service
from services import opa_service
from services import alert_service

_scheduler = None

def _run_scheduled_cloud_scan():
    """Fetches real AWS data and scans it."""
    print(f"[SCHEDULER] Starting automated periodic cloud scan at {datetime.datetime.now()}...")
    live_config = aws_service.generate_live_cloud_config()
    if not live_config:
        print("[SCHEDULER] No AWS credentials available, skipping automated cloud scan.")
        return
        
    result = opa_service.evaluate_cloud_config(live_config)
    if result.get("status") == "completed":
        try:
            db_service.save_cloud_scan("sched_aws", result)
            print(f"[SCHEDULER] Saved cloud scan. Violations: {result['summary']['total']}")
            
            # trigger alert rules
            if result['summary']['CRITICAL'] > 0:
                alert_service.trigger_alert(
                    level="CRITICAL", 
                    source="CloudScan", 
                    message=f"Automated scan found {result['summary']['CRITICAL']} critical cloud policy violations."
                )
        except Exception as e:
            print(f"[SCHEDULER] Error saving cloud scan: {e}")

def _run_scheduled_container_scan():
    """Scans a configured list of key container images."""
    images = os.environ.get("MONITOR_IMAGES", "nginx:latest").split(",")
    print(f"[SCHEDULER] Starting periodic container scans for {images}...")
    for img in images:
        img = img.strip()
        if not img: continue
        
        result = trivy_service.scan_container_image(img)
        if result.get("status") == "completed":
            try:
                db_service.save_vulnerability_scan(img, result)
                print(f"[SCHEDULER] Saved container scan for {img}. Vulns: {result['summary']['total']}")
                
                # trigger alert rules
                if result['summary']['critical'] > 0:
                    alert_service.trigger_alert(
                        level="CRITICAL", 
                        source="ContainerScan", 
                        message=f"Automated scan found {result['summary']['critical']} critical vulnerabilities in image '{img}'."
                    )
            except Exception as e:
                print(f"[SCHEDULER] Error saving container scan: {e}")


def start_scheduler():
    global _scheduler
    if _scheduler is not None:
        return
        
    _scheduler = BackgroundScheduler(daemon=True)
    
    # Run every 6 hours
    _scheduler.add_job(_run_scheduled_cloud_scan, 'interval', hours=6, id='cloud_scan_job')
    _scheduler.add_job(_run_scheduled_container_scan, 'interval', hours=6, id='container_scan_job')
    
    _scheduler.start()
    print("[SCHEDULER] Background scheduler started. Scans registered every 6 hours.")
    
    atexit.register(lambda: _scheduler.shutdown(wait=False))
