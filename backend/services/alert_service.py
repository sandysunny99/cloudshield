"""
CloudShield Alerting System
Manages email alerts and console log fallback for critical finding and risk thresholds.
"""

import os
import smtplib
from email.message import EmailMessage
import datetime

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = os.environ.get("SMTP_PORT", "587")
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "")

# in-memory alert history for dashboard
_recent_alerts = []

def trigger_alert(level: str, source: str, message: str, risk_score: float = None) -> bool:
    """
    Trigger an alert based on criticality.
    Routes to email if configured, otherwise console.
    """
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    
    alert_record = {
        "level": level,
        "source": source,
        "message": message,
        "risk_score": risk_score,
        "timestamp": timestamp
    }
    
    _recent_alerts.insert(0, alert_record)
    if len(_recent_alerts) > 50:
        _recent_alerts.pop()
        
    print(f"\n{'='*50}")
    print(f"🚨 [ALERT] {level} | {source}")
    print(f"Message: {message}")
    if risk_score:
        print(f"Risk Score: {risk_score}")
    print(f"{'='*50}\n")
    
    # Send email if configured
    if SMTP_HOST and ALERT_EMAIL:
        try:
            msg = EmailMessage()
            msg.set_content(f"CloudShield Security Alert\n\nLevel: {level}\nSource: {source}\nMessage: {message}\nRisk Score: {risk_score or 'N/A'}\nTime: {timestamp}")
            msg['Subject'] = f"CloudShield Alert [{level}] - {source}"
            msg['From'] = SMTP_USER or 'alerts@cloudshield.local'
            msg['To'] = ALERT_EMAIL
            
            with smtplib.SMTP(SMTP_HOST, int(SMTP_PORT)) as server:
                if SMTP_USER and SMTP_PASS:
                    server.starttls()
                    server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
            return True
        except Exception as e:
            print(f"[ALERT] Failed to send email alert: {e}")
            return False
            
    return True

def get_recent_alerts(limit: int = 20) -> list:
    """Return recent system alerts bounding to limit."""
    return _recent_alerts[:limit]
