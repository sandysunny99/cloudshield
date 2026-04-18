from flask_sqlalchemy import SQLAlchemy
import json

db = SQLAlchemy()

class Agent(db.Model):
    __tablename__ = 'agents'
    agent_id = db.Column(db.String(120), primary_key=True)
    hostname = db.Column(db.String(120))
    cpu = db.Column(db.Float)
    ram = db.Column(db.Float)
    status = db.Column(db.String(20))
    last_seen = db.Column(db.Float)
    data = db.Column(db.Text)  # JSON string

    def set_data(self, json_data):
        self.data = json.dumps(json_data)

    def get_data(self):
        return json.loads(self.data) if self.data else {}

class FailedAuth(db.Model):
    __tablename__ = 'failed_auths'
    ip = db.Column(db.String(120), primary_key=True)
    count = db.Column(db.Integer, default=0)
    first_attempt = db.Column(db.Float)

class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'
    ip = db.Column(db.String(120), primary_key=True)
    rule_id = db.Column(db.String(120), nullable=True)
    banned_at = db.Column(db.Float)
    expires_at = db.Column(db.Float)

class AttackMetric(db.Model):
    __tablename__ = 'attack_metrics'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.Float)
