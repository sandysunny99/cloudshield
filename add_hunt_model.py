import codecs

with codecs.open('backend/app.py', 'r', 'utf-8', errors='ignore') as f:
    lines = f.readlines()

# Insert HuntEvent model after line 310 (0-indexed: 309), before CACHE_FILE
hunt_model = [
    '\n',
    '# ── HuntEvent model: stores agent telemetry for local Threat Hunting ──\n',
    'class HuntEvent(db.Model):\n',
    '    __tablename__ = "hunt_events"\n',
    '    id         = db.Column(db.Integer, primary_key=True)\n',
    '    timestamp  = db.Column(db.String(32), nullable=False)\n',
    '    endpoint   = db.Column(db.String(128), nullable=False, default="unknown")\n',
    '    event_type = db.Column(db.String(64),  nullable=False, default="process_anomaly")\n',
    '    detail     = db.Column(db.Text,        nullable=False, default="")\n',
    '\n',
]

# Insert after line index 309 (from database import...)
insert_at = 310
lines = lines[:insert_at] + hunt_model + lines[insert_at:]

with codecs.open('backend/app.py', 'w', 'utf-8') as f:
    f.writelines(lines)

print("HuntEvent model inserted at line", insert_at + 1)
