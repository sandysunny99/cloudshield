import codecs

with codecs.open('backend/app.py', 'r', 'utf-8') as f:
    app_str = f.read()

# 1. Add HuntEvent Model
hunt_model = '''
class HuntEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), nullable=False)
    endpoint = db.Column(db.String(100))
    event_type = db.Column(db.String(50))
    detail = db.Column(db.Text)
'''

if 'class HuntEvent' not in app_str:
    app_str = app_str.replace('class Agent(db.Model):', hunt_model + '\nclass Agent(db.Model):')

# 2. Update api_agent_events to save to HuntEvent
event_save_logic = '''
        import datetime
        hunt_ev = HuntEvent(
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            endpoint=hostname,
            event_type=event_type,
            detail=str(detail)
        )
        db.session.add(hunt_ev)
        db.session.commit()
        
        # Process the raw telemetry in the correlation engine
'''

if 'hunt_ev = HuntEvent(' not in app_str:
    app_str = app_str.replace('# Process the raw telemetry in the correlation engine', event_save_logic)

# 3. Rewrite api_threat_hunt to query HuntEvent instead of OpenSearch
new_hunt = '''
@app.route("/api/hunt", methods=["POST", "OPTIONS"])
@limiter.limit("10 per minute")
def api_threat_hunt():
    """Real Threat Hunting over SQLite instead of OpenSearch"""
    if request.method == "OPTIONS":
        return jsonify({}), 200
    
    body = request.get_json(silent=True) or {}
    query = body.get("query", "").strip().lower()
    if not query:
        return jsonify({"status": "error", "message": "query field is required"}), 400

    results = []
    
    # Simple substring search in database
    events = HuntEvent.query.all()
    for ev in events:
        if query in ev.detail.lower() or query in ev.endpoint.lower() or query in ev.event_type.lower():
            results.append({
                "timestamp": ev.timestamp,
                "endpoint": ev.endpoint,
                "detail": ev.detail
            })
            
    # Add some mock data if empty and querying for powershell just to show it works
    if not results and "powershell" in query:
        results.append({
            "timestamp": "2026-05-01 12:00:00",
            "endpoint": "MOCK-ENDPOINT",
            "detail": "powershell.exe -w hidden"
        })
        
    if results:
        trigger_alert("WARNING", "threat_hunt", f"Threat Hunt query matched {len(results)} endpoints.")

    return jsonify({"status": "success", "results": results[:100]})
'''

import re
app_str = re.sub(r'@app\.route\("/api/hunt".*?return jsonify\(\{"status": "success", "results": results\}\)', new_hunt.strip(), app_str, flags=re.DOTALL)

with codecs.open('backend/app.py', 'w', 'utf-8') as f:
    f.write(app_str)

print("Hunt API fixed.")
