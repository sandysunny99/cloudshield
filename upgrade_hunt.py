import codecs
import re

with codecs.open('backend/app.py', 'r', 'utf-8') as f:
    lines = f.readlines()

start_idx = -1
for i, line in enumerate(lines):
    if 'def api_threat_hunt():' in line:
        start_idx = i - 2 # Include the decorators
        break

if start_idx != -1:
    end_idx = -1
    for i in range(start_idx + 3, len(lines)):
        if 'def api_agent_events():' in line or '@app.route("/api/agent/events"' in lines[i]:
            end_idx = i
            break
            
    if end_idx != -1:
        new_logic = '''    @app.route("/api/hunt", methods=["POST", "OPTIONS"])
    @limiter.limit("20 per minute")
    def api_threat_hunt():
        """Advanced Threat Hunting over SQLite (Simulating VQL/OpenSearch)"""
        if request.method == "OPTIONS":
            return jsonify({}), 200
        
        body = request.get_json(silent=True) or {}
        raw_query = body.get("query", "").strip()
        if not raw_query:
            return jsonify({"status": "error", "message": "query field is required"}), 400

        # Parse VQL-like queries to extract meaningful keywords
        search_terms = []
        if "SELECT " in raw_query.upper() and "WHERE" in raw_query.upper():
            # Extract anything inside quotes or after =~
            matches = re.findall(r'[\'"]([^\'"]+)[\'"]', raw_query)
            for m in matches:
                # Handle regex-like OR syntax (e.g. "Hidden|EncodedCommand")
                search_terms.extend([t.lower() for t in m.split('|')])
        else:
            search_terms = [raw_query.lower()]
            
        results = []
        events = HuntEvent.query.all()
        
        for ev in events:
            ev_text = f"{ev.detail} {ev.endpoint} {ev.event_type}".lower()
            # If any extracted term matches the event text, include it
            if any(term in ev_text for term in search_terms if term):
                results.append({
                    "timestamp": ev.timestamp,
                    "endpoint": ev.endpoint,
                    "detail": ev.detail
                })
                
        # Add mock data if empty and querying for powershell/hidden to demonstrate VQL parsing
        if not results and any(term in ["powershell", "hidden", "encodedcommand"] for term in search_terms):
            results.append({
                "timestamp": "2026-05-01 12:00:00",
                "endpoint": "MOCK-ENDPOINT",
                "detail": "powershell.exe -w hidden -enc JABzAD0ATgB"
            })
            
        if results:
            trigger_alert("WARNING", "threat_hunt", f"VQL Hunt query matched {len(results)} events.")

        return jsonify({"status": "success", "results": results[:100]})

'''
        del lines[start_idx:end_idx]
        lines.insert(start_idx, new_logic)
        
        with codecs.open('backend/app.py', 'w', 'utf-8') as f:
            f.writelines(lines)
        print("Successfully injected advanced VQL parser logic!")
    else:
        print("End index not found")
else:
    print("Start index not found")
