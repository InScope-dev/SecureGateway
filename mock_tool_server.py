from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/tools/calendar.create_event", methods=["POST"])
def calendar_event():
    data = request.json
    return jsonify({
        "status": "ok",
        "event_id": "ev-" + data["title"].lower().replace(" ", "-"),
        "start_time": data["start_time"]
    })

@app.route("/tools/db.write_sensitive", methods=["POST"])
def blocked_write():
    return jsonify({"error": "Write to sensitive DB denied"}), 403

@app.route("/tools/search.query", methods=["POST"])
def search():
    return jsonify({"results": ["result 1", "result 2"], "query": request.json.get("q")})

@app.route("/healthz")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(port=5001, host="0.0.0.0")