import os
import yara_x
from flask import Flask, request, jsonify

app = Flask(__name__)

MAX_FILE_SIZE = 500 * 1024 * 1024
RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "basic_malware.yarax")

with open(RULES_PATH, "r", encoding="utf-8") as f:
    RULES = yara_x.compile(f.read())

@app.get("/")
def home():
    return jsonify({
        "service": "SecureFileCrypt Scanner",
        "status": "online",
        "engine": "YARA-X"
    })

@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "engine": "YARA-X"
    })

@app.post("/scan")
def scan():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]

    if not file.filename:
        return jsonify({"error": "Invalid filename."}), 400

    data = file.read(MAX_FILE_SIZE + 1)

    if len(data) > MAX_FILE_SIZE:
        return jsonify({"error": "File is too large."}), 413

    try:
        result = RULES.scan(data)
        matches = result.matching_rules

        return jsonify({
            "engine": "YARA-X",
            "filename": file.filename,
            "size": len(data),
            "status": "suspicious" if matches else "no_match",
            "matches": [rule.identifier for rule in matches]
        })

    except Exception as error:
        print("YARA-X error:", error)
        return jsonify({
            "engine": "YARA-X",
            "status": "error",
            "error": "YARA-X scan failed."
        }), 503

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
