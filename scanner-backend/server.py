import os
import tempfile
import yara_x
from flask import Flask, request, jsonify

app = Flask(__name__)

MAX_FILE_SIZE = 500 * 1024 * 1024
RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
COMMUNITY_DIR = os.path.join(os.path.dirname(__file__), "rules-community")

rule_files = []
for directory in (RULES_DIR, COMMUNITY_DIR):
    if os.path.isdir(directory):
        for root, _, files in os.walk(directory):
            for name in files:
                if name.lower().endswith((".yar", ".yara", ".yarax")):
                    rule_files.append(os.path.join(root, name))

rule_files.sort()

valid_sources = []
failed_rules = []

for path in rule_files:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        yara_x.compile(source)
        valid_sources.append(source)

    except Exception as error:
        failed_rules.append((path, str(error).splitlines()[0]))

if not valid_sources:
    raise RuntimeError("No compatible YARA-X rules found.")

RULES = yara_x.compile("\n\n".join(valid_sources))

print(
    f"YARA-X: {len(valid_sources)}/{len(rule_files)} rule files loaded; "
    f"{len(failed_rules)} skipped.",
    flush=True
)

for path, error in failed_rules:
    print(f"YARA-X skipped: {path} :: {error}", flush=True)



@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


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

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp_path = temp.name

            total_size = 0

            while True:
                chunk = file.stream.read(1024 * 1024)

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > MAX_FILE_SIZE:
                    return jsonify({
                        "engine": "YARA-X",
                        "status": "too_large",
                        "error": "File is too large. Maximum scan size is 500 MiB."
                    }), 413

                temp.write(chunk)

        scanner = yara_x.Scanner(RULES)
        result = scanner.scan_file(temp_path)
        matches = result.matching_rules

        return jsonify({
            "engine": "YARA-X",
            "filename": file.filename,
            "size": total_size,
            "status": "suspicious" if matches else "no_match",
            "matches": [rule.identifier for rule in matches]
        })

    except Exception as error:
        print("YARA-X error:", repr(error), flush=True)

        return jsonify({
            "engine": "YARA-X",
            "status": "error",
            "error": "YARA-X scan failed.",
            "debug": repr(error)
        }), 503

    finally:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
