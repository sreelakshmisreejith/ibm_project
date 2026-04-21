from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory, session, redirect, url_for

from modules.forensic_service import scan_forensic_directory


# ── Constants ────────────────────────────────────────────────
BASE_DIR        = Path(__file__).resolve().parent
REPORTS_DIR     = BASE_DIR / "reports"
REPORT_FILENAME = "evidence_report.csv"
REPORT_PATH     = str(REPORTS_DIR / REPORT_FILENAME)

CASE_ID       = "HC-2026-009"
INVESTIGATOR  = "Sreelakshmi"
SYSTEM_NAME   = "MedTrace Healthcare Cloud Storage System"
BREACH_DATE   = datetime(2026, 4, 8)

# ── App setup ────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "healthcare_forensics_security_key"

latest_scan_result = None


# ── Helpers ──────────────────────────────────────────────────
def resolve_path(raw: str) -> Path:
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = BASE_DIR / p
    return p.resolve()


def build_logs(result: dict, directory: str) -> list:
    records = result.get("records", [])
    logs = [
        {"level": "info",    "message": f"Scan started: {directory}"},
        {"level": "info",    "message": f"Indexed {len(records)} evidence records"},
    ]
    for r in records[:40]:
        level = "warning" if r.get("Risk Level") == "High" else "info"
        logs.append({
            "level": level,
            "message": f"{r.get('File Name')} | {r.get('Category')} | {r.get('Risk Level')}",
        })
    logs.append({
        "level": "warning" if result.get("high_risk", 0) else "info",
        "message": f"High-risk findings: {result.get('high_risk', 0)}",
    })
    logs.append({"level": "success", "message": "Evidence report generated: evidence_report.csv"})
    return logs


# ── Routes ───────────────────────────────────────────────────
@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("username") == "admin" and request.form.get("password") == "admin":
            session["logged_in"] = True
            return redirect(url_for("index"))
        error = "Invalid credentials. Access denied."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))


@app.route("/api/results")
def api_results():
    if not latest_scan_result:
        return jsonify({"message": "No scan has been run yet"}), 404
    return jsonify(latest_scan_result)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    global latest_scan_result

    payload   = request.get_json(silent=True) or {}
    raw_path  = (payload.get("directory_path") or "").strip()

    if not raw_path:
        return jsonify({"error": "directory_path is required"}), 400

    resolved = resolve_path(raw_path)
    if not resolved.exists() or not resolved.is_dir():
        return jsonify({
            "error": "Directory does not exist",
            "requested_path": raw_path,
            "resolved_path": str(resolved),
        }), 400

    try:
        result = scan_forensic_directory(
            str(resolved),
            case_id=CASE_ID,
            investigator=INVESTIGATOR,
            system_name=SYSTEM_NAME,
            breach_date=BREACH_DATE,
            report_path=REPORT_PATH,
        )
    except Exception as exc:
        return jsonify({"error": f"Scan failed: {exc}"}), 500

    result["logs"] = build_logs(result, str(resolved))
    latest_scan_result = result
    return jsonify(result)


@app.route("/reports/<path:filename>")
def reports(filename):
    safe = Path(filename).name
    return send_from_directory(REPORTS_DIR, safe, as_attachment=True)


# ── Entry point ──────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)
