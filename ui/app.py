import os
import threading
from flask import Flask, render_template, request, send_file,jsonify
from database.scans import scan_storage

from core.recon_controller import run_scan

app = Flask(__name__)

def background_scan(scan_id, target):

    scan_storage[scan_id]["status"] = "running"

    try:

        scan_data = run_scan(target)

        scan_storage[scan_id] = scan_data

        scan_storage[scan_id]["status"] = "completed"

    except Exception as e:

        scan_storage[scan_id]["status"] = "failed"

        scan_storage[scan_id]["error"] = str(e)

@app.route("/", methods=["GET", "POST"])
def home():

    global LATEST_REPORT

    pdf_ready = False

    if request.method == "POST":

        target = request.form.get("target")

        if target:

            scan_data = run_scan(target)

            scan_id = scan_data["scan_id"]
            scan_storage[scan_id] = scan_data
            pdf_ready = True

    return render_template(
        "index.html",
        pdf_ready=pdf_ready,
        scan_id=scan_id if pdf_ready else None
    )

@app.route("/view/<scan_id>")
def view_report(scan_id):

    scan_data = scan_storage.get(scan_id)

    if not scan_data:
        return "Report not found", 404

    return send_file(
        os.path.abspath(scan_data["pdf_path"]),
        mimetype="application/pdf"
    )
    
@app.route("/download/<scan_id>")
def download_report(scan_id):

    scan_data = scan_storage.get(scan_id)

    if not scan_data:
        return "Report not found", 404

    return send_file(
        os.path.abspath(scan_data["pdf_path"]),
        as_attachment=True
    )
    
@app.route("/api/scan", methods=["POST"])
def api_scan():

    data = request.get_json()

    if not data or "target" not in data:

        return jsonify({
            "error": "Target is required"
        }), 400

    target = data["target"]

    import uuid

    scan_id = str(uuid.uuid4())

    scan_storage[scan_id] = {
        "status": "queued",
        "target": target
    }

    thread = threading.Thread(
        target=background_scan,
        args=(scan_id, target)
    )

    thread.start()

    return jsonify({
        "message": "Scan started",
        "scan_id": scan_id,
        "status": "queued"
    })
    
@app.route("/api/results/<scan_id>")
def api_results(scan_id):

    scan_data = scan_storage.get(scan_id)

    if not scan_data:
        return jsonify({
            "error": "Scan not found"
        }), 404

    return jsonify(scan_data)

@app.route("/api/status/<scan_id>")
def api_status(scan_id):

    scan_data = scan_storage.get(scan_id)

    if not scan_data:
        return jsonify({
            "status": "not_found"
        }), 404

    return jsonify({
        "scan_id": scan_id,
        "status": scan_data["status"]
    })

if __name__ == "__main__":

    app.run(debug=True)