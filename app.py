import os
import csv
import io
from datetime import date
from flask import Flask, request, jsonify, render_template, Response
import requests

app = Flask(__name__)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
TABLE = "daily_log"

def sb_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

@app.route("/")
def index():
    return render_template("index.html", today=date.today().isoformat())

@app.route("/submit", methods=["POST"])
def submit():
    data = request.get_json()
    required = ["date", "period", "position"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Campo requerido: {field}"}), 400

    progress_raw = data.get("progress_pct", "")
    progress = None
    if progress_raw != "" and progress_raw is not None:
        try:
            progress = float(str(progress_raw).replace("%", "").strip()) / 100
        except ValueError:
            pass

    row = {
        "date": data["date"],
        "period": data["period"],
        "position": data["position"],
        "area_phase": data.get("area_phase", ""),
        "progress_pct": progress,
        "crew": data.get("crew", ""),
        "notes": data.get("notes", "")
    }

    resp = requests.post(
        f"{SUPABASE_URL}/rest/v1/{TABLE}",
        json=row,
        headers=sb_headers()
    )

    if resp.status_code in (200, 201):
        return jsonify({"ok": True, "data": resp.json()})
    else:
        return jsonify({"error": resp.text}), 500

@app.route("/submit-batch", methods=["POST"])
def submit_batch():
    entries = request.get_json()
    if not entries:
        return jsonify({"error": "No entries"}), 400

    rows = []
    for entry in entries:
        progress = None
        pct_raw = entry.get("progress_pct")
        if pct_raw not in ("", None):
            try:
                progress = max(0.0, min(1.0, float(str(pct_raw)) / 100))
            except (ValueError, TypeError):
                pass

        responsible = (entry.get("responsible") or "").strip()
        contractor  = (entry.get("contractor") or "").strip()
        crew = f"{responsible} ({contractor})" if responsible and contractor else responsible or contractor

        rows.append({
            "date":         entry["date"],
            "period":       entry["period"],
            "position":     entry["position"],
            "area_phase":   entry.get("trade", ""),
            "progress_pct": progress,
            "crew":         crew,
            "notes":        entry.get("notes", "")
        })

    resp = requests.post(
        f"{SUPABASE_URL}/rest/v1/{TABLE}",
        json=rows,
        headers={**sb_headers(), "Prefer": "return=minimal"}
    )

    if resp.status_code in (200, 201, 204):
        return jsonify({"ok": True, "saved": len(rows)})
    return jsonify({"ok": False, "errors": [resp.text]}), 500

@app.route("/unit-progress/<position>")
def unit_progress(position):
    """Return latest recorded % per trade for a given unit."""
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}"
        f"?select=area_phase,progress_pct&position=eq.{position}"
        f"&order=created_at.desc&limit=500",
        headers=sb_headers()
    )
    latest = {}
    for r in resp.json():
        phase = r.get("area_phase", "")
        if phase and phase not in latest and r.get("progress_pct") is not None:
            latest[phase] = r["progress_pct"]
    return jsonify(latest)

@app.route("/export.csv")
def export_csv():
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}?select=date,period,position,area_phase,progress_pct,crew,notes&order=date.desc,period.asc",
        headers=sb_headers()
    )
    rows = resp.json()

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["date","period","position","area_phase","progress_pct","crew","notes"])
    writer.writeheader()
    for r in rows:
        writer.writerow({
            "date": r.get("date",""),
            "period": r.get("period",""),
            "position": r.get("position",""),
            "area_phase": r.get("area_phase",""),
            "progress_pct": r.get("progress_pct",""),
            "crew": r.get("crew",""),
            "notes": r.get("notes","")
        })

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=daily_log.csv"}
    )

@app.route("/recent")
def recent():
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}?select=*&order=created_at.desc&limit=50",
        headers=sb_headers()
    )
    return jsonify(resp.json())

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
