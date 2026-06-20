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
    return render_template("landing.html")

@app.route("/log")
def log():
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

        rows.append({
            "date":         entry["date"],
            "period":       entry["period"],
            "position":     entry["position"],
            "area_phase":   entry.get("trade", ""),
            "progress_pct": progress,
            "crew":         (entry.get("responsible") or "").strip(),
            "notes":        entry.get("notes", ""),
            "tdg_number":   entry.get("tdg_number", ""),
            "mbr_number":   entry.get("mbr_number", ""),
            "skid_by":      entry.get("skid_by", ""),
            "skid_ref":     entry.get("skid_ref", ""),
        })

    resp = requests.post(
        f"{SUPABASE_URL}/rest/v1/{TABLE}",
        json=rows,
        headers={**sb_headers(), "Prefer": "return=minimal"}
    )

    if resp.status_code in (200, 201, 204):
