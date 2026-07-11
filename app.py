import os
import csv
import io
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import date, datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template, Response, session
import requests
import uuid

# ── Kiosk IP restriction ─────────────────────────────────────────────────────
KIOSK_PASS = os.environ.get("KIOSK_ADMIN_PASS", "MBR2026admin")
# KIOSK_IPS supports exact IPs and prefix patterns (e.g. "174.202." matches
# any IP starting with that prefix). Comma-separated. Set in Render env vars.
# Using a prefix like "174.202." handles dynamic IPs from the same ISP.
KIOSK_IPS_RAW = [
    ip.strip() for ip in
    os.environ.get("KIOSK_IPS", "174.202.").split(",")
    if ip.strip()
]

def get_client_ip():
    """Real client IP, accounting for Render's reverse proxy."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""

def kiosk_allowed():
    """Returns True if request is from an allowed kiosk IP, bypass key, or admin session.
    Supports exact IP match and prefix match (entry ending in '.').
    """
    # Session bypass: set when admin password is used to unlock /tablet
    try:
        if session.get('kiosk_bypass'):
            return True
    except RuntimeError:
        pass  # Outside request context (e.g. scheduler)
    ip = get_client_ip()
    if ip == "127.0.0.1":
        return True
    for pattern in KIOSK_IPS_RAW:
        if pattern.endswith("."):
            # Prefix match — e.g. "174.202." matches "174.202.x.x"
            if ip.startswith(pattern):
                return True
        else:
            # Exact match
            if ip == pattern:
                return True
    # Admin bypass: ?key=KIOSK_BYPASS_KEY (set in Render env vars)
    bypass = os.environ.get("KIOSK_BYPASS_KEY", "")
    if bypass and request.args.get("key") == bypass:
        return True
    return False


CDT = timezone(timedelta(hours=-5))  # Houston = CDT (UTC-5) in summer; CST (UTC-6) in winter

def utc_to_cdt(iso_str):
    """Convert UTC ISO string to Houston CDT h:mm AM/PM format."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        local = dt.astimezone(CDT)
        return local.strftime("%-I:%M %p")   # e.g. "7:15 AM"
    except Exception:
        return iso_str[11:16]  # fallback: raw HH:MM

# ── Email config (set SMTP_EMAIL + SMTP_PASSWORD in Render env) ──
SMTP_EMAIL    = os.environ.get("SMTP_EMAIL", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
ADMIN_EMAIL   = os.environ.get("ADMIN_EMAIL", "dshidalgop@gmail.com")

# ── Admin secret (machine-to-machine auth for destructive endpoints) ──
CRON_SECRET = os.environ.get("CRON_SECRET", "")

def require_admin_secret():
    """Guard for machine-to-machine admin endpoints.
    Accepts secret via X-Admin-Secret header OR ?key= query param
    (query param allows browser access to HTML-form endpoints).
    Returns 403 if secret is missing or wrong.
    """
    provided = (request.headers.get("X-Admin-Secret", "")
                or request.args.get("key", ""))
    if not CRON_SECRET or provided != CRON_SECRET:
        from flask import abort
        abort(403)

def _verify_caller_is_admin(name):
    """Check that name is an approved admin or boss in app_users.
    Used to authenticate frontend-initiated admin actions where the
    caller sends their logged-in name in the request body.
    """
    if not name:
        return False
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_users"
        f"?name=eq.{requests.utils.quote(str(name))}"
        f"&approved=eq.true&select=role&limit=1",
        headers=sb_headers(), timeout=5
    )
    if not r.ok:
        return False
    users = r.json()
    if not users:
        return False
    return (users[0].get("role") or "").lower() in ("admin", "boss")

def send_registration_email(to_email, name, username, role="worker"):
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        return  # Not configured — skip silently
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Welcome to MBR Texas Operations"
        msg["From"]    = SMTP_EMAIL
        msg["To"]      = to_email
        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#0f1117;color:#e2e8f0;border-radius:12px;padding:32px;">
          <div style="background:#1a6bc4;width:48px;height:48px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:800;color:#fff;margin-bottom:20px;">MBR</div>
          <h2 style="margin:0 0 8px;">Welcome, {name}!</h2>
          <p style="color:#94a3b8;margin:0 0 24px;">Your MBR Texas account has been created.</p>
          <table style="background:#1a2234;border-radius:8px;padding:18px 20px;width:100%;border-collapse:collapse;">
            <tr><td style="color:#64748b;font-size:12px;padding:6px 12px 6px 0;width:90px;">USERNAME</td><td style="color:#e2e8f0;font-weight:700;padding:6px 0;font-size:14px;">{username}</td></tr>
            <tr><td style="color:#64748b;font-size:12px;padding:6px 12px 6px 0;">ROLE</td><td style="color:#e2e8f0;padding:6px 0;font-size:14px;">{role.capitalize()}</td></tr>
            <tr><td style="color:#64748b;font-size:12px;padding:6px 12px 6px 0;">EMAIL</td><td style="color:#e2e8f0;padding:6px 0;font-size:14px;">{to_email}</td></tr>
          </table>
          <p style="margin:20px 0 8px;color:#94a3b8;font-size:13px;">Access the platform at:</p>
          <a href="https://tdg-tracker.onrender.com/login" style="display:inline-block;background:#1a6bc4;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;">Sign In →</a>
          <p style="margin-top:24px;color:#475569;font-size:12px;">Keep your password secure. Contact your supervisor if you need assistance.</p>
          <p style="color:#334155;font-size:11px;margin-top:16px;">MBR Texas · TDG Data Center Operations</p>
        </div>
        """
        msg.attach(MIMEText(html, "html"))
        # Also send notification to admin
        admin_msg = MIMEMultipart("alternative")
        admin_msg["Subject"] = f"New MBR account: {name} ({username})"
        admin_msg["From"]    = SMTP_EMAIL
        admin_msg["To"]      = ADMIN_EMAIL
        admin_html = f"""
        <div style="font-family:Arial,sans-serif;max-width:480px;">
          <h3>New account registered</h3>
          <p><b>Name:</b> {name}<br><b>Username:</b> {username}<br><b>Email:</b> {to_email}<br><b>Role:</b> {role}</p>
          <p style="color:#64748b;font-size:12px;">Account was auto-approved as worker. Update role in Settings if needed.</p>
        </div>
        """
        admin_msg.attach(MIMEText(admin_html, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as srv:
            srv.login(SMTP_EMAIL, SMTP_PASSWORD)
            srv.sendmail(SMTP_EMAIL, [to_email], msg.as_string())
            srv.sendmail(SMTP_EMAIL, [ADMIN_EMAIL], admin_msg.as_string())
    except Exception as e:
        print(f"[Email] Error: {e}")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "mbr-kiosk-2026")

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
    from flask import redirect
    return redirect("/login")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/home")
def home_page():
    return render_template("landing.html")

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    # Try username field, then email, then name (backward compat)
    users = []
    for field in ["username", "email", "name"]:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/app_users"
            f"?select=name,role,email,phone,username,approved"
            f"&{field}=eq.{requests.utils.quote(username)}"
            f"&password=eq.{requests.utils.quote(password)}"
            f"&limit=1",
            headers=sb_headers()
        )
        users = r.json() if r.ok else []
        if users:
            break
    if not users:
        return jsonify({"error": "Invalid username or password"}), 401
    u = users[0]
    if u.get("approved") == False:
        return jsonify({"error": "pending_approval"}), 403
    return jsonify({"name": u["name"], "role": u.get("role","worker"), "email": u.get("email","")})

@app.route("/api/check-username", methods=["POST"])
def check_username():
    data = request.get_json() or {}
    uname = data.get("username", "").strip().lower()
    if not uname:
        return jsonify({"available": False, "error": "Username required"}), 400
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_users?username=eq.{requests.utils.quote(uname)}&limit=1&select=id",
        headers=sb_headers()
    )
    exists = r.ok and len(r.json()) > 0
    return jsonify({"available": not exists})

@app.route("/api/register", methods=["POST"])
def api_register():
    import datetime as dt
    data = request.get_json() or {}
    name     = data.get("name", "").strip()
    username = data.get("username", "").strip().lower()
    email    = data.get("email", "").strip()
    phone    = data.get("phone", "").strip()
    password = data.get("password", "").strip()
    consent  = data.get("consent", False)
    if not name or not username or not email or not password:
        return jsonify({"error": "Name, username, email and password are required"}), 400
    if not consent:
        return jsonify({"error": "You must accept the data consent agreement"}), 400
    # Check username uniqueness
    chk = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_users?username=eq.{requests.utils.quote(username)}&limit=1&select=id",
        headers=sb_headers()
    )
    if chk.ok and len(chk.json()) > 0:
        return jsonify({"error": "Username already taken. Please choose another."}), 409
    payload = {
        "name": name,
        "username": username,
        "email": email,
        "phone": phone or None,
        "password": password,
        "role": "worker",
        "approved": False,
        "consent_signed": True,
        "consent_date": dt.datetime.utcnow().isoformat()
    }
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/app_users",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json=payload
    )
    if r.ok:
        user = r.json()[0]
        send_registration_email(email, name, username, "worker")
        return jsonify({"name": user["name"], "role": user.get("role","worker"), "pending": True})
    err = r.text
    if "duplicate" in err.lower() or "unique" in err.lower():
        err = "Username or email already registered."
    return jsonify({"error": err}), 400


@app.route("/register")
def register_page():
    """Public self-registration page for workers."""
    return render_template("register.html")

@app.route("/api/self-register", methods=["POST"])
def api_self_register():
    """Simplified registration — no username/password required.
    Worker fills name, phone, trade, led_by. Admin activates later."""
    import datetime as dt
    data = request.get_json() or {}
    name   = data.get("name", "").strip()
    phone  = data.get("phone", "").strip()
    trade  = data.get("trade", "").strip()
    led_by = data.get("led_by", "").strip() or None
    if not name or not phone or not trade:
        return jsonify({"error": "Name, phone and trade are required"}), 400
    # Check for duplicate name
    chk = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_users?name=eq.{requests.utils.quote(name)}&limit=1&select=id",
        headers=sb_headers()
    )
    if chk.ok and len(chk.json()) > 0:
        return jsonify({"error": "A user with that name is already registered. Ask your lead or admin for help."}), 409
    payload = {
        "name": name,
        "phone": phone,
        "trade": trade,
        "led_by": led_by,
        "role": "worker",
        "approved": False,
    }
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/app_users",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json=payload
    )
    if r.ok:
        return jsonify({"ok": True, "name": name})
    err = r.text
    if "duplicate" in err.lower() or "unique" in err.lower():
        err = "You are already registered. Talk to your lead or admin."
    return jsonify({"error": err}), 400


@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    """Generate a temp password and email it, OR return admin contact info."""
    import datetime as dt, random, string
    data = request.get_json() or {}
    email = data.get("email","").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400
    # Look up user by email
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_users?email=eq.{requests.utils.quote(email)}&select=name,role&limit=1",
        headers=sb_headers()
    )
    users = r.json() if r.ok else []
    if not users:
        return jsonify({"error": "No account found with that email."}), 404
    user = users[0]
    # Generate temp password
    temp_pw = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    # Update password in DB
    upd = requests.patch(
        f"{SUPABASE_URL}/rest/v1/app_users?email=eq.{requests.utils.quote(email)}",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json={"password": temp_pw}
    )
    if not upd.ok:
        return jsonify({"error": "Failed to reset password"}), 500
    # Try to send email
    email_sent = False
    if SMTP_EMAIL and SMTP_PASSWORD:
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart as MM
            from email.mime.text import MIMEText as MT
            msg = MM("alternative")
            msg["Subject"] = "MBR Texas — Password Reset"
            msg["From"] = SMTP_EMAIL
            msg["To"] = email
            html = f"""
            <div style="font-family:Arial,sans-serif;max-width:480px;background:#0f1117;color:#e2e8f0;padding:32px;border-radius:12px;">
              <div style="background:#1a6bc4;width:44px;height:44px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:800;color:#fff;margin-bottom:20px;font-size:16px;">MBR</div>
              <h2 style="margin:0 0 8px;">Password Reset</h2>
              <p style="color:#94a3b8;">Hi {user['name']}, here is your temporary password:</p>
              <div style="background:#1a2234;border:1px solid #1e2d45;border-radius:8px;padding:16px 20px;margin:20px 0;font-size:24px;font-weight:700;letter-spacing:4px;color:#60a5fa;">{temp_pw}</div>
              <p style="color:#94a3b8;font-size:13px;">Sign in with this password, then change it immediately in your profile.</p>
              <a href="https://tdg-tracker.onrender.com/login" style="display:inline-block;background:#1a6bc4;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;margin-top:8px;">Go to Login →</a>
            </div>"""
            msg.attach(MT(html,"html"))
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as srv:
                srv.login(SMTP_EMAIL, SMTP_PASSWORD)
                srv.sendmail(SMTP_EMAIL, [email], msg.as_string())
            email_sent = True
        except Exception as e:
            print(f"[Reset email error] {e}")
    return jsonify({"ok": True, "email_sent": email_sent, "temp_pw": temp_pw if not email_sent else None})


@app.route("/api/users/approve", methods=["POST"])
def approve_user():
    data = request.get_json() or {}
    name = data.get("name","").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/app_users?name=eq.{requests.utils.quote(name)}",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json={"approved": True}
    )
    return jsonify({"ok": r.ok, "error": r.text if not r.ok else None})

@app.route("/api/users/pending", methods=["GET"])
def pending_users():
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_users?approved=eq.false&select=name,role,email,phone,trade,led_by,created_at&order=created_at.desc&limit=50",
        headers=sb_headers()
    )
    return jsonify(r.json() if r.ok else [])

@app.route("/api/reset-password", methods=["POST"])
def admin_reset_password():
    """Admin resets any user's password."""
    data = request.get_json() or {}
    caller = data.get("caller_name", "").strip()
    if not _verify_caller_is_admin(caller):
        return jsonify({"error": "Admin access required"}), 403
    target_name = data.get("name","").strip()
    new_pw      = data.get("password","").strip()
    if not target_name or not new_pw:
        return jsonify({"error": "name and password required"}), 400
    if len(new_pw) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/app_users?name=eq.{requests.utils.quote(target_name)}",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json={"password": new_pw}
    )
    return jsonify({"ok": r.ok, "error": r.text if not r.ok else None})

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
    resp = requests.post(f"{SUPABASE_URL}/rest/v1/{TABLE}", json=row, headers=sb_headers())
    if resp.status_code in (200, 201):
        return jsonify({"ok": True, "data": resp.json()})
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
        row = {
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
            "workers":      entry.get("workers") or None,
        }
        if entry.get("fase"):
            row["fase"] = entry["fase"]
        if entry.get("building_no"):
            row["building_no"] = entry["building_no"]
        rows.append(row)
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
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}"
        f"?select=area_phase,progress_pct&position=eq.{position}"
        f"&progress_pct=not.is.null&order=created_at.asc&limit=2000",
        headers=sb_headers()
    )
    latest = {}
    for r in resp.json():
        phase = r.get("area_phase", "")
        if phase and r.get("progress_pct") is not None:
            latest[phase] = r["progress_pct"]  # always overwrite → last = most recent
    meta_resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}"
        f"?select=tdg_number,mbr_number,skid_by,skid_ref,fase,building_no"
        f"&position=eq.{position}&order=created_at.desc&limit=100",
        headers=sb_headers()
    )
    meta = {"tdg_number": "", "mbr_number": "", "skid_by": "", "skid_ref": "", "fase": "", "building_no": ""}
    records = meta_resp.json() if meta_resp.ok else []
    # Use the most recent record as authoritative — empty string = explicitly cleared
    # (records ordered desc so first = most recent)
    if records:
        # Find the first record that has at least one non-null meta field
        for r in records:
            has_any = any(r.get(f) is not None for f in meta.keys())
            if has_any:
                for field in meta.keys():
                    val = r.get(field)
                    if val is not None:
                        meta[field] = str(val).strip()
                break
    return jsonify({"trades": latest, "meta": meta})

@app.route("/export.csv")
def export_csv():
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}"
        f"?select=date,period,position,area_phase,progress_pct,crew,notes&order=date.desc,period.asc",
        headers=sb_headers()
    )
    rows = resp.json()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["date","period","position","area_phase","progress_pct","crew","notes"])
    writer.writeheader()
    for r in rows:
        writer.writerow({
            "date": r.get("date",""), "period": r.get("period",""),
            "position": r.get("position",""), "area_phase": r.get("area_phase",""),
            "progress_pct": r.get("progress_pct",""), "crew": r.get("crew",""),
            "notes": r.get("notes","")
        })
    return Response(output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=daily_log.csv"})

@app.route("/recent")
def recent():
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}?select=*&order=created_at.desc&limit=50",
        headers=sb_headers()
    )
    return jsonify(resp.json())

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/data")
def api_data():
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}"
        f"?select=date,period,position,area_phase,progress_pct,crew,notes"
        f"&order=date.asc,created_at.asc&limit=5000",
        headers=sb_headers()
    )
    records = resp.json()

    INTERNAL_SUBS = {
        'ELECTRICAL', 'BATTERY CABINETS', 'IOs/POWER CABINETS',
        'SWITCH GEAR', 'PANELS & CABLE', 'BATTERY CONNECTIONS',
        'IO CONDUIT', 'LIGHTING', 'CLOSEOUT',
    }
    TRADE_TOTALS = {
        '1. Structure': 13,
        '2. Structure Paint': 1, '3. Envelope': 1, '4. Unit Paint': 1,
        '5. Internal Systems Rough-In': 54,
        '6. Electrical': 1, '7. Final QC': 1, '8. Final Touchups': 1,
    }

    def get_main_trade(ap):
        top = ap.split(" > ")[0] if " > " in ap else ap
        return "5. Internal Systems Rough-In" if top in INTERNAL_SUBS else top

    for r in records:
        r["main_trade"] = get_main_trade(r.get("area_phase") or "")

    latest = {}
    for r in records:
        key = (r.get("position", ""), r.get("area_phase", ""))
        if r.get("progress_pct") is not None:
            latest[key] = r["progress_pct"]

    unit_trade_pct = {}
    for key, pct in latest.items():
        pos, trade = key
        unit_trade_pct.setdefault(pos, {})[trade] = pct

    unit_progress = {
        pos: round(sum(v.values()) / len(v), 4)
        for pos, v in unit_trade_pct.items() if v
    }

    mt_unit_pcts = {}
    for key, pct in latest.items():
        pos, trade = key
        mt = get_main_trade(trade)
        mt_unit_pcts.setdefault((pos, mt), []).append(pct)

    mt_unit_completions = {}
    for key2, pcts in mt_unit_pcts.items():
        pos2, mt2 = key2
        total = TRADE_TOTALS.get(mt2, len(pcts))
        mt_unit_completions.setdefault(mt2, []).append(sum(pcts) / total)

    main_trade_pct = {
        mt: round(sum(vals) / len(vals), 4)
        for mt, vals in mt_unit_completions.items()
    }

    return jsonify({
        "records": records,
        "unit_trade_pct": unit_trade_pct,
        "unit_progress": unit_progress,
        "main_trade_pct": main_trade_pct,
    })

@app.route("/lock/<position>", methods=["GET"])
def get_lock(position):
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/unit_locks?position=eq.{position}&select=locked_by,locked_at",
        headers=sb_headers()
    )
    data = resp.json()
    if data:
        return jsonify({"locked": True, "by": data[0].get("locked_by"), "at": data[0].get("locked_at")})
    return jsonify({"locked": False})

@app.route("/lock/<position>", methods=["POST"])
def set_lock(position):
    body = request.get_json() or {}
    locked_by = body.get("locked_by", "unknown")
    resp = requests.post(
        f"{SUPABASE_URL}/rest/v1/unit_locks",
        json={"position": position, "locked_by": locked_by},
        headers={**sb_headers(), "Prefer": "resolution=merge-duplicates"}
    )
    return jsonify({"ok": resp.ok})

@app.route("/lock/<position>", methods=["DELETE"])
def del_lock(position):
    resp = requests.delete(
        f"{SUPABASE_URL}/rest/v1/unit_locks?position=eq.{position}",
        headers=sb_headers()
    )
    return jsonify({"ok": resp.ok})

@app.route("/migrate")
def migrate_page():
    return render_template("migrate.html")

@app.route("/migrate/preview/<from_pos>")
def migrate_preview(from_pos):
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}?position=eq.{from_pos}&select=id",
        headers={**sb_headers(), "Prefer": "count=exact"}
    )
    count = int(resp.headers.get("Content-Range", "0/0").split("/")[-1])
    return jsonify({"count": count})

@app.route("/migrate", methods=["POST"])
def migrate_execute():
    body = request.get_json() or {}
    from_pos = body.get("from_pos", "").strip()
    to_pos   = body.get("to_pos", "").strip()
    if not from_pos or not to_pos:
        return jsonify({"ok": False, "error": "Missing positions"}), 400
    count_resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}?position=eq.{from_pos}&select=id",
        headers={**sb_headers(), "Prefer": "count=exact"}
    )
    count = int(count_resp.headers.get("Content-Range", "0/0").split("/")[-1])
    resp = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{TABLE}?position=eq.{from_pos}",
        json={"position": to_pos},
        headers={**sb_headers(), "Prefer": "return=minimal"}
    )
    if resp.ok:
        return jsonify({"ok": True, "moved": count})
    return jsonify({"ok": False, "error": resp.text}), 500

# ═══════════════════════════════════════════════════════════════════
#  QR CHECK-IN SYSTEM
# ═══════════════════════════════════════════════════════════════════
CHECKINS_TABLE = "checkins"

@app.route("/api/workers/hours", methods=["GET"])
def worker_hours():
    """Aggregate total hours per worker from checkins table."""
    import datetime as dt
    days = int(request.args.get("days", 30))
    since = (dt.date.today() - dt.timedelta(days=days)).isoformat()
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/checkins"
        f"?select=worker_name,checked_in_at,checked_out_at,date"
        f"&date=gte.{since}&order=date.desc&limit=5000",
        headers=sb_headers()
    )
    rows = r.json() if r.ok else []
    summary = {}
    for row in rows:
        name = row.get("worker_name","")
        if not name: continue
        if name not in summary:
            summary[name] = {"worker_name": name, "days": 0, "total_hours": 0.0, "last_seen": row.get("date","")}
        summary[name]["days"] += 1
        cin  = row.get("checked_in_at")
        cout = row.get("checked_out_at")
        if cin and cout:
            try:
                fmt = "%Y-%m-%dT%H:%M:%S"
                t1 = dt.datetime.fromisoformat(cin.split("+")[0].split("Z")[0])
                t2 = dt.datetime.fromisoformat(cout.split("+")[0].split("Z")[0])
                hrs = (t2 - t1).total_seconds() / 3600
                if 0 < hrs < 24:
                    summary[name]["total_hours"] += hrs
            except Exception:
                pass
    result = sorted(summary.values(), key=lambda x: x["worker_name"])
    for w in result:
        w["total_hours"] = round(w["total_hours"], 1)
    return jsonify(result)

@app.route("/checkin/<position>")
def checkin_page(position):
    return render_template("checkin.html", position=position)

@app.route("/qr-codes")
def qr_codes_page():
    return render_template("qr_codes.html")

@app.route("/api/checkin", methods=["POST"])
def api_checkin():
    data = request.json or {}
    position = data.get("position", "").strip()
    name = data.get("worker_name", "").strip()
    if not position or not name:
        return jsonify({"error": "position and worker_name required"}), 400
    from datetime import date as _today
    row = {"position": position, "worker_name": name, "date": _today.today().isoformat()}
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}",
        json=row,
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    if r.ok:
        rows = r.json() if r.ok else []
        return jsonify({"ok": True, "checkin": rows[0] if rows else {}})
    return jsonify({"ok": False, "error": r.text}), 400

@app.route("/api/checkin/<checkin_id>/checkout", methods=["POST"])
def api_checkout(checkin_id):
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}?id=eq.{checkin_id}",
        json={"checked_out_at": "now()"},
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    if r.ok:
        return jsonify({"ok": True})
    return jsonify({"error": r.text}), 400

@app.route("/api/checkin/manual", methods=["POST"])
def api_manual_checkin():
    """Boss/Admin: create a check-in for a worker with a specified time.
    Used when a worker arrives late and needs to be checked in manually.
    Body: { caller_name, worker_name, checked_in_at (HH:MM 24h), date (YYYY-MM-DD, optional) }
    """
    data = request.get_json() or {}
    caller = data.get("caller_name", "").strip()
    if not _verify_caller_is_admin(caller):
        return jsonify({"error": "Admin access required"}), 403

    worker_name = data.get("worker_name", "").strip()
    time_str    = data.get("checked_in_at", "").strip()  # "HH:MM"
    if not worker_name or not time_str:
        return jsonify({"error": "worker_name and checked_in_at required"}), 400

    import datetime as dt
    target_date = data.get("date") or dt.date.today().isoformat()

    # Build full ISO timestamp (treat as CDT = UTC-5)
    try:
        h, m = [int(x) for x in time_str.split(":")]
        # Store as UTC: CDT is UTC-5, so add 5 hours
        dt_cdt = dt.datetime(
            *[int(p) for p in target_date.split("-")], h, m, 0
        )
        dt_utc = dt_cdt + dt.timedelta(hours=5)
        checked_in_iso = dt_utc.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception as e:
        return jsonify({"error": f"Invalid time format: {e}"}), 400

    # Check for existing open check-in for this worker today
    existing = requests.get(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}"
        f"?worker_name=eq.{requests.utils.quote(worker_name)}"
        f"&date=eq.{target_date}&checked_out_at=is.null&select=id&limit=1",
        headers=sb_headers(), timeout=5
    )
    if existing.ok and existing.json():
        return jsonify({"error": f"{worker_name} already has an open check-in today."}), 409

    row = {
        "worker_name":    worker_name,
        "date":           target_date,
        "checked_in_at":  checked_in_iso,
        "position":       data.get("position", "Manual"),
        "manual_entry":   True,
        "entered_by":     caller,
    }
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}",
        json=row,
        headers={**sb_headers(), "Prefer": "return=representation"},
        timeout=8
    )
    if r.ok:
        return jsonify({"ok": True, "checkin": r.json()[0] if r.json() else {}})
    return jsonify({"ok": False, "error": r.text}), 400

@app.route("/api/active-checkins", methods=["GET"])
def api_active_checkins():
    """Returns all currently checked-in workers (no checkout yet)."""
    today = __import__('datetime').date.today().isoformat()
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}"
        f"?checked_out_at=is.null&date=eq.{today}"
        f"&select=id,position,worker_name,checked_in_at&order=checked_in_at.asc",
        headers=sb_headers()
    )
    return jsonify(r.json() if r.ok else [])

@app.route("/api/today-checkins", methods=["GET"])
def api_today_checkins():
    """Returns all check-ins for today (including checked-out)."""
    today = __import__('datetime').date.today().isoformat()
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}"
        f"?date=eq.{today}"
        f"&select=id,position,worker_name,checked_in_at,checked_out_at"
        f"&order=checked_in_at.asc",
        headers=sb_headers()
    )
    return jsonify(r.json() if r.ok else [])

@app.route("/api/checkin/by-name", methods=["GET"])
def api_checkin_by_name():
    """Check if a worker has an active check-in today."""
    name = request.args.get("name","").strip()
    if not name:
        return jsonify({"active": None})
    today = __import__('datetime').date.today().isoformat()
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}"
        f"?worker_name=eq.{requests.utils.quote(name)}&date=eq.{today}"
        f"&checked_out_at=is.null&select=id,position,checked_in_at&limit=1",
        headers=sb_headers()
    )
    rows = r.json() if r.ok else []
    return jsonify({"active": rows[0] if rows else None})


@app.route("/admin/fix-periods", methods=["GET","POST"])
def admin_fix_periods():
    require_admin_secret()
    """
    One-time fix: assign AM/PM to records that have null or empty period.
    Houston = CDT = UTC-5. Cutoff: noon CDT = 17:00 UTC → PM.
    GET  → preview how many records would be changed.
    POST → apply the fix.
    """
    import datetime
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}"
        f"?select=id,created_at,period&or=(period.is.null,period.eq.)"
        f"&limit=5000",
        headers=sb_headers()
    )
    rows = resp.json() if resp.ok else []
    if not isinstance(rows, list):
        return jsonify({"error": str(rows)}), 400

    am_ids, pm_ids = [], []
    for r in rows:
        ca = r.get("created_at","")
        try:
            # Parse UTC timestamp
            dt = datetime.datetime.fromisoformat(ca.replace("Z","+00:00"))
            # Convert to CDT (UTC-5)
            dt_local = dt - datetime.timedelta(hours=5)
            period = "PM" if dt_local.hour >= 12 else "AM"
        except Exception:
            period = "AM"
        (pm_ids if period == "PM" else am_ids).append(r["id"])

    if request.method == "GET":
        return jsonify({
            "preview": True,
            "total_null_period": len(rows),
            "would_set_AM": len(am_ids),
            "would_set_PM": len(pm_ids),
            "note": "POST to this URL to apply the fix"
        })

    # POST → apply
    fixed = 0
    for period, ids in [("AM", am_ids), ("PM", pm_ids)]:
        for i in range(0, len(ids), 50):
            chunk = ids[i:i+50]
            id_list = ",".join(chunk)
            r2 = requests.patch(
                f"{SUPABASE_URL}/rest/v1/{TABLE}?id=in.({id_list})",
                json={"period": period},
                headers=sb_headers()
            )
            if r2.ok:
                fixed += len(chunk)
    return jsonify({"ok": True, "fixed": fixed, "AM": len(am_ids), "PM": len(pm_ids)})


# ═══════════════════════════════════════════════════════
#  WORKERS REGISTRY
# ═══════════════════════════════════════════════════════
WORKERS_TABLE = "workers"
SM_TABLE = "safety_meetings"

@app.route("/api/workers", methods=["GET"])
def get_workers():
    """Pull worker list from app_users (approved accounts only)."""
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_users"
        f"?approved=eq.true&select=name,role&order=name.asc&limit=200",
        headers=sb_headers()
    )
    rows = r.json() if r.ok else []
    # Return in same shape timesheet expects: {name, active:True}
    return jsonify([{"name": row["name"], "active": True, "role": row.get("role","")} for row in rows])

@app.route("/api/workers", methods=["POST"])
def add_worker():
    import random
    data = request.get_json() or {}
    name = data.get("name","").strip()
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400
    # Auto-assign a unique 4-digit PIN
    pin = None
    for _ in range(50):
        candidate = str(random.randint(1000, 9999))
        check = requests.get(
            f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?pin=eq.{candidate}&select=id&limit=1",
            headers=sb_headers()
        )
        if check.ok and not check.json():
            pin = candidate
            break
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}",
        json={"name": name, "role": data.get("role",""), "active": True, "pin": pin},
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    return jsonify({"ok": r.ok, "worker": r.json()[0] if r.ok and r.json() else {}})

@app.route("/api/workers/assign-pins", methods=["POST"])
def assign_pins_bulk():
    """Assign a unique random 4-digit PIN to every worker that doesn't have one."""
    import random
    # Get all workers without a PIN
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?pin=is.null&active=eq.true&select=id,name&limit=500",
        headers=sb_headers()
    )
    workers = r.json() if r.ok else []
    # Get existing PINs to avoid collisions
    ep = requests.get(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?pin=not.is.null&select=pin&limit=500",
        headers=sb_headers()
    )
    used = set(w["pin"] for w in (ep.json() if ep.ok else []) if w.get("pin"))
    assigned = []
    for worker in workers:
        for _ in range(100):
            candidate = str(random.randint(1000, 9999))
            if candidate not in used:
                used.add(candidate)
                requests.patch(
                    f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?id=eq.{worker['id']}",
                    json={"pin": candidate},
                    headers=sb_headers()
                )
                assigned.append({"name": worker["name"], "pin": candidate})
                break
    return jsonify({"ok": True, "assigned": len(assigned), "workers": assigned})

@app.route("/api/workers/<worker_id>", methods=["PATCH"])
def update_worker(worker_id):
    """Update worker fields — currently used for PIN assignment."""
    data = request.get_json() or {}
    allowed = ["pin", "role", "active", "name"]
    payload = {k: data[k] for k in allowed if k in data}
    if not payload:
        return jsonify({"ok": False, "error": "nothing to update"}), 400
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?id=eq.{worker_id}",
        json=payload,
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    if r.ok:
        return jsonify({"ok": True})
    if "unique" in r.text.lower() or "duplicate" in r.text.lower():
        return jsonify({"ok": False, "error": "unique constraint — PIN already taken"}), 409
    return jsonify({"ok": False, "error": r.text}), 400

@app.route("/api/workers/<worker_id>", methods=["DELETE"])
def deactivate_worker(worker_id):
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?id=eq.{worker_id}",
        json={"active": False}, headers=sb_headers()
    )
    return jsonify({"ok": r.ok})

# ═══════════════════════════════════════════════════════
#  SAFETY MEETING
# ═══════════════════════════════════════════════════════
@app.route("/api/safety-meeting", methods=["GET"])
def get_safety_meeting():
    """Today's safety meeting attendance."""
    today = __import__('datetime').date.today().isoformat()
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{SM_TABLE}"
        f"?date=eq.{today}&order=checked_in_at.asc",
        headers=sb_headers()
    )
    return jsonify(r.json() if r.ok else [])

@app.route("/api/safety-meeting", methods=["POST"])
def checkin_safety():
    """Mark worker as present in today's safety meeting + create payroll check-in."""
    import datetime as dt
    data = request.get_json() or {}
    name = data.get("worker_name","").strip()
    if not name:
        return jsonify({"ok": False, "error": "worker_name required"}), 400
    today = dt.date.today().isoformat()
    now_iso = dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

    # 1. Record safety meeting attendance
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/{SM_TABLE}",
        json={"worker_name": name, "date": today,
              "supervisor": data.get("supervisor","")},
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    if not r.ok:
        if "duplicate" in r.text.lower() or "unique" in r.text.lower():
            return jsonify({"ok": True, "duplicate": True})
        return jsonify({"ok": False, "error": r.text}), 400

    sm_record = r.json()[0] if r.json() else {}

    # 2. Create payroll check-in (if not already checked in today)
    existing = requests.get(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}"
        f"?worker_name=eq.{requests.utils.quote(name)}&date=eq.{today}"
        f"&checked_out_at=is.null&select=id&limit=1",
        headers=sb_headers()
    )
    if existing.ok and not existing.json():
        requests.post(
            f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}",
            json={"worker_name": name, "position": "Safety Meeting",
                  "date": today, "checked_in_at": now_iso},
            headers={**sb_headers(), "Prefer": "return=representation"}
        )

    return jsonify({"ok": True, "record": sm_record})

@app.route("/api/safety-meeting/<record_id>", methods=["DELETE"])
def undo_safety_checkin(record_id):
    """Remove a worker from today's safety meeting (undo) + remove payroll check-in if no checkout."""
    import datetime as dt
    # Get the worker name from the SM record before deleting
    sr = requests.get(
        f"{SUPABASE_URL}/rest/v1/{SM_TABLE}?id=eq.{record_id}&select=worker_name&limit=1",
        headers=sb_headers()
    )
    worker_name = ""
    if sr.ok and sr.json():
        worker_name = sr.json()[0].get("worker_name","")

    # Delete SM record
    r = requests.delete(
        f"{SUPABASE_URL}/rest/v1/{SM_TABLE}?id=eq.{record_id}",
        headers=sb_headers()
    )

    # Also remove payroll check-in for today if no checkout yet
    if worker_name:
        today = dt.date.today().isoformat()
        requests.delete(
            f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}"
            f"?worker_name=eq.{requests.utils.quote(worker_name)}"
            f"&date=eq.{today}&position=eq.Safety Meeting&checked_out_at=is.null",
            headers=sb_headers()
        )

    return jsonify({"ok": r.ok})

@app.route("/api/safety-meeting/history", methods=["GET"])
def safety_meeting_history():
    """Last 30 days of safety meeting attendance."""
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{SM_TABLE}"
        f"?order=date.desc,worker_name.asc&limit=500",
        headers=sb_headers()
    )
    return jsonify(r.json() if r.ok else [])

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/unit-log/<position>")
def unit_log(position):
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}"
        f"?select=date,period,area_phase,progress_pct,crew,notes,workers,created_at"
        f"&position=eq.{position}&order=date.asc,created_at.asc&limit=2000",
        headers=sb_headers()
    )
    return jsonify(resp.json() if resp.ok else [])


@app.route("/admin/wipe", methods=["GET", "POST"])
def admin_wipe():
    require_admin_secret()
    if request.method == "GET":
        return """<!DOCTYPE html><html><head><title>Admin - Wipe Logs</title>
        <style>body{background:#0d1117;color:#e2e8f0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:20px;}
        button{background:#ef4444;color:#fff;border:none;padding:12px 28px;border-radius:8px;font-size:16px;cursor:pointer;font-weight:700;}
        button:hover{opacity:.85;} .warn{color:#f59e0b;font-size:13px;}</style></head>
        <body><h2>Admin: Wipe All Log Data</h2>
        <p class="warn">This will permanently delete ALL records from daily_log.</p>
        <form method="POST"><button type="submit">DELETE ALL LOG DATA</button></form>
        <a href="/" style="color:#6b7280;font-size:13px">Cancel</a></body></html>"""
    # POST — actually wipe
    resp = requests.delete(
        f"{SUPABASE_URL}/rest/v1/{TABLE}?created_at=gte.2000-01-01",
        headers=sb_headers()
    )
    if resp.ok:
        return """<!DOCTYPE html><html><head><title>Wiped</title>
        <style>body{background:#0d1117;color:#22c55e;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px;}</style></head>
        <body><h2>All log data deleted.</h2><a href="/" style="color:#6b7280">Back to home</a></body></html>"""
    return f"Error: {resp.status_code} {resp.text}", 500



@app.route("/issues-log")
def issues_log_page():
    return render_template("issues_log.html")

@app.route("/api/issues/all", methods=["GET"])
def get_all_issues():
    """All issues across all units, newest first."""
    unit_filter = request.args.get("unit", "")
    status_filter = request.args.get("status", "")
    qs = f"{SUPABASE_URL}/rest/v1/unit_issues?order=created_at.desc&limit=500"
    if unit_filter:
        qs += f"&unit=eq.{unit_filter}"
    if status_filter:
        qs += f"&status=eq.{requests.utils.quote(status_filter)}"
    resp = requests.get(qs, headers=sb_headers())
    return jsonify(resp.json() if resp.ok else [])

@app.route("/api/issues/<issue_id>/status", methods=["PATCH"])
def update_issue_status(issue_id):
    data = request.get_json() or {}
    new_status = data.get("status")
    resolution = data.get("resolution", "")
    if not new_status:
        return jsonify({"ok": False, "error": "status required"}), 400
    patch = {"status": new_status}
    if resolution:
        patch["resolution"] = resolution
    resp = requests.patch(
        f"{SUPABASE_URL}/rest/v1/unit_issues?id=eq.{issue_id}",
        json=patch,
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    return jsonify({"ok": resp.ok})

@app.route("/api/issues/<issue_id>/edit", methods=["PATCH"])
def edit_issue(issue_id):
    data = request.get_json() or {}
    patch = {}
    for field in ["title", "category", "status", "description", "resolution", "date", "photos"]:
        if field in data:
            patch[field] = data[field]
    if not patch:
        return jsonify({"ok": False, "error": "Nothing to update"}), 400
    resp = requests.patch(
        f"{SUPABASE_URL}/rest/v1/unit_issues?id=eq.{issue_id}",
        json=patch,
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    return jsonify({"ok": resp.ok, "error": resp.text if not resp.ok else None})

@app.route("/api/issues/<issue_id>", methods=["DELETE"])
def delete_issue(issue_id):
    resp = requests.delete(
        f"{SUPABASE_URL}/rest/v1/unit_issues?id=eq.{issue_id}",
        headers=sb_headers()
    )
    return jsonify({"ok": resp.ok, "error": resp.text if not resp.ok else None})

@app.route("/issues/<unit>")
def issues_page(unit):
    return render_template("issues.html", unit=unit)

@app.route("/api/issues/<unit>")
def get_issues(unit):
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/unit_issues"
        f"?unit=eq.{unit}&order=created_at.desc&limit=100",
        headers=sb_headers()
    )
    return jsonify(resp.json() if resp.ok else [])

@app.route("/api/issues", methods=["POST"])
def create_issue():
    data = request.get_json()
    if not data or not data.get("unit") or not data.get("title"):
        return jsonify({"ok": False, "error": "unit and title required"}), 400
    row = {
        "unit":        data["unit"],
        "date":        data.get("date", date.today().isoformat()),
        "title":       data["title"],
        "status":      data.get("status", "Open"),
        "category":    data.get("category", "Other"),
        "description": data.get("description", ""),
        "resolution":  data.get("resolution", ""),
        "photos":      data.get("photos", []),
        "created_by":  data.get("created_by", "")
    }
    resp = requests.post(
        f"{SUPABASE_URL}/rest/v1/unit_issues",
        json=row,
        headers=sb_headers()
    )
    if resp.status_code in (200, 201):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": resp.text}), 500

@app.route("/api/test-storage")
def test_storage():
    """Debug: test if storage upload works with a tiny file."""
    import io
    test_data = b"hello"
    resp = requests.post(
        f"{SUPABASE_URL}/storage/v1/object/issue-photos/test-ping.txt",
        data=test_data,
        headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "text/plain",
            "Cache-Control": "max-age=3600"
        }
    )
    return jsonify({
        "status": resp.status_code,
        "ok": resp.ok,
        "response": resp.text[:500],
        "storage_url": f"{SUPABASE_URL}/storage/v1/object/issue-photos/test-ping.txt",
        "key_prefix": SUPABASE_KEY[:12] + "..." if SUPABASE_KEY else "MISSING"
    })

@app.route("/api/issues/upload-photo", methods=["POST"])
def upload_photo():
    file = request.files.get("photo")
    if not file:
        return jsonify({"ok": False, "error": "No file"}), 400
    ext = (file.filename or "img").rsplit(".", 1)[-1].lower()
    filename = f"{uuid.uuid4()}.{ext}"
    content_type = file.content_type or "image/jpeg"
    resp = requests.post(
        f"{SUPABASE_URL}/storage/v1/object/issue-photos/{filename}",
        data=file.read(),
        headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": content_type,
            "Cache-Control": "3600"
        }
    )
    if resp.ok:
        url = f"{SUPABASE_URL}/storage/v1/object/public/issue-photos/{filename}"
        return jsonify({"ok": True, "url": url})
    return jsonify({"ok": False, "error": resp.text}), 500




# ── Full ordered list of sub-trades (matches Log page sequence) ──
ORDERED_TRADES = []
_STRUCTURE_SUBS = [
    'C Channel / Holes Templates','Weld 4 I Beams (10\" I Beams)',
    'C Channels 12\" Weld To Enclose Frame','Square The Frame',
    'Inside C Channels/Square','Nuts Inside C Channel',
    'Floor Plate (Pull, Cut, Weld)','Square Tube Halo (Pull, Cut, Grind, Weld)',
    'I Beam On Halo Stand Up Posts','Square Halo And Weld To Post',
    'Square Tubes For Doors','Ground Plates','Weld Floor Plates Together'
]
for s in _STRUCTURE_SUBS:
    ORDERED_TRADES.append(f'1. Structure > {s}')
ORDERED_TRADES += ['2. Structure Paint','3. Envelope','4. Unit Paint']
_INT_SUBS = {
    'ELECTRICAL':         ['Ground Bar','Wall/Ceiling Boxes & Conduit','H2 Control Box & Conduit','HVAC Control Box & Conduit','Exhaust Fan Control Box & Conduit','PLC & Conduit','Wall/Ceiling Conduit'],
    'BATTERY CABINETS':   ['Place Inside Building','Unpack Units','Unpalletize Units','Position Units In Place','Uninstall Plates','Install Pucks','Put In Covers','Fans','KO Plates','Cover W/ Drop Cloth'],
    'IOs/POWER CABINETS': ['Unload From Truck','Unpack Units','Unpalletize Units','Position Units In Place','Uninstall Plates','Install Bars','Put In Covers','KO Plates','Cover W/ Drop Cloth'],
    'SWITCH GEAR':        ['Place Inside Building','Unpack Units','Unpalletize Units','Bus Bar','ATS Plate @ SwGr #2 To #3','Top Hats','KO Plates'],
    'PANELS & CABLE':     ['Panels/Transformers & Conduit','Cable Tray Supports (Struts)','24\" Cable Tray','30\" Cable Tray','24\" Step Down Tray','18\" Battery Tray'],
    'CONDUIT':            ['Battery To Battery','Battery To SwGr #4','IO To IO','IO To Batteries','IO To SwGr #4','Battery Cabinet Conduit','Batt To SwGr #4 Comm Conduit','2\" EMT @ SwGr #4'],
    'LIGHTING':           ['Lighting & Lamps','Lighting & Conduit'],
    'CLOSEOUT':           ['Cut Down All Thread','Cap All Thread','Caulk Screw Holes','Clean Up','Final Walk Through','Check All Boxes For Bushings','Check Conduit/Unistrut/All Thread Level & Plumb'],
}
for cat, subs in _INT_SUBS.items():
    for s in subs:
        ORDERED_TRADES.append(f'{cat} > {s}')
ORDERED_TRADES += ['6. Electrical','7. Final QC','8. Final Touchups']
# Pre-computed list of section 5 sub-tasks in workflow order (used for sec5_pct)
_SEC5_PREFIXES = {'ELECTRICAL','BATTERY CABINETS','IOs/POWER CABINETS',
                  'SWITCH GEAR','PANELS & CABLE','CONDUIT','LIGHTING','CLOSEOUT'}
INT_ORDERED = [ap for ap in ORDERED_TRADES
               if ' > ' in ap and ap.split(' > ')[0].strip() in _SEC5_PREFIXES]

@app.route("/api/urgency-report")
def urgency_report():
    # 1. MBR numbers per position
    mbr_resp = requests.get(f"{SUPABASE_URL}/rest/v1/rpc/get_latest_mbr_numbers", headers=sb_headers())
    mbr_map = {}
    for r in (mbr_resp.json() if mbr_resp.ok else []):
        pos = r.get("position",""); mbr = r.get("mbr_number","")
        if pos and str(mbr).strip():
            try: mbr_map[pos] = int(str(mbr).strip())
            except: pass

    if not mbr_map:
        return jsonify([])

    # 2. Latest progress per (position, area_phase) — same logic as unit-progress endpoint
    # Query only positions that have MBR numbers; order asc so last entry wins (most recent)
    pos_in = ",".join(f'"{p}"' for p in mbr_map.keys())
    prog_resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}"
        f"?select=position,area_phase,progress_pct"
        f"&position=in.({pos_in})"
        f"&progress_pct=not.is.null"
        f"&order=created_at.asc&limit=5000",
        headers=sb_headers()
    )
    progress = {}  # {position: {area_phase: pct}}
    for r in (prog_resp.json() if prog_resp.ok else []):
        pos = r.get("position",""); ap = r.get("area_phase",""); pct = r.get("progress_pct")
        if pos and ap and pct is not None:
            if pos not in progress: progress[pos] = {}
            progress[pos][ap] = pct  # last write wins = most recent

    # 3. Last 2 log entries per position (for "Last Updated" section)
    pos_list = ",".join(f'"{p}"' for p in mbr_map.keys())
    recent_resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}"
        f"?select=position,area_phase,progress_pct,date,period"
        f"&position=in.({pos_list})"
        f"&progress_pct=eq.1"
        f"&order=created_at.desc&limit=500",
        headers=sb_headers()
    )
    last_updated_map = {}  # {position: [{trade, pct, date, period}, ...]}
    for r in (recent_resp.json() if recent_resp.ok else []):
        pos = r.get("position",""); ap = r.get("area_phase","")
        pct = r.get("progress_pct"); d = r.get("date",""); per = r.get("period","")
        if not pos or not ap: continue
        if pos not in last_updated_map: last_updated_map[pos] = []
        if len(last_updated_map[pos]) < 2:
            last_updated_map[pos].append({
                "trade": ap,
                "pct": round(pct * 100) if pct is not None else 0,
                "date": d,
                "period": per
            })

    # 4. Build urgency data per unit
    results = []
    for pos, mbr_no in sorted(mbr_map.items(), key=lambda x: x[1]):
        trades = progress.get(pos, {})
        in_progress, not_started = [], []
        for ap in ORDERED_TRADES:
            pct = trades.get(ap)
            if pct is None or pct == 0.0:
                if len(not_started) < 2:
                    not_started.append({"trade": ap, "pct": 0})
            elif pct < 1.0:
                in_progress.append({"trade": ap, "pct": round(pct * 100)})
        in_progress.sort(key=lambda x: x["pct"])
        in_progress = in_progress[:2]

        # Section 5 overall % — use INT_ORDERED as definitive list
        # Unlogged tasks count as 0%; extra/renamed DB entries are ignored
        sec5_sum = sum(trades.get(ap, 0.0) for ap in INT_ORDERED)
        sec5_pct = min(round(sec5_sum / len(INT_ORDERED) * 100), 100) if INT_ORDERED else 0

        # Hide units where Section 5 is fully complete
        if sec5_pct >= 100:
            continue
        results.append({
            "position": pos,
            "mbr_no": mbr_no,
            "sec5_pct": sec5_pct,
            "last_updated": last_updated_map.get(pos, []),
            "in_progress": in_progress,
            "not_started": not_started
        })

    return jsonify(results)

@app.route("/all-mbr-numbers")
def all_mbr_numbers():
    """Return latest MBR No per unit position via RPC (DISTINCT ON — no limit truncation)."""
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/rpc/get_latest_mbr_numbers",
        headers=sb_headers()
    )
    records = resp.json() if resp.ok else []
    result = {}
    for r in records:
        pos = r.get("position", "") or ""
        mbr = r.get("mbr_number") or ""
        if pos and str(mbr).strip():
            result[pos] = str(mbr).strip()
    return jsonify(result)

@app.route("/all-progress")
def all_progress():
    # Use RPC function (DISTINCT ON) — returns exactly one row per (position, area_phase),
    # most recent. No limit/truncation issues regardless of DB size.
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/rpc/get_latest_progress",
        headers=sb_headers()
    )
    records = resp.json() if resp.ok else []
    latest = {}
    for r in records:
        pos = r.get("position", "")
        ap  = r.get("area_phase", "")
        key = (pos, ap)
        if r.get("progress_pct") is not None:
            latest[key] = r["progress_pct"]
    # Group by unit
    unit_trades = {}
    for (pos, ap), pct in latest.items():
        unit_trades.setdefault(pos, {})[ap] = pct
    # Known structure (mirrors KNOWN_SUBS in JS)
    KNOWN = {
        "1. Structure": ["C Channel / Holes Templates","Weld 4 I Beams (10\" I Beams)","C Channels 12\" Weld To Enclose Frame","Square The Frame","Inside C Channels/Square","Nuts Inside C Channel","Floor Plate (Pull, Cut, Weld)","Square Tube Halo (Pull, Cut, Grind, Weld)","I Beam On Halo Stand Up Posts","Square Halo And Weld To Post","Square Tubes For Doors","Ground Plates","Weld Floor Plates Together"],
        "ELECTRICAL": ["Ground Bar","Wall/Ceiling Boxes & Conduit","H2 Control Box & Conduit","HVAC Control Box & Conduit","Exhaust Fan Control Box & Conduit","PLC & Conduit","Wall/Ceiling Conduit"],
        "BATTERY CABINETS": ["Unload From Truck","Unpack Units","Unpalletize Units","Position Units In Place","Uninstall Plates","Install Pucks","Put In Covers","Fans","KO Plates","Cover W/ Drop Cloth"],
        "IOs/POWER CABINETS": ["Unload From Truck","Unpack Units","Unpalletize Units","Position Units In Place","Uninstall Plates","Install Bars","Put In Covers","KO Plates","Cover W/ Drop Cloth"],
        "SWITCH GEAR": ["Bus Bar","ATS Plate @ SwGr #2 To #3","Top Hats","KO Plates","2\" EMT @ SwGr #4"],
        "PANELS & CABLE": ["Panels/Transformers & Conduit","Cable Tray Supports (Struts)","24\" Cable Tray","30\" Cable Tray","24\" Step Down Tray","Battery To Battery Conduit","Batt To SwGr #4 Comm Conduit","18\" Battery Tray","Battery Cabinet Conduit"],
        "BATTERY CONNECTIONS": ["Battery To Battery","Battery To SwGr #4","18\" Battery Tray"],
        "IO CONDUIT": ["IO To IO","IO To Batteries","IO To SwGr #4"],
        "LIGHTING": ["Lighting & Conduit"],
        "CLOSEOUT": ["Cut Down All Thread","Cap All Thread","Caulk Screw Holes","Clean Up","Final Walk Through","Check All Boxes For Bushings","Check Conduit/Unistrut/All Thread Level & Plumb"]
    }
    CAT_TOT = {"1. Structure":13,"ELECTRICAL":7,"BATTERY CABINETS":10,"IOs/POWER CABINETS":9,"SWITCH GEAR":5,"PANELS & CABLE":9,"BATTERY CONNECTIONS":3,"IO CONDUIT":3,"LIGHTING":1,"CLOSEOUT":7}
    INT_SUBS = ["ELECTRICAL","BATTERY CABINETS","IOs/POWER CABINETS","SWITCH GEAR","PANELS & CABLE","BATTERY CONNECTIONS","IO CONDUIT","LIGHTING","CLOSEOUT"]
    CATONLY  = ["2. Structure Paint","3. Envelope","4. Unit Paint","6. Electrical","7. Final QC","8. Final Touchups"]
    MAINS    = ["1. Structure","2. Structure Paint","3. Envelope","4. Unit Paint","5. Internal Systems Rough-In","6. Electrical","7. Final QC","8. Final Touchups"]

    def trade_pct(trade, tmap):
        if trade in CATONLY:
            return tmap.get(trade)
        if trade == "5. Internal Systems Rough-In":
            s, has = 0, False
            for sub in INT_SUBS:
                for act in KNOWN.get(sub, []):
                    v = tmap.get(sub + " > " + act)
                    if v is not None: s += v; has = True
            return s / 54 if has else None
        acts = KNOWN.get(trade, [])
        if not acts: return None
        s, has = 0, False
        for act in acts:
            v = tmap.get(trade + " > " + act)
            if v is not None: s += v; has = True
        return (s / CAT_TOT.get(trade, len(acts))) if has else None

    result = {}
    for pos, tmap in unit_trades.items():
        pcts = [p for p in [trade_pct(t, tmap) for t in MAINS] if p is not None]
        # always divide by 8 so partial data doesn't inflate overall %
        sum_all8 = sum(trade_pct(t, tmap) or 0.0 for t in MAINS)
        result[pos] = round(sum_all8 / 8, 4) if pcts else 0.0
    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════
#  INVENTORY SYSTEM
# ═══════════════════════════════════════════════════════════════════

EDITOR_NAMES = ["Daniel H.", "Fabio", "Dispatcher"]

def is_editor(name):
    if not name:
        return False
    if name in EDITOR_NAMES:
        return True
    # Also accept any approved user with editor-level role
    try:
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/app_users"
            f"?name=eq.{requests.utils.quote(name)}&approved=eq.true&select=role&limit=1",
            headers=sb_headers()
        )
        rows = r.json() if r.ok else []
        if rows and rows[0].get("role") in ("admin", "boss", "inventory", "dispatcher"):
            return True
    except Exception:
        pass
    return False


@app.route("/api/users/editors", methods=["GET"])
def get_editors():
    """Return the fixed list of editor names for the picker modal."""
    return jsonify({"editors": sorted(EDITOR_NAMES)})

def notify_leads_attendance(worker_name, att_type, report_date, return_date, reason):
    """Email all leads/admins when someone submits an attendance report."""
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        return
    try:
        resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/app_users"
            f"?select=name,email,role"
            f"&role=in.(lead,admin,supervisor,boss)"
            f"&email=not.is.null&limit=50",
            headers=sb_headers()
        )
        leads = [u for u in (resp.json() if resp.ok else []) if u.get("email")]
        if ADMIN_EMAIL not in [u.get("email") for u in leads]:
            leads.append({"name": "Daniel", "email": ADMIN_EMAIL})
        if not leads:
            return

        type_labels = {"late": "🕐 Running Late", "absent": "❌ Absent", "vacation": "🏖 Vacation"}
        type_label = type_labels.get(att_type, att_type.upper())
        range_str = f"<br><b>Back to Work On:</b> {return_date}" if return_date else ""
        subject = f"MBR Texas Attendance — {worker_name} reported {att_type}"
        body_html = f"""
        <div style="font-family:Arial,sans-serif;max-width:480px;padding:20px;">
          <h2 style="margin:0 0 16px;color:#1e3a5f;">📋 Attendance Report</h2>
          <table style="width:100%;border-collapse:collapse;font-size:14px;">
            <tr><td style="padding:8px 0;color:#64748b;width:140px;">Type</td>
                <td style="padding:8px 0;font-weight:700;">{type_label}</td></tr>
            <tr><td style="padding:8px 0;color:#64748b;">Worker</td>
                <td style="padding:8px 0;font-weight:700;">{worker_name}</td></tr>
            <tr><td style="padding:8px 0;color:#64748b;">Date</td>
                <td style="padding:8px 0;">{report_date}{range_str}</td></tr>
            <tr><td style="padding:8px 0;color:#64748b;">Reason</td>
                <td style="padding:8px 0;">{reason or "—"}</td></tr>
          </table>
          <p style="margin-top:20px;font-size:12px;color:#94a3b8;">MBR Texas · TDG Tracker · Auto-notification</p>
        </div>"""

        for lead in leads:
            to_email = lead.get("email")
            if not to_email:
                continue
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"]    = SMTP_EMAIL
            msg["To"]      = to_email
            msg.attach(MIMEText(body_html, "html"))
            try:
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as srv:
                    srv.login(SMTP_EMAIL, SMTP_PASSWORD)
                    srv.sendmail(SMTP_EMAIL, [to_email], msg.as_string())
            except Exception:
                pass
    except Exception:
        pass


@app.route("/api/attendance", methods=["GET"])
def get_attendance():
    # Pass Supabase-style filters from query string (e.g. report_date=eq.2026-07-07)
    allowed = {"report_date", "worker_name", "type", "status"}
    qs_parts = ["select=*", "order=created_at.desc", "limit=200"]
    for key, val in request.args.items():
        # accept both bare keys and PostgREST operators (key=eq.value)
        col = key.split(".")[0] if "." in key else key
        if col in allowed:
            qs_parts.append(f"{key}={val}")
    qs = "&".join(qs_parts)
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/attendance_reports?{qs}",
        headers=sb_headers()
    )
    return jsonify(resp.json() if resp.ok else [])

@app.route("/api/attendance", methods=["POST"])
def post_attendance():
    data = request.get_json() or {}
    if not data.get("worker_name") or not data.get("type"):
        return jsonify({"error": "Missing fields"}), 400
    payload = {
        "worker_name": str(data.get("worker_name","")).strip(),
        "type":        str(data.get("type","")).strip(),
        "reason":      str(data.get("reason","")).strip(),
        "report_date": data.get("report_date") or None,
        "return_date": data.get("return_date") or None,
        "arrival_time":data.get("arrival_time") or None,
    }
    resp = requests.post(
        f"{SUPABASE_URL}/rest/v1/attendance_reports",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json=payload
    )
    if resp.ok:
        try:
            notify_leads_attendance(
                worker_name=payload["worker_name"],
                att_type=payload["type"],
                report_date=payload.get("report_date",""),
                return_date=payload.get("return_date",""),
                reason=payload.get("reason","")
            )
        except Exception:
            pass
        # Create in-app notification for leads/boss/admin
        try:
            type_labels = {"late": "🕐 Running Late", "absent": "❌ Absent", "vacation": "🏖 Vacation"}
            tlabel = type_labels.get(payload["type"], payload["type"].upper())
            notif_title = f"{tlabel} — {payload['worker_name']}"
            notif_body  = f"{payload.get('reason','—')} | {payload.get('report_date','')}"
            requests.post(
                f"{SUPABASE_URL}/rest/v1/notifications",
                json={"title": notif_title, "body": notif_body,
                      "target": "supervisor", "created_by": payload["worker_name"]},
                headers={**sb_headers(), "Prefer": "return=minimal"},
                timeout=5
            )
        except Exception:
            pass
        return jsonify({"ok": True})
    try:
        err_detail = resp.json()
    except Exception:
        err_detail = resp.text
    return jsonify({"error": str(err_detail)}), 500

@app.route("/api/attendance/<int:att_id>", methods=["PATCH"])
def patch_attendance(att_id):
    data = request.get_json() or {}
    allowed = {"type","reason","report_date","return_date","arrival_time","status"}
    payload = {k: v for k,v in data.items() if k in allowed}
    if not payload:
        return jsonify({"error": "Nothing to update"}), 400
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/attendance_reports?id=eq.{att_id}",
        json=payload,
        headers={**sb_headers(), "Prefer": "return=minimal"}
    )
    return jsonify({"ok": r.ok, "status": r.status_code})

@app.route("/api/attendance/<int:att_id>", methods=["DELETE"])
def delete_attendance(att_id):
    r = requests.delete(
        f"{SUPABASE_URL}/rest/v1/attendance_reports?id=eq.{att_id}",
        headers=sb_headers()
    )
    return jsonify({"ok": r.ok})

@app.route("/api/attendance/today", methods=["GET"])
def get_attendance_today():
    from datetime import date as _d
    today = _d.today().isoformat()
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/attendance_reports"
        f"?report_date=eq.{today}&select=*&order=created_at.desc",
        headers=sb_headers(), timeout=5
    )
    return jsonify(r.json() if r.ok else [])

@app.route("/api/attendance/active", methods=["GET"])
def get_attendance_active():
    """Returns attendance records that are active RIGHT NOW.

    Rules:
    - late:              report_date == today only
    - absent / vacation: report_date <= today AND return_date > today
                         (return_date is the day they come BACK, so they are
                          absent up to but not including that date).
                         If return_date is null, treat as single-day (report_date == today).
    """
    from datetime import date as _d
    today = _d.today().isoformat()

    # Fetch a window of recent records that could possibly be active:
    # report_date <= today, going back up to 60 days.
    import datetime as dt
    sixty_ago = (dt.date.today() - dt.timedelta(days=60)).isoformat()
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/attendance_reports"
        f"?report_date=lte.{today}&report_date=gte.{sixty_ago}"
        f"&select=*&order=created_at.desc&limit=500",
        headers=sb_headers(), timeout=8
    )
    if not r.ok:
        return jsonify([])

    rows = r.json()
    active = []
    for row in rows:
        t            = (row.get("type") or "absent").lower()
        report_date  = row.get("report_date") or ""
        return_date  = row.get("return_date") or ""

        if t == "late":
            # Late only applies on its own date
            if report_date == today:
                active.append(row)
        else:
            # absent / vacation: active if today is in [report_date, return_date)
            if not return_date:
                # No return date → treat as single-day absence
                if report_date == today:
                    active.append(row)
            else:
                # return_date is the day they come BACK → absent while today < return_date
                if report_date <= today < return_date:
                    active.append(row)

    return jsonify(active)

@app.route("/timesheet")
def timesheet_page():
    return render_template("timesheet.html")


@app.route("/inventory")
def inventory_page():
    return render_template("inventory.html")

@app.route("/schedule")
def schedule_page():
    return render_template("schedule.html")

# ── Inventory items ──────────────────────────────────────────────

# ── Inventory SKU generation ─────────────────────────────────────────────────
_CAT_PREFIX = {
    'Cable Tray':'CBL','Conduit':'CON','Electrical':'ELE','Fasteners':'FST',
    'Hardware':'HRW','Roofing':'ROF','Sealant':'SEL','Trim':'TRM',
    'Drainage':'DRN','Insulation':'INS','Wall Panels':'WLP',
    'Coatings':'CTG','General':'GEN'
}
def gen_sku(category, item_id):
    pfx = _CAT_PREFIX.get(category, (category[:3].upper() if category else 'GEN'))
    return f"MBR-{pfx}-{str(item_id).zfill(4)}"

@app.route("/api/inventory", methods=["GET"])
def get_inventory():
    url = f"{SUPABASE_URL}/rest/v1/inventory_items?select=*&order=category.asc,name.asc&limit=500"
    r = requests.get(url, headers=sb_headers())
    return jsonify(r.json() if r.ok else [])

@app.route("/api/inventory", methods=["POST"])
def add_inventory_item():
    data = request.json or {}
    if not is_editor(data.get("editor", "")):
        return jsonify({"error": "Editor access required"}), 403
    payload = {k: data[k] for k in ["name","category","unit","qty_on_hand","notes","safe_qty","location_code"] if k in data}
    if data.get("created_by"): payload["created_by"] = data["created_by"]
    url = f"{SUPABASE_URL}/rest/v1/inventory_items"
    r = requests.post(url, headers={**sb_headers(), "Prefer": "return=representation"}, json=payload)
    if r.ok:
        rows = r.json()
        if rows and isinstance(rows, list):
            new_id = rows[0].get("id")
            cat = payload.get("category", "General")
            sku = gen_sku(cat, new_id)
            requests.patch(
                f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{new_id}",
                headers=sb_headers(), json={"sku": sku}
            )
            return jsonify({"ok": True, "sku": sku})
        return jsonify({"ok": True})
    return jsonify({"error": r.text}), 400

@app.route("/api/inventory/<item_id>", methods=["PUT"])
def update_inventory_item(item_id):
    data = request.json or {}
    if not is_editor(data.get("editor", "")):
        return jsonify({"error": "Editor access required"}), 403
    payload = {}
    if "qty_on_hand" in data:
        new_qty = data["qty_on_hand"]
        payload["qty_on_hand"] = new_qty
        # Auto-set last_restocked_at if qty increased
        cur_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{item_id}&select=qty_on_hand&limit=1",
            headers=sb_headers()
        )
        if cur_r.ok:
            cur = cur_r.json()
            if cur and isinstance(new_qty, (int, float)) and new_qty > (cur[0].get("qty_on_hand") or 0):
                payload["last_restocked_at"] = "now()"
    if "name" in data: payload["name"] = data["name"]
    if "category" in data: payload["category"] = data["category"]
    if "unit" in data: payload["unit"] = data["unit"]
    if "notes" in data: payload["notes"] = data["notes"]
    if "safe_qty" in data: payload["safe_qty"] = data["safe_qty"]
    if "location_code" in data: payload["location_code"] = data["location_code"]
    if data.get("updated_by"): payload["updated_by"] = data["updated_by"]
    payload["updated_at"] = "now()"
    url = f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{item_id}"
    r = requests.patch(url, headers={**sb_headers(), "Prefer": "return=representation"}, json=payload)
    if r.ok:
        # ── Safety stock notification ─────────────────────────────────
        try:
            new_qty   = payload.get("qty_on_hand")
            new_safe  = payload.get("safe_qty")
            # Fetch current item to get all values if not in payload
            item_r = requests.get(
                f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{item_id}&select=name,qty_on_hand,safe_qty&limit=1",
                headers=sb_headers(), timeout=5
            )
            if item_r.ok and item_r.json():
                item = item_r.json()[0]
                cur_qty  = new_qty  if new_qty  is not None else (item.get("qty_on_hand") or 0)
                cur_safe = new_safe if new_safe is not None else (item.get("safe_qty") or 0)
                item_name = item.get("name", "Item")
                if cur_safe > 0 and cur_qty <= cur_safe:
                    status_word = "OUT" if cur_qty <= 0 else "LOW"
                    notif_title = f"⚠️ Inventory {status_word}: {item_name}"
                    notif_body  = f"On hand: {cur_qty} | Safe level: {cur_safe}. Restock needed."
                    requests.post(
                        f"{SUPABASE_URL}/rest/v1/notifications",
                        json={"title": notif_title, "body": notif_body,
                              "target": "supervisor", "created_by": "system"},
                        headers={**sb_headers(), "Prefer": "return=minimal"},
                        timeout=5
                    )
        except Exception:
            pass
        # ─────────────────────────────────────────────────────────────
        return jsonify({"ok": True})
    return jsonify({"error": r.text}), 400

@app.route("/api/inventory/low-stock", methods=["GET"])
def get_low_stock():
    """Return items where qty_on_hand <= safe_qty (and safe_qty > 0)."""
    url = f"{SUPABASE_URL}/rest/v1/inventory_items?safe_qty=gt.0&order=category.asc,name.asc&select=*&limit=500"
    r = requests.get(url, headers=sb_headers())
    if not r.ok:
        return jsonify([])
    items = [it for it in r.json() if (it.get("qty_on_hand") or 0) <= (it.get("safe_qty") or 0)]
    return jsonify(items)

@app.route("/api/inventory/low-stock/email", methods=["POST"])
def email_low_stock():
    """Send low-stock alert email to admin."""
    if not SMTP_EMAIL or not SMTP_PASSWORD or not ADMIN_EMAIL:
        return jsonify({"error": "Email not configured"}), 500
    # Fetch low-stock items
    url = f"{SUPABASE_URL}/rest/v1/inventory_items?safe_qty=gt.0&order=category.asc,name.asc&select=*&limit=500"
    r = requests.get(url, headers=sb_headers())
    if not r.ok:
        return jsonify({"error": "Failed to fetch inventory"}), 500
    items = [it for it in r.json() if (it.get("qty_on_hand") or 0) <= (it.get("safe_qty") or 0)]
    if not items:
        return jsonify({"ok": True, "count": 0, "message": "No low-stock items"})
    rows = "".join(
        f"<tr><td style='padding:8px 12px;border-bottom:1px solid #1a2535;color:#e2e8f0;'>{it.get('category','')}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #1a2535;color:#e2e8f0;font-weight:700;'>{it.get('name','')}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #1a2535;color:#f87171;font-weight:700;text-align:center;'>{it.get('qty_on_hand',0)}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #1a2535;color:#fbbf24;text-align:center;'>{it.get('safe_qty',0)}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #1a2535;color:#94a3b8;text-align:center;'>{(it.get('last_restocked_at') or 'Never')[:10]}</td>"
        f"</tr>"
        for it in items
    )
    from datetime import datetime
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    html = f"""<div style="background:#060c18;padding:24px;font-family:Arial,sans-serif;">
<h2 style="color:#f87171;margin:0 0 8px;">⚠️ Low Stock Alert — MBR Texas</h2>
<p style="color:#94a3b8;margin:0 0 20px;font-size:13px;">Generated {now_str} &middot; {len(items)} item(s) at or below safe quantity</p>
<table style="width:100%;border-collapse:collapse;background:#0d1a2d;border-radius:8px;overflow:hidden;">
<thead><tr>
  <th style="padding:10px 12px;text-align:left;color:#94a3b8;font-size:11px;border-bottom:1px solid #1a2535;">CATEGORY</th>
  <th style="padding:10px 12px;text-align:left;color:#94a3b8;font-size:11px;border-bottom:1px solid #1a2535;">ITEM</th>
  <th style="padding:10px 12px;text-align:center;color:#94a3b8;font-size:11px;border-bottom:1px solid #1a2535;">ON HAND</th>
  <th style="padding:10px 12px;text-align:center;color:#94a3b8;font-size:11px;border-bottom:1px solid #1a2535;">SAFE QTY</th>
  <th style="padding:10px 12px;text-align:center;color:#94a3b8;font-size:11px;border-bottom:1px solid #1a2535;">LAST RESTOCKED</th>
</tr></thead>
<tbody>{rows}</tbody>
</table></div>"""
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"⚠️ Low Stock Alert — {len(items)} item(s) need restocking"
    msg["From"] = SMTP_EMAIL
    msg["To"] = ADMIN_EMAIL
    msg.attach(MIMEText(html, "html"))
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as srv:
            srv.login(SMTP_EMAIL, SMTP_PASSWORD)
            srv.sendmail(SMTP_EMAIL, [ADMIN_EMAIL], msg.as_string())
        return jsonify({"ok": True, "count": len(items)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# ══════════════════════════════════════════════════════════════════
#  PURCHASE ORDERS  (Albaranes / Receiving)
# ══════════════════════════════════════════════════════════════════

@app.route("/api/po-test", methods=["POST","GET"])
def po_test():
    """Debug: confirm Flask receives POSTs"""
    return {"ok": True, "method": request.method, "got": (request.get_json(silent=True) or {})}

@app.route("/api/po", methods=["GET"])
def list_pos():
    """List purchase orders — optional ?status= filter."""
    status = request.args.get("status","")
    q = f"&status=eq.{status}" if status else ""
    url = f"{SUPABASE_URL}/rest/v1/purchase_orders?order=created_at.desc&limit=200{q}"
    r = requests.get(url, headers=sb_headers())
    if not r.ok:
        return jsonify({"ok": False, "pos": [], "error": r.text}), 500
    return jsonify({"ok": True, "pos": r.json()})


@app.route("/api/po", methods=["POST"])
def create_po():
    """Create a new purchase order."""
    data = request.get_json(silent=True) or {}
    required = ["po_number"]
    for f in required:
        if not data.get(f):
            return jsonify({"error": f"Missing {f}"}), 400
    payload = {
        "po_number":     data["po_number"].strip().upper(),
        "supplier":      data.get("supplier","").strip() or None,
        "expected_date": data.get("expected_date") or None,
        "status":        "pending",
        "items":         data.get("items", []),
        "notes":         data.get("notes","").strip() or None,
        "created_by":    data.get("created_by",""),
    }
    try:
        r = requests.post(
            f"{SUPABASE_URL}/rest/v1/purchase_orders",
            json=payload,
            headers={**sb_headers(), "Prefer": "return=representation"},
            timeout=10
        )
    except Exception as e:
        return jsonify({"error": f"Request failed: {str(e)}"}), 500
    if r.ok:
        try:
            rows = r.json()
            return jsonify({"ok": True, "po": rows[0] if rows else {}})
        except Exception:
            return jsonify({"ok": True, "po": {}})
    return jsonify({"error": f"Supabase {r.status_code}: {r.text[:300]}"}), 400


@app.route("/api/po/<po_id>", methods=["GET"])
def get_po(po_id):
    url = f"{SUPABASE_URL}/rest/v1/purchase_orders?id=eq.{po_id}&limit=1"
    r = requests.get(url, headers=sb_headers())
    if not r.ok or not r.json():
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True, "po": r.json()[0]})


@app.route("/api/po/<po_id>", methods=["PATCH"])
def update_po(po_id):
    """Update PO fields — items, notes, status, photos, etc."""
    data = request.get_json(silent=True) or {}
    allowed = {"po_number","supplier","expected_date","status","items",
               "notes","discrepancy_notes","photos","received_by","received_at"}
    payload = {k: v for k, v in data.items() if k in allowed}
    if not payload:
        return jsonify({"error": "Nothing to update"}), 400
    payload["updated_at"] = "now()"
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/purchase_orders?id=eq.{po_id}",
        json=payload,
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    if r.ok:
        return jsonify({"ok": True})
    return jsonify({"error": r.text}), 400


@app.route("/api/po/<po_id>/receive", methods=["POST"])
def receive_po(po_id):
    """
    Accept a received PO:
    - Update qty_received on each item in the PO
    - Increment inventory_items.qty_on_hand for each item
    - Set PO status to received/partial
    - Record received_by + photos + notes
    """
    data = request.get_json(silent=True) or {}
    received_by = data.get("received_by","")
    items       = data.get("items", [])       # [{item_id, qty_received}]
    photos      = data.get("photos", [])
    disc_notes  = data.get("discrepancy_notes","")

    if not items:
        return jsonify({"error": "No items provided"}), 400

    # Fetch current PO
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/purchase_orders?id=eq.{po_id}&limit=1",
        headers=sb_headers()
    )
    if not r.ok or not r.json():
        return jsonify({"error": "PO not found"}), 404
    po = r.json()[0]
    po_items = po.get("items", [])

    # Build a lookup of received quantities {item_id: qty_received}
    recv_map = {str(it.get("item_id","")): float(it.get("qty_received",0)) for it in items}

    # Update each PO item's qty_received
    fully_received = True
    for pi in po_items:
        iid = str(pi.get("item_id",""))
        if iid in recv_map:
            pi["qty_received"] = recv_map[iid]
        expected = float(pi.get("qty_expected", 0))
        received = float(pi.get("qty_received", 0))
        if received < expected:
            fully_received = False

    # Increment inventory qty_on_hand for each item
    errors = []
    for iid, qty in recv_map.items():
        if not iid or qty <= 0:
            continue
        # Get current qty
        ir = requests.get(
            f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{iid}&select=qty_on_hand,name&limit=1",
            headers=sb_headers()
        )
        if not ir.ok or not ir.json():
            errors.append(f"Item {iid} not found")
            continue
        cur = ir.json()[0]
        new_qty = (cur.get("qty_on_hand") or 0) + qty
        pr = requests.patch(
            f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{iid}",
            json={"qty_on_hand": new_qty, "last_restocked_at": "now()", "updated_at": "now()"},
            headers={**sb_headers(), "Prefer": "return=minimal"}
        )
        if not pr.ok:
            errors.append(f"Failed to update {cur.get('name',iid)}: {pr.text}")

    # Update PO record
    from datetime import datetime
    new_status = "received" if fully_received else "partial"
    patch_payload = {
        "status":             new_status,
        "items":              po_items,
        "photos":             photos,
        "discrepancy_notes":  disc_notes or None,
        "received_by":        received_by,
        "received_at":        datetime.utcnow().isoformat() + "Z",
        "updated_at":         "now()"
    }
    requests.patch(
        f"{SUPABASE_URL}/rest/v1/purchase_orders?id=eq.{po_id}",
        json=patch_payload,
        headers={**sb_headers(), "Prefer": "return=minimal"}
    )

    # In-app notification
    try:
        requests.post(
            f"{SUPABASE_URL}/rest/v1/notifications",
            json={"title": f"📦 PO Received: {po.get('po_number',po_id)}",
                  "body": f"{new_status.upper()} — received by {received_by}. {len(errors)} error(s).",
                  "target": "supervisor", "created_by": received_by},
            headers={**sb_headers(), "Prefer": "return=minimal"}, timeout=5
        )
    except Exception:
        pass

    return jsonify({"ok": True, "status": new_status, "errors": errors})



@app.route("/api/inventory/locations", methods=["GET"])
def get_inventory_locations():
    """Return items grouped by location_code."""
    url = f"{SUPABASE_URL}/rest/v1/inventory_items?select=id,name,category,sku,location_code,qty_on_hand,unit&order=location_code.asc,name.asc&limit=500"
    r = requests.get(url, headers=sb_headers())
    if not r.ok:
        return jsonify([])
    items = r.json()
    groups = {}
    unassigned = []
    for it in items:
        loc = (it.get("location_code") or "").strip()
        if loc:
            if loc not in groups:
                groups[loc] = []
            groups[loc].append(it)
        else:
            unassigned.append(it)
    result = [{"location": k, "items": v} for k, v in sorted(groups.items())]
    if unassigned:
        result.append({"location": None, "items": unassigned})
    return jsonify(result)


@app.route("/api/inventory/locations/qr-pdf", methods=["GET"])
def inventory_locations_qr_pdf():
    """Generate a PDF with one QR code per location."""
    import qrcode
    import io as _io
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.utils import ImageReader

    # Fetch distinct locations
    url = f"{SUPABASE_URL}/rest/v1/inventory_items?select=location_code&not.location_code.is=null&order=location_code.asc&limit=500"
    r = requests.get(url, headers=sb_headers())
    if not r.ok:
        return "Error fetching locations", 500
    rows = r.json()
    locs = sorted(set((row.get("location_code") or "").strip() for row in rows if (row.get("location_code") or "").strip()))
    if not locs:
        return "No locations assigned yet", 404

    # Build PDF
    buf = _io.BytesIO()
    W, H = letter
    c = rl_canvas.Canvas(buf, pagesize=letter)
    
    # Header
    c.setFillColorRGB(0.118, 0.227, 0.373)  # #1e3a5f
    c.rect(0, H-52, W, 52, fill=1, stroke=0)
    c.setFillColorRGB(1,1,1)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(36, H-34, "MBR Texas — Inventory Location QR Codes")
    c.setFont("Helvetica", 9)
    from datetime import datetime
    c.drawString(36, H-47, f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC")

    # Grid layout
    COLS = 3
    QR_SIZE = 120
    CELL_W = (W - 72) / COLS
    CELL_H = QR_SIZE + 44
    MARGIN_TOP = H - 52 - 20
    x0, y0 = 36, MARGIN_TOP

    for i, loc in enumerate(locs):
        col = i % COLS
        row = i // COLS
        cx = x0 + col * CELL_W
        cy = y0 - row * CELL_H

        # New page if needed
        if cy - CELL_H < 36:
            c.showPage()
            c.setFillColorRGB(0.118, 0.227, 0.373)
            c.rect(0, H-52, W, 52, fill=1, stroke=0)
            c.setFillColorRGB(1,1,1)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(36, H-34, "MBR Texas — Inventory Location QR Codes")
            cy = H - 52 - 20
            row = 0

        # Generate QR
        qr_url = f"https://tdg-tracker.onrender.com/inventory?loc={loc}"
        qr_img = qrcode.make(qr_url)
        qr_buf = _io.BytesIO()
        qr_img.save(qr_buf, format='PNG')
        qr_buf.seek(0)

        # Draw QR
        qx = cx + (CELL_W - QR_SIZE) / 2
        qy = cy - QR_SIZE - 8
        c.drawImage(ImageReader(qr_buf), qx, qy, width=QR_SIZE, height=QR_SIZE)

        # Location label
        c.setFillColorRGB(0.12, 0.22, 0.35)
        c.setFont("Helvetica-Bold", 13)
        label_x = cx + CELL_W / 2
        c.drawCentredString(label_x, qy - 16, loc)
        c.setFillColorRGB(0.4, 0.5, 0.6)
        c.setFont("Helvetica", 8)
        c.drawCentredString(label_x, qy - 28, "Scan to view inventory at this location")

        # Border
        c.setStrokeColorRGB(0.88, 0.91, 0.94)
        c.roundRect(cx + 4, qy - 34, CELL_W - 8, QR_SIZE + 42, 6, stroke=1, fill=0)

    c.save()
    buf.seek(0)
    from flask import send_file
    return send_file(buf, mimetype='application/pdf',
                     as_attachment=True,
                     download_name='MBR_Inventory_Locations_QR.pdf')


@app.route("/api/inventory/sku-backfill", methods=["POST"])
def sku_backfill():
    """Generate SKUs for existing items that don't have one."""
    data = request.json or {}
    if not is_editor(data.get("editor","")):
        return jsonify({"error":"Editor access required"}),403
    url = f"{SUPABASE_URL}/rest/v1/inventory_items?sku=is.null&select=id,category&limit=500"
    r = requests.get(url, headers=sb_headers())
    if not r.ok:
        return jsonify({"error":r.text}),500
    items = r.json()
    updated = 0
    for it in items:
        sku = gen_sku(it.get("category","General"), it["id"])
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{it['id']}",
            headers=sb_headers(), json={"sku": sku}
        )
        updated += 1
    return jsonify({"ok":True,"updated":updated})

@app.route("/api/inventory/<item_id>", methods=["DELETE"])
def delete_inventory_item(item_id):
    data = request.json or {}
    if not is_editor(data.get("editor", "")):
        return jsonify({"error": "Editor access required"}), 403
    url = f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{item_id}"
    r = requests.delete(url, headers=sb_headers())
    if r.ok:
        return jsonify({"ok": True})
    return jsonify({"error": r.text}), 400

# ── Material requests ────────────────────────────────────────────
@app.route("/api/material-requests", methods=["GET"])
def get_material_requests():
    status = request.args.get("status")
    item_id = request.args.get("item_id")
    url = f"{SUPABASE_URL}/rest/v1/material_requests?select=*&order=created_at.desc&limit=200"
    if status:
        url += f"&status=eq.{status}"
    if item_id:
        url += f"&item_id=eq.{item_id}"
    r = requests.get(url, headers=sb_headers())
    return jsonify(r.json() if r.ok else [])

@app.route("/api/material-requests", methods=["POST"])
def create_material_request():
    data = request.json or {}
    required = ["requester_name", "item_name", "qty_needed"]
    for f in required:
        if not data.get(f):
            return jsonify({"error": f"{f} required"}), 400
    payload = {
        "requester_name": data["requester_name"],
        "item_name": data["item_name"],
        "qty_needed": data["qty_needed"],
        "item_id": data.get("item_id"),
        "building": data.get("building", ""),
        "notes": data.get("notes", ""),
        "job_name": data.get("job_name", ""),
        "contractor_company": data.get("contractor_company", ""),
        "status": "Pending"
    }
    if data.get("materials_json"):
        payload["materials_json"] = data["materials_json"]
    url = f"{SUPABASE_URL}/rest/v1/material_requests"
    r = requests.post(url, headers={**sb_headers(), "Prefer": "return=representation"}, json=payload)
    if r.ok:
        return jsonify({"ok": True})
    return jsonify({"error": r.text}), 400

@app.route("/api/material-requests/<req_id>/approve", methods=["POST"])
def approve_material_request(req_id):
    data = request.json or {}
    if not is_editor(data.get("approved_by", "")):
        return jsonify({"error": "Editor access required"}), 403
    status = data.get("status", "Approved")
    payload = {"status": status, "approved_by": data["approved_by"], "approved_at": "now()"}
    url = f"{SUPABASE_URL}/rest/v1/material_requests?id=eq.{req_id}"
    r = requests.patch(url, headers={**sb_headers(), "Prefer": "return=representation"}, json=payload)
    if r.ok:
        return jsonify({"ok": True})
    return jsonify({"error": r.text}), 400

@app.route("/api/material-requests/<req_id>/deliver", methods=["POST"])
def deliver_material_request(req_id):
    import json as _json
    data = request.json or {}
    delivered_by = data.get("delivered_by", "")
    signature_data = data.get("signature_data", "")
    pickup_by = data.get("pickup_by", "")
    if not delivered_by:
        return jsonify({"error": "delivered_by required"}), 400
    # Fetch the request to get all material lines
    req_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/material_requests?id=eq.{req_id}&select=*&limit=1",
        headers=sb_headers()
    )
    materials = []
    if req_r.ok and req_r.json():
        rd = req_r.json()[0]
        if rd.get("materials_json"):
            try: materials = _json.loads(rd["materials_json"])
            except Exception: pass
        if not materials:
            materials = [{"item_id": rd.get("item_id"), "item_name": rd.get("item_name",""), "qty_needed": rd.get("qty_needed", 0)}]
    # Decrement inventory for each material line
    for mat in materials:
        iid = mat.get("item_id")
        qty = int(mat.get("qty_needed") or 0)
        if not iid or qty <= 0:
            continue
        inv_r = requests.get(
            f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{iid}&select=qty_on_hand&limit=1",
            headers=sb_headers()
        )
        if inv_r.ok and inv_r.json():
            cur_qty = inv_r.json()[0].get("qty_on_hand") or 0
            new_qty = max(0, cur_qty - qty)
            requests.patch(
                f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{iid}",
                headers={**sb_headers(), "Prefer": "return=minimal"},
                json={"qty_on_hand": new_qty, "updated_at": "now()"}
            )
    # Mark request delivered
    payload = {
        "status": "Delivered",
        "delivered_by": delivered_by,
        "delivered_at": "now()",
        "signature_data": signature_data,
        "pickup_by": pickup_by
    }
    url = f"{SUPABASE_URL}/rest/v1/material_requests?id=eq.{req_id}"
    r = requests.patch(url, headers={**sb_headers(), "Prefer": "return=representation"}, json=payload)
    if r.ok:
        return jsonify({"ok": True})
    return jsonify({"error": r.text}), 400


@app.route("/api/material-requests/<req_id>", methods=["DELETE"])
def delete_material_request(req_id):
    """Admin-only: permanently delete a material request.
    If the request was Delivered, restores inventory quantities."""
    import json as _json
    role = request.headers.get("X-Role", "worker")
    if role not in ("admin",):
        return jsonify({"error": "Admin only"}), 403

    # Fetch the request first to check status and get material lines
    req_r = requests.get(
        f"{SUPABASE_URL}/rest/v1/material_requests?id=eq.{req_id}&select=*&limit=1",
        headers=sb_headers()
    )
    restored = 0
    if req_r.ok and req_r.json():
        rd = req_r.json()[0]
        if rd.get("status") == "Delivered":
            # Build materials list
            materials = []
            if rd.get("materials_json"):
                try: materials = _json.loads(rd["materials_json"])
                except Exception: pass
            if not materials:
                materials = [{"item_id": rd.get("item_id"),
                              "item_name": rd.get("item_name", ""),
                              "qty_needed": rd.get("qty_needed", 0)}]
            # Restore inventory for each line
            for mat in materials:
                iid = mat.get("item_id")
                qty = int(mat.get("qty_needed") or 0)
                if not iid or qty <= 0:
                    continue
                inv_r = requests.get(
                    f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{iid}&select=qty_on_hand&limit=1",
                    headers=sb_headers()
                )
                if inv_r.ok and inv_r.json():
                    cur_qty = inv_r.json()[0].get("qty_on_hand") or 0
                    requests.patch(
                        f"{SUPABASE_URL}/rest/v1/inventory_items?id=eq.{iid}",
                        headers={**sb_headers(), "Prefer": "return=minimal"},
                        json={"qty_on_hand": cur_qty + qty, "updated_at": "now()"}
                    )
                    restored += qty

    # Delete the request
    url = f"{SUPABASE_URL}/rest/v1/material_requests?id=eq.{req_id}"
    r = requests.delete(url, headers={
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Prefer": "return=minimal"
    })
    if r.status_code in (200, 204):
        return jsonify({"ok": True, "inventory_restored": restored > 0, "qty_restored": restored})
    return jsonify({"error": r.text}), 400

@app.route("/api/material-requests/export", methods=["GET"])
def export_material_requests():
    """Export material requests with optional filters."""
    filters = []
    if request.args.get("status"):
        filters.append(f"status=eq.{requests.utils.quote(request.args['status'])}")
    if request.args.get("job_name"):
        filters.append(f"job_name=eq.{requests.utils.quote(request.args['job_name'])}")
    if request.args.get("contractor_company"):
        filters.append(f"contractor_company=eq.{requests.utils.quote(request.args['contractor_company'])}")
    if request.args.get("item_name"):
        filters.append(f"item_name=ilike.*{requests.utils.quote(request.args['item_name'])}*")
    if request.args.get("date_from"):
        filters.append(f"created_at=gte.{requests.utils.quote(request.args['date_from'])}")
    if request.args.get("date_to"):
        filters.append(f"created_at=lte.{requests.utils.quote(request.args['date_to'])}T23:59:59")
    qs = "&".join(filters) + ("&" if filters else "")
    url = (f"{SUPABASE_URL}/rest/v1/material_requests"
           f"?{qs}select=id,created_at,requester_name,contractor_company,job_name,"
           f"item_name,qty_needed,building,notes,status,approved_by,approved_at,"
           f"delivered_by,delivered_at,pickup_by&order=created_at.desc&limit=1000")
    r = requests.get(url, headers=sb_headers())
    return jsonify(r.json() if r.ok else [])

# ── App users / PIN ──────────────────────────────────────────────
@app.route("/api/users/has-pin", methods=["GET"])
def has_pin():
    name = request.args.get("name", "")
    url = f"{SUPABASE_URL}/rest/v1/app_users?name=eq.{requests.utils.quote(name)}&select=pin"
    r = requests.get(url, headers=sb_headers())
    rows = r.json() if r.ok else []
    has = bool(rows and rows[0].get("pin"))
    return jsonify({"has_pin": has})

@app.route("/api/users/set-pin", methods=["POST"])
def set_pin():
    data = request.json or {}
    name = data.get("name", "")
    pin = str(data.get("pin", ""))
    if not pin or len(pin) != 4 or not pin.isdigit():
        return jsonify({"error": "PIN must be 4 digits"}), 400
    # Uniqueness check — no two users can share a PIN
    chk = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_users?pin=eq.{pin}&select=name&limit=1",
        headers=sb_headers()
    )
    taken = [r for r in (chk.json() if chk.ok else []) if r.get("name") != name]
    if taken:
        return jsonify({"error": "PIN already taken — choose another"}), 409
    url = f"{SUPABASE_URL}/rest/v1/app_users"
    existing = requests.get(f"{url}?name=eq.{requests.utils.quote(name)}&select=role&limit=1", headers=sb_headers())
    existing_rows = existing.json() if existing.ok else []
    if existing_rows:
        r = requests.patch(
            f"{url}?name=eq.{requests.utils.quote(name)}",
            headers={**sb_headers(), "Prefer": "return=representation"},
            json={"pin": pin}
        )
    else:
        r = requests.post(
            url,
            headers={**sb_headers(), "Prefer": "return=representation"},
            json={"name": name, "pin": pin, "role": "lead"}
        )
    if r.ok:
        return jsonify({"ok": True})
    return jsonify({"error": r.text}), 400

@app.route("/api/users/verify-pin", methods=["POST"])
def verify_pin():
    data = request.json or {}
    name = data.get("name", "")
    pin = str(data.get("pin", ""))
    url = f"{SUPABASE_URL}/rest/v1/app_users?name=eq.{requests.utils.quote(name)}&select=pin,role"
    r = requests.get(url, headers=sb_headers())
    rows = r.json() if r.ok else []
    if not rows:
        return jsonify({"ok": False, "error": "User not found"}), 404
    stored = rows[0].get("pin")
    role = rows[0].get("role", "lead")
    if stored and str(stored) == str(pin):
        return jsonify({"ok": True, "role": role})
    return jsonify({"ok": False, "error": "Incorrect PIN"})


UM_TABLE = "unit_materials"

@app.route("/api/unit-materials/<unit>", methods=["GET"])
def get_unit_materials(unit):
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{UM_TABLE}"
        f"?unit=eq.{requests.utils.quote(unit)}&order=date.asc,created_at.asc&limit=500",
        headers=sb_headers()
    )
    return jsonify(r.json() if r.ok else [])

@app.route("/api/unit-materials", methods=["POST"])
def add_unit_material():
    data = request.json or {}
    payload = {
        "unit":          data.get("unit", ""),
        "material":      data.get("material", ""),
        "qty_delivered": data.get("qty_delivered", 0),
        "qty_remaining": data.get("qty_remaining", 0),
        "unit_measure":  data.get("unit_measure", ""),
        "notes":         data.get("notes", ""),
        "date":          data.get("date", ""),
        "created_by":    data.get("created_by", ""),
    }
    r = requests.post(f"{SUPABASE_URL}/rest/v1/{UM_TABLE}",
                      headers=sb_headers(), json=payload)
    rows = r.json() if r.ok else []
    if rows:
        return jsonify({"ok": True, "item": rows[0]})
    return jsonify({"error": r.text}), 400

@app.route("/api/unit-materials/<item_id>", methods=["PATCH"])
def update_unit_material(item_id):
    data = request.json or {}
    allowed = ["material", "qty_delivered", "qty_remaining", "unit_measure", "notes", "date"]
    payload = {k: data[k] for k in allowed if k in data}
    if not payload:
        return jsonify({"error": "nothing to update"}), 400
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{UM_TABLE}?id=eq.{item_id}",
        headers=sb_headers(), json=payload
    )
    rows = r.json() if r.ok else []
    if rows:
        return jsonify({"ok": True, "item": rows[0]})
    return jsonify({"error": r.text}), 400

@app.route("/api/unit-materials/<item_id>", methods=["DELETE"])
def delete_unit_material(item_id):
    r = requests.delete(
        f"{SUPABASE_URL}/rest/v1/{UM_TABLE}?id=eq.{item_id}",
        headers=sb_headers()
    )
    return jsonify({"ok": r.ok})


# ── Project Units ─────────────────────────────────────────────────────────────
PU_TABLE = "project_units"

@app.route("/api/project-units", methods=["GET"])
def get_project_units():
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{PU_TABLE}?order=created_at.asc&limit=200",
        headers=sb_headers()
    )
    return jsonify(r.json() if r.ok else [])

@app.route("/api/project-units", methods=["POST"])
def create_project_unit():
    data = request.json or {}
    unit_name = data.get("unit_name", "").strip()
    if not unit_name:
        return jsonify({"error": "unit_name required"}), 400
    payload = {"unit_name": unit_name, "status": "active"}
    r = requests.post(f"{SUPABASE_URL}/rest/v1/{PU_TABLE}",
                      headers=sb_headers(), json=payload)
    rows = r.json() if r.ok else []
    if rows:
        return jsonify({"ok": True, "unit": rows[0]})
    return jsonify({"error": r.text}), 400

@app.route("/api/project-units/<unit_id>", methods=["PATCH"])
def update_project_unit(unit_id):
    data = request.json or {}
    allowed = ["status", "unit_name"]
    payload = {k: data[k] for k in allowed if k in data}
    if not payload:
        return jsonify({"error": "nothing to update"}), 400
    if payload.get("status") == "completed":
        payload["completed_at"] = datetime.utcnow().isoformat()
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{PU_TABLE}?id=eq.{unit_id}",
        headers=sb_headers(), json=payload
    )
    rows = r.json() if r.ok else []
    if rows:
        return jsonify({"ok": True, "unit": rows[0]})
    return jsonify({"error": r.text}), 400

@app.route("/api/project-units/<unit_id>", methods=["DELETE"])
def delete_project_unit(unit_id):
    r = requests.delete(
        f"{SUPABASE_URL}/rest/v1/{PU_TABLE}?id=eq.{unit_id}",
        headers=sb_headers()
    )
    return jsonify({"ok": r.ok})


# ═══════════════════════════════════════════════════════════════════
#  SETTINGS PAGE
# ═══════════════════════════════════════════════════════════════════

@app.route("/settings")
def settings_page():
    return render_template("settings.html")

# ── App Users CRUD ───────────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
def list_users():
    url = f"{SUPABASE_URL}/rest/v1/app_users?order=name.asc&select=name,role,pin,email,phone,led_by,company&limit=200"
    r = requests.get(url, headers=sb_headers(), timeout=8)
    rows = r.json() if r.ok else []
    # Mask pin
    for row in rows:
        row["has_pin"] = bool(row.get("pin"))
        row.pop("pin", None)
    return jsonify(rows)

@app.route("/api/team-members", methods=["GET"])
def get_team_members():
    """Returns workers (from app_users) whose led_by matches the given lead name."""
    lead = request.args.get("lead","").strip()
    if not lead:
        # Boss/admin: return all with led_by populated
        url = f"{SUPABASE_URL}/rest/v1/app_users?led_by=not.is.null&order=led_by.asc,name.asc&select=name,role,led_by&limit=200"
    else:
        url = (f"{SUPABASE_URL}/rest/v1/app_users"
               f"?led_by=eq.{requests.utils.quote(lead)}&order=name.asc&select=name,role,led_by&limit=200")
    r = requests.get(url, headers=sb_headers(), timeout=8)
    return jsonify(r.json() if r.ok else [])

@app.route("/api/users", methods=["POST"])
def create_user():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    role = data.get("role", "lead")
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400
    payload = {"name": name, "role": role,
               "email": data.get("email") or None,
               "phone": data.get("phone") or None,
               "company": data.get("company") or "MBR Texas"}
    if data.get("pin"):
        payload["pin"] = str(data["pin"])
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/app_users",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json=payload
    )
    if r.ok:
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": r.text}), 400

@app.route("/api/users/by-name/<path:name>", methods=["PATCH"])
def update_user_by_name(name):
    data = request.get_json() or {}
    payload = {}
    if "role"  in data: payload["role"]  = data["role"]
    if data.get("pin"):  payload["pin"]   = str(data["pin"])
    if "email" in data:  payload["email"] = data["email"] or None
    if "phone" in data:  payload["phone"] = data["phone"] or None
    if "led_by"  in data: payload["led_by"]  = data["led_by"] or None
    if "company" in data: payload["company"] = data["company"] or "MBR Texas"
    new_name = data.get("new_name", "").strip()
    if new_name:         payload["name"]  = new_name
    if not payload:
        return jsonify({"ok": False, "error": "nothing to update"}), 400
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/app_users?name=eq.{requests.utils.quote(name)}",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json=payload
    )
    # If name changed, sync to workers table too
    if r.ok and new_name:
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/workers?name=eq.{requests.utils.quote(name)}",
            headers={**sb_headers(), "Prefer": "return=representation"},
            json={"name": new_name}
        )
    return jsonify({"ok": r.ok, "error": r.text if not r.ok else None})

@app.route("/api/users/by-name/<path:name>", methods=["DELETE"])
def delete_user_by_name(name):
    r = requests.delete(
        f"{SUPABASE_URL}/rest/v1/app_users?name=eq.{requests.utils.quote(name)}",
        headers=sb_headers()
    )
    return jsonify({"ok": r.ok})

@app.route("/api/users/set-consent", methods=["POST"])
def set_consent():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400
    import datetime as dt
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/app_users?name=eq.{requests.utils.quote(name)}",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json={"consented_at": dt.datetime.utcnow().isoformat()}
    )
    return jsonify({"ok": r.ok})

# ── Workers CRUD by name ──────────────────────────────────────────
@app.route("/api/workers/all", methods=["GET"])
def get_all_workers():
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}"
        f"?order=name.asc&limit=200",
        headers=sb_headers()
    )
    return jsonify(r.json() if r.ok else [])

@app.route("/api/workers/by-name/<path:name>", methods=["PATCH"])
def update_worker_by_name(name):
    data = request.get_json() or {}
    allowed = ["role", "pin", "email", "phone"]
    payload = {k: data[k] for k in allowed if k in data}
    if not payload:
        return jsonify({"ok": False, "error": "nothing to update"}), 400
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?name=eq.{requests.utils.quote(name)}",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json=payload
    )
    return jsonify({"ok": r.ok, "error": r.text if not r.ok else None})

@app.route("/api/workers/by-name/<path:name>", methods=["DELETE"])
def delete_worker_by_name(name):
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?name=eq.{requests.utils.quote(name)}",
        headers=sb_headers(),
        json={"active": False}
    )
    return jsonify({"ok": r.ok})

# ── Contacts CRUD ─────────────────────────────────────────────────
CONTACTS_TABLE = "contacts"

@app.route("/api/contacts", methods=["GET"])
def list_contacts():
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{CONTACTS_TABLE}?order=name.asc&limit=200",
        headers=sb_headers()
    )
    return jsonify(r.json() if r.ok else [])

@app.route("/api/contacts", methods=["POST"])
def create_contact():
    data = request.get_json() or {}
    if not data.get("name", "").strip():
        return jsonify({"ok": False, "error": "name required"}), 400
    allowed = ["name", "company", "role", "phone", "email", "notes"]
    payload = {k: data[k] for k in allowed if k in data}
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/{CONTACTS_TABLE}",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json=payload
    )
    return jsonify({"ok": r.ok, "error": r.text if not r.ok else None})

@app.route("/api/contacts/<contact_id>", methods=["PATCH"])
def update_contact(contact_id):
    data = request.get_json() or {}
    allowed = ["name", "company", "role", "phone", "email", "notes"]
    payload = {k: data[k] for k in allowed if k in data}
    if not payload:
        return jsonify({"ok": False, "error": "nothing to update"}), 400
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{CONTACTS_TABLE}?id=eq.{contact_id}",
        headers={**sb_headers(), "Prefer": "return=representation"},
        json=payload
    )
    return jsonify({"ok": r.ok, "error": r.text if not r.ok else None})

@app.route("/api/contacts/<contact_id>", methods=["DELETE"])
def delete_contact(contact_id):
    r = requests.delete(
        f"{SUPABASE_URL}/rest/v1/{CONTACTS_TABLE}?id=eq.{contact_id}",
        headers=sb_headers()
    )
    return jsonify({"ok": r.ok})

# ── Hours / Checkins week view ────────────────────────────────────
@app.route("/api/checkins/week", methods=["GET"])
def checkins_week():
    """Return check-ins with calculated hours for date range."""
    import datetime as dt
    start = request.args.get("start", "")
    end   = request.args.get("end", "")
    url = (f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}"
           f"?select=id,worker_name,position,date,checked_in_at,checked_out_at"
           f"&order=date.asc,worker_name.asc&limit=5000")
    if start: url += f"&date=gte.{start}"
    if end:   url += f"&date=lte.{end}"
    r = requests.get(url, headers=sb_headers())
    rows = r.json() if r.ok else []
    result = []
    for row in rows:
        cin  = row.get("checked_in_at") or ""
        cout = row.get("checked_out_at") or ""
        hours = None
        if cin and cout:
            try:
                t1 = dt.datetime.fromisoformat(cin.split("+")[0].split("Z")[0])
                t2 = dt.datetime.fromisoformat(cout.split("+")[0].split("Z")[0])
                h = (t2 - t1).total_seconds() / 3600
                hours = round(h, 2) if 0 < h < 24 else None
            except Exception:
                pass
        result.append({
            "worker_name":    row.get("worker_name"),
            "position":       row.get("position") or "",
            "date":           row.get("date") or (cin[:10] if cin else ""),
            "checked_in_at":  cin,
            "checked_out_at": cout,
            "hours":          hours
        })
    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════
#  APP CONFIG (role permissions, etc.)
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/auto-checkout", methods=["POST"])
def auto_checkout():
    """6:15 PM daily job:
       1. Check out anyone still clocked in (logs 6:00 PM checkout).
       2. Mark as absent anyone with NO check-in record at all today.

    Handles late execution: if the job runs after midnight UTC, it also
    sweeps the previous calendar day so no open checkins are left unclosed.
    """
    import datetime as dt
    today = dt.date.today().isoformat()
    yesterday = (dt.date.today() - dt.timedelta(days=1)).isoformat()

    # ── 1. Auto-checkout open check-ins (today AND yesterday) ────────────────
    checked_out = 0
    for target_date in [yesterday, today]:
        checkout_time = target_date + "T23:00:00"
        co = requests.patch(
            f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}"
            f"?date=eq.{target_date}&checked_out_at=is.null",
            json={"checked_out_at": checkout_time, "auto_checkout": True},
            headers={**sb_headers(), "Prefer": "return=representation"}
        )
        if co.ok and co.json():
            checked_out += len(co.json())

    # ── 2. Mark absent — workers with zero check-ins today ───────────────────
    # Get all active workers
    wr = requests.get(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?active=eq.true&select=name&limit=500",
        headers=sb_headers()
    )
    all_workers = [w["name"] for w in (wr.json() if wr.ok else []) if w.get("name")]

    # Get all workers who had ANY check-in today
    cr = requests.get(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}?date=eq.{today}&select=worker_name&limit=500",
        headers=sb_headers()
    )
    checked_in_names = set(r["worker_name"] for r in (cr.json() if cr.ok else []) if r.get("worker_name"))

    # Also check who already has an attendance record for today (don't double-mark)
    ar = requests.get(
        f"{SUPABASE_URL}/rest/v1/attendance_reports?report_date=eq.{today}&select=worker_name&limit=500",
        headers=sb_headers()
    )
    already_attendance = set(r["worker_name"] for r in (ar.json() if ar.ok else []) if r.get("worker_name"))

    absent_names = []
    for name in all_workers:
        if name not in checked_in_names and name not in already_attendance:
            # Create absent record automatically
            requests.post(
                f"{SUPABASE_URL}/rest/v1/attendance_reports",
                json={"worker_name": name, "type": "absent",
                      "reason": "Auto-marked: no check-in recorded for this day.",
                      "report_date": today},
                headers={**sb_headers(), "Prefer": "return=representation"}
            )
            absent_names.append(name)

    return jsonify({
        "ok": True,
        "auto_checked_out": checked_out,
        "auto_marked_absent": len(absent_names),
        "absent_workers": absent_names
    })

@app.route("/api/checkin/by-pin", methods=["POST"])
def checkin_by_pin():
    if not kiosk_allowed():
        return jsonify({"ok": False, "error": "Unauthorized IP"}), 403
    """Look up worker by 4-digit PIN and check them in or out."""
    import datetime as dt
    data = request.get_json() or {}
    pin = str(data.get("pin","")).strip().zfill(4)
    if len(pin) != 4 or not pin.isdigit():
        return jsonify({"ok": False, "error": "Invalid PIN"}), 400

    # Find worker with this PIN — look in app_users first, fall back to workers table
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_users?pin=eq.{pin}&approved=eq.true&select=name&limit=1",
        headers=sb_headers()
    )
    rows = r.json() if r.ok else []
    if not rows:
        # Fallback: legacy pins stored in workers table
        r2 = requests.get(
            f"{SUPABASE_URL}/rest/v1/workers?pin=eq.{pin}&select=name&limit=1",
            headers=sb_headers()
        )
        rows = r2.json() if r2.ok else []
    if not rows:
        return jsonify({"ok": False, "error": "PIN not found"}), 404

    worker_name = rows[0].get("name","")
    today = dt.date.today().isoformat()

    # Check if currently checked in
    active = requests.get(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}"
        f"?worker_name=eq.{requests.utils.quote(worker_name)}"
        f"&date=eq.{today}&checked_out_at=is.null&select=id,position,checked_in_at&limit=1",
        headers=sb_headers()
    )
    active_rows = active.json() if active.ok else []

    if active_rows:
        # Check OUT
        checkin_id = active_rows[0]["id"]
        co = requests.patch(
            f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}?id=eq.{checkin_id}",
            json={"checked_out_at": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")},
            headers={**sb_headers(), "Prefer": "return=representation"}
        )
        return jsonify({"ok": co.ok, "action": "checkout", "worker_name": worker_name,
                        "position": active_rows[0].get("position",""),
                        "checked_in_at": active_rows[0].get("checked_in_at","")})
    else:
        # Check IN (late arrival via tablet)
        now_iso = dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        ci = requests.post(
            f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}",
            json={"worker_name": worker_name, "position": "Late Arrival",
                  "date": today, "checked_in_at": now_iso, "source": "tablet"},
            headers={**sb_headers(), "Prefer": "return=representation"}
        )
        return jsonify({"ok": ci.ok, "action": "checkin", "worker_name": worker_name})



@app.route("/api/workers/no-pin", methods=["GET"])
def workers_no_pin():
    """Kiosk: list of active workers without a PIN (for self-registration)."""
    if not kiosk_allowed():
        return jsonify({"ok": False, "error": "Unauthorized IP"}), 403
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?pin=is.null&active=eq.true"
        f"&select=id,name&order=name.asc&limit=200",
        headers=sb_headers()
    )
    rows = r.json() if r.ok else []
    return jsonify([{"id": w["id"], "name": w["name"]} for w in rows if w.get("name")])

@app.route("/api/workers/<worker_id>/set-kiosk-pin", methods=["POST"])
def set_kiosk_pin(worker_id):
    """Kiosk: assign a PIN to a worker who does not have one yet."""
    if not kiosk_allowed():
        return jsonify({"ok": False, "error": "Unauthorized IP"}), 403
    data = request.get_json() or {}
    pin = str(data.get("pin", "")).strip()
    if len(pin) != 4 or not pin.isdigit():
        return jsonify({"ok": False, "error": "PIN must be 4 digits"}), 400
    # Uniqueness check
    check = requests.get(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?pin=eq.{pin}&select=id&limit=1",
        headers=sb_headers()
    )
    if check.ok and check.json():
        return jsonify({"ok": False, "error": "PIN already taken — choose another"}), 409
    # Save PIN
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?id=eq.{worker_id}",
        json={"pin": pin},
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    if not r.ok:
        return jsonify({"ok": False, "error": "Failed to save PIN"}), 500
    return jsonify({"ok": True})

@app.route("/api/contractor/profile", methods=["GET"])
def get_contractor_profile():
    """Get a user's company from app_users (works for all roles)."""
    name = request.args.get("name","").strip()
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_users"
        f"?name=eq.{requests.utils.quote(name)}&select=name,pin,company&limit=1",
        headers=sb_headers()
    )
    rows = r.json() if r.ok else []
    if not rows:
        return jsonify({"ok": False, "error": "user not found"}), 404
    u = rows[0]
    return jsonify({"ok": True, "name": u["name"],
                    "pin_set": bool(u.get("pin")),
                    "contractor_company": u.get("company") or "MBR Texas"})

@app.route("/api/contractor/profile", methods=["PATCH"])
def update_contractor_profile():
    """Update contractor's company name in app_users."""
    data = request.json or {}
    name = data.get("name", "").strip()
    company = data.get("contractor_company", "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/app_users?name=eq.{requests.utils.quote(name)}",
        headers={**sb_headers(), "Prefer": "return=minimal"},
        json={"company": company}
    )
    return jsonify({"ok": r.ok})

@app.route("/api/contractor/pin", methods=["PATCH"])
def update_contractor_pin():
    """Worker changes their own PIN. First-time: old_pin may be blank if pin is null."""
    import datetime as dt
    data = request.get_json() or {}
    name     = data.get("name","").strip()
    old_pin  = str(data.get("old_pin","")).strip()
    new_pin  = str(data.get("new_pin","")).strip()

    if not name or not new_pin:
        return jsonify({"ok": False, "error": "name and new_pin required"}), 400
    if not new_pin.isdigit() or len(new_pin) != 4:
        return jsonify({"ok": False, "error": "PIN must be 4 digits"}), 400

    # Get current PIN
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}"
        f"?name=eq.{requests.utils.quote(name)}&select=id,pin&limit=1",
        headers=sb_headers()
    )
    rows = r.json() if r.ok else []
    if not rows:
        return jsonify({"ok": False, "error": "worker not found"}), 404

    current_pin = rows[0].get("pin") or ""
    worker_id   = rows[0]["id"]

    # Validate old PIN — skip if this is first-time setup (current_pin is null/empty)
    if current_pin and old_pin != current_pin:
        return jsonify({"ok": False, "error": "Current PIN is incorrect"}), 403

    # Check new PIN is not already taken by someone else
    dup = requests.get(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}"
        f"?pin=eq.{new_pin}&id=neq.{worker_id}&select=id&limit=1",
        headers=sb_headers()
    )
    if dup.ok and dup.json():
        return jsonify({"ok": False, "error": "That PIN is already in use. Choose another."}), 409

    # Save new PIN
    pr = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?id=eq.{worker_id}",
        json={"pin": new_pin},
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    return jsonify({"ok": pr.ok})

@app.route("/api/contractor/name", methods=["PATCH"])
def update_contractor_name():
    """Worker updates their display name."""
    data = request.get_json() or {}
    old_name = data.get("old_name","").strip()
    new_name = data.get("new_name","").strip()
    if not old_name or not new_name:
        return jsonify({"ok": False, "error": "old_name and new_name required"}), 400
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?name=eq.{requests.utils.quote(old_name)}",
        json={"name": new_name},
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    if r.ok:
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": r.text}), 400

@app.route("/tablet")
def tablet_page():
    """Tablet check-in/out kiosk — restricted to job site IP, or admin pass."""
    admin_pass = request.args.get("pass", "")
    if not kiosk_allowed() and admin_pass != KIOSK_PASS:
        ip = get_client_ip()
        return f"""<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;gap:16px;text-align:center;padding:24px;}}
h1{{font-size:28px;color:#ef4444;}}p{{color:#94a3b8;font-size:14px;max-width:340px;}}
form{{display:flex;flex-direction:column;gap:10px;margin-top:16px;}}
input{{background:#1e293b;border:1px solid #334155;border-radius:8px;color:#e2e8f0;padding:10px 14px;font-size:15px;text-align:center;}}
button{{background:#3b82f6;color:#fff;border:none;border-radius:8px;padding:10px 18px;font-size:14px;font-weight:700;cursor:pointer;}}
</style></head>
<body><h1>🔒 Access Restricted</h1>
<p>This kiosk is only accessible from the authorized job site network.</p>
<p style="font-size:12px;color:#475569;">Your IP: {ip}</p>
<form method="get" action="/tablet">
  <input type="password" name="pass" placeholder="Admin access code" autocomplete="off">
  <button type="submit">Unlock</button>
</form>
</body></html>""", 403
    # Mark session as bypass-authorized so API calls (by-pin, etc.) also pass kiosk_allowed()
    session['kiosk_bypass'] = True
    return render_template("tablet.html")

@app.route("/api/config/<key>", methods=["GET"])
def get_config(key):
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_config?key=eq.{requests.utils.quote(key)}&select=value&limit=1",
        headers=sb_headers()
    )
    rows = r.json() if r.ok else []
    if rows:
        return jsonify({"ok": True, "value": rows[0].get("value")})
    return jsonify({"ok": False, "value": None})

@app.route("/api/config/<key>", methods=["POST"])
def set_config(key):
    data = request.get_json() or {}
    value = data.get("value")
    import datetime as dt
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/app_config",
        headers={**sb_headers(), "Prefer": "resolution=merge-duplicates,return=representation"},
        json={"key": key, "value": value, "updated_at": dt.datetime.utcnow().isoformat()}
    )
    return jsonify({"ok": r.ok, "error": r.text if not r.ok else None})

# ── Cleanup inactive workers ──────────────────────────────────────
@app.route("/api/workers/inactive", methods=["DELETE"])
def delete_inactive_workers():
    r = requests.delete(
        f"{SUPABASE_URL}/rest/v1/{WORKERS_TABLE}?active=eq.false",
        headers=sb_headers()
    )
    return jsonify({"ok": r.ok, "error": r.text if not r.ok else None})

# ═══════════════════════════════════════════════════════════════════
#  UNIT SENT — archive + download
# ═══════════════════════════════════════════════════════════════════
SENT_TABLE = "sent_units"

@app.route("/api/unit-sent/<position>", methods=["POST"])
def mark_unit_sent(position):
    import io, csv
    from datetime import date as _dt_date, datetime, timezone, timedelta
    from flask import send_file
    data = request.json or {}
    editor     = data.get("editor", "Unknown")
    tdg_number = data.get("tdg_number", "")
    mbr_number = data.get("mbr_number", "")
    mbr_skid   = data.get("mbr_skid", "")
    fase       = data.get("fase", "")
    building   = data.get("building_no", "")

    # 1. Fetch all daily_log records for this position
    logs_resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{TABLE}?position=eq.{position}"
        f"&order=created_at.asc&limit=100000",
        headers=sb_headers()
    )
    logs = logs_resp.json() if logs_resp.ok else []

    # 2. Compute latest overall progress (reuse all-progress logic)
    latest = {}
    for r in sorted(logs, key=lambda x: x.get("created_at",""), reverse=True):
        ap  = r.get("area_phase","")
        key = ap
        if key not in latest and r.get("progress_pct") is not None:
            latest[key] = r["progress_pct"]
    MAINS = ["1. Structure","2. Structure Paint","3. Envelope","4. Unit Paint",
             "5. Internal Systems Rough-In","6. Electrical","7. Final QC","8. Final Touchups"]
    CATONLY = ["2. Structure Paint","3. Envelope","4. Unit Paint",
               "6. Electrical","7. Final QC","8. Final Touchups"]
    KNOWN_STR = ["C Channel / Holes Templates","Weld 4 I Beams (10\" I Beams)",
                 "C Channels 12\" Weld To Enclose Frame","Square The Frame",
                 "Inside C Channels/Square","Nuts Inside C Channel",
                 "Floor Plate (Pull, Cut, Weld)","Square Tube Halo (Pull, Cut, Grind, Weld)",
                 "I Beam On Halo Stand Up Posts","Square Halo And Weld To Post",
                 "Square Tubes For Doors","Ground Plates","Weld Floor Plates Together"]
    def quick_pct(trade):
        if trade in CATONLY:
            return latest.get(trade)
        if trade == "1. Structure":
            s, has = 0, False
            for a in KNOWN_STR:
                v = latest.get(f"1. Structure > {a}")
                if v is not None: s += v; has = True
            return round(s/13,4) if has else None
        return None
    trade_pcts = {t: quick_pct(t) for t in MAINS}
    sum8 = sum(v or 0.0 for v in trade_pcts.values())
    overall = round(sum8/8, 4)

    # 3. Save snapshot to sent_units table
    snapshot = {
        "trade_pcts": {k: v for k,v in trade_pcts.items()},
        "log_count": len(logs)
    }
    sent_payload = {
        "position": position,
        "tdg_number": tdg_number,
        "mbr_number": mbr_number,
        "mbr_skid": mbr_skid,
        "fase": fase,
        "building_no": building,
        "sent_date": _dt_date.today().isoformat(),
        "sent_by": editor,
        "overall_pct": overall,
        "log_count": len(logs),
        "snapshot_json": snapshot
    }
    requests.post(
        f"{SUPABASE_URL}/rest/v1/{SENT_TABLE}",
        headers={**sb_headers(), "Prefer": "return=minimal"},
        json=sent_payload
    )

    # 4. Delete all daily_log records for this position
    requests.delete(
        f"{SUPABASE_URL}/rest/v1/{TABLE}?position=eq.{position}",
        headers=sb_headers()
    )

    # 5. Generate CSV report for download
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["UNIT SENT REPORT"])
    w.writerow(["Position", position])
    w.writerow(["TDG No", tdg_number])
    w.writerow(["MBR No", mbr_number])
    w.writerow(["MBR Skid", mbr_skid])
    w.writerow(["Fase", fase])
    w.writerow(["Building", building])
    w.writerow(["Date Sent", _dt_date.today().isoformat()])
    w.writerow(["Sent By", editor])
    w.writerow(["Overall Progress", f"{round(overall*100)}%"])
    w.writerow([])
    w.writerow(["TRADE", "PROGRESS"])
    for t, v in trade_pcts.items():
        w.writerow([t, f"{round((v or 0)*100)}%"])
    w.writerow([])
    w.writerow(["Total log records archived", len(logs)])

    fname = f"{position}_sent_{_dt_date.today().isoformat()}.csv"
    buf.seek(0)
    return send_file(
        io.BytesIO(buf.getvalue().encode("utf-8-sig")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=fname
    )

@app.route("/api/sent-units", methods=["GET"])
def get_sent_units():
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{SENT_TABLE}"
        f"?select=id,position,tdg_number,mbr_number,sent_date,sent_by,overall_pct,log_count"
        f"&order=sent_date.desc&limit=200",
        headers=sb_headers()
    )
    return jsonify(r.json() if r.ok else [])



# -- Safety Meeting: bulk check-in
@app.route("/api/safety-meeting/bulk-checkin", methods=["POST"])
def safety_meeting_bulk_checkin():
    data = request.get_json() or {}
    workers   = data.get("workers", [])
    time_val  = data.get("time", "")      # "HH:MM" CDT from client
    supervisor = data.get("supervisor", "")
    if not workers:
        return jsonify({"ok": False, "error": "No workers"}), 400

    today = date.today().isoformat()

    # Convert HH:MM CDT → UTC ISO
    if time_val and ":" in time_val:
        try:
            h, m = map(int, time_val.split(":"))
            y, mo, d_ = int(today[:4]), int(today[5:7]), int(today[8:])
            local_dt = datetime(y, mo, d_, h, m, 0, tzinfo=timezone(timedelta(hours=-5)))
            now_iso = local_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z"
        except Exception:
            now_iso = datetime.utcnow().isoformat() + "Z"
    else:
        now_iso = datetime.utcnow().isoformat() + "Z"

    # Already in safety meeting today
    r_sm = requests.get(f"{SUPABASE_URL}/rest/v1/{SM_TABLE}?date=eq.{today}&select=worker_name", headers=sb_headers())
    already_sm = {r["worker_name"] for r in (r_sm.json() if r_sm.ok and isinstance(r_sm.json(), list) else [])}

    # Already checked in via checkins table
    r_ci = requests.get(f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}?date=eq.{today}&checked_out_at=is.null&select=worker_name", headers=sb_headers())
    already_ci = {r["worker_name"] for r in (r_ci.json() if r_ci.ok and isinstance(r_ci.json(), list) else [])}

    # Has attendance record today (skip these)
    r_att = requests.get(f"{SUPABASE_URL}/rest/v1/attendance_reports?report_date=eq.{today}&select=worker_name", headers=sb_headers())
    has_att = {r["worker_name"] for r in (r_att.json() if r_att.ok and isinstance(r_att.json(), list) else [])}

    checked_in, skipped = 0, 0
    for name in workers:
        if not name: continue
        if name in already_sm or name in already_ci:
            skipped += 1; continue
        if name in has_att:
            skipped += 1; continue
        # Insert safety_meeting record
        requests.post(f"{SUPABASE_URL}/rest/v1/{SM_TABLE}",
            json={"worker_name": name, "supervisor": supervisor, "date": today, "checked_in_at": now_iso},
            headers={**sb_headers(), "Prefer": "return=minimal"})
        # Insert checkins record
        requests.post(f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}",
            json={"worker_name": name, "position": "Safety Meeting", "date": today, "checked_in_at": now_iso},
            headers={**sb_headers(), "Prefer": "return=minimal"})
        checked_in += 1

    return jsonify({"ok": True, "checked_in": checked_in, "skipped": skipped})

# -- Contractor: today check-in status
@app.route("/api/contractor/status", methods=["GET"])
def contractor_status():
    name = request.args.get("name","").strip()
    if not name: return jsonify({"ok":False}), 400
    today = date.today().isoformat()
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}"
        f"?worker_name=eq.{requests.utils.quote(name)}&date=eq.{today}"
        f"&checked_out_at=is.null&select=id,checked_in_at&limit=1",
        headers=sb_headers(), timeout=5
    )
    rows = r.json() if r.ok else []
    if rows:
        ci = rows[0].get("checked_in_at","")
        return jsonify({"ok":True,"checked_in":True,"since":utc_to_cdt(ci)})
    # Fallback: check safety_meetings table (covers day safety meeting attended but checkins INSERT failed)
    sm = requests.get(
        f"{SUPABASE_URL}/rest/v1/{SM_TABLE}"
        f"?worker_name=eq.{requests.utils.quote(name)}&date=eq.{today}"
        f"&select=id,checked_in_at&limit=1",
        headers=sb_headers(), timeout=5
    )
    sm_rows = sm.json() if sm.ok else []
    if sm_rows:
        ci = sm_rows[0].get("checked_in_at","")
        return jsonify({"ok":True,"checked_in":True,"since":utc_to_cdt(ci)})
    return jsonify({"ok":True,"checked_in":False})

# -- Notifications
@app.route("/api/notifications", methods=["GET","POST"])
def notifications():
    if request.method == "POST":
        data = request.get_json() or {}
        r = requests.post(
            f"{SUPABASE_URL}/rest/v1/notifications",
            json={"title":data.get("title","").strip(),
                  "body":data.get("body","").strip(),
                  "target":data.get("target","all"),
                  "created_by":data.get("created_by","")},
            headers={**sb_headers(),"Prefer":"return=representation"}
        )
        return jsonify({"ok":r.ok})
    name = request.args.get("name","").strip()
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/notifications?order=created_at.desc&limit=20",
        headers=sb_headers(), timeout=5
    )
    notifs = r.json() if r.ok else []
    read_ids = set()
    if name:
        r2 = requests.get(
            f"{SUPABASE_URL}/rest/v1/notification_reads"
            f"?worker_name=eq.{requests.utils.quote(name)}&select=notification_id",
            headers=sb_headers(), timeout=5
        )
        if r2.ok:
            read_ids = {x["notification_id"] for x in r2.json()}
    for n in notifs:
        n["read"] = str(n["id"]) in read_ids
    return jsonify({"ok":True,"notifications":notifs})

@app.route("/api/notifications/<nid>/read", methods=["POST"])
def mark_notification_read(nid):
    name = (request.get_json() or {}).get("name","").strip()
    if not name: return jsonify({"ok":False}),400
    requests.post(
        f"{SUPABASE_URL}/rest/v1/notification_reads",
        json={"notification_id":nid,"worker_name":name},
        headers={**sb_headers(),"Prefer":"return=minimal,resolution=ignore-duplicates"}
    )
    return jsonify({"ok":True})


# ── Contractor: hours by week ─────────────────────────────────────────────────
@app.route("/api/notifications/admin", methods=["GET"])
def notifications_admin():
    """Admin/Boss: full notification list with per-notification read counts (batched)."""
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/notifications?order=created_at.desc&limit=200",
        headers=sb_headers(), timeout=8
    )
    if not r.ok:
        return jsonify({"ok": False, "notifications": [], "error": r.text}), 500
    notifs = r.json() if r.ok else []
    if not notifs:
        return jsonify({"ok": True, "notifications": []})
    # Batch: fetch ALL reads in one query
    ids = [str(n["id"]) for n in notifs]
    id_filter = "(" + ",".join(ids) + ")"
    r2 = requests.get(
        f"{SUPABASE_URL}/rest/v1/notification_reads"
        f"?notification_id=in.{id_filter}&select=notification_id",
        headers=sb_headers(), timeout=8
    )
    read_counts = {}
    if r2.ok:
        for row in r2.json():
            nid = str(row["notification_id"])
            read_counts[nid] = read_counts.get(nid, 0) + 1
    for n in notifs:
        n["read_count"] = read_counts.get(str(n["id"]), 0)
    return jsonify({"ok": True, "notifications": notifs})

@app.route("/api/notifications/<nid>", methods=["PATCH","DELETE"])
def notification_manage(nid):
    if request.method == "PATCH":
        data = request.get_json() or {}
        payload = {}
        if "title" in data: payload["title"] = str(data["title"]).strip()
        if "body"  in data: payload["body"]  = str(data["body"]).strip()
        if "target" in data: payload["target"] = str(data["target"])
        if not payload: return jsonify({"ok": False, "error": "nothing to update"}), 400
        r = requests.patch(
            f"{SUPABASE_URL}/rest/v1/notifications?id=eq.{nid}",
            json=payload,
            headers={**sb_headers(), "Prefer": "return=minimal"}
        )
        return jsonify({"ok": r.ok})
    else:  # DELETE
        requests.delete(
            f"{SUPABASE_URL}/rest/v1/notification_reads?notification_id=eq.{nid}",
            headers=sb_headers(), timeout=5
        )
        r = requests.delete(
            f"{SUPABASE_URL}/rest/v1/notifications?id=eq.{nid}",
            headers=sb_headers(), timeout=5
        )
        return jsonify({"ok": r.ok})

@app.route("/api/contractor/hours", methods=["GET"])
def contractor_hours():
    name       = request.args.get("name","").strip()
    week_start = request.args.get("week_start","")  # YYYY-MM-DD (Monday)
    if not name or not week_start:
        return jsonify({"error":"name and week_start required"}),400
    try:
        from datetime import date, datetime, timezone, timedelta, timedelta, datetime
        ws = date.fromisoformat(week_start)
        we = ws + timedelta(days=6)
    except:
        return jsonify({"error":"invalid week_start"}),400

    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/{CHECKINS_TABLE}"
        f"?worker_name=eq.{requests.utils.quote(name)}"
        f"&date=gte.{ws.isoformat()}&date=lte.{we.isoformat()}"
        f"&select=date,checked_in_at,checked_out_at,auto_checkout"
        f"&order=date.asc",
        headers=sb_headers(), timeout=8
    )
    rows = r.json() if r.ok else []
    days = []
    total_mins = 0
    for row in rows:
        ci = row.get("checked_in_at")
        co = row.get("checked_out_at")
        hrs = None
        if ci and co:
            try:
                from datetime import date, datetime, timezone
                fmt = "%Y-%m-%dT%H:%M:%S"
                ci_dt = datetime.fromisoformat(ci[:19])
                co_dt = datetime.fromisoformat(co[:19])
                mins = max(0, int((co_dt - ci_dt).total_seconds() / 60))
                hrs = round(mins / 60, 2)
                total_mins += mins
            except:
                pass
        days.append({
            "date": row["date"],
            "checked_in":  ci[11:16] if ci else None,
            "checked_out": co[11:16] if co else None,
            "hours": hrs,
            "auto_checkout": row.get("auto_checkout", False)
        })
    return jsonify({
        "ok": True,
        "week_start": ws.isoformat(),
        "week_end":   we.isoformat(),
        "total_hours": round(total_mins / 60, 2),
        "days": days
    })

# ── Contractor: change own password ──────────────────────────────────────────
@app.route("/api/contractor/password", methods=["PATCH"])
def contractor_change_password():
    data = request.get_json() or {}
    name     = data.get("name","").strip()
    curr_pw  = data.get("current_password","").strip()
    new_pw   = data.get("new_password","").strip()
    if not all([name, curr_pw, new_pw]):
        return jsonify({"error":"All fields required"}),400
    if len(new_pw) < 4:
        return jsonify({"error":"Password must be at least 4 characters"}),400
    # Verify current password
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_users?name=eq.{requests.utils.quote(name)}&select=password&limit=1",
        headers=sb_headers(), timeout=5
    )
    users = r.json() if r.ok else []
    if not users:
        return jsonify({"error":"User not found"}),404
    if users[0].get("password","") != curr_pw:
        return jsonify({"error":"Current password incorrect"}),403
    # Update password
    r2 = requests.patch(
        f"{SUPABASE_URL}/rest/v1/app_users?name=eq.{requests.utils.quote(name)}",
        json={"password": new_pw},
        headers={**sb_headers(), "Prefer":"return=representation"}
    )
    return jsonify({"ok": r2.ok})

# ── Contractor: reset own PIN ─────────────────────────────────────────────────
@app.route("/api/contractor/reset-pin", methods=["POST"])
def contractor_reset_own_pin():
    data = request.get_json() or {}
    name = data.get("name","").strip()
    if not name:
        return jsonify({"error":"name required"}),400
    # Find worker id by name
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/workers?name=eq.{requests.utils.quote(name)}&select=id&limit=1",
        headers=sb_headers(), timeout=5
    )
    workers = r.json() if r.ok else []
    if not workers:
        return jsonify({"error":"Worker not found"}),404
    wid = workers[0]["id"]
    r2 = requests.patch(
        f"{SUPABASE_URL}/rest/v1/workers?id=eq.{wid}",
        json={"pin": None},
        headers={**sb_headers(), "Prefer":"return=representation"}
    )
    return jsonify({"ok": r2.ok})

# ── Reset worker PIN (Admin) ──────────────────────────────────────────────────
@app.route("/api/workers/<worker_id>/reset-pin", methods=["POST"])
def reset_worker_pin(worker_id):
    r = requests.patch(
        f"{SUPABASE_URL}/rest/v1/workers?id=eq.{worker_id}",
        json={"pin": None},
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    return jsonify({"ok": r.ok})

# ── Session version (for force-logout) ───────────────────────────────────────
@app.route("/api/session-version", methods=["GET"])
def get_session_version():
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/app_settings?key=eq.session_version&select=value&limit=1",
        headers=sb_headers(), timeout=5
    )
    data = r.json() if r.ok else []
    version = data[0]["value"] if data else "1"
    return jsonify({"version": version})

# ── Force logout all sessions (Admin) ────────────────────────────────────────
@app.route("/api/admin/force-logout", methods=["POST"])
def force_logout_all():
    data = request.get_json() or {}
    caller = data.get("caller_name", "").strip()
    if not _verify_caller_is_admin(caller):
        return jsonify({"error": "Admin access required"}), 403
    import time
    new_ver = str(int(time.time()))
    requests.patch(
        f"{SUPABASE_URL}/rest/v1/app_settings?key=eq.session_version",
        json={"value": new_ver},
        headers={**sb_headers(), "Prefer": "return=representation"}
    )
    return jsonify({"ok": True, "version": new_ver})

# ── Worker location: update current unit ─────────────────────────────────────
@app.route("/api/worker/location", methods=["POST"])
def update_worker_location():
    data = request.get_json() or {}
    name = data.get("name","").strip()
    unit = data.get("unit","").strip().upper()
    if not name or not unit:
        return jsonify({"error":"name and unit required"}),400
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    # Upsert current location
    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/worker_locations?on_conflict=worker_name",
        json={"worker_name": name, "unit": unit, "updated_at": now_iso},
        headers={**sb_headers(), "Prefer": "resolution=merge-duplicates,return=representation"},
        timeout=5
    )
    if not r.ok:
        return jsonify({"ok": False, "error": r.text}), 200
    # Log to history
    requests.post(
        f"{SUPABASE_URL}/rest/v1/worker_location_history",
        json={"worker_name": name, "unit": unit, "recorded_at": now_iso},
        headers={**sb_headers(), "Prefer": "return=minimal"},
        timeout=5
    )
    return jsonify({"ok": True, "unit": unit})

# ── Worker locations: get all current (Boss/Admin) ───────────────────────────
@app.route("/api/worker/locations", methods=["GET"])
def get_worker_locations():
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/worker_locations?select=worker_name,unit,updated_at&order=unit.asc",
        headers=sb_headers(), timeout=5
    )
    return jsonify(r.json() if r.ok else [])

# ── Location page (QR scan target) ───────────────────────────────────────────
@app.route("/location")
def location_page():
    unit = request.args.get("unit","").upper()
    return render_template("location.html", unit=unit)

# ── Section B live map ────────────────────────────────────────────────────────
@app.route("/sectionb")
def section_b_map():
    return render_template("sectionb.html")

# ── Location history PDF — standalone builder (usable without HTTP) ─────────
def build_location_pdf(target_date=None):
    """Build and return a BytesIO PDF for the given date (defaults to today).
    Called by the HTTP route AND by the nightly APScheduler job.
    """
    from datetime import datetime, timezone, date as dt_date
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.lib.colors import HexColor, white, black
    from reportlab.lib.units import inch
    import io as _io

    if target_date is None:
        target_date = dt_date.today().isoformat()

    # Fetch history for the date
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/worker_location_history"
        f"?recorded_at=gte.{target_date}T00:00:00Z"
        f"&recorded_at=lt.{target_date}T23:59:59Z"
        f"&select=worker_name,unit,recorded_at&order=recorded_at.asc",
        headers=sb_headers(), timeout=10
    )
    rows = r.json() if r.ok else []

    # Build PDF
    buf = _io.BytesIO()
    PAGE_W, PAGE_H = letter
    NAVY  = HexColor("#0c1f3a")
    TEAL  = HexColor("#1abc9c")
    LGRAY = HexColor("#94a3b8")
    DGRAY = HexColor("#334155")

    c = rl_canvas.Canvas(buf, pagesize=letter)
    MARGIN = 0.65 * inch

    def new_page():
        c.showPage()
        return PAGE_H - MARGIN

    # Header
    c.setFillColor(NAVY)
    c.rect(0, PAGE_H - 60, PAGE_W, 60, fill=1, stroke=0)
    c.setFillColor(TEAL)
    c.rect(0, PAGE_H - 64, PAGE_W, 4, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(MARGIN, PAGE_H - 38, "MBR Texas — Location Movement Report")
    c.setFont("Helvetica", 10)
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 38, f"Date: {target_date}")
    c.setFillColor(LGRAY)
    c.setFont("Helvetica", 9)
    c.drawString(MARGIN, PAGE_H - 54, f"TDG Data Center Project · Katy, TX  ·  Total movements: {len(rows)}")

    y = PAGE_H - 80

    # Summary by worker
    summary = {}
    for row in rows:
        wn = row.get("worker_name","")
        if wn not in summary:
            summary[wn] = []
        summary[wn].append(row)

    # Column headers
    def draw_col_headers(y_pos):
        c.setFillColor(DGRAY)
        c.rect(MARGIN, y_pos - 18, PAGE_W - 2*MARGIN, 18, fill=1, stroke=0)
        c.setFillColor(white)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(MARGIN + 6,  y_pos - 12, "WORKER")
        c.drawString(MARGIN + 200, y_pos - 12, "UNIT")
        c.drawString(MARGIN + 310, y_pos - 12, "TIME (CT)")
        return y_pos - 22

    y = draw_col_headers(y)

    alt = False
    for row in rows:
        if y < MARGIN + 40:
            y = new_page()
            y -= 10
            y = draw_col_headers(y)

        ts = row.get("recorded_at","")
        try:
            from datetime import date, datetime, timezone
            dt_utc = datetime.fromisoformat(ts.replace("Z","+00:00"))
            dt_ct  = dt_utc.replace(tzinfo=None)
            time_str = dt_ct.strftime("%I:%M:%S %p")
        except:
            time_str = ts[11:19] if len(ts) > 18 else ts

        if alt:
            c.setFillColor(HexColor("#f8fafc"))
            c.rect(MARGIN, y - 14, PAGE_W - 2*MARGIN, 18, fill=1, stroke=0)
        alt = not alt

        c.setFillColor(DGRAY)
        c.setFont("Helvetica", 9)
        c.drawString(MARGIN + 6,   y - 8, row.get("worker_name",""))
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(HexColor("#0c1f3a"))
        c.drawString(MARGIN + 200, y - 8, row.get("unit",""))
        c.setFont("Helvetica", 9)
        c.setFillColor(DGRAY)
        c.drawString(MARGIN + 310, y - 8, time_str)
        y -= 18

    # Footer
    c.setFillColor(LGRAY)
    c.setFont("Helvetica", 8)
    c.drawCentredString(PAGE_W/2, MARGIN/2,
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC  ·  MBR Texas / TDG Data Center")

    c.save()
    buf.seek(0)
    return buf, target_date, len(rows)


# ── Location history PDF route ───────────────────────────────────────────────
@app.route("/api/reports/location-history")
def location_history_pdf():
    # Auth: accept CRON_SECRET (machine) OR verified admin name (?admin=name)
    cron_provided = request.headers.get("X-Admin-Secret", "") or request.args.get("key", "")
    if cron_provided:
        if not CRON_SECRET or cron_provided != CRON_SECRET:
            from flask import abort
            abort(403)
    else:
        admin_name = request.args.get("admin", "").strip()
        if not _verify_caller_is_admin(admin_name):
            from flask import abort
            abort(403)

    from datetime import date as dt_date
    target_date = request.args.get("date", dt_date.today().isoformat())
    buf, target_date, _ = build_location_pdf(target_date)
    from flask import send_file
    return send_file(
        buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"Location_Report_{target_date}.pdf"
    )

# ── Reset worker locations (Admin/Boss, or scheduled) ────────────────────────
def _do_reset_locations():
    """Direct Python call — no auth check, used by APScheduler and HTTP route."""
    r = requests.delete(
        f"{SUPABASE_URL}/rest/v1/worker_locations?worker_name=neq.PLACEHOLDER",
        headers={**sb_headers(), "Prefer": "return=minimal"},
        timeout=10
    )
    return r.ok

@app.route("/api/admin/reset-locations", methods=["POST"])
def reset_locations():
    require_admin_secret()
    ok = _do_reset_locations()
    return jsonify({"ok": ok})


# ── Nightly APScheduler job ───────────────────────────────────────────────────
def _nightly_report_and_reset():
    """Runs at 22:00 America/Chicago every day.
    1. Generates today's location-movement PDF in-process.
    2. Emails it to ADMIN_EMAIL as an attachment.
    3. Clears the worker_locations table for the next day.
    No HTTP round-trips — everything runs in-process.
    """
    import datetime as dt
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders

    today = dt.date.today().isoformat()
    print(f"[APScheduler] nightly_report_and_reset starting for {today}")

    # 1. Build PDF
    try:
        buf, report_date, row_count = build_location_pdf(today)
        pdf_bytes = buf.getvalue()
        print(f"[APScheduler] PDF built — {row_count} movements for {report_date}")
    except Exception as e:
        print(f"[APScheduler] PDF generation failed: {e}")
        pdf_bytes = None
        report_date = today
        row_count = 0

    # 2. Email PDF to admin
    if SMTP_EMAIL and SMTP_PASSWORD and ADMIN_EMAIL:
        try:
            msg = MIMEMultipart()
            msg["Subject"] = f"MBR Texas — Location Report {report_date}"
            msg["From"]    = SMTP_EMAIL
            msg["To"]      = ADMIN_EMAIL

            body_html = f"""
            <div style="font-family:Arial,sans-serif;max-width:520px;background:#0f1117;color:#e2e8f0;padding:28px;border-radius:12px;">
              <div style="background:#1a6bc4;width:44px;height:44px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:800;color:#fff;margin-bottom:16px;font-size:16px;">MBR</div>
              <h2 style="margin:0 0 6px;">Location Report — {report_date}</h2>
              <p style="color:#94a3b8;font-size:14px;margin:0 0 16px;">
                {row_count} worker movements recorded today on the TDG Data Center project.
                The full report is attached as a PDF.
              </p>
              <p style="color:#64748b;font-size:12px;">Worker location table has been cleared for tomorrow.</p>
            </div>"""
            msg.attach(MIMEText(body_html, "html"))

            if pdf_bytes:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(pdf_bytes)
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f'attachment; filename="Location_Report_{report_date}.pdf"'
                )
                msg.attach(part)

            with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as srv:
                srv.login(SMTP_EMAIL, SMTP_PASSWORD)
                srv.sendmail(SMTP_EMAIL, [ADMIN_EMAIL], msg.as_string())
            print(f"[APScheduler] Report emailed to {ADMIN_EMAIL}")
        except Exception as e:
            print(f"[APScheduler] Email failed: {e}")
    else:
        print("[APScheduler] Email skipped — SMTP not configured")

    # 3. Reset locations table
    ok = _do_reset_locations()
    print(f"[APScheduler] Location table reset: {'OK' if ok else 'FAILED'}")


# Start APSche