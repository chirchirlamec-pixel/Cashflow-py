"""cashflow.site backend (Flask + Postgres, or SQLite for local use).

Members register, pay the access fee by M-Pesa and wait for approval.
Admin (Hakim Ray) signs in, approves payments, manages members and sees insights.
Optional M-Pesa Daraja STK push confirms payments automatically.
"""
import base64
import csv
import datetime as dt
import hmac
import io
import os
import re
import secrets
import sqlite3
import time
from functools import wraps

import requests
from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=8),
    MAX_CONTENT_LENGTH=64 * 1024,
)
DB_PATH = os.environ.get("DATABASE_PATH", "cashflow.db")
DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL") or ""
USE_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))
if USE_PG:
    import psycopg
    from psycopg.rows import dict_row
    IntegrityError = psycopg.IntegrityError
else:
    IntegrityError = sqlite3.IntegrityError
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "chirchirlamec@gmail.com").strip().lower()
SITE_NAME = "cashflow.site"
SPONSOR = "Hakim Ray"

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE, email TEXT,
  pw_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','suspended')),
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER NOT NULL REFERENCES members(id),
  amount INTEGER NOT NULL, method TEXT NOT NULL,
  mpesa_code TEXT UNIQUE, phone TEXT, checkout_id TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  created_at TEXT NOT NULL, reviewed_at TEXT, reviewed_by TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, detail TEXT);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, phone TEXT, body TEXT, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
CREATE INDEX IF NOT EXISTS idx_members_created ON members(created_at);
"""
DEFAULT_SETTINGS = {
    "fee": "100",
    "method_label": "M-Pesa",
    "payee": "",
    "instructions": "Send the fee by M-Pesa, then enter the confirmation code from the SMS.",
}


# ---------- database ----------
class Conn:
    """Small wrapper so the same code runs on Postgres (production) and SQLite (local)."""

    def __init__(self):
        if USE_PG:
            self.raw = psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=False, connect_timeout=10)
        else:
            self.raw = sqlite3.connect(DB_PATH)
            self.raw.row_factory = lambda cur, row: {d[0]: v for d, v in zip(cur.description, row)}
            self.raw.execute("PRAGMA foreign_keys=ON")

    @staticmethod
    def _sql(sql):
        return sql.replace("?", "%s").replace(" LIKE ", " ILIKE ") if USE_PG else sql

    def execute(self, sql, args=()):
        cur = self.raw.cursor()
        try:
            cur.execute(self._sql(sql), tuple(args))
        except IntegrityError:
            self.raw.rollback()
            raise
        return cur

    def insert(self, sql, args=()):
        if USE_PG:
            return self.execute(sql + " RETURNING id", args).fetchone()["id"]
        return self.execute(sql, args).lastrowid

    def commit(self):
        self.raw.commit()

    def close(self):
        try:
            self.raw.close()
        except Exception:
            pass


def get_db():
    if "db" not in g:
        g.db = Conn()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = Conn()
    schema = SCHEMA.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY") if USE_PG else SCHEMA
    for stmt in [x.strip() for x in schema.split(";") if x.strip()]:
        db.execute(stmt)
    for k, v in DEFAULT_SETTINGS.items():
        db.execute("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT (key) DO NOTHING", (k, v))
    db.commit()
    db.close()


def now():
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def setting(key):
    row = get_db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else DEFAULT_SETTINGS.get(key, "")


def audit(action, detail=""):
    actor = "admin" if session.get("admin") else ("member:%s" % session.get("member_id") if session.get("member_id") else "system")
    get_db().execute("INSERT INTO audit(ts,actor,action,detail) VALUES (?,?,?,?)", (now(), actor, action, detail))


# ---------- security helpers ----------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


@app.context_processor
def inject():
    return dict(csrf=csrf_token, site=SITE_NAME, sponsor=SPONSOR, fee=setting("fee"),
                is_admin=bool(session.get("admin")), member_id=session.get("member_id"))


@app.before_request
def csrf_protect():
    if request.method == "POST" and not request.path.startswith("/mpesa/callback/"):
        sent = request.form.get("csrf", "")
        if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing form token. Go back, reload the page and try again.")


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:")
    return resp


def client_ip():
    if os.environ.get("VERCEL") or os.environ.get("TRUST_PROXY") == "1":
        fwd = request.headers.get("X-Vercel-Forwarded-For") or request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote_addr or "?"


_attempts = {}


def too_many_attempts(key, limit=5, window=600):
    t = time.time()
    hits = [x for x in _attempts.get(key, []) if t - x < window]
    _attempts[key] = hits
    return len(hits) >= limit


def record_attempt(key):
    _attempts.setdefault(key, []).append(time.time())


def admin_required(fn):
    @wraps(fn)
    def wrap(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return fn(*a, **kw)
    return wrap


def member_required(fn):
    @wraps(fn)
    def wrap(*a, **kw):
        if not session.get("member_id"):
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrap


def normalize_phone(raw):
    p = re.sub(r"[\s\-()]", "", raw or "")
    if p.startswith("+"):
        p = p[1:]
    if re.fullmatch(r"0[17]\d{8}", p):
        p = "254" + p[1:]
    return p if re.fullmatch(r"254[17]\d{8}", p) else None


def admin_password_ok(password):
    pw_hash = os.environ.get("ADMIN_PASSWORD_HASH")
    if pw_hash:
        return check_password_hash(pw_hash, password)
    plain = os.environ.get("ADMIN_PASSWORD")
    return bool(plain) and hmac.compare_digest(plain.encode(), password.encode())


# ---------- public pages ----------
@app.get("/")
def index():
    return render_template("index.html", payee=setting("payee"))


@app.get("/healthz")
def healthz():
    """Setup check: shows which settings exist (never their values) and whether the database answers."""
    info = {
        "database_url_set": bool(DATABASE_URL),
        "using_postgres": USE_PG,
        "secret_key_set": bool(os.environ.get("SECRET_KEY")),
        "admin_email_set": bool(os.environ.get("ADMIN_EMAIL")),
        "admin_password_set": bool(os.environ.get("ADMIN_PASSWORD_HASH") or os.environ.get("ADMIN_PASSWORD")),
    }
    try:
        get_db().execute("SELECT 1")
        info["database"] = "ok"
    except Exception as exc:
        msg = str(exc)
        if DATABASE_URL:
            msg = msg.replace(DATABASE_URL, "[hidden]")
        info["database"] = "error: %s: %s" % (type(exc).__name__, msg[:200])
    return jsonify(info)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:60]
        phone = normalize_phone(request.form.get("phone"))
        email = request.form.get("email", "").strip()[:120]
        pw = request.form.get("password", "")
        if len(name) < 2 or not phone or len(pw) < 8:
            flash("Enter your name, a valid Kenyan phone number (07xx or 01xx) and a password of at least 8 characters.", "err")
            return render_template("register.html")
        db = get_db()
        try:
            new_id = db.insert("INSERT INTO members(name,phone,email,pw_hash,created_at) VALUES (?,?,?,?,?)",
                           (name, phone, email, generate_password_hash(pw), now()))
        except IntegrityError:
            flash("That phone number is already registered. Sign in instead.", "err")
            return render_template("register.html")
        session.clear()
        session["member_id"] = new_id
        audit("member_registered", phone)
        db.commit()
        return redirect(url_for("member"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = normalize_phone(request.form.get("phone")) or ""
        key = "m:" + client_ip() + phone
        if too_many_attempts(key):
            flash("Too many attempts. Try again in 10 minutes.", "err")
            return render_template("login.html")
        row = get_db().execute("SELECT * FROM members WHERE phone=?", (phone,)).fetchone()
        if row and check_password_hash(row["pw_hash"], request.form.get("password", "")):
            session.clear()
            session["member_id"] = row["id"]
            return redirect(url_for("member"))
        record_attempt(key)
        flash("Phone number or password is not right.", "err")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/member")
@member_required
def member():
    db = get_db()
    me = db.execute("SELECT * FROM members WHERE id=?", (session["member_id"],)).fetchone()
    if not me:
        session.clear()
        return redirect(url_for("login"))
    pays = db.execute("SELECT * FROM payments WHERE member_id=? ORDER BY id DESC", (me["id"],)).fetchall()
    return render_template("member.html", me=me, pays=pays, payee=setting("payee"),
                           label=setting("method_label"), instructions=setting("instructions"),
                           stk=daraja_ready())


@app.post("/pay")
@member_required
def pay():
    code = re.sub(r"\s", "", request.form.get("code", "")).upper()
    if not re.fullmatch(r"[A-Z0-9]{10}", code):
        flash("An M-Pesa code has 10 letters and numbers, for example ABC1D2EFGH.", "err")
        return redirect(url_for("member"))
    db = get_db()
    me = db.execute("SELECT * FROM members WHERE id=?", (session["member_id"],)).fetchone()
    if me["status"] != "pending":
        return redirect(url_for("member"))
    try:
        db.execute("INSERT INTO payments(member_id,amount,method,mpesa_code,phone,created_at) VALUES (?,?,?,?,?,?)",
                   (me["id"], int(setting("fee")), "manual", code, me["phone"], now()))
    except IntegrityError:
        flash("That M-Pesa code has already been submitted.", "err")
        return redirect(url_for("member"))
    audit("payment_submitted", code)
    db.commit()
    flash("Payment submitted. The administrator will review it.", "ok")
    return redirect(url_for("member"))


@app.post("/contact")
def contact():
    name, phone, body = (request.form.get(k, "").strip()[:300] for k in ("name", "phone", "body"))
    if name and body:
        get_db().execute("INSERT INTO messages(name,phone,body,created_at) VALUES (?,?,?,?)", (name, phone, body, now()))
        get_db().commit()
        flash("Message sent. The admin will follow up.", "ok")
    return redirect(url_for("index"))


# ---------- M-Pesa Daraja (optional, STK push) ----------
def daraja_ready():
    need = ("DARAJA_CONSUMER_KEY", "DARAJA_CONSUMER_SECRET", "DARAJA_SHORTCODE", "DARAJA_PASSKEY",
            "CALLBACK_BASE_URL", "CALLBACK_SECRET")
    return all(os.environ.get(k) for k in need)


def daraja_base():
    return "https://api.safaricom.co.ke" if os.environ.get("DARAJA_ENV") == "production" else "https://sandbox.safaricom.co.ke"


def daraja_token():
    r = requests.get(daraja_base() + "/oauth/v1/generate?grant_type=client_credentials",
                     auth=(os.environ["DARAJA_CONSUMER_KEY"], os.environ["DARAJA_CONSUMER_SECRET"]), timeout=20)
    r.raise_for_status()
    return r.json()["access_token"]


@app.post("/pay/stk")
@member_required
def pay_stk():
    if not daraja_ready():
        abort(404)
    db = get_db()
    me = db.execute("SELECT * FROM members WHERE id=?", (session["member_id"],)).fetchone()
    if me["status"] != "pending":
        return redirect(url_for("member"))
    ts = dt.datetime.now().strftime("%Y%m%d%H%M%S")
    shortcode = os.environ["DARAJA_SHORTCODE"]
    password = base64.b64encode((shortcode + os.environ["DARAJA_PASSKEY"] + ts).encode()).decode()
    amount = int(setting("fee"))
    body = {
        "BusinessShortCode": shortcode, "Password": password, "Timestamp": ts,
        "TransactionType": os.environ.get("DARAJA_TXN_TYPE", "CustomerPayBillOnline"),
        "Amount": amount, "PartyA": me["phone"], "PartyB": os.environ.get("DARAJA_PARTYB", shortcode),
        "PhoneNumber": me["phone"],
        "CallBackURL": "%s/mpesa/callback/%s" % (os.environ["CALLBACK_BASE_URL"].rstrip("/"), os.environ["CALLBACK_SECRET"]),
        "AccountReference": "CASHFLOW%d" % me["id"], "TransactionDesc": "Access fee",
    }
    try:
        r = requests.post(daraja_base() + "/mpesa/stkpush/v1/processrequest", json=body,
                          headers={"Authorization": "Bearer " + daraja_token()}, timeout=25)
        data = r.json()
    except Exception:
        flash("Could not reach M-Pesa. Try again or pay manually.", "err")
        return redirect(url_for("member"))
    if data.get("ResponseCode") == "0":
        db.execute("INSERT INTO payments(member_id,amount,method,phone,checkout_id,created_at) VALUES (?,?,?,?,?,?)",
                   (me["id"], amount, "stk", me["phone"], data["CheckoutRequestID"], now()))
        audit("stk_requested", data["CheckoutRequestID"])
        db.commit()
        flash("Check your phone and enter your M-Pesa PIN to approve the payment.", "ok")
    else:
        flash("M-Pesa did not accept the request. Try again or pay manually.", "err")
    return redirect(url_for("member"))


@app.post("/mpesa/callback/<secret>")
def mpesa_callback(secret):
    expected = os.environ.get("CALLBACK_SECRET", "")
    if not expected or not hmac.compare_digest(secret, expected):
        abort(404)
    data = (request.get_json(silent=True) or {}).get("Body", {}).get("stkCallback", {})
    checkout = data.get("CheckoutRequestID")
    db = get_db()
    pay_row = db.execute("SELECT * FROM payments WHERE checkout_id=? AND status='pending'", (checkout,)).fetchone()
    if pay_row:
        if data.get("ResultCode") == 0:
            items = {i.get("Name"): i.get("Value") for i in data.get("CallbackMetadata", {}).get("Item", [])}
            receipt, paid = items.get("MpesaReceiptNumber"), int(items.get("Amount") or 0)
            if receipt and paid >= pay_row["amount"]:
                db.execute("UPDATE payments SET status='approved',mpesa_code=?,reviewed_at=?,reviewed_by='mpesa-auto' WHERE id=?",
                           (receipt, now(), pay_row["id"]))
                db.execute("UPDATE members SET status='active' WHERE id=? AND status='pending'", (pay_row["member_id"],))
                db.execute("INSERT INTO audit(ts,actor,action,detail) VALUES (?,?,?,?)", (now(), "mpesa", "payment_confirmed", receipt))
        else:
            db.execute("UPDATE payments SET status='rejected',reviewed_at=?,reviewed_by='mpesa-auto',note=? WHERE id=?",
                       (now(), str(data.get("ResultDesc", ""))[:200], pay_row["id"]))
        db.commit()
    return jsonify(ResultCode=0, ResultDesc="Accepted")


# ---------- admin ----------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    configured = bool(os.environ.get("ADMIN_PASSWORD_HASH") or os.environ.get("ADMIN_PASSWORD"))
    if request.method == "POST":
        key = "a:" + client_ip()
        if too_many_attempts(key):
            flash("Too many attempts. Try again in 10 minutes.", "err")
        elif not configured:
            flash("Admin password is not configured on the server.", "err")
        else:
            email = request.form.get("email", "").strip().lower()
            ok = hmac.compare_digest(email, ADMIN_EMAIL) & admin_password_ok(request.form.get("password", ""))
            if ok:
                session.clear()
                session["admin"] = True
                session.permanent = True
                audit("admin_login")
                get_db().commit()
                return redirect(url_for("admin_dashboard"))
            record_attempt(key)
            flash("Email or password is not right.", "err")
    return render_template("admin_login.html", configured=configured)


@app.post("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


AVG_SQL = (
    "SELECT AVG(EXTRACT(EPOCH FROM (reviewed_at::timestamp - created_at::timestamp)) / 3600.0) FROM payments WHERE status='approved'"
    if USE_PG else
    "SELECT AVG((julianday(reviewed_at)-julianday(created_at))*24) FROM payments WHERE status='approved'")


def insights():
    db = get_db()
    today = dt.date.today()
    days = [(today - dt.timedelta(days=i)).isoformat() for i in range(29, -1, -1)]
    signups = {r["d"]: r["c"] for r in db.execute(
        "SELECT substr(created_at,1,10) d, COUNT(*) c FROM members WHERE created_at>=? GROUP BY d", (days[0],))}
    revenue = {r["d"]: r["s"] for r in db.execute(
        "SELECT substr(reviewed_at,1,10) d, SUM(amount) s FROM payments WHERE status='approved' AND reviewed_at>=? GROUP BY d", (days[0],))}
    one = lambda q, *a: next(iter(db.execute(q, a).fetchone().values())) or 0
    total = one("SELECT COUNT(*) FROM members")
    active = one("SELECT COUNT(*) FROM members WHERE status='active'")
    return {
        "days": [d[5:] for d in days],
        "signups": [signups.get(d, 0) for d in days],
        "revenue": [revenue.get(d, 0) for d in days],
        "member_status": {s: one("SELECT COUNT(*) FROM members WHERE status=?", s) for s in ("active", "pending", "suspended")},
        "payment_status": {s: one("SELECT COUNT(*) FROM payments WHERE status=?", s) for s in ("approved", "pending", "rejected")},
        "method": {m: one("SELECT COUNT(*) FROM payments WHERE status='approved' AND method=?", m) for m in ("manual", "stk")},
        "kpi": {
            "members": total, "active": active,
            "conversion": round(100 * active / total, 1) if total else 0,
            "pending_payments": one("SELECT COUNT(*) FROM payments WHERE status='pending'"),
            "revenue_total": one("SELECT SUM(amount) FROM payments WHERE status='approved'"),
            "revenue_30d": sum(revenue.values()),
            "avg_hours": round(float(one(AVG_SQL)), 1),
        },
    }


# ---------- charts (server-rendered SVG, no external scripts) ----------
from markupsafe import Markup  # noqa: E402


def _nice_max(v):
    v = max(v, 1)
    for step in (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000):
        if v <= step * 4:
            return step * 4, step
    return v, max(v // 4, 1)


def _axes(labels, top, step, w, h, L=42, B=26, T=10, R=8):
    out = []
    for i in range(0, top + 1, step):
        y = T + (h - T - B) * (1 - i / top)
        out.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="#dce0ec"/>' % (L, w - R, y, y))
        out.append('<text x="%d" y="%.1f" text-anchor="end" font-size="11" fill="#687087">%s</text>' % (L - 6, y + 4, "{:,}".format(i)))
    every = max(1, len(labels) // 6)
    for i, lab in enumerate(labels):
        if i % every == 0:
            x = L + (w - L - R) * (i + .5) / len(labels)
            out.append('<text x="%.1f" y="%d" text-anchor="middle" font-size="11" fill="#687087">%s</text>' % (x, h - 8, lab))
    return "".join(out)


def svg_chart(kind, labels, vals, color, title, w=520, h=240):
    top, step = _nice_max(max(vals) if vals else 1)
    L, B, T, R = 42, 26, 10, 8
    body = _axes(labels, top, step, w, h)
    n = max(len(vals), 1)
    pw, ph = w - L - R, h - T - B
    if kind == "bar":
        bw = pw / n * .7
        for i, v in enumerate(vals):
            bh = ph * v / top
            x = L + pw * (i + .5) / n - bw / 2
            body += '<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="2" fill="%s"><title>%s: %s</title></rect>' % (x, T + ph - bh, bw, bh, color, labels[i], "{:,}".format(v))
    else:
        pts = ["%.1f,%.1f" % (L + pw * (i + .5) / n, T + ph * (1 - v / top)) for i, v in enumerate(vals)]
        if pts:
            area = "%.1f,%d %s %.1f,%d" % (L + pw * .5 / n, T + ph, " ".join(pts), L + pw * (n - .5) / n, T + ph)
            body += '<polygon points="%s" fill="%s" opacity=".15"/><polyline points="%s" fill="none" stroke="%s" stroke-width="2.5" stroke-linejoin="round"/>' % (area, color, " ".join(pts), color)
            for i, p in enumerate(pts):
                x, y = p.split(",")
                body += '<circle cx="%s" cy="%s" r="3" fill="%s"><title>%s: %s</title></circle>' % (x, y, color, labels[i], vals[i])
    return Markup('<svg viewBox="0 0 %d %d" width="100%%" role="img" aria-label="%s">%s</svg>' % (w, h, title, body))


def svg_donut(data, colors, title):
    total = sum(data.values())
    r, cx, cy, C = 62, 90, 90, 2 * 3.14159265 * 62
    parts, off = "", 0
    for (k, v), col in zip(data.items(), colors):
        if total:
            seg = C * v / total
            parts += '<circle cx="%d" cy="%d" r="%d" fill="none" stroke="%s" stroke-width="26" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 %d %d)"/>' % (cx, cy, r, col, seg, C - seg, -off, cx, cy)
            off += seg
    if not total:
        parts = '<circle cx="%d" cy="%d" r="%d" fill="none" stroke="#dce0ec" stroke-width="26"/>' % (cx, cy, r)
    legend = "".join('<g transform="translate(200,%d)"><rect width="12" height="12" rx="3" fill="%s"/><text x="20" y="11" font-size="13" fill="#20233d">%s: %s</text></g>' % (50 + i * 24, col, k, v) for i, ((k, v), col) in enumerate(zip(data.items(), colors)))
    centre = '<text x="%d" y="%d" text-anchor="middle" font-size="22" font-weight="800" fill="#20233d">%s</text>' % (cx, cy + 7, total)
    return Markup('<svg viewBox="0 0 340 180" width="100%%" role="img" aria-label="%s">%s%s%s</svg>' % (title, parts, centre, legend))



@app.get("/admin")
@admin_required
def admin_dashboard():
    d = insights()
    charts = dict(
        signups=svg_chart("line", d["days"], d["signups"], "#7412a0", "New members per day"),
        revenue=svg_chart("bar", d["days"], d["revenue"], "#20bf72", "Approved revenue per day"),
        members=svg_donut(d["member_status"], ["#20bf72", "#f4ad55", "#d9534f"], "Members by status"),
        payments=svg_donut(d["payment_status"], ["#20bf72", "#f4ad55", "#d9534f"], "Payments by status"),
    )
    return render_template("dashboard.html", d=d, charts=charts)


@app.get("/admin/members")
@admin_required
def admin_members():
    q = request.args.get("q", "").strip()[:40]
    status = request.args.get("status", "")
    sql, args = "SELECT * FROM members WHERE 1=1", []
    if q:
        sql += " AND (name LIKE ? OR phone LIKE ?)"
        args += ["%" + q + "%"] * 2
    if status in ("active", "pending", "suspended"):
        sql += " AND status=?"
        args.append(status)
    rows = get_db().execute(sql + " ORDER BY id DESC LIMIT 300", args).fetchall()
    return render_template("members.html", rows=rows, q=q, status=status)


@app.post("/admin/members/<int:mid>/status")
@admin_required
def admin_member_status(mid):
    new = request.form.get("status")
    if new not in ("active", "pending", "suspended"):
        abort(400)
    db = get_db()
    db.execute("UPDATE members SET status=? WHERE id=?", (new, mid))
    audit("member_status", "%d -> %s" % (mid, new))
    db.commit()
    return redirect(request.referrer or url_for("admin_members"))


@app.get("/admin/payments")
@admin_required
def admin_payments():
    status = request.args.get("status", "pending")
    sql = ("SELECT p.*, m.name, m.phone AS member_phone FROM payments p JOIN members m ON m.id=p.member_id")
    args = []
    if status in ("pending", "approved", "rejected"):
        sql += " WHERE p.status=?"
        args.append(status)
    rows = get_db().execute(sql + " ORDER BY p.id DESC LIMIT 300", args).fetchall()
    return render_template("payments.html", rows=rows, status=status)


@app.post("/admin/payments/<int:pid>/<action>")
@admin_required
def admin_payment_action(pid, action):
    if action not in ("approve", "reject"):
        abort(404)
    db = get_db()
    p = db.execute("SELECT * FROM payments WHERE id=?", (pid,)).fetchone()
    if not p or p["status"] != "pending":
        flash("That payment was already reviewed.", "err")
        return redirect(url_for("admin_payments"))
    new = "approved" if action == "approve" else "rejected"
    db.execute("UPDATE payments SET status=?,reviewed_at=?,reviewed_by=?,note=? WHERE id=?",
               (new, now(), "admin", request.form.get("note", "")[:200], pid))
    if new == "approved":
        db.execute("UPDATE members SET status='active' WHERE id=? AND status='pending'", (p["member_id"],))
    audit("payment_" + new, "%s %s" % (p["mpesa_code"], p["amount"]))
    db.commit()
    return redirect(url_for("admin_payments"))


@app.get("/admin/payments.csv")
@admin_required
def admin_payments_csv():
    rows = get_db().execute(
        "SELECT p.id,m.name,m.phone,p.amount,p.method,p.mpesa_code,p.status,p.created_at,p.reviewed_at,p.reviewed_by "
        "FROM payments p JOIN members m ON m.id=p.member_id ORDER BY p.id").fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(rows[0].keys() if rows else ["id", "name", "phone", "amount", "method", "mpesa_code", "status", "created_at", "reviewed_at", "reviewed_by"])
    for r in rows:
        w.writerow([("'" + str(v)) if isinstance(v, str) and v[:1] in "=+-@" else v for v in r.values()])
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=payments.csv"})


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    db = get_db()
    if request.method == "POST":
        fee = request.form.get("fee", "")
        if not fee.isdigit() or not (1 <= int(fee) <= 100000):
            flash("The fee must be a whole number of KSh.", "err")
        else:
            for k in ("fee", "method_label", "payee", "instructions"):
                db.execute("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", (k, request.form.get(k, "").strip()[:200]))
            audit("settings_changed")
            db.commit()
            flash("Settings saved.", "ok")
    vals = {k: setting(k) for k in DEFAULT_SETTINGS}
    return render_template("settings.html", s=vals, stk=daraja_ready())


@app.get("/admin/audit")
@admin_required
def admin_audit():
    rows = get_db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
    msgs = get_db().execute("SELECT * FROM messages ORDER BY id DESC LIMIT 50").fetchall()
    return render_template("audit.html", rows=rows, msgs=msgs)


@app.cli.command("seed-demo")
def seed_demo():
    """Fill the database with clearly fake demo data to preview the charts."""
    import random
    init_db()
    db = get_db()
    random.seed(7)
    for i in range(60):
        day = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(days=random.randint(0, 29), hours=random.randint(0, 20))
        st = random.choices(["active", "pending", "suspended"], [6, 3, 1])[0]
        mid = db.insert("INSERT INTO members(name,phone,pw_hash,status,created_at) VALUES (?,?,?,?,?)",
                        ("Demo Member %d" % i, "2547000%05d" % i, "x", st, day.isoformat(timespec="seconds")))
        if st == "active":
            rev = day + dt.timedelta(hours=random.randint(1, 30))
            db.execute("INSERT INTO payments(member_id,amount,method,mpesa_code,phone,status,created_at,reviewed_at,reviewed_by) VALUES (?,?,?,?,?,?,?,?,?)",
                       (mid, 100, random.choice(["manual", "stk"]), "DEMO%06d" % i, "x", "approved",
                        day.isoformat(timespec="seconds"), rev.isoformat(timespec="seconds"), "admin"))
        elif random.random() < .6:
            db.execute("INSERT INTO payments(member_id,amount,method,mpesa_code,phone,status,created_at) VALUES (?,?,?,?,?,?,?)",
                       (mid, 100, "manual", "DEMO%06d" % i, "x", "pending", day.isoformat(timespec="seconds")))
    db.commit()
    print("Demo data added.")


try:
    init_db()
except Exception as exc:  # keep the app importable so the error shows in logs, not as a failed deploy
    print("Database setup failed:", exc)

if __name__ == "__main__":
    app.run(debug=False, port=int(os.environ.get("PORT", 5000)))
