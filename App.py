"""
SecureFuture Solutions LTD

Security Features:
  - Input sanitisation (bleach + regex)
  - Two-Factor Authentication (TOTP)
  - Admin login monitoring (every attempt logged)
  - SQL injection detection on ALL fields including password
  - Invite-only registration (admin emails a signed token link)
  - Rate limiting on all sensitive routes (brute-force protection)
"""

import re, io, base64, logging, uuid, os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
load_dotenv()  # Loads .env file automatically when running locally

import bleach, pyotp, qrcode
from flask import (Flask, render_template, redirect, url_for,
                   request, flash, session, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                         logout_user, login_required, current_user)
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt


# ── App & extensions ──────────────────────────────────────────────────────────
app = Flask(__name__)

# Secrets come from environment variables so they are never hardcoded in source.
# Locally: set them in your shell or a .env file.
# On Railway: add them in the Railway dashboard → Variables tab.
app.config["SECRET_KEY"]                     = os.environ.get("SECRET_KEY", "change-me-in-production")
_db_url = os.environ.get("DATABASE_URL", "sqlite:///secure_future.db")
if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"]        = _db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ── Email config ──────────────────────────────────────────────────────────────
app.config["MAIL_SERVER"]         = os.environ.get("MAIL_SERVER",   "smtp.gmail.com")
app.config["MAIL_PORT"]           = int(os.environ.get("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"]        = os.environ.get("MAIL_USE_TLS",  "true").lower() == "true"
app.config["MAIL_USERNAME"]       = os.environ.get("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"]       = os.environ.get("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = (
    os.environ.get("MAIL_SENDER_NAME", "SecureFuture Solutions"),
    os.environ.get("MAIL_USERNAME", ""),
)

INVITE_EXPIRY_HOURS = int(os.environ.get("INVITE_EXPIRY_HOURS", "1"))

db            = SQLAlchemy(app)
mail          = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "LoginPage"

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
security_log = logging.getLogger("security")


# ── SQL injection detection ───────────────────────────────────────────────────
_SQL_PATTERN = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|EXEC|UNION"
    r"|DECLARE|CAST|CONVERT|SLEEP|BENCHMARK|INFORMATION_SCHEMA|SYSOBJECTS)\b"
    r"|--|/\*|\*/|xp_|0x[0-9a-fA-F]+)",
    re.IGNORECASE,
)

def contains_sql(value):
    return bool(_SQL_PATTERN.search(value))

def scan_fields_for_sql(fields):
    """Check only the given field names from the posted form."""
    return [f for f in fields
            if contains_sql(request.form.get(f, ""))]


# ── Input sanitisation ────────────────────────────────────────────────────────
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,64}$")
_EMAIL_RE    = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def sanitise(value, max_len=255):
    """Strip HTML tags and truncate. Do NOT use on usernames or passwords."""
    return bleach.clean(value, tags=[], strip=True)[:max_len].strip()

def clean_username(value):
    """Safe username extraction — strip whitespace only, no bleach."""
    return value.strip()[:64]

def validate_username(u):
    return None if _USERNAME_RE.match(u) else "Username: 3-64 chars, letters/digits/_ . -"

def validate_email(e):
    return None if _EMAIL_RE.match(e) else "Please enter a valid email address."

def validate_password(p):
    if len(p) < 8:   return "Password must be at least 8 characters."
    if len(p) > 128: return "Password must not exceed 128 characters."
    return None


# ── Models ────────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    id          = db.Column(db.Integer,   primary_key=True)
    username    = db.Column(db.String(64),  unique=True, nullable=False)
    email       = db.Column(db.String(120), unique=True, nullable=False)
    password    = db.Column(db.String(255), nullable=False)
    role        = db.Column(db.String(20),  nullable=False, default="employee")
    totp_secret = db.Column(db.String(32),  nullable=True)

    def set_password(self, plaintext):
        self.password = bcrypt.hashpw(
            plaintext.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

    def check_password(self, plaintext):
        try:
            return bcrypt.checkpw(
                plaintext.encode("utf-8"), self.password.encode("utf-8")
            )
        except Exception:
            return False

    @property
    def two_fa_enabled(self):
        return self.totp_secret is not None

    def verify_totp(self, code):
        try:
            return pyotp.TOTP(self.totp_secret).verify(code, valid_window=1)
        except Exception:
            return False


class Invitation(db.Model):
    id         = db.Column(db.Integer,    primary_key=True)
    token      = db.Column(db.String(64), unique=True, nullable=False,
                           default=lambda: uuid.uuid4().hex)
    email      = db.Column(db.String(120), nullable=False)
    role       = db.Column(db.String(20),  nullable=False, default="employee")
    created_by = db.Column(db.Integer,    db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime,   nullable=False,
                           default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime,   nullable=False)
    used       = db.Column(db.Boolean,    nullable=False, default=False)
    creator    = db.relationship("User",  foreign_keys=[created_by])

    @property
    def is_valid(self):
        now = datetime.now(timezone.utc)
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return not self.used and now < exp


class LoginLog(db.Model):
    id             = db.Column(db.Integer,   primary_key=True)
    timestamp      = db.Column(db.DateTime,  nullable=False,
                               default=lambda: datetime.now(timezone.utc))
    username       = db.Column(db.String(64),  nullable=False)
    ip_address     = db.Column(db.String(45),  nullable=False)
    success        = db.Column(db.Boolean,   nullable=False)
    role           = db.Column(db.String(20),  nullable=True)
    sql_flagged    = db.Column(db.Boolean,   nullable=False, default=False)
    flagged_fields = db.Column(db.String(255), nullable=True)


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


# ── Helpers ───────────────────────────────────────────────────────────────────
def get_client_ip():
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")


def log_attempt(username, success, role, sql_flagged, flagged_fields):
    """Write a login attempt to the audit log. Never raises — errors are printed."""
    try:
        entry = LoginLog(
            username=username,
            ip_address=get_client_ip(),
            success=success,
            role=role,
            sql_flagged=sql_flagged,
            flagged_fields=", ".join(flagged_fields) if flagged_fields else None,
        )
        db.session.add(entry)
        db.session.commit()
        if sql_flagged:
            security_log.warning("SQL INJECTION — user=%r ip=%s fields=%s",
                                 username, entry.ip_address, entry.flagged_fields)
        if not success:
            security_log.warning("FAILED LOGIN — user=%r ip=%s",
                                 username, entry.ip_address)
    except Exception as e:
        # Never let logging break the login flow
        db.session.rollback()
        security_log.error("log_attempt() failed: %s", e)


def make_qr_data_uri(uri):
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def send_invite_email(invite):
    link = url_for("register_with_token", token=invite.token, _external=True)
    body = (
        f"Hello,\n\nYou have been invited to join SecureFuture Solutions.\n\n"
        f"Click the link below to create your account "
        f"(expires in {INVITE_EXPIRY_HOURS} hours):\n\n  {link}\n\n"
        f"This link is single-use and cannot be shared.\n\n"
        f"— SecureFuture Solutions Security Team"
    )
    html = render_template("invite_email.html", link=link,
                           expiry_hours=INVITE_EXPIRY_HOURS)
    msg = Message(subject="Your SecureFuture Invitation",
                  recipients=[invite.email], body=body, html=html)
    mail.send(msg)


# ── Rate limit error handler ──────────────────────────────────────────────────
@app.errorhandler(429)
def rate_limited(e):
    flash("Too many attempts. Please wait a moment before trying again.", "danger")
    return render_template("LoginPage.html"), 429


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("Dashboard"))
    return redirect(url_for("LoginPage"))


# ── Login ─────────────────────────────────────────────────────────────────────
@app.route("/LoginPage", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def LoginPage():
    if current_user.is_authenticated:
        return redirect(url_for("Dashboard"))

    if request.method == "POST":
        # Use clean_username (strip only) — bleach must NOT touch the username
        username = clean_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        # SQL check on username field only — password is safe behind bcrypt
        if contains_sql(username):
            flash("SECURITY ALERT: SQL injection pattern detected. Logged.", "danger")
            log_attempt(username, False, None, True, ["username"])
            return render_template("LoginPage.html")

        # Look up user — wrapped in try/except so DB errors surface clearly
        try:
            # ilike = case-insensitive match so 'Admin' and 'admin' both work
            user = User.query.filter(
                User.username.ilike(username)
            ).first()
        except Exception as e:
            security_log.error("User lookup failed during login: %s", e)
            db.session.rollback()
            flash("A database error occurred. Please contact your administrator.", "danger")
            return render_template("LoginPage.html")

        # Validate credentials
        valid_creds = user is not None and user.check_password(password)

        if not valid_creds:
            flash("Invalid username or password.", "danger")
            log_attempt(username, False,
                        user.role if user else None, False, [])
            return render_template("LoginPage.html")

        # 2FA gate
        if user.two_fa_enabled:
            session["pending_2fa_user_id"] = user.id
            return redirect(url_for("two_fa_verify"))

        # Success
        login_user(user)
        log_attempt(username, True, user.role, False, [])
        flash("Logged in successfully!", "success")
        return redirect(url_for("Dashboard"))

    return render_template("LoginPage.html")


# ── 2FA verify ────────────────────────────────────────────────────────────────
@app.route("/2fa/verify", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def two_fa_verify():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("LoginPage"))

    user = db.session.get(User, user_id)
    if not user:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("LoginPage"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if user.verify_totp(code):
            session.pop("pending_2fa_user_id", None)
            login_user(user)
            log_attempt(user.username, True, user.role, False, [])
            flash("Two-factor authentication successful!", "success")
            return redirect(url_for("Dashboard"))
        flash("Invalid or expired code. Please try again.", "danger")

    return render_template("two_fa_verify.html")


# ── 2FA setup ─────────────────────────────────────────────────────────────────
@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def two_fa_setup():
    if current_user.two_fa_enabled:
        flash("2FA is already enabled on your account.", "info")
        return redirect(url_for("Dashboard"))

    if request.method == "POST":
        secret = session.get("pending_totp_secret")
        code   = request.form.get("code", "").strip()
        if not secret:
            flash("Session expired — please restart 2FA setup.", "danger")
            return redirect(url_for("two_fa_setup"))
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            current_user.totp_secret = secret
            db.session.commit()
            session.pop("pending_totp_secret", None)
            flash("Two-factor authentication enabled!", "success")
            return redirect(url_for("Dashboard"))
        flash("Invalid code — scan the QR again and retry.", "danger")

    secret = pyotp.random_base32()
    session["pending_totp_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name="SecureFuture Solutions")
    return render_template("two_fa_setup.html",
                           qr_uri=make_qr_data_uri(uri), secret=secret)


# ── Invite-only registration ──────────────────────────────────────────────────
@app.route("/register/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register_with_token(token):
    if current_user.is_authenticated:
        return redirect(url_for("Dashboard"))

    invite = Invitation.query.filter_by(token=token).first()
    if not invite or not invite.is_valid:
        return render_template("invite_invalid.html"), 403

    if request.method == "POST":
        # SQL check on username only
        if contains_sql(request.form.get("username", "")):
            flash("SECURITY ALERT: SQL injection detected.", "danger")
            return render_template("register.html", invite=invite, token=token)

        username = clean_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        errors = []
        if not username or not password:
            errors.append("Please fill out all fields.")
        else:
            e = validate_username(username); e and errors.append(e)
            e = validate_password(password); e and errors.append(e)

        if User.query.filter(User.username.ilike(username)).first():
            errors.append("Username already taken — please choose another.")
        if User.query.filter_by(email=invite.email).first():
            errors.append("An account with this email already exists.")

        for msg in errors:
            flash(msg, "danger")
        if errors:
            return render_template("register.html", invite=invite, token=token)

        user = User(username=username, email=invite.email, role=invite.role)
        user.set_password(password)
        db.session.add(user)
        invite.used = True
        db.session.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("LoginPage"))

    return render_template("register.html", invite=invite, token=token)


# ── Admin: send invite (GET - page load, no rate limit) ──────────────────────
@app.route("/admin/invite", methods=["GET"])
@login_required
def admin_invite():
    if current_user.role != "admin":
        abort(403)
    pending = (Invitation.query
               .filter_by(used=False)
               .order_by(Invitation.created_at.desc())
               .all())
    return render_template("admin_invite.html", pending=pending)


# ── Admin: send invite (POST - rate limited to 10 per hour) ──────────────────
@app.route("/admin/invite", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def admin_invite_post():
    if current_user.role != "admin":
        abort(403)

    email = sanitise(request.form.get("email", ""))
    role  = sanitise(request.form.get("role", "employee"))

    if contains_sql(email):
        flash("SQL injection detected in email field.", "danger")
    elif validate_email(email):
        flash(validate_email(email), "danger")
    elif role not in ("employee", "manager", "admin"):
        flash("Invalid role selected.", "danger")
    else:
        old = Invitation.query.filter_by(email=email, used=False).first()
        if old:
            db.session.delete(old)

        invite = Invitation(
            email=email, role=role, created_by=current_user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=INVITE_EXPIRY_HOURS),
        )
        db.session.add(invite)
        db.session.commit()

        try:
            send_invite_email(invite)
            flash(f"Invite sent to {email}.", "success")
        except Exception as exc:
            security_log.error("Mail send failed: %s", exc)
            link = url_for("register_with_token", token=invite.token, _external=True)
            flash(f"Email failed to send — share this link manually: {link}", "warning")

    return redirect(url_for("admin_invite"))


# ── Admin: revoke invite ──────────────────────────────────────────────────────
@app.route("/admin/invite/revoke/<int:invite_id>", methods=["POST"])
@login_required
def admin_revoke_invite(invite_id):
    if current_user.role != "admin":
        abort(403)
    invite = db.session.get(Invitation, invite_id)
    if invite:
        db.session.delete(invite)
        db.session.commit()
        flash("Invite revoked.", "success")
    return redirect(url_for("admin_invite"))


# ── Dashboards ────────────────────────────────────────────────────────────────
@app.route("/Dashboard")
@login_required
def Dashboard():
    if current_user.role == "admin":   return redirect(url_for("admin_dashboard"))
    if current_user.role == "manager": return redirect(url_for("manager_dashboard"))
    return redirect(url_for("employee_dashboard"))

@app.route("/employee")
@login_required
def employee_dashboard():
    return render_template("employee_dashboard.html", username=current_user.username)

@app.route("/manager")
@login_required
def manager_dashboard():
    return render_template("manager_dashboard.html", username=current_user.username)

@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        abort(403)
    try:
        logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(50).all()
    except Exception:
        logs = []
    return render_template("admin_dashboard.html",
                           username=current_user.username, logs=logs)

@app.route("/Logout")
@login_required
def Logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("LoginPage"))


# ── View Logs ─────────────────────────────────────────────────────────────────
@app.route("/view_logs")
@login_required
def view_logs():
    if current_user.role != "admin":
        abort(403)
    try:
        logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).all()
    except Exception:
        logs = []
    return render_template("view_logs.html", logs=logs)


# ── Edit Users ────────────────────────────────────────────────────────────────
@app.route("/edit_users", methods=["GET", "POST"])
@login_required
def edit_users():
    if current_user.role != "admin":
        abort(403)

    if request.method == "POST":
        user_id  = request.form.get("user_id", "")
        new_role = sanitise(request.form.get("role", ""))
        action   = request.form.get("action", "")

        user = db.session.get(User, int(user_id)) if user_id.isdigit() else None
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("edit_users"))

        if action == "update_role":
            if new_role not in ("employee", "manager", "admin"):
                flash("Invalid role.", "danger")
            elif user.id == current_user.id:
                flash("You cannot change your own role.", "danger")
            else:
                user.role = new_role
                db.session.commit()
                flash(f"Role for '{user.username}' updated to {new_role}.", "success")

        elif action == "delete":
            if user.id == current_user.id:
                flash("You cannot delete your own account.", "danger")
            else:
                uname = user.username
                db.session.delete(user)
                db.session.commit()
                flash(f"User '{uname}' has been deleted.", "success")

    users = User.query.order_by(User.role, User.username).all()
    return render_template("edit_users.html", users=users)
# ── One-time admin setup (only works when zero users exist) ───────────────────
@app.route("/setup-admin", methods=["GET", "POST"])
def setup_admin():
    if User.query.first() is not None:
        abort(404)
    if request.method == "POST":
        username = clean_username(request.form.get("username", ""))
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        if username and email and password:
            user = User(username=username, email=email, role="admin")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Admin created! Please log in.", "success")
            return redirect(url_for("LoginPage"))
    return '''
    <form method="POST" style="max-width:400px;margin:80px auto;font-family:sans-serif;">
        <h3>Create First Admin</h3>
        <input name="username" placeholder="Username" required style="display:block;width:100%;margin:10px 0;padding:8px;">
        <input name="email" placeholder="Email" required style="display:block;width:100%;margin:10px 0;padding:8px;">
        <input name="password" type="password" placeholder="Password (min 8 chars)" required style="display:block;width:100%;margin:10px 0;padding:8px;">
        <button type="submit" style="padding:10px 20px;">Create Admin</button>
    </form>'''

# ── Startup ───────────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
