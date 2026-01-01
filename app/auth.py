import re
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Blueprint, current_app, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash

from . import db, limiter
from .models import User, AuditLog

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

EMAIL_REGEX = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

def log_event(event: str, email: str | None):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    entry = AuditLog(event=event, email=email, ip_address=ip)
    db.session.add(entry)
    db.session.commit()

def validate_password(pw: str) -> tuple[bool, str]:
    # Basic rules
    if len(pw) < 8:
        return False, "Password must be at least 8 characters."
    if not any(c.islower() for c in pw):
        return False, "Password must include a lowercase letter."
    if not any(c.isupper() for c in pw):
        return False, "Password must include an uppercase letter."
    if not any(c.isdigit() for c in pw):
        return False, "Password must include a number."
    if not any(c in "!@#$%^&*()_+-=[]{};':\",.<>/?\\|" for c in pw):
        return False, "Password must include a special character."
    return True, ""

def create_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=current_app.config["JWT_EXPIRES_MINUTES"])
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm=current_app.config["JWT_ALG"])

def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=[current_app.config["JWT_ALG"]],
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        request.user = payload  # attach to request
        return fn(*args, **kwargs)
    return wrapper

@auth_bp.route("/register", methods=["POST"])
@limiter.limit("10/minute")
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not re.match(EMAIL_REGEX, email):
        return jsonify({"error": "Invalid email format"}), 400

    ok, msg = validate_password(password)
    if not ok:
        return jsonify({"error": msg}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    user = User(
        email=email,
        password_hash=generate_password_hash(password),
    )
    db.session.add(user)
    db.session.commit()

    log_event("REGISTER", email)
    return jsonify({"message": "registered successfully"}), 201

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5/minute")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    # Same response style to reduce user enumeration
    generic_error = {"error": "Invalid email or password"}

    user = User.query.filter_by(email=email).first()
    if not user:
        log_event("LOGIN_FAIL", email)
        return jsonify(generic_error), 401

    # lockout check
    now = datetime.utcnow()
    if user.locked_until and user.locked_until > now:
        log_event("LOCKOUT", user.email)
        return jsonify({"error": "Account temporarily locked. Try again later."}), 423

    # password check
    if not check_password_hash(user.password_hash, password):
        user.failed_attempts += 1

        max_fails = current_app.config["MAX_FAILED_LOGINS"]
        if user.failed_attempts >= max_fails:
            lock_minutes = current_app.config["LOCKOUT_MINUTES"]
            user.locked_until = now + timedelta(minutes=lock_minutes)
            log_event("LOCKOUT", user.email)
        else:
            log_event("LOGIN_FAIL", user.email)

        db.session.commit()
        return jsonify(generic_error), 401

    # success
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = now
    db.session.commit()

    token = create_token(user)
    log_event("LOGIN_SUCCESS", user.email)

    return jsonify({"message": "logged in", "token": token}), 200

@auth_bp.route("/me", methods=["GET"])
@require_auth
def me():
    return jsonify({"user": {"id": request.user["sub"], "email": request.user["email"]}}), 200
