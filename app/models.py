from datetime import datetime
from . import db

class User(db.Model):
 __tablename__ = "users"

 id = db.Column(db.Integer, primary_key=True)
 email = db.Column(db.String(255), unique=True, nullable=False, index=True)
 password_hash = db.Column(db.String(255), nullable=False)

 failed_attempts = db.Column(db.Integer, default=0, nullable=False)
 locked_until = db.Column(db.DateTime, nullable=True)

 created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
 last_login = db.Column(db.DateTime, nullable=True)

class AuditLog(db.Model):
 __tablename__ = "audit_logs"

 id = db.Column(db.Integer, primary_key=True)
 event = db.Column(db.String(64), nullable=False) # REGISTER, LOGIN_SUCCESS, LOGIN_FAIL, LOCKOUT
 email = db.Column(db.String(255), nullable=True)
 ip_address = db.Column(db.String(64), nullable=True)
 created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)