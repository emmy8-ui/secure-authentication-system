import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

db = SQLAlchemy()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)

def create_app():
    load_dotenv()

    app = Flask(__name__)

# Security: secret key (used for Flask + JWT signing)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

# Database: SQLite stored in project folder
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///auth.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Auth settings
    app.config["JWT_ALG"] = "HS256"
    app.config["JWT_EXPIRES_MINUTES"] = int(os.getenv("JWT_EXPIRES_MINUTES", "30"))
    app.config["MAX_FAILED_LOGINS"] = int(os.getenv("MAX_FAILED_LOGINS", "5"))
    app.config["LOCKOUT_MINUTES"] = int(os.getenv("LOCKOUT_MINUTES", "10"))

    db.init_app(app)
    limiter.init_app(app)

# Register blueprints
    from .auth import auth_bp
    from .routes import main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

# Create tables
    with app.app_context():
       db.create_all()

    return app