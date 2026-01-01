# secure-authentication-system
A Flask-based authentication API that demonstrates secure password handling, login validation, rate limiting, account lockout protection, and automated testing using pytest.
This project is designed as a backend-focused security system in order to facilitate my learning of real-world authentication practices

Features
- User registration and login
- Secure password hashing
- JSON based API responses
- Account lockout after repeated failed logins
- JWT-style session handling (configurable)
- Rate limiting for authentication endpoints
- Environment-based configuration
- Automated tests with pytest

Tech Stack
- Python
- Flask
- Flask SQLAlchemy
- Werkzeug Security
- Flask-limiter
- Pytest
- SQLite
