import os
import jwt
import time
import logging

logger = logging.getLogger("cloudshield.auth")

JWT_SECRET = os.environ.get("JWT_SECRET", "super-secret-dev-key")
JWT_ALGORITHM = "HS256"

# Mock Database of users for the SOC Platform
USERS = {
    "admin": {"password": "password123", "role": "admin", "name": "Admin User"},
    "analyst": {"password": "password123", "role": "analyst", "name": "SOC Analyst"}
}

def verify_credentials(username, password):
    if username in USERS and USERS[username]["password"] == password:
        return USERS[username]
    return None

def generate_token(username, role):
    payload = {
        "sub": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + (24 * 3600)  # 24 hour expiry
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}
