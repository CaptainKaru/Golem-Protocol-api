"""
Golem-Protocol-API v0.9.0
(c) 2025 Talos Inc.
"""

import re
import os
from datetime import datetime

from supabase import create_client, Client
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask("Golem-Protocol-api")
CORS(app)

supabase_url = os.environ.get("SUPABASE_URL", "")
supabase_key = os.environ.get("SUPABASE_KEY", "")
supabase: Client = create_client(supabase_url, supabase_key)

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,16}$")

# messages
MSG_USERNAME_EMPTY = "Username must not be empty."
MSG_EMAIL_INVALID = "Fix email address format."
MSG_PASSWORD_INVALID = (
    "Password must be 8–16 characters; contains at least 1 "
    "uppercase, lowercase, digit, and symbol."
)
MSG_USERNAME_TAKEN = "Username already taken."
MSG_EMAIL_TAKEN = "Email already registered."

MSG_SIGNUP_FAILED = "Sign up failed."
MSG_ACCOUNT_CREATE_FAILED = "Account creation failed."
MSG_SIGNIN_INVALID = "Email/password is incorrect."
MSG_SIGNIN_FAILED = "Sign in failed."
MSG_NOT_FOUND = "Page not found."
MSG_UNAUTHORIZED = "Unauthorized access."


@app.route("/")
def index():
    return set_cors({})


@app.route("/signup", methods=["POST", "OPTIONS"])
def signup():
    if request.method == "OPTIONS":
        return set_cors({})

    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "").strip()
    email = payload.get("email", "").strip().lower()
    pword = payload.get("password", "")

    if not username:
        return set_cors({"success": 0, "message": MSG_USERNAME_EMPTY})

    if not EMAIL_PATTERN.match(email):
        return set_cors({"success": 0, "message": MSG_EMAIL_INVALID})

    if not PWORD_PATTERN.match(pword):
        return set_cors({"success": 0, "message": MSG_PASSWORD_INVALID})

    # Check if username or email already exists in custom user table
    try:
        existing = supabase.table("user").select("username, email").or_(
            f"username.eq.{username},email.eq.{email}"
        ).execute()
        
        if existing.data:
            for record in existing.data:
                if record.get("username") == username:
                    return set_cors({"success": 0, "message": MSG_USERNAME_TAKEN})
                if record.get("email") == email:
                    return set_cors({"success": 0, "message": MSG_EMAIL_TAKEN})
    except Exception as e:
        print(f"User check error: {e}")
        return set_cors({"success": 0, "message": MSG_SIGNUP_FAILED})

    try:
        # Sign up the user in Supabase Auth
        auth_response = supabase.auth.sign_up({
            "email": email,
            "password": pword,
            "options": {
                "data": {
                    "username": username
                }
            }
        })
        auth_user_id = auth_response.user.id
    except Exception as e:
        print(f"Signup error: {e}")
        return set_cors({"success": 0, "message": MSG_SIGNUP_FAILED})

    try:
        # Insert into custom user table (matches schema)
        supabase.table("user").insert({
            "id": auth_user_id,  # Use same UUID as auth.users
            "username": username,
            "email": email,
            "password_hash": generate_password_hash(pword),
            "role": "user",  # Default role
            "is_active": True,
            "is_deleted": False
        }).execute()
    except Exception as e:
        print(f"User insert error: {e}")
        # Clean up auth user if custom table insert fails
        supabase.auth.admin.delete_user(auth_user_id)
        return set_cors({"success": 0, "message": MSG_ACCOUNT_CREATE_FAILED})

    return set_cors({"success": 1, "message": ""})


@app.route("/signin", methods=["POST", "OPTIONS"])
def signin():
    if request.method == "OPTIONS":
        return set_cors({})

    username = ""
    role = ""
    access_token = ""
    
    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "").strip().lower()
    pword = payload.get("password", "")

    if not EMAIL_PATTERN.match(email) or not PWORD_PATTERN.match(pword):
        return set_cors({
            "success": 0,
            "accessToken": access_token,
            "username": username,
            "role": role,
            "message": MSG_SIGNIN_INVALID,
        })

    try:
        # Sign in with Supabase Auth
        data = supabase.auth.sign_in_with_password({
            "email": email,
            "password": pword
        })
        access_token = data.session.access_token
    except Exception as e:
        print(f"Signin error: {e}")
        return set_cors({
            "success": 0,
            "accessToken": access_token,
            "username": username,
            "role": role,
            "message": MSG_SIGNIN_FAILED,
        })

    try:
        # Fetch user details from custom user table using auth.uid() via RLS
        # We need to set the session for RLS to work
        supabase.auth.set_session(access_token, data.session.refresh_token)
        
        response = supabase.table("user").select("username, role").eq("email", email).execute()
        
        if response.data:
            username = response.data[0].get("username", "")
            role = response.data[0].get("role", "user")
    except Exception as e:
        print(f"User fetch error: {e}")
        return set_cors({
            "success": 0,
            "accessToken": access_token,
            "username": username,
            "role": role,
            "message": MSG_SIGNIN_FAILED,
        })

    return set_cors({
        "success": 1,
        "accessToken": access_token,
        "username": username,
        "role": role,
        "message": "",
    })


# Protected endpoint example - requires valid access token
@app.route("/me", methods=["GET", "OPTIONS"])
def get_current_user():
    if request.method == "OPTIONS":
        return set_cors({})
    
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return set_cors({"success": 0, "message": MSG_UNAUTHORIZED}), 401
    
    token = auth_header.split(" ")[1]
    
    try:
        supabase.auth.set_session(token, None)
        user = supabase.auth.get_user()
        user_id = user.user.id
        
        response = supabase.table("user").select("*").eq("id", user_id).execute()
        
        if not response.data:
            return set_cors({"success": 0, "message": "User not found"}), 404
        
        user_data = response.data[0]
        return set_cors({
            "success": 1,
            "id": user_data["id"],
            "username": user_data["username"],
            "email": user_data["email"],
            "role": user_data["role"],
            "is_active": user_data["is_active"],
            "created_at": user_data["created_at"]
        })
    except Exception as e:
        print(f"Me endpoint error: {e}")
        return set_cors({"success": 0, "message": MSG_UNAUTHORIZED}), 401


@app.route("/golems", methods=["GET", "OPTIONS"])
def get_golems():
    if request.method == "OPTIONS":
        return set_cors({})
    
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return set_cors({"success": 0, "message": MSG_UNAUTHORIZED}), 401
    
    token = auth_header.split(" ")[1]
    
    try:
        supabase.auth.set_session(token, None)
        user = supabase.auth.get_user()
        user_id = user.user.id
        
        # Get user's role from custom table
        user_response = supabase.table("user").select("role").eq("id", user_id).execute()
        user_role = user_response.data[0].get("role", "user") if user_response.data else "user"
        
        if user_role == "admin":
            # Admins can see all non-deleted golems
            response = supabase.table("golem").select("*").eq("is_deleted", False).execute()
        else:
            # Regular users see their own golems + public golems
            response = supabase.table("golem").select("*").or_(
                f"owner_id.eq.{user_id},is_public.eq.true"
            ).eq("is_deleted", False).execute()
        
        return set_cors({
            "success": 1,
            "golems": response.data if response.data else []
        })
    except Exception as e:
        print(f"Get golems error: {e}")
        return set_cors({"success": 0, "message": str(e)}), 500


@app.route("/golems", methods=["POST", "OPTIONS"])
def create_golem():
    if request.method == "OPTIONS":
        return set_cors({})
    
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return set_cors({"success": 0, "message": MSG_UNAUTHORIZED}), 401
    
    token = auth_header.split(" ")[1]
    payload = request.get_json(silent=True) or {}
    
    name = payload.get("name", "").strip()
    description = payload.get("description", "")
    avatar_url = payload.get("avatar_url", "")
    is_public = payload.get("is_public", False)
    
    if not name:
        return set_cors({"success": 0, "message": "Golem name is required"}), 400
    
    try:
        supabase.auth.set_session(token, None)
        user = supabase.auth.get_user()
        user_id = user.user.id
        
        response = supabase.table("golem").insert({
            "owner_id": user_id,
            "name": name,
            "description": description,
            "avatar_url": avatar_url,
            "is_public": is_public,
            "is_deleted": False
        }).execute()
        
        return set_cors({
            "success": 1,
            "golem": response.data[0] if response.data else {}
        })
    except Exception as e:
        print(f"Create golem error: {e}")
        return set_cors({"success": 0, "message": str(e)}), 500


@app.errorhandler(404)
def page_not_found(e):
    return set_cors({"message": MSG_NOT_FOUND})


def set_cors(payload, status_code=200):
    response = jsonify(payload)
    response.status_code = status_code
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    return response


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)