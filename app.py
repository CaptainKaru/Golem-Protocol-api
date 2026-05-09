"""
Golem-Protocol-API v0.9.0
(c) 2025 Talos Inc.
""" 
import re
import os

from supabase import create_client, Client
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask("Golem-Protocol-api")
CORS(app)

supabase_url = os.environ.get("SUPABASE_URL", "")
supabase_key = os.environ.get("SUPABASE_KEY", "")
supabase: Client = create_client(supabase_url, supabase_key)

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,16}$")

# messages
MSG_FULLNAME_EMPTY = "Full name must not be empty."
MSG_EMAIL_INVALID = "Fix email address format."
MSG_PASSWORD_INVALID = (
    "Password must be 8–16 characters; contains at least 1 "
    "uppercase, lowercase, digit, and symbol."
)

MSG_SIGNUP_FAILED = "Sign up failed."
MSG_ACCOUNT_CREATE_FAILED = "Account creation failed."
MSG_SIGNIN_INVALID = "Email/password is incorrect."
MSG_SIGNIN_FAILED = "Sign in failed."
MSG_NOT_FOUND = "Page not found."

@app.route("/")
def index():
    return set_cors({})

@app.route("/signup", methods=["POST", "OPTIONS"])
def signup():
    if request.method == "OPTIONS":
        return set_cors({})

    payload = request.get_json(silent=True) or {}
    full_name = payload.get("fullName", "").strip()
    email = payload.get("email", "").strip().lower()
    pword = payload.get("password", "")

    if not full_name:
        return set_cors({"success": 0, "message": MSG_FULLNAME_EMPTY})

    if not EMAIL_PATTERN.match(email):
        return set_cors({"success": 0, "message": MSG_EMAIL_INVALID})

    if not PWORD_PATTERN.match(pword):
        return set_cors({"success": 0, "message": MSG_PASSWORD_INVALID})

    try:
        # Sign up the user - this creates the user in auth.users
        auth_response = supabase.auth.sign_up(
            {
                "email": email,
                "password": pword,
                "options": {
                    "email_redirect_to": "https://golem-protocol.vercel.app/login",
                },
            }
        )
        
        # Get the user's auth ID from the response
        # This will be used for the foreign key reference auth.users(id)
        auth_user_id = auth_response.user.id
        
    except Exception as e:
        print(f"Signup error: {e}")
        return set_cors({"success": 0, "message": MSG_SIGNUP_FAILED})
    
    try:
        # Insert into user table with auth_id (foreign key to auth.users)
        # The profile will be automatically created by the trigger
        supabase.from_("user").insert({
            "auth_id": auth_user_id,
            "full_name": full_name,
            "email": email,
            "role": 0,
        }).execute()
    except Exception as e:
        print(f"User insert error: {e}")
        return set_cors({"success": 0, "message": MSG_ACCOUNT_CREATE_FAILED})

    return set_cors({"success": 1, "message": ""})

@app.route("/signin", methods=["POST", "OPTIONS"])
def signin():
    if request.method == "OPTIONS":
        return set_cors({})

    full_name = ""
    user_level = -1
    access_token = ""
    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "").strip().lower()
    pword = payload.get("password", "")

    if not (EMAIL_PATTERN.match(email) and PWORD_PATTERN.match(pword)):
        return set_cors(
            {
                "success": 0,
                "accessToken": access_token,
                "userLevel": user_level,
                "fullName": full_name,
                "message": MSG_SIGNIN_INVALID,
            }
        )
    
    try:
        # Sign in with password - authenticates against auth.users
        data = supabase.auth.sign_in_with_password({
            "email": email, "password": pword
        })
        access_token = data.session.access_token
    except Exception as e:
        print(f"Signin error: {e}")
        return set_cors(
            {
                "success": 0,
                "accessToken": access_token,
                "userLevel": user_level,
                "fullName": full_name,
                "message": MSG_SIGNIN_FAILED,
            }
        )
    
    try:
        # Fetch user details from custom user table
        # The RLS policy will ensure only the authenticated user can access their data
        response = (
            supabase.table("user")
            .select("full_name, role")
            .eq("email", email)
            .execute()
        )
        
        if response.data:
            full_name = response.data[0].get("full_name", "")
            user_level = response.data[0].get("role", -1)
            
    except Exception as e:
        print(f"User fetch error: {e}")
        return set_cors(
            {
                "success": 0,
                "accessToken": access_token,
                "userLevel": user_level,
                "fullName": full_name,
                "message": MSG_SIGNIN_FAILED,
            }
        )

    return set_cors(
        {
            "success": 1,
            "accessToken": access_token,
            "userLevel": user_level,
            "fullName": full_name,
            "message": "",
        }
    )

@app.errorhandler(404)
def page_not_found(e):
    return set_cors({"message": MSG_NOT_FOUND})

def set_cors(payload):
    response = jsonify(payload)
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    return response

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)