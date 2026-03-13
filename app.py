import os 
import jwt
import time
import bcrypt

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from supabase import create_client

load_dotenv() 
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
port = os.environ.get("PORT")
user = os.environ.get("USER")

supabase = create_client(url, key)

app = Flask(__name__)
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)


@app.route('/health')
def check():
    return 'Server is working'

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    result = (
        supabase.table("IAM")
        .select("id,email,password")
        .eq("email", email)
        .limit(1)
        .execute()
    )

    if not result.data:
        return jsonify({"error": "invalid credentials"}), 401

    user_row = result.data[0]
    stored_hash = user_row.get("password")
    if not stored_hash:
        return jsonify({"error": "invalid credentials"}), 401

    ok = bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    if not ok:
        return jsonify({"error": "invalid credentials"}), 401

    payload = {
        "sub": data.get("email"),
        "iss": user,
        "exp": int(time.time()) + 3600
    }

    with open("private.pem", "r") as f:
        private_key = f.read()

    token = jwt.encode(payload, private_key, algorithm="RS256")

    response = jsonify({"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False, 
        samesite="Lax",
        max_age=3600,
        path="/"
    )

    return response, 200

@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"message": "logged out"})
    response.delete_cookie("access_token", path="/")

    return response, 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(port or 5000))