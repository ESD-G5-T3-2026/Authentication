import os 
import jwt
import time
import bcrypt

from flasgger import Swagger
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from supabase import create_client

load_dotenv() 
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
port = os.environ.get("PORT")
user = os.environ.get("USER")
frontend_origins = os.environ.get("ORIGIN")

supabase = create_client(url, key)

app = Flask(__name__)
swagger = Swagger(app)
CORS(
    app,
    resources={r"/*": {"origins": frontend_origins}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)


@app.route('/health')
def health():
    """
    Health Check
    ---
    responses:
      200:
        description: Server is working
        schema:
          type: string
    """
    return 'Server is working'

@app.route("/login", methods=["POST"])
def login():
    """
    User Login
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
              required: true
            password:
              type: string
              required: true
    responses:
      200:
        description: Login successful, returns user info and sets access_token cookie
        schema:
          type: object
          properties:
            message:
              type: string
            user:
              type: object
              properties:
                email:
                  type: string
                club_id:
                  type: integer
      400:
        description: Missing email or password
      401:
        description: Invalid credentials
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    result = (
        supabase.table("IAM")
        .select("id,email,password,club_id")
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
        "club_id": user_row.get("club_id"),
        "iss": user,
        "exp": int(time.time()) + 3600
    }

    with open("private.pem", "r") as f:
        private_key = f.read()

    token = jwt.encode(payload, private_key, algorithm="RS256")

    response = jsonify(
        {
            "message": "Login successful",
            "user": {
                "email": user_row.get("email"),
                "club_id": user_row.get("club_id"),
            },
        }
    )
    cookie_kwargs = {
        "key": "access_token",
        "value": token,
        "httponly": True,
        "secure": True,
        "samesite": "None",
        "max_age": 3600,
        "path": "/",
    }

    response.set_cookie(**cookie_kwargs)

    return response, 200

@app.route("/logout", methods=["POST"])
def logout():
    """
    User Logout
    ---
    responses:
      200:
        description: Logout successful, access_token cookie deleted
        schema:
          type: object
          properties:
            message:
              type: string
    """
    response = jsonify({"message": "logged out"})
    response.delete_cookie("access_token", path="/", secure=True, samesite="None")

    return response, 200

@app.route("/check", methods=["GET"])
def check():
    """
    Check Authentication
    ---
    responses:
      200:
        description: Returns authenticated user info
        schema:
          type: object
          properties:
            user:
              type: object
              properties:
                email:
                  type: string
                club_id:
                  type: integer
      401:
        description: Unauthorized or token expired/invalid
        schema:
          type: object
          properties:
            error:
              type: string
    """
    token = request.cookies.get("access_token")
    if not token:
        return jsonify({"error": "unauthorized"}), 401

    try:
        with open("public.pem", "r") as f:
            public_key = f.read()

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=user,
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 401

    return jsonify(
        {
            "user": {
                "email": payload.get("sub"),
                "club_id": payload.get("club_id"),
            }
        }
    ), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(port or 5000))