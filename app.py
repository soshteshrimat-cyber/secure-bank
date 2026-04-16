from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import time, hmac, hashlib, struct, bcrypt
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

SECRET = "SUPER_SECRET_KEY_123"

def get_db():
    return mysql.connector.connect(
        host="mysql-32bffbe3-soshteshrimat-c34a.d.aivencloud.com",
        user="avnadmin",
        password="AVNS_8w1r9ZNS4ptYvZUPJ4P", 
        port=15210,
        database="defaultdb",
        ssl_ca=None,
        ssl_verify_cert=False,
        ssl_disabled=False,
        connection_timeout=10
    )

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"success": False, "message": "Missing details"})

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password, last_login) VALUES (%s, %s, NOW())", (username, hashed))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})
    finally:
        cursor.close()
        db.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    db = get_db(); cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (data.get("username"),))
    user = cursor.fetchone()
    if user and bcrypt.checkpw(data.get("password").encode(), user["password"].encode()):
        cursor.execute("UPDATE users SET last_login=NOW() WHERE username=%s", (data.get("username"),))
        db.commit()
        cursor.close(); db.close()
        return jsonify({"success": True})
    cursor.close(); db.close()
    return jsonify({"success": False, "message": "Invalid Login"})

# --- Keep your other OTP routes (handle_otp, get_otp, verify) the same as before ---

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
