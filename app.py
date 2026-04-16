from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import time, hmac, hashlib, struct, bcrypt
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

SECRET = "SUPER_SECRET_KEY_123"

# 1. Connect to Aiven (Using your Service URI)
def get_db():
    return mysql.connector.connect(
        host="mysql-32bffbe3-soshteshrimat-c34a.d.aivencloud.com",
        user="avnadmin",
        password="AVNS_8w1r9ZNS4ptYvZUPJ4P", # Replace this if you changed your password
        port=15210,
        database="defaultdb",
        ssl_disabled=False  # This forces the SSL connection Aiven wants
    )

# 2. Create the table automatically on startup
try:
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        otp VARCHAR(6),
        otp_created_at DATETIME
    )
    """)
    db.commit()
    cursor.close()
    db.close()
    print("Database table ready!")
except Exception as e:
    print(f"Database error: {e}")

def generate_otp_logic(username):
    T = int(time.time()) // 30
    counter = struct.pack(">Q", T)
    data = counter + username.encode()
    hs = hmac.new(SECRET.encode(), data, hashlib.sha1).digest()
    offset = hs[-1] & 0x0F
    p = hs[offset:offset + 4]
    num = (((p[0] & 0x7F) << 24) | (p[1] << 16) | (p[2] << 8) | p[3])
    return str(num % 1000000).zfill(6)

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    u, p = data["username"], data["password"]
    db = get_db(); cursor = db.cursor()
    hashed = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (u, hashed))
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
    cursor.execute("SELECT * FROM users WHERE username=%s", (data["username"],))
    user = cursor.fetchone()
    cursor.close()
    db.close()
    if user and bcrypt.checkpw(data["password"].encode(), user["password"].encode()):
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Invalid Login"})

@app.route("/request_otp", methods=["POST"])
@app.route("/resend_otp", methods=["POST"])
def handle_otp():
    user = request.json["username"]
    otp = generate_otp_logic(user)
    db = get_db(); cursor = db.cursor()
    cursor.execute("UPDATE users SET otp=%s, otp_created_at=NOW() WHERE username=%s", (otp, user))
    db.commit(); cursor.close(); db.close()
    return jsonify({"success": True})

@app.route("/get_otp/<username>", methods=["GET"])
def get_otp(username):
    db = get_db(); cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT otp FROM users WHERE username=%s", (username,))
    res = cursor.fetchone()
    cursor.close()
    db.close()
    return jsonify({"otp": res["otp"] if res else None})

@app.route("/verify_otp", methods=["POST"])
def verify():
    data = request.json
    u, entered_otp = data["username"], data["otp"]
    db = get_db(); cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT otp, otp_created_at FROM users WHERE username=%s", (u,))
    row = cursor.fetchone()
    cursor.close()
    db.close()

    if row and row["otp"]:
        diff = (datetime.now() - row["otp_created_at"]).total_seconds()
        if diff > 120:
            return jsonify({"success": False, "message": "OTP Expired (2m)!"})
        if entered_otp == row["otp"]:
            return jsonify({"success": True})
            
    return jsonify({"success": False, "message": "Invalid or Vanished OTP"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
    app.run(debug=True, port=5000)
