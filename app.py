from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import time, hmac, hashlib, struct, bcrypt
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

SECRET = "SUPER_SECRET_KEY_123"

# 1. Connect to Aiven
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

# 2. Create the table automatically (Updated to match your local list)
try:
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        otp VARCHAR(6),
        otp_created_at DATETIME,
        last_login DATETIME
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
    username = data.get('username')
    password = data.get('password')
    
    print(f"--- REGISTERING: {username} ---")

    # Hashing the password correctly
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    db = get_db()
    cursor = db.cursor()
    try:
        # Fixed: using 'username' and 'hashed' instead of 'u' and 'p'
        cursor.execute("INSERT INTO users (username, password, last_login) VALUES (%s, %s, NOW())", (username, hashed))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(f"Register Error: {e}")
        return jsonify({"success": False, "message": str(e)})
    finally:
        cursor.close()
        db.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    db = get_db(); cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    
    if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
        # Update last_login time
        cursor.execute("UPDATE users SET last_login=NOW() WHERE username=%s", (username,))
        db.commit()
        cursor.close(); db.close()
        return jsonify({"success": True})
    
    cursor.close(); db.close()
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
    cursor.close(); db.close()
    return jsonify({"otp": res["otp"] if res else None})

@app.route("/verify_otp", methods=["POST"])
def verify():
    data = request.json
    u, entered_otp = data["username"], data["otp"]
    db = get_db(); cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT otp, otp_created_at FROM users WHERE username=%s", (u,))
    row = cursor.fetchone()
    cursor.close(); db.close()

    if row and row["otp"]:
        diff = (datetime.now() - row["otp_created_at"]).total_seconds()
        if diff > 120:
            return jsonify({"success": False, "message": "OTP Expired (2m)!"})
        if entered_otp == row["otp"]:
            return jsonify({"success": True})
            
    return jsonify({"success": False, "message": "Invalid or Vanished OTP"})

if __name__ == "__main__":
    # Render uses the PORT environment variable
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
