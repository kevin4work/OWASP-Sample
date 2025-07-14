from flask import Flask, request
import sqlite3
import subprocess
import pickle
import hashlib

app = Flask(__name__)

# A7: Identification Failures
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']  # No rate limiting or MFA
    
    # A2: Cryptographic Failures (weak hashing)
    hashed_pass = hashlib.md5(password.encode()).hexdigest()  # Weak algorithm
    
    # A3: SQL Injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{hashed_pass}'")
    return "Logged in" if cursor.fetchone() else "Failed"

# A1: Broken Access Control
@app.route('/admin')
def admin_panel():
    if 'admin' in request.cookies:  # Unsafe admin check
        return "Admin dashboard"
    return "Access denied"

# A8: Deserialization Vulnerability
@app.route('/deserialize')
def deserialize():
    data = request.cookies.get('data')
    return pickle.loads(data)  # Unsafe deserialization

# A10: SSRF & A9: Security Logging Failures
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    subprocess.call(f"curl {url}", shell=True)  # SSRF + Command Injection
    # No logging of the event
    return "Done"

# A4: Insecure Design (hardcoded creds)
API_KEY = "supersecret123"  # Hardcoded secret

if __name__ == '__main__':
    app.run(debug=True)  # A5: Debug mode enabled in production