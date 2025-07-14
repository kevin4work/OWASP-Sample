import hashlib
import os
import pickle
import sqlite3
import subprocess
import base64
import requests

from flask import Flask, request, redirect, render_template_string

# To run this application, you need to install Flask:
# pip install Flask requests

app = Flask(__name__)

# --- Database Setup ---
# This setup is for demonstration purposes. It creates an in-memory database.
def get_db_connection():
    """Establishes a connection to the in-memory SQLite database."""
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database with a users table and some data."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );
    """)
    # OWASP A02:2021 - Cryptographic Failures (using a weak hashing algorithm)
    # The password 'adminpass' is hashed with MD5, which is not secure.
    hashed_password = hashlib.md5(b'adminpass').hexdigest()
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                   ('admin', hashed_password, 'admin'))
    conn.commit()
    conn.close()

# Initialize the database when the app starts
with app.app_context():
    init_db()

# --- Vulnerable Code Sections ---

@app.route('/')
def index():
    """Main page with links to vulnerable sections."""
    return """
    <h1>OWASP Top 10 Vulnerable Application</h1>
    <p>This application contains intentional vulnerabilities for testing security scanners.</p>
    <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/user_details?username=admin">User Details (SQL Injection)</a></li>
        <li><a href="/admin/dashboard">Admin Dashboard (Broken Access Control)</a></li>
        <li><a href="/fetch_url?url=https://example.com">Fetch URL (SSRF)</a></li>
        <li><a href="/deserialize?data=gASVBwAAAAAAAACMCGRpbmdoYQAAAAAATElOVVhYAwAAAHVucG9wLg==">Deserialize Data (Insecure Deserialization)</a></li>
        <li><a href="/redirect?url=http://example.com">Open Redirect</a></li>
    </ul>
    """

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page with multiple vulnerabilities.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        cursor = conn.cursor()

        # OWASP A07:2021 - Identification and Authentication Failures
        # No brute-force protection (e.g., rate limiting, account lockout).
        # Also, user enumeration is possible due to different responses.
        
        # OWASP A02:2021 - Cryptographic Failures
        # The provided password is being hashed with the same weak algorithm (MD5) for comparison.
        hashed_password = hashlib.md5(password.encode()).hexdigest()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            if user['password'] == hashed_password:
                return f"Login successful for user: {user['username']}"
            else:
                # OWASP A09:2021 - Security Logging and Monitoring Failures
                # A failed login attempt is a critical security event that is not being logged here.
                return "Login failed: Incorrect password."
        else:
            return "Login failed: User not found."
        conn.close()

    return """
    <form method="post">
        <h2>Login</h2>
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    """

@app.route('/user_details')
def user_details():
    """
    This endpoint is vulnerable to SQL Injection.
    """
    username = request.args.get('username')
    conn = get_db_connection()
    cursor = conn.cursor()

    # OWASP A03:2021 - Injection
    # The user input is directly concatenated into the SQL query, allowing for SQL Injection.
    # Example exploit: /user_details?username=' OR 1=1 --
    query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            return f"User details: ID={user['id']}, Username={user['username']}, Role={user['role']}"
        else:
            return "User not found."
    except sqlite3.Error as e:
        return f"Database error: {e}"
    finally:
        conn.close()

@app.route('/admin/dashboard')
def admin_dashboard():
    """
    This endpoint is vulnerable to Broken Access Control.
    """
    # OWASP A01:2021 - Broken Access Control
    # The application should check if the logged-in user has the 'admin' role.
    # Here, it only checks for a query parameter, which is easily manipulated by any user.
    # A secure implementation would check a server-side session variable.
    is_admin = request.args.get('is_admin', 'false').lower() == 'true'

    if is_admin:
        return "Welcome to the admin dashboard!"
    else:
        return "Access Denied. You are not an admin.", 403

@app.route('/fetch_url')
def fetch_url():
    """
    This endpoint is vulnerable to Server-Side Request Forgery (SSRF).
    """
    url = request.args.get('url')

    # OWASP A10:2021 - Server-Side Request Forgery (SSRF)
    # The server makes a request to a URL provided by the user without validating it.
    # An attacker can use this to scan internal networks, access cloud metadata, etc.
    # Example exploit: /fetch_url?url=http://127.0.0.1:5000/admin/dashboard?is_admin=true
    if url:
        try:
            response = requests.get(url, timeout=3)
            return response.text
        except requests.exceptions.RequestException as e:
            return f"Error fetching URL: {e}", 500
    return "Please provide a 'url' parameter."

@app.route('/deserialize')
def deserialize_data():
    """
    This endpoint is vulnerable to Insecure Deserialization.
    """
    data = request.args.get('data')
    
    # OWASP A08:2021 - Software and Data Integrity Failures (Insecure Deserialization)
    # Deserializing data from untrusted sources using 'pickle' can lead to Remote Code Execution (RCE).
    # The provided example data is a base64 encoded pickle payload for `os.system('uname -a')`.
    if data:
        try:
            decoded_data = base64.b64decode(data)
            deserialized_object = pickle.loads(decoded_data)
            return f"Deserialized object: {deserialized_object}"
        except Exception as e:
            return f"Deserialization error: {e}"
    return "Please provide base64 encoded pickle data in the 'data' parameter."

@app.route('/redirect')
def open_redirect():
    """
    This endpoint is vulnerable to Open Redirect. This is often part of A01:2021.
    """
    url = request.args.get('url')
    # The application redirects to a user-supplied URL without validation.
    # This can be used for phishing attacks.
    if url:
        return redirect(url)
    return "Please provide a 'url' to redirect to."

# OWASP A04:2021 - Insecure Design
# The entire application demonstrates insecure design. There is no central authentication,
# authorization checks are missing or flawed, and input validation is inconsistent.
# For example, a password reset feature might be designed to send the new password
# to the user's browser, which is an insecure practice.

# OWASP A06:2021 - Vulnerable and Outdated Components
# This vulnerability depends on the libraries used. If this application were using an old
# version of Flask or requests with a known CVE, it would be vulnerable.
# For example, if `requirements.txt` specified `PyYAML==5.3`, a scanner
# should flag it for a known RCE vulnerability.

if __name__ == '__main__':
    # OWASP A05:2021 - Security Misconfiguration
    # Running a Flask application with debug mode enabled in a production environment
    # is a major security risk. It can expose sensitive information and allow for
    # arbitrary code execution through the Werkzeug debugger.
    app.run(debug=True, host='0.0.0.0', port=5000)