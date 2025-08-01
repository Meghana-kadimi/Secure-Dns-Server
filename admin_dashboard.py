from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import os
import logging
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threats.db")
LOG_FILE = "dns_logs.txt"

# Email Configuration (Use environment variables for security)
ALERT_EMAIL = "1203sap@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = os.getenv("EMAIL_USER", "1203sap@gmail.com")
EMAIL_PASS = os.getenv("EMAIL_PASS", "gymb tpwr wufo wmwb")

# Logging setup
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# Admin Credentials (replace with DB in production)
ADMIN_USER = "hack"
ADMIN_PASS = "123456789"

# --- Utility Functions ---
def send_email_alert(username, status):
    subject = f"ALERT: {status} Login Attempt"
    body = f"User {username} attempted to login. Status: {status}."
    msg = MIMEText(body)
    msg["From"] = EMAIL_USER
    msg["To"] = ALERT_EMAIL
    msg["Subject"] = subject

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, ALERT_EMAIL, msg.as_string())
        server.quit()
        print("✅ Email Alert Sent!")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def log_login_attempt(username, status):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"LOGIN ATTEMPT - User: {username}, Status: {status}\n")
    send_email_alert(username, status)

# --- Authentication Routes ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == ADMIN_USER and password == ADMIN_PASS:
            session["logged_in"] = True
            log_login_attempt(username, "SUCCESS")
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            log_login_attempt(username, "FAILED")
            flash("Invalid credentials!", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/")
def dashboard():
    if not session.get("logged_in"):
        flash("You must log in first!", "warning")
        return redirect(url_for("login"))
    return render_template("dashboard.html")

# --- Threat Intelligence Functions ---
@app.route("/api/threats", methods=["GET"])
def get_threats_api():
    limit = request.args.get("limit", default=None, type=int)
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    if limit:
        cursor.execute("SELECT domain FROM threats ORDER BY rowid DESC LIMIT ?", (limit,))
    else:
        cursor.execute("SELECT domain FROM threats")
        
    threats = [row[0] for row in cursor.fetchall()]
    conn.close()

    return jsonify({"threats": threats})

def get_dns_logs(limit=10):
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        return lines[-limit:]
    except FileNotFoundError:
        return ["No logs available"]

def get_login_logs(limit=10):
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        return {"logs": lines[-limit:]}
    except FileNotFoundError:
        return {"logs": ["No logs available."]}

def add_threat(domain):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO threats (domain) VALUES (?)", (domain,))
    conn.commit()
    conn.close()

def remove_threat(domain):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM threats WHERE domain = ?", (domain,))
    conn.commit()
    conn.close()

def check_domain_exists(domain):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM threats WHERE domain = ?", (domain,))
    exists = cursor.fetchone()
    conn.close()
    return exists is not None

# --- API Routes ---
@app.route("/api/threats")
def api_threats():
    return jsonify(get_threats_api())

@app.route("/api/check_domain")
def api_check_domain():
    domain = request.args.get("domain")
    exists = check_domain_exists(domain)
    return jsonify({"exists": exists})


@app.route("/api/logs")
def api_logs():
    return jsonify(get_dns_logs())

@app.route("/api/login_logs")
def api_login_logs():
    return jsonify(get_login_logs())

@app.route("/add_threat", methods=["POST"])
def add_threat_route():
    if not session.get("logged_in"):
        flash("You must log in first!", "warning")
        return redirect(url_for("login"))

    domain = request.form["domain"].strip().lower()

    if check_domain_exists(domain):
        flash(f"⚠️ Domain '{domain}' already exists in the threat list.", "warning")
    else:
        add_threat(domain)
        if check_domain_exists(domain):  # Confirm it was added
            flash(f"✅ Domain '{domain}' successfully added to the threat list.", "success")
        else:
            flash(f"❌ Failed to add domain '{domain}'.", "danger")

    return redirect(url_for("dashboard"))


@app.route("/remove_threat", methods=["POST"])
def remove_threat_route():
    if not session.get("logged_in"):
        flash("You must log in first!", "warning")
        return redirect(url_for("login"))

    domain = request.form["domain"].strip().lower()

    if not check_domain_exists(domain):
        flash(f"⚠️ Domain '{domain}' not found in the threat list.", "danger")
    else:
        remove_threat(domain)
        if not check_domain_exists(domain):  # Confirm it was removed
            flash(f"✅ Domain '{domain}' successfully removed from the threat list.", "success")
        else:
            flash(f"❌ Failed to remove domain '{domain}'.", "danger")

    return redirect(url_for("dashboard"))


@app.route("/check_domain", methods=["GET"])
def check_domain_route():
    domain = request.args.get("domain")
    if domain:
        exists = check_domain_exists(domain)
        if exists:
            return jsonify({"message": f"🚫 Blocked – The domain '{domain}' is in the threat list.", "blocked": True})
        else:
            return jsonify({"redirect": f"http://{domain}", "blocked": False})
    return jsonify({"message": "❌ No domain provided."}), 400



if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
