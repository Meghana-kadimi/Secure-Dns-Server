import sqlite3
import os
import socket
import logging
from datetime import datetime, timezone
from subprocess import run

# Database Path
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threats.db")

def is_domain_malicious(domain):
    """Check if a domain exists in the threats database."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM threats WHERE domain = ?", (domain,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        logging.error(f"Error accessing database: {e}")
        return False

def resolve_dns(domain):
    """Resolve DNS and block malicious domains."""
    if is_domain_malicious(domain):
        logging.warning(f"🚫 Blocked: {domain}")
        return "0.0.0.0"  # Block the domain by returning a fake IP
    
    try:
        ip = socket.gethostbyname(domain)
        logging.info(f"✅ Resolved: {domain} -> {ip}")
        return ip
    except socket.gaierror:
        logging.error(f"❌ Unable to resolve: {domain}")
        return "0.0.0.0"  # If the domain can't be resolved, return a fake IP

def add_malicious_domain(domain):
    """Add a new malicious domain to the threats database."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO threats (domain) VALUES (?)", (domain,))
        conn.commit()
        conn.close()
        logging.info(f"Added new malicious domain: {domain}")
    except Exception as e:
        logging.error(f"Error adding domain to database: {e}")

def remove_malicious_domain(domain):
    """Remove a domain from the threats database."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM threats WHERE domain = ?", (domain,))
        conn.commit()
        conn.close()
        logging.info(f"Removed malicious domain: {domain}")
    except Exception as e:
        logging.error(f"Error removing domain from database: {e}")

def generate_blocklist():
    """Generate the Unbound blocklist based on the current threats database."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT domain FROM threats")
    domains = cursor.fetchall()
    
    blocklist_file_path = "/etc/unbound/unbound_blocklist.conf"
    
    with open(blocklist_file_path, "w") as file:
        for domain in domains:
            file.write(f"local-zone: \"{domain[0]}\" refuse\n")
    
    conn.close()
    logging.info(f"✅ Unbound blocklist generated at {blocklist_file_path}")
    
    # Restart Unbound to apply the updated blocklist
    restart_unbound_service()

def restart_unbound_service():
    """Restart Unbound DNS service to apply new blocklist."""
    try:
        run(["sudo", "systemctl", "restart", "unbound"], check=True)
        logging.info("✅ Unbound service restarted to apply blocklist.")
    except Exception as e:
        logging.error(f"❌ Error restarting Unbound service: {e}")
