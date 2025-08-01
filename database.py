import sqlite3
import os

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threats.db")

def init_db():
    """Initialize the database and create necessary tables."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            domain TEXT PRIMARY KEY,
            added_on TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            resolved_ip TEXT,
            queried_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def log_dns_query(domain, resolved_ip):
    """Logs a DNS query into the database."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO dns_queries (domain, resolved_ip) VALUES (?, ?)", (domain, resolved_ip))
    conn.commit()
    conn.close()

def get_recent_queries(limit=10):
    """Fetch the most recent DNS queries."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT domain, resolved_ip, queried_at FROM dns_queries ORDER BY queried_at DESC LIMIT ?", (limit,))
    queries = cursor.fetchall()
    conn.close()
    return queries

if __name__ == "__main__":
    init_db()
