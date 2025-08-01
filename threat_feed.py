import requests
import sqlite3
import os
from datetime import datetime, timezone

# Database Path
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threats.db")

# Threat Intelligence Feeds
THREAT_INTEL_FEEDS = [
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://www.spamhaus.org/drop/drop.txt",
]

def update_threat_db():
    """Fetches threat intelligence feeds and updates the threats database."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Ensure threats table exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            domain TEXT PRIMARY KEY,
            added_on TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    total_new_domains = 0  # Track the total new threats added

    for feed in THREAT_INTEL_FEEDS:
        try:
            response = requests.get(feed, timeout=5)

            if response.status_code == 200:
                threat_domains = [
                    (domain.strip(), datetime.now(timezone.utc).isoformat())  # Convert datetime to ISO format
                    for domain in response.text.splitlines()
                    if domain.strip() and not domain.startswith("#") and "." in domain
                ]

                if threat_domains:
                    cursor.executemany("INSERT OR IGNORE INTO threats (domain, added_on) VALUES (?, ?)", threat_domains)
                    new_domains = cursor.rowcount  # Number of new entries inserted
                    total_new_domains += new_domains
                    print(f"✅ {new_domains} new threats added from {feed}")
                else:
                    print(f"⚠️ No valid threats found in {feed}")

            else:
                print(f"⚠️ Failed to fetch feed: {feed} - Status Code: {response.status_code}")

        except Exception as e:
            print(f"❌ Error fetching threat feed {feed}: {e}")

    conn.commit()
    conn.close()
    
    print(f"✅ Threat database update completed. {total_new_domains} new threats added.")

if __name__ == "__main__":
    update_threat_db()
