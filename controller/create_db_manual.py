"""
Database Initialization Script
Run this to create tables if they don't exist.
It will NOT delete existing data.
"""
import sqlite3
import os

# Get the directory of this script
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'nids.db')

print(f"Checking database at: {db_path}")

# Connect to database (creates it if not exists)
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create sensor_node table
cursor.execute('''
CREATE TABLE IF NOT EXISTS sensor_node (
    id VARCHAR(50) PRIMARY KEY,
    ip VARCHAR(50),
    trust_score REAL DEFAULT 50.0,
    last_seen DATETIME,
    status VARCHAR(20) DEFAULT 'offline'
)
''')
print("✅ Table checked/created: sensor_node")

# Create alert table
cursor.execute('''
CREATE TABLE IF NOT EXISTS alert (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id VARCHAR(50),
    source_ip VARCHAR(50),
    score REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sensor_id) REFERENCES sensor_node(id)
)
''')
print("✅ Table checked/created: alert")

# Create block_event table
cursor.execute('''
CREATE TABLE IF NOT EXISTS block_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip VARCHAR(50),
    reason VARCHAR(100),
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
)
''')
print("✅ Table checked/created: block_event")

# Commit and verify
conn.commit()

# Show all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print(f"\n📊 Database ready with tables: {[t[0] for t in tables]}")

# Show file size
conn.close()
if os.path.exists(db_path):
    print(f"📁 Database file size: {os.path.getsize(db_path)} bytes")
print("\n🎉 Database setup complete! You can now run app.py")
