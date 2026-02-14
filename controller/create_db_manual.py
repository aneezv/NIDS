"""
Database Initialization Script
Run ONCE to create all tables: python create_db_manual.py
"""
import sqlite3
import os

# Get the directory of this script
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'nids.db')

print(f"Creating database at: {db_path}")

# Delete old database if exists
if os.path.exists(db_path):
    os.remove(db_path)
    print("Removed old database file")

# Connect to database (creates it)
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
print("✅ Created table: sensor_node")

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
print("✅ Created table: alert")

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
print("✅ Created table: block_event")

# Commit and verify
conn.commit()

# Show all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print(f"\n📊 Database ready with tables: {[t[0] for t in tables]}")

# Show file size
conn.close()
print(f"📁 Database file size: {os.path.getsize(db_path)} bytes")
print("\n🎉 Database created successfully! You can now run app.py")
