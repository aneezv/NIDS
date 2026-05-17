"""
setup_db.py

Unified Database Initialization & Migration Script.
Run this ONCE on the controller server to set up the SQLite database or add missing tables.

Note: Uses SQLAlchemy's db.create_all() which safely creates only MISSING tables.
      Existing data and tables are left completely untouched.
"""

import os
import sqlite3
import json
from dotenv import load_dotenv
from flask import Flask
from models import db

# Load environment variables
load_dotenv()

# Setup Flask app context
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'nids.db')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize DB with app
db.init_app(app)

print(f"Checking database at: {db_path}...")

with app.app_context():
    # Safely creates all tables defined in models.py that don't currently exist
    db.create_all()

    # Lightweight per-column migration: SQLAlchemy's create_all() only creates
    # missing TABLES, not missing COLUMNS. Add new columns on existing tables here.
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    def _ensure_column(table, column, ddl):
        cursor.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cursor.fetchall()}
        if column not in existing:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
            print(f"   + Added column {table}.{column}")

    _ensure_column('sensor_node', 'cpu_load', 'cpu_load REAL')

    conn.commit()

    # Verify tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    table_names = [t[0] for t in tables]
    conn.close()

    print("\n✅ Database setup complete!")
    print(f"📊 Active tables: {', '.join(table_names)}")
    
    if os.path.exists(db_path):
        print(f"📁 Database file size: {os.path.getsize(db_path)} bytes")

print("\n🎉 You can now run app.py")
