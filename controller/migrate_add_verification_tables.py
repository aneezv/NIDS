"""
migrate_add_verification_tables.py
Run this ONCE on the controller server to add the two new tables:
    - verification_result
    - honeypot_queue

Usage (from the controller/ directory):
    python migrate_add_verification_tables.py

Note: Uses db.create_all() which only creates MISSING tables.
      Existing tables (sensor_node, alert, block_event) are left untouched.
"""

import os
import json
from dotenv import load_dotenv
from flask import Flask
from models import db, VerificationResult, HoneypotQueue

load_dotenv()

with open('config.json') as f:
    CONFIG = json.load(f)

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'nids.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

with app.app_context():
    db.create_all()
    print("[OK] Tables created (if they didn't exist):")
    print("     - verification_result")
    print("     - honeypot_queue")
