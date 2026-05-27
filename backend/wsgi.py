"""
wsgi.py — Entry point for Gunicorn (Render / production)
"""
import sys, os

# Ensure the backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, load_models

# Load models on startup
load_models()

if __name__ == "__main__":
    app.run()
