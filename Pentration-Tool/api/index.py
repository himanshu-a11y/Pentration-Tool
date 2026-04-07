"""
Vercel Serverless Function - WSGI Entry Point
"""
import sys
import os

# Ensure the parent directory is in the path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    # Import the Flask app
    from app import app
    
    # Vercel looks for this app variable
    application = app
    
except ImportError as e:
    print(f"Error importing app: {e}")
    from flask import Flask
    application = Flask(__name__)
    
    @application.route('/')
    def error():
        return f"Error: Could not import main app. {str(e)}", 500

