"""
Vercel Serverless Function - WSGI Entry Point
Vercel looks for a WSGI app named 'app'
"""
import sys
import os

# Add parent directory to Python path (where app.py is)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # Import and export the Flask app from app.py
    from app import app, socketio
    # Vercel expects variable named 'app'
    
except ImportError as e:
    import traceback
    # Fallback app in case of import error
    from flask import Flask, jsonify
    app = Flask(__name__)
    
    @app.route('/')
    def error():
        return jsonify({
            "error": f"Failed to import main app",
            "details": str(e),
            "traceback": traceback.format_exc()
        }), 500
    
    @app.route('/api/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
    def catch_all(path):
        return jsonify({
            "error": "Failed to import main app",
            "details": str(e)
        }), 500

