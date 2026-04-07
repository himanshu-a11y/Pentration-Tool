#!/usr/bin/env python3
"""
Root level entry point for Render deployment
"""
import sys
import os

# Add the Pentration-Tool subdirectory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Pentration-Tool'))

# Import and run the app
from app import app, socketio

if __name__ == '__main__':
    # Get port from environment or default to 5000
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    
    # Run with socketio
    socketio.run(app, host=host, port=port, debug=False)
