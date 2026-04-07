"""
Vercel WSGI entry point for the Flask application
"""
import sys
import os

# Add parent directory to path to import the app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the Flask app from the original app.py
from app import app

# Export the app for Vercel
# Vercel automatically looks for 'app' variable
__all__ = ['app']
