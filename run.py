#!/usr/bin/env python
"""
QR Phishing Detection System
Run script to start the Flask application
"""

import os
import sys

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the Flask app
from backend.app import app

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Create necessary directories
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('results', exist_ok=True)
    
    print(f"Starting QR Phishing Detection API on port {port}...")
    print("Open the frontend/index.html file in your browser to use the application.")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=port, debug=True) 