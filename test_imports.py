#!/usr/bin/env python
"""
Test script to verify imports are working correctly
"""

import os
import sys

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("Testing imports...")

try:
    from backend.qr_detector import QRDetector
    print("✓ Successfully imported QRDetector")
except ImportError as e:
    print(f"✗ Error importing QRDetector: {str(e)}")

try:
    from backend.url_analyzer import URLAnalyzer
    print("✓ Successfully imported URLAnalyzer")
except ImportError as e:
    print(f"✗ Error importing URLAnalyzer: {str(e)}")

try:
    from backend.ml_model import PhishingModel
    print("✓ Successfully imported PhishingModel")
except ImportError as e:
    print(f"✗ Error importing PhishingModel: {str(e)}")

try:
    from backend.app import app
    print("✓ Successfully imported Flask app")
except ImportError as e:
    print(f"✗ Error importing Flask app: {str(e)}")

print("\nAll imports tested.")
print("If all imports were successful, you can run the application with 'python run.py'") 