import os
import json
import uuid
import logging
import base64
import sys
from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_cors import CORS
from werkzeug.utils import secure_filename
import numpy as np
import cv2

# Add the project root to the Python path to fix import issues
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our custom modules - using local imports
from backend.qr_detector import QRDetector
from backend.url_analyzer import URLAnalyzer
from backend.ml_model import PhishingModel

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='../frontend/static')
CORS(app)  # Enable CORS for all routes

# Configure file types
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit uploads to 16MB

# Initialize our models and detectors
qr_detector = QRDetector()
url_analyzer = URLAnalyzer()
phishing_model = PhishingModel()

# No directory creation code - we process images in memory

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'components': {
            'qr_detector': True,
            'url_analyzer': True,
            'phishing_model': phishing_model.rf_model is not None
        }
    })

@app.route('/scan', methods=['POST'])
def scan_qr():
    """
    Scan a QR code and analyze it for phishing
    
    Request:
        file: The image file containing the QR code
        
    Returns:
        JSON with analysis results
    """
    try:
        # Check if file was included in request
        if 'file' not in request.files:
            return jsonify({
                'status': 'error',
                'message': 'No file uploaded'
            }), 400
            
        file = request.files['file']
        
        # Check if filename is empty
        if file.filename == '':
            return jsonify({
                'status': 'error',
                'message': 'No file selected'
            }), 400
            
        # Check if file is allowed
        if not allowed_file(file.filename):
            return jsonify({
                'status': 'error',
                'message': f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'
            }), 400
            
        # Generate unique ID for this session
        unique_id = str(uuid.uuid4())
        
        # Read file into memory instead of saving to disk
        in_memory_file = file.read()
        np_arr = np.frombuffer(in_memory_file, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        
        if img is None:
            return jsonify({
                'status': 'error',
                'message': 'Failed to decode image'
            }), 400
            
        # Detect QR code directly from memory
        qr_data = qr_detector.detect_qr_code_from_image(img)
        
        if not qr_data:
            return jsonify({
                'status': 'error',
                'message': 'No QR code detected in the image'
            }), 400
            
        # Process detected QR code(s)
        results = []
        for qr in qr_data:
            result = {
                'qr_type': qr['type'],
                'qr_data': qr['data'],
                'qr_position': qr['rect']
            }
            
            # If QR code contains a URL, analyze it
            if qr['data'].startswith(('http://', 'https://')) or '.' in qr['data']:
                url = qr['data']
                
                # Extract URL features
                url_features = url_analyzer.extract_features(url)
                
                # Rule-based analysis
                url_analysis = url_analyzer.is_phishing(url, check_content=True)
                
                # Model-based prediction
                model_prediction = phishing_model.predict_url(url_features)
                
                # Draw boundary on image in memory (don't save to disk)
                result_img = qr_detector.draw_qr_boundary_in_memory(img)
                
                # Convert image to base64 for embedding in response
                _, buffer = cv2.imencode('.png', result_img)
                img_base64 = base64.b64encode(buffer).decode('utf-8')
                result['visualized_image_base64'] = f"data:image/png;base64,{img_base64}"
                
                # Determine risk level
                risk_level = 'Low Risk'
                if url_analysis.get('is_phishing', False) or (model_prediction.get('prediction', 0) == 1):
                    risk_level = 'High Risk'
                elif url_analysis.get('score', 0) > 0.4 or model_prediction.get('probability', 0) > 0.4:
                    risk_level = 'Medium Risk'
                
                # Get triggered risk factors
                risk_factors = []
                if url_analysis.get('reasons'):
                    risk_factors = url_analysis.get('reasons')
                
                # Prepare result
                result['phishing_analysis'] = {
                    'url': url,
                    'url_features': url_features,
                    'rule_analysis': url_analysis,
                    'model_prediction': model_prediction,
                    'final_assessment': {
                        'is_phishing': url_analysis.get('is_phishing', False) or model_prediction.get('prediction', 0) == 1,
                        'risk_level': risk_level,
                        'confidence_score': model_prediction.get('confidence', 0),
                        'probability': model_prediction.get('probability', 0),
                        'risk_factors': risk_factors
                    }
                }
            else:
                # Not a URL
                result['phishing_analysis'] = {
                    'url': None,
                    'final_assessment': {
                        'is_phishing': False,
                        'risk_level': 'Not Applicable',
                        'message': 'QR code does not contain a URL'
                    }
                }
                
            results.append(result)
            
        return jsonify({
            'status': 'success',
            'qr_code_count': len(results),
            'analysis': results
        })
        
    except Exception as e:
        logger.error(f"Error scanning QR code: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error scanning QR code: {str(e)}'
        }), 500

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    """
    Analyze a URL for phishing
    
    Request:
        JSON with URL to analyze
        
    Returns:
        JSON with analysis results
    """
    try:
        # Get URL from request
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                'status': 'error',
                'message': 'URL not provided'
            }), 400
            
        url = data['url']
        
        # Extract URL features
        url_features = url_analyzer.extract_features(url)
        
        # Rule-based analysis
        url_analysis = url_analyzer.is_phishing(url, check_content=True)
        
        # Model-based prediction
        model_prediction = phishing_model.predict_url(url_features)
        
        # Get feature importance if available
        feature_importance = phishing_model.extract_feature_importance()
        
        # Determine risk level
        risk_level = 'Low Risk'
        if url_analysis.get('is_phishing', False) or (model_prediction.get('prediction', 0) == 1):
            risk_level = 'High Risk'
        elif url_analysis.get('score', 0) > 0.4 or model_prediction.get('probability', 0) > 0.4:
            risk_level = 'Medium Risk'
        
        # Get triggered risk factors
        risk_factors = []
        if url_analysis.get('reasons'):
            risk_factors = url_analysis.get('reasons')
        
        # Combine results
        response = {
            'status': 'success',
            'url': url,
            'phishing_analysis': {
                'rule_based': url_analysis,
                'model_based': model_prediction,
                'feature_importance': feature_importance,
                'final_assessment': {
                    'is_phishing': url_analysis.get('is_phishing', False) or model_prediction.get('prediction', 0) == 1,
                    'risk_level': risk_level,
                    'confidence_score': model_prediction.get('confidence', 0),
                    'probability': model_prediction.get('probability', 0),
                    'risk_factors': risk_factors
                }
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error analyzing URL: {str(e)}'
        }), 500

@app.route('/api', methods=['GET'])
def api_info():
    """Return API info and available endpoints"""
    return jsonify({
        'name': 'QR Phishing Detection API',
        'description': 'API for detecting phishing attempts in QR codes',
        'endpoints': [
            {
                'path': '/health',
                'method': 'GET',
                'description': 'Health check endpoint'
            },
            {
                'path': '/scan',
                'method': 'POST',
                'description': 'Scan a QR code image and check for phishing'
            },
            {
                'path': '/analyze_url',
                'method': 'POST',
                'description': 'Analyze a URL for phishing'
            }
        ]
    })

# Add routes to serve the frontend HTML
@app.route('/')
def serve_frontend():
    """Serve the frontend HTML"""
    return send_from_directory('../frontend', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files from the frontend folder"""
    return send_from_directory('../frontend', path)

if __name__ == '__main__':
    # Run the app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 