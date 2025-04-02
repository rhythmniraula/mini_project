import os
import json
import uuid
import logging
from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_cors import CORS
from werkzeug.utils import secure_filename
import numpy as np

# Import our custom modules - using relative imports
from .qr_detector import QRDetector
from .url_analyzer import URLAnalyzer
from .ml_model import PhishingModel

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='../frontend/static')
CORS(app)  # Enable CORS for all routes

# Configure upload folder
UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp'}
RESULTS_FOLDER = './results'

# Create necessary directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit uploads to 16MB

# Initialize our models and detectors
qr_detector = QRDetector()
url_analyzer = URLAnalyzer()
phishing_model = PhishingModel()

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'ok',
        'message': 'QR Phishing Detection API is running'
    })

@app.route('/scan', methods=['POST'])
def scan_qr():
    """
    Endpoint to scan a QR code image and check for phishing
    
    Request body should be multipart/form-data with an 'image' field
    Optional 'check_content' boolean field to analyze website content
    
    Returns: JSON with analysis results
    """
    # Check if image was uploaded
    if 'image' not in request.files:
        return jsonify({
            'status': 'error',
            'message': 'No image provided'
        }), 400
    
    file = request.files['image']
    
    # Check if the file is valid
    if file.filename == '':
        return jsonify({
            'status': 'error',
            'message': 'No file selected'
        }), 400
    
    if not allowed_file(file.filename):
        return jsonify({
            'status': 'error',
            'message': f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'
        }), 400
    
    try:
        # Save the uploaded file with a secure filename
        filename = secure_filename(file.filename)
        unique_id = str(uuid.uuid4())
        base_name, extension = os.path.splitext(filename)
        unique_filename = f"{base_name}_{unique_id}{extension}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # Optional: Check website content (default to True)
        check_content = request.form.get('check_content', 'true').lower() == 'true'
        
        # Process the image - detect QR code
        qr_data = qr_detector.detect_qr_code(file_path)
        
        if not qr_data:
            return jsonify({
                'status': 'error',
                'message': 'No QR code detected in the image'
            }), 400
        
        # Extract the URL or data from the QR code
        qr_content = qr_data[0]['data']  # Get the first QR code detected
        
        # Check if the QR code contains a URL
        is_url = qr_content.startswith(('http://', 'https://')) or '.' in qr_content
        
        # Process visualization if it's a QR code
        visualization_path = None
        if qr_data:
            result_filename = f"result_{unique_id}{extension}"
            visualization_path = os.path.join(RESULTS_FOLDER, result_filename)
            qr_detector.draw_qr_boundary(file_path, visualization_path)
        
        # Initialize results
        phishing_risk = None
        model_prediction = None
        url_analysis = None
        
        # If the QR code contains a URL, analyze it
        if is_url:
            # Get URL features
            url_features = url_analyzer.extract_features(qr_content)
            
            # Get rule-based analysis
            url_analysis = url_analyzer.is_phishing(qr_content, check_content)
            
            # Get model-based prediction
            model_prediction = phishing_model.predict_url(url_features)
            
            # Get model explanation
            model_explanation = phishing_model.explain_prediction(url_features, model_prediction)
            
            # Combine results
            phishing_risk = {
                'rule_based': url_analysis,
                'model_based': model_prediction,
                'explanation': model_explanation,
                'final_assessment': {
                    'is_phishing': url_analysis.get('is_phishing', False) or model_prediction.get('is_phishing', False),
                    'risk_level': url_analysis.get('risk_level', 'Unknown'),
                    'confidence': model_prediction.get('confidence', 'low')
                }
            }
        
        # Prepare the response
        response = {
            'status': 'success',
            'qr_code': {
                'detected': True,
                'data': qr_content,
                'is_url': is_url
            },
            'visualization': f"/results/{os.path.basename(visualization_path)}" if visualization_path else None,
            'phishing_analysis': phishing_risk
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error processing QR code: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error processing QR code: {str(e)}'
        }), 500

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    """
    Endpoint to analyze a URL for phishing
    
    Request body: JSON with 'url' field and optional 'check_content' boolean
    
    Returns: JSON with analysis results
    """
    try:
        data = request.json
        
        if not data or 'url' not in data:
            return jsonify({
                'status': 'error',
                'message': 'URL not provided'
            }), 400
        
        url = data['url']
        check_content = data.get('check_content', True)
        
        # Get URL features
        url_features = url_analyzer.extract_features(url)
        
        # Get rule-based analysis
        url_analysis = url_analyzer.is_phishing(url, check_content)
        
        # Get model-based prediction
        model_prediction = phishing_model.predict_url(url_features)
        
        # Get model explanation
        model_explanation = phishing_model.explain_prediction(url_features, model_prediction)
        
        # Combine results
        response = {
            'status': 'success',
            'url': url,
            'phishing_analysis': {
                'rule_based': url_analysis,
                'model_based': model_prediction,
                'explanation': model_explanation,
                'final_assessment': {
                    'is_phishing': url_analysis.get('is_phishing', False) or model_prediction.get('is_phishing', False),
                    'risk_level': url_analysis.get('risk_level', 'Unknown'),
                    'confidence': model_prediction.get('confidence', 'low')
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

@app.route('/results/<filename>')
def get_result(filename):
    """
    Endpoint to serve visualization results
    
    Args:
        filename: Filename of the result image
        
    Returns:
        The image file
    """
    return send_from_directory(RESULTS_FOLDER, filename)

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
            },
            {
                'path': '/results/<filename>',
                'method': 'GET',
                'description': 'Get visualization results'
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
    # Create and initialize baseline models if they don't exist
    phishing_model.create_random_forest_model()
    phishing_model.create_deep_learning_model()
    
    # Run the app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 