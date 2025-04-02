<<<<<<< HEAD
# QR Phishing Detection System

A comprehensive system to detect and analyze malicious content in QR codes using AI/ML/DL techniques. This tool helps users verify the safety of QR codes before scanning them with their devices.

## Features

- **QR Code Detection**: Extract data from QR code images
- **URL Analysis**: Examine URLs for phishing indicators
- **Machine Learning Models**: Use ML/DL models to detect sophisticated phishing attempts
- **Visual Reporting**: User-friendly interface for understanding risk assessments
- **Detailed Explanations**: Transparent reporting of why a QR code is flagged as suspicious

## Technology Stack

### Backend
- Python 3.8+
- Flask (REST API)
- OpenCV and pyzbar (QR code detection)
- TensorFlow (Deep Learning model)
- scikit-learn (Machine Learning)
- Beautiful Soup (Web content analysis)
- Requests (Web scraping)

### Frontend
- HTML5, CSS3, JavaScript (ES6+)
- Responsive design
- Drag & drop interface

## Project Structure

```
QR_Phishing_Detection/
├── backend/
│   ├── models/          # ML/DL model storage
│   ├── app.py           # Flask API
│   ├── qr_detector.py   # QR code detection module
│   ├── url_analyzer.py  # URL analysis module
│   ├── ml_model.py      # ML/DL model implementation
│   └── __init__.py      # Package initialization
├── frontend/
│   ├── static/
│   │   ├── css/         # Stylesheets
│   │   ├── js/          # JavaScript
│   │   └── images/      # Image assets
│   └── index.html       # Main web interface
├── uploads/             # Temporary storage for uploaded images
├── results/             # Storage for analysis results
├── requirements.txt     # Python dependencies
└── README.md            # Project documentation
```

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Git

### Setup Steps

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/qr-phishing-detection.git
   cd qr-phishing-detection
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # macOS/Linux
   source venv/bin/activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create necessary directories:
   ```
   mkdir -p uploads results
   ```

5. Run the application:
   ```
   python -m backend.app
   ```

6. Open the frontend in a web browser:
   - Open `frontend/index.html` in your browser
   - Alternatively, use a simple HTTP server: `python -m http.server 8000`
   - Navigate to `http://localhost:8000/frontend/`

## Usage

1. **Upload QR Code**: Drag & drop or select a QR code image
2. **Direct URL Analysis**: Enter a URL directly if you already have it
3. **Scan Settings**: Enable/disable deep scanning of website content
4. **View Results**: See risk assessment, detected phishing indicators, and recommendations
5. **Detailed Report**: Access in-depth analysis of detected threats

## How It Works

### QR Code Detection
The system uses OpenCV and pyzbar to detect and decode QR codes from images. It extracts any embedded URLs or text.

### URL Analysis
URLs are analyzed using:
1. **Rule-based analysis**: Checks for common phishing indicators like suspicious TLDs, URL length, special characters, etc.
2. **Machine Learning**: Extracts URL features and uses Random Forest classifier to identify phishing patterns
3. **Deep Learning**: Uses neural networks to detect sophisticated phishing attempts
4. **Content Analysis**: Optionally examines actual website content for suspicious elements

### Risk Assessment
The system combines multiple analysis techniques to provide a comprehensive risk assessment:
- **Low Risk**: No suspicious indicators detected
- **Medium Risk**: Some suspicious patterns detected
- **High Risk**: Strong evidence of phishing

## Extending the System

### Training Custom Models
The ML/DL models included are baseline models. For better accuracy:

1. Collect labeled phishing and legitimate URL datasets
2. Extract features using the `url_analyzer.py` module
3. Train models using the `ml_model.py` training functions
4. Save models to the `backend/models/` directory

### Adding New Detection Methods
To add new detection methods:

1. Implement the detection logic in the appropriate module
2. Update the API in `app.py` to include the new method
3. Modify the frontend to display the results

## License

[MIT License](LICENSE)

## Acknowledgements

- [OpenCV](https://opencv.org/) for image processing
- [TensorFlow](https://www.tensorflow.org/) for deep learning capabilities
- [scikit-learn](https://scikit-learn.org/) for machine learning algorithms
- [Flask](https://flask.palletsprojects.com/) for the API framework 
=======
# mini_project
>>>>>>> 84adc3a8bd88d9e72a1b4628161a872b6f044f65
