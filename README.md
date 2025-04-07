# QR Phishing Detection System
## System Requirements

- Python 3.9+
- Flask for the web server
- Scikit-learn, TensorFlow, and other ML libraries
- OpenCV and pyzbar for QR code processing

## Installation

1. Clone the repository:
```
git clone <repository-url>
cd mini_project
```

2. Create and activate a virtual environment:
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```
pip install -r requirements.txt
```

## Training the Model

2. Run the training script:
```
python qr_model_trainer.py --samples 4000
```

## Running the Application

1. Start the Flask server:
```
python backend/app.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

