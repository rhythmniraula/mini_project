import os
import random
import numpy as np
import pandas as pd
import cv2
from pyzbar.pyzbar import decode
import joblib
from tqdm import tqdm
import logging
import sys
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Add the project root to the Python path to fix import issues
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import project modules from backend directory
from backend.url_analyzer import URLAnalyzer
from backend.qr_detector import QRDetector
from backend.ml_model import PhishingModel

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QRModelTrainer:
    def __init__(self, malicious_dir, benign_dir, sample_size=4000):
        """
        Initialize the QR Model Trainer
        
        Args:
            malicious_dir (str): Path to directory containing malicious QR codes
            benign_dir (str): Path to directory containing benign QR codes
            sample_size (int): Number of samples to use from each category
        """
        self.malicious_dir = malicious_dir
        self.benign_dir = benign_dir
        self.sample_size = sample_size
        self.url_analyzer = URLAnalyzer()
        self.qr_detector = QRDetector()
        
        # Initialize model storage location
        self.model_dir = './backend/models'
        if not os.path.exists(self.model_dir):
            os.makedirs(self.model_dir)
            
        logger.info(f"QR Model Trainer initialized with {sample_size} samples per class")
    
    def load_and_shuffle_qr_files(self, directory):
        """
        Load and shuffle file paths from a directory
        
        Args:
            directory (str): Path to directory containing QR code images
            
        Returns:
            list: Shuffled list of file paths
        """
        if not os.path.exists(directory):
            logger.error(f"Directory not found: {directory}")
            return []
            
        file_paths = [os.path.join(directory, f) for f in os.listdir(directory) 
                     if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
        
        logger.info(f"Found {len(file_paths)} QR code images in {directory}")
        random.shuffle(file_paths)
        return file_paths
    
    def extract_url_from_qr(self, image_path):
        """
        Detect and decode QR code from image to extract URL
        
        Args:
            image_path (str): Path to QR code image
            
        Returns:
            str or None: Extracted URL or None if not found/valid
        """
        try:
            # Read the image
            img = cv2.imread(image_path)
            if img is None:
                return None
                
            # Try to decode the QR code
            decoded_objects = decode(img)
            
            if not decoded_objects:
                return None
                
            # Extract data from the first QR code
            qr_data = decoded_objects[0].data.decode('utf-8')
            
            # Check if it's a URL
            if qr_data.startswith(('http://', 'https://')) or '.' in qr_data:
                return qr_data
            
            return None
            
        except Exception as e:
            logger.error(f"Error extracting URL from QR: {str(e)}")
            return None
    
    def extract_features_from_qr_batch(self, qr_files, label):
        """
        Process a batch of QR codes and extract features from their URLs
        
        Args:
            qr_files (list): List of QR code image paths
            label (int): Class label (0 for benign, 1 for malicious)
            
        Returns:
            tuple: (feature_list, text_list, label_list)
        """
        feature_list = []
        text_list = []
        label_list = []
        
        for file_path in tqdm(qr_files, desc=f"Processing {'malicious' if label == 1 else 'benign'} QR codes"):
            # Extract URL from QR code
            url = self.extract_url_from_qr(file_path)
            
            if not url:
                continue
                
            # Extract features from URL
            features = self.url_analyzer.extract_features(url)
            
            if not features:
                continue
                
            # Extract numerical features
            numerical_features = [
                features['url_length'],
                features['domain_length'],
                features['num_dots'],
                features['num_subdomains'],
                features['has_ip_address'],
                features['has_at_symbol'],
                features['has_double_slash_redirect'],
                features['has_hex_chars'],
                features['has_suspicious_tld'],
                features['has_phishing_terms'],
                features['path_depth'],
                features['num_query_params'],
                features['has_suspicious_anchor']
            ]
            
            # Extract text features
            text_features = f"{features['domain']} {features['path']} {features['query']}"
            
            feature_list.append(numerical_features)
            text_list.append(text_features)
            label_list.append(label)
        
        return feature_list, text_list, label_list
    
    def train_model(self):
        """
        Train the phishing detection model using QR code datasets
        
        Returns:
            bool: True if training was successful
        """
        try:
            # Load and shuffle QR code image paths
            malicious_files = self.load_and_shuffle_qr_files(self.malicious_dir)
            benign_files = self.load_and_shuffle_qr_files(self.benign_dir)
            
            # Take samples based on sample_size
            malicious_sample = malicious_files[:self.sample_size] if len(malicious_files) > self.sample_size else malicious_files
            benign_sample = benign_files[:self.sample_size] if len(benign_files) > self.sample_size else benign_files
            
            logger.info(f"Using {len(malicious_sample)} malicious and {len(benign_sample)} benign samples")
            
            # Extract features from malicious QR codes
            mal_features, mal_text, mal_labels = self.extract_features_from_qr_batch(malicious_sample, 1)
            
            # Extract features from benign QR codes
            ben_features, ben_text, ben_labels = self.extract_features_from_qr_batch(benign_sample, 0)
            
            # Combine features
            all_features = mal_features + ben_features
            all_text = mal_text + ben_text
            all_labels = mal_labels + ben_labels
            
            if len(all_features) == 0:
                logger.error("No valid features extracted from QR codes")
                return False
                
            logger.info(f"Extracted features from {len(all_features)} QR codes")
            
            # Convert to numpy arrays
            X_features = np.array(all_features)
            y_labels = np.array(all_labels)
            
            # Create TF-IDF features
            vectorizer = TfidfVectorizer(max_features=100)
            X_text = vectorizer.fit_transform(all_text).toarray()
            
            # Combine numerical and text features
            X_combined = np.hstack((X_features, X_text))
            
            # Split into training and testing sets
            X_train, X_test, y_train, y_test = train_test_split(
                X_combined, y_labels, test_size=0.2, random_state=42, stratify=y_labels
            )
            
            # Train Random Forest model
            rf_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced'
            )
            
            rf_model.fit(X_train, y_train)
            
            # Evaluate model
            y_pred = rf_model.predict(X_test)
            accuracy = accuracy_score(y_test, y_test)
            
            logger.info(f"Model Training Complete - Accuracy: {accuracy:.4f}")
            logger.info("\nClassification Report:\n" + classification_report(y_test, y_pred))
            
            # Save the trained model
            model_path = os.path.join(self.model_dir, 'random_forest_model.joblib')
            vectorizer_path = os.path.join(self.model_dir, 'tfidf_vectorizer.joblib')
            
            joblib.dump(rf_model, model_path)
            joblib.dump(vectorizer, vectorizer_path)
            
            logger.info(f"Saved trained model to {model_path}")
            logger.info(f"Saved TF-IDF vectorizer to {vectorizer_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")
            return False


if __name__ == "__main__":
    # Define paths to QR code datasets
    malicious_dir = "qr_datasets/malicious"
    benign_dir = "qr_datasets/benign"
    
    # Create trainer instance with 4000 samples per class
    trainer = QRModelTrainer(malicious_dir, benign_dir, sample_size=4000)
    
    # Train the model
    success = trainer.train_model()
    
    if success:
        print("Model training completed successfully!")
    else:
        print("Model training failed. Check logs for details.") 