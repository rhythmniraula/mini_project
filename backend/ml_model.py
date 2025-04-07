import os
import numpy as np
import pandas as pd
import joblib
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model, Model
from tensorflow.keras.layers import Dense, Dropout, Input, Concatenate
from tensorflow.keras.optimizers import Adam
from urllib.parse import urlparse
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PhishingModel:
    def __init__(self, model_dir='./backend/models'):
        self.model_dir = model_dir
        self.rf_model_path = os.path.join(model_dir, 'random_forest_model.joblib')
        self.dl_model_path = os.path.join(model_dir, 'dl_model.h5')
        self.scaler_path = os.path.join(model_dir, 'feature_scaler.joblib')
        self.vectorizer_path = os.path.join(model_dir, 'tfidf_vectorizer.joblib')
        
        # Check if model directory exists
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
            
        # Try to load models if they exist
        self.rf_model = self._load_rf_model()
        self.dl_model = self._load_dl_model()
        self.scaler = self._load_scaler()
        self.vectorizer = self._load_vectorizer()
        
        # Safe logging that doesn't try to access estimators_
        rf_status = "Loaded" if self.rf_model is not None else "Not loaded"
        dl_status = "Loaded" if self.dl_model is not None else "Not loaded"
        logger.info(f"PhishingModel initialized. RF Model: {rf_status}, DL Model: {dl_status}")
    
    def _load_rf_model(self):
        """Load Random Forest model if it exists"""
        try:
            if os.path.exists(self.rf_model_path):
                return joblib.load(self.rf_model_path)
            return None
        except Exception as e:
            logger.error(f"Error loading Random Forest model: {str(e)}")
            return None
    
    def _load_dl_model(self):
        """Load Deep Learning model if it exists"""
        try:
            if os.path.exists(self.dl_model_path):
                return load_model(self.dl_model_path)
            return None
        except Exception as e:
            logger.error(f"Error loading Deep Learning model: {str(e)}")
            return None
    
    def _load_scaler(self):
        """Load feature scaler if it exists"""
        try:
            if os.path.exists(self.scaler_path):
                return joblib.load(self.scaler_path)
            return None
        except Exception as e:
            logger.error(f"Error loading feature scaler: {str(e)}")
            return None
    
    def _load_vectorizer(self):
        """Load TF-IDF vectorizer if it exists"""
        try:
            if os.path.exists(self.vectorizer_path):
                return joblib.load(self.vectorizer_path)
            return None
        except Exception as e:
            logger.error(f"Error loading TF-IDF vectorizer: {str(e)}")
            return None
    
    def create_random_forest_model(self, train_features=None, train_labels=None):
        """
        Create and train a Random Forest model for phishing detection
        
        Args:
            train_features: Feature matrix for training
            train_labels: Target labels for training
            
        Returns:
            bool: True if model was created or already exists
        """
        # If model already exists, return True
        if self.rf_model is not None:
            logger.info("Random Forest model already exists")
            return True
            
        # If no training data is provided, return False
        if train_features is None or train_labels is None:
            logger.error("No training data provided for model creation")
            return False
            
        # Train the model with provided data
        try:
            self.rf_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced'
            )
            self.rf_model.fit(train_features, train_labels)
            
            # Save the trained model
            joblib.dump(self.rf_model, self.rf_model_path)
            logger.info(f"Trained Random Forest model saved to {self.rf_model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating Random Forest model: {str(e)}")
            return False
    
    def create_deep_learning_model(self, train_features=None, train_labels=None):
        """
        Create and train a Deep Learning model for phishing detection
        
        Args:
            train_features: Feature matrix for training (numerical and textual)
            train_labels: Target labels for training
            
        Returns:
            bool: True if model was created or already exists
        """
        # If model already exists, return True
        if self.dl_model is not None:
            logger.info("Deep Learning model already exists")
            return True
            
        # If no training data, return False
        if train_features is None or train_labels is None:
            logger.error("No training data provided for model creation")
            return False
            
        try:
            # Input for numerical features
            num_input = Input(shape=(train_features[0].shape[0],), name='numerical_input')
            x1 = Dense(32, activation='relu')(num_input)
            x1 = Dropout(0.2)(x1)
            
            # Input for text features
            text_input = Input(shape=(train_features[1].shape[1],), name='text_input')
            x2 = Dense(32, activation='relu')(text_input)
            x2 = Dropout(0.2)(x2)
            
            # Merge layers
            merged = Concatenate()([x1, x2])
            
            # Additional layers
            x = Dense(64, activation='relu')(merged)
            x = Dropout(0.3)(x)
            x = Dense(32, activation='relu')(x)
            x = Dropout(0.2)(x)
            
            # Output layer
            output = Dense(1, activation='sigmoid')(x)
            
            # Create model
            self.dl_model = Model(inputs=[num_input, text_input], outputs=output)
            
            # Compile model
            self.dl_model.compile(
                optimizer=Adam(learning_rate=0.001),
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            # Train the model
            self.dl_model.fit(
                [train_features[0], train_features[1]], 
                train_labels, 
                epochs=10, 
                batch_size=32, 
                validation_split=0.2
            )
            
            # Save the trained model
            self.dl_model.save(self.dl_model_path)
            logger.info(f"Trained Deep Learning model saved to {self.dl_model_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating Deep Learning model: {str(e)}")
            return False
    
    def train_models(self, features_dict, labels):
        """
        Train both Random Forest and Deep Learning models
        
        Args:
            features_dict: Dictionary of feature sets
            labels: Target labels
            
        Returns:
            bool: True if models were trained successfully
        """
        try:
            # Extract numerical features
            numerical_features = np.array(features_dict['numerical_features'])
            
            # Create and fit scaler
            self.scaler = StandardScaler()
            scaled_features = self.scaler.fit_transform(numerical_features)
            
            # Extract text features
            text_features = features_dict['text_features']
            
            # Create and fit vectorizer
            self.vectorizer = TfidfVectorizer(max_features=100)
            text_vectors = self.vectorizer.fit_transform(text_features).toarray()
            
            # Save scaler and vectorizer
            joblib.dump(self.scaler, self.scaler_path)
            joblib.dump(self.vectorizer, self.vectorizer_path)
            
            # Combine features for Random Forest
            combined_features = np.hstack((scaled_features, text_vectors))
            
            # Train Random Forest model
            rf_success = self.create_random_forest_model(combined_features, labels)
            
            # Train Deep Learning model with separate inputs
            dl_features = [scaled_features, text_vectors]
            dl_success = self.create_deep_learning_model(dl_features, labels)
            
            return rf_success or dl_success
            
        except Exception as e:
            logger.error(f"Error training models: {str(e)}")
            return False
    
    def predict_url(self, url_features):
        """
        Predict if a URL is a phishing attempt based on its features
        
        Args:
            url_features: Dictionary of URL features
            
        Returns:
            dict: Prediction results including probability, class label, and model confidence
        """
        try:
            # Check if at least the Random Forest model is available
            if self.rf_model is None:
                logger.error("No models available for prediction")
                return {
                    'prediction': None,
                    'probability': None,
                    'confidence': None,
                    'error': 'No trained model available'
                }
            
            # Extract features
            numerical_features = np.array([
                url_features['url_length'],
                url_features['domain_length'],
                url_features['num_dots'],
                url_features['num_subdomains'],
                url_features['has_ip_address'],
                url_features['has_at_symbol'],
                url_features['has_double_slash_redirect'],
                url_features['has_hex_chars'],
                url_features['has_suspicious_tld'],
                url_features['has_phishing_terms'],
                url_features['path_depth'],
                url_features['num_query_params'],
                url_features.get('has_suspicious_anchor', 0)
            ]).reshape(1, -1)
            
            # Process text features
            text_features = f"{url_features['domain']} {url_features['path']} {url_features['query']}"
            
            # Transform numerical features
            if self.scaler:
                try:
                    numerical_features = self.scaler.transform(numerical_features)
                except Exception as e:
                    logger.warning(f"Error scaling features: {str(e)}. Using unscaled features.")
            
            # Transform text features
            if self.vectorizer:
                try:
                    text_vectors = self.vectorizer.transform([text_features]).toarray()
                except Exception as e:
                    logger.warning(f"Error vectorizing text: {str(e)}. Using default zero vector.")
                    text_vectors = np.zeros((1, 100))
            else:
                text_vectors = np.zeros((1, 100))
            
            # Combine features for Random Forest prediction
            combined_features = np.hstack((numerical_features, text_vectors))
            
            # Make prediction with Random Forest
            try:
                rf_probabilities = self.rf_model.predict_proba(combined_features)
                rf_prediction = int(rf_probabilities[0, 1] > 0.5)
                rf_confidence = rf_probabilities[0, 1] if rf_prediction == 1 else 1 - rf_probabilities[0, 1]
                
                # Format probabilities to be human-readable percentages
                probability_formatted = float(rf_probabilities[0, 1])
                
                return {
                    'prediction': rf_prediction,
                    'probability': probability_formatted,
                    'confidence': float(rf_confidence),
                    'model_used': 'random_forest'
                }
                
            except Exception as e:
                logger.error(f"Error making prediction with Random Forest: {str(e)}")
                return {
                    'prediction': None,
                    'probability': None,
                    'confidence': None,
                    'error': f'Prediction error: {str(e)}'
                }
                
        except Exception as e:
            logger.error(f"Error in predict_url: {str(e)}")
            return {
                'prediction': None,
                'probability': None,
                'confidence': None,
                'error': f'Feature processing error: {str(e)}'
            }
    
    def extract_feature_importance(self):
        """
        Extract feature importance from the Random Forest model
        
        Returns:
            dict: Dictionary mapping feature names to importance scores
        """
        if self.rf_model is None or not hasattr(self.rf_model, 'feature_importances_'):
            return None
            
        try:
            # Define feature names
            numerical_feature_names = [
                'URL Length', 'Domain Length', 'Number of Dots', 'Number of Subdomains',
                'Has IP Address', 'Has @ Symbol', 'Has Double Slash Redirect',
                'Has Hex Characters', 'Has Suspicious TLD', 'Has Phishing Terms',
                'Path Depth', 'Number of Query Parameters', 'Has Suspicious Anchor'
            ]
            
            # Get number of text features
            n_text_features = len(self.rf_model.feature_importances_) - len(numerical_feature_names)
            text_feature_names = [f'Text Feature {i+1}' for i in range(n_text_features)]
            
            # Combine feature names
            feature_names = numerical_feature_names + text_feature_names
            
            # Create dictionary of feature importance
            importance_dict = {
                name: float(importance) 
                for name, importance in zip(feature_names, self.rf_model.feature_importances_)
            }
            
            # Sort by importance
            return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))
            
        except Exception as e:
            logger.error(f"Error extracting feature importance: {str(e)}")
            return None 