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
            
        # If no training data is provided, create a baseline model
        if train_features is None or train_labels is None:
            logger.info("No training data provided, creating baseline model")
            self.rf_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced'
            )
            
            # Create minimal training data to initialize the model
            # This ensures estimators_ attribute is created
            dummy_features = np.zeros((10, 10))
            dummy_labels = np.zeros(10)
            dummy_labels[5:] = 1  # Half positive, half negative
            self.rf_model.fit(dummy_features, dummy_labels)
            
            # Save the minimally trained model
            joblib.dump(self.rf_model, self.rf_model_path)
            logger.info(f"Baseline Random Forest model saved to {self.rf_model_path}")
            return True
            
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
            
        # If no training data, create baseline model architecture
        try:
            # Input for numerical features
            num_input = Input(shape=(10,), name='numerical_input')
            x1 = Dense(32, activation='relu')(num_input)
            x1 = Dropout(0.2)(x1)
            
            # Input for text features
            text_input = Input(shape=(100,), name='text_input')  # Assuming 100 TF-IDF features
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
            
            # Save the untrained model
            self.dl_model.save(self.dl_model_path)
            logger.info(f"Baseline Deep Learning model saved to {self.dl_model_path}")
            
            # Create and save default scaler and vectorizer if they don't exist
            if self.scaler is None:
                self.scaler = StandardScaler()
                joblib.dump(self.scaler, self.scaler_path)
                
            if self.vectorizer is None:
                self.vectorizer = TfidfVectorizer(max_features=100)
                joblib.dump(self.vectorizer, self.vectorizer_path)
                
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
            
            # Train Deep Learning model
            dl_success = False
            if rf_success:
                # For deep learning, we keep numerical and text features separate
                dl_success = self.create_deep_learning_model(
                    train_features=[scaled_features, text_vectors],
                    train_labels=labels
                )
            
            return rf_success and dl_success
            
        except Exception as e:
            logger.error(f"Error training models: {str(e)}")
            return False
    
    def predict_url(self, url_features):
        """
        Predict whether a URL is phishing based on its features
        
        Args:
            url_features: Dictionary of URL features from URLAnalyzer
            
        Returns:
            dict: Prediction results including probabilities and model decisions
        """
        try:
            # Extract numerical features and text data
            numerical_features = self._extract_numerical_features(url_features)
            text_features = self._extract_text_features(url_features)
            
            # Check if models are loaded
            models_loaded = self.rf_model is not None and self.dl_model is not None
            if not models_loaded:
                logger.warning("Models not loaded, creating baseline models")
                self.create_random_forest_model()
                self.create_deep_learning_model()
            
            # Scale numerical features
            if self.scaler is None:
                self.scaler = StandardScaler()
                scaled_features = numerical_features
            else:
                scaled_features = self.scaler.transform([numerical_features])[0]
            
            # Vectorize text features
            if self.vectorizer is None:
                self.vectorizer = TfidfVectorizer(max_features=100)
                text_vector = np.zeros(100)  # Default empty vector
            else:
                # Handle case where text feature is not in training vocab
                try:
                    text_vector = self.vectorizer.transform([text_features]).toarray()[0]
                except:
                    text_vector = np.zeros(100)  # Default empty vector
            
            # Combine features for Random Forest
            combined_features = np.hstack((scaled_features.reshape(1, -1), text_vector.reshape(1, -1)))
            
            # Get Random Forest prediction with error handling
            rf_pred_proba = 0.5  # Default value
            try:
                if self.rf_model and hasattr(self.rf_model, 'estimators_') and len(self.rf_model.estimators_) > 0:
                    rf_pred_proba = self.rf_model.predict_proba(combined_features)[0][1]
                else:
                    logger.warning("Random Forest model not properly trained, using default probability")
            except Exception as e:
                logger.error(f"Error in RF prediction: {str(e)}")
            rf_prediction = rf_pred_proba >= 0.5
            
            # Get Deep Learning prediction
            dl_pred_proba = 0.5  # Default value
            try:
                if self.dl_model:
                    dl_pred_proba = self.dl_model.predict(
                        [scaled_features.reshape(1, -1), text_vector.reshape(1, -1)]
                    )[0][0]
            except Exception as e:
                logger.warning(f"Error in DL prediction: {str(e)}")
            dl_prediction = dl_pred_proba >= 0.5
            
            # Combine predictions (weighted average)
            combined_prob = 0.6 * rf_pred_proba + 0.4 * dl_pred_proba
            combined_prediction = combined_prob >= 0.5
            
            # Return prediction results
            return {
                'is_phishing': bool(combined_prediction),
                'probability': float(combined_prob),
                'rf_probability': float(rf_pred_proba),
                'dl_probability': float(dl_pred_proba),
                'model_consensus': rf_prediction == dl_prediction,
                'confidence': 'high' if abs(combined_prob - 0.5) > 0.3 else 'medium' if abs(combined_prob - 0.5) > 0.15 else 'low'
            }
            
        except Exception as e:
            logger.error(f"Error making prediction: {str(e)}")
            return {
                'is_phishing': None,
                'probability': None,
                'error': str(e)
            }
    
    def _extract_numerical_features(self, url_features):
        """Extract numerical features from URL features dictionary"""
        # List of numerical features to extract
        numerical_feature_names = [
            'url_length', 'domain_length', 'num_dots', 'num_subdomains',
            'path_depth', 'num_query_params'
        ]
        
        # Boolean features to convert to integers
        boolean_feature_names = [
            'has_ip_address', 'has_at_symbol', 'has_double_slash_redirect',
            'has_hex_chars', 'has_suspicious_tld', 'has_phishing_terms',
            'has_suspicious_anchor'
        ]
        
        # Extract and normalize numerical features
        numerical_values = []
        
        # Add numerical features
        for feature in numerical_feature_names:
            value = url_features.get(feature, 0)
            numerical_values.append(value)
        
        # Add boolean features (as 0 or 1)
        for feature in boolean_feature_names:
            value = 1 if url_features.get(feature, False) else 0
            numerical_values.append(value)
        
        return np.array(numerical_values)
    
    def _extract_text_features(self, url_features):
        """Extract text features from URL for vectorization"""
        # Combine URL and domain as text features
        url = url_features.get('url', '')
        domain = url_features.get('domain', '')
        path = url_features.get('path', '')
        
        # Get path tokens
        path_tokens = ' '.join(re.split(r'[/\-_.?=&]', path))
        
        # Combine all text
        combined_text = f"{url} {domain} {path_tokens}"
        
        return combined_text
        
    def explain_prediction(self, url_features, prediction_result):
        """
        Explain the model's prediction
        
        Args:
            url_features: Dictionary of URL features
            prediction_result: Result from predict_url method
            
        Returns:
            dict: Explanation of prediction factors
        """
        # Define risk factors and their weights
        risk_factors = {
            'url_length': ('URL is unusually long', 0.1, url_features.get('url_length', 0) > 75),
            'has_ip_address': ('URL contains IP address instead of domain name', 0.3, url_features.get('has_ip_address', False)),
            'has_at_symbol': ('URL contains @ symbol', 0.3, url_features.get('has_at_symbol', False)),
            'has_double_slash_redirect': ('URL contains suspicious redirect', 0.2, url_features.get('has_double_slash_redirect', False)),
            'has_hex_chars': ('URL contains hexadecimal characters', 0.1, url_features.get('has_hex_chars', False)),
            'has_suspicious_tld': ('Domain uses suspicious TLD', 0.2, url_features.get('has_suspicious_tld', False)),
            'has_phishing_terms': ('URL contains terms commonly used in phishing', 0.2, url_features.get('has_phishing_terms', False)),
            'num_subdomains': ('URL has excessive subdomains', 0.1, url_features.get('num_subdomains', 0) >= 3),
            'has_suspicious_anchor': ('URL contains suspicious anchor usage', 0.1, url_features.get('has_suspicious_anchor', False))
        }
        
        # Calculate risk score
        total_risk_score = 0
        triggered_factors = []
        
        for factor, (description, weight, is_triggered) in risk_factors.items():
            if is_triggered:
                total_risk_score += weight
                triggered_factors.append(description)
        
        # Determine risk level
        risk_level = 'Minimal Risk'
        if total_risk_score >= 0.7:
            risk_level = 'High Risk'
        elif total_risk_score >= 0.4:
            risk_level = 'Medium Risk'
        elif total_risk_score >= 0.2:
            risk_level = 'Low Risk'
        
        # Prepare explanation
        explanation = {
            'triggered_factors': triggered_factors if triggered_factors else ['No suspicious factors detected'],
            'risk_score': round(total_risk_score, 2),
            'risk_level': risk_level,
            'model_confidence': prediction_result.get('confidence', 'unknown'),
            'model_probability': prediction_result.get('probability', 0),
            'model_consensus': prediction_result.get('model_consensus', True)
        }
        
        return explanation 