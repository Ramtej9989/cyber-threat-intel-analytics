import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import joblib
import os
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

# Create models directory if it doesn't exist
os.makedirs("models", exist_ok=True)

def train_network_model(db) -> Dict[str, Any]:
    """Train anomaly detection model for network logs"""
    logger.info("Training network anomaly detection model")
    
    # Get data
    logs = list(db.network_logs.find({}))
    if not logs:
        raise ValueError("No network logs found for training")
    
    # Convert to DataFrame
    df = pd.DataFrame(logs)
    
    # Feature selection
    features = ['src_port', 'dest_port', 'bytes_sent', 'bytes_received']
    
    # Add categorical features
    categorical_features = ['protocol', 'action']
    
    # Create a preprocessing pipeline
    numeric_transformer = StandardScaler()
    categorical_transformer = OneHotEncoder(handle_unknown='ignore')
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, features),
            ('cat', categorical_transformer, categorical_features)
        ]
    )
    
    # Create the model
    model = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('model', IsolationForest(contamination=0.1, random_state=42))
    ])
    
    # Fit the model
    X = df[features + categorical_features]
    model.fit(X)
    
    # Save the model
    joblib.dump(model, "models/network_model.joblib")
    
    # Return model info
    return {
        "model_type": "IsolationForest",
        "features": features + categorical_features,
        "training_samples": len(df),
        "timestamp": datetime.utcnow().isoformat()
    }

def train_auth_model(db) -> Dict[str, Any]:
    """Train anomaly detection model for authentication logs"""
    logger.info("Training authentication anomaly detection model")
    
    # Get data
    logs = list(db.auth_logs.find({}))
    if not logs:
        raise ValueError("No authentication logs found for training")
    
    # Convert to DataFrame
    df = pd.DataFrame(logs)
    
    # Feature engineering: count login attempts per user and IP
    user_counts = df.groupby('username').size().to_dict()
    ip_counts = df.groupby('src_ip').size().to_dict()
    
    df['user_freq'] = df['username'].map(user_counts)
    df['ip_freq'] = df['src_ip'].map(ip_counts)
    
    # Add features for auth failures
    user_failure_counts = df[df['status'] == 'FAILURE'].groupby('username').size().to_dict()
    ip_failure_counts = df[df['status'] == 'FAILURE'].groupby('src_ip').size().to_dict()
    
    # Handle missing values with default 0
    df['user_failure_count'] = df['username'].map(lambda x: user_failure_counts.get(x, 0))
    df['ip_failure_count'] = df['src_ip'].map(lambda x: ip_failure_counts.get(x, 0))
    
    # Calculate failure ratios
    df['user_failure_ratio'] = df['user_failure_count'] / df['user_freq'].clip(lower=1)
    df['ip_failure_ratio'] = df['ip_failure_count'] / df['ip_freq'].clip(lower=1)
    
    # Features for model
    features = ['user_freq', 'ip_freq', 'user_failure_count', 'ip_failure_count', 
                'user_failure_ratio', 'ip_failure_ratio']
    
    # Add categorical features
    categorical_features = ['auth_method', 'status']
    
    # Create a preprocessing pipeline
    numeric_transformer = StandardScaler()
    categorical_transformer = OneHotEncoder(handle_unknown='ignore')
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, features),
            ('cat', categorical_transformer, categorical_features)
        ]
    )
    
    # Create the model
    model = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('model', IsolationForest(contamination=0.1, random_state=42))
    ])
    
    # Fit the model
    X = df[features + categorical_features]
    model.fit(X)
    
    # Save the model and feature data
    joblib.dump(model, "models/auth_model.joblib")
    joblib.dump({
        'user_counts': user_counts,
        'ip_counts': ip_counts,
        'user_failure_counts': user_failure_counts,
        'ip_failure_counts': ip_failure_counts
    }, "models/auth_feature_data.joblib")
    
    # Return model info
    return {
        "model_type": "IsolationForest",
        "features": features + categorical_features,
        "training_samples": len(df),
        "timestamp": datetime.utcnow().isoformat()
    }

def detect_network_anomalies(db, start_time, end_time) -> List[Dict[str, Any]]:
    """Detect anomalies in network logs using the trained model"""
    try:
        # Load model
        model = joblib.load("models/network_model.joblib")
        
        # Get recent logs
        query = {"timestamp": {"$gte": start_time, "$lte": end_time}}
        logs = list(db.network_logs.find(query))
        
        if not logs:
            logger.info("No logs found in the specified time range")
            return []
        
        # Convert to DataFrame
        df = pd.DataFrame(logs)
        
        # Features used in training
        features = ['src_port', 'dest_port', 'bytes_sent', 'bytes_received']
        categorical_features = ['protocol', 'action']
        
        # Make predictions
        X = df[features + categorical_features]
        df['anomaly_score'] = -model.decision_function(X)  # Convert to positive score where higher is more anomalous
        df['is_anomaly'] = model.predict(X) == -1  # -1 indicates anomaly
        
        # Get anomalous records
        anomalies = df[df['is_anomaly']].sort_values('anomaly_score', ascending=False)
        
        # Convert to list of dictionaries and add feature metadata
        results = []
        for _, row in anomalies.iterrows():
            # Create a copy to avoid modifying the original
            anomaly_dict = row.to_dict()
            
            # Add feature information
            anomaly_dict['features'] = {
                'src_port': int(row['src_port']),
                'dest_port': int(row['dest_port']),
                'bytes_sent': int(row['bytes_sent']),
                'bytes_received': int(row['bytes_received']),
                'protocol': row['protocol'],
                'action': row['action']
            }
            
            results.append(anomaly_dict)
        
        return results
        
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"Error in anomaly detection: {str(e)}")
        raise ValueError("Model not found. Train the model first.")

def detect_auth_anomalies(db, start_time, end_time) -> List[Dict[str, Any]]:
    """Detect anomalies in authentication logs using the trained model"""
    try:
        # Load model and feature data
        model = joblib.load("models/auth_model.joblib")
        feature_data = joblib.load("models/auth_feature_data.joblib")
        
        # Get recent logs
        query = {"timestamp": {"$gte": start_time, "$lte": end_time}}
        logs = list(db.auth_logs.find(query))
        
        if not logs:
            logger.info("No logs found in the specified time range")
            return []
        
        # Convert to DataFrame
        df = pd.DataFrame(logs)
        
        # Apply feature engineering using stored data
        user_counts = feature_data['user_counts']
        ip_counts = feature_data['ip_counts']
        user_failure_counts = feature_data['user_failure_counts']
        ip_failure_counts = feature_data['ip_failure_counts']
        
        # Calculate features
        df['user_freq'] = df['username'].map(lambda x: user_counts.get(x, 1))
        df['ip_freq'] = df['src_ip'].map(lambda x: ip_counts.get(x, 1))
        df['user_failure_count'] = df['username'].map(lambda x: user_failure_counts.get(x, 0))
        df['ip_failure_count'] = df['src_ip'].map(lambda x: ip_failure_counts.get(x, 0))
        df['user_failure_ratio'] = df['user_failure_count'] / df['user_freq'].clip(lower=1)
        df['ip_failure_ratio'] = df['ip_failure_count'] / df['ip_freq'].clip(lower=1)
        
        # Features for model
        features = ['user_freq', 'ip_freq', 'user_failure_count', 'ip_failure_count', 
                   'user_failure_ratio', 'ip_failure_ratio']
        categorical_features = ['auth_method', 'status']
        
        # Make predictions
        X = df[features + categorical_features]
        df['anomaly_score'] = -model.decision_function(X)  # Convert to positive score
        df['is_anomaly'] = model.predict(X) == -1  # -1 indicates anomaly
        
        # Get anomalous records
        anomalies = df[df['is_anomaly']].sort_values('anomaly_score', ascending=False)
        
        # Convert to list of dictionaries and add feature metadata
        results = []
        for _, row in anomalies.iterrows():
            # Create a copy to avoid modifying the original
            anomaly_dict = row.to_dict()
            
            # Add feature information
            anomaly_dict['features'] = {
                'user_freq': float(row['user_freq']),
                'ip_freq': float(row['ip_freq']),
                'user_failure_count': int(row['user_failure_count']),
                'ip_failure_count': int(row['ip_failure_count']),
                'user_failure_ratio': float(row['user_failure_ratio']),
                'ip_failure_ratio': float(row['ip_failure_ratio']),
                'auth_method': row['auth_method'],
                'status': row['status']
            }
            
            results.append(anomaly_dict)
        
        return results
        
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"Error in anomaly detection: {str(e)}")
        raise ValueError("Model not found. Train the model first.")
