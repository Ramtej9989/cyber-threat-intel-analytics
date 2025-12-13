import logging
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pymongo.database import Database

from app.api.dependencies import get_db, get_api_key, get_sync_db
from app.core.ml import models
from app.database.models import AlertSeverity, LogType

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/train/network")
async def train_network_anomaly_model(
    db: Database = Depends(get_db),
    sync_db = Depends(get_sync_db),
    api_key: str = Depends(get_api_key)
):
    """Train the network anomaly detection model"""
    try:
        # Train model (this is synchronous because of ML libraries)
        model_info = models.train_network_model(sync_db)
        
        return {
            "message": "Network anomaly model trained successfully",
            "model_info": model_info
        }
        
    except Exception as e:
        logger.error(f"Error training network anomaly model: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to train model: {str(e)}")

@router.post("/train/auth")
async def train_auth_anomaly_model(
    db: Database = Depends(get_db),
    sync_db = Depends(get_sync_db),
    api_key: str = Depends(get_api_key)
):
    """Train the authentication anomaly detection model"""
    try:
        # Train model (this is synchronous because of ML libraries)
        model_info = models.train_auth_model(sync_db)
        
        return {
            "message": "Authentication anomaly model trained successfully",
            "model_info": model_info
        }
        
    except Exception as e:
        logger.error(f"Error training auth anomaly model: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to train model: {str(e)}")

@router.post("/predict/network")
async def detect_network_anomalies(
    hours_back: int = Query(24, ge=1, le=168),
    db: Database = Depends(get_db),
    sync_db = Depends(get_sync_db),
    api_key: str = Depends(get_api_key)
):
    """Detect anomalies in network logs"""
    try:
        # Get time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours_back)
        
        # Run anomaly detection (this is synchronous because of ML libraries)
        anomalies = models.detect_network_anomalies(sync_db, start_time, end_time)
        
        # Create alerts for anomalies
        if anomalies:
            alerts = []
            for anomaly in anomalies:
                alert = {
                    "timestamp": anomaly["timestamp"],
                    "title": "ML: Network Anomaly Detected",
                    "description": f"Anomalous network traffic detected from {anomaly['src_ip']} to {anomaly['dest_ip']}",
                    "source_log_id": str(anomaly["_id"]),
                    "log_type": "NETWORK",
                    "severity": "MEDIUM",
                    "status": "NEW",
                    "entities": [
                        {"type": "IP", "value": anomaly["src_ip"]},
                        {"type": "IP", "value": anomaly["dest_ip"]}
                    ],
                    "tactic": "Discovery",
                    "technique": "Network Service Scanning",
                    "metadata": {
                        "anomaly_score": anomaly["anomaly_score"],
                        "features": anomaly["features"]
                    }
                }
                alerts.append(alert)
            
            # Insert alerts
            await db.alerts.insert_many(alerts)
        
        return {
            "message": f"Anomaly detection completed. Found {len(anomalies)} network anomalies.",
            "anomaly_count": len(anomalies)
        }
        
    except Exception as e:
        logger.error(f"Error detecting network anomalies: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Anomaly detection failed: {str(e)}")

@router.post("/predict/auth")
async def detect_auth_anomalies(
    hours_back: int = Query(24, ge=1, le=168),
    db: Database = Depends(get_db),
    sync_db = Depends(get_sync_db),
    api_key: str = Depends(get_api_key)
):
    """Detect anomalies in authentication logs"""
    try:
        # Get time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours_back)
        
        # Run anomaly detection (this is synchronous because of ML libraries)
        anomalies = models.detect_auth_anomalies(sync_db, start_time, end_time)
        
        # Create alerts for anomalies
        if anomalies:
            alerts = []
            for anomaly in anomalies:
                alert = {
                    "timestamp": anomaly["timestamp"],
                    "title": "ML: Authentication Anomaly Detected",
                    "description": f"Anomalous authentication behavior detected for user {anomaly['username']} from {anomaly['src_ip']}",
                    "source_log_id": str(anomaly["_id"]),
                    "log_type": "AUTH",
                    "severity": "HIGH",
                    "status": "NEW",
                    "entities": [
                        {"type": "USER", "value": anomaly["username"]},
                        {"type": "IP", "value": anomaly["src_ip"]}
                    ],
                    "tactic": "Initial Access",
                    "technique": "Valid Accounts",
                    "metadata": {
                        "anomaly_score": anomaly["anomaly_score"],
                        "features": anomaly["features"]
                    }
                }
                alerts.append(alert)
            
            # Insert alerts
            await db.alerts.insert_many(alerts)
        
        return {
            "message": f"Anomaly detection completed. Found {len(anomalies)} authentication anomalies.",
            "anomaly_count": len(anomalies)
        }
        
    except Exception as e:
        logger.error(f"Error detecting authentication anomalies: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Anomaly detection failed: {str(e)}")

                    
