import logging
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pymongo.database import Database

from app.api.dependencies import get_db, get_api_key
from app.core.detection import rules
from app.database.models import AlertSeverity, LogType, Alert

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/run")
async def run_detection(
    hours_back: int = Query(24, ge=1, le=168),
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Run rule-based detection on logs"""
    try:
        # Get time range for detection
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours_back)
        
        # Run different types of detection
        auth_alerts = await rules.detect_auth_anomalies(db, start_time, end_time)
        network_alerts = await rules.detect_network_anomalies(db, start_time, end_time)
        threat_intel_alerts = await rules.detect_threat_intel_matches(db, start_time, end_time)
        
        # Combine all alerts
        all_alerts = auth_alerts + network_alerts + threat_intel_alerts
        
        # Insert alerts to database if any found
        if all_alerts:
            await db.alerts.insert_many(all_alerts)
        
        return {
            "message": f"Detection completed. Found {len(all_alerts)} alerts.",
            "auth_alerts": len(auth_alerts),
            "network_alerts": len(network_alerts),
            "threat_intel_alerts": len(threat_intel_alerts)
        }
        
    except Exception as e:
        logger.error(f"Error in detection run: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")

@router.get("/alerts")
async def get_alerts(
    severity: Optional[AlertSeverity] = None,
    status: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    skip: int = Query(0, ge=0),
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Get alerts with optional filtering"""
    try:
        # Build filter
        filter_query = {}
        if severity:
            filter_query["severity"] = severity
        if status:
            filter_query["status"] = status
        
        # Get alerts
        alerts = await db.alerts.find(filter_query).sort("timestamp", -1).skip(skip).limit(limit).to_list(limit)
        count = await db.alerts.count_documents(filter_query)
        
        return {
            "total": count,
            "alerts": alerts
        }
        
    except Exception as e:
        logger.error(f"Error getting alerts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve alerts: {str(e)}")

@router.put("/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    status: str,
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Update an alert's status"""
    try:
        from bson.objectid import ObjectId
        
        # Validate status
        valid_statuses = ["NEW", "IN_PROGRESS", "RESOLVED", "FALSE_POSITIVE"]
        if status not in valid_statuses:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )
        
        # Update alert
        result = await db.alerts.update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {"status": status, "updated_at": datetime.utcnow()}}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
            
        return {"message": f"Alert status updated to {status}"}
        
    except Exception as e:
        logger.error(f"Error updating alert status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update alert status: {str(e)}")
