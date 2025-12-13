from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Query, Body, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader, APIKeyQuery
from typing import List, Optional, Dict, Any
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import io
import csv
import json
import logging
import os
from pymongo import MongoClient
from bson.objectid import ObjectId
import uuid
import hashlib
from pydantic import BaseModel, Field
from fastapi import FastAPI

app = FastAPI()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API key setup
API_KEY = "API_KEY_7F9X_K2P8_QM2L_Z8R1X"
API_KEY_NAME = "api_key"

api_key_query = APIKeyQuery(name=API_KEY_NAME, auto_error=False)
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

# MongoDB connection
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb+srv://tejbonthu45_db_user:k476QemWIp0ZYusO@cyberintelcluster.q7kvfn9.mongodb.net/?retryWrites=true&w=majority&appName=CyberIntelCluster")
MONGODB_DB = os.getenv("MONGODB_DB", "soc_platform")

client = MongoClient(MONGODB_URI)
db = client[MONGODB_DB]

# Initialize FastAPI
app = FastAPI(
    title="Enterprise Cyber Threat Intelligence & SOC Analytics Platform API",
    description="Backend API for security data processing and analytics",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API key validation
async def get_api_key(
    query_key: str = Depends(api_key_query),
    header_key: str = Depends(api_key_header)
):
    if query_key == API_KEY:
        return query_key
    elif header_key and header_key.startswith("Bearer "):
        key = header_key.replace("Bearer ", "")
        if key == API_KEY:
            return key
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key"
    )

# Models
class DetectionRequest(BaseModel):
    hours_back: int = Field(24, description="Hours to look back for detection")

class AlertStatusUpdate(BaseModel):
    status: str = Field(..., description="New status for the alert")

# API Endpoints

@app.get("/api/status", tags=["Health"])
async def check_status(api_key: str = Depends(get_api_key)):
    """Check API health status"""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

# Data Ingestion Endpoints

@app.post("/api/ingestion/upload/{file_type}", tags=["Ingestion"])
async def upload_file(
    file_type: str, 
    file: UploadFile = File(...), 
    api_key: str = Depends(get_api_key)
):
    """Upload data files for processing"""
    if file_type not in ["assets", "threat_intel", "auth_logs", "network_logs"]:
        raise HTTPException(status_code=400, detail="Invalid file type")
    
    try:
        # Process file
        contents = await file.read()
        df = pd.read_csv(io.StringIO(contents.decode('utf-8')))
        
        # Save to MongoDB
        collection = db[file_type]
        # Drop existing data if collection exists
        collection.delete_many({})
        
        # Convert DataFrame to dict and insert
        records = df.to_dict('records')
        
        # Add _id and created_at fields
        for record in records:
            record['_id'] = str(ObjectId())
            record['created_at'] = datetime.utcnow().isoformat()
        
        collection.insert_many(records)
        
        return {"status": "success", "records_processed": len(records)}
        
    except Exception as e:
        logger.error(f"Error processing upload: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

# Detection and Analytics Endpoints

@app.post("/api/detection/run", tags=["Detection"])
async def run_detection(
    request: DetectionRequest = Body(...),
    api_key: str = Depends(get_api_key)
):
    """Run detection rules on data"""
    try:
        hours_back = request.hours_back
        cutoff_time = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat()
        
        # Clear existing alerts
        db.alerts.delete_many({})
        
        # Generate alerts
        auth_alerts = detect_auth_anomalies(cutoff_time)
        network_alerts = detect_network_anomalies(cutoff_time)
        threat_intel_alerts = detect_threat_intel_matches(cutoff_time)
        
        # Calculate risk scores
        calculate_risk_scores()
        
        total_alerts = auth_alerts + network_alerts + threat_intel_alerts
        
        return {
            "status": "success",
            "auth_alerts": auth_alerts,
            "network_alerts": network_alerts,
            "threat_intel_alerts": threat_intel_alerts,
            "total_alerts": total_alerts,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error running detection: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error running detection: {str(e)}")

def detect_auth_anomalies(cutoff_time):
    """Detect authentication anomalies"""
    try:
        # Get auth logs
        auth_logs = list(db.auth_logs.find({"timestamp": {"$gte": cutoff_time}}))
        
        alerts_generated = 0
        
        # Failed login detection
        for user in set(log['username'] for log in auth_logs):
            user_logs = [log for log in auth_logs if log['username'] == user]
            failed_logs = [log for log in user_logs if log['status'] == 'FAILURE']
            
            # More than 3 failures for a user
            if len(failed_logs) >= 3:
                alert = {
                    "_id": str(ObjectId()),
                    "timestamp": datetime.utcnow().isoformat(),
                    "title": f"Multiple failed login attempts for user {user}",
                    "description": f"Detected {len(failed_logs)} failed login attempts for user {user}",
                    "severity": "MEDIUM" if len(failed_logs) < 5 else "HIGH",
                    "status": "NEW",
                    "source_log_id": failed_logs[0]['_id'],
                    "log_type": "auth_logs",
                    "entities": [
                        {"type": "USER", "value": user}
                    ],
                    "tactic": "CREDENTIAL_ACCESS",
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
                db.alerts.insert_one(alert)
                alerts_generated += 1
        
        # Check for failed logins from known malicious IPs
        threat_intel = list(db.threat_intel.find({}))
        malicious_ips = [ti['indicator'] for ti in threat_intel]
        
        for log in auth_logs:
            if log['src_ip'] in malicious_ips:
                threat_info = next((ti for ti in threat_intel if ti['indicator'] == log['src_ip']), None)
                severity = "HIGH" if log['status'] == 'FAILURE' else "MEDIUM"
                if threat_info and threat_info['threat_level'] >= 8:
                    severity = "CRITICAL"
                
                alert = {
                    "_id": str(ObjectId()),
                    "timestamp": datetime.utcnow().isoformat(),
                    "title": f"Authentication attempt from known malicious IP",
                    "description": f"User {log['username']} authentication {log['status'].lower()} from malicious IP {log['src_ip']}",
                    "severity": severity,
                    "status": "NEW",
                    "source_log_id": log['_id'],
                    "log_type": "auth_logs",
                    "entities": [
                        {"type": "USER", "value": log['username']},
                        {"type": "IP", "value": log['src_ip']}
                    ],
                    "tactic": "INITIAL_ACCESS",
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
                db.alerts.insert_one(alert)
                alerts_generated += 1
        
        return alerts_generated
    except Exception as e:
        logger.error(f"Error detecting auth anomalies: {str(e)}")
        return 0

def detect_network_anomalies(cutoff_time):
    """Detect network anomalies"""
    try:
        # Get network logs
        network_logs = list(db.network_logs.find({"timestamp": {"$gte": cutoff_time}}))
        
        alerts_generated = 0
        
        # Get assets info for criticality
        assets = list(db.assets.find({}))
        asset_ip_map = {asset['ip_address']: asset for asset in assets}
        
        # Get threat intelligence
        threat_intel = list(db.threat_intel.find({}))
        malicious_ips = [ti['indicator'] for ti in threat_intel]
        
        # Check for known attack traffic
        attack_logs = [log for log in network_logs if log.get('label') == 'attack']
        for log in attack_logs:
            # Check if destination is a critical asset
            dest_asset = asset_ip_map.get(log['dest_ip'])
            severity = "MEDIUM"
            
            if dest_asset and dest_asset.get('criticality', 0) >= 4:
                severity = "HIGH"
                if log['action'] == 'ALLOW':
                    severity = "CRITICAL"
            
            alert = {
                "_id": str(ObjectId()),
                "timestamp": datetime.utcnow().isoformat(),
                "title": f"Attack traffic detected",
                "description": f"Attack traffic from {log['src_ip']} to {log['dest_ip']} on port {log['dest_port']} ({log['protocol']}) was {log['action'].lower()}ed",
                "severity": severity,
                "status": "NEW",
                "source_log_id": log['_id'],
                "log_type": "network_logs",
                "entities": [
                    {"type": "IP", "value": log['src_ip']},
                    {"type": "IP", "value": log['dest_ip']}
                ],
                "tactic": "COMMAND_AND_CONTROL",
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            
            db.alerts.insert_one(alert)
            alerts_generated += 1
        
        # Check for connections from malicious IPs
        for log in network_logs:
            if log['src_ip'] in malicious_ips:
                threat_info = next((ti for ti in threat_intel if ti['indicator'] == log['src_ip']), None)
                
                # Check if this is to a critical asset
                dest_asset = asset_ip_map.get(log['dest_ip'])
                severity = "MEDIUM"
                
                if threat_info and threat_info['threat_level'] >= 8:
                    severity = "HIGH"
                
                if dest_asset and dest_asset.get('criticality', 0) >= 4:
                    if severity == "HIGH":
                        severity = "CRITICAL"
                    else:
                        severity = "HIGH"
                
                alert = {
                    "_id": str(ObjectId()),
                    "timestamp": datetime.utcnow().isoformat(),
                    "title": f"Connection from known malicious IP",
                    "description": f"Connection from malicious IP {log['src_ip']} to {log['dest_ip']} on port {log['dest_port']} ({log['protocol']}) was {log['action'].lower()}ed",
                    "severity": severity,
                    "status": "NEW",
                    "source_log_id": log['_id'],
                    "log_type": "network_logs",
                    "entities": [
                        {"type": "IP", "value": log['src_ip']},
                        {"type": "IP", "value": log['dest_ip']}
                    ],
                    "tactic": "COMMAND_AND_CONTROL",
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
                
                db.alerts.insert_one(alert)
                alerts_generated += 1
        
        return alerts_generated
    except Exception as e:
        logger.error(f"Error detecting network anomalies: {str(e)}")
        return 0

def detect_threat_intel_matches(cutoff_time):
    """Detect matches with threat intelligence"""
    # This is already covered in the other detection functions
    return 0

def calculate_risk_scores():
    """Calculate risk scores for entities"""
    try:
        # Clear existing risk scores
        db.entity_risk_scores.delete_many({})
        
        calculate_user_risk_scores()
        calculate_ip_risk_scores()
        calculate_host_risk_scores()
        
        return True
    except Exception as e:
        logger.error(f"Error calculating risk scores: {str(e)}")
        return False

def calculate_user_risk_scores():
    """Calculate risk scores for users"""
    users = {}
    auth_logs = list(db.auth_logs.find({}))
    alerts = list(db.alerts.find({}))
    
    # Process all users from auth logs
    for log in auth_logs:
        username = log['username']
        if username not in users:
            users[username] = {
                "failed_logins": 0,
                "total_logins": 0,
                "alert_mentions": 0,
                "risk_factors": []
            }
        
        users[username]["total_logins"] += 1
        if log["status"] == "FAILURE":
            users[username]["failed_logins"] += 1
    
    # Count alert mentions
    for alert in alerts:
        entities = alert.get("entities", [])
        for entity in entities:
            if entity["type"] == "USER" and entity["value"] in users:
                users[entity["value"]]["alert_mentions"] += 1
    
    # Calculate risk scores
    for username, data in users.items():
        base_score = 1.0
        risk_factors = []
        
        # Failed login factor
        if data["failed_logins"] > 0:
            failure_rate = data["failed_logins"] / data["total_logins"]
            if failure_rate > 0.5:
                factor_score = min(4.0, failure_rate * 5)
                risk_factors.append({
                    "factor": "SUSPICIOUS_AUTH",
                    "score": factor_score,
                    "details": f"High login failure rate ({data['failed_logins']} of {data['total_logins']} failed)"
                })
            elif data["failed_logins"] >= 3:
                risk_factors.append({
                    "factor": "FAILED_LOGIN",
                    "score": min(3.0, data["failed_logins"] * 0.5),
                    "details": f"Multiple failed logins ({data['failed_logins']})"
                })
        
        # Alert mentions factor
        if data["alert_mentions"] > 0:
            risk_factors.append({
                "factor": "ALERT_ASSOCIATION",
                "score": min(5.0, data["alert_mentions"]),
                "details": f"Associated with {data['alert_mentions']} security alerts"
            })
        
        # Calculate final score
        risk_score = base_score
        for factor in risk_factors:
            risk_score += factor["score"]
        
        # Cap at 10
        risk_score = min(10.0, risk_score)
        
        # Insert to database
        db.entity_risk_scores.insert_one({
            "_id": str(ObjectId()),
            "entity_id": username,
            "entity_type": "USER",
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "last_updated": datetime.utcnow().isoformat(),
            "metadata": {
                "total_logins": data["total_logins"],
                "failed_logins": data["failed_logins"],
                "alert_mentions": data["alert_mentions"]
            }
        })

def calculate_ip_risk_scores():
    """Calculate risk scores for IP addresses"""
    ips = {}
    auth_logs = list(db.auth_logs.find({}))
    network_logs = list(db.network_logs.find({}))
    alerts = list(db.alerts.find({}))
    threat_intel = list(db.threat_intel.find({}))
    
    # Create lookup for threat intel
    threat_intel_dict = {ti["indicator"]: ti for ti in threat_intel}
    
    # Process all IPs from auth and network logs
    for log in auth_logs:
        src_ip = log["src_ip"]
        if src_ip not in ips:
            ips[src_ip] = {
                "failed_logins": 0,
                "total_auth": 0,
                "network_denies": 0,
                "total_network": 0,
                "attack_traffic": 0,
                "alert_mentions": 0,
                "is_threat_intel": False,
                "threat_level": 0,
                "risk_factors": []
            }
        
        ips[src_ip]["total_auth"] += 1
        if log["status"] == "FAILURE":
            ips[src_ip]["failed_logins"] += 1
    
    for log in network_logs:
        src_ip = log["src_ip"]
        if src_ip not in ips:
            ips[src_ip] = {
                "failed_logins": 0,
                "total_auth": 0,
                "network_denies": 0,
                "total_network": 0,
                "attack_traffic": 0,
                "alert_mentions": 0,
                "is_threat_intel": False,
                "threat_level": 0,
                "risk_factors": []
            }
        
        ips[src_ip]["total_network"] += 1
        if log["action"] == "DENY":
            ips[src_ip]["network_denies"] += 1
        
        if log.get("label") == "attack":
            ips[src_ip]["attack_traffic"] += 1
    
    # Count alert mentions
    for alert in alerts:
        entities = alert.get("entities", [])
        for entity in entities:
            if entity["type"] == "IP" and entity["value"] in ips:
                ips[entity["value"]]["alert_mentions"] += 1
    
    # Check threat intel matches
    for ip, data in ips.items():
        if ip in threat_intel_dict:
            data["is_threat_intel"] = True
            data["threat_level"] = threat_intel_dict[ip]["threat_level"]
    
    # Calculate risk scores
    for ip, data in ips.items():
        base_score = 1.0
        risk_factors = []
        
        # Threat intel factor
        if data["is_threat_intel"]:
            threat_factor = min(5.0, data["threat_level"] * 0.5)
            risk_factors.append({
                "factor": "KNOWN_THREAT_ACTOR",
                "score": threat_factor,
                "details": f"Known malicious IP with threat level {data['threat_level']}/10"
            })
        
        # Failed login factor
        if data["total_auth"] > 0 and data["failed_logins"] > 0:
            failure_rate = data["failed_logins"] / data["total_auth"]
            if failure_rate > 0.5 and data["failed_logins"] >= 3:
                factor_score = min(3.0, failure_rate * 4)
                risk_factors.append({
                    "factor": "AUTHENTICATION_FAILURES",
                    "score": factor_score,
                    "details": f"High login failure rate ({data['failed_logins']} of {data['total_auth']} failed)"
                })
        
        # Network deny factor
        if data["total_network"] > 0 and data["network_denies"] > 0:
            deny_rate = data["network_denies"] / data["total_network"]
            if deny_rate > 0.5 and data["network_denies"] >= 3:
                factor_score = min(2.5, deny_rate * 3)
                risk_factors.append({
                    "factor": "BLOCKED_CONNECTIONS",
                    "score": factor_score,
                    "details": f"High connection block rate ({data['network_denies']} of {data['total_network']} blocked)"
                })
        
        # Attack traffic factor
        if data["attack_traffic"] > 0:
            factor_score = min(4.0, data["attack_traffic"] * 0.8)
            risk_factors.append({
                "factor": "DETECTED_ATTACK",
                "score": factor_score,
                "details": f"Source of {data['attack_traffic']} detected attack traffic events"
            })
        
        # Alert mentions factor
        if data["alert_mentions"] > 0:
            risk_factors.append({
                "factor": "ALERT_ASSOCIATION",
                "score": min(3.0, data["alert_mentions"] * 0.7),
                "details": f"Associated with {data['alert_mentions']} security alerts"
            })
        
        # Calculate final score
        risk_score = base_score
        for factor in risk_factors:
            risk_score += factor["score"]
        
        # Cap at 10
        risk_score = min(10.0, risk_score)
        
        # Insert to database
        db.entity_risk_scores.insert_one({
            "_id": str(ObjectId()),
            "entity_id": ip,
            "entity_type": "IP",
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "last_updated": datetime.utcnow().isoformat(),
            "metadata": {
                "total_auth": data["total_auth"],
                "failed_logins": data["failed_logins"],
                "total_network": data["total_network"],
                "network_denies": data["network_denies"],
                "attack_traffic": data["attack_traffic"],
                "alert_mentions": data["alert_mentions"],
                "is_threat_intel": data["is_threat_intel"],
                "threat_level": data["threat_level"]
            }
        })

def calculate_host_risk_scores():
    """Calculate risk scores for hosts"""
    hosts = {}
    auth_logs = list(db.auth_logs.find({}))
    network_logs = list(db.network_logs.find({}))
    alerts = list(db.alerts.find({}))
    assets = list(db.assets.find({}))
    
    # Create lookup for assets
    asset_dict = {asset["host"]: asset for asset in assets}
    
    # Process all hosts from logs
    for log in auth_logs:
        host = log["dest_host"]
        if host not in hosts:
            hosts[host] = {
                "failed_logins": 0,
                "total_auth": 0,
                "incoming_traffic": 0,
                "attack_traffic": 0,
                "alert_mentions": 0,
                "criticality": asset_dict.get(host, {}).get("criticality", 1),
                "risk_factors": []
            }
        
        hosts[host]["total_auth"] += 1
        if log["status"] == "FAILURE":
            hosts[host]["failed_logins"] += 1
    
    for log in network_logs:
        dest_ip = log["dest_ip"]
        # Try to find host that has this IP
        matching_asset = None
        for asset in assets:
            if asset["ip_address"] == dest_ip:
                matching_asset = asset
                break
        
        if not matching_asset:
            continue
            
        host = matching_asset["host"]
        if host not in hosts:
            hosts[host] = {
                "failed_logins": 0,
                "total_auth": 0,
                "incoming_traffic": 0,
                "attack_traffic": 0,
                "alert_mentions": 0,
                "criticality": matching_asset.get("criticality", 1),
                "risk_factors": []
            }
        
        hosts[host]["incoming_traffic"] += 1
        if log.get("label") == "attack":
            hosts[host]["attack_traffic"] += 1
    
    # Count alert mentions
    for alert in alerts:
        entities = alert.get("entities", [])
        for entity in entities:
            if entity["type"] == "HOST" and entity["value"] in hosts:
                hosts[entity["value"]]["alert_mentions"] += 1
    
    # Calculate risk scores
    for host, data in hosts.items():
        base_score = 1.0
        risk_factors = []
        
        # Critical asset factor
        if data["criticality"] >= 4:
            risk_factors.append({
                "factor": "CRITICAL_ASSET",
                "score": data["criticality"] * 0.5,
                "details": f"Critical asset with criticality rating {data['criticality']}/5"
            })
        
        # Authentication failures
        if data["total_auth"] > 0 and data["failed_logins"] > 0:
            failure_rate = data["failed_logins"] / data["total_auth"]
            if failure_rate > 0.4 and data["failed_logins"] >= 3:
                factor_score = min(3.0, failure_rate * 3.5)
                risk_factors.append({
                    "factor": "AUTHENTICATION_FAILURES",
                    "score": factor_score,
                    "details": f"High login failure rate ({data['failed_logins']} of {data['total_auth']} failed)"
                })
        
        # Attack traffic factor
        if data["attack_traffic"] > 0:
            factor_score = min(4.0, data["attack_traffic"] * 0.5)
            risk_factors.append({
                "factor": "ATTACK_TARGET",
                "score": factor_score,
                "details": f"Target of {data['attack_traffic']} attack traffic events"
            })
        
        # Alert mentions factor
        if data["alert_mentions"] > 0:
            risk_factors.append({
                "factor": "ALERT_ASSOCIATION",
                "score": min(3.0, data["alert_mentions"] * 0.7),
                "details": f"Associated with {data['alert_mentions']} security alerts"
            })
        
        # Calculate final score
        risk_score = base_score
        for factor in risk_factors:
            risk_score += factor["score"]
        
        # For high criticality assets, increase risk slightly
        if data["criticality"] >= 4:
            risk_score += 0.5
        
        # Cap at 10
        risk_score = min(10.0, risk_score)
        
        # Insert to database
        db.entity_risk_scores.insert_one({
            "_id": str(ObjectId()),
            "entity_id": host,
            "entity_type": "HOST",
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "last_updated": datetime.utcnow().isoformat(),
            "metadata": {
                "total_auth": data["total_auth"],
                "failed_logins": data["failed_logins"],
                "incoming_traffic": data["incoming_traffic"],
                "attack_traffic": data["attack_traffic"],
                "alert_mentions": data["alert_mentions"],
                "criticality": data["criticality"]
            }
        })

# Data Access Endpoints

@app.get("/api/alerts", tags=["Alerts"])
async def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    api_key: str = Depends(get_api_key)
):
    """Get security alerts"""
    try:
        # Build query
        query = {}
        if severity:
            query["severity"] = severity
        if status:
            query["status"] = status
        
        # Query database
        alerts = list(db.alerts.find(query).skip(skip).limit(limit).sort("timestamp", -1))
        total = db.alerts.count_documents(query)
        
        # Return results
        return {
            "alerts": alerts,
            "total": total,
            "page": skip // limit + 1 if limit > 0 else 1,
            "pageSize": limit,
            "totalPages": (total + limit - 1) // limit if limit > 0 else 1
        }
    except Exception as e:
        logger.error(f"Error getting alerts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting alerts: {str(e)}")

@app.get("/api/alerts/{alert_id}", tags=["Alerts"])
async def get_alert(
    alert_id: str,
    api_key: str = Depends(get_api_key)
):
    """Get a specific alert"""
    try:
        alert = db.alerts.find_one({"_id": alert_id})
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting alert: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting alert: {str(e)}")
# Add these endpoints to your main.py FastAPI backend

@app.get("/api/logs/network", tags=["Logs"])
async def get_network_logs(
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    action: Optional[str] = None,
    label: Optional[str] = None,
    startDate: Optional[str] = None,
    endDate: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    api_key: str = Depends(get_api_key)
):
    """Get network logs"""
    try:
        # Build query
        query = {}
        if src_ip:
            query["src_ip"] = {"$regex": src_ip, "$options": "i"}
        if dest_ip:
            query["dest_ip"] = {"$regex": dest_ip, "$options": "i"}
        if protocol:
            query["protocol"] = protocol
        if action:
            query["action"] = action
        if label:
            query["label"] = label
        
        # Add date filtering if provided
        if startDate or endDate:
            query["timestamp"] = {}
            if startDate:
                query["timestamp"]["$gte"] = startDate
            if endDate:
                query["timestamp"]["$lte"] = endDate
        
        # Query database
        logs = list(db.network_logs.find(query).skip(skip).limit(limit).sort("timestamp", -1))
        total = db.network_logs.count_documents(query)
        
        # Return results
        return {
            "logs": logs,
            "total": total,
            "page": skip // limit + 1 if limit > 0 else 1,
            "pageSize": limit,
            "totalPages": (total + limit - 1) // limit if limit > 0 else 1
        }
    except Exception as e:
        logger.error(f"Error getting network logs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting network logs: {str(e)}")

@app.get("/api/logs/auth", tags=["Logs"])
async def get_auth_logs(
    username: Optional[str] = None,
    src_ip: Optional[str] = None,
    dest_host: Optional[str] = None,
    status: Optional[str] = None,
    auth_method: Optional[str] = None,
    startDate: Optional[str] = None,
    endDate: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    api_key: str = Depends(get_api_key)
):
    """Get authentication logs"""
    try:
        # Build query
        query = {}
        if username:
            query["username"] = {"$regex": username, "$options": "i"}
        if src_ip:
            query["src_ip"] = {"$regex": src_ip, "$options": "i"}
        if dest_host:
            query["dest_host"] = {"$regex": dest_host, "$options": "i"}
        if status:
            query["status"] = status
        if auth_method:
            query["auth_method"] = auth_method
        
        # Add date filtering if provided
        if startDate or endDate:
            query["timestamp"] = {}
            if startDate:
                query["timestamp"]["$gte"] = startDate
            if endDate:
                query["timestamp"]["$lte"] = endDate
        
        # Query database
        logs = list(db.auth_logs.find(query).skip(skip).limit(limit).sort("timestamp", -1))
        total = db.auth_logs.count_documents(query)
        
        # Return results
        return {
            "logs": logs,
            "total": total,
            "page": skip // limit + 1 if limit > 0 else 1,
            "pageSize": limit,
            "totalPages": (total + limit - 1) // limit if limit > 0 else 1
        }
    except Exception as e:
        logger.error(f"Error getting auth logs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting auth logs: {str(e)}")

@app.get("/api/threat-intel", tags=["Threat Intel"])
async def get_threat_intel(
    indicator: Optional[str] = None,
    type: Optional[str] = None,
    min_threat_level: Optional[int] = None,
    max_threat_level: Optional[int] = None,
    source: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    api_key: str = Depends(get_api_key)
):
    """Get threat intelligence indicators"""
    try:
        # Build query
        query = {}
        if indicator:
            query["indicator"] = {"$regex": indicator, "$options": "i"}
        if type:
            query["type"] = type
        
        # Add threat level filtering
        if min_threat_level is not None or max_threat_level is not None:
            query["threat_level"] = {}
            if min_threat_level is not None:
                query["threat_level"]["$gte"] = min_threat_level
            if max_threat_level is not None:
                query["threat_level"]["$lte"] = max_threat_level
        
        if source:
            query["source"] = source
        
        # Query database
        threat_intel = list(db.threat_intel.find(query).skip(skip).limit(limit))
        total = db.threat_intel.count_documents(query)
        
        # Return results
        return {
            "threat_intel": threat_intel,
            "total": total,
            "page": skip // limit + 1 if limit > 0 else 1,
            "pageSize": limit,
            "totalPages": (total + limit - 1) // limit if limit > 0 else 1
        }
    except Exception as e:
        logger.error(f"Error getting threat intelligence: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting threat intelligence: {str(e)}")

@app.get("/api/entities", tags=["Entities"])
async def get_entities(
    entity_type: Optional[str] = None,
    min_score: Optional[float] = None,
    max_score: Optional[float] = None,
    skip: int = 0,
    limit: int = 100,
    api_key: str = Depends(get_api_key)
):
    """Get entity risk scores"""
    try:
        # Build query
        query = {}
        if entity_type:
            query["entity_type"] = entity_type
        
        # Add risk score filtering
        if min_score is not None or max_score is not None:
            query["risk_score"] = {}
            if min_score is not None:
                query["risk_score"]["$gte"] = min_score
            if max_score is not None:
                query["risk_score"]["$lte"] = max_score
        
        # Query database
        entities = list(db.entity_risk_scores.find(query).skip(skip).limit(limit).sort("risk_score", -1))
        total = db.entity_risk_scores.count_documents(query)
        
        # Return results
        return {
            "scores": entities,
            "total": total,
            "page": skip // limit + 1 if limit > 0 else 1,
            "pageSize": limit,
            "totalPages": (total + limit - 1) // limit if limit > 0 else 1
        }
    except Exception as e:
        logger.error(f"Error getting entity risk scores: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting entity risk scores: {str(e)}")

@app.get("/api/entities/{entity_type}/{entity_id}", tags=["Entities"])
async def get_entity_detail(
    entity_type: str,
    entity_id: str,
    api_key: str = Depends(get_api_key)
):
    """Get detailed information about a specific entity"""
    try:
        # Find the entity
        entity = db.entity_risk_scores.find_one({
            "entity_type": entity_type.upper(),
            "entity_id": entity_id
        })
        
        if not entity:
            raise HTTPException(status_code=404, detail="Entity not found")
        
        # Get additional data based on entity type
        additional_data = {}
        
        if entity_type.upper() == "USER":
            # Get recent auth logs for this user
            additional_data["auth_logs"] = list(
                db.auth_logs.find({"username": entity_id}).sort("timestamp", -1).limit(10)
            )
        
        elif entity_type.upper() == "IP":
            # Get threat intel for this IP
            threat_intel = db.threat_intel.find_one({"indicator": entity_id})
            if threat_intel:
                additional_data["threat_intel"] = threat_intel
            
            # Get network logs for this IP
            additional_data["network_logs"] = list(
                db.network_logs.find({
                    "$or": [
                        {"src_ip": entity_id},
                        {"dest_ip": entity_id}
                    ]
                }).sort("timestamp", -1).limit(10)
            )
        
        elif entity_type.upper() == "HOST":
            # Get asset information for this host
            asset = db.assets.find_one({"host": entity_id})
            if asset:
                additional_data["asset"] = asset
        
        # Return entity with additional data
        return {
            **entity,
            "additional_data": additional_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting entity detail: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting entity detail: {str(e)}")

@app.post("/api/entities/recalculate", tags=["Entities"])
async def recalculate_risk_scores(
    request: dict = Body(...),
    api_key: str = Depends(get_api_key)
):
    """Recalculate entity risk scores"""
    try:
        force = request.get("force", False)
        entity_type = request.get("entity_type", None)
        entity_id = request.get("entity_id", None)
        
        # Execute recalculation
        start_time = time.time()
        
        if entity_id and entity_type:
            # Recalculate single entity
            if entity_type.upper() == "USER":
                db.entity_risk_scores.delete_one({"entity_type": "USER", "entity_id": entity_id})
                calculate_user_risk_scores()
            elif entity_type.upper() == "IP":
                db.entity_risk_scores.delete_one({"entity_type": "IP", "entity_id": entity_id})
                calculate_ip_risk_scores()
            elif entity_type.upper() == "HOST":
                db.entity_risk_scores.delete_one({"entity_type": "HOST", "entity_id": entity_id})
                calculate_host_risk_scores()
        elif entity_type:
            # Recalculate entity type
            db.entity_risk_scores.delete_many({"entity_type": entity_type.upper()})
            if entity_type.upper() == "USER":
                calculate_user_risk_scores()
            elif entity_type.upper() == "IP":
                calculate_ip_risk_scores()
            elif entity_type.upper() == "HOST":
                calculate_host_risk_scores()
        else:
            # Recalculate all
            db.entity_risk_scores.delete_many({})
            calculate_user_risk_scores()
            calculate_ip_risk_scores()
            calculate_host_risk_scores()
        
        execution_time = time.time() - start_time
        
        return {
            "message": "Risk scores recalculated successfully",
            "timestamp": datetime.utcnow().isoformat(),
            "entities_processed": db.entity_risk_scores.count_documents({}),
            "execution_time_ms": round(execution_time * 1000)
        }
        
    except Exception as e:
        logger.error(f"Error recalculating risk scores: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error recalculating risk scores: {str(e)}")

@app.put("/api/alerts/{alert_id}/status", tags=["Alerts"])
async def update_alert_status(
    alert_id: str,
    update: AlertStatusUpdate,
    api_key: str = Depends(get_api_key)
):
    """Update alert status"""
    try:
        if update.status not in ["NEW", "IN_PROGRESS", "RESOLVED", "FALSE_POSITIVE"]:
            raise HTTPException(status_code=400, detail="Invalid status")
        
        result = db.alerts.update_one(
            {"_id": alert_id},
            {
                "$set": {
                    "status": update.status,
                    "updated_at": datetime.utcnow().isoformat()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating alert status: {str(e)}")

