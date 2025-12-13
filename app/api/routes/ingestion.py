import csv
import io
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Query
from pymongo.database import Database

from app.api.dependencies import get_db, get_api_key
from app.database.models import NetworkLog, AuthLog, Asset, ThreatIntel

router = APIRouter()

@router.post("/upload/network_logs")
async def upload_network_logs(
    file: UploadFile = File(...),
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Upload and ingest network logs from CSV"""
    try:
        contents = await file.read()
        buffer = io.StringIO(contents.decode('utf-8'))
        csv_reader = csv.DictReader(buffer)
        
        network_logs = []
        for row in csv_reader:
            network_log = {
                'timestamp': datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00')),
                'src_ip': row['src_ip'],
                'dest_ip': row['dest_ip'],
                'src_port': int(row['src_port']),
                'dest_port': int(row['dest_port']),
                'protocol': row['protocol'],
                'action': row['action'],
                'bytes_sent': int(row['bytes_sent']),
                'bytes_received': int(row['bytes_received']),
                'label': row.get('label', 'unknown')  # Use get to handle optional field
            }
            network_logs.append(network_log)
        
        if network_logs:
            result = await db.network_logs.insert_many(network_logs)
            return {
                "message": f"Successfully ingested {len(result.inserted_ids)} network logs",
                "count": len(result.inserted_ids)
            }
        
        return {"message": "No logs were ingested", "count": 0}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest network logs: {str(e)}")

@router.post("/upload/auth_logs")
async def upload_auth_logs(
    file: UploadFile = File(...),
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Upload and ingest authentication logs from CSV"""
    try:
        contents = await file.read()
        buffer = io.StringIO(contents.decode('utf-8'))
        csv_reader = csv.DictReader(buffer)
        
        auth_logs = []
        for row in csv_reader:
            auth_log = {
                'timestamp': datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00')),
                'username': row['username'],
                'src_ip': row['src_ip'],
                'dest_host': row['dest_host'],
                'status': row['status'],
                'auth_method': row['auth_method']
            }
            auth_logs.append(auth_log)
        
        if auth_logs:
            result = await db.auth_logs.insert_many(auth_logs)
            return {
                "message": f"Successfully ingested {len(result.inserted_ids)} authentication logs",
                "count": len(result.inserted_ids)
            }
        
        return {"message": "No logs were ingested", "count": 0}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest authentication logs: {str(e)}")

@router.post("/upload/assets")
async def upload_assets(
    file: UploadFile = File(...),
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Upload and ingest assets from CSV"""
    try:
        contents = await file.read()
        buffer = io.StringIO(contents.decode('utf-8'))
        csv_reader = csv.DictReader(buffer)
        
        assets = []
        for row in csv_reader:
            asset = {
                'host': row['host'],
                'ip_address': row['ip_address'],
                'owner': row['owner'],
                'criticality': int(row['criticality'])
            }
            assets.append(asset)
        
        if assets:
            # Use upsert to avoid duplicates based on host name
            for asset in assets:
                await db.assets.update_one(
                    {'host': asset['host']},
                    {'$set': asset},
                    upsert=True
                )
            
            return {
                "message": f"Successfully processed {len(assets)} assets",
                "count": len(assets)
            }
        
        return {"message": "No assets were ingested", "count": 0}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest assets: {str(e)}")

@router.post("/upload/threat_intel")
async def upload_threat_intel(
    file: UploadFile = File(...),
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Upload and ingest threat intelligence from CSV"""
    try:
        contents = await file.read()
        buffer = io.StringIO(contents.decode('utf-8'))
        csv_reader = csv.DictReader(buffer)
        
        threat_intel_items = []
        for row in csv_reader:
            threat_intel = {
                'indicator': row['indicator'],
                'type': row['type'],
                'threat_level': int(row['threat_level']),
                'source': row['source'],
                'first_seen': datetime.fromisoformat(row['first_seen'].replace('Z', '+00:00')),
                'last_seen': datetime.fromisoformat(row['last_seen'].replace('Z', '+00:00'))
            }
            threat_intel_items.append(threat_intel)
        
        if threat_intel_items:
            # Use upsert to avoid duplicates based on indicator
            for item in threat_intel_items:
                await db.threat_intel.update_one(
                    {'indicator': item['indicator']},
                    {'$set': item},
                    upsert=True
                )
            
            return {
                "message": f"Successfully processed {len(threat_intel_items)} threat intelligence items",
                "count": len(threat_intel_items)
            }
        
        return {"message": "No threat intelligence was ingested", "count": 0}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest threat intelligence: {str(e)}")

@router.get("/logs/network")
async def get_network_logs(
    limit: int = Query(100, ge=1, le=1000),
    skip: int = Query(0, ge=0),
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Retrieve network logs"""
    try:
        logs = await db.network_logs.find().sort("timestamp", -1).skip(skip).limit(limit).to_list(limit)
        count = await db.network_logs.count_documents({})
        
        return {
            "total": count,
            "logs": logs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve network logs: {str(e)}")

@router.get("/logs/auth")
async def get_auth_logs(
    limit: int = Query(100, ge=1, le=1000),
    skip: int = Query(0, ge=0),
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Retrieve authentication logs"""
    try:
        logs = await db.auth_logs.find().sort("timestamp", -1).skip(skip).limit(limit).to_list(limit)
        count = await db.auth_logs.count_documents({})
        
        return {
            "total": count,
            "logs": logs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve authentication logs: {str(e)}")

@router.get("/assets")
async def get_assets(
    limit: int = Query(100, ge=1, le=1000),
    skip: int = Query(0, ge=0),
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Retrieve assets"""
    try:
        assets = await db.assets.find().skip(skip).limit(limit).to_list(limit)
        count = await db.assets.count_documents({})
        
        return {
            "total": count,
            "assets": assets
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve assets: {str(e)}")

@router.get("/threat_intel")
async def get_threat_intel(
    limit: int = Query(100, ge=1, le=1000),
    skip: int = Query(0, ge=0),
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Retrieve threat intelligence"""
    try:
        threat_intel = await db.threat_intel.find().skip(skip).limit(limit).to_list(limit)
        count = await db.threat_intel.count_documents({})
        
        return {
            "total": count,
            "threat_intel": threat_intel
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve threat intelligence: {str(e)}")

@router.get("/status")
async def get_data_status(
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Get status of loaded data"""
    try:
        network_logs_count = await db.network_logs.count_documents({})
        auth_logs_count = await db.auth_logs.count_documents({})
        assets_count = await db.assets.count_documents({})
        threat_intel_count = await db.threat_intel.count_documents({})
        
        return {
            "network_logs": network_logs_count,
            "auth_logs": auth_logs_count,
            "assets": assets_count,
            "threat_intel": threat_intel_count,
            "has_data": network_logs_count > 0 and auth_logs_count > 0 and assets_count > 0 and threat_intel_count > 0,
            "timestamp": datetime.utcnow()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking data status: {str(e)}")

@router.delete("/all")
async def delete_all_data(
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Delete all data (except users) - use with caution"""
    try:
        # Delete all data from collections except users
        await db.network_logs.delete_many({})
        await db.auth_logs.delete_many({})
        await db.assets.delete_many({})
        await db.threat_intel.delete_many({})
        await db.alerts.delete_many({})
        await db.entity_risk_scores.delete_many({})
        await db.graph_summary.delete_many({})
        
        return {
            "message": "All data has been deleted",
            "timestamp": datetime.utcnow()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting data: {str(e)}")
