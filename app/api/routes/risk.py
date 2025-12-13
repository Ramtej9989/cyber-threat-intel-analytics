import logging
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pymongo.database import Database

from app.api.dependencies import get_db, get_api_key, get_sync_db
from app.core.entity import scoring
from app.database.models import EntityType

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/calculate")
async def calculate_risk_scores(
    entity_type: Optional[EntityType] = None,
    db: Database = Depends(get_db),
    sync_db = Depends(get_sync_db),
    api_key: str = Depends(get_api_key)
):
    """Calculate risk scores for entities"""
    try:
        # Calculate risk scores
        if entity_type:
            # Calculate for specific entity type
            scores = scoring.calculate_entity_risk_scores(sync_db, entity_type)
            
            # Update database with new risk scores
            for score in scores:
                await db.entity_risk_scores.update_one(
                    {"entity_id": score["entity_id"], "entity_type": score["entity_type"]},
                    {"$set": score},
                    upsert=True
                )
                
            return {
                "message": f"Risk scoring completed for {entity_type} entities.",
                "count": len(scores)
            }
        else:
            # Calculate for all entity types
            user_scores = scoring.calculate_entity_risk_scores(sync_db, EntityType.USER)
            ip_scores = scoring.calculate_entity_risk_scores(sync_db, EntityType.IP)
            host_scores = scoring.calculate_entity_risk_scores(sync_db, EntityType.HOST)
            
            # Update database with new risk scores
            all_scores = user_scores + ip_scores + host_scores
            for score in all_scores:
                await db.entity_risk_scores.update_one(
                    {"entity_id": score["entity_id"], "entity_type": score["entity_type"]},
                    {"$set": score},
                    upsert=True
                )
                
            return {
                "message": "Risk scoring completed for all entity types.",
                "user_count": len(user_scores),
                "ip_count": len(ip_scores),
                "host_count": len(host_scores),
                "total_count": len(all_scores)
            }
        
    except Exception as e:
        logger.error(f"Error in risk scoring: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Risk scoring failed: {str(e)}")

@router.get("/scores")
async def get_risk_scores(
    entity_type: Optional[EntityType] = None,
    min_score: float = Query(0.0, ge=0.0, le=10.0),
    limit: int = Query(100, ge=1, le=1000),
    skip: int = Query(0, ge=0),
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Get entity risk scores"""
    try:
        # Build query
        query = {}
        if entity_type:
            query["entity_type"] = entity_type
        if min_score > 0:
            query["risk_score"] = {"$gte": min_score}
        
        # Get risk scores
        scores = await db.entity_risk_scores.find(query).sort("risk_score", -1).skip(skip).limit(limit).to_list(limit)
        count = await db.entity_risk_scores.count_documents(query)
        
        return {
            "total": count,
            "scores": scores
        }
        
    except Exception as e:
        logger.error(f"Error getting risk scores: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve risk scores: {str(e)}")

@router.get("/entities/{entity_type}/{entity_id}")
async def get_entity_profile(
    entity_type: EntityType,
    entity_id: str,
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Get detailed profile for an entity including risk factors"""
    try:
        # Get risk score
        risk_score = await db.entity_risk_scores.find_one(
            {"entity_id": entity_id, "entity_type": entity_type}
        )
        
        if not risk_score:
            raise HTTPException(status_code=404, detail="Entity not found")
        
        # Get additional data based on entity type
        additional_data = {}
        
        if entity_type == EntityType.USER:
            # Get user's recent auth logs
            auth_logs = await db.auth_logs.find({"username": entity_id}).sort("timestamp", -1).limit(20).to_list(20)
            additional_data["auth_logs"] = auth_logs
            
        elif entity_type == EntityType.IP:
            # Get IP's network logs
            network_logs = await db.network_logs.find({"$or": [{"src_ip": entity_id}, {"dest_ip": entity_id}]}).sort("timestamp", -1).limit(20).to_list(20)
            auth_logs = await db.auth_logs.find({"src_ip": entity_id}).sort("timestamp", -1).limit(20).to_list(20)
            
            # Check if IP is in threat intel
            threat_intel = await db.threat_intel.find_one({"indicator": entity_id})
            
            additional_data["network_logs"] = network_logs
            additional_data["auth_logs"] = auth_logs
            additional_data["threat_intel"] = threat_intel
            
        elif entity_type == EntityType.HOST:
            # Get host's logs
            auth_logs = await db.auth_logs.find({"dest_host": entity_id}).sort("timestamp", -1).limit(20).to_list(20)
            
            # Get asset info
            asset = await db.assets.find_one({"host": entity_id})
            
            additional_data["auth_logs"] = auth_logs
            additional_data["asset"] = asset
        
        # Combine data for response
        response = {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "risk_score": risk_score["risk_score"],
            "risk_factors": risk_score["risk_factors"],
            "last_updated": risk_score["last_updated"],
            "additional_data": additional_data
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting entity profile: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve entity profile: {str(e)}")
