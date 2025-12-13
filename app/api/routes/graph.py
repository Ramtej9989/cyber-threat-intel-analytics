import logging
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pymongo.database import Database

from app.api.dependencies import get_db, get_api_key, get_sync_db
from app.core.graph import builder

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/build")
async def build_threat_graph(
    hours_back: int = Query(24, ge=1, le=168),
    db: Database = Depends(get_db),
    sync_db = Depends(get_sync_db),
    api_key: str = Depends(get_api_key)
):
    """Build a threat graph from logs and alerts"""
    try:
        # Get time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours_back)
        
        # Build graph (this is synchronous due to networkx)
        graph_data = builder.build_threat_graph(sync_db, start_time, end_time)
        
        # Save graph summary
        summary = {
            "timestamp": datetime.utcnow(),
            "node_count": graph_data["node_count"],
            "edge_count": graph_data["edge_count"],
            "top_central_entities": graph_data["top_central_entities"],
            "metadata": {
                "hours_back": hours_back,
                "start_time": start_time,
                "end_time": end_time
            }
        }
        
        await db.graph_summary.insert_one(summary)
        
        return {
            "message": "Threat graph built successfully",
            "summary": summary
        }
        
    except Exception as e:
        logger.error(f"Error building threat graph: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Graph building failed: {str(e)}")

@router.get("/summary")
async def get_graph_summary(
    db: Database = Depends(get_db),
    api_key: str = Depends(get_api_key)
):
    """Get the latest graph summary"""
    try:
        # Get latest summary
        summary = await db.graph_summary.find_one({}, sort=[("timestamp", -1)])
        
        if not summary:
            raise HTTPException(status_code=404, detail="No graph summary found")
        
        return summary
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving graph summary: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve graph summary: {str(e)}")

@router.get("/paths")
async def find_attack_paths(
    source: str,
    target: str,
    db: Database = Depends(get_db),
    sync_db = Depends(get_sync_db),
    api_key: str = Depends(get_api_key)
):
    """Find potential attack paths between entities"""
    try:
        # Build the latest graph
        graph_data = builder.get_latest_graph(sync_db)
        
        if not graph_data or "graph" not in graph_data:
            raise HTTPException(status_code=404, detail="No graph available. Build a graph first.")
        
        # Find paths
        paths = builder.find_attack_paths(graph_data["graph"], source, target)
        
        if not paths:
            return {
                "message": "No paths found between these entities",
                "paths": []
            }
        
        return {
            "message": f"Found {len(paths)} possible attack path(s)",
            "source": source,
            "target": target,
            "paths": paths
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error finding attack paths: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to find attack paths: {str(e)}")

@router.get("/neighbors/{entity_id}")
async def get_entity_neighbors(
    entity_id: str,
    entity_type: Optional[str] = None,
    db: Database = Depends(get_db),
    sync_db = Depends(get_sync_db),
    api_key: str = Depends(get_api_key)
):
    """Get neighboring entities in the threat graph"""
    try:
        # Get the latest graph
        graph_data = builder.get_latest_graph(sync_db)
        
        if not graph_data or "graph" not in graph_data:
            raise HTTPException(status_code=404, detail="No graph available. Build a graph first.")
        
        # Get neighbors
        neighbors = builder.get_entity_neighbors(graph_data["graph"], entity_id, entity_type)
        
        if not neighbors:
            return {
                "entity_id": entity_id,
                "neighbors": []
            }
        
        return {
            "entity_id": entity_id,
            "neighbors": neighbors
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting entity neighbors: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get entity neighbors: {str(e)}")
