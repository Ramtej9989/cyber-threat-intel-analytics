import logging
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

from app.config import settings

# Configure logging
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL))
logger = logging.getLogger(__name__)

# Global database client instances
async_client = None
async_db = None
sync_client = None
sync_db = None

async def connect_and_init_db():
    """Connect to MongoDB and initialize collections"""
    global async_client, async_db, sync_client, sync_db
    
    try:
        # Async client for FastAPI operations
        async_client = AsyncIOMotorClient(settings.MONGODB_URI)
        async_db = async_client[settings.MONGODB_DB]
        
        # Sync client for some operations that might need it
        sync_client = MongoClient(settings.MONGODB_URI)
        sync_db = sync_client[settings.MONGODB_DB]
        
        # Create indexes for collections
        await create_indexes()
        
        logger.info("Connected to MongoDB")
    except ConnectionFailure as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise

async def create_indexes():
    """Create necessary indexes for collections"""
    # Users collection
    await async_db.users.create_index("email", unique=True)
    
    # Auth logs collection
    await async_db.auth_logs.create_index("timestamp")
    await async_db.auth_logs.create_index("src_ip")
    await async_db.auth_logs.create_index("username")
    
    # Network logs collection
    await async_db.network_logs.create_index("timestamp")
    await async_db.network_logs.create_index("src_ip")
    await async_db.network_logs.create_index("dest_ip")
    
    # Alerts collection
    await async_db.alerts.create_index("timestamp")
    await async_db.alerts.create_index("severity")
    
    # Entity risk scores collection
    await async_db.entity_risk_scores.create_index("entity_id")
    await async_db.entity_risk_scores.create_index("entity_type")
    
    # Threat intel collection
    await async_db.threat_intel.create_index("indicator", unique=True)
    
    logger.info("MongoDB indexes created")

def get_database():
    """Get MongoDB database instance (async)"""
    return async_db

def get_sync_database():
    """Get MongoDB database instance (sync)"""
    return sync_db
