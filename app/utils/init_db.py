import logging
import asyncio
import sys
import os
from datetime import datetime
import pymongo
from pymongo.errors import DuplicateKeyError
from passlib.hash import bcrypt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def init_db():
    """Initialize the database with collections and indexes only - no sample data"""
    try:
        # Get MongoDB connection string from environment
        mongodb_uri = os.getenv("MONGODB_URI", "mongodb+srv://tejbonthu45_db_user:k476QemWIp0ZYusO@cyberintelcluster.q7kvfn9.mongodb.net/?retryWrites=true&w=majority&appName=CyberIntelCluster")
        mongodb_db = os.getenv("MONGODB_DB", "soc_platform")
        
        # Connect to MongoDB
        client = pymongo.MongoClient(mongodb_uri)
        db = client[mongodb_db]
        
        # Create collections
        collections = [
            'users', 'auth_logs', 'network_logs', 'endpoint_logs', 
            'assets', 'threat_intel', 'alerts', 'entity_risk_scores', 
            'graph_summary'
        ]
        
        for collection in collections:
            if collection not in db.list_collection_names():
                logger.info(f"Creating collection: {collection}")
                db.create_collection(collection)
        
        # Create indexes
        logger.info("Creating indexes")
        db.users.create_index("email", unique=True)
        db.auth_logs.create_index("timestamp")
        db.auth_logs.create_index("src_ip")
        db.auth_logs.create_index("username")
        db.network_logs.create_index("timestamp")
        db.network_logs.create_index("src_ip")
        db.network_logs.create_index("dest_ip")
        db.alerts.create_index("timestamp")
        db.alerts.create_index("severity")
        db.entity_risk_scores.create_index("entity_id")
        db.entity_risk_scores.create_index("entity_type")
        db.threat_intel.create_index("indicator", unique=True)
        
        # Create default admin user if not exists
        admin_user = db.users.find_one({"email": "admin@example.com"})
        if not admin_user:
            logger.info("Creating default admin user")
            db.users.insert_one({
                "name": "Admin User",
                "email": "admin@example.com",
                "password_hash": bcrypt.hash("admin123"),
                "role": "ADMIN",
                "createdAt": datetime.utcnow()
            })
            
        # Create default analyst user if not exists
        analyst_user = db.users.find_one({"email": "analyst@example.com"})
        if not analyst_user:
            logger.info("Creating default analyst user")
            db.users.insert_one({
                "name": "Analyst User",
                "email": "analyst@example.com",
                "password_hash": bcrypt.hash("analyst123"),
                "role": "ANALYST",
                "createdAt": datetime.utcnow()
            })
        
        logger.info("Database initialization complete")
        return db
        
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        raise

async def main():
    """Main function to initialize database"""
    try:
        await init_db()
        logger.info("Database setup complete")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
