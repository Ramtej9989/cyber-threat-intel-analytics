from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, APIKeyQuery

from app.config import settings
from app.database.connection import get_database, get_sync_database

# API key security options
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)

async def get_api_key(
    api_key_header: str = Security(api_key_header),
    api_key_query: str = Security(api_key_query)
):
    """Validate API key from header or query parameter"""
    api_key = api_key_header or api_key_query
    
    if api_key == settings.API_SECRET_KEY:
        return api_key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key",
    )

# Database dependencies
async def get_db():
    """Get MongoDB database instance"""
    return get_database()

def get_sync_db():
    """Get sync MongoDB database instance"""
    return get_sync_database()
