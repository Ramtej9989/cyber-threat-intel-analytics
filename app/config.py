import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings  # Changed from pydantic import BaseSettings

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    """Application settings"""
    
    # MongoDB settings
    MONGODB_URI: str = os.getenv("MONGODB_URI", "")
    MONGODB_DB: str = os.getenv("MONGODB_DB", "soc_platform")
    
    # API settings
    API_SECRET_KEY: str = os.getenv("API_SECRET_KEY", "default-secret-key")
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    class Config:
        env_file = ".env"

settings = Settings()
