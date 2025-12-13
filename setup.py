import os
import sys
import subprocess
import logging
import asyncio
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def check_python_version():
    """Check Python version"""
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 9):
        logger.error("Python 3.9 or higher is required")
        sys.exit(1)
    logger.info(f"Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")

def create_folders():
    """Create necessary folders"""
    folders = [
        "data",
        "models"
    ]
    for folder in folders:
        os.makedirs(folder, exist_ok=True)
        logger.info(f"Created folder: {folder}")

def install_dependencies():
    """Install dependencies"""
    try:
        logger.info("Installing dependencies...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
        logger.info("Dependencies installed successfully")
    except subprocess.CalledProcessError:
        logger.error("Failed to install dependencies")
        sys.exit(1)

def create_env_file():
    """Create .env file if it doesn't exist"""
    env_file = Path(".env")
    if env_file.exists():
        logger.info(".env file already exists")
        return
    
    logger.info("Creating .env file")
    
    mongodb_uri = input("MongoDB URI (default: mongodb+srv://tejbonthu45_db_user:k476QemWIp0ZYusO@cyberintelcluster.q7kvfn9.mongodb.net/?retryWrites=true&w=majority&appName=CyberIntelCluster): ") or "mongodb+srv://tejbonthu45_db_user:k476QemWIp0ZYusO@cyberintelcluster.q7kvfn9.mongodb.net/?retryWrites=true&w=majority&appName=CyberIntelCluster"
    db_name = input("Database name (default: soc_platform): ") or "soc_platform"
    api_key = input("API Secret Key (default: your-secret-key-for-api-auth): ") or "your-secret-key-for-api-auth"
    log_level = input("Log level (default: INFO): ") or "INFO"
    
    with open(env_file, "w") as f:
        f.write(f"MONGODB_URI=\"{mongodb_uri}\"\n")
        f.write(f"MONGODB_DB=\"{db_name}\"\n")
        f.write(f"API_SECRET_KEY=\"{api_key}\"\n")
        f.write(f"LOG_LEVEL=\"{log_level}\"\n")
    
    logger.info(".env file created")

def move_sample_data():
    """Move sample CSV files to data directory"""
    data_dir = Path("data")
    
    # Check if sample data files exist in the current directory
    sample_files = ["assets.csv", "threat_intel.csv", "auth_logs.csv", "network_logs.csv"]
    for file_name in sample_files:
        source = Path(file_name)
        dest = data_dir / file_name
        
        if source.exists() and not dest.exists():
            import shutil
            shutil.copy(source, dest)
            logger.info(f"Moved {file_name} to data directory")

async def initialize_database():
    """Initialize database with sample data"""
    logger.info("Initializing database...")
    try:
        from app.utils.init_db import main as init_db_main
        await init_db_main()
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        sys.exit(1)

def main():
    """Main setup function"""
    logger.info("Starting setup...")
    
    # Check Python version
    check_python_version()
    
    # Create necessary folders
    create_folders()
    
    # Install dependencies
    install_dependencies()
    
    # Create .env file
    create_env_file()
    
    # Move sample data if available
    move_sample_data()
    
    # Initialize database
    asyncio.run(initialize_database())
    
    logger.info("Setup complete!")
    logger.info("You can now start the application with: uvicorn main:app --reload")

if __name__ == "__main__":
    main()
