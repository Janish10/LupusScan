import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Application configuration
class Config:
    # Secret key for sessions
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'your-default-secret-key')
    
    # VirusTotal API configuration
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
    VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3'
    
    # AbuseIPDB API configuration 
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
    ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2'
    
    # Upload folder configuration
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size