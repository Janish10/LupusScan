import os
import requests
import logging

logger = logging.getLogger(__name__)

# Get the API key from environment variable
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')

def check_ip(ip):
    """
    Check an IP address using AbuseIPDB API
    
    Args:
        ip (str): The IP address to check
        
    Returns:
        dict: The check results
    """
    if not ABUSEIPDB_API_KEY:
        logger.error("AbuseIPDB API key not found in environment variables")
        return {"error": "AbuseIPDB API key not found. Please set the ABUSEIPDB_API_KEY environment variable."}
    
    try:
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        }
        
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params
        )
        
        if response.status_code != 200:
            return {"error": f"Error checking IP: {response.text}"}
        
        return response.json()
        
    except Exception as e:
        logger.error(f"Error in check_ip: {str(e)}")
        return {"error": f"Error checking IP: {str(e)}"}

def process_abuseipdb_results(data):
    """Process and format AbuseIPDB check results"""
    if "error" in data:
        return {"error": data["error"]}
    
    try:
        # Extract the data from the response
        data = data.get("data", {})
        
        # Set up the results object
        results = {
            "ipAddress": data.get("ipAddress", "N/A"),
            "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
            "countryCode": data.get("countryCode", "N/A"),
            "domain": data.get("domain", "N/A"),
            "isp": data.get("isp", "N/A"),
            "totalReports": data.get("totalReports", 0),
            "lastReportedAt": data.get("lastReportedAt", "Never"),
            "reports": data.get("reports", [])
        }
        
        # Determine report status - use more sensitive thresholds
        if results["abuseConfidenceScore"] >= 20:
            results["result"] = "malicious"
        elif results["abuseConfidenceScore"] > 0:
            results["result"] = "suspicious"
        else:
            results["result"] = "clean"
        
        return results
    except Exception as e:
        logger.error(f"Error processing AbuseIPDB results: {str(e)}")
        return {"error": f"Error processing AbuseIPDB results: {str(e)}"}