import os
import requests
import logging

logger = logging.getLogger(__name__)

# Get the API key from environment variable
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

def scan_url(url):
    """
    Scan a URL using VirusTotal API
    
    Args:
        url (str): The URL to scan
        
    Returns:
        dict: The scan results
    """
    if not VIRUSTOTAL_API_KEY:
        logger.error("VirusTotal API key not found in environment variables")
        return {"error": "VirusTotal API key not found. Please set the VIRUSTOTAL_API_KEY environment variable."}
    
    try:
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        
        # First check if the URL has been scanned before
        url_id = requests.utils.quote(url, safe='')
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers
        )
        
        # If URL not found or need to rescan
        if response.status_code == 404 or response.status_code >= 400:
            # Submit URL for scanning
            scan_data = {
                "url": url
            }
            response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data=scan_data
            )
            
            if response.status_code != 200:
                return {"error": f"Error submitting URL scan: {response.text}"}
            
            # Get the analysis ID from the response
            analysis_id = response.json().get("data", {}).get("id")
            
            # Get analysis results
            response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )
        
        if response.status_code != 200:
            return {"error": f"Error getting scan results: {response.text}"}
        
        return response.json()
        
    except Exception as e:
        logger.error(f"Error in scan_url: {str(e)}")
        return {"error": f"Error scanning URL: {str(e)}"}

def scan_ip(ip):
    """
    Get information about an IP address from VirusTotal
    
    Args:
        ip (str): The IP address to check
        
    Returns:
        dict: The scan results
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not found. Please set the VIRUSTOTAL_API_KEY environment variable."}
    
    try:
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        
        # Get IP report
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers
        )
        
        if response.status_code != 200:
            return {"error": f"Error getting IP information: {response.text}"}
        
        return response.json()
        
    except Exception as e:
        logger.error(f"Error in scan_ip: {str(e)}")
        return {"error": f"Error scanning IP: {str(e)}"}

def scan_file(file_path, original_filename):
    """
    Scan a file using VirusTotal API
    
    Args:
        file_path (str): Path to the file to scan
        original_filename (str): Original name of the file
        
    Returns:
        dict: The scan results
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not found. Please set the VIRUSTOTAL_API_KEY environment variable."}
    
    try:
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        
        # Upload file for scanning
        with open(file_path, 'rb') as file:
            files = {'file': (original_filename, file)}
            response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files=files
            )
        
        if response.status_code != 200:
            return {"error": f"Error uploading file: {response.text}"}
        
        # Get the analysis ID from the response
        analysis_id = response.json().get("data", {}).get("id")
        
        # Get analysis results
        response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )
        
        if response.status_code != 200:
            return {"error": f"Error getting file scan results: {response.text}"}
        
        return response.json()
        
    except Exception as e:
        logger.error(f"Error in scan_file: {str(e)}")
        return {"error": f"Error scanning file: {str(e)}"}

def process_url_results(report_data):
    """Process and format URL scan results"""
    if "error" in report_data:
        return {"error": report_data["error"]}
    
    try:
        # Extract the relevant data from the response
        data = report_data.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("stats", {})
        
        # Set default values
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        results = {
            "url": attributes.get("url", "N/A"),
            "scan_date": attributes.get("date", "N/A"),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": stats.get("timeout", 0),
            "reputation": attributes.get("reputation", 0),
            "total_votes": attributes.get("total_votes", {}),
            "analysis_stats": stats,
            "status": "completed"
        }
        
        # Calculate detection rate
        total_scans = malicious + suspicious + harmless + undetected
        if total_scans > 0:
            detection_rate = (malicious + suspicious) / total_scans * 100
            results["detection_rate"] = f"{detection_rate:.2f}%"
        else:
            results["detection_rate"] = "0%"
        
        # Determine result status - use more sensitive thresholds
        if malicious > 0:
            results["result"] = "malicious"
        elif suspicious > 0:
            results["result"] = "suspicious"
        elif total_scans == 0:
            results["result"] = "unknown"
        else:
            results["result"] = "clean"
            
        return results
        
    except Exception as e:
        logger.error(f"Error processing URL results: {str(e)}")
        return {"error": f"Error processing scan results: {str(e)}"}

def process_ip_results(ip_data):
    """Process and format IP scan results"""
    if "error" in ip_data:
        return {"error": ip_data["error"]}
    
    try:
        # Extract the relevant data from the response
        data = ip_data.get("data", {})
        attributes = data.get("attributes", {})
        
        # Get analysis stats
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        harmless = stats.get("harmless", 0)
        
        results = {
            "ip": attributes.get("ip", "N/A"),
            "as_owner": attributes.get("as_owner", "N/A"),
            "country": attributes.get("country", "N/A"),
            "reputation": attributes.get("reputation", 0),
            "malicious": malicious,
            "harmless": harmless,
            "last_analysis_stats": stats,
            "status": "completed"
        }
        
        # Calculate detection rate
        total_scans = sum(stats.values()) if stats else 0
        if total_scans > 0:
            detection_rate = malicious / total_scans * 100
            results["detection_rate"] = f"{detection_rate:.2f}%"
        else:
            results["detection_rate"] = "0%"
        
        # Determine result status - be more conservative
        if malicious > 0:
            results["result"] = "malicious"
        elif total_scans == 0:
            results["result"] = "unknown"
        else:
            results["result"] = "clean"
            
        return results
        
    except Exception as e:
        logger.error(f"Error processing IP results: {str(e)}")
        return {"error": f"Error processing scan results: {str(e)}"}

def process_file_results(report_data, original_filename):
    """Process and format file scan results"""
    if "error" in report_data:
        return {"error": report_data["error"]}
    
    try:
        # Extract the relevant data from the response
        data = report_data.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("stats", {})
        
        # Set default values
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        results = {
            "filename": original_filename,
            "scan_date": attributes.get("date", "N/A"),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "analysis_stats": stats,
            "status": "completed"
        }
        
        # Calculate detection rate
        total_scans = malicious + suspicious + harmless + undetected
        if total_scans > 0:
            detection_rate = (malicious + suspicious) / total_scans * 100
            results["detection_rate"] = f"{detection_rate:.2f}%"
        else:
            results["detection_rate"] = "0%"
        
        # Determine result status - be more conservative
        if malicious > 0:
            results["result"] = "malicious"
        elif suspicious > 0:
            results["result"] = "suspicious"
        elif total_scans == 0:
            results["result"] = "unknown"
        else:
            results["result"] = "clean"
            
        return results
        
    except Exception as e:
        logger.error(f"Error processing file results: {str(e)}")
        return {"error": f"Error processing scan results: {str(e)}"}