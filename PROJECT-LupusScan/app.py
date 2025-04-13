import os
import logging
from datetime import datetime
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from config import Config

# Import forms
from forms import URLScanForm, IPScanForm, FileScanForm

# Import services
from services.virus_total import scan_url, scan_ip, scan_file, process_url_results, process_ip_results, process_file_results
from services.abuseipdb import check_ip, process_abuseipdb_results

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Helper function to check if file is allowed
def allowed_file(filename):
    """Check if file type is allowed for upload"""
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'exe', 'dll', 'zip'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Home page route"""
    return render_template('index.html')

@app.route('/url-scan', methods=['GET', 'POST'])
def url_scan():
    """URL scanning route"""
    form = URLScanForm()
    
    if form.validate_on_submit():
        url = form.url.data
        
        # Scan the URL
        scan_data = scan_url(url)
        
        # Print raw data for debugging
        print("URL SCAN RAW DATA:", scan_data)
        
        # Process the results
        results = process_url_results(scan_data)
        
        # Print processed results for debugging
        print("URL SCAN PROCESSED RESULTS:", results)
        
        return render_template('url_scan.html', form=form, url=url, results=results)
    
    return render_template('url_scan.html', form=form)

@app.route('/ip-scan', methods=['GET', 'POST'])
def ip_scan():
    """IP scanning route"""
    form = IPScanForm()
    
    if form.validate_on_submit():
        ip = form.ip.data
        
        # Get VirusTotal results
        vt_data = scan_ip(ip)
        vt_results = process_ip_results(vt_data)
        
        # Print raw VirusTotal data for debugging
        print("VT RAW DATA:", vt_data)
        print("VT PROCESSED RESULTS:", vt_results)
        
        # Get AbuseIPDB results
        abuse_data = check_ip(ip)
        abuse_results = process_abuseipdb_results(abuse_data)
        
        # Print raw AbuseIPDB data for debugging
        print("ABUSE RAW DATA:", abuse_data)
        print("ABUSE PROCESSED RESULTS:", abuse_results)
        
        return render_template('ip_scan.html', form=form, ip=ip, vt_results=vt_results, abuse_results=abuse_results)
    
    return render_template('ip_scan.html', form=form)

@app.route('/file-scan', methods=['GET', 'POST'])
def file_scan():
    """File scanning route"""
    form = FileScanForm()
    
    if form.validate_on_submit():
        file = form.file.data
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                file.save(file_path)
                
                # Scan the file
                scan_data = scan_file(file_path, filename)
                
                # Process the results
                results = process_file_results(scan_data, filename)
                
                # Remove the file after scanning
                try:
                    os.remove(file_path)
                except Exception as e:
                    logger.error(f"Error removing file: {str(e)}")
                
                return render_template('file_scan.html', form=form, filename=filename, results=results)
                
            except RequestEntityTooLarge:
                flash('The file is too large. Maximum size is 10 MB.', 'danger')
            except Exception as e:
                logger.error(f"Error scanning file: {str(e)}")
                flash(f'Error scanning file: {str(e)}', 'danger')
        else:
            flash('Invalid file type.', 'danger')
    
    return render_template('file_scan.html', form=form)

@app.route('/about')
def about():
    """About page route"""
    return render_template('about.html')

@app.errorhandler(404)
def page_not_found(e):
    """404 error handler"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """500 error handler"""
    return render_template('500.html'), 500

# Set secret key from environment variable with a fallback
app.secret_key = os.environ.get('SESSION_SECRET', 'default-secret-key')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)