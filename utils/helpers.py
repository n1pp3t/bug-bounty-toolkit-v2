import json
import os
import socket
import re
from datetime import datetime
from urllib.parse import urlparse

def validate_ip(ip):
    """Validate if string is a valid IP address"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_url(url):
    """Validate if string is a valid URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def validate_domain(domain):
    """Validate if string is a valid domain name"""
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return pattern.match(domain) is not None

def parse_port_range(port_range):
    """Parse port range string into list of ports"""
    ports = []
    
    if ',' in port_range:
        # Handle comma-separated ports/ranges
        parts = port_range.split(',')
        for part in parts:
            ports.extend(parse_single_range(part.strip()))
    else:
        ports.extend(parse_single_range(port_range))
    
    return sorted(list(set(ports)))

def parse_single_range(range_str):
    """Parse single port range (e.g., '80-443' or '80')"""
    if '-' in range_str:
        start, end = map(int, range_str.split('-'))
        return list(range(start, end + 1))
    else:
        return [int(range_str)]

def get_common_ports():
    """Return list of commonly scanned ports"""
    return [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
        1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090, 10000
    ]

def save_results(data, filename, format_type='json'):
    """Save results to file in specified format"""
    os.makedirs('output', exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if format_type.lower() == 'json':
        filepath = f"output/{filename}_{timestamp}.json"
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    elif format_type.lower() == 'txt':
        filepath = f"output/{filename}_{timestamp}.txt"
        with open(filepath, 'w') as f:
            if isinstance(data, dict):
                for key, value in data.items():
                    f.write(f"{key}: {value}\n")
            elif isinstance(data, list):
                for item in data:
                    f.write(f"{item}\n")
            else:
                f.write(str(data))
    
    elif format_type.lower() == 'html':
        filepath = f"output/{filename}_{timestamp}.html"
        generate_html_report(data, filepath)
    
    return filepath

def generate_html_report(data, filepath):
    """Generate HTML report from scan data"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bug Bounty Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #f4f4f4; padding: 10px; border-radius: 5px; }}
            .section {{ margin: 20px 0; }}
            .result {{ background-color: #f9f9f9; padding: 10px; margin: 5px 0; border-left: 3px solid #007cba; }}
            .error {{ border-left-color: #d32f2f; }}
            .success {{ border-left-color: #388e3c; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Bug Bounty Reconnaissance Report</h1>
            <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        <div class="section">
            <h2>Scan Results</h2>
            <pre>{json.dumps(data, indent=2, default=str)}</pre>
        </div>
    </body>
    </html>
    """
    
    with open(filepath, 'w') as f:
        f.write(html_content)

def format_bytes(bytes_value):
    """Format bytes into human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"

def get_timestamp():
    """Get current timestamp string"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def clean_url(url):
    """Clean and normalize URL"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')
