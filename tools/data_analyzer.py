import json
import os
from collections import Counter, defaultdict
from datetime import datetime
import re
from utils.logger import setup_logger, log_error
from utils.helpers import save_results, get_timestamp

class DataAnalyzer:
    def __init__(self):
        self.logger = setup_logger("data_analyzer")
        self.analysis_results = {}
        
    def load_scan_data(self, file_path):
        """Load scan data from JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            self.logger.info(f"Loaded scan data from {file_path}")
            return data
        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
            return None
        except json.JSONDecodeError as e:
            log_error(f"Invalid JSON in file: {file_path}", self.logger, e)
            return None
        except Exception as e:
            log_error(f"Error loading file: {file_path}", self.logger, e)
            return None
    
    def analyze_port_scan(self, scan_data):
        """Analyze port scan results"""
        if scan_data.get('scan_type') != 'port_scan':
            self.logger.warning("Data is not from a port scan")
            return None
        
        open_ports = scan_data.get('open_ports', [])
        
        analysis = {
            'scan_type': 'port_scan_analysis',
            'target': scan_data.get('target'),
            'timestamp': get_timestamp(),
            'summary': {
                'total_open_ports': len(open_ports),
                'total_scanned': scan_data.get('total_scanned', 0),
                'scan_date': scan_data.get('timestamp')
            },
            'service_breakdown': {},
            'risk_assessment': {},
            'recommendations': []
        }
        
        # Service breakdown
        services = [port['service'] for port in open_ports]
        service_counts = Counter(services)
        analysis['service_breakdown'] = dict(service_counts)
        
        # Risk assessment
        high_risk_ports = []
        medium_risk_ports = []
        low_risk_ports = []
        
        risk_categories = {
            'high': [21, 23, 135, 139, 445, 1433, 3389, 5432, 5900],  # FTP, Telnet, RPC, SMB, SQL, RDP, VNC
            'medium': [22, 25, 53, 110, 143, 993, 995, 3306],  # SSH, SMTP, DNS, POP3, IMAP, MySQL
            'low': [80, 443, 8080, 8443, 8888]  # HTTP/HTTPS
        }
        
        for port_info in open_ports:
            port_num = port_info['port']
            if port_num in risk_categories['high']:
                high_risk_ports.append(port_info)
            elif port_num in risk_categories['medium']:
                medium_risk_ports.append(port_info)
            else:
                low_risk_ports.append(port_info)
        
        analysis['risk_assessment'] = {
            'high_risk': {
                'count': len(high_risk_ports),
                'ports': high_risk_ports
            },
            'medium_risk': {
                'count': len(medium_risk_ports),
                'ports': medium_risk_ports
            },
            'low_risk': {
                'count': len(low_risk_ports),
                'ports': low_risk_ports
            }
        }
        
        # Generate recommendations
        recommendations = []
        
        if high_risk_ports:
            recommendations.append("HIGH PRIORITY: Review high-risk services (FTP, Telnet, RDP, etc.) for security configurations")
        
        if any(port['port'] in [21, 23] for port in open_ports):
            recommendations.append("Consider disabling unencrypted protocols (FTP, Telnet) and use secure alternatives")
        
        if any(port['port'] == 3389 for port in open_ports):
            recommendations.append("RDP is exposed - ensure strong authentication and consider VPN access")
        
        if any(port['port'] in [1433, 3306, 5432] for port in open_ports):
            recommendations.append("Database services are exposed - verify access controls and firewall rules")
        
        web_ports = [port for port in open_ports if port['port'] in [80, 443, 8080, 8443, 8888]]
        if web_ports:
            recommendations.append(f"Web services found on {len(web_ports)} ports - consider directory enumeration")
        
        analysis['recommendations'] = recommendations
        
        self.logger.info(f"Port scan analysis completed for {analysis['target']}")
        return analysis
    
    def analyze_directory_scan(self, scan_data):
        """Analyze directory enumeration results"""
        if scan_data.get('scan_type') != 'directory_enumeration':
            self.logger.warning("Data is not from a directory scan")
            return None
        
        directories = scan_data.get('directories', [])
        files = scan_data.get('files', [])
        
        analysis = {
            'scan_type': 'directory_scan_analysis',
            'target': scan_data.get('target'),
            'timestamp': get_timestamp(),
            'summary': {
                'total_directories': len(directories),
                'total_files': len(files),
                'total_found': len(directories) + len(files),
                'scan_date': scan_data.get('timestamp')
            },
            'status_code_breakdown': {},
            'interesting_findings': {},
            'file_extensions': {},
            'recommendations': []
        }
        
        # Status code breakdown
        all_items = directories + files
        status_codes = [item['status_code'] for item in all_items]
        status_counts = Counter(status_codes)
        analysis['status_code_breakdown'] = dict(status_counts)
        
        # File extension analysis
        file_extensions = []
        for file_item in files:
            path = file_item['path']
            if '.' in path:
                ext = path.split('.')[-1].lower()
                file_extensions.append(ext)
        
        ext_counts = Counter(file_extensions)
        analysis['file_extensions'] = dict(ext_counts)
        
        # Interesting findings
        interesting = {
            'admin_panels': [],
            'config_files': [],
            'backup_files': [],
            'sensitive_files': [],
            'forbidden_access': [],
            'redirects': []
        }
        
        admin_keywords = ['admin', 'administrator', 'panel', 'dashboard', 'login', 'manage']
        config_keywords = ['config', 'configuration', 'settings', '.env', 'web.config', '.htaccess']
        backup_keywords = ['backup', 'bak', 'old', 'copy', 'archive', 'dump']
        sensitive_keywords = ['password', 'passwd', 'secret', 'key', 'token', 'credential']
        
        for item in all_items:
            path_lower = item['path'].lower()
            
            # Admin panels
            if any(keyword in path_lower for keyword in admin_keywords):
                interesting['admin_panels'].append(item)
            
            # Config files
            if any(keyword in path_lower for keyword in config_keywords):
                interesting['config_files'].append(item)
            
            # Backup files
            if any(keyword in path_lower for keyword in backup_keywords):
                interesting['backup_files'].append(item)
            
            # Sensitive files
            if any(keyword in path_lower for keyword in sensitive_keywords):
                interesting['sensitive_files'].append(item)
            
            # Forbidden access (might indicate something interesting)
            if item['status_code'] == 403:
                interesting['forbidden_access'].append(item)
            
            # Redirects
            if item['status_code'] in [301, 302]:
                interesting['redirects'].append(item)
        
        analysis['interesting_findings'] = interesting
        
        # Generate recommendations
        recommendations = []
        
        if interesting['admin_panels']:
            recommendations.append(f"Found {len(interesting['admin_panels'])} potential admin panels - investigate for weak credentials")
        
        if interesting['config_files']:
            recommendations.append(f"Found {len(interesting['config_files'])} configuration files - check for sensitive information")
        
        if interesting['backup_files']:
            recommendations.append(f"Found {len(interesting['backup_files'])} backup files - may contain sensitive data")
        
        if interesting['sensitive_files']:
            recommendations.append(f"Found {len(interesting['sensitive_files'])} potentially sensitive files")
        
        if interesting['forbidden_access']:
            recommendations.append(f"Found {len(interesting['forbidden_access'])} forbidden directories - may indicate hidden content")
        
        if status_counts.get(200, 0) > 10:
            recommendations.append("Many accessible directories found - consider deeper enumeration")
        
        analysis['recommendations'] = recommendations
        
        self.logger.info(f"Directory scan analysis completed for {analysis['target']}")
        return analysis
    
    def generate_combined_report(self, scan_files):
        """Generate combined analysis report from multiple scan files"""
        combined_analysis = {
            'report_type': 'combined_analysis',
            'timestamp': get_timestamp(),
            'scans_analyzed': len(scan_files),
            'targets': [],
            'port_scans': [],
            'directory_scans': [],
            'overall_recommendations': []
        }
        
        for file_path in scan_files:
            scan_data = self.load_scan_data(file_path)
            if not scan_data:
                continue
            
            target = scan_data.get('target')
            if target not in combined_analysis['targets']:
                combined_analysis['targets'].append(target)
            
            if scan_data.get('scan_type') == 'port_scan':
                analysis = self.analyze_port_scan(scan_data)
                if analysis:
                    combined_analysis['port_scans'].append(analysis)
            
            elif scan_data.get('scan_type') == 'directory_enumeration':
                analysis = self.analyze_directory_scan(scan_data)
                if analysis:
                    combined_analysis['directory_scans'].append(analysis)
        
        # Generate overall recommendations
        overall_recommendations = []
        
        # Check for common patterns across scans
        if combined_analysis['port_scans'] and combined_analysis['directory_scans']:
            overall_recommendations.append("Both port and directory scans completed - correlate findings for comprehensive assessment")
        
        if len(combined_analysis['targets']) > 1:
            overall_recommendations.append(f"Multiple targets analyzed ({len(combined_analysis['targets'])}) - look for common vulnerabilities")
        
        combined_analysis['overall_recommendations'] = overall_recommendations
        
        self.logger.info(f"Combined analysis completed for {len(scan_files)} scan files")
        return combined_analysis
    
    def save_analysis(self, analysis_data, format_type='json'):
        """Save analysis results to file"""
        if analysis_data.get('report_type') == 'combined_analysis':
            filename = "combined_analysis"
        else:
            target = analysis_data.get('target', 'unknown').replace('.', '_').replace('://', '_')
            scan_type = analysis_data.get('scan_type', 'analysis')
            filename = f"{scan_type}_{target}"
        
        filepath = save_results(analysis_data, filename, format_type)
        self.logger.info(f"Analysis saved to: {filepath}")
        return filepath

def run_analysis(input_files, output_format='json'):
    """Main function to run data analysis"""
    analyzer = DataAnalyzer()
    
    if isinstance(input_files, str):
        input_files = [input_files]
    
    try:
        if len(input_files) == 1:
            # Single file analysis
            scan_data = analyzer.load_scan_data(input_files[0])
            if not scan_data:
                return None
            
            if scan_data.get('scan_type') == 'port_scan':
                analysis = analyzer.analyze_port_scan(scan_data)
            elif scan_data.get('scan_type') == 'directory_enumeration':
                analysis = analyzer.analyze_directory_scan(scan_data)
            else:
                analyzer.logger.error(f"Unknown scan type: {scan_data.get('scan_type')}")
                return None
        
        else:
            # Combined analysis
            analysis = analyzer.generate_combined_report(input_files)
        
        # Save analysis
        if output_format:
            analyzer.save_analysis(analysis, output_format)
        
        return analysis
        
    except Exception as e:
        log_error("Error during analysis", analyzer.logger, e)
        return None

if __name__ == "__main__":
    # Example usage
    analyzer = DataAnalyzer()
    
    # Example: analyze a port scan file
    # analysis = run_analysis("output/port_scan_example_com_20231201_120000.json")
    
    print("Data Analyzer ready. Use run_analysis() function to analyze scan results.")
