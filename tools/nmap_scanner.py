import subprocess
import json
import xml.etree.ElementTree as ET
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from utils.logger import setup_logger, log_scan_result, log_error
from utils.helpers import validate_ip, validate_domain, save_results, get_timestamp

class NmapScanner:
    def __init__(self, target, output_format='json'):
        self.target = target
        self.output_format = output_format
        self.logger = setup_logger("nmap_scanner")
        self.scan_results = {}
        
    def check_nmap_installed(self):
        """Check if nmap is installed on the system"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                self.logger.info(f"Nmap found: {version_line}")
                return True
            else:
                self.logger.error("Nmap not found or not working properly")
                return False
        except FileNotFoundError:
            self.logger.error("Nmap is not installed. Please install nmap first.")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Nmap version check timed out")
            return False
        except Exception as e:
            log_error("Error checking nmap installation", self.logger, e)
            return False
    
    def run_nmap_command(self, nmap_args, scan_type="custom"):
        """Execute nmap command and parse results"""
        if not self.check_nmap_installed():
            return None
        
        # Create temporary file for XML output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            xml_output_file = temp_file.name
        
        try:
            # Build nmap command
            cmd = ['nmap'] + nmap_args + ['-oX', xml_output_file, self.target]
            
            self.logger.info(f"Running nmap command: {' '.join(cmd)}")
            
            # Execute nmap
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                self.logger.error(f"Nmap command failed: {result.stderr}")
                return None
            
            # Parse XML output
            scan_results = self.parse_nmap_xml(xml_output_file, scan_type)
            
            return scan_results
            
        except subprocess.TimeoutExpired:
            self.logger.error("Nmap scan timed out")
            return None
        except Exception as e:
            log_error("Error running nmap command", self.logger, e)
            return None
        finally:
            # Clean up temporary file
            try:
                os.unlink(xml_output_file)
            except:
                pass
    
    def parse_nmap_xml(self, xml_file, scan_type):
        """Parse nmap XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            scan_results = {
                'target': self.target,
                'scan_type': f'nmap_{scan_type}',
                'timestamp': get_timestamp(),
                'nmap_version': root.get('version', 'unknown'),
                'scan_args': root.get('args', ''),
                'hosts': [],
                'summary': {}
            }
            
            # Parse each host
            for host in root.findall('host'):
                host_info = self.parse_host(host)
                if host_info:
                    scan_results['hosts'].append(host_info)
            
            # Generate summary
            scan_results['summary'] = self.generate_summary(scan_results['hosts'])
            
            self.logger.info(f"Parsed nmap results: {len(scan_results['hosts'])} hosts")
            return scan_results
            
        except ET.ParseError as e:
            log_error("Error parsing nmap XML output", self.logger, e)
            return None
        except Exception as e:
            log_error("Error processing nmap results", self.logger, e)
            return None
    
    def parse_host(self, host_element):
        """Parse individual host information"""
        host_info = {
            'addresses': [],
            'hostnames': [],
            'status': {},
            'ports': [],
            'os': {},
            'scripts': []
        }
        
        # Parse addresses
        for address in host_element.findall('address'):
            addr_info = {
                'addr': address.get('addr'),
                'addrtype': address.get('addrtype'),
                'vendor': address.get('vendor', '')
            }
            host_info['addresses'].append(addr_info)
        
        # Parse hostnames
        hostnames_elem = host_element.find('hostnames')
        if hostnames_elem is not None:
            for hostname in hostnames_elem.findall('hostname'):
                host_info['hostnames'].append({
                    'name': hostname.get('name'),
                    'type': hostname.get('type')
                })
        
        # Parse status
        status_elem = host_element.find('status')
        if status_elem is not None:
            host_info['status'] = {
                'state': status_elem.get('state'),
                'reason': status_elem.get('reason'),
                'reason_ttl': status_elem.get('reason_ttl')
            }
        
        # Parse ports
        ports_elem = host_element.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_info = self.parse_port(port)
                if port_info:
                    host_info['ports'].append(port_info)
        
        # Parse OS detection
        os_elem = host_element.find('os')
        if os_elem is not None:
            host_info['os'] = self.parse_os(os_elem)
        
        # Parse host scripts
        hostscript_elem = host_element.find('hostscript')
        if hostscript_elem is not None:
            for script in hostscript_elem.findall('script'):
                script_info = {
                    'id': script.get('id'),
                    'output': script.get('output', ''),
                    'elements': []
                }
                
                # Parse script elements
                for elem in script.findall('elem'):
                    script_info['elements'].append({
                        'key': elem.get('key'),
                        'value': elem.text
                    })
                
                host_info['scripts'].append(script_info)
        
        return host_info
    
    def parse_port(self, port_element):
        """Parse port information"""
        port_info = {
            'portid': int(port_element.get('portid')),
            'protocol': port_element.get('protocol'),
            'state': {},
            'service': {},
            'scripts': []
        }
        
        # Parse state
        state_elem = port_element.find('state')
        if state_elem is not None:
            port_info['state'] = {
                'state': state_elem.get('state'),
                'reason': state_elem.get('reason'),
                'reason_ttl': state_elem.get('reason_ttl')
            }
        
        # Parse service
        service_elem = port_element.find('service')
        if service_elem is not None:
            port_info['service'] = {
                'name': service_elem.get('name', ''),
                'product': service_elem.get('product', ''),
                'version': service_elem.get('version', ''),
                'extrainfo': service_elem.get('extrainfo', ''),
                'ostype': service_elem.get('ostype', ''),
                'method': service_elem.get('method', ''),
                'conf': service_elem.get('conf', '')
            }
        
        # Parse port scripts
        for script in port_element.findall('script'):
            script_info = {
                'id': script.get('id'),
                'output': script.get('output', ''),
                'elements': []
            }
            
            # Parse script elements
            for elem in script.findall('elem'):
                script_info['elements'].append({
                    'key': elem.get('key'),
                    'value': elem.text
                })
            
            port_info['scripts'].append(script_info)
        
        return port_info
    
    def parse_os(self, os_element):
        """Parse OS detection information"""
        os_info = {
            'portused': [],
            'osmatch': [],
            'osfingerprint': []
        }
        
        # Parse ports used for OS detection
        for portused in os_element.findall('portused'):
            os_info['portused'].append({
                'state': portused.get('state'),
                'proto': portused.get('proto'),
                'portid': portused.get('portid')
            })
        
        # Parse OS matches
        for osmatch in os_element.findall('osmatch'):
            match_info = {
                'name': osmatch.get('name'),
                'accuracy': osmatch.get('accuracy'),
                'line': osmatch.get('line'),
                'osclass': []
            }
            
            # Parse OS classes
            for osclass in osmatch.findall('osclass'):
                match_info['osclass'].append({
                    'type': osclass.get('type'),
                    'vendor': osclass.get('vendor'),
                    'osfamily': osclass.get('osfamily'),
                    'osgen': osclass.get('osgen'),
                    'accuracy': osclass.get('accuracy')
                })
            
            os_info['osmatch'].append(match_info)
        
        return os_info
    
    def generate_summary(self, hosts):
        """Generate summary statistics"""
        summary = {
            'total_hosts': len(hosts),
            'hosts_up': 0,
            'hosts_down': 0,
            'total_open_ports': 0,
            'unique_services': set(),
            'os_matches': []
        }
        
        for host in hosts:
            if host['status'].get('state') == 'up':
                summary['hosts_up'] += 1
            else:
                summary['hosts_down'] += 1
            
            # Count open ports and services
            for port in host['ports']:
                if port['state'].get('state') == 'open':
                    summary['total_open_ports'] += 1
                    service_name = port['service'].get('name', 'unknown')
                    summary['unique_services'].add(service_name)
            
            # Collect OS matches
            for osmatch in host['os'].get('osmatch', []):
                if osmatch['name'] not in summary['os_matches']:
                    summary['os_matches'].append(osmatch['name'])
        
        summary['unique_services'] = list(summary['unique_services'])
        return summary
    
    def quick_scan(self, ports=None):
        """Quick TCP SYN scan"""
        args = ['-sS', '-T4', '--open']
        if ports:
            args.extend(['-p', ports])
        
        return self.run_nmap_command(args, "quick_scan")
    
    def service_scan(self, ports=None):
        """Service version detection scan"""
        args = ['-sV', '-T4', '--open']
        if ports:
            args.extend(['-p', ports])
        
        return self.run_nmap_command(args, "service_scan")
    
    def os_scan(self, ports=None):
        """OS detection scan"""
        args = ['-O', '-T4', '--open']
        if ports:
            args.extend(['-p', ports])
        
        return self.run_nmap_command(args, "os_scan")
    
    def aggressive_scan(self, ports=None):
        """Aggressive scan with OS detection, version detection, script scanning"""
        args = ['-A', '-T4', '--open']
        if ports:
            args.extend(['-p', ports])
        
        return self.run_nmap_command(args, "aggressive_scan")
    
    def vulnerability_scan(self, ports=None):
        """Vulnerability scanning using NSE scripts"""
        args = ['-sV', '--script=vuln', '-T4', '--open']
        if ports:
            args.extend(['-p', ports])
        
        return self.run_nmap_command(args, "vulnerability_scan")
    
    def udp_scan(self, ports=None):
        """UDP port scan"""
        args = ['-sU', '-T4', '--open']
        if ports:
            args.extend(['-p', ports])
        else:
            args.extend(['-p', '53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353'])
        
        return self.run_nmap_command(args, "udp_scan")
    
    def stealth_scan(self, ports=None):
        """Stealth scan with timing and evasion"""
        args = ['-sS', '-T2', '-f', '--open', '--randomize-hosts']
        if ports:
            args.extend(['-p', ports])
        
        return self.run_nmap_command(args, "stealth_scan")
    
    def comprehensive_scan(self, ports=None):
        """Comprehensive scan combining multiple techniques"""
        self.logger.info("Starting comprehensive nmap scan...")
        
        results = {
            'target': self.target,
            'scan_type': 'nmap_comprehensive',
            'timestamp': get_timestamp(),
            'scans': {}
        }
        
        # Run multiple scan types
        scan_types = [
            ('quick_scan', self.quick_scan),
            ('service_scan', self.service_scan),
            ('os_scan', self.os_scan),
            ('vulnerability_scan', self.vulnerability_scan)
        ]
        
        for scan_name, scan_func in scan_types:
            self.logger.info(f"Running {scan_name}...")
            try:
                scan_result = scan_func(ports)
                if scan_result:
                    results['scans'][scan_name] = scan_result
                    self.logger.info(f"{scan_name} completed successfully")
                else:
                    self.logger.warning(f"{scan_name} failed or returned no results")
            except Exception as e:
                log_error(f"Error in {scan_name}", self.logger, e)
        
        return results
    
    def save_results(self, results, format_type='json'):
        """Save scan results to file"""
        if not results:
            return None
        
        target_clean = self.target.replace('.', '_').replace('/', '_')
        scan_type = results.get('scan_type', 'nmap_scan')
        filename = f"{scan_type}_{target_clean}"
        
        filepath = save_results(results, filename, format_type)
        self.logger.info(f"Nmap results saved to: {filepath}")
        return filepath

def run_nmap_scan(target, scan_type='quick', ports=None, save_format='json'):
    """Main function to run nmap scans"""
    
    # Validate target
    if not (validate_ip(target) or validate_domain(target)):
        print(f"Error: Invalid target '{target}'. Please provide a valid IP address or domain name.")
        return None
    
    # Initialize scanner
    scanner = NmapScanner(target)
    
    try:
        # Run specified scan type
        if scan_type == 'quick':
            results = scanner.quick_scan(ports)
        elif scan_type == 'service':
            results = scanner.service_scan(ports)
        elif scan_type == 'os':
            results = scanner.os_scan(ports)
        elif scan_type == 'aggressive':
            results = scanner.aggressive_scan(ports)
        elif scan_type == 'vulnerability':
            results = scanner.vulnerability_scan(ports)
        elif scan_type == 'udp':
            results = scanner.udp_scan(ports)
        elif scan_type == 'stealth':
            results = scanner.stealth_scan(ports)
        elif scan_type == 'comprehensive':
            results = scanner.comprehensive_scan(ports)
        else:
            scanner.logger.error(f"Unknown scan type: {scan_type}")
            return None
        
        # Save results
        if results and save_format:
            scanner.save_results(results, save_format)
        
        return results
        
    except KeyboardInterrupt:
        scanner.logger.info("Nmap scan interrupted by user")
        return None
    except Exception as e:
        log_error("Unexpected error during nmap scan", scanner.logger, e)
        return None

if __name__ == "__main__":
    # Example usage
    target = "scanme.nmap.org"
    results = run_nmap_scan(target, scan_type='service', ports='1-1000')
    
    if results:
        print(f"\nNmap Scan Results for {target}:")
        for host in results.get('hosts', []):
            print(f"Host: {host['addresses'][0]['addr']} - {host['status']['state']}")
            for port in host['ports']:
                if port['state']['state'] == 'open':
                    service = port['service'].get('name', 'unknown')
                    version = port['service'].get('version', '')
                    print(f"  Port {port['portid']}/{port['protocol']}: {service} {version}")
