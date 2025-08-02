import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import setup_logger, log_scan_result, log_error
from utils.helpers import validate_ip, validate_domain, parse_port_range, get_common_ports, save_results, get_timestamp

class PortScanner:
    def __init__(self, target, threads=100, timeout=3):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.logger = setup_logger("port_scanner")
        self.open_ports = []
        self.closed_ports = []
        
    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = self.get_service_name(port)
                port_info = {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'timestamp': get_timestamp()
                }
                self.open_ports.append(port_info)
                self.logger.info(f"Port {port} is OPEN ({service})")
                return port_info
            else:
                self.closed_ports.append(port)
                return None
                
        except socket.gaierror:
            self.logger.error(f"Hostname {self.target} could not be resolved")
            return None
        except Exception as e:
            log_error(f"Error scanning port {port}", self.logger, e)
            return None
    
    def get_service_name(self, port):
        """Get service name for a port"""
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            8888: 'HTTP-Alt',
            9090: 'HTTP-Alt',
            10000: 'Webmin'
        }
        
        return common_services.get(port, 'Unknown')
    
    def scan_ports(self, ports):
        """Scan multiple ports using threading"""
        self.logger.info(f"Starting port scan on {self.target}")
        self.logger.info(f"Scanning {len(ports)} ports with {self.threads} threads")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                except Exception as e:
                    log_error(f"Port {port} generated an exception", self.logger, e)
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Log results
        log_scan_result(self.target, "Port Scan", self.open_ports, self.logger)
        self.logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        self.logger.info(f"Open ports found: {len(self.open_ports)}")
        
        return self.get_results()
    
    def scan_common_ports(self):
        """Scan commonly used ports"""
        common_ports = get_common_ports()
        return self.scan_ports(common_ports)
    
    def scan_port_range(self, port_range):
        """Scan a range of ports"""
        try:
            ports = parse_port_range(port_range)
            return self.scan_ports(ports)
        except Exception as e:
            log_error(f"Error parsing port range: {port_range}", self.logger, e)
            return None
    
    def get_results(self):
        """Get scan results in structured format"""
        results = {
            'target': self.target,
            'scan_type': 'port_scan',
            'timestamp': get_timestamp(),
            'open_ports': self.open_ports,
            'total_open': len(self.open_ports),
            'total_scanned': len(self.open_ports) + len(self.closed_ports),
            'scan_settings': {
                'threads': self.threads,
                'timeout': self.timeout
            }
        }
        return results
    
    def save_results(self, format_type='json'):
        """Save scan results to file"""
        results = self.get_results()
        filename = f"port_scan_{self.target.replace('.', '_')}"
        filepath = save_results(results, filename, format_type)
        self.logger.info(f"Results saved to: {filepath}")
        return filepath

def run_port_scan(target, port_range=None, common_ports=False, threads=100, timeout=3, save_format='json'):
    """Main function to run port scan"""
    
    # Validate target
    if not (validate_ip(target) or validate_domain(target)):
        print(f"Error: Invalid target '{target}'. Please provide a valid IP address or domain name.")
        return None
    
    # Initialize scanner
    scanner = PortScanner(target, threads, timeout)
    
    try:
        # Determine what to scan
        if common_ports:
            results = scanner.scan_common_ports()
        elif port_range:
            results = scanner.scan_port_range(port_range)
        else:
            # Default to common ports if nothing specified
            results = scanner.scan_common_ports()
        
        # Save results
        if save_format:
            scanner.save_results(save_format)
        
        return results
        
    except KeyboardInterrupt:
        scanner.logger.info("Scan interrupted by user")
        return scanner.get_results()
    except Exception as e:
        log_error("Unexpected error during port scan", scanner.logger, e)
        return None

if __name__ == "__main__":
    # Example usage
    target = "scanme.nmap.org"
    results = run_port_scan(target, common_ports=True, threads=50)
    
    if results:
        print(f"\nScan Results for {target}:")
        print(f"Open ports: {results['total_open']}")
        for port_info in results['open_ports']:
            print(f"  Port {port_info['port']}: {port_info['service']}")
