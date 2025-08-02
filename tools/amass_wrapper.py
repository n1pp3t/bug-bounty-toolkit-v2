import subprocess
import json
import os
import tempfile
import time
from utils.logger import setup_logger, log_scan_result, log_error
from utils.helpers import validate_domain, save_results, get_timestamp

class AmassWrapper:
    def __init__(self, domain, output_dir=None):
        self.domain = domain.lower().strip()
        self.output_dir = output_dir or "output"
        self.logger = setup_logger("amass_wrapper")
        self.amass_path = self.find_amass_binary()
        
    def find_amass_binary(self):
        """Find amass binary in system PATH"""
        try:
            result = subprocess.run(['which', 'amass'], capture_output=True, text=True)
            if result.returncode == 0:
                amass_path = result.stdout.strip()
                self.logger.info(f"Found amass at: {amass_path}")
                return amass_path
            else:
                # Try common installation paths
                common_paths = [
                    '/usr/local/bin/amass',
                    '/usr/bin/amass',
                    '/opt/amass/amass',
                    '~/go/bin/amass',
                    './amass'
                ]
                
                for path in common_paths:
                    expanded_path = os.path.expanduser(path)
                    if os.path.exists(expanded_path) and os.access(expanded_path, os.X_OK):
                        self.logger.info(f"Found amass at: {expanded_path}")
                        return expanded_path
                
                self.logger.error("Amass not found in system PATH or common locations")
                return None
                
        except Exception as e:
            log_error("Error finding amass binary", self.logger, e)
            return None
    
    def check_amass_installed(self):
        """Check if amass is installed and get version"""
        if not self.amass_path:
            self.logger.error("Amass is not installed or not found in PATH")
            self.logger.info("Install amass from: https://github.com/OWASP/Amass")
            return False
        
        try:
            result = subprocess.run([self.amass_path, 'version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_info = result.stdout.strip()
                self.logger.info(f"Amass version: {version_info}")
                return True
            else:
                self.logger.error("Amass found but not working properly")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Amass version check timed out")
            return False
        except Exception as e:
            log_error("Error checking amass installation", self.logger, e)
            return False
    
    def run_amass_enum(self, passive=False, active=True, brute=False, wordlist=None, 
                       resolvers=None, timeout=None, max_dns_queries=None):
        """Run amass enum command"""
        if not self.check_amass_installed():
            return None
        
        self.logger.info(f"Starting amass enumeration for {self.domain}")
        
        # Create temporary output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            json_output_file = temp_file.name
        
        try:
            # Build amass command
            cmd = [self.amass_path, 'enum']
            
            # Add domain
            cmd.extend(['-d', self.domain])
            
            # Output format
            cmd.extend(['-json', json_output_file])
            
            # Passive mode
            if passive:
                cmd.append('-passive')
                self.logger.info("Running in passive mode")
            
            # Active enumeration
            if active and not passive:
                cmd.append('-active')
                self.logger.info("Running in active mode")
            
            # Brute force
            if brute:
                cmd.append('-brute')
                self.logger.info("Brute force enabled")
                
                if wordlist and os.path.exists(wordlist):
                    cmd.extend(['-w', wordlist])
                    self.logger.info(f"Using wordlist: {wordlist}")
            
            # Custom resolvers
            if resolvers:
                if isinstance(resolvers, list):
                    resolvers_file = self.create_resolvers_file(resolvers)
                    cmd.extend(['-rf', resolvers_file])
                elif os.path.exists(resolvers):
                    cmd.extend(['-rf', resolvers])
            
            # Timeout
            if timeout:
                cmd.extend(['-timeout', str(timeout)])
            
            # Max DNS queries per second
            if max_dns_queries:
                cmd.extend(['-max-dns-queries', str(max_dns_queries)])
            
            # Add some useful flags
            cmd.extend(['-v'])  # Verbose output
            
            self.logger.info(f"Running command: {' '.join(cmd)}")
            
            # Execute amass
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 min timeout
            end_time = time.time()
            
            if result.returncode != 0:
                self.logger.error(f"Amass command failed: {result.stderr}")
                return None
            
            # Parse results
            scan_results = self.parse_amass_output(json_output_file)
            
            if scan_results:
                scan_results['scan_duration'] = end_time - start_time
                scan_results['command_used'] = ' '.join(cmd)
                self.logger.info(f"Amass enumeration completed in {scan_results['scan_duration']:.2f} seconds")
                self.logger.info(f"Found {len(scan_results.get('subdomains', []))} subdomains")
            
            return scan_results
            
        except subprocess.TimeoutExpired:
            self.logger.error("Amass enumeration timed out")
            return None
        except Exception as e:
            log_error("Error running amass enumeration", self.logger, e)
            return None
        finally:
            # Clean up temporary files
            try:
                os.unlink(json_output_file)
            except:
                pass
    
    def run_amass_intel(self, org=None, asn=None, cidr=None, whois=False):
        """Run amass intel command for intelligence gathering"""
        if not self.check_amass_installed():
            return None
        
        self.logger.info(f"Starting amass intelligence gathering")
        
        try:
            # Build amass intel command
            cmd = [self.amass_path, 'intel']
            
            if org:
                cmd.extend(['-org', org])
                self.logger.info(f"Searching for organization: {org}")
            
            if asn:
                cmd.extend(['-asn', str(asn)])
                self.logger.info(f"Searching ASN: {asn}")
            
            if cidr:
                cmd.extend(['-cidr', cidr])
                self.logger.info(f"Searching CIDR: {cidr}")
            
            if whois:
                cmd.append('-whois')
                self.logger.info("WHOIS lookup enabled")
            
            # Add domain if no other options specified
            if not any([org, asn, cidr]):
                cmd.extend(['-d', self.domain])
            
            cmd.extend(['-v'])  # Verbose output
            
            self.logger.info(f"Running command: {' '.join(cmd)}")
            
            # Execute amass intel
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # 10 min timeout
            
            if result.returncode != 0:
                self.logger.error(f"Amass intel command failed: {result.stderr}")
                return None
            
            # Parse intel results
            intel_results = self.parse_amass_intel_output(result.stdout)
            intel_results['command_used'] = ' '.join(cmd)
            
            self.logger.info(f"Amass intelligence gathering completed")
            return intel_results
            
        except subprocess.TimeoutExpired:
            self.logger.error("Amass intel timed out")
            return None
        except Exception as e:
            log_error("Error running amass intel", self.logger, e)
            return None
    
    def run_amass_db(self, show=False, list_sources=False, import_file=None):
        """Run amass db command for database operations"""
        if not self.check_amass_installed():
            return None
        
        try:
            cmd = [self.amass_path, 'db']
            
            if show:
                cmd.extend(['-show'])
                cmd.extend(['-d', self.domain])
                self.logger.info(f"Showing database entries for {self.domain}")
            
            if list_sources:
                cmd.extend(['-list'])
                self.logger.info("Listing available data sources")
            
            if import_file and os.path.exists(import_file):
                cmd.extend(['-import', import_file])
                self.logger.info(f"Importing data from {import_file}")
            
            # Execute amass db
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                self.logger.error(f"Amass db command failed: {result.stderr}")
                return None
            
            db_results = {
                'domain': self.domain,
                'scan_type': 'amass_db',
                'timestamp': get_timestamp(),
                'command_used': ' '.join(cmd),
                'output': result.stdout,
                'data': self.parse_amass_db_output(result.stdout)
            }
            
            return db_results
            
        except subprocess.TimeoutExpired:
            self.logger.error("Amass db command timed out")
            return None
        except Exception as e:
            log_error("Error running amass db", self.logger, e)
            return None
    
    def parse_amass_output(self, json_file):
        """Parse amass JSON output"""
        try:
            subdomains = []
            
            with open(json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            subdomain_info = {
                                'subdomain': data.get('name', ''),
                                'domain': data.get('domain', ''),
                                'addresses': data.get('addresses', []),
                                'tag': data.get('tag', ''),
                                'source': data.get('source', ''),
                                'timestamp': get_timestamp()
                            }
                            subdomains.append(subdomain_info)
                        except json.JSONDecodeError:
                            continue
            
            results = {
                'domain': self.domain,
                'scan_type': 'amass_enum',
                'timestamp': get_timestamp(),
                'subdomains': subdomains,
                'total_subdomains': len(subdomains),
                'unique_subdomains': list(set([s['subdomain'] for s in subdomains])),
                'sources_used': list(set([s['source'] for s in subdomains if s['source']]))
            }
            
            return results
            
        except Exception as e:
            log_error("Error parsing amass output", self.logger, e)
            return None
    
    def parse_amass_intel_output(self, output):
        """Parse amass intel output"""
        try:
            lines = output.strip().split('\n')
            domains = []
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('['):  # Skip log messages
                    domains.append(line)
            
            results = {
                'scan_type': 'amass_intel',
                'timestamp': get_timestamp(),
                'domains_found': domains,
                'total_domains': len(domains)
            }
            
            return results
            
        except Exception as e:
            log_error("Error parsing amass intel output", self.logger, e)
            return {'domains_found': [], 'total_domains': 0}
    
    def parse_amass_db_output(self, output):
        """Parse amass db output"""
        try:
            lines = output.strip().split('\n')
            data = []
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('['):  # Skip log messages
                    data.append(line)
            
            return data
            
        except Exception as e:
            log_error("Error parsing amass db output", self.logger, e)
            return []
    
    def create_resolvers_file(self, resolvers):
        """Create temporary resolvers file"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for resolver in resolvers:
                    f.write(f"{resolver}\n")
                return f.name
        except Exception as e:
            log_error("Error creating resolvers file", self.logger, e)
            return None
    
    def comprehensive_scan(self, config=None):
        """Run comprehensive amass scan with multiple techniques"""
        self.logger.info(f"Starting comprehensive amass scan for {self.domain}")
        
        results = {
            'domain': self.domain,
            'scan_type': 'amass_comprehensive',
            'timestamp': get_timestamp(),
            'scans': {}
        }
        
        # Default configuration
        default_config = {
            'passive_scan': True,
            'active_scan': True,
            'brute_force': True,
            'intel_gathering': True,
            'timeout': 1800,  # 30 minutes
            'max_dns_queries': 20000
        }
        
        if config:
            default_config.update(config)
        
        # Run passive enumeration
        if default_config['passive_scan']:
            self.logger.info("Running passive enumeration...")
            passive_results = self.run_amass_enum(
                passive=True,
                timeout=default_config['timeout'] // 3,
                max_dns_queries=default_config['max_dns_queries']
            )
            if passive_results:
                results['scans']['passive'] = passive_results
        
        # Run active enumeration
        if default_config['active_scan']:
            self.logger.info("Running active enumeration...")
            active_results = self.run_amass_enum(
                active=True,
                timeout=default_config['timeout'] // 3,
                max_dns_queries=default_config['max_dns_queries']
            )
            if active_results:
                results['scans']['active'] = active_results
        
        # Run brute force
        if default_config['brute_force']:
            self.logger.info("Running brute force enumeration...")
            brute_results = self.run_amass_enum(
                active=True,
                brute=True,
                timeout=default_config['timeout'] // 3,
                max_dns_queries=default_config['max_dns_queries']
            )
            if brute_results:
                results['scans']['brute_force'] = brute_results
        
        # Run intelligence gathering
        if default_config['intel_gathering']:
            self.logger.info("Running intelligence gathering...")
            intel_results = self.run_amass_intel()
            if intel_results:
                results['scans']['intelligence'] = intel_results
        
        # Combine and deduplicate results
        all_subdomains = set()
        all_sources = set()
        
        for scan_name, scan_data in results['scans'].items():
            if 'subdomains' in scan_data:
                for subdomain_info in scan_data['subdomains']:
                    all_subdomains.add(subdomain_info['subdomain'])
                    if subdomain_info.get('source'):
                        all_sources.add(subdomain_info['source'])
        
        results['summary'] = {
            'total_unique_subdomains': len(all_subdomains),
            'unique_subdomains': list(all_subdomains),
            'sources_used': list(all_sources),
            'scans_completed': len(results['scans'])
        }
        
        self.logger.info(f"Comprehensive amass scan completed: {len(all_subdomains)} unique subdomains found")
        return results
    
    def save_results(self, results, format_type='json'):
        """Save amass results to file"""
        if not results:
            return None
        
        domain_clean = self.domain.replace('.', '_')
        scan_type = results.get('scan_type', 'amass_scan')
        filename = f"{scan_type}_{domain_clean}"
        
        filepath = save_results(results, filename, format_type)
        self.logger.info(f"Amass results saved to: {filepath}")
        return filepath

def run_amass_scan(domain, scan_type='comprehensive', config=None, save_format='json'):
    """Main function to run amass scans"""
    
    # Validate domain
    if not validate_domain(domain):
        print(f"Error: Invalid domain '{domain}'. Please provide a valid domain name.")
        return None
    
    # Initialize amass wrapper
    amass = AmassWrapper(domain)
    
    try:
        if scan_type == 'passive':
            results = amass.run_amass_enum(passive=True)
        elif scan_type == 'active':
            results = amass.run_amass_enum(active=True)
        elif scan_type == 'brute':
            results = amass.run_amass_enum(active=True, brute=True)
        elif scan_type == 'intel':
            results = amass.run_amass_intel()
        elif scan_type == 'comprehensive':
            results = amass.comprehensive_scan(config)
        else:
            amass.logger.error(f"Unknown scan type: {scan_type}")
            return None
        
        # Save results
        if results and save_format:
            amass.save_results(results, save_format)
        
        return results
        
    except KeyboardInterrupt:
        amass.logger.info("Amass scan interrupted by user")
        return None
    except Exception as e:
        log_error("Unexpected error during amass scan", amass.logger, e)
        return None

if __name__ == "__main__":
    # Example usage
    domain = "example.com"
    results = run_amass_scan(domain, scan_type='passive')
    
    if results:
        print(f"\nAmass Scan Results for {domain}:")
        if 'subdomains' in results:
            print(f"Total subdomains found: {results['total_subdomains']}")
            for subdomain_info in results['subdomains'][:10]:
                print(f"  {subdomain_info['subdomain']} (source: {subdomain_info['source']})")
        elif 'summary' in results:
            print(f"Total unique subdomains: {results['summary']['total_unique_subdomains']}")
            for subdomain in results['summary']['unique_subdomains'][:10]:
                print(f"  {subdomain}")
