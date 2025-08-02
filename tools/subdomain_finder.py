import requests
import dns.resolver
import dns.exception
import threading
import time
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from utils.logger import setup_logger, log_scan_result, log_error
from utils.helpers import validate_domain, save_results, get_timestamp

class SubdomainFinder:
    def __init__(self, domain, threads=50, timeout=5):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.timeout = timeout
        self.logger = setup_logger("subdomain_finder")
        self.found_subdomains = set()
        self.session = requests.Session()
        
        # Set headers for web requests
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # DNS resolver configuration
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def dns_bruteforce(self, wordlist=None):
        """Brute force subdomains using DNS queries"""
        self.logger.info(f"Starting DNS brute force for {self.domain}")
        
        if wordlist is None:
            wordlist = self.get_default_subdomain_wordlist()
        
        found_count = 0
        
        def check_subdomain(subdomain):
            nonlocal found_count
            full_domain = f"{subdomain}.{self.domain}"
            
            try:
                # Try A record
                answers = self.resolver.resolve(full_domain, 'A')
                ips = [str(answer) for answer in answers]
                
                subdomain_info = {
                    'subdomain': full_domain,
                    'method': 'dns_bruteforce',
                    'record_type': 'A',
                    'ips': ips,
                    'timestamp': get_timestamp()
                }
                
                self.found_subdomains.add(full_domain)
                found_count += 1
                self.logger.info(f"Found subdomain: {full_domain} -> {', '.join(ips)}")
                return subdomain_info
                
            except dns.exception.DNSException:
                # Try CNAME record
                try:
                    answers = self.resolver.resolve(full_domain, 'CNAME')
                    cnames = [str(answer) for answer in answers]
                    
                    subdomain_info = {
                        'subdomain': full_domain,
                        'method': 'dns_bruteforce',
                        'record_type': 'CNAME',
                        'cnames': cnames,
                        'timestamp': get_timestamp()
                    }
                    
                    self.found_subdomains.add(full_domain)
                    found_count += 1
                    self.logger.info(f"Found subdomain: {full_domain} -> CNAME: {', '.join(cnames)}")
                    return subdomain_info
                    
                except dns.exception.DNSException:
                    return None
            except Exception as e:
                return None
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            
            completed = 0
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                completed += 1
                
                if completed % 100 == 0:
                    self.logger.info(f"DNS brute force progress: {completed}/{len(wordlist)} ({found_count} found)")
                
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    pass
        
        self.logger.info(f"DNS brute force completed: {found_count} subdomains found")
        return results
    
    def certificate_transparency(self):
        """Find subdomains using Certificate Transparency logs"""
        self.logger.info(f"Searching Certificate Transparency logs for {self.domain}")
        
        results = []
        ct_sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        ]
        
        for source_url in ct_sources:
            try:
                self.logger.info(f"Querying: {source_url}")
                response = self.session.get(source_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    if 'crt.sh' in source_url:
                        results.extend(self.parse_crtsh_response(response.json()))
                    elif 'certspotter' in source_url:
                        results.extend(self.parse_certspotter_response(response.json()))
                else:
                    self.logger.warning(f"CT source returned status {response.status_code}: {source_url}")
                    
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"Error querying CT source {source_url}: {str(e)}")
            except json.JSONDecodeError as e:
                self.logger.warning(f"Invalid JSON response from {source_url}")
            except Exception as e:
                log_error(f"Error processing CT source {source_url}", self.logger, e)
        
        # Remove duplicates and validate
        unique_subdomains = set()
        validated_results = []
        
        for result in results:
            subdomain = result['subdomain']
            if subdomain not in unique_subdomains and self.is_valid_subdomain(subdomain):
                unique_subdomains.add(subdomain)
                self.found_subdomains.add(subdomain)
                validated_results.append(result)
        
        self.logger.info(f"Certificate Transparency search completed: {len(validated_results)} subdomains found")
        return validated_results
    
    def parse_crtsh_response(self, data):
        """Parse crt.sh JSON response"""
        results = []
        
        for entry in data:
            name_value = entry.get('name_value', '')
            
            # Split multiple domains in name_value
            domains = name_value.split('\n')
            
            for domain in domains:
                domain = domain.strip().lower()
                
                # Remove wildcards
                if domain.startswith('*.'):
                    domain = domain[2:]
                
                if domain.endswith(f'.{self.domain}') or domain == self.domain:
                    result = {
                        'subdomain': domain,
                        'method': 'certificate_transparency',
                        'source': 'crt.sh',
                        'issuer': entry.get('issuer_name', ''),
                        'timestamp': get_timestamp()
                    }
                    results.append(result)
        
        return results
    
    def parse_certspotter_response(self, data):
        """Parse CertSpotter JSON response"""
        results = []
        
        for entry in data:
            dns_names = entry.get('dns_names', [])
            
            for domain in dns_names:
                domain = domain.strip().lower()
                
                # Remove wildcards
                if domain.startswith('*.'):
                    domain = domain[2:]
                
                if domain.endswith(f'.{self.domain}') or domain == self.domain:
                    result = {
                        'subdomain': domain,
                        'method': 'certificate_transparency',
                        'source': 'certspotter',
                        'issuer': entry.get('issuer', {}).get('name', ''),
                        'timestamp': get_timestamp()
                    }
                    results.append(result)
        
        return results
    
    def search_engines(self):
        """Find subdomains using search engines"""
        self.logger.info(f"Searching for subdomains using search engines for {self.domain}")
        
        results = []
        search_queries = [
            f"site:{self.domain}",
            f"site:*.{self.domain}",
        ]
        
        # Note: This is a basic implementation
        # In practice, you might want to use APIs like Google Custom Search, Bing API, etc.
        # For now, we'll use a simple approach with some common patterns
        
        try:
            # Search for common subdomain patterns in public sources
            common_patterns = [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
                'blog', 'shop', 'forum', 'support', 'help', 'docs', 'cdn',
                'static', 'assets', 'img', 'images', 'media', 'files'
            ]
            
            for pattern in common_patterns:
                subdomain = f"{pattern}.{self.domain}"
                
                # Quick HTTP check to see if subdomain responds
                try:
                    response = self.session.head(f"http://{subdomain}", timeout=3)
                    if response.status_code < 400:
                        result = {
                            'subdomain': subdomain,
                            'method': 'search_engines',
                            'source': 'http_check',
                            'status_code': response.status_code,
                            'timestamp': get_timestamp()
                        }
                        results.append(result)
                        self.found_subdomains.add(subdomain)
                        self.logger.info(f"Found active subdomain: {subdomain}")
                except:
                    pass
        
        except Exception as e:
            log_error("Error in search engine enumeration", self.logger, e)
        
        self.logger.info(f"Search engine enumeration completed: {len(results)} subdomains found")
        return results
    
    def dns_zone_transfer(self):
        """Attempt DNS zone transfer"""
        self.logger.info(f"Attempting DNS zone transfer for {self.domain}")
        
        results = []
        
        try:
            # Get NS records
            ns_answers = self.resolver.resolve(self.domain, 'NS')
            nameservers = [str(ns) for ns in ns_answers]
            
            self.logger.info(f"Found nameservers: {', '.join(nameservers)}")
            
            for ns in nameservers:
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain))
                    
                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{self.domain}" if name != '@' else self.domain
                        
                        result = {
                            'subdomain': subdomain,
                            'method': 'dns_zone_transfer',
                            'nameserver': ns,
                            'timestamp': get_timestamp()
                        }
                        results.append(result)
                        self.found_subdomains.add(subdomain)
                        
                    self.logger.info(f"Zone transfer successful from {ns}: {len(results)} records")
                    break  # If one succeeds, we don't need to try others
                    
                except Exception as e:
                    self.logger.debug(f"Zone transfer failed for {ns}: {str(e)}")
                    continue
        
        except dns.exception.DNSException as e:
            self.logger.debug(f"Could not get NS records for {self.domain}: {str(e)}")
        except Exception as e:
            log_error("Error in DNS zone transfer", self.logger, e)
        
        if not results:
            self.logger.info("DNS zone transfer not allowed or failed")
        
        return results
    
    def reverse_dns(self, ip_ranges=None):
        """Perform reverse DNS lookups on IP ranges"""
        self.logger.info(f"Performing reverse DNS lookups for {self.domain}")
        
        results = []
        
        if ip_ranges is None:
            # Try to get IP ranges from the main domain
            try:
                answers = self.resolver.resolve(self.domain, 'A')
                ips = [str(answer) for answer in answers]
                
                # Generate IP ranges based on found IPs
                ip_ranges = []
                for ip in ips:
                    # Get /24 subnet
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                        ip_ranges.append(subnet)
                
            except dns.exception.DNSException:
                self.logger.warning(f"Could not resolve {self.domain} for reverse DNS")
                return results
        
        # Perform reverse DNS on IP ranges
        for subnet in ip_ranges[:3]:  # Limit to first 3 subnets
            self.logger.info(f"Checking subnet: {subnet}.0/24")
            
            def check_reverse_dns(ip_suffix):
                ip = f"{subnet}.{ip_suffix}"
                try:
                    hostname = str(self.resolver.resolve_address(ip))
                    if self.domain in hostname:
                        result = {
                            'subdomain': hostname,
                            'method': 'reverse_dns',
                            'ip': ip,
                            'timestamp': get_timestamp()
                        }
                        self.found_subdomains.add(hostname)
                        return result
                except:
                    pass
                return None
            
            # Check a sample of IPs in the subnet (not all 254)
            sample_ips = list(range(1, 255, 10))  # Every 10th IP
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(check_reverse_dns, ip) for ip in sample_ips]
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                            self.logger.info(f"Found via reverse DNS: {result['subdomain']}")
                    except:
                        pass
        
        self.logger.info(f"Reverse DNS completed: {len(results)} subdomains found")
        return results
    
    def comprehensive_scan(self, wordlist=None):
        """Run all subdomain enumeration methods"""
        self.logger.info(f"Starting comprehensive subdomain enumeration for {self.domain}")
        
        all_results = {
            'domain': self.domain,
            'scan_type': 'subdomain_enumeration',
            'timestamp': get_timestamp(),
            'methods': {},
            'summary': {}
        }
        
        # Run all enumeration methods
        methods = [
            ('dns_bruteforce', lambda: self.dns_bruteforce(wordlist)),
            ('certificate_transparency', self.certificate_transparency),
            ('search_engines', self.search_engines),
            ('dns_zone_transfer', self.dns_zone_transfer),
            ('reverse_dns', self.reverse_dns)
        ]
        
        for method_name, method_func in methods:
            self.logger.info(f"Running {method_name}...")
            try:
                results = method_func()
                all_results['methods'][method_name] = results
                self.logger.info(f"{method_name} completed: {len(results)} results")
            except Exception as e:
                log_error(f"Error in {method_name}", self.logger, e)
                all_results['methods'][method_name] = []
        
        # Generate summary
        all_results['summary'] = {
            'total_subdomains': len(self.found_subdomains),
            'unique_subdomains': list(self.found_subdomains),
            'methods_used': len([m for m in all_results['methods'] if all_results['methods'][m]]),
            'scan_duration': get_timestamp()
        }
        
        self.logger.info(f"Comprehensive scan completed: {len(self.found_subdomains)} unique subdomains found")
        return all_results
    
    def is_valid_subdomain(self, subdomain):
        """Validate if subdomain is valid and belongs to target domain"""
        if not subdomain or subdomain == self.domain:
            return False
        
        # Check if it's a valid subdomain of our target
        if not (subdomain.endswith(f'.{self.domain}') or subdomain == self.domain):
            return False
        
        # Basic format validation
        if '..' in subdomain or subdomain.startswith('.') or subdomain.endswith('.'):
            return False
        
        return True
    
    def get_default_subdomain_wordlist(self):
        """Get default subdomain wordlist"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap',
            'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news',
            'vpn', 'ns4', 'email', 'webmaster', 'hosting', 'secure', 'www1', 'api',
            'www3', 'mail2', 'help', 'im', 'web', 'support', 'ftp2', 'host', 'wap',
            'dns1', 'dns2', 'ns5', 'upload', 'www4', 'www5', 'origin', 'video',
            'www6', 'ftp1', 'www7', 'www8', 'www9', 'www10', 'mail3', 'mx', 'mx1',
            'mx2', 'mx3', 'promo', 'shop', 'mail4', 'mail5', 'music', 'download',
            'app', 'service', 'beta', 'stage', 'staging', 'demo', 'preview', 'mobile',
            'cdn', 'assets', 'static', 'media', 'images', 'img', 'css', 'js',
            'files', 'docs', 'doc', 'documentation', 'wiki', 'kb', 'knowledgebase',
            'portal', 'dashboard', 'panel', 'control', 'manage', 'management',
            'crm', 'erp', 'intranet', 'extranet', 'vpn', 'remote', 'ssh', 'sftp',
            'git', 'svn', 'repo', 'repository', 'code', 'build', 'ci', 'jenkins',
            'status', 'monitor', 'monitoring', 'stats', 'statistics', 'metrics',
            'log', 'logs', 'syslog', 'kibana', 'grafana', 'prometheus',
            'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elasticsearch',
            'search', 'solr', 'lucene', 'sphinx', 'memcache', 'cache',
            'queue', 'worker', 'job', 'cron', 'scheduler', 'task',
            'backup', 'backups', 'archive', 'old', 'legacy', 'deprecated',
            'v1', 'v2', 'v3', 'v4', 'version1', 'version2', 'alpha', 'beta',
            'rc', 'release', 'stable', 'latest', 'current', 'new',
            'temp', 'tmp', 'temporary', 'test1', 'test2', 'test3', 'testing',
            'sandbox', 'lab', 'experiment', 'research', 'development',
            'prod', 'production', 'live', 'www-prod', 'prod-www',
            'internal', 'private', 'secret', 'hidden', 'secure', 'protected',
            'admin1', 'admin2', 'administrator', 'root', 'superuser',
            'user', 'users', 'account', 'accounts', 'profile', 'profiles',
            'member', 'members', 'client', 'clients', 'customer', 'customers'
        ]
    
    def save_results(self, results, format_type='json'):
        """Save subdomain enumeration results"""
        if not results:
            return None
        
        domain_clean = self.domain.replace('.', '_')
        filename = f"subdomain_enum_{domain_clean}"
        
        filepath = save_results(results, filename, format_type)
        self.logger.info(f"Subdomain enumeration results saved to: {filepath}")
        return filepath

def run_subdomain_enumeration(domain, methods=['all'], wordlist=None, threads=50, save_format='json'):
    """Main function to run subdomain enumeration"""
    
    # Validate domain
    if not validate_domain(domain):
        print(f"Error: Invalid domain '{domain}'. Please provide a valid domain name.")
        return None
    
    # Initialize finder
    finder = SubdomainFinder(domain, threads)
    
    try:
        if 'all' in methods or 'comprehensive' in methods:
            results = finder.comprehensive_scan(wordlist)
        else:
            # Run specific methods
            results = {
                'domain': domain,
                'scan_type': 'subdomain_enumeration',
                'timestamp': get_timestamp(),
                'methods': {},
                'summary': {}
            }
            
            if 'dns' in methods or 'bruteforce' in methods:
                results['methods']['dns_bruteforce'] = finder.dns_bruteforce(wordlist)
            
            if 'ct' in methods or 'certificate' in methods:
                results['methods']['certificate_transparency'] = finder.certificate_transparency()
            
            if 'search' in methods:
                results['methods']['search_engines'] = finder.search_engines()
            
            if 'zone' in methods:
                results['methods']['dns_zone_transfer'] = finder.dns_zone_transfer()
            
            if 'reverse' in methods:
                results['methods']['reverse_dns'] = finder.reverse_dns()
            
            # Generate summary
            results['summary'] = {
                'total_subdomains': len(finder.found_subdomains),
                'unique_subdomains': list(finder.found_subdomains),
                'methods_used': len([m for m in results['methods'] if results['methods'][m]])
            }
        
        # Save results
        if results and save_format:
            finder.save_results(results, save_format)
        
        return results
        
    except KeyboardInterrupt:
        finder.logger.info("Subdomain enumeration interrupted by user")
        return None
    except Exception as e:
        log_error("Unexpected error during subdomain enumeration", finder.logger, e)
        return None

if __name__ == "__main__":
    # Example usage
    domain = "example.com"
    results = run_subdomain_enumeration(domain, methods=['all'])
    
    if results:
        print(f"\nSubdomain Enumeration Results for {domain}:")
        print(f"Total subdomains found: {results['summary']['total_subdomains']}")
        
        for subdomain in results['summary']['unique_subdomains'][:10]:
            print(f"  {subdomain}")
        
        if len(results['summary']['unique_subdomains']) > 10:
            print(f"  ... and {len(results['summary']['unique_subdomains']) - 10} more")
