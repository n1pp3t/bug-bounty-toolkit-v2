import requests
import json
import re
import time
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import setup_logger, log_scan_result, log_error
from utils.helpers import validate_domain, save_results, get_timestamp

class OSINTCollector:
    def __init__(self, target, api_keys=None):
        self.target = target.lower().strip()
        self.api_keys = api_keys or {}
        self.logger = setup_logger("osint_collector")
        
        # Results storage
        self.results = {
            'target': self.target,
            'scan_type': 'osint_collection',
            'timestamp': get_timestamp(),
            'sources': {}
        }
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def collect_whois_info(self):
        """Collect WHOIS information"""
        self.logger.info(f"Collecting WHOIS information for {self.target}")
        
        try:
            # Try multiple WHOIS API sources
            whois_sources = [
                f"https://api.whois.vu/?q={self.target}",
                f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={self.target}&outputFormat=JSON"
            ]
            
            whois_data = {}
            
            for source_url in whois_sources:
                try:
                    response = self.session.get(source_url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        whois_data = data
                        break
                except:
                    continue
            
            # If API fails, try parsing from whois.net
            if not whois_data:
                try:
                    whois_url = f"https://www.whois.net/whois/{self.target}"
                    response = self.session.get(whois_url, timeout=10)
                    if response.status_code == 200:
                        whois_data = self.parse_whois_html(response.text)
                except:
                    pass
            
            self.results['sources']['whois'] = {
                'data': whois_data,
                'timestamp': get_timestamp(),
                'status': 'success' if whois_data else 'failed'
            }
            
            return whois_data
            
        except Exception as e:
            log_error(f"Error collecting WHOIS info for {self.target}", self.logger, e)
            self.results['sources']['whois'] = {
                'data': {},
                'timestamp': get_timestamp(),
                'status': 'error',
                'error': str(e)
            }
            return {}
    
    def parse_whois_html(self, html_content):
        """Parse WHOIS information from HTML"""
        try:
            whois_data = {}
            
            # Extract common WHOIS fields using regex
            patterns = {
                'registrar': r'Registrar:\s*(.+)',
                'creation_date': r'Creation Date:\s*(.+)',
                'expiration_date': r'Registry Expiry Date:\s*(.+)',
                'updated_date': r'Updated Date:\s*(.+)',
                'name_servers': r'Name Server:\s*(.+)',
                'status': r'Domain Status:\s*(.+)',
                'registrant_org': r'Registrant Organization:\s*(.+)',
                'registrant_country': r'Registrant Country:\s*(.+)',
                'admin_email': r'Admin Email:\s*(.+)',
                'tech_email': r'Tech Email:\s*(.+)'
            }
            
            for field, pattern in patterns.items():
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                if matches:
                    whois_data[field] = matches[0].strip() if len(matches) == 1 else matches
            
            return whois_data
            
        except Exception as e:
            log_error("Error parsing WHOIS HTML", self.logger, e)
            return {}
    
    def collect_dns_records(self):
        """Collect DNS records"""
        self.logger.info(f"Collecting DNS records for {self.target}")
        
        try:
            dns_data = {}
            
            # Use DNS over HTTPS (DoH) API
            doh_url = f"https://cloudflare-dns.com/dns-query?name={self.target}&type=ANY"
            headers = {'Accept': 'application/dns-json'}
            
            response = self.session.get(doh_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                dns_response = response.json()
                
                if 'Answer' in dns_response:
                    records_by_type = {}
                    
                    for record in dns_response['Answer']:
                        record_type = record.get('type')
                        record_name = record.get('name')
                        record_data = record.get('data')
                        
                        # Convert type number to name
                        type_names = {1: 'A', 5: 'CNAME', 15: 'MX', 16: 'TXT', 2: 'NS', 28: 'AAAA'}
                        type_name = type_names.get(record_type, str(record_type))
                        
                        if type_name not in records_by_type:
                            records_by_type[type_name] = []
                        
                        records_by_type[type_name].append({
                            'name': record_name,
                            'data': record_data,
                            'ttl': record.get('TTL')
                        })
                    
                    dns_data = records_by_type
            
            # Try alternative DNS API if first fails
            if not dns_data:
                try:
                    alt_url = f"https://dns.google/resolve?name={self.target}&type=ANY"
                    response = self.session.get(alt_url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        if 'Answer' in data:
                            dns_data = self.parse_google_dns_response(data['Answer'])
                except:
                    pass
            
            self.results['sources']['dns_records'] = {
                'data': dns_data,
                'timestamp': get_timestamp(),
                'status': 'success' if dns_data else 'failed'
            }
            
            return dns_data
            
        except Exception as e:
            log_error(f"Error collecting DNS records for {self.target}", self.logger, e)
            self.results['sources']['dns_records'] = {
                'data': {},
                'timestamp': get_timestamp(),
                'status': 'error',
                'error': str(e)
            }
            return {}
    
    def parse_google_dns_response(self, answers):
        """Parse Google DNS API response"""
        try:
            records_by_type = {}
            
            for record in answers:
                record_type = record.get('type')
                record_name = record.get('name')
                record_data = record.get('data')
                
                type_names = {1: 'A', 5: 'CNAME', 15: 'MX', 16: 'TXT', 2: 'NS', 28: 'AAAA'}
                type_name = type_names.get(record_type, str(record_type))
                
                if type_name not in records_by_type:
                    records_by_type[type_name] = []
                
                records_by_type[type_name].append({
                    'name': record_name,
                    'data': record_data,
                    'ttl': record.get('TTL')
                })
            
            return records_by_type
            
        except Exception as e:
            log_error("Error parsing Google DNS response", self.logger, e)
            return {}
    
    def collect_certificate_info(self):
        """Collect SSL certificate information"""
        self.logger.info(f"Collecting certificate information for {self.target}")
        
        try:
            cert_data = {}
            
            # Use crt.sh for certificate transparency logs
            crtsh_url = f"https://crt.sh/?q={self.target}&output=json"
            response = self.session.get(crtsh_url, timeout=15)
            
            if response.status_code == 200:
                certificates = response.json()
                
                if certificates:
                    # Process certificate data
                    cert_summary = {
                        'total_certificates': len(certificates),
                        'issuers': set(),
                        'common_names': set(),
                        'san_domains': set(),
                        'earliest_date': None,
                        'latest_date': None
                    }
                    
                    for cert in certificates:
                        # Extract issuer
                        issuer = cert.get('issuer_name', '')
                        if issuer:
                            cert_summary['issuers'].add(issuer)
                        
                        # Extract common name
                        common_name = cert.get('common_name', '')
                        if common_name:
                            cert_summary['common_names'].add(common_name)
                        
                        # Extract SAN domains from name_value
                        name_value = cert.get('name_value', '')
                        if name_value:
                            domains = name_value.split('\n')
                            for domain in domains:
                                domain = domain.strip()
                                if domain and not domain.startswith('*'):
                                    cert_summary['san_domains'].add(domain)
                        
                        # Track dates
                        not_before = cert.get('not_before')
                        not_after = cert.get('not_after')
                        
                        if not_before:
                            if not cert_summary['earliest_date'] or not_before < cert_summary['earliest_date']:
                                cert_summary['earliest_date'] = not_before
                        
                        if not_after:
                            if not cert_summary['latest_date'] or not_after > cert_summary['latest_date']:
                                cert_summary['latest_date'] = not_after
                    
                    # Convert sets to lists for JSON serialization
                    cert_summary['issuers'] = list(cert_summary['issuers'])
                    cert_summary['common_names'] = list(cert_summary['common_names'])
                    cert_summary['san_domains'] = list(cert_summary['san_domains'])
                    
                    cert_data = {
                        'summary': cert_summary,
                        'certificates': certificates[:10]  # Limit to first 10 for storage
                    }
            
            self.results['sources']['certificates'] = {
                'data': cert_data,
                'timestamp': get_timestamp(),
                'status': 'success' if cert_data else 'failed'
            }
            
            return cert_data
            
        except Exception as e:
            log_error(f"Error collecting certificate info for {self.target}", self.logger, e)
            self.results['sources']['certificates'] = {
                'data': {},
                'timestamp': get_timestamp(),
                'status': 'error',
                'error': str(e)
            }
            return {}
    
    def collect_shodan_info(self):
        """Collect information from Shodan (requires API key)"""
        self.logger.info(f"Collecting Shodan information for {self.target}")
        
        if 'shodan' not in self.api_keys:
            self.logger.warning("Shodan API key not provided, skipping Shodan collection")
            self.results['sources']['shodan'] = {
                'data': {},
                'timestamp': get_timestamp(),
                'status': 'skipped',
                'reason': 'API key not provided'
            }
            return {}
        
        try:
            shodan_data = {}
            api_key = self.api_keys['shodan']
            
            # Search for host information
            shodan_url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{self.target}"
            response = self.session.get(shodan_url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'matches' in data:
                    shodan_summary = {
                        'total_results': data.get('total', 0),
                        'hosts': [],
                        'ports': set(),
                        'services': set(),
                        'countries': set(),
                        'organizations': set()
                    }
                    
                    for match in data['matches'][:20]:  # Limit to first 20 results
                        host_info = {
                            'ip': match.get('ip_str'),
                            'port': match.get('port'),
                            'service': match.get('product', ''),
                            'version': match.get('version', ''),
                            'country': match.get('location', {}).get('country_name', ''),
                            'organization': match.get('org', ''),
                            'timestamp': match.get('timestamp')
                        }
                        
                        shodan_summary['hosts'].append(host_info)
                        
                        if host_info['port']:
                            shodan_summary['ports'].add(host_info['port'])
                        if host_info['service']:
                            shodan_summary['services'].add(host_info['service'])
                        if host_info['country']:
                            shodan_summary['countries'].add(host_info['country'])
                        if host_info['organization']:
                            shodan_summary['organizations'].add(host_info['organization'])
                    
                    # Convert sets to lists
                    shodan_summary['ports'] = list(shodan_summary['ports'])
                    shodan_summary['services'] = list(shodan_summary['services'])
                    shodan_summary['countries'] = list(shodan_summary['countries'])
                    shodan_summary['organizations'] = list(shodan_summary['organizations'])
                    
                    shodan_data = shodan_summary
            
            self.results['sources']['shodan'] = {
                'data': shodan_data,
                'timestamp': get_timestamp(),
                'status': 'success' if shodan_data else 'failed'
            }
            
            return shodan_data
            
        except Exception as e:
            log_error(f"Error collecting Shodan info for {self.target}", self.logger, e)
            self.results['sources']['shodan'] = {
                'data': {},
                'timestamp': get_timestamp(),
                'status': 'error',
                'error': str(e)
            }
            return {}
    
    def collect_github_info(self):
        """Collect information from GitHub"""
        self.logger.info(f"Searching GitHub for {self.target}")
        
        try:
            github_data = {}
            
            # Search GitHub for repositories and code mentioning the target
            search_queries = [
                f'"{self.target}"',
                f'{self.target.replace(".", " ")}',
                f'site:{self.target}'
            ]
            
            github_results = {
                'repositories': [],
                'code_results': [],
                'total_repositories': 0,
                'total_code_results': 0
            }
            
            headers = {}
            if 'github' in self.api_keys:
                headers['Authorization'] = f"token {self.api_keys['github']}"
            
            for query in search_queries:
                try:
                    # Search repositories
                    repo_url = f"https://api.github.com/search/repositories?q={quote(query)}&sort=updated&per_page=10"
                    response = self.session.get(repo_url, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        repo_data = response.json()
                        if 'items' in repo_data:
                            for repo in repo_data['items']:
                                repo_info = {
                                    'name': repo.get('full_name'),
                                    'description': repo.get('description'),
                                    'url': repo.get('html_url'),
                                    'stars': repo.get('stargazers_count'),
                                    'language': repo.get('language'),
                                    'updated_at': repo.get('updated_at')
                                }
                                github_results['repositories'].append(repo_info)
                            
                            github_results['total_repositories'] += repo_data.get('total_count', 0)
                    
                    # Search code (requires authentication)
                    if 'github' in self.api_keys:
                        code_url = f"https://api.github.com/search/code?q={quote(query)}&per_page=10"
                        response = self.session.get(code_url, headers=headers, timeout=10)
                        
                        if response.status_code == 200:
                            code_data = response.json()
                            if 'items' in code_data:
                                for code in code_data['items']:
                                    code_info = {
                                        'name': code.get('name'),
                                        'path': code.get('path'),
                                        'repository': code.get('repository', {}).get('full_name'),
                                        'url': code.get('html_url'),
                                        'score': code.get('score')
                                    }
                                    github_results['code_results'].append(code_info)
                                
                                github_results['total_code_results'] += code_data.get('total_count', 0)
                    
                    # Rate limiting
                    time.sleep(1)
                    
                except Exception as e:
                    self.logger.debug(f"Error searching GitHub with query '{query}': {str(e)}")
                    continue
            
            github_data = github_results
            
            self.results['sources']['github'] = {
                'data': github_data,
                'timestamp': get_timestamp(),
                'status': 'success' if github_data else 'failed'
            }
            
            return github_data
            
        except Exception as e:
            log_error(f"Error collecting GitHub info for {self.target}", self.logger, e)
            self.results['sources']['github'] = {
                'data': {},
                'timestamp': get_timestamp(),
                'status': 'error',
                'error': str(e)
            }
            return {}
    
    def collect_wayback_urls(self):
        """Collect URLs from Wayback Machine"""
        self.logger.info(f"Collecting Wayback Machine URLs for {self.target}")
        
        try:
            wayback_data = {}
            
            # Get URL list from Wayback Machine
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={self.target}/*&output=json&collapse=urlkey&limit=1000"
            response = self.session.get(wayback_url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if data and len(data) > 1:  # First row is headers
                    urls = []
                    file_extensions = {}
                    years = set()
                    
                    for row in data[1:]:  # Skip header row
                        if len(row) >= 3:
                            timestamp = row[1]
                            url = row[2]
                            
                            urls.append({
                                'url': url,
                                'timestamp': timestamp,
                                'year': timestamp[:4] if len(timestamp) >= 4 else 'unknown'
                            })
                            
                            # Extract file extension
                            if '.' in url.split('/')[-1]:
                                ext = url.split('.')[-1].lower()
                                if len(ext) <= 5:  # Reasonable extension length
                                    file_extensions[ext] = file_extensions.get(ext, 0) + 1
                            
                            # Track years
                            if len(timestamp) >= 4:
                                years.add(timestamp[:4])
                    
                    wayback_data = {
                        'total_urls': len(urls),
                        'urls': urls[:100],  # Limit stored URLs
                        'file_extensions': file_extensions,
                        'years_active': sorted(list(years)),
                        'earliest_capture': min(data[1:], key=lambda x: x[1])[1] if data[1:] else None,
                        'latest_capture': max(data[1:], key=lambda x: x[1])[1] if data[1:] else None
                    }
            
            self.results['sources']['wayback_machine'] = {
                'data': wayback_data,
                'timestamp': get_timestamp(),
                'status': 'success' if wayback_data else 'failed'
            }
            
            return wayback_data
            
        except Exception as e:
            log_error(f"Error collecting Wayback Machine URLs for {self.target}", self.logger, e)
            self.results['sources']['wayback_machine'] = {
                'data': {},
                'timestamp': get_timestamp(),
                'status': 'error',
                'error': str(e)
            }
            return {}
    
    def collect_social_media_mentions(self):
        """Collect social media mentions (basic implementation)"""
        self.logger.info(f"Searching for social media mentions of {self.target}")
        
        try:
            social_data = {}
            
            # Search for social media profiles and mentions
            # Note: This is a basic implementation. Real-world usage might require API access
            
            social_platforms = {
                'twitter': f"https://twitter.com/{self.target.replace('.', '')}",
                'linkedin': f"https://www.linkedin.com/company/{self.target.replace('.', '-')}",
                'facebook': f"https://www.facebook.com/{self.target.replace('.', '')}",
                'instagram': f"https://www.instagram.com/{self.target.replace('.', '')}"
            }
            
            found_profiles = {}
            
            for platform, url in social_platforms.items():
                try:
                    response = self.session.head(url, timeout=5)
                    if response.status_code == 200:
                        found_profiles[platform] = url
                except:
                    pass
            
            social_data = {
                'potential_profiles': found_profiles,
                'search_performed': True
            }
            
            self.results['sources']['social_media'] = {
                'data': social_data,
                'timestamp': get_timestamp(),
                'status': 'success'
            }
            
            return social_data
            
        except Exception as e:
            log_error(f"Error collecting social media info for {self.target}", self.logger, e)
            self.results['sources']['social_media'] = {
                'data': {},
                'timestamp': get_timestamp(),
                'status': 'error',
                'error': str(e)
            }
            return {}
    
    def comprehensive_collection(self):
        """Run comprehensive OSINT collection"""
        self.logger.info(f"Starting comprehensive OSINT collection for {self.target}")
        
        start_time = time.time()
        
        # Collection methods
        collection_methods = [
            ('whois', self.collect_whois_info),
            ('dns_records', self.collect_dns_records),
            ('certificates', self.collect_certificate_info),
            ('shodan', self.collect_shodan_info),
            ('github', self.collect_github_info),
            ('wayback_machine', self.collect_wayback_urls),
            ('social_media', self.collect_social_media_mentions)
        ]
        
        # Run collections in parallel for better performance
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_method = {
                executor.submit(method_func): method_name 
                for method_name, method_func in collection_methods
            }
            
            for future in as_completed(future_to_method):
                method_name = future_to_method[future]
                try:
                    result = future.result()
                    self.logger.info(f"Completed {method_name} collection")
                except Exception as e:
                    log_error(f"Error in {method_name} collection", self.logger, e)
        
        end_time = time.time()
        collection_duration = end_time - start_time
        
        # Generate summary
        self.results['summary'] = {
            'collection_duration': collection_duration,
            'sources_attempted': len(collection_methods),
            'sources_successful': len([s for s in self.results['sources'] if self.results['sources'][s]['status'] == 'success']),
            'sources_failed': len([s for s in self.results['sources'] if self.results['sources'][s]['status'] == 'error']),
            'sources_skipped': len([s for s in self.results['sources'] if self.results['sources'][s]['status'] == 'skipped'])
        }
        
        self.logger.info(f"OSINT collection completed in {collection_duration:.2f} seconds")
        self.logger.info(f"Successful sources: {self.results['summary']['sources_successful']}/{len(collection_methods)}")
        
        return self.results
    
    def save_results(self, format_type='json'):
        """Save OSINT collection results"""
        target_clean = self.target.replace('.', '_')
        filename = f"osint_collection_{target_clean}"
        
        filepath = save_results(self.results, filename, format_type)
        self.logger.info(f"OSINT results saved to: {filepath}")
        return filepath

def run_osint_collection(target, api_keys=None, save_format='json'):
    """Main function to run OSINT collection"""
    
    # Validate target (can be domain or other identifier)
    if not target or len(target.strip()) < 3:
        print(f"Error: Invalid target '{target}'. Please provide a valid target.")
        return None
    
    # Initialize collector
    collector = OSINTCollector(target, api_keys)
    
    try:
        # Run comprehensive collection
        results = collector.comprehensive_collection()
        
        # Save results
        if results and save_format:
            collector.save_results(save_format)
        
        return results
        
    except KeyboardInterrupt:
        collector.logger.info("OSINT collection interrupted by user")
        return collector.results
    except Exception as e:
        log_error("Unexpected error during OSINT collection", collector.logger, e)
        return None

if __name__ == "__main__":
    # Example usage
    target = "example.com"
    api_keys = {
        'shodan': 'your_shodan_api_key_here',
        'github': 'your_github_token_here'
    }
    
    results = run_osint_collection(target, api_keys)
    
    if results:
        print(f"\nOSINT Collection Results for {target}:")
        print(f"Sources attempted: {results['summary']['sources_attempted']}")
        print(f"Sources successful: {results['summary']['sources_successful']}")
        
        for source_name, source_data in results['sources'].items():
            status = source_data['status']
            print(f"  {source_name}: {status}")
            
            if status == 'success' and source_data['data']:
                # Show sample data
                data = source_data['data']
                if isinstance(data, dict):
                    for key, value in list(data.items())[:3]:
                        if isinstance(value, (list, set)):
                            print(f"    {key}: {len(value)} items")
                        else:
                            print(f"    {key}: {str(value)[:50]}...")
