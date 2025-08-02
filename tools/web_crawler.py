import requests
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from urllib.robotparser import RobotFileParser
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque, defaultdict
import hashlib
from utils.logger import setup_logger, log_scan_result, log_error
from utils.helpers import validate_url, clean_url, save_results, get_timestamp

class WebCrawler:
    def __init__(self, base_url, max_depth=3, max_pages=500, threads=10, timeout=10):
        self.base_url = clean_url(base_url)
        self.base_domain = urlparse(self.base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.threads = threads
        self.timeout = timeout
        self.logger = setup_logger("web_crawler")
        
        # Tracking sets and data structures
        self.visited_urls = set()
        self.found_urls = set()
        self.crawl_queue = deque([(self.base_url, 0)])  # (url, depth)
        self.endpoints = set()
        self.parameters = defaultdict(set)
        self.forms = []
        self.js_files = set()
        self.interesting_files = set()
        self.external_links = set()
        self.subdomains = set()
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # File extensions to look for
        self.interesting_extensions = {
            '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
            '.json', '.xml', '.txt', '.log', '.bak', '.old',
            '.config', '.conf', '.ini', '.env', '.sql',
            '.zip', '.tar', '.gz', '.rar', '.7z',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx'
        }
        
        # Robots.txt parser
        self.robots_parser = None
        self.load_robots_txt()
    
    def load_robots_txt(self):
        """Load and parse robots.txt"""
        try:
            robots_url = urljoin(self.base_url, '/robots.txt')
            self.robots_parser = RobotFileParser()
            self.robots_parser.set_url(robots_url)
            self.robots_parser.read()
            
            # Extract interesting paths from robots.txt
            response = self.session.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                self.parse_robots_txt(response.text)
                self.logger.info("Loaded robots.txt successfully")
            
        except Exception as e:
            self.logger.debug(f"Could not load robots.txt: {str(e)}")
    
    def parse_robots_txt(self, robots_content):
        """Parse robots.txt for interesting paths"""
        try:
            lines = robots_content.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('Disallow:') or line.startswith('Allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        full_url = urljoin(self.base_url, path)
                        self.found_urls.add(full_url)
                        self.endpoints.add(path)
                elif line.startswith('Sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    self.found_urls.add(sitemap_url)
        except Exception as e:
            log_error("Error parsing robots.txt", self.logger, e)
    
    def is_valid_url(self, url):
        """Check if URL is valid for crawling"""
        try:
            parsed = urlparse(url)
            
            # Skip non-HTTP(S) URLs
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Skip external domains (unless we want to track them)
            if parsed.netloc != self.base_domain:
                self.external_links.add(url)
                # Check if it's a subdomain
                if parsed.netloc.endswith(f'.{self.base_domain}'):
                    self.subdomains.add(parsed.netloc)
                return False
            
            # Skip certain file types
            skip_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', 
                             '.css', '.woff', '.woff2', '.ttf', '.eot', '.svg',
                             '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv'}
            
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in skip_extensions):
                return False
            
            # Check robots.txt compliance
            if self.robots_parser and not self.robots_parser.can_fetch('*', url):
                self.logger.debug(f"Robots.txt disallows: {url}")
                return False
            
            return True
            
        except Exception as e:
            return False
    
    def extract_urls_from_html(self, html_content, base_url):
        """Extract URLs from HTML content"""
        urls = set()
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract links from various HTML elements
            link_elements = [
                ('a', 'href'),
                ('link', 'href'),
                ('script', 'src'),
                ('img', 'src'),
                ('iframe', 'src'),
                ('form', 'action'),
                ('area', 'href'),
                ('base', 'href')
            ]
            
            for tag, attr in link_elements:
                elements = soup.find_all(tag)
                for element in elements:
                    url = element.get(attr)
                    if url:
                        # Handle relative URLs
                        full_url = urljoin(base_url, url)
                        urls.add(full_url)
                        
                        # Track JavaScript files
                        if tag == 'script' and attr == 'src':
                            self.js_files.add(full_url)
            
            # Extract URLs from JavaScript (basic regex patterns)
            js_url_patterns = [
                r'["\']([^"\']*\.(?:php|asp|aspx|jsp|do|action|json|xml)[^"\']*)["\']',
                r'["\']([^"\']*\/[^"\']*)["\']',
                r'url\s*:\s*["\']([^"\']+)["\']',
                r'ajax\s*\(\s*["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in js_url_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if match.startswith('/') or match.startswith('http'):
                        full_url = urljoin(base_url, match)
                        urls.add(full_url)
            
            # Extract forms and their parameters
            forms = soup.find_all('form')
            for form in forms:
                form_info = self.extract_form_info(form, base_url)
                if form_info:
                    self.forms.append(form_info)
            
            return urls
            
        except Exception as e:
            log_error(f"Error extracting URLs from HTML", self.logger, e)
            return set()
    
    def extract_form_info(self, form_element, base_url):
        """Extract form information"""
        try:
            form_info = {
                'action': urljoin(base_url, form_element.get('action', '')),
                'method': form_element.get('method', 'GET').upper(),
                'inputs': [],
                'timestamp': get_timestamp()
            }
            
            # Extract input fields
            inputs = form_element.find_all(['input', 'select', 'textarea'])
            for input_elem in inputs:
                input_info = {
                    'name': input_elem.get('name', ''),
                    'type': input_elem.get('type', 'text'),
                    'value': input_elem.get('value', ''),
                    'required': input_elem.has_attr('required')
                }
                
                if input_info['name']:
                    form_info['inputs'].append(input_info)
                    # Track parameters
                    self.parameters[form_info['action']].add(input_info['name'])
            
            return form_info
            
        except Exception as e:
            log_error("Error extracting form info", self.logger, e)
            return None
    
    def extract_parameters_from_url(self, url):
        """Extract parameters from URL query string"""
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                for param_name in params.keys():
                    self.parameters[base_url].add(param_name)
        except Exception as e:
            log_error("Error extracting URL parameters", self.logger, e)
    
    def crawl_url(self, url, depth):
        """Crawl a single URL"""
        if url in self.visited_urls or depth > self.max_depth:
            return set()
        
        if len(self.visited_urls) >= self.max_pages:
            return set()
        
        try:
            self.logger.debug(f"Crawling: {url} (depth: {depth})")
            
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            self.visited_urls.add(url)
            
            # Track the endpoint
            parsed = urlparse(url)
            endpoint = parsed.path
            if parsed.query:
                endpoint += f"?{parsed.query}"
            self.endpoints.add(endpoint)
            
            # Extract parameters from URL
            self.extract_parameters_from_url(url)
            
            # Check for interesting files
            if any(url.lower().endswith(ext) for ext in self.interesting_extensions):
                self.interesting_files.add(url)
            
            # Only process HTML content
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type:
                return set()
            
            # Extract URLs from HTML
            new_urls = self.extract_urls_from_html(response.text, url)
            
            # Filter valid URLs
            valid_urls = set()
            for new_url in new_urls:
                if self.is_valid_url(new_url) and new_url not in self.visited_urls:
                    valid_urls.add(new_url)
                    self.found_urls.add(new_url)
            
            return valid_urls
            
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Request failed for {url}: {str(e)}")
            return set()
        except Exception as e:
            log_error(f"Error crawling {url}", self.logger, e)
            return set()
    
    def crawl_website(self):
        """Main crawling function"""
        self.logger.info(f"Starting web crawl of {self.base_url}")
        self.logger.info(f"Max depth: {self.max_depth}, Max pages: {self.max_pages}, Threads: {self.threads}")
        
        start_time = time.time()
        
        while self.crawl_queue and len(self.visited_urls) < self.max_pages:
            # Get batch of URLs to crawl
            batch = []
            batch_size = min(self.threads, len(self.crawl_queue))
            
            for _ in range(batch_size):
                if self.crawl_queue:
                    batch.append(self.crawl_queue.popleft())
            
            if not batch:
                break
            
            # Crawl batch in parallel
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {
                    executor.submit(self.crawl_url, url, depth): (url, depth) 
                    for url, depth in batch
                }
                
                for future in as_completed(future_to_url):
                    url, depth = future_to_url[future]
                    try:
                        new_urls = future.result()
                        
                        # Add new URLs to queue
                        for new_url in new_urls:
                            if new_url not in self.visited_urls:
                                self.crawl_queue.append((new_url, depth + 1))
                                
                    except Exception as e:
                        log_error(f"Error processing {url}", self.logger, e)
            
            # Progress update
            if len(self.visited_urls) % 50 == 0:
                self.logger.info(f"Crawled {len(self.visited_urls)} pages, found {len(self.found_urls)} URLs")
        
        end_time = time.time()
        crawl_duration = end_time - start_time
        
        self.logger.info(f"Web crawl completed in {crawl_duration:.2f} seconds")
        self.logger.info(f"Visited {len(self.visited_urls)} pages")
        self.logger.info(f"Found {len(self.endpoints)} unique endpoints")
        self.logger.info(f"Found {len(self.parameters)} parameterized endpoints")
        self.logger.info(f"Found {len(self.forms)} forms")
        
        return self.get_results()
    
    def analyze_javascript_files(self):
        """Analyze JavaScript files for additional endpoints"""
        self.logger.info(f"Analyzing {len(self.js_files)} JavaScript files")
        
        js_endpoints = set()
        js_parameters = defaultdict(set)
        
        def analyze_js_file(js_url):
            try:
                response = self.session.get(js_url, timeout=self.timeout)
                if response.status_code == 200:
                    js_content = response.text
                    
                    # Extract API endpoints
                    api_patterns = [
                        r'["\']([^"\']*\/api\/[^"\']*)["\']',
                        r'["\']([^"\']*\.php[^"\']*)["\']',
                        r'["\']([^"\']*\.asp[^"\']*)["\']',
                        r'["\']([^"\']*\.jsp[^"\']*)["\']',
                        r'["\']([^"\']*\.json[^"\']*)["\']',
                        r'["\']([^"\']*\.xml[^"\']*)["\']'
                    ]
                    
                    for pattern in api_patterns:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        for match in matches:
                            if match.startswith('/'):
                                js_endpoints.add(match)
                    
                    # Extract parameter names
                    param_patterns = [
                        r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\']?[^,}]+',
                        r'data\s*:\s*{\s*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',
                        r'params\s*:\s*{\s*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']'
                    ]
                    
                    for pattern in param_patterns:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        for match in matches:
                            js_parameters['javascript'].add(match)
                    
            except Exception as e:
                self.logger.debug(f"Error analyzing JS file {js_url}: {str(e)}")
        
        # Analyze JS files in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(analyze_js_file, js_url) for js_url in list(self.js_files)[:20]]  # Limit to 20 files
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    pass
        
        # Add JS findings to main results
        self.endpoints.update(js_endpoints)
        for endpoint, params in js_parameters.items():
            self.parameters[endpoint].update(params)
        
        self.logger.info(f"JavaScript analysis found {len(js_endpoints)} additional endpoints")
    
    def get_results(self):
        """Compile crawling results"""
        # Convert defaultdict to regular dict for JSON serialization
        parameters_dict = {k: list(v) for k, v in self.parameters.items()}
        
        results = {
            'base_url': self.base_url,
            'scan_type': 'web_crawl',
            'timestamp': get_timestamp(),
            'crawl_settings': {
                'max_depth': self.max_depth,
                'max_pages': self.max_pages,
                'threads': self.threads,
                'timeout': self.timeout
            },
            'summary': {
                'pages_visited': len(self.visited_urls),
                'urls_found': len(self.found_urls),
                'endpoints_found': len(self.endpoints),
                'parameterized_endpoints': len(self.parameters),
                'forms_found': len(self.forms),
                'js_files_found': len(self.js_files),
                'interesting_files': len(self.interesting_files),
                'external_links': len(self.external_links),
                'subdomains_found': len(self.subdomains)
            },
            'endpoints': list(self.endpoints),
            'parameters': parameters_dict,
            'forms': self.forms,
            'interesting_files': list(self.interesting_files),
            'js_files': list(self.js_files),
            'external_links': list(self.external_links),
            'subdomains': list(self.subdomains),
            'visited_urls': list(self.visited_urls)
        }
        
        return results
    
    def save_results(self, results, format_type='json'):
        """Save crawling results"""
        if not results:
            return None
        
        parsed_url = urlparse(self.base_url)
        domain_clean = parsed_url.netloc.replace('.', '_')
        filename = f"web_crawl_{domain_clean}"
        
        filepath = save_results(results, filename, format_type)
        self.logger.info(f"Web crawl results saved to: {filepath}")
        return filepath

def run_web_crawl(base_url, max_depth=3, max_pages=500, threads=10, analyze_js=True, save_format='json'):
    """Main function to run web crawling"""
    
    # Validate URL
    if not validate_url(base_url):
        print(f"Error: Invalid URL '{base_url}'. Please provide a valid URL.")
        return None
    
    # Initialize crawler
    crawler = WebCrawler(base_url, max_depth, max_pages, threads)
    
    try:
        # Run main crawl
        results = crawler.crawl_website()
        
        # Analyze JavaScript files if requested
        if analyze_js and crawler.js_files:
            crawler.analyze_javascript_files()
            results = crawler.get_results()  # Update results with JS analysis
        
        # Save results
        if results and save_format:
            crawler.save_results(results, save_format)
        
        return results
        
    except KeyboardInterrupt:
        crawler.logger.info("Web crawl interrupted by user")
        return crawler.get_results()
    except Exception as e:
        log_error("Unexpected error during web crawl", crawler.logger, e)
        return None

if __name__ == "__main__":
    # Example usage
    base_url = "http://testphp.vulnweb.com"
    results = run_web_crawl(base_url, max_depth=2, max_pages=100)
    
    if results:
        print(f"\nWeb Crawl Results for {base_url}:")
        print(f"Pages visited: {results['summary']['pages_visited']}")
        print(f"Endpoints found: {results['summary']['endpoints_found']}")
        print(f"Forms found: {results['summary']['forms_found']}")
        print(f"Interesting files: {results['summary']['interesting_files']}")
        
        print("\nSample endpoints:")
        for endpoint in list(results['endpoints'])[:10]:
            print(f"  {endpoint}")
        
        if results['parameters']:
            print("\nParameterized endpoints:")
            for endpoint, params in list(results['parameters'].items())[:5]:
                print(f"  {endpoint}: {', '.join(params)}")
