import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from utils.logger import setup_logger, log_scan_result, log_error
from utils.helpers import validate_url, clean_url, save_results, get_timestamp

class SubdirFinder:
    def __init__(self, target_url, threads=50, timeout=10):
        self.target_url = clean_url(target_url)
        self.threads = threads
        self.timeout = timeout
        self.logger = setup_logger("subdir_finder")
        self.found_dirs = []
        self.found_files = []
        self.session = requests.Session()
        
        # Set headers to appear more legitimate
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def check_path(self, path):
        """Check if a path exists on the target"""
        url = urljoin(self.target_url, path)
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            
            result = {
                'path': path,
                'url': url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', 'Unknown'),
                'timestamp': get_timestamp()
            }
            
            # Determine if it's interesting based on status code
            if response.status_code in [200, 301, 302, 403, 401]:
                if path.endswith('/'):
                    result['type'] = 'directory'
                    self.found_dirs.append(result)
                else:
                    result['type'] = 'file'
                    self.found_files.append(result)
                
                status_msg = f"Found: {url} [{response.status_code}] ({len(response.content)} bytes)"
                
                if response.status_code == 200:
                    self.logger.info(status_msg)
                elif response.status_code in [301, 302]:
                    redirect_url = response.headers.get('location', 'Unknown')
                    self.logger.info(f"{status_msg} -> {redirect_url}")
                elif response.status_code == 403:
                    self.logger.warning(f"{status_msg} [FORBIDDEN]")
                elif response.status_code == 401:
                    self.logger.warning(f"{status_msg} [UNAUTHORIZED]")
                
                return result
            
            return None
            
        except requests.exceptions.Timeout:
            self.logger.debug(f"Timeout: {url}")
            return None
        except requests.exceptions.ConnectionError:
            self.logger.debug(f"Connection error: {url}")
            return None
        except Exception as e:
            log_error(f"Error checking {url}", self.logger, e)
            return None
    
    def load_wordlist(self, wordlist_path):
        """Load wordlist from file"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            self.logger.info(f"Loaded {len(wordlist)} words from {wordlist_path}")
            return wordlist
            
        except FileNotFoundError:
            self.logger.error(f"Wordlist file not found: {wordlist_path}")
            return []
        except Exception as e:
            log_error(f"Error loading wordlist: {wordlist_path}", self.logger, e)
            return []
    
    def get_default_wordlist(self):
        """Get default wordlist for directory enumeration"""
        return [
            'admin', 'administrator', 'login', 'panel', 'dashboard', 'config',
            'backup', 'backups', 'old', 'new', 'test', 'testing', 'dev',
            'development', 'staging', 'prod', 'production', 'api', 'v1', 'v2',
            'uploads', 'upload', 'files', 'file', 'images', 'img', 'css', 'js',
            'assets', 'static', 'public', 'private', 'secure', 'hidden',
            'temp', 'tmp', 'cache', 'logs', 'log', 'debug', 'error',
            'phpmyadmin', 'mysql', 'database', 'db', 'sql', 'data',
            'wp-admin', 'wp-content', 'wp-includes', 'wordpress',
            'cgi-bin', 'bin', 'etc', 'var', 'usr', 'home', 'root',
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'readme.txt', 'changelog.txt', 'license.txt', 'install.txt',
            'phpinfo.php', 'info.php', 'test.php', 'index.php',
            'index.html', 'index.htm', 'default.html', 'home.html'
        ]
    
    def scan_directories(self, wordlist=None, extensions=None):
        """Scan for directories and files using wordlist"""
        
        if wordlist is None:
            wordlist = self.get_default_wordlist()
        
        if extensions is None:
            extensions = ['', '/', '.php', '.html', '.htm', '.txt', '.xml', '.json', '.js', '.css']
        
        # Generate paths to test
        paths_to_test = []
        for word in wordlist:
            for ext in extensions:
                if ext == '/' and not word.endswith('/'):
                    paths_to_test.append(word + ext)
                elif ext != '/' and not word.endswith('/'):
                    paths_to_test.append(word + ext)
        
        self.logger.info(f"Starting directory enumeration on {self.target_url}")
        self.logger.info(f"Testing {len(paths_to_test)} paths with {self.threads} threads")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {executor.submit(self.check_path, path): path for path in paths_to_test}
            
            completed = 0
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                completed += 1
                
                if completed % 100 == 0:
                    self.logger.info(f"Progress: {completed}/{len(paths_to_test)} paths tested")
                
                try:
                    result = future.result()
                except Exception as e:
                    log_error(f"Path {path} generated an exception", self.logger, e)
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Log results
        total_found = len(self.found_dirs) + len(self.found_files)
        log_scan_result(self.target_url, "Directory Enumeration", total_found, self.logger)
        self.logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        self.logger.info(f"Directories found: {len(self.found_dirs)}")
        self.logger.info(f"Files found: {len(self.found_files)}")
        
        return self.get_results()
    
    def scan_with_wordlist_file(self, wordlist_path, extensions=None):
        """Scan using wordlist from file"""
        wordlist = self.load_wordlist(wordlist_path)
        if not wordlist:
            self.logger.error("No valid wordlist loaded, using default wordlist")
            wordlist = self.get_default_wordlist()
        
        return self.scan_directories(wordlist, extensions)
    
    def get_results(self):
        """Get scan results in structured format"""
        results = {
            'target': self.target_url,
            'scan_type': 'directory_enumeration',
            'timestamp': get_timestamp(),
            'directories': self.found_dirs,
            'files': self.found_files,
            'total_directories': len(self.found_dirs),
            'total_files': len(self.found_files),
            'total_found': len(self.found_dirs) + len(self.found_files),
            'scan_settings': {
                'threads': self.threads,
                'timeout': self.timeout
            }
        }
        return results
    
    def save_results(self, format_type='json'):
        """Save scan results to file"""
        results = self.get_results()
        parsed_url = urlparse(self.target_url)
        filename = f"dir_scan_{parsed_url.netloc.replace('.', '_')}"
        filepath = save_results(results, filename, format_type)
        self.logger.info(f"Results saved to: {filepath}")
        return filepath

def run_directory_scan(target_url, wordlist_path=None, threads=50, timeout=10, extensions=None, save_format='json'):
    """Main function to run directory enumeration"""
    
    # Validate target URL
    if not validate_url(target_url):
        print(f"Error: Invalid URL '{target_url}'. Please provide a valid URL.")
        return None
    
    # Initialize scanner
    scanner = SubdirFinder(target_url, threads, timeout)
    
    try:
        # Test if target is reachable
        test_response = scanner.session.get(target_url, timeout=timeout)
        scanner.logger.info(f"Target is reachable: {target_url} [{test_response.status_code}]")
        
        # Run scan
        if wordlist_path:
            results = scanner.scan_with_wordlist_file(wordlist_path, extensions)
        else:
            results = scanner.scan_directories(extensions=extensions)
        
        # Save results
        if save_format:
            scanner.save_results(save_format)
        
        return results
        
    except requests.exceptions.RequestException as e:
        scanner.logger.error(f"Cannot reach target: {target_url}")
        log_error("Connection error", scanner.logger, e)
        return None
    except KeyboardInterrupt:
        scanner.logger.info("Scan interrupted by user")
        return scanner.get_results()
    except Exception as e:
        log_error("Unexpected error during directory scan", scanner.logger, e)
        return None

if __name__ == "__main__":
    # Example usage
    target = "http://testphp.vulnweb.com"
    results = run_directory_scan(target, threads=30)
    
    if results:
        print(f"\nDirectory Scan Results for {target}:")
        print(f"Directories found: {results['total_directories']}")
        print(f"Files found: {results['total_files']}")
        
        if results['directories']:
            print("\nDirectories:")
            for dir_info in results['directories'][:10]:  # Show first 10
                print(f"  {dir_info['path']} [{dir_info['status_code']}]")
        
        if results['files']:
            print("\nFiles:")
            for file_info in results['files'][:10]:  # Show first 10
                print(f"  {file_info['path']} [{file_info['status_code']}]")
