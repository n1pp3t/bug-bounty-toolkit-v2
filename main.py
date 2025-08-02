#!/usr/bin/env python3
"""
Bug Bounty Reconnaissance Toolkit
Main CLI interface for port scanning, directory enumeration, and data analysis
"""

import argparse
import sys
import os
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Add the current directory to Python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from tools.port_scanner import run_port_scan
from tools.subdir_finder import run_directory_scan
from tools.data_analyzer import run_analysis
from tools.nmap_scanner import run_nmap_scan
from tools.subdomain_finder import run_subdomain_enumeration
from tools.amass_wrapper import run_amass_scan
from tools.web_crawler import run_web_crawl
from tools.vulnerability_scanner import run_vulnerability_scan
from tools.osint_collector import run_osint_collection
from tools.hashcat_wrapper import run_hashcat_attack
from tools.airgeddon_wrapper import run_airgeddon
from tools.sherlock_wrapper import run_sherlock_scan
from tools.gobuster_wrapper import run_gobuster_scan
from tools.sqlmap_wrapper import run_sqlmap_scan
from tools.email_user_finder import find_email_users
from tools.mobile_phone_osint import get_phone_info
from tools.modem_vuln_scanner import scan_modem
from tools.payload_tools import generate_payload
from tools.metasploit_automation import run_metasploit_module
from tools.osintgram_wrapper import run_osintgram
from tools.instagram_scraper import run_instagram_scan
from tools.twitter_scraper import run_twitter_scan, search_twitter_hashtags
from tools.linkedin_searcher import run_linkedin_search, get_linkedin_company_info
from tools.facebook_searcher import run_facebook_search, get_facebook_page_info
from tools.email_verifier import run_email_verification
from tools.phone_validator import validate_phone_number
from tools.domain_reputation import run_domain_reputation_check
from tools.ip_geolocation import get_ip_geolocation, get_hostname_geolocation
from utils.helpers import validate_ip, validate_domain, validate_url


def print_banner():
    """Print the toolkit banner"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                   F-Society Toolkit - V2                    ║
║                Bug Bounty Reconnaissance Toolkit            ║
║                                                              ║
║  🔍 Subdomain Enum  │  🔧 Port Scanner   │  🌐 Web Crawler   ║
║  🛡️  Vuln Scanner   │  📊 OSINT Collector │  🎯 Full Recon    ║
║  ⚡ Nmap Integration │  🔎 Amass Wrapper  │  📈 Data Analysis ║
║  🔑 Hashcat Attack  │  📶 WiFi Hacking   │  👤 Social Scan   ║
║  💥 GoBuster Scan   │  💉 SQL Injection  │  📧 Email Finder   ║
║  📱 Mobile OSINT   │  📡 Modem Scanner  │  💣 Payload Gen    ║
║  🤖 Metasploit     │  📸 OSINTGram      │  🌐 Social Media   ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}⚠️  For authorized testing only - Always get permission first!{Style.RESET_ALL}
"""
    print(banner)
def setup_port_scan_parser(subparsers):
    """Setup port scan command parser"""
    port_parser = subparsers.add_parser('port-scan', help='Scan for open ports')
    port_parser.add_argument('target', help='Target IP address or domain name')
    port_parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000, 80,443,8080)')
    port_parser.add_argument('-c', '--common-ports', action='store_true', 
                           help='Scan common ports only')
    port_parser.add_argument('-t', '--threads', type=int, default=100,
                           help='Number of threads (default: 100)')
    port_parser.add_argument('--timeout', type=int, default=3,
                           help='Connection timeout in seconds (default: 3)')
    port_parser.add_argument('-o', '--output', choices=['json', 'txt', 'html'], 
                           default='json', help='Output format (default: json)')
    port_parser.add_argument('--no-save', action='store_true',
                           help='Don\'t save results to file')

def setup_dir_scan_parser(subparsers):
    """Setup directory scan command parser"""
    dir_parser = subparsers.add_parser('dir-scan', help='Enumerate directories and files')
    dir_parser.add_argument('target', help='Target URL (e.g., https://example.com)')
    dir_parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    dir_parser.add_argument('-t', '--threads', type=int, default=50,
                          help='Number of threads (default: 50)')
    dir_parser.add_argument('--timeout', type=int, default=10,
                          help='Request timeout in seconds (default: 10)')
    dir_parser.add_argument('-e', '--extensions', 
                          help='File extensions to test (comma-separated, e.g., php,html,txt)')
    dir_parser.add_argument('-o', '--output', choices=['json', 'txt', 'html'], 
                          default='json', help='Output format (default: json)')
    dir_parser.add_argument('--no-save', action='store_true',
                          help='Don\'t save results to file')

def setup_analyze_parser(subparsers):
    """Setup data analysis command parser"""
    analyze_parser = subparsers.add_parser('analyze', help='Analyze scan results')
    analyze_parser.add_argument('input', nargs='+', help='Input file(s) to analyze')
    analyze_parser.add_argument('-o', '--output', choices=['json', 'txt', 'html'], 
                              default='html', help='Output format (default: html)')
    analyze_parser.add_argument('--no-save', action='store_true',
                              help='Don\'t save analysis to file')

def setup_nmap_parser(subparsers):
    """Setup nmap scan command parser"""
    nmap_parser = subparsers.add_parser('nmap-scan', help='Advanced Nmap scanning')
    nmap_parser.add_argument('target', help='Target IP address or domain name')
    nmap_parser.add_argument('-t', '--type', choices=['quick', 'service', 'os', 'aggressive', 'vulnerability', 'udp', 'stealth', 'comprehensive'],
                           default='quick', help='Scan type (default: quick)')
    nmap_parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000, 80,443,8080)')
    nmap_parser.add_argument('-o', '--output', choices=['json', 'txt', 'html'], 
                           default='json', help='Output format (default: json)')
    nmap_parser.add_argument('--no-save', action='store_true',
                           help='Don\'t save results to file')

def setup_subdomain_parser(subparsers):
    """Setup subdomain enumeration command parser"""
    subdomain_parser = subparsers.add_parser('subdomain-enum', help='Subdomain enumeration')
    subdomain_parser.add_argument('domain', help='Target domain')
    subdomain_parser.add_argument('-m', '--methods', nargs='+', 
                                 choices=['all', 'dns', 'ct', 'search', 'zone', 'reverse'],
                                 default=['all'], help='Enumeration methods')
    subdomain_parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    subdomain_parser.add_argument('-t', '--threads', type=int, default=50,
                                 help='Number of threads (default: 50)')
    subdomain_parser.add_argument('-o', '--output', choices=['json', 'txt', 'html'], 
                                 default='json', help='Output format (default: json)')
    subdomain_parser.add_argument('--no-save', action='store_true',
                                 help='Don\'t save results to file')

def setup_amass_parser(subparsers):
    """Setup amass scan command parser"""
    amass_parser = subparsers.add_parser('amass-scan', help='Amass subdomain enumeration')
    amass_parser.add_argument('domain', help='Target domain')
    amass_parser.add_argument('-t', '--type', choices=['passive', 'active', 'brute', 'intel', 'comprehensive'],
                            default='comprehensive', help='Scan type (default: comprehensive)')
    amass_parser.add_argument('-o', '--output', choices=['json', 'txt', 'html'], 
                            default='json', help='Output format (default: json)')
    amass_parser.add_argument('--no-save', action='store_true',
                            help='Don\'t save results to file')

def setup_webcrawl_parser(subparsers):
    """Setup web crawl command parser"""
    webcrawl_parser = subparsers.add_parser('web-crawl', help='Web application crawling')
    webcrawl_parser.add_argument('url', help='Target URL')
    webcrawl_parser.add_argument('-d', '--max-depth', type=int, default=3,
                                help='Maximum crawl depth (default: 3)')
    webcrawl_parser.add_argument('-p', '--max-pages', type=int, default=500,
                                help='Maximum pages to crawl (default: 500)')
    webcrawl_parser.add_argument('-t', '--threads', type=int, default=10,
                                help='Number of threads (default: 10)')
    webcrawl_parser.add_argument('--analyze-js', action='store_true',
                                help='Analyze JavaScript files for endpoints')
    webcrawl_parser.add_argument('-o', '--output', choices=['json', 'txt', 'html'], 
                                default='json', help='Output format (default: json)')
    webcrawl_parser.add_argument('--no-save', action='store_true',
                                help='Don\'t save results to file')

def setup_vulnscan_parser(subparsers):
    """Setup vulnerability scan command parser"""
    vulnscan_parser = subparsers.add_parser('vuln-scan', help='Vulnerability scanning')
    vulnscan_parser.add_argument('url', help='Target URL')
    vulnscan_parser.add_argument('-e', '--endpoints', nargs='+', help='Specific endpoints to test')
    vulnscan_parser.add_argument('-p', '--parameters', nargs='+', help='Parameters to test')
    vulnscan_parser.add_argument('-o', '--output', choices=['json', 'txt', 'html'], 
                                default='json', help='Output format (default: json)')
    vulnscan_parser.add_argument('--no-save', action='store_true',
                                help='Don\'t save results to file')

def setup_osint_parser(subparsers):
    """Setup OSINT collection command parser"""
    osint_parser = subparsers.add_parser('osint', help='OSINT data collection')
    osint_parser.add_argument('target', help='Target domain or identifier')
    osint_parser.add_argument('--shodan-key', help='Shodan API key')
    osint_parser.add_argument('--github-token', help='GitHub API token')
    osint_parser.add_argument('-o', '--output', choices=['json', 'txt', 'html'], 
                            default='json', help='Output format (default: json)')
    osint_parser.add_argument('--no-save', action='store_true',
                            help='Don\'t save results to file')

def setup_full_recon_parser(subparsers):
    """Setup full reconnaissance command parser"""
    recon_parser = subparsers.add_parser('full-recon', help='Complete reconnaissance pipeline')
    recon_parser.add_argument('target', help='Target domain')
    recon_parser.add_argument('--config', help='Configuration file (JSON)')
    recon_parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    recon_parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    recon_parser.add_argument('--max-subdomains', type=int, default=100, help='Maximum subdomains to scan')
    recon_parser.add_argument('--max-crawl-pages', type=int, default=200, help='Maximum pages to crawl')
    recon_parser.add_argument('--no-subdomain', action='store_true', help='Skip subdomain enumeration')
    recon_parser.add_argument('--no-port-scan', action='store_true', help='Skip port scanning')
    recon_parser.add_argument('--no-web-crawl', action='store_true', help='Skip web crawling')
    recon_parser.add_argument('--no-vuln-scan', action='store_true', help='Skip vulnerability scanning')
    recon_parser.add_argument('--no-osint', action='store_true', help='Skip OSINT collection')
    recon_parser.add_argument('-o', '--output', choices=['json', 'html'], 
                            default='json', help='Output format (default: json)')

def setup_hashcat_parser(subparsers):
    """Setup Hashcat attack command parser"""
    hashcat_parser = subparsers.add_parser('hashcat-attack', help='Password cracking with Hashcat')
    hashcat_parser.add_argument('hash_file', help='Path to the file containing hashes')
    hashcat_parser.add_argument('-m', '--hash-type', type=int, required=True, help='Hashcat hash type code (e.g., 0 for MD5)')
    hashcat_parser.add_argument('-w', '--wordlist', required=True, help='Path to the wordlist file')
    hashcat_parser.add_argument('-o', '--output', default='cracked.txt', help='Output file for cracked hashes (default: cracked.txt)')

def setup_airgeddon_parser(subparsers):
    """Setup Airgeddon command parser"""
    subparsers.add_parser('wifi-hack', help='Launch Airgeddon for WiFi hacking (interactive)')

def setup_social_scan_parser(subparsers):
    """Setup Sherlock social media scan command parser"""
    social_parser = subparsers.add_parser('social-scan', help='Find social media accounts by username')
    social_parser.add_argument('username', help='The username to search for')
    social_parser.add_argument('-o', '--output', help='Output file to save the report (e.g., report.txt)')
    social_parser.add_argument('--timeout', type=int, default=60, help='Timeout for each request (default: 60s)')

def setup_gobuster_parser(subparsers):
    """Setup GoBuster scan command parser"""
    gobuster_parser = subparsers.add_parser('gobuster-scan', help='Directory/file & DNS busting with GoBuster')
    gobuster_parser.add_argument('mode', choices=['dir', 'dns'], help="GoBuster mode ('dir' or 'dns')")
    gobuster_parser.add_argument('target', help='The target URL (for dir) or domain (for dns)')
    gobuster_parser.add_argument('-w', '--wordlist', required=True, help='Path to the wordlist file')
    gobuster_parser.add_argument('-o', '--output', help='Output file to save results')
    gobuster_parser.add_argument('-x', '--extensions', help='File extensions to search for (e.g., php,html)')

def setup_sqlmap_parser(subparsers):
    """Setup SQLMap scan command parser"""
    sqlmap_parser = subparsers.add_parser('sql-injection', help='Automated SQL injection testing with SQLMap')
    sqlmap_parser.add_argument('target', help='The target URL with parameters (e.g., "http://test.com/search?id=1")')
    sqlmap_parser.add_argument('--level', type=int, default=1, choices=range(1, 6), help='Level of tests to perform (1-5, default: 1)')
    sqlmap_parser.add_argument('--risk', type=int, default=1, choices=range(1, 4), help='Risk of tests to perform (1-3, default: 1)')
    sqlmap_parser.add_argument('--output-dir', help='Directory to save SQLMap session files')

def handle_port_scan(args):
    """Handle port scan command"""
    print(f"{Fore.GREEN}[+] Starting port scan on {args.target}{Style.RESET_ALL}")
    
    # Validate target
    if not (validate_ip(args.target) or validate_domain(args.target)):
        print(f"{Fore.RED}[!] Error: Invalid target '{args.target}'{Style.RESET_ALL}")
        return False
    
    # Determine scan type
    if args.common_ports:
        print(f"{Fore.BLUE}[*] Scanning common ports with {args.threads} threads{Style.RESET_ALL}")
        scan_type = "common_ports"
        port_range = None
    elif args.ports:
        print(f"{Fore.BLUE}[*] Scanning ports {args.ports} with {args.threads} threads{Style.RESET_ALL}")
        scan_type = "port_range"
        port_range = args.ports
    else:
        print(f"{Fore.BLUE}[*] No port range specified, using common ports{Style.RESET_ALL}")
        scan_type = "common_ports"
        port_range = None
    
    # Run scan
    save_format = None if args.no_save else args.output
    
    if scan_type == "common_ports":
        results = run_port_scan(args.target, common_ports=True, threads=args.threads, 
                              timeout=args.timeout, save_format=save_format)
    else:
        results = run_port_scan(args.target, port_range=port_range, threads=args.threads,
                              timeout=args.timeout, save_format=save_format)
    
    if results:
        print(f"\n{Fore.GREEN}[+] Scan completed successfully!{Style.RESET_ALL}")
        print(f"    Open ports found: {results['total_open']}")
        print(f"    Total ports scanned: {results['total_scanned']}")
        
        if results['open_ports']:
            print(f"\n{Fore.CYAN}Open Ports:{Style.RESET_ALL}")
            for port_info in results['open_ports']:
                print(f"    {port_info['port']}/tcp - {port_info['service']}")
        
        return True
    else:
        print(f"{Fore.RED}[!] Scan failed{Style.RESET_ALL}")
        return False

def handle_dir_scan(args):
    """Handle directory scan command"""
    print(f"{Fore.GREEN}[+] Starting directory enumeration on {args.target}{Style.RESET_ALL}")
    
    # Validate target URL
    if not validate_url(args.target):
        print(f"{Fore.RED}[!] Error: Invalid URL '{args.target}'{Style.RESET_ALL}")
        return False
    
    # Parse extensions
    extensions = None
    if args.extensions:
        extensions = ['.' + ext.strip() for ext in args.extensions.split(',')]
        extensions.append('')  # Also test without extension
        extensions.append('/')  # Also test as directory
        print(f"{Fore.BLUE}[*] Testing extensions: {', '.join(extensions)}{Style.RESET_ALL}")
    
    # Set wordlist
    wordlist_path = args.wordlist
    if wordlist_path:
        if not os.path.exists(wordlist_path):
            print(f"{Fore.RED}[!] Error: Wordlist file not found: {wordlist_path}{Style.RESET_ALL}")
            return False
        print(f"{Fore.BLUE}[*] Using wordlist: {wordlist_path}{Style.RESET_ALL}")
    else:
        # Try to use default wordlist
        default_wordlist = "wordlists/common_dirs.txt"
        if os.path.exists(default_wordlist):
            wordlist_path = default_wordlist
            print(f"{Fore.BLUE}[*] Using default wordlist: {default_wordlist}{Style.RESET_ALL}")
        else:
            print(f"{Fore.BLUE}[*] Using built-in wordlist{Style.RESET_ALL}")
    
    print(f"{Fore.BLUE}[*] Using {args.threads} threads with {args.timeout}s timeout{Style.RESET_ALL}")
    
    # Run scan
    save_format = None if args.no_save else args.output
    results = run_directory_scan(args.target, wordlist_path=wordlist_path, 
                               threads=args.threads, timeout=args.timeout,
                               extensions=extensions, save_format=save_format)
    
    if results:
        print(f"\n{Fore.GREEN}[+] Directory scan completed successfully!{Style.RESET_ALL}")
        print(f"    Directories found: {results['total_directories']}")
        print(f"    Files found: {results['total_files']}")
        print(f"    Total items found: {results['total_found']}")
        
        # Show some results
        if results['directories']:
            print(f"\n{Fore.CYAN}Sample Directories:{Style.RESET_ALL}")
            for dir_info in results['directories'][:5]:
                status_color = Fore.GREEN if dir_info['status_code'] == 200 else Fore.YELLOW
                print(f"    {status_color}{dir_info['path']} [{dir_info['status_code']}]{Style.RESET_ALL}")
        
        if results['files']:
            print(f"\n{Fore.CYAN}Sample Files:{Style.RESET_ALL}")
            for file_info in results['files'][:5]:
                status_color = Fore.GREEN if file_info['status_code'] == 200 else Fore.YELLOW
                print(f"    {status_color}{file_info['path']} [{file_info['status_code']}]{Style.RESET_ALL}")
        
        return True
    else:
        print(f"{Fore.RED}[!] Directory scan failed{Style.RESET_ALL}")
        return False

def handle_analyze(args):
    """Handle data analysis command"""
    print(f"{Fore.GREEN}[+] Starting data analysis{Style.RESET_ALL}")
    
    # Validate input files
    for file_path in args.input:
        if not os.path.exists(file_path):
            print(f"{Fore.RED}[!] Error: File not found: {file_path}{Style.RESET_ALL}")
            return False
    
    print(f"{Fore.BLUE}[*] Analyzing {len(args.input)} file(s){Style.RESET_ALL}")
    for file_path in args.input:
        print(f"    - {file_path}")
    
    # Run analysis
    save_format = None if args.no_save else args.output
    results = run_analysis(args.input, output_format=save_format)
    
    if results:
        print(f"\n{Fore.GREEN}[+] Analysis completed successfully!{Style.RESET_ALL}")
        
        # Show summary based on analysis type
        if results.get('report_type') == 'combined_analysis':
            print(f"    Targets analyzed: {len(results['targets'])}")
            print(f"    Port scans: {len(results['port_scans'])}")
            print(f"    Directory scans: {len(results['directory_scans'])}")
        else:
            scan_type = results.get('scan_type', 'unknown')
            target = results.get('target', 'unknown')
            print(f"    Analysis type: {scan_type}")
            print(f"    Target: {target}")
        
        # Show recommendations
        recommendations = results.get('recommendations', []) or results.get('overall_recommendations', [])
        if recommendations:
            print(f"\n{Fore.YELLOW}Key Recommendations:{Style.RESET_ALL}")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"    {i}. {rec}")
        
        return True
    else:
        print(f"{Fore.RED}[!] Analysis failed{Style.RESET_ALL}")
        return False

def handle_nmap_scan(args):
    """Handle nmap scan command"""
    print(f"{Fore.GREEN}[+] Starting Nmap scan on {args.target}{Style.RESET_ALL}")
    
    # Validate target
    if not (validate_ip(args.target) or validate_domain(args.target)):
        print(f"{Fore.RED}[!] Error: Invalid target '{args.target}'{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.BLUE}[*] Running {args.type} scan{Style.RESET_ALL}")
    
    # Run scan
    save_format = None if args.no_save else args.output
    results = run_nmap_scan(args.target, scan_type=args.type, ports=args.ports, save_format=save_format)
    
    if results:
        print(f"\n{Fore.GREEN}[+] Nmap scan completed successfully!{Style.RESET_ALL}")
        
        if 'hosts' in results:
            for host in results['hosts']:
                print(f"Host: {host['addresses'][0]['addr']} - {host['status']['state']}")
                for port in host['ports']:
                    if port['state']['state'] == 'open':
                        service = port['service'].get('name', 'unknown')
                        version = port['service'].get('version', '')
                        print(f"  Port {port['portid']}/{port['protocol']}: {service} {version}")
        
        return True
    else:
        print(f"{Fore.RED}[!] Nmap scan failed{Style.RESET_ALL}")
        return False

def handle_subdomain_enum(args):
    """Handle subdomain enumeration command"""
    print(f"{Fore.GREEN}[+] Starting subdomain enumeration for {args.domain}{Style.RESET_ALL}")
    
    # Validate domain
    if not validate_domain(args.domain):
        print(f"{Fore.RED}[!] Error: Invalid domain '{args.domain}'{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.BLUE}[*] Using methods: {', '.join(args.methods)}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Using {args.threads} threads{Style.RESET_ALL}")
    
    # Run enumeration
    save_format = None if args.no_save else args.output
    results = run_subdomain_enumeration(args.domain, methods=args.methods, wordlist=args.wordlist, 
                                      threads=args.threads, save_format=save_format)
    
    if results:
        print(f"\n{Fore.GREEN}[+] Subdomain enumeration completed successfully!{Style.RESET_ALL}")
        
        if 'summary' in results:
            total = results['summary'].get('total_subdomains', 0)
            print(f"    Total subdomains found: {total}")
            
            subdomains = results['summary'].get('unique_subdomains', [])
            if subdomains:
                print(f"\n{Fore.CYAN}Sample Subdomains:{Style.RESET_ALL}")
                for subdomain in subdomains[:10]:
                    print(f"    {subdomain}")
                
                if len(subdomains) > 10:
                    print(f"    ... and {len(subdomains) - 10} more")
        
        return True
    else:
        print(f"{Fore.RED}[!] Subdomain enumeration failed{Style.RESET_ALL}")
        return False

def handle_amass_scan(args):
    """Handle amass scan command"""
    print(f"{Fore.GREEN}[+] Starting Amass scan for {args.domain}{Style.RESET_ALL}")
    
    # Validate domain
    if not validate_domain(args.domain):
        print(f"{Fore.RED}[!] Error: Invalid domain '{args.domain}'{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.BLUE}[*] Running {args.type} scan{Style.RESET_ALL}")
    
    # Run scan
    save_format = None if args.no_save else args.output
    results = run_amass_scan(args.domain, scan_type=args.type, save_format=save_format)
    
    if results:
        print(f"\n{Fore.GREEN}[+] Amass scan completed successfully!{Style.RESET_ALL}")
        
        if 'subdomains' in results:
            print(f"    Total subdomains found: {results['total_subdomains']}")
            
            for subdomain_info in results['subdomains'][:10]:
                print(f"    {subdomain_info['subdomain']} (source: {subdomain_info['source']})")
        elif 'summary' in results:
            print(f"    Total unique subdomains: {results['summary']['total_unique_subdomains']}")
            
            for subdomain in results['summary']['unique_subdomains'][:10]:
                print(f"    {subdomain}")
        
        return True
    else:
        print(f"{Fore.RED}[!] Amass scan failed{Style.RESET_ALL}")
        return False

def handle_web_crawl(args):
    """Handle web crawl command"""
    print(f"{Fore.GREEN}[+] Starting web crawl of {args.url}{Style.RESET_ALL}")
    
    # Validate URL
    if not validate_url(args.url):
        print(f"{Fore.RED}[!] Error: Invalid URL '{args.url}'{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.BLUE}[*] Max depth: {args.max_depth}, Max pages: {args.max_pages}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Using {args.threads} threads{Style.RESET_ALL}")
    
    # Run crawl
    save_format = None if args.no_save else args.output
    results = run_web_crawl(args.url, max_depth=args.max_depth, max_pages=args.max_pages,
                          threads=args.threads, analyze_js=args.analyze_js, save_format=save_format)
    
    if results:
        print(f"\n{Fore.GREEN}[+] Web crawl completed successfully!{Style.RESET_ALL}")
        
        if 'summary' in results:
            summary = results['summary']
            print(f"    Pages visited: {summary['pages_visited']}")
            print(f"    Endpoints found: {summary['endpoints_found']}")
            print(f"    Forms found: {summary['forms_found']}")
            print(f"    Interesting files: {summary['interesting_files']}")
            
            if results.get('endpoints'):
                print(f"\n{Fore.CYAN}Sample Endpoints:{Style.RESET_ALL}")
                for endpoint in list(results['endpoints'])[:10]:
                    print(f"    {endpoint}")
        
        return True
    else:
        print(f"{Fore.RED}[!] Web crawl failed{Style.RESET_ALL}")
        return False

def handle_vuln_scan(args):
    """Handle vulnerability scan command"""
    print(f"{Fore.GREEN}[+] Starting vulnerability scan on {args.url}{Style.RESET_ALL}")
    
    # Validate URL
    if not validate_url(args.url):
        print(f"{Fore.RED}[!] Error: Invalid URL '{args.url}'{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.BLUE}[*] Testing for common vulnerabilities{Style.RESET_ALL}")
    
    # Run scan
    save_format = None if args.no_save else args.output
    results = run_vulnerability_scan(args.url, endpoints=args.endpoints, 
                                   parameters=args.parameters, save_format=save_format)
    
    if results:
        print(f"\n{Fore.GREEN}[+] Vulnerability scan completed successfully!{Style.RESET_ALL}")
        
        if 'summary' in results:
            summary = results['summary']
            print(f"    Total vulnerabilities: {summary['total_vulnerabilities']}")
            print(f"    Critical: {summary['critical']}")
            print(f"    High: {summary['high']}")
            print(f"    Medium: {summary['medium']}")
            print(f"    Low: {summary['low']}")
            
            if results.get('vulnerabilities'):
                print(f"\n{Fore.YELLOW}Found Vulnerabilities:{Style.RESET_ALL}")
                for vuln in results['vulnerabilities'][:5]:
                    severity_color = Fore.RED if vuln['severity'] in ['Critical', 'High'] else Fore.YELLOW
                    print(f"    {severity_color}[{vuln['severity']}] {vuln['type']}: {vuln['description']}{Style.RESET_ALL}")
        
        return True
    else:
        print(f"{Fore.RED}[!] Vulnerability scan failed{Style.RESET_ALL}")
        return False

def handle_osint(args):
    """Handle OSINT collection command"""
    print(f"{Fore.GREEN}[+] Starting OSINT collection for {args.target}{Style.RESET_ALL}")
    
    print(f"{Fore.BLUE}[*] Collecting intelligence from multiple sources{Style.RESET_ALL}")
    
    # Prepare API keys
    api_keys = {}
    if args.shodan_key:
        api_keys['shodan'] = args.shodan_key
    if args.github_token:
        api_keys['github'] = args.github_token
    
    # Run collection
    save_format = None if args.no_save else args.output
    results = run_osint_collection(args.target, api_keys=api_keys, save_format=save_format)
    
    if results:
        print(f"\n{Fore.GREEN}[+] OSINT collection completed successfully!{Style.RESET_ALL}")
        
        if 'summary' in results:
            summary = results['summary']
            print(f"    Sources attempted: {summary['sources_attempted']}")
            print(f"    Sources successful: {summary['sources_successful']}")
            
            for source_name, source_data in results['sources'].items():
                status = source_data['status']
                status_color = Fore.GREEN if status == 'success' else Fore.YELLOW if status == 'skipped' else Fore.RED
                print(f"    {source_name}: {status_color}{status}{Style.RESET_ALL}")
        
        return True
    else:
        print(f"{Fore.RED}[!] OSINT collection failed{Style.RESET_ALL}")
        return False

def handle_full_recon(args):
    """Handle full reconnaissance command"""
    print(f"{Fore.GREEN}[+] Starting full reconnaissance pipeline for {args.target}{Style.RESET_ALL}")
    
    # Validate domain
    if not validate_domain(args.target):
        print(f"{Fore.RED}[!] Error: Invalid domain '{args.target}'{Style.RESET_ALL}")
        return False
    
    # Import and run full recon
    try:
        import sys
        sys.path.append('scripts')
        from scripts.full_recon import FullReconPipeline
        
        # Build config
        config = {
            'threads': args.threads,
            'timeout': args.timeout,
            'max_subdomains': args.max_subdomains,
            'max_crawl_pages': args.max_crawl_pages,
            'subdomain_enumeration': not args.no_subdomain,
            'port_scanning': not args.no_port_scan,
            'web_crawling': not args.no_web_crawl,
            'vulnerability_scanning': not args.no_vuln_scan,
            'osint_collection': not args.no_osint
        }
        
        # Load config file if provided
        if args.config:
            import json
            with open(args.config, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
        
        # Run pipeline
        pipeline = FullReconPipeline(args.target, config)
        results = pipeline.run_full_pipeline()
        
        if results:
            # Save results
            pipeline.save_results(args.output)
            
            # Print summary
            if 'summary' in results:
                summary = results['summary']
                print(f"\n{Fore.GREEN}[+] Full reconnaissance completed!{Style.RESET_ALL}")
                print(f"    Phases completed: {len(summary['phases_completed'])}")
                print(f"    Subdomains found: {summary['total_subdomains']}")
                print(f"    Open ports: {summary['total_open_ports']}")
                print(f"    Web targets: {summary['total_web_targets']}")
                print(f"    Vulnerabilities: {summary['total_vulnerabilities']}")
                
                if summary['key_findings']:
                    print(f"\n{Fore.CYAN}Key Findings:{Style.RESET_ALL}")
                    for finding in summary['key_findings']:
                        print(f"    • {finding}")
        
        return True
        
    except ImportError as e:
        print(f"{Fore.RED}[!] Error importing full recon module: {str(e)}{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.RED}[!] Error in full reconnaissance: {str(e)}{Style.RESET_ALL}")
        return False

def handle_hashcat_attack(args):
    """Handle Hashcat attack command"""
    print(f"{Fore.GREEN}[+] Starting Hashcat attack on {args.hash_file}{Style.RESET_ALL}")
    
    # Run attack
    results = run_hashcat_attack(
        hash_file=args.hash_file,
        hash_type=args.hash_type,
        wordlist=args.wordlist,
        output_file=args.output
    )
    
    if results and results['status'] == 'success':
        return True
    else:
        print(f"{Fore.RED}[!] Hashcat attack failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def handle_airgeddon(args):
    """Handle Airgeddon command"""
    print(f"{Fore.GREEN}[+] Launching Airgeddon...{Style.RESET_ALL}")
    
    # Run airgeddon
    results = run_airgeddon()
    
    if results and results['status'] == 'success':
        return True
    else:
        print(f"{Fore.RED}[!] Airgeddon session failed or was interrupted.{Style.RESET_ALL}")
        return False

def handle_social_scan(args):
    """Handle Sherlock social media scan command"""
    print(f"{Fore.GREEN}[+] Starting social media scan for username: {args.username}{Style.RESET_ALL}")
    
    # Run scan
    results = run_sherlock_scan(
        username=args.username,
        output_file=args.output,
        timeout=args.timeout
    )
    
    if results and results['status'] == 'success':
        print(f"\n{Fore.GREEN}[+] Found {results['found_count']} accounts.{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}[!] Social media scan failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def handle_gobuster_scan(args):
    """Handle GoBuster scan command"""
    print(f"{Fore.GREEN}[+] Starting GoBuster {args.mode} scan on {args.target}{Style.RESET_ALL}")
    
    extra_args = []
    if args.extensions:
        extra_args.extend(['-x', args.extensions])

    results = run_gobuster_scan(
        mode=args.mode,
        target=args.target,
        wordlist=args.wordlist,
        output_file=args.output,
        extra_args=extra_args
    )
    
    if results and results['status'] == 'success':
        return True
    else:
        print(f"{Fore.RED}[!] GoBuster scan failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def handle_sqlmap_scan(args):
    """Handle SQLMap scan command"""
    print(f"{Fore.GREEN}[+] Starting SQLMap scan on {args.target}{Style.RESET_ALL}")
    
    if not ('?' in args.target and '=' in args.target):
        print(f"{Fore.YELLOW}[!] Warning: Target URL does not seem to have parameters. SQLMap may not find injection points.{Style.RESET_ALL}")

    results = run_sqlmap_scan(
        target_url=args.target,
        output_dir=args.output_dir,
        level=args.level,
        risk=args.risk
    )
    
    if results and results['status'] == 'success':
        if results.get('vulnerable'):
            print(f"{Fore.YELLOW}[+] SQLMap found potential vulnerabilities! Check logs for details.{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}[!] SQLMap scan failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def setup_email_finder_parser(subparsers):
    """Setup Email User Finder command parser"""
    email_parser = subparsers.add_parser('email-find', help='Find email users for a domain')
    email_parser.add_argument('domain', help='The domain to search for email users.')

def setup_mobile_osint_parser(subparsers):
    """Setup Mobile Phone OSINT command parser"""
    mobile_parser = subparsers.add_parser('mobile-osint', help='Gather OSINT data for a phone number')
    mobile_parser.add_argument('phone_number', help='The phone number to investigate.')

def setup_modem_scanner_parser(subparsers):
    """Setup Modem Vulnerability Scanner command parser"""
    modem_parser = subparsers.add_parser('modem-scan', help='Scan a network modem for vulnerabilities')
    modem_parser.add_argument('ip_address', help='The IP address of the modem to scan.')

def setup_payload_gen_parser(subparsers):
    """Setup Payload Generation command parser"""
    payload_parser = subparsers.add_parser('payload-gen', help='Generate a payload')
    payload_parser.add_argument('payload_type', help='The type of payload to generate (e.g., reverse_shell).')
    payload_parser.add_argument('--lhost', help='The listening host for the payload.')
    payload_parser.add_argument('--lport', help='The listening port for the payload.')

def setup_metasploit_parser(subparsers):
    """Setup Metasploit Automation command parser"""
    msf_parser = subparsers.add_parser('metasploit-run', help='Run a Metasploit module')
    msf_parser.add_argument('module', help='The Metasploit module to run.')
    msf_parser.add_argument('--rhosts', help='The target host(s).')
    msf_parser.add_argument('--lhost', help='The listening host.')
    msf_parser.add_argument('--lport', help='The listening port.')

def setup_osintgram_parser(subparsers):
    """Setup OSINTGram command parser"""
    osintgram_parser = subparsers.add_parser('osintgram', help='Gather Instagram OSINT data using OSINTGram')
    osintgram_parser.add_argument('username', help='The Instagram username to investigate.')
    osintgram_parser.add_argument('--output-dir', help='Directory to save results.')
    osintgram_parser.add_argument('--session-file', help='Session file for authentication.')

def setup_instagram_scraper_parser(subparsers):
    """Setup Instagram Scraper command parser"""
    instagram_parser = subparsers.add_parser('instagram-scan', help='Scrape public Instagram profile information')
    instagram_parser.add_argument('username', help='The Instagram username to scrape.')
    instagram_parser.add_argument('-o', '--output', help='Output file to save results (JSON format).')

def setup_twitter_scraper_parser(subparsers):
    """Setup Twitter Scraper command parser"""
    twitter_parser = subparsers.add_parser('twitter-scan', help='Scrape public Twitter profile information')
    twitter_parser.add_argument('username', help='The Twitter username to scrape.')
    twitter_parser.add_argument('-o', '--output', help='Output file to save results (JSON format).')
    twitter_parser.add_argument('--hashtag', help='Search for posts with this hashtag.')

def setup_linkedin_searcher_parser(subparsers):
    """Setup LinkedIn Searcher command parser"""
    linkedin_parser = subparsers.add_parser('linkedin-search', help='Search LinkedIn profiles and companies')
    linkedin_parser.add_argument('query', help='The search query (name, company, etc.).')
    linkedin_parser.add_argument('-o', '--output', help='Output file to save results (JSON format).')
    linkedin_parser.add_argument('--company', action='store_true', help='Search for companies instead of people.')

def setup_facebook_searcher_parser(subparsers):
    """Setup Facebook Searcher command parser"""
    facebook_parser = subparsers.add_parser('facebook-search', help='Search Facebook profiles and pages')
    facebook_parser.add_argument('query', help='The search query (name, page, etc.).')
    facebook_parser.add_argument('-o', '--output', help='Output file to save results (JSON format).')

def setup_email_verifier_parser(subparsers):
    """Setup Email Verifier command parser"""
    email_parser = subparsers.add_parser('email-verify', help='Verify email addresses and check their validity')
    email_parser.add_argument('email', help='The email address to verify.')
    email_parser.add_argument('--no-existence-check', action='store_true', help='Skip existence check on mail server.')
    email_parser.add_argument('-o', '--output', help='Output file to save results (JSON format).')

def setup_phone_validator_parser(subparsers):
    """Setup Phone Validator command parser"""
    phone_parser = subparsers.add_parser('phone-validate', help='Validate and gather information about phone numbers')
    phone_parser.add_argument('phone_number', help='The phone number to validate.')
    phone_parser.add_argument('--region', help='Region code for parsing (e.g., US, GB).')
    phone_parser.add_argument('-o', '--output', help='Output file to save results (JSON format).')

def setup_domain_reputation_parser(subparsers):
    """Setup Domain Reputation command parser"""
    domain_parser = subparsers.add_parser('domain-reputation', help='Check domain/IP reputation using various services')
    domain_parser.add_argument('domain_or_ip', help='The domain or IP address to check.')
    domain_parser.add_argument('--vt-key', help='VirusTotal API key.')
    domain_parser.add_argument('--abuse-key', help='AbuseIPDB API key.')
    domain_parser.add_argument('-o', '--output', help='Output file to save results (JSON format).')

def setup_ip_geolocation_parser(subparsers):
    """Setup IP Geolocation command parser"""
    geo_parser = subparsers.add_parser('ip-geolocate', help='Get geolocation information for IP addresses')
    geo_parser.add_argument('ip_address', help='The IP address to geolocate.')
    geo_parser.add_argument('--api-key', help='API key for geolocation service.')
    geo_parser.add_argument('-o', '--output', help='Output file to save results (JSON format).')
    geo_parser.add_argument('--hostname', action='store_true', help='Treat input as hostname instead of IP.')

def handle_email_find(args):
    """Handle Email User Finder command"""
    print(f"{Fore.GREEN}[+] Finding email users for {args.domain}{Style.RESET_ALL}")
    users = find_email_users(args.domain)
    print(users)
    return True

def handle_mobile_osint(args):
    """Handle Mobile Phone OSINT command"""
    print(f"{Fore.GREEN}[+] Gathering OSINT for {args.phone_number}{Style.RESET_ALL}")
    info = get_phone_info(args.phone_number)
    print(info)
    return True

def handle_modem_scan(args):
    """Handle Modem Vulnerability Scanner command"""
    print(f"{Fore.GREEN}[+] Scanning modem at {args.ip_address}{Style.RESET_ALL}")
    results = scan_modem(args.ip_address)
    print(results)
    return True

def handle_payload_gen(args):
    """Handle Payload Generation command"""
    print(f"{Fore.GREEN}[+] Generating payload: {args.payload_type}{Style.RESET_ALL}")
    options = {"lhost": args.lhost, "lport": args.lport}
    payload = generate_payload(args.payload_type, options)
    print(payload)
    return True

def handle_metasploit_run(args):
    """Handle Metasploit Automation command"""
    print(f"{Fore.GREEN}[+] Running Metasploit module: {args.module}{Style.RESET_ALL}")
    options = {}
    if args.rhosts:
        options["RHOSTS"] = args.rhosts
    if args.lhost:
        options["LHOST"] = args.lhost
    if args.lport:
        options["LPORT"] = args.lport
    output = run_metasploit_module(args.module, options)
    print(output)
    return True

def handle_osintgram(args):
    """Handle OSINTGram command"""
    print(f"{Fore.GREEN}[+] Starting OSINTGram scan for Instagram user: {args.username}{Style.RESET_ALL}")
    
    results = run_osintgram(
        target_username=args.username,
        output_dir=args.output_dir,
        session_file=args.session_file
    )
    
    if results and results['status'] == 'success':
        print(f"\n{Fore.GREEN}[+] OSINTGram scan completed successfully!{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}[!] OSINTGram scan failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def handle_instagram_scan(args):
    """Handle Instagram Scraper command"""
    print(f"{Fore.GREEN}[+] Starting Instagram profile scan for: {args.username}{Style.RESET_ALL}")
    
    results = run_instagram_scan(
        username=args.username,
        output_file=args.output
    )
    
    if results and results['status'] == 'success':
        print(f"\n{Fore.GREEN}[+] Instagram scan completed successfully!{Style.RESET_ALL}")
        # Print some key information
        if 'name' in results:
            print(f"Name: {results['name']}")
        if 'followers' in results:
            print(f"Followers: {results['followers']}")
        if 'following' in results:
            print(f"Following: {results['following']}")
        if 'posts' in results:
            print(f"Posts: {results['posts']}")
        return True
    else:
        print(f"{Fore.RED}[!] Instagram scan failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def handle_twitter_scan(args):
    """Handle Twitter Scraper command"""
    print(f"{Fore.GREEN}[+] Starting Twitter profile scan for: {args.username}{Style.RESET_ALL}")
    
    results = run_twitter_scan(
        username=args.username,
        output_file=args.output
    )
    
    if results and results['status'] == 'success':
        print(f"\n{Fore.GREEN}[+] Twitter scan completed successfully!{Style.RESET_ALL}")
        # Print some key information
        if 'name' in results:
            print(f"Name: {results['name']}")
        if 'followers_count' in results:
            print(f"Followers: {results['followers_count']}")
        if 'following_count' in results:
            print(f"Following: {results['following_count']}")
        if 'statuses_count' in results:
            print(f"Tweets: {results['statuses_count']}")
        return True
    else:
        print(f"{Fore.RED}[!] Twitter scan failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def handle_linkedin_search(args):
    """Handle LinkedIn Searcher command"""
    print(f"{Fore.GREEN}[+] Starting LinkedIn search for: {args.query}{Style.RESET_ALL}")
    
    if args.company:
        results = get_linkedin_company_info(args.query)
    else:
        results = run_linkedin_search(
            query=args.query,
            output_file=args.output
        )
    
    if results and results['status'] == 'success':
        print(f"\n{Fore.GREEN}[+] LinkedIn search completed successfully!{Style.RESET_ALL}")
        print(f"Found {results.get('total_profiles', results.get('total_companies', 0))} results")
        return True
    else:
        print(f"{Fore.RED}[!] LinkedIn search failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def handle_facebook_search(args):
    """Handle Facebook Searcher command"""
    print(f"{Fore.GREEN}[+] Starting Facebook search for: {args.query}{Style.RESET_ALL}")
    
    results = run_facebook_search(
        query=args.query,
        output_file=args.output
    )
    
    if results and results['status'] == 'success':
        print(f"\n{Fore.GREEN}[+] Facebook search completed successfully!{Style.RESET_ALL}")
        print(f"Found {results['total_profiles']} profiles")
        return True
    else:
        print(f"{Fore.RED}[!] Facebook search failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def handle_email_verify(args):
    """Handle Email Verifier command"""
    print(f"{Fore.GREEN}[+] Starting email verification for: {args.email}{Style.RESET_ALL}")
    
    results = run_email_verification(
        email=args.email,
        check_existence=not args.no_existence_check
    )
    
    if results and results['status'] in ['valid', 'valid_format']:
        print(f"\n{Fore.GREEN}[+] Email verification completed successfully!{Style.RESET_ALL}")
        print(f"Status: {results['status']}")
        print(f"Message: {results['message']}")
        return True
    else:
        print(f"{Fore.RED}[!] Email verification failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def handle_phone_validate(args):
    """Handle Phone Validator command"""
    print(f"{Fore.GREEN}[+] Starting phone validation for: {args.phone_number}{Style.RESET_ALL}")
    
    results = validate_phone_number(
        phone_number=args.phone_number,
        region=args.region
    )
    
    if results and results['status'] == 'valid':
        print(f"\n{Fore.GREEN}[+] Phone validation completed successfully!{Style.RESET_ALL}")
        print(f"Country: {results['country']}")
        print(f"Carrier: {results['carrier']}")
        print(f"Number Type: {results['number_type']}")
        return True
    else:
        print(f"{Fore.RED}[!] Phone validation failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def handle_domain_reputation(args):
    """Handle Domain Reputation command"""
    print(f"{Fore.GREEN}[+] Starting domain reputation check for: {args.domain_or_ip}{Style.RESET_ALL}")
    
    results = run_domain_reputation_check(
        domain_or_ip=args.domain_or_ip,
        virustotal_api_key=args.vt_key,
        abuseipdb_api_key=args.abuse_key
    )
    
    if results:
        print(f"\n{Fore.GREEN}[+] Domain reputation check completed successfully!{Style.RESET_ALL}")
        risk_level = results['risk_assessment']['risk_level']
        print(f"Overall Risk Level: {risk_level}")
        
        # Print risk factors
        risk_factors = results['risk_assessment']['risk_factors']
        if risk_factors:
            print("Risk Factors:")
            for factor in risk_factors:
                print(f"  - {factor}")
        return True
    else:
        print(f"{Fore.RED}[!] Domain reputation check failed{Style.RESET_ALL}")
        return False

def handle_ip_geolocate(args):
    """Handle IP Geolocation command"""
    print(f"{Fore.GREEN}[+] Starting IP geolocation for: {args.ip_address}{Style.RESET_ALL}")
    
    if args.hostname:
        results = get_hostname_geolocation(args.ip_address)
    else:
        results = get_ip_geolocation(
            ip_address=args.ip_address,
            api_key=args.api_key
        )
    
    if results and results['status'] == 'success':
        print(f"\n{Fore.GREEN}[+] IP geolocation completed successfully!{Style.RESET_ALL}")
        geo_data = results['geolocation_data']
        print(f"Country: {geo_data.get('country', 'N/A')}")
        print(f"City: {geo_data.get('city', 'N/A')}")
        print(f"Coordinates: {geo_data.get('lat', 'N/A')}, {geo_data.get('lon', 'N/A')}")
        print(f"ISP: {geo_data.get('isp', 'N/A')}")
        return True
    else:
        print(f"{Fore.RED}[!] IP geolocation failed: {results.get('message', 'Unknown error')}{Style.RESET_ALL}")
        return False

def main():
    """Main function"""
    print_banner()
    
    # Create argument parser
    parser = argparse.ArgumentParser(
        description='Bug Bounty Reconnaissance Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scans
  %(prog)s port-scan 192.168.1.1 --common-ports
  %(prog)s dir-scan https://example.com -w wordlists/common_dirs.txt
  %(prog)s analyze output/port_scan_*.json -o html
  
  # Advanced reconnaissance
  %(prog)s nmap-scan example.com -t comprehensive
  %(prog)s subdomain-enum example.com -m all -t 100
  %(prog)s amass-scan example.com -t comprehensive
  %(prog)s web-crawl https://example.com -d 3 -p 200 --analyze-js
  %(prog)s vuln-scan https://example.com -e /login,/admin
  %(prog)s osint example.com --shodan-key YOUR_KEY --github-token YOUR_TOKEN
  
  # Password Cracking & WiFi Hacking
  %(prog)s hashcat-attack hashes.txt -m 0 -w wordlist.txt -o cracked.txt
  %(prog)s wifi-hack
  
  # Social Media Scanning
  %(prog)s social-scan johndoe -o social_report.txt
  
  # Directory and SQL Injection Scanning
  %(prog)s gobuster-scan dir -t https://example.com -w wordlists/common_dirs.txt
  %(prog)s sql-injection "http://test.com/search.php?id=1" --level 2 --risk 2
  
  # Social-Media and Exploitation Tools
  %(prog)s email-find example.com
  %(prog)s mobile-osint +11234567890
  %(prog)s modem-scan 192.168.1.1
  %(prog)s payload-gen reverse_shell --lhost 10.10.10.2 --lport 4444
  %(prog)s metasploit-run exploit/multi/handler --lhost 10.10.10.2 --lport 4444

  # Social Media OSINT Tools
  %(prog)s osintgram username
  %(prog)s instagram-scan username
  %(prog)s twitter-scan username
  %(prog)s linkedin-search "security researcher"
  %(prog)s facebook-search "company name"

  # Validation and Reputation Tools
  %(prog)s email-verify user@example.com
  %(prog)s phone-validate +11234567890
  %(prog)s domain-reputation example.com
  %(prog)s ip-geolocate 8.8.8.8

  # Full reconnaissance pipeline
  %(prog)s full-recon example.com --threads 100 --max-subdomains 200
        """
    )
    
    # Create subparsers
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup command parsers
    setup_port_scan_parser(subparsers)
    setup_dir_scan_parser(subparsers)
    setup_analyze_parser(subparsers)
    setup_nmap_parser(subparsers)
    setup_subdomain_parser(subparsers)
    setup_amass_parser(subparsers)
    setup_webcrawl_parser(subparsers)
    setup_vulnscan_parser(subparsers)
    setup_osint_parser(subparsers)
    setup_full_recon_parser(subparsers)
    setup_hashcat_parser(subparsers)
    setup_airgeddon_parser(subparsers)
    setup_social_scan_parser(subparsers)
    setup_gobuster_parser(subparsers)
    setup_sqlmap_parser(subparsers)
    setup_email_finder_parser(subparsers)
    setup_mobile_osint_parser(subparsers)
    setup_modem_scanner_parser(subparsers)
    setup_payload_gen_parser(subparsers)
    setup_metasploit_parser(subparsers)
    setup_osintgram_parser(subparsers)
    setup_instagram_scraper_parser(subparsers)
    setup_twitter_scraper_parser(subparsers)
    setup_linkedin_searcher_parser(subparsers)
    setup_facebook_searcher_parser(subparsers)
    setup_email_verifier_parser(subparsers)
    setup_phone_validator_parser(subparsers)
    setup_domain_reputation_parser(subparsers)
    setup_ip_geolocation_parser(subparsers)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Create output directory
    os.makedirs('output', exist_ok=True)
    
    # Handle commands
    try:
        if args.command == 'port-scan':
            success = handle_port_scan(args)
        elif args.command == 'dir-scan':
            success = handle_dir_scan(args)
        elif args.command == 'analyze':
            success = handle_analyze(args)
        elif args.command == 'nmap-scan':
            success = handle_nmap_scan(args)
        elif args.command == 'subdomain-enum':
            success = handle_subdomain_enum(args)
        elif args.command == 'amass-scan':
            success = handle_amass_scan(args)
        elif args.command == 'web-crawl':
            success = handle_web_crawl(args)
        elif args.command == 'vuln-scan':
            success = handle_vuln_scan(args)
        elif args.command == 'osint':
            success = handle_osint(args)
        elif args.command == 'full-recon':
            success = handle_full_recon(args)
        elif args.command == 'hashcat-attack':
            success = handle_hashcat_attack(args)
        elif args.command == 'wifi-hack':
            success = handle_airgeddon(args)
        elif args.command == 'social-scan':
            success = handle_social_scan(args)
        elif args.command == 'gobuster-scan':
            success = handle_gobuster_scan(args)
        elif args.command == 'sql-injection':
            success = handle_sqlmap_scan(args)
        elif args.command == 'email-find':
            success = handle_email_find(args)
        elif args.command == 'mobile-osint':
            success = handle_mobile_osint(args)
        elif args.command == 'modem-scan':
            success = handle_modem_scan(args)
        elif args.command == 'payload-gen':
            success = handle_payload_gen(args)
        elif args.command == 'metasploit-run':
            success = handle_metasploit_run(args)
        elif args.command == 'osintgram':
            success = handle_osintgram(args)
        elif args.command == 'instagram-scan':
            success = handle_instagram_scan(args)
        elif args.command == 'twitter-scan':
            success = handle_twitter_scan(args)
        elif args.command == 'linkedin-search':
            success = handle_linkedin_search(args)
        elif args.command == 'facebook-search':
            success = handle_facebook_search(args)
        elif args.command == 'email-verify':
            success = handle_email_verify(args)
        elif args.command == 'phone-validate':
            success = handle_phone_validate(args)
        elif args.command == 'domain-reputation':
            success = handle_domain_reputation(args)
        elif args.command == 'ip-geolocate':
            success = handle_ip_geolocate(args)
        else:
            print(f"{Fore.RED}[!] Unknown command: {args.command}{Style.RESET_ALL}")
            return 1
        
        if success:
            print(f"\n{Fore.GREEN}[+] Operation completed successfully!{Style.RESET_ALL}")
            return 0
        else:
            print(f"\n{Fore.RED}[!] Operation failed!{Style.RESET_ALL}")
            return 1
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation interrupted by user{Style.RESET_ALL}")
        return 1
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error: {str(e)}{Style.RESET_ALL}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
