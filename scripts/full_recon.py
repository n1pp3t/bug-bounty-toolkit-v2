#!/usr/bin/env python3
"""
Full Reconnaissance Automation Script
Comprehensive bug bounty reconnaissance pipeline
"""

import sys
import os
import time
import argparse
import json
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.nmap_scanner import run_nmap_scan
from tools.subdomain_finder import run_subdomain_enumeration
from tools.amass_wrapper import run_amass_scan
from tools.web_crawler import run_web_crawl
from tools.vulnerability_scanner import run_vulnerability_scan
from tools.osint_collector import run_osint_collection
from tools.port_scanner import run_port_scan
from tools.subdir_finder import run_directory_scan
from tools.data_analyzer import run_analysis
from utils.logger import setup_logger
from utils.helpers import validate_domain, validate_url, save_results, get_timestamp

class FullReconPipeline:
    def __init__(self, target, config=None):
        self.target = target
        self.config = config or {}
        self.logger = setup_logger("full_recon")
        self.results = {
            'target': target,
            'scan_type': 'full_reconnaissance',
            'timestamp': get_timestamp(),
            'pipeline_results': {},
            'summary': {}
        }
        
        # Default configuration
        self.default_config = {
            'subdomain_enumeration': True,
            'port_scanning': True,
            'web_crawling': True,
            'directory_enumeration': True,
            'vulnerability_scanning': True,
            'osint_collection': True,
            'nmap_scanning': True,
            'amass_scanning': True,
            'threads': 50,
            'timeout': 10,
            'max_subdomains': 100,
            'max_crawl_pages': 200,
            'save_individual_results': True,
            'generate_report': True
        }
        
        # Merge with provided config
        for key, value in self.default_config.items():
            if key not in self.config:
                self.config[key] = value
    
    def run_subdomain_enumeration(self):
        """Run comprehensive subdomain enumeration"""
        if not self.config.get('subdomain_enumeration', True):
            return None
        
        self.logger.info("Starting subdomain enumeration phase...")
        
        try:
            # Run built-in subdomain finder
            subdomain_results = run_subdomain_enumeration(
                self.target,
                methods=['all'],
                threads=self.config.get('threads', 50),
                save_format='json' if self.config.get('save_individual_results') else None
            )
            
            # Run Amass if enabled
            if self.config.get('amass_scanning', True):
                self.logger.info("Running Amass subdomain enumeration...")
                amass_results = run_amass_scan(
                    self.target,
                    scan_type='comprehensive',
                    save_format='json' if self.config.get('save_individual_results') else None
                )
                
                if amass_results:
                    # Combine results
                    if subdomain_results and 'summary' in subdomain_results:
                        amass_subdomains = set()
                        if 'summary' in amass_results:
                            amass_subdomains = set(amass_results['summary'].get('unique_subdomains', []))
                        
                        existing_subdomains = set(subdomain_results['summary'].get('unique_subdomains', []))
                        combined_subdomains = existing_subdomains.union(amass_subdomains)
                        
                        subdomain_results['summary']['unique_subdomains'] = list(combined_subdomains)
                        subdomain_results['summary']['total_subdomains'] = len(combined_subdomains)
                        subdomain_results['amass_results'] = amass_results
            
            self.results['pipeline_results']['subdomain_enumeration'] = subdomain_results
            
            if subdomain_results and 'summary' in subdomain_results:
                found_count = subdomain_results['summary'].get('total_subdomains', 0)
                self.logger.info(f"Subdomain enumeration completed: {found_count} subdomains found")
                return subdomain_results['summary'].get('unique_subdomains', [])
            
            return []
            
        except Exception as e:
            self.logger.error(f"Error in subdomain enumeration: {str(e)}")
            return []
    
    def run_port_scanning(self, targets):
        """Run port scanning on discovered targets"""
        if not self.config.get('port_scanning', True) or not targets:
            return None
        
        self.logger.info(f"Starting port scanning phase on {len(targets)} targets...")
        
        port_results = {}
        
        # Limit targets to avoid overwhelming scans
        max_targets = min(len(targets), self.config.get('max_subdomains', 100))
        scan_targets = targets[:max_targets]
        
        for i, target in enumerate(scan_targets, 1):
            try:
                self.logger.info(f"Port scanning {target} ({i}/{len(scan_targets)})")
                
                # Run basic port scan first
                basic_results = run_port_scan(
                    target,
                    common_ports=True,
                    threads=self.config.get('threads', 50),
                    timeout=self.config.get('timeout', 10),
                    save_format='json' if self.config.get('save_individual_results') else None
                )
                
                if basic_results and basic_results.get('total_open', 0) > 0:
                    port_results[target] = basic_results
                    
                    # Run Nmap scan if enabled and ports found
                    if self.config.get('nmap_scanning', True):
                        self.logger.info(f"Running Nmap scan on {target}")
                        nmap_results = run_nmap_scan(
                            target,
                            scan_type='service',
                            save_format='json' if self.config.get('save_individual_results') else None
                        )
                        
                        if nmap_results:
                            port_results[target]['nmap_results'] = nmap_results
                
                # Rate limiting
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Error port scanning {target}: {str(e)}")
                continue
        
        self.results['pipeline_results']['port_scanning'] = port_results
        
        total_targets_with_ports = len(port_results)
        self.logger.info(f"Port scanning completed: {total_targets_with_ports} targets with open ports")
        
        return port_results
    
    def run_web_enumeration(self, targets):
        """Run web crawling and directory enumeration"""
        if not targets:
            return None
        
        web_results = {}
        
        # Find web targets (targets with HTTP/HTTPS ports)
        web_targets = []
        
        if isinstance(targets, dict):  # Port scan results
            for target, port_data in targets.items():
                if 'open_ports' in port_data:
                    for port_info in port_data['open_ports']:
                        port = port_info['port']
                        if port in [80, 443, 8080, 8443, 8888]:
                            protocol = 'https' if port in [443, 8443] else 'http'
                            port_suffix = '' if port in [80, 443] else f':{port}'
                            web_url = f"{protocol}://{target}{port_suffix}"
                            web_targets.append(web_url)
        else:  # List of domains
            for target in targets[:10]:  # Limit web targets
                web_targets.extend([f"http://{target}", f"https://{target}"])
        
        if not web_targets:
            self.logger.info("No web targets found for web enumeration")
            return None
        
        self.logger.info(f"Starting web enumeration on {len(web_targets)} web targets...")
        
        for i, web_url in enumerate(web_targets[:20], 1):  # Limit to 20 web targets
            try:
                self.logger.info(f"Web enumeration on {web_url} ({i}/{min(len(web_targets), 20)})")
                
                target_results = {}
                
                # Web crawling
                if self.config.get('web_crawling', True):
                    self.logger.info(f"Crawling {web_url}")
                    crawl_results = run_web_crawl(
                        web_url,
                        max_depth=2,
                        max_pages=self.config.get('max_crawl_pages', 200),
                        threads=10,
                        save_format='json' if self.config.get('save_individual_results') else None
                    )
                    
                    if crawl_results:
                        target_results['web_crawl'] = crawl_results
                
                # Directory enumeration
                if self.config.get('directory_enumeration', True):
                    self.logger.info(f"Directory enumeration on {web_url}")
                    dir_results = run_directory_scan(
                        web_url,
                        threads=self.config.get('threads', 50),
                        timeout=self.config.get('timeout', 10),
                        save_format='json' if self.config.get('save_individual_results') else None
                    )
                    
                    if dir_results:
                        target_results['directory_scan'] = dir_results
                
                # Vulnerability scanning
                if self.config.get('vulnerability_scanning', True):
                    self.logger.info(f"Vulnerability scanning on {web_url}")
                    
                    # Extract endpoints and parameters from crawl results
                    endpoints = []
                    parameters = {}
                    
                    if 'web_crawl' in target_results:
                        endpoints = target_results['web_crawl'].get('endpoints', [])
                        parameters = target_results['web_crawl'].get('parameters', {})
                    
                    vuln_results = run_vulnerability_scan(
                        web_url,
                        endpoints=endpoints[:50],  # Limit endpoints
                        parameters=parameters,
                        save_format='json' if self.config.get('save_individual_results') else None
                    )
                    
                    if vuln_results:
                        target_results['vulnerability_scan'] = vuln_results
                
                if target_results:
                    web_results[web_url] = target_results
                
                # Rate limiting
                time.sleep(2)
                
            except Exception as e:
                self.logger.error(f"Error in web enumeration for {web_url}: {str(e)}")
                continue
        
        self.results['pipeline_results']['web_enumeration'] = web_results
        
        self.logger.info(f"Web enumeration completed on {len(web_results)} targets")
        return web_results
    
    def run_osint_collection(self):
        """Run OSINT collection"""
        if not self.config.get('osint_collection', True):
            return None
        
        self.logger.info("Starting OSINT collection phase...")
        
        try:
            # Get API keys from config
            api_keys = self.config.get('api_keys', {})
            
            osint_results = run_osint_collection(
                self.target,
                api_keys=api_keys,
                save_format='json' if self.config.get('save_individual_results') else None
            )
            
            self.results['pipeline_results']['osint_collection'] = osint_results
            
            if osint_results and 'summary' in osint_results:
                successful_sources = osint_results['summary'].get('sources_successful', 0)
                self.logger.info(f"OSINT collection completed: {successful_sources} sources successful")
            
            return osint_results
            
        except Exception as e:
            self.logger.error(f"Error in OSINT collection: {str(e)}")
            return None
    
    def generate_summary(self):
        """Generate comprehensive summary of all results"""
        self.logger.info("Generating reconnaissance summary...")
        
        summary = {
            'target': self.target,
            'scan_start_time': self.results['timestamp'],
            'scan_end_time': get_timestamp(),
            'phases_completed': [],
            'total_subdomains': 0,
            'total_open_ports': 0,
            'total_web_targets': 0,
            'total_vulnerabilities': 0,
            'total_endpoints': 0,
            'key_findings': [],
            'recommendations': []
        }
        
        # Analyze subdomain enumeration results
        if 'subdomain_enumeration' in self.results['pipeline_results']:
            summary['phases_completed'].append('subdomain_enumeration')
            subdomain_data = self.results['pipeline_results']['subdomain_enumeration']
            if subdomain_data and 'summary' in subdomain_data:
                summary['total_subdomains'] = subdomain_data['summary'].get('total_subdomains', 0)
                
                if summary['total_subdomains'] > 0:
                    summary['key_findings'].append(f"Found {summary['total_subdomains']} subdomains")
        
        # Analyze port scanning results
        if 'port_scanning' in self.results['pipeline_results']:
            summary['phases_completed'].append('port_scanning')
            port_data = self.results['pipeline_results']['port_scanning']
            if port_data:
                total_ports = 0
                for target, target_data in port_data.items():
                    total_ports += target_data.get('total_open', 0)
                summary['total_open_ports'] = total_ports
                
                if total_ports > 0:
                    summary['key_findings'].append(f"Found {total_ports} open ports across {len(port_data)} targets")
        
        # Analyze web enumeration results
        if 'web_enumeration' in self.results['pipeline_results']:
            summary['phases_completed'].append('web_enumeration')
            web_data = self.results['pipeline_results']['web_enumeration']
            if web_data:
                summary['total_web_targets'] = len(web_data)
                
                total_endpoints = 0
                total_vulns = 0
                
                for web_url, web_results in web_data.items():
                    if 'web_crawl' in web_results:
                        crawl_data = web_results['web_crawl']
                        if 'summary' in crawl_data:
                            total_endpoints += crawl_data['summary'].get('endpoints_found', 0)
                    
                    if 'vulnerability_scan' in web_results:
                        vuln_data = web_results['vulnerability_scan']
                        if 'summary' in vuln_data:
                            total_vulns += vuln_data['summary'].get('total_vulnerabilities', 0)
                
                summary['total_endpoints'] = total_endpoints
                summary['total_vulnerabilities'] = total_vulns
                
                if total_endpoints > 0:
                    summary['key_findings'].append(f"Discovered {total_endpoints} web endpoints")
                
                if total_vulns > 0:
                    summary['key_findings'].append(f"Found {total_vulns} potential vulnerabilities")
        
        # Analyze OSINT results
        if 'osint_collection' in self.results['pipeline_results']:
            summary['phases_completed'].append('osint_collection')
            osint_data = self.results['pipeline_results']['osint_collection']
            if osint_data and 'summary' in osint_data:
                successful_sources = osint_data['summary'].get('sources_successful', 0)
                if successful_sources > 0:
                    summary['key_findings'].append(f"OSINT data collected from {successful_sources} sources")
        
        # Generate recommendations
        if summary['total_subdomains'] > 50:
            summary['recommendations'].append("Large subdomain footprint detected - review for unused/forgotten subdomains")
        
        if summary['total_open_ports'] > 20:
            summary['recommendations'].append("Many open ports found - review for unnecessary services")
        
        if summary['total_vulnerabilities'] > 0:
            summary['recommendations'].append("Vulnerabilities detected - prioritize remediation based on severity")
        
        if summary['total_endpoints'] > 100:
            summary['recommendations'].append("Large web application surface - consider additional security testing")
        
        self.results['summary'] = summary
        
        self.logger.info(f"Reconnaissance summary generated:")
        self.logger.info(f"  Phases completed: {len(summary['phases_completed'])}")
        self.logger.info(f"  Subdomains found: {summary['total_subdomains']}")
        self.logger.info(f"  Open ports: {summary['total_open_ports']}")
        self.logger.info(f"  Web targets: {summary['total_web_targets']}")
        self.logger.info(f"  Vulnerabilities: {summary['total_vulnerabilities']}")
        
        return summary
    
    def run_full_pipeline(self):
        """Execute the complete reconnaissance pipeline"""
        self.logger.info(f"Starting full reconnaissance pipeline for {self.target}")
        
        start_time = time.time()
        
        try:
            # Phase 1: Subdomain Enumeration
            subdomains = self.run_subdomain_enumeration()
            
            # Phase 2: Port Scanning
            port_results = self.run_port_scanning(subdomains or [self.target])
            
            # Phase 3: Web Enumeration
            web_results = self.run_web_enumeration(port_results or subdomains or [self.target])
            
            # Phase 4: OSINT Collection
            osint_results = self.run_osint_collection()
            
            # Phase 5: Generate Summary
            summary = self.generate_summary()
            
            end_time = time.time()
            total_duration = end_time - start_time
            
            self.results['total_duration'] = total_duration
            self.logger.info(f"Full reconnaissance pipeline completed in {total_duration:.2f} seconds")
            
            return self.results
            
        except KeyboardInterrupt:
            self.logger.info("Reconnaissance pipeline interrupted by user")
            return self.results
        except Exception as e:
            self.logger.error(f"Error in reconnaissance pipeline: {str(e)}")
            return self.results
    
    def save_results(self, format_type='json'):
        """Save comprehensive results"""
        target_clean = self.target.replace('.', '_')
        filename = f"full_recon_{target_clean}"
        
        filepath = save_results(self.results, filename, format_type)
        self.logger.info(f"Full reconnaissance results saved to: {filepath}")
        return filepath

def main():
    parser = argparse.ArgumentParser(
        description='Full Bug Bounty Reconnaissance Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python full_recon.py example.com
  python full_recon.py example.com --no-nmap --threads 100
  python full_recon.py example.com --config config.json
        """
    )
    
    parser.add_argument('target', help='Target domain to reconnaissance')
    parser.add_argument('--config', help='Configuration file (JSON)')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--max-subdomains', type=int, default=100, help='Maximum subdomains to scan')
    parser.add_argument('--max-crawl-pages', type=int, default=200, help='Maximum pages to crawl')
    parser.add_argument('--no-subdomain', action='store_true', help='Skip subdomain enumeration')
    parser.add_argument('--no-port-scan', action='store_true', help='Skip port scanning')
    parser.add_argument('--no-web-crawl', action='store_true', help='Skip web crawling')
    parser.add_argument('--no-dir-enum', action='store_true', help='Skip directory enumeration')
    parser.add_argument('--no-vuln-scan', action='store_true', help='Skip vulnerability scanning')
    parser.add_argument('--no-osint', action='store_true', help='Skip OSINT collection')
    parser.add_argument('--no-nmap', action='store_true', help='Skip Nmap scanning')
    parser.add_argument('--no-amass', action='store_true', help='Skip Amass scanning')
    parser.add_argument('--output', choices=['json', 'html'], default='json', help='Output format')
    
    args = parser.parse_args()
    
    # Validate target
    if not validate_domain(args.target):
        print(f"Error: Invalid domain '{args.target}'")
        return 1
    
    # Load configuration
    config = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Error loading config file: {e}")
            return 1
    
    # Override config with command line arguments
    config.update({
        'threads': args.threads,
        'timeout': args.timeout,
        'max_subdomains': args.max_subdomains,
        'max_crawl_pages': args.max_crawl_pages,
        'subdomain_enumeration': not args.no_subdomain,
        'port_scanning': not args.no_port_scan,
        'web_crawling': not args.no_web_crawl,
        'directory_enumeration': not args.no_dir_enum,
        'vulnerability_scanning': not args.no_vuln_scan,
        'osint_collection': not args.no_osint,
        'nmap_scanning': not args.no_nmap,
        'amass_scanning': not args.no_amass
    })
    
    # Initialize and run pipeline
    pipeline = FullReconPipeline(args.target, config)
    
    try:
        results = pipeline.run_full_pipeline()
        
        # Save results
        if results:
            pipeline.save_results(args.output)
            
            # Print summary
            if 'summary' in results:
                summary = results['summary']
                print(f"\n{'='*60}")
                print(f"RECONNAISSANCE SUMMARY FOR {args.target.upper()}")
                print(f"{'='*60}")
                print(f"Phases completed: {', '.join(summary['phases_completed'])}")
                print(f"Subdomains found: {summary['total_subdomains']}")
                print(f"Open ports: {summary['total_open_ports']}")
                print(f"Web targets: {summary['total_web_targets']}")
                print(f"Endpoints discovered: {summary['total_endpoints']}")
                print(f"Vulnerabilities found: {summary['total_vulnerabilities']}")
                
                if summary['key_findings']:
                    print(f"\nKey Findings:")
                    for finding in summary['key_findings']:
                        print(f"  • {finding}")
                
                if summary['recommendations']:
                    print(f"\nRecommendations:")
                    for rec in summary['recommendations']:
                        print(f"  • {rec}")
                
                print(f"\nTotal scan time: {results.get('total_duration', 0):.2f} seconds")
                print(f"{'='*60}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\nReconnaissance interrupted by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
