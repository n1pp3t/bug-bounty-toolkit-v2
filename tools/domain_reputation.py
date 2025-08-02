#!/usr/bin/env python3
"""
Domain Reputation Checker Tool
This script provides functionality to check the reputation of domains and IP addresses.
"""

import requests
import json
import socket
import re
from colorama import Fore, Style

def check_virustotal_reputation(domain_or_ip, api_key=None):
    """
    Check domain/IP reputation using VirusTotal API.
    
    Args:
        domain_or_ip (str): The domain or IP address to check.
        api_key (str): Optional VirusTotal API key.
        
    Returns:
        dict: A dictionary containing reputation results.
    """
    print(f"{Fore.CYAN}[*] Checking VirusTotal reputation for: {domain_or_ip}{Style.RESET_ALL}")
    
    # If no API key provided, return limited information
    if not api_key:
        return {
            'status': 'limited',
            'domain_or_ip': domain_or_ip,
            'message': 'No VirusTotal API key provided - limited information available',
            'reputation_check_url': f'https://www.virustotal.com/gui/search/{domain_or_ip}'
        }
    
    try:
        # Determine if it's a domain or IP
        is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_or_ip) is not None
        
        if is_ip:
            # Check IP reputation
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{domain_or_ip}"
        else:
            # Check domain reputation
            url = f"https://www.virustotal.com/api/v3/domains/{domain_or_ip}"
        
        headers = {
            'x-apikey': api_key,
            'Accept': 'application/json'
        }
        
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract relevant information
            attributes = data.get('data', {}).get('attributes', {})
            
            results = {
                'status': 'success',
                'domain_or_ip': domain_or_ip,
                'is_ip': is_ip,
                'reputation_data': {
                    'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                    'reputation': attributes.get('reputation', 0),
                    'categories': attributes.get('categories', {}),
                    'tags': attributes.get('tags', [])
                }
            }
            
            # Calculate risk score
            stats = attributes.get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            total_engines = sum(stats.values())
            
            if total_engines > 0:
                risk_percentage = ((malicious_count + suspicious_count) / total_engines) * 100
                results['risk_score'] = round(risk_percentage, 2)
                
                if risk_percentage >= 50:
                    results['risk_level'] = 'High'
                elif risk_percentage >= 20:
                    results['risk_level'] = 'Medium'
                elif risk_percentage > 0:
                    results['risk_level'] = 'Low'
                else:
                    results['risk_level'] = 'Safe'
            
            print(f"{Fore.GREEN}[+] VirusTotal check completed for {domain_or_ip}{Style.RESET_ALL}")
            return results
            
        elif response.status_code == 401:
            return {
                'status': 'error',
                'domain_or_ip': domain_or_ip,
                'message': 'Invalid VirusTotal API key'
            }
        elif response.status_code == 404:
            return {
                'status': 'not_found',
                'domain_or_ip': domain_or_ip,
                'message': 'Domain/IP not found in VirusTotal database'
            }
        else:
            return {
                'status': 'error',
                'domain_or_ip': domain_or_ip,
                'message': f'VirusTotal API error: {response.status_code}',
                'response_text': response.text[:200]  # First 200 chars
            }
            
    except requests.exceptions.RequestException as e:
        return {
            'status': 'error',
            'domain_or_ip': domain_or_ip,
            'message': f'Network error: {str(e)}'
        }
    except Exception as e:
        return {
            'status': 'error',
            'domain_or_ip': domain_or_ip,
            'message': str(e)
        }

def check_abuseipdb_reputation(ip_address, api_key=None):
    """
    Check IP reputation using AbuseIPDB API.
    
    Args:
        ip_address (str): The IP address to check.
        api_key (str): Optional AbuseIPDB API key.
        
    Returns:
        dict: A dictionary containing reputation results.
    """
    print(f"{Fore.CYAN}[*] Checking AbuseIPDB reputation for: {ip_address}{Style.RESET_ALL}")
    
    # If no API key provided, return limited information
    if not api_key:
        return {
            'status': 'limited',
            'ip_address': ip_address,
            'message': 'No AbuseIPDB API key provided - limited information available',
            'reputation_check_url': f'https://www.abuseipdb.com/check/{ip_address}'
        }
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90
        }
        
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            results = {
                'status': 'success',
                'ip_address': ip_address,
                'reputation_data': data.get('data', {})
            }
            
            # Calculate risk level
            abuse_confidence = data.get('data', {}).get('abuseConfidenceScore', 0)
            results['abuse_confidence_score'] = abuse_confidence
            
            if abuse_confidence >= 70:
                results['risk_level'] = 'High'
            elif abuse_confidence >= 30:
                results['risk_level'] = 'Medium'
            elif abuse_confidence > 0:
                results['risk_level'] = 'Low'
            else:
                results['risk_level'] = 'Safe'
            
            print(f"{Fore.GREEN}[+] AbuseIPDB check completed for {ip_address}{Style.RESET_ALL}")
            return results
            
        elif response.status_code == 401:
            return {
                'status': 'error',
                'ip_address': ip_address,
                'message': 'Invalid AbuseIPDB API key'
            }
        elif response.status_code == 429:
            return {
                'status': 'error',
                'ip_address': ip_address,
                'message': 'Rate limit exceeded for AbuseIPDB API'
            }
        else:
            return {
                'status': 'error',
                'ip_address': ip_address,
                'message': f'AbuseIPDB API error: {response.status_code}',
                'response_text': response.text[:200]
            }
            
    except requests.exceptions.RequestException as e:
        return {
            'status': 'error',
            'ip_address': ip_address,
            'message': f'Network error: {str(e)}'
        }
    except Exception as e:
        return {
            'status': 'error',
            'ip_address': ip_address,
            'message': str(e)
        }

def check_domain_dns(domain):
    """
    Check DNS records for a domain.
    
    Args:
        domain (str): The domain to check.
        
    Returns:
        dict: A dictionary containing DNS information.
    """
    print(f"{Fore.CYAN}[*] Checking DNS records for: {domain}{Style.RESET_ALL}")
    
    try:
        dns_info = {}
        
        # Check A records (IPv4 addresses)
        try:
            a_records = socket.getaddrinfo(domain, None, socket.AF_INET)
            dns_info['a_records'] = [record[4][0] for record in a_records]
        except:
            dns_info['a_records'] = []
        
        # Check AAAA records (IPv6 addresses)
        try:
            aaaa_records = socket.getaddrinfo(domain, None, socket.AF_INET6)
            dns_info['aaaa_records'] = [record[4][0] for record in aaaa_records]
        except:
            dns_info['aaaa_records'] = []
        
        # Check MX records (mail servers)
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_info['mx_records'] = [str(record) for record in mx_records]
        except:
            dns_info['mx_records'] = []
        
        # Check NS records (name servers)
        try:
            import dns.resolver
            ns_records = dns.resolver.resolve(domain, 'NS')
            dns_info['ns_records'] = [str(record) for record in ns_records]
        except:
            dns_info['ns_records'] = []
        
        # Check TXT records
        try:
            import dns.resolver
            txt_records = dns.resolver.resolve(domain, 'TXT')
            dns_info['txt_records'] = [str(record) for record in txt_records]
        except:
            dns_info['txt_records'] = []
        
        # Check CNAME records
        try:
            import dns.resolver
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            dns_info['cname_records'] = [str(record) for record in cname_records]
        except:
            dns_info['cname_records'] = []
        
        results = {
            'status': 'success',
            'domain': domain,
            'dns_info': dns_info
        }
        
        print(f"{Fore.GREEN}[+] DNS check completed for {domain}{Style.RESET_ALL}")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'domain': domain,
            'message': str(e)
        }

def run_domain_reputation_check(domain_or_ip, virustotal_api_key=None, abuseipdb_api_key=None):
    """
    Run comprehensive domain/IP reputation check.
    
    Args:
        domain_or_ip (str): The domain or IP address to check.
        virustotal_api_key (str): Optional VirusTotal API key.
        abuseipdb_api_key (str): Optional AbuseIPDB API key.
        
    Returns:
        dict: Comprehensive reputation results.
    """
    print(f"{Fore.CYAN}[*] Running comprehensive reputation check for: {domain_or_ip}{Style.RESET_ALL}")
    
    results = {
        'target': domain_or_ip,
        'checks': {}
    }
    
    # Check VirusTotal reputation
    vt_result = check_virustotal_reputation(domain_or_ip, virustotal_api_key)
    results['checks']['virustotal'] = vt_result
    
    # If it's an IP address, check AbuseIPDB
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_or_ip) is not None
    if is_ip:
        abuse_result = check_abuseipdb_reputation(domain_or_ip, abuseipdb_api_key)
        results['checks']['abuseipdb'] = abuse_result
    
    # If it's a domain, check DNS records
    if not is_ip:
        dns_result = check_domain_dns(domain_or_ip)
        results['checks']['dns'] = dns_result
    
    # Overall risk assessment
    risk_assessment = {
        'risk_level': 'Unknown',
        'risk_factors': []
    }
    
    # Check VirusTotal risk
    if 'risk_level' in vt_result:
        risk_assessment['risk_factors'].append(f"VirusTotal: {vt_result['risk_level']}")
    
    # Check AbuseIPDB risk if applicable
    if is_ip and 'risk_level' in results['checks']['abuseipdb']:
        risk_assessment['risk_factors'].append(f"AbuseIPDB: {results['checks']['abuseipdb']['risk_level']}")
    
    # Determine overall risk level
    risk_levels = [factor.split(': ')[1] for factor in risk_assessment['risk_factors']]
    if 'High' in risk_levels:
        risk_assessment['risk_level'] = 'High'
    elif 'Medium' in risk_levels:
        risk_assessment['risk_level'] = 'Medium'
    elif 'Low' in risk_levels:
        risk_assessment['risk_level'] = 'Low'
    elif 'Safe' in risk_levels:
        risk_assessment['risk_level'] = 'Safe'
    else:
        risk_assessment['risk_level'] = 'Unknown'
    
    results['risk_assessment'] = risk_assessment
    
    print(f"{Fore.GREEN}[+] Reputation check completed for {domain_or_ip}{Style.RESET_ALL}")
    return results

def check_multiple_domains(domains_list, virustotal_api_key=None, abuseipdb_api_key=None, output_file=None):
    """
    Check reputation for multiple domains/IPs.
    
    Args:
        domains_list (list): List of domains/IPs to check.
        virustotal_api_key (str): Optional VirusTotal API key.
        abuseipdb_api_key (str): Optional AbuseIPDB API key.
        output_file (str): Optional file to save results.
        
    Returns:
        dict: Comprehensive reputation results for all domains.
    """
    print(f"{Fore.CYAN}[*] Checking reputation for {len(domains_list)} domains/IPs{Style.RESET_ALL}")
    
    results = {
        'total_targets': len(domains_list),
        'checks': []
    }
    
    for i, domain_or_ip in enumerate(domains_list, 1):
        print(f"{Fore.BLUE}[+] Checking {i}/{len(domains_list)}: {domain_or_ip}{Style.RESET_ALL}")
        
        result = run_domain_reputation_check(domain_or_ip, virustotal_api_key, abuseipdb_api_key)
        results['checks'].append(result)
    
    # Summary statistics
    risk_levels = {}
    for check in results['checks']:
        risk_level = check['risk_assessment']['risk_level']
        risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
    
    results['summary'] = {
        'risk_distribution': risk_levels,
        'total_high_risk': risk_levels.get('High', 0),
        'total_medium_risk': risk_levels.get('Medium', 0),
        'total_low_risk': risk_levels.get('Low', 0),
        'total_safe': risk_levels.get('Safe', 0)
    }
    
    # Save to file if requested
    if output_file:
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.BLUE}[+] Results saved to: {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {str(e)}{Style.RESET_ALL}")
    
    return results

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running domain reputation checker test...")
    
    # Test domains/IPs
    test_targets = [
        "google.com",
        "github.com",
        "8.8.8.8"
    ]
    
    results = check_multiple_domains(
        domains_list=test_targets,
        output_file="output/domain_reputation_test.json"
    )
    
    print("\nTest results summary:")
    print(f"  Total targets: {results['total_targets']}")
    if 'summary' in results:
        summary = results['summary']
        print(f"  High risk: {summary.get('total_high_risk', 0)}")
        print(f"  Medium risk: {summary.get('total_medium_risk', 0)}")
        print(f"  Low risk: {summary.get('total_low_risk', 0)}")
        print(f"  Safe: {summary.get('total_safe', 0)}")
