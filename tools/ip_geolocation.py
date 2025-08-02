#!/usr/bin/env python3
"""
IP Geolocation Tool
This script provides functionality to get geolocation information for IP addresses.
"""

import requests
import json
import re
from colorama import Fore, Style

def get_ip_geolocation(ip_address, api_key=None):
    """
    Get geolocation information for an IP address.
    
    Args:
        ip_address (str): The IP address to geolocate.
        api_key (str): Optional API key for geolocation service.
        
    Returns:
        dict: A dictionary containing geolocation information.
    """
    print(f"{Fore.CYAN}[*] Getting geolocation for IP: {ip_address}{Style.RESET_ALL}")
    
    try:
        # Validate IP address format
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_address):
            return {
                'status': 'error',
                'ip_address': ip_address,
                'message': 'Invalid IP address format'
            }
        
        # Try multiple geolocation services
        
        # 1. ip-api.com (free, no API key required)
        ipapi_url = f"http://ip-api.com/json/{ip_address}"
        ipapi_params = {}
        
        if api_key:
            # If API key provided, we could use a premium service
            # For this example, we'll still use ip-api but note the key is available
            pass
        
        try:
            ipapi_response = requests.get(ipapi_url, params=ipapi_params, timeout=10)
            if ipapi_response.status_code == 200:
                data = ipapi_response.json()
                
                if data.get('status') == 'success':
                    results = {
                        'status': 'success',
                        'ip_address': ip_address,
                        'geolocation_data': {
                            'country': data.get('country'),
                            'country_code': data.get('countryCode'),
                            'region': data.get('regionName'),
                            'region_code': data.get('region'),
                            'city': data.get('city'),
                            'zip': data.get('zip'),
                            'lat': data.get('lat'),
                            'lon': data.get('lon'),
                            'timezone': data.get('timezone'),
                            'isp': data.get('isp'),
                            'org': data.get('org'),
                            'as': data.get('as')
                        },
                        'source': 'ip-api.com'
                    }
                    
                    print(f"{Fore.GREEN}[+] Geolocation found for {ip_address}{Style.RESET_ALL}")
                    return results
                else:
                    # Try another service
                    pass
                    
        except:
            # Try another service if this one fails
            pass
        
        # 2. ipinfo.io (free tier available)
        ipinfo_url = f"https://ipinfo.io/{ip_address}/json"
        ipinfo_headers = {}
        
        if api_key:
            ipinfo_headers['Authorization'] = f'Bearer {api_key}'
        
        try:
            ipinfo_response = requests.get(ipinfo_url, headers=ipinfo_headers, timeout=10)
            if ipinfo_response.status_code == 200:
                data = ipinfo_response.json()
                
                # Parse location data
                loc = data.get('loc', '').split(',')
                lat = float(loc[0]) if len(loc) > 0 and loc[0] else None
                lon = float(loc[1]) if len(loc) > 1 and loc[1] else None
                
                results = {
                    'status': 'success',
                    'ip_address': ip_address,
                    'geolocation_data': {
                        'country': data.get('country'),
                        'region': data.get('region'),
                        'city': data.get('city'),
                        'zip': data.get('postal'),
                        'lat': lat,
                        'lon': lon,
                        'timezone': data.get('timezone'),
                        'org': data.get('org'),
                        'hostname': data.get('hostname')
                    },
                    'source': 'ipinfo.io'
                }
                
                print(f"{Fore.GREEN}[+] Geolocation found for {ip_address}{Style.RESET_ALL}")
                return results
                
        except:
            # Try another service if this one fails
            pass
        
        # 3. ipgeolocation.io (requires API key)
        if api_key:
            ipgeolocation_url = f"https://api.ipgeolocation.io/ipgeo"
            ipgeolocation_params = {
                'apiKey': api_key,
                'ip': ip_address
            }
            
            try:
                ipgeolocation_response = requests.get(ipgeolocation_url, params=ipgeolocation_params, timeout=10)
                if ipgeolocation_response.status_code == 200:
                    data = ipgeolocation_response.json()
                    
                    results = {
                        'status': 'success',
                        'ip_address': ip_address,
                        'geolocation_data': {
                            'country': data.get('country_name'),
                            'country_code': data.get('country_code2'),
                            'region': data.get('state_prov'),
                            'city': data.get('city'),
                            'zip': data.get('zipcode'),
                            'lat': data.get('latitude'),
                            'lon': data.get('longitude'),
                            'timezone': data.get('time_zone', {}).get('name'),
                            'isp': data.get('isp'),
                            'org': data.get('organization')
                        },
                        'source': 'ipgeolocation.io'
                    }
                    
                    print(f"{Fore.GREEN}[+] Geolocation found for {ip_address}{Style.RESET_ALL}")
                    return results
                    
            except:
                pass
        
        # If all services fail
        return {
            'status': 'error',
            'ip_address': ip_address,
            'message': 'Unable to get geolocation information from any service'
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'ip_address': ip_address,
            'message': str(e)
        }

def get_hostname_geolocation(hostname):
    """
    Get geolocation information for a hostname by resolving to IP first.
    
    Args:
        hostname (str): The hostname to geolocate.
        
    Returns:
        dict: A dictionary containing geolocation information.
    """
    print(f"{Fore.CYAN}[*] Resolving hostname and getting geolocation for: {hostname}{Style.RESET_ALL}")
    
    try:
        # Resolve hostname to IP
        import socket
        ip_address = socket.gethostbyname(hostname)
        
        print(f"{Fore.BLUE}[+] Resolved {hostname} to {ip_address}{Style.RESET_ALL}")
        
        # Get geolocation for the IP
        return get_ip_geolocation(ip_address)
        
    except socket.gaierror as e:
        return {
            'status': 'error',
            'hostname': hostname,
            'message': f'Unable to resolve hostname: {str(e)}'
        }
    except Exception as e:
        return {
            'status': 'error',
            'hostname': hostname,
            'message': str(e)
        }

def batch_geolocation_lookup(ip_list, api_key=None, output_file=None):
    """
    Get geolocation information for multiple IP addresses.
    
    Args:
        ip_list (list): List of IP addresses to geolocate.
        api_key (str): Optional API key for geolocation service.
        output_file (str): Optional file to save results.
        
    Returns:
        dict: Geolocation results for all IP addresses.
    """
    print(f"{Fore.CYAN}[*] Getting geolocation for {len(ip_list)} IP addresses{Style.RESET_ALL}")
    
    results = {
        'total_ips': len(ip_list),
        'successful_lookups': [],
        'failed_lookups': [],
        'errors': []
    }
    
    for i, ip in enumerate(ip_list, 1):
        print(f"{Fore.BLUE}[+] Looking up IP {i}/{len(ip_list)}: {ip}{Style.RESET_ALL}")
        
        result = get_ip_geolocation(ip, api_key)
        
        if result['status'] == 'success':
            results['successful_lookups'].append(result)
        else:
            results['failed_lookups'].append(result)
    
    # Summary
    print(f"{Fore.GREEN}[+] Geolocation lookup complete:{Style.RESET_ALL}")
    print(f"    Successful lookups: {len(results['successful_lookups'])}")
    print(f"    Failed lookups: {len(results['failed_lookups'])}")
    print(f"    Errors: {len(results.get('errors', []))}")
    
    # Save to file if requested
    if output_file:
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.BLUE}[+] Results saved to: {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {str(e)}{Style.RESET_ALL}")
    
    return results

def get_my_ip_geolocation(api_key=None):
    """
    Get geolocation information for the current machine's public IP.
    
    Args:
        api_key (str): Optional API key for geolocation service.
        
    Returns:
        dict: A dictionary containing geolocation information for current IP.
    """
    print(f"{Fore.CYAN}[*] Getting geolocation for current public IP{Style.RESET_ALL}")
    
    try:
        # Get current public IP
        ip_response = requests.get('https://api.ipify.org', timeout=5)
        if ip_response.status_code == 200:
            current_ip = ip_response.text.strip()
            print(f"{Fore.BLUE}[+] Current public IP: {current_ip}{Style.RESET_ALL}")
            
            # Get geolocation for current IP
            return get_ip_geolocation(current_ip, api_key)
        else:
            return {
                'status': 'error',
                'message': 'Unable to get current public IP'
            }
            
    except requests.exceptions.RequestException as e:
        return {
            'status': 'error',
            'message': f'Network error: {str(e)}'
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

def format_geolocation_data(geo_data):
    """
    Format geolocation data for display.
    
    Args:
        geo_data (dict): Geolocation data dictionary.
        
    Returns:
        str: Formatted geolocation information.
    """
    if not geo_data or geo_data['status'] != 'success':
        return "No geolocation data available"
    
    data = geo_data.get('geolocation_data', {})
    
    formatted = []
    formatted.append(f"IP Address: {geo_data.get('ip_address', 'N/A')}")
    formatted.append(f"Country: {data.get('country', 'N/A')}")
    formatted.append(f"Region: {data.get('region', 'N/A')}")
    formatted.append(f"City: {data.get('city', 'N/A')}")
    formatted.append(f"ZIP: {data.get('zip', 'N/A')}")
    formatted.append(f"Coordinates: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
    formatted.append(f"Timezone: {data.get('timezone', 'N/A')}")
    formatted.append(f"ISP: {data.get('isp', 'N/A')}")
    formatted.append(f"Organization: {data.get('org', 'N/A')}")
    formatted.append(f"Source: {geo_data.get('source', 'N/A')}")
    
    return '\n'.join(formatted)

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running IP geolocation tool test...")
    
    # Test IP addresses
    test_ips = [
        "8.8.8.8",      # Google DNS
        "1.1.1.1",      # Cloudflare DNS
        "208.67.222.222" # OpenDNS
    ]
    
    results = batch_geolocation_lookup(
        ip_list=test_ips,
        output_file="output/ip_geolocation_test.json"
    )
    
    print("\nTest results summary:")
    print(f"  Total IPs: {results['total_ips']}")
    print(f"  Successful lookups: {len(results['successful_lookups'])}")
    print(f"  Failed lookups: {len(results['failed_lookups'])}")
    
    # Show sample formatted data
    if results['successful_lookups']:
        print("\nSample geolocation data:")
        print(format_geolocation_data(results['successful_lookups'][0]))
