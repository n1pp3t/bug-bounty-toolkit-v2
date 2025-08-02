#!/usr/bin/env python3
"""
LinkedIn Searcher Tool
This script provides functionality to search for LinkedIn profiles.
"""

import requests
import json
import re
from bs4 import BeautifulSoup
from colorama import Fore, Style

def search_linkedin_profiles(query, limit=10):
    """
    Search LinkedIn for profiles matching a query.
    
    Args:
        query (str): The search query (name, company, etc.).
        limit (int): Maximum number of profiles to retrieve.
        
    Returns:
        dict: A dictionary containing search results.
    """
    print(f"{Fore.CYAN}[*] Searching LinkedIn for: {query}{Style.RESET_ALL}")
    
    try:
        # LinkedIn search URL
        url = f"https://www.linkedin.com/search/results/people/?keywords={query.replace(' ', '%20')}"
        
        # Headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Send request to LinkedIn search page
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract profile information
            profiles = []
            
            # Find profile cards
            profile_cards = soup.find_all('div', {'class': 'search-entity'})
            
            for card in profile_cards[:limit]:
                try:
                    profile_data = {}
                    
                    # Get profile name
                    name_element = card.find('span', {'class': 'name'})
                    if name_element:
                        profile_data['name'] = name_element.get_text().strip()
                    
                    # Get profile title
                    title_element = card.find('p', {'class': 'subline-level-1'})
                    if title_element:
                        profile_data['title'] = title_element.get_text().strip()
                    
                    # Get profile location
                    location_element = card.find('p', {'class': 'subline-level-2'})
                    if location_element:
                        profile_data['location'] = location_element.get_text().strip()
                    
                    # Get profile URL
                    link_element = card.find('a', {'class': 'search-result__result-link'})
                    if link_element and link_element.get('href'):
                        profile_data['profile_url'] = f"https://www.linkedin.com{link_element.get('href')}"
                    
                    # Get profile image
                    img_element = card.find('img', {'class': 'presence-entity__image'})
                    if img_element and img_element.get('src'):
                        profile_data['profile_image'] = img_element.get('src')
                    
                    if profile_data:
                        profiles.append(profile_data)
                        
                except Exception as e:
                    continue
            
            results = {
                'status': 'success',
                'query': query,
                'profiles': profiles,
                'total_profiles': len(profiles)
            }
            
            print(f"{Fore.GREEN}[+] Found {len(profiles)} LinkedIn profiles for query: {query}{Style.RESET_ALL}")
            return results
            
        else:
            print(f"{Fore.RED}[!] Error: Received status code {response.status_code} from LinkedIn{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'Received status code {response.status_code} from LinkedIn'}
            
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error: Network error while searching LinkedIn - {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': str(e)}

def run_linkedin_search(query, output_file=None):
    """
    Run LinkedIn search and optionally save results to file.
    
    Args:
        query (str): The search query.
        output_file (str): Optional file to save results.
        
    Returns:
        dict: Search results.
    """
    results = search_linkedin_profiles(query)
    
    if results and results['status'] == 'success':
        # Save to file if requested
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"{Fore.BLUE}[+] Results saved to: {output_file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error saving results: {str(e)}{Style.RESET_ALL}")
    
    return results

def get_linkedin_company_info(company_name):
    """
    Get LinkedIn company information.
    
    Args:
        company_name (str): The company name to search for.
        
    Returns:
        dict: A dictionary containing company information.
    """
    print(f"{Fore.CYAN}[*] Searching LinkedIn for company: {company_name}{Style.RESET_ALL}")
    
    try:
        # LinkedIn company search URL
        url = f"https://www.linkedin.com/search/results/companies/?keywords={company_name.replace(' ', '%20')}"
        
        # Headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Send request to LinkedIn company search page
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract company information
            companies = []
            
            # Find company cards
            company_cards = soup.find_all('div', {'class': 'search-entity'})
            
            for card in company_cards[:5]:  # Limit to 5 companies
                try:
                    company_data = {}
                    
                    # Get company name
                    name_element = card.find('span', {'class': 'entity-result__title-text'})
                    if name_element:
                        company_data['name'] = name_element.get_text().strip()
                    
                    # Get company URL
                    link_element = card.find('a', {'class': 'app-aware-link'})
                    if link_element and link_element.get('href'):
                        # Extract company URL from the link
                        href = link_element.get('href')
                        if '/company/' in href:
                            company_data['company_url'] = href.split('?')[0]  # Remove query parameters
                    
                    # Get company description
                    desc_element = card.find('p', {'class': 'entity-result__summary'})
                    if desc_element:
                        company_data['description'] = desc_element.get_text().strip()
                    
                    if company_data:
                        companies.append(company_data)
                        
                except Exception as e:
                    continue
            
            results = {
                'status': 'success',
                'company_name': company_name,
                'companies': companies,
                'total_companies': len(companies)
            }
            
            print(f"{Fore.GREEN}[+] Found {len(companies)} LinkedIn companies for query: {company_name}{Style.RESET_ALL}")
            return results
            
        else:
            print(f"{Fore.RED}[!] Error: Received status code {response.status_code} from LinkedIn{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'Received status code {response.status_code} from LinkedIn'}
            
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error: Network error while searching LinkedIn companies - {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': str(e)}

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running LinkedIn searcher test...")
    
    # A test query for testing
    test_query = "security researcher"
    
    results = run_linkedin_search(
        query=test_query,
        output_file="output/linkedin_test.json"
    )
    
    if results and results['status'] == 'success':
        print("\nTest results:")
        print(f"  Query: {results['query']}")
        print(f"  Total profiles: {results['total_profiles']}")
        for profile in results['profiles'][:3]:  # Show first 3 profiles
            print(f"  Profile: {profile}")
    else:
        print("\nTest failed:", results)
