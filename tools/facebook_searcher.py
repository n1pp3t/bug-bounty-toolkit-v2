#!/usr/bin/env python3
"""
Facebook Searcher Tool
This script provides functionality to search for Facebook profiles and pages.
"""

import requests
import json
import re
from bs4 import BeautifulSoup
from colorama import Fore, Style

def search_facebook_profiles(query, limit=10):
    """
    Search Facebook for profiles/pages matching a query.
    
    Args:
        query (str): The search query (name, page, etc.).
        limit (int): Maximum number of results to retrieve.
        
    Returns:
        dict: A dictionary containing search results.
    """
    print(f"{Fore.CYAN}[*] Searching Facebook for: {query}{Style.RESET_ALL}")
    
    try:
        # Facebook search URL
        url = f"https://www.facebook.com/public/{query.replace(' ', '%20')}"
        
        # Headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Send request to Facebook search page
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract profile information
            profiles = []
            
            # Find profile cards (this is a simplified approach as Facebook's structure changes frequently)
            profile_cards = soup.find_all('div', {'data-sigil': 'mfeed_pivots_message feed-story-highlight-candidate'})
            
            for card in profile_cards[:limit]:
                try:
                    profile_data = {}
                    
                    # Get profile name
                    name_element = card.find('h3')
                    if name_element:
                        profile_data['name'] = name_element.get_text().strip()
                    
                    # Get profile URL
                    link_element = card.find('a')
                    if link_element and link_element.get('href'):
                        href = link_element.get('href')
                        if href.startswith('/'):
                            profile_data['profile_url'] = f"https://www.facebook.com{href}"
                        else:
                            profile_data['profile_url'] = href
                    
                    # Get profile image
                    img_element = card.find('img')
                    if img_element and img_element.get('src'):
                        profile_data['profile_image'] = img_element.get('src')
                    
                    if profile_data:
                        profiles.append(profile_data)
                        
                except Exception as e:
                    continue
            
            # Alternative approach for public profiles
            if not profiles:
                # Look for any links that might be profiles
                links = soup.find_all('a', href=True)
                for link in links[:limit*2]:  # Check more links
                    try:
                        href = link.get('href')
                        if href and '/people/' in href and 'profile.php' not in href:
                            profile_data = {}
                            profile_data['profile_url'] = f"https://www.facebook.com{href}"
                            
                            # Get name from link text
                            name = link.get_text().strip()
                            if name and len(name) > 1:
                                profile_data['name'] = name
                                profiles.append(profile_data)
                                
                            if len(profiles) >= limit:
                                break
                    except:
                        continue
            
            results = {
                'status': 'success',
                'query': query,
                'profiles': profiles[:limit],
                'total_profiles': len(profiles[:limit])
            }
            
            print(f"{Fore.GREEN}[+] Found {len(profiles[:limit])} Facebook profiles for query: {query}{Style.RESET_ALL}")
            return results
            
        else:
            print(f"{Fore.RED}[!] Error: Received status code {response.status_code} from Facebook{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'Received status code {response.status_code} from Facebook'}
            
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error: Network error while searching Facebook - {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': str(e)}

def run_facebook_search(query, output_file=None):
    """
    Run Facebook search and optionally save results to file.
    
    Args:
        query (str): The search query.
        output_file (str): Optional file to save results.
        
    Returns:
        dict: Search results.
    """
    results = search_facebook_profiles(query)
    
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

def get_facebook_page_info(page_url):
    """
    Get information about a Facebook page.
    
    Args:
        page_url (str): The URL of the Facebook page.
        
    Returns:
        dict: A dictionary containing page information.
    """
    print(f"{Fore.CYAN}[*] Getting Facebook page info for: {page_url}{Style.RESET_ALL}")
    
    try:
        # Ensure URL is properly formatted
        if not page_url.startswith('http'):
            page_url = f"https://www.facebook.com/{page_url}"
        
        # Headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Send request to Facebook page
        response = requests.get(page_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract page information
            page_data = {}
            
            # Get page title
            title_element = soup.find('title')
            if title_element:
                page_data['title'] = title_element.get_text().strip()
            
            # Get page description
            desc_element = soup.find('meta', {'name': 'description'})
            if desc_element:
                page_data['description'] = desc_element.get('content')
            
            # Get page image
            img_element = soup.find('meta', {'property': 'og:image'})
            if img_element:
                page_data['page_image'] = img_element.get('content')
            
            # Get page URL
            url_element = soup.find('meta', {'property': 'og:url'})
            if url_element:
                page_data['page_url'] = url_element.get('content')
            
            # Try to extract additional information from JSON data in script tag
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string and 'PageHeaderProfileInfo' in script.string:
                    # Extract JSON data
                    try:
                        # This is a simplified approach - Facebook's structure is complex
                        page_data['page_type'] = 'Facebook Page'
                        break
                    except:
                        pass
            
            page_data['status'] = 'success'
            page_data['scraped_url'] = page_url
            
            print(f"{Fore.GREEN}[+] Successfully scraped Facebook page info{Style.RESET_ALL}")
            return page_data
            
        else:
            print(f"{Fore.RED}[!] Error: Received status code {response.status_code} from Facebook{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'Received status code {response.status_code} from Facebook'}
            
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error: Network error while scraping Facebook page - {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': str(e)}

def search_facebook_groups(query, limit=5):
    """
    Search Facebook for groups matching a query.
    
    Args:
        query (str): The search query for groups.
        limit (int): Maximum number of groups to retrieve.
        
    Returns:
        dict: A dictionary containing group search results.
    """
    print(f"{Fore.CYAN}[*] Searching Facebook groups for: {query}{Style.RESET_ALL}")
    
    try:
        # Facebook groups search URL (public groups)
        url = f"https://www.facebook.com/search/groups/?q={query.replace(' ', '%20')}"
        
        # Headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Send request to Facebook groups search page
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract group information
            groups = []
            
            # Find group cards (this is a simplified approach)
            group_cards = soup.find_all('div', {'role': 'article'})
            
            for card in group_cards[:limit]:
                try:
                    group_data = {}
                    
                    # Get group name
                    name_element = card.find('span')
                    if name_element:
                        group_data['name'] = name_element.get_text().strip()
                    
                    # Get group URL
                    link_element = card.find('a')
                    if link_element and link_element.get('href'):
                        href = link_element.get('href')
                        if href.startswith('/groups/'):
                            group_data['group_url'] = f"https://www.facebook.com{href}"
                    
                    if group_data:
                        groups.append(group_data)
                        
                except Exception as e:
                    continue
            
            results = {
                'status': 'success',
                'query': query,
                'groups': groups,
                'total_groups': len(groups)
            }
            
            print(f"{Fore.GREEN}[+] Found {len(groups)} Facebook groups for query: {query}{Style.RESET_ALL}")
            return results
            
        else:
            print(f"{Fore.RED}[!] Error: Received status code {response.status_code} from Facebook{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'Received status code {response.status_code} from Facebook'}
            
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error: Network error while searching Facebook groups - {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': str(e)}

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running Facebook searcher test...")
    
    # A test query for testing
    test_query = "security"
    
    results = run_facebook_search(
        query=test_query,
        output_file="output/facebook_test.json"
    )
    
    if results and results['status'] == 'success':
        print("\nTest results:")
        print(f"  Query: {results['query']}")
        print(f"  Total profiles: {results['total_profiles']}")
        for profile in results['profiles'][:3]:  # Show first 3 profiles
            print(f"  Profile: {profile}")
    else:
        print("\nTest failed:", results)
