#!/usr/bin/env python3
"""
Instagram Scraper Tool
This script provides functionality to scrape public Instagram profile information.
"""

import requests
import json
import re
from bs4 import BeautifulSoup
from colorama import Fore, Style

def scrape_instagram_profile(username):
    """
    Scrape public Instagram profile information.
    
    Args:
        username (str): The Instagram username to scrape.
        
    Returns:
        dict: A dictionary containing profile information.
    """
    print(f"{Fore.CYAN}[*] Scraping Instagram profile for: {username}{Style.RESET_ALL}")
    
    try:
        # Instagram profile URL
        url = f"https://www.instagram.com/{username}/"
        
        # Headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Send request to Instagram profile page
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract profile information from meta tags
            profile_data = {}
            
            # Get profile picture
            profile_pic = soup.find('meta', property='og:image')
            if profile_pic:
                profile_data['profile_picture'] = profile_pic.get('content')
            
            # Get profile description
            description = soup.find('meta', property='og:description')
            if description:
                desc_text = description.get('content')
                profile_data['description'] = desc_text
                
                # Extract followers, following, posts from description
                followers_match = re.search(r'([0-9,.KMB]+) Followers', desc_text)
                following_match = re.search(r'([0-9,.KMB]+) Following', desc_text)
                posts_match = re.search(r'([0-9,.KMB]+) Posts', desc_text)
                
                if followers_match:
                    profile_data['followers'] = followers_match.group(1)
                if following_match:
                    profile_data['following'] = following_match.group(1)
                if posts_match:
                    profile_data['posts'] = posts_match.group(1)
            
            # Get profile name
            profile_name = soup.find('meta', property='og:title')
            if profile_name:
                profile_data['name'] = profile_name.get('content').replace(' on Instagram', '')
            
            # Try to extract additional information from JSON data in script tag
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string and 'window._sharedData' in script.string:
                    # Extract JSON data
                    json_text = script.string.replace('window._sharedData = ', '')[:-1]
                    try:
                        data = json.loads(json_text)
                        user_data = data.get('entry_data', {}).get('ProfilePage', [{}])[0].get('graphql', {}).get('user', {})
                        
                        if user_data:
                            profile_data['is_private'] = user_data.get('is_private', False)
                            profile_data['is_verified'] = user_data.get('is_verified', False)
                            profile_data['external_url'] = user_data.get('external_url')
                            profile_data['bio'] = user_data.get('biography')
                            profile_data['followed_by'] = user_data.get('edge_followed_by', {}).get('count')
                            profile_data['follows'] = user_data.get('edge_follow', {}).get('count')
                            profile_data['total_posts'] = user_data.get('edge_owner_to_timeline_media', {}).get('count')
                    except:
                        pass
            
            profile_data['status'] = 'success'
            profile_data['username'] = username
            profile_data['profile_url'] = url
            
            print(f"{Fore.GREEN}[+] Successfully scraped Instagram profile for {username}{Style.RESET_ALL}")
            return profile_data
            
        else:
            print(f"{Fore.RED}[!] Error: Received status code {response.status_code} from Instagram{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'Received status code {response.status_code} from Instagram'}
            
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error: Network error while scraping Instagram - {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': str(e)}

def format_instagram_number(num_str):
    """
    Format Instagram number strings (e.g., '1.2M' -> 1200000).
    
    Args:
        num_str (str): Number string from Instagram.
        
    Returns:
        int: Formatted number.
    """
    if not num_str:
        return 0
    
    # Remove commas
    num_str = num_str.replace(',', '')
    
    # Handle K (thousands), M (millions), B (billions)
    if 'K' in num_str:
        return int(float(num_str.replace('K', '')) * 1000)
    elif 'M' in num_str:
        return int(float(num_str.replace('M', '')) * 1000000)
    elif 'B' in num_str:
        return int(float(num_str.replace('B', '')) * 1000000000)
    else:
        try:
            return int(num_str)
        except:
            return 0

def run_instagram_scan(username, output_file=None):
    """
    Run Instagram scan and optionally save results to file.
    
    Args:
        username (str): The Instagram username to scan.
        output_file (str): Optional file to save results.
        
    Returns:
        dict: Scan results.
    """
    results = scrape_instagram_profile(username)
    
    if results and results['status'] == 'success':
        # Format numbers
        if 'followers' in results:
            results['followers_count'] = format_instagram_number(results['followers'])
        if 'following' in results:
            results['following_count'] = format_instagram_number(results['following'])
        if 'posts' in results:
            results['posts_count'] = format_instagram_number(results['posts'])
        
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
    print("Running Instagram scraper test...")
    
    # A test username for testing (replace with a real Instagram username for actual testing)
    test_username = "instagram"
    
    results = run_instagram_scan(
        username=test_username,
        output_file="output/instagram_test.json"
    )
    
    if results and results['status'] == 'success':
        print("\nTest results:")
        for key, value in results.items():
            print(f"  {key}: {value}")
    else:
        print("\nTest failed:", results)
