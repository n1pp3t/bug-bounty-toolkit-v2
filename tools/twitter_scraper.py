#!/usr/bin/env python3
"""
Twitter Scraper Tool
This script provides functionality to scrape public Twitter profile information.
"""

import requests
import json
import re
from bs4 import BeautifulSoup
from colorama import Fore, Style

def scrape_twitter_profile(username):
    """
    Scrape public Twitter profile information.
    
    Args:
        username (str): The Twitter username to scrape.
        
    Returns:
        dict: A dictionary containing profile information.
    """
    print(f"{Fore.CYAN}[*] Scraping Twitter profile for: {username}{Style.RESET_ALL}")
    
    try:
        # Twitter profile URL
        url = f"https://twitter.com/{username}"
        
        # Headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Send request to Twitter profile page
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract profile information
            profile_data = {}
            
            # Get profile name
            name_element = soup.find('h1', {'data-testid': 'UserName'})
            if name_element:
                profile_data['name'] = name_element.get_text().strip()
            
            # Get username (already known but let's verify)
            profile_data['username'] = username
            
            # Get bio
            bio_element = soup.find('div', {'data-testid': 'UserDescription'})
            if bio_element:
                profile_data['bio'] = bio_element.get_text().strip()
            
            # Get location
            location_element = soup.find('span', {'data-testid': 'UserLocation'})
            if location_element:
                profile_data['location'] = location_element.get_text().strip()
            
            # Get website
            website_element = soup.find('a', {'data-testid': 'UserUrl'})
            if website_element:
                profile_data['website'] = website_element.get('href')
            
            # Get join date
            join_date_element = soup.find('span', {'data-testid': 'UserJoinDate'})
            if join_date_element:
                profile_data['join_date'] = join_date_element.get_text().strip()
            
            # Get follower counts from meta tags
            followers_element = soup.find('a', {'href': f'/{username}/followers'})
            if followers_element:
                followers_text = followers_element.get_text().strip()
                profile_data['followers'] = followers_text
            
            following_element = soup.find('a', {'href': f'/{username}/following'})
            if following_element:
                following_text = following_element.get_text().strip()
                profile_data['following'] = following_text
            
            # Try to extract additional information from JSON data in script tag
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string and 'window.__INITIAL_STATE__' in script.string:
                    # Extract JSON data
                    try:
                        json_start = script.string.find('{"entities":')
                        json_end = script.string.find('};', json_start) + 1
                        if json_start != -1 and json_end != 0:
                            json_text = script.string[json_start:json_end]
                            data = json.loads(json_text)
                            
                            # Extract user data
                            user_data = data.get('entities', {}).get('users', {}).get('entities', {})
                            if user_data:
                                for user_id, user_info in user_data.items():
                                    if user_info.get('screen_name', '').lower() == username.lower():
                                        profile_data['verified'] = user_info.get('verified', False)
                                        profile_data['followers_count'] = user_info.get('followers_count')
                                        profile_data['following_count'] = user_info.get('following_count')
                                        profile_data['statuses_count'] = user_info.get('statuses_count')
                                        profile_data['favourites_count'] = user_info.get('favourites_count')
                                        profile_data['listed_count'] = user_info.get('listed_count')
                                        profile_data['media_count'] = user_info.get('media_count')
                                        break
                    except:
                        pass
            
            profile_data['status'] = 'success'
            profile_data['profile_url'] = url
            
            print(f"{Fore.GREEN}[+] Successfully scraped Twitter profile for {username}{Style.RESET_ALL}")
            return profile_data
            
        else:
            print(f"{Fore.RED}[!] Error: Received status code {response.status_code} from Twitter{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'Received status code {response.status_code} from Twitter'}
            
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error: Network error while scraping Twitter - {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': str(e)}

def run_twitter_scan(username, output_file=None):
    """
    Run Twitter scan and optionally save results to file.
    
    Args:
        username (str): The Twitter username to scan.
        output_file (str): Optional file to save results.
        
    Returns:
        dict: Scan results.
    """
    results = scrape_twitter_profile(username)
    
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

def search_twitter_hashtags(hashtag, limit=10):
    """
    Search Twitter for posts with a specific hashtag.
    
    Args:
        hashtag (str): The hashtag to search for (without #).
        limit (int): Maximum number of posts to retrieve.
        
    Returns:
        dict: Search results.
    """
    print(f"{Fore.CYAN}[*] Searching Twitter for hashtag: #{hashtag}{Style.RESET_ALL}")
    
    try:
        # Twitter search URL
        url = f"https://twitter.com/hashtag/{hashtag}"
        
        # Headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Send request to Twitter hashtag search
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract posts with hashtag
            posts = []
            post_elements = soup.find_all('article', {'data-testid': 'tweet'})
            
            for post_element in post_elements[:limit]:
                try:
                    post_data = {}
                    
                    # Get username
                    username_element = post_element.find('div', {'data-testid': 'User-Name'})
                    if username_element:
                        username_text = username_element.get_text().strip()
                        # Extract username from text like "Name @username"
                        username_match = re.search(r'@(\w+)', username_text)
                        if username_match:
                            post_data['username'] = username_match.group(1)
                    
                    # Get tweet text
                    tweet_text_element = post_element.find('div', {'data-testid': 'tweetText'})
                    if tweet_text_element:
                        post_data['text'] = tweet_text_element.get_text().strip()
                    
                    # Get timestamp
                    timestamp_element = post_element.find('time')
                    if timestamp_element:
                        post_data['timestamp'] = timestamp_element.get('datetime')
                    
                    # Get engagement metrics
                    engagement_elements = post_element.find_all('div', {'role': 'group'})
                    for engagement in engagement_elements:
                        aria_label = engagement.get('aria-label', '')
                        if 'replies' in aria_label:
                            post_data['replies'] = aria_label
                        elif 'retweets' in aria_label:
                            post_data['retweets'] = aria_label
                        elif 'likes' in aria_label:
                            post_data['likes'] = aria_label
                    
                    if post_data:
                        posts.append(post_data)
                        
                except Exception as e:
                    continue
            
            results = {
                'status': 'success',
                'hashtag': hashtag,
                'posts': posts,
                'total_posts': len(posts)
            }
            
            print(f"{Fore.GREEN}[+] Found {len(posts)} posts with hashtag #{hashtag}{Style.RESET_ALL}")
            return results
            
        else:
            print(f"{Fore.RED}[!] Error: Received status code {response.status_code} from Twitter{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'Received status code {response.status_code} from Twitter'}
            
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error: Network error while searching Twitter - {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        return {'status': 'error', 'message': str(e)}

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running Twitter scraper test...")
    
    # A test username for testing (replace with a real Twitter username for actual testing)
    test_username = "twitter"
    
    results = run_twitter_scan(
        username=test_username,
        output_file="output/twitter_test.json"
    )
    
    if results and results['status'] == 'success':
        print("\nTest results:")
        for key, value in results.items():
            print(f"  {key}: {value}")
    else:
        print("\nTest failed:", results)
