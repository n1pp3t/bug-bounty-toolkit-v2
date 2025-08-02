#!/usr/bin/env python3
"""
OSINTGram Wrapper Tool
This script provides a Python wrapper for executing OSINTGram to gather Instagram OSINT data.
"""

import subprocess
import os
import json
from colorama import Fore, Style

def is_tool_installed(name):
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None

def run_osintgram(target_username, output_dir=None, session_file=None, extra_args=None):
    """
    Run OSINTGram for Instagram OSINT collection.
    
    Args:
        target_username (str): The Instagram username to investigate.
        output_dir (str): Optional directory to save results.
        session_file (str): Optional session file for authentication.
        extra_args (list): Optional list of additional arguments.
        
    Returns:
        dict: A dictionary containing the status and results of the scan.
    """
    print(f"{Fore.CYAN}[*] Initializing OSINTGram scan for Instagram user: {target_username}{Style.RESET_ALL}")

    # 1. Check if OSINTGram is installed
    if not is_tool_installed('osintgram'):
        print(f"{Fore.RED}[!] Error: OSINTGram is not installed or not in the system's PATH.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Please install it from: https://github.com/Datalux/Osintgram{Style.RESET_ALL}")
        return {'status': 'error', 'message': 'OSINTGram not found.'}

    # 2. Create output directory if specified
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        print(f"{Fore.BLUE}[+] Saving results to: {output_dir}{Style.RESET_ALL}")

    # 3. Construct the OSINTGram command
    command = ['osintgram', target_username]
    
    # Add session file if provided
    if session_file and os.path.exists(session_file):
        command.extend(['--session', session_file])
        print(f"{Fore.BLUE}[+] Using session file: {session_file}{Style.RESET_ALL}")
    
    # Add output directory if specified
    if output_dir:
        command.extend(['--output', output_dir])

    if extra_args:
        command.extend(extra_args)

    print(f"{Fore.BLUE}[+] Executing command: {' '.join(command)}{Style.RESET_ALL}")

    try:
        # 4. Execute the command
        # OSINTGram is interactive, so we'll capture the output
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        output_lines = []
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                line = output.strip()
                print(line)
                output_lines.append(line)
        
        process.wait()

        if process.returncode == 0:
            print(f"\n{Fore.GREEN}[+] OSINTGram scan completed successfully.{Style.RESET_ALL}")
            
            # Parse results if output directory was specified
            results = {
                'status': 'success',
                'username': target_username,
                'output_lines': output_lines
            }
            
            if output_dir:
                results['output_dir'] = output_dir
                
                # Look for JSON files in output directory
                json_files = []
                if os.path.exists(output_dir):
                    for file in os.listdir(output_dir):
                        if file.endswith('.json'):
                            json_files.append(file)
                
                if json_files:
                    results['json_files'] = json_files
            
            return results
        else:
            print(f"\n{Fore.RED}[!] OSINTGram exited with error code: {process.returncode}{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'OSINTGram exited with error code {process.returncode}.'}

    except FileNotFoundError:
        return {'status': 'error', 'message': 'OSINTGram command not found.'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def parse_osintgram_output(output_lines):
    """
    Parse OSINTGram output to extract structured information.
    
    Args:
        output_lines (list): List of output lines from OSINTGram.
        
    Returns:
        dict: Structured data extracted from the output.
    """
    parsed_data = {
        'profile_info': {},
        'followers': None,
        'following': None,
        'posts': None,
        'bio': None,
        'external_url': None,
        'is_private': None,
        'is_verified': None
    }
    
    # Process each line to extract information
    for line in output_lines:
        if 'Username:' in line:
            parsed_data['profile_info']['username'] = line.split('Username:')[-1].strip()
        elif 'Full Name:' in line:
            parsed_data['profile_info']['full_name'] = line.split('Full Name:')[-1].strip()
        elif 'ID:' in line:
            parsed_data['profile_info']['id'] = line.split('ID:')[-1].strip()
        elif 'Followers:' in line:
            try:
                parsed_data['followers'] = int(line.split('Followers:')[-1].strip())
            except:
                pass
        elif 'Following:' in line:
            try:
                parsed_data['following'] = int(line.split('Following:')[-1].strip())
            except:
                pass
        elif 'Posts:' in line:
            try:
                parsed_data['posts'] = int(line.split('Posts:')[-1].strip())
            except:
                pass
        elif 'Bio:' in line:
            parsed_data['bio'] = line.split('Bio:')[-1].strip()
        elif 'External URL:' in line:
            parsed_data['external_url'] = line.split('External URL:')[-1].strip()
        elif 'Private Account:' in line:
            parsed_data['is_private'] = 'Yes' in line.split('Private Account:')[-1].strip()
        elif 'Verified:' in line:
            parsed_data['is_verified'] = 'Yes' in line.split('Verified:')[-1].strip()
    
    return parsed_data

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running OSINTGram wrapper test...")
    
    # A test username for testing (replace with a real Instagram username for actual testing)
    test_username = "instagram"
    
    results = run_osintgram(
        target_username=test_username,
        output_dir="output/osintgram_test"
    )
    
    if results and results['status'] == 'success':
        print("\nTest results:", results)
    else:
        print("\nTest failed:", results)
