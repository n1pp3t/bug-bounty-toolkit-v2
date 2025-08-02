#!/usr/bin/env python3
"""
Sherlock Wrapper Tool
This script provides a Python wrapper for executing Sherlock to find social media accounts by username.
"""

import subprocess
import os
from colorama import Fore, Style

def is_tool_installed(name):
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None

def run_sherlock_scan(username, output_file=None, timeout=60, extra_args=None):
    """
    Run a Sherlock scan for a specific username.
    
    Args:
        username (str): The username to search for.
        output_file (str): Optional path to save the report. If None, results are not saved to a file.
        timeout (int): Timeout in seconds for the Sherlock scan.
        extra_args (list): Optional list of additional arguments for Sherlock.
        
    Returns:
        dict: A dictionary containing the status and results of the scan.
    """
    print(f"{Fore.CYAN}[*] Initializing Sherlock scan for username: {username}{Style.RESET_ALL}")

    # 1. Check if Sherlock is installed
    if not is_tool_installed('sherlock'):
        print(f"{Fore.RED}[!] Error: Sherlock is not installed or not in the system's PATH.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Please install it via pip: 'pip install sherlock-project'{Style.RESET_ALL}")
        return {'status': 'error', 'message': 'Sherlock not found.'}

    # 2. Construct the Sherlock command
    command = [
        'sherlock',
        username,
        '--timeout', str(timeout),
        '--print-found' # Only print found accounts to stdout
    ]

    # If an output file is specified, Sherlock will save a text report there
    if output_file:
        # Ensure the output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        command.extend(['-o', output_file])
        print(f"{Fore.BLUE}[+] Saving report to: {output_file}{Style.RESET_ALL}")


    if extra_args:
        command.extend(extra_args)

    print(f"{Fore.BLUE}[+] Executing command: {' '.join(command)}{Style.RESET_ALL}")

    try:
        # 3. Execute the command
        # We stream the output to show progress in real-time
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        found_accounts = []
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                line = output.strip()
                print(line)
                # Capture found accounts from standard output
                if "[+]" in line and "http" in line:
                    found_accounts.append(line)
        
        process.wait()

        if process.returncode == 0:
            print(f"\n{Fore.GREEN}[+] Sherlock scan completed successfully.{Style.RESET_ALL}")
            result = {'status': 'success', 'found_count': len(found_accounts), 'accounts': found_accounts}
            if output_file and os.path.exists(output_file):
                result['output_file'] = output_file
            return result
        else:
            print(f"\n{Fore.RED}[!] Sherlock exited with error code: {process.returncode}{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'Sherlock exited with error code {process.returncode}.'}

    except FileNotFoundError:
        return {'status': 'error', 'message': 'Sherlock command not found.'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running Sherlock wrapper test...")
    
    # A well-known username for testing
    test_username = "nasa"
    output_filename = "sherlock_nasa_report.txt"
    
    results = run_sherlock_scan(
        username=test_username,
        output_file=output_filename
    )
    
    print("\nTest results:", results)

    # Clean up dummy file
    if os.path.exists(output_filename):
        os.remove(output_filename)
