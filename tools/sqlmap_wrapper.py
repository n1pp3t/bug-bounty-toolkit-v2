#!/usr/bin/env python3
"""
SQLMap Wrapper Tool
This script provides a Python wrapper for executing SQLMap for automated SQL injection and database takeover.
"""

import subprocess
import os
from colorama import Fore, Style

def is_tool_installed(name):
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None

def run_sqlmap_scan(target_url, output_dir=None, level=1, risk=1, extra_args=None):
    """
    Run an SQLMap scan on a given URL.

    Args:
        target_url (str): The URL to scan, including parameters (e.g., "http://testphp.vulnweb.com/listproducts.php?cat=1").
        output_dir (str, optional): Directory to save SQLMap session files. Defaults to None.
        level (int, optional): The level of tests to perform (1-5). Defaults to 1.
        risk (int, optional): The risk of tests to perform (1-3). Defaults to 1.
        extra_args (list, optional): Optional list of additional arguments for SQLMap. Defaults to None.

    Returns:
        dict: A dictionary containing the status and results of the scan.
    """
    print(f"{Fore.CYAN}[*] Initializing SQLMap scan on {target_url}...{Style.RESET_ALL}")

    # 1. Check if SQLMap is installed
    if not is_tool_installed('sqlmap'):
        print(f"{Fore.RED}[!] Error: SQLMap is not installed or not in the system's PATH.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Please install it from http://sqlmap.org/{Style.RESET_ALL}")
        return {'status': 'error', 'message': 'SQLMap not found.'}

    # 2. Construct the SQLMap command
    command = [
        'sqlmap',
        '-u', target_url,
        '--batch',  # Never ask for user input, use default behavior
        '--level', str(level),
        '--risk', str(risk)
    ]

    if output_dir:
        # SQLMap uses this directory to store session files, logs, and results
        os.makedirs(output_dir, exist_ok=True)
        command.extend(['--output-dir', output_dir])

    if extra_args:
        command.extend(extra_args)

    print(f"{Fore.BLUE}[+] Executing command: {' '.join(command)}{Style.RESET_ALL}")

    try:
        # 3. Execute the command
        # SQLMap can be very verbose, so we capture and print its output
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

        vulnerabilities_found = []
        for line in iter(process.stdout.readline, ''):
            print(line, end='')
            if "is vulnerable" in line or "seems to be injectable" in line:
                vulnerabilities_found.append(line.strip())
        
        process.wait()

        if process.returncode == 0:
            print(f"\n{Fore.GREEN}[+] SQLMap scan completed.{Style.RESET_ALL}")
            if vulnerabilities_found:
                print(f"{Fore.YELLOW}    [!] Potential vulnerabilities found!{Style.RESET_ALL}")
                return {'status': 'success', 'vulnerable': True, 'details': vulnerabilities_found, 'output_dir': output_dir}
            else:
                print(f"{Fore.GREEN}    No obvious vulnerabilities were found with the current settings.{Style.RESET_ALL}")
                return {'status': 'success', 'vulnerable': False, 'output_dir': output_dir}
        else:
            print(f"\n{Fore.RED}[!] SQLMap exited with a non-zero status code: {process.returncode}{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'SQLMap exited with code {process.returncode}.'}

    except FileNotFoundError:
        return {'status': 'error', 'message': 'SQLMap command not found.'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running SQLMap wrapper test...")
    # NOTE: This test uses a publicly available test site. Use with caution and for educational purposes only.
    
    test_target = "http://testphp.vulnweb.com/listproducts.php?cat=1"
    
    results = run_sqlmap_scan(
        target_url=test_target,
        output_dir="output/sqlmap_test",
        level=1,
        risk=1
    )
    
    print("\nTest results:", results)
