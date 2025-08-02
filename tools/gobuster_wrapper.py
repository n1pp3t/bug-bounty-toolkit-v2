#!/usr/bin/env python3
"""
GoBuster Wrapper Tool
This script provides a Python wrapper for executing GoBuster for directory, file, and DNS scanning.
"""

import subprocess
import os
from colorama import Fore, Style

def is_tool_installed(name):
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None

def run_gobuster_scan(mode, target, wordlist, output_file=None, extra_args=None):
    """
    Run a GoBuster scan with the specified mode and parameters.

    Args:
        mode (str): The GoBuster mode to use (e.g., 'dir', 'dns').
        target (str): The target URL or domain.
        wordlist (str): Path to the wordlist file.
        output_file (str, optional): Path to save the output file. Defaults to None.
        extra_args (list, optional): Optional list of additional arguments for GoBuster. Defaults to None.

    Returns:
        dict: A dictionary containing the status and results of the scan.
    """
    print(f"{Fore.CYAN}[*] Initializing GoBuster {mode} scan on {target}...{Style.RESET_ALL}")

    # 1. Check if GoBuster is installed
    if not is_tool_installed('gobuster'):
        print(f"{Fore.RED}[!] Error: GoBuster is not installed or not in the system's PATH.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Please install it from https://github.com/OJ/gobuster{Style.RESET_ALL}")
        return {'status': 'error', 'message': 'GoBuster not found.'}

    # 2. Validate wordlist
    if not os.path.exists(wordlist):
        return {'status': 'error', 'message': f"Wordlist not found: {wordlist}"}

    # 3. Construct the GoBuster command
    command = [
        'gobuster',
        mode,
        '-u' if mode == 'dir' else '-d', target,
        '-w', wordlist,
        '--no-progress', # Cleaner output for parsing
        '-q' # Don't print banner
    ]

    if output_file:
        command.extend(['-o', output_file])

    if extra_args:
        command.extend(extra_args)

    print(f"{Fore.BLUE}[+] Executing command: {' '.join(command)}{Style.RESET_ALL}")

    try:
        # 4. Execute the command
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        found_items = []
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                line = output.strip()
                print(line)
                if line and not line.startswith("[-]"):
                    found_items.append(line)
        
        process.wait()

        if process.returncode == 0:
            print(f"\n{Fore.GREEN}[+] GoBuster scan completed successfully.{Style.RESET_ALL}")
            return {'status': 'success', 'found_count': len(found_items), 'results': found_items, 'output_file': output_file}
        else:
            print(f"\n{Fore.RED}[!] GoBuster exited with error code: {process.returncode}{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'GoBuster exited with error code {process.returncode}.'}

    except FileNotFoundError:
        return {'status': 'error', 'message': 'GoBuster command not found.'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running GoBuster wrapper test...")
    # This test requires a running web server on localhost:8080 to find anything.
    # We will mainly test the command construction and execution flow.
    # A dummy wordlist is created for the test.
    
    with open('test_wordlist_gobuster.txt', 'w') as f:
        f.write("admin\n.git\nindex.html\n")

    results = run_gobuster_scan(
        mode='dir',
        target='http://localhost:8080',
        wordlist='test_wordlist_gobuster.txt'
    )
    
    print("\nTest results:", results)

    # Clean up dummy file
    if os.path.exists('test_wordlist_gobuster.txt'):
        os.remove('test_wordlist_gobuster.txt')
