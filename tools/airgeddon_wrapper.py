#!/usr/bin/env python3
"""
Airgeddon Wrapper Tool
This script provides a Python wrapper for launching the Airgeddon script for WiFi hacking.
"""

import subprocess
from colorama import Fore, Style

def is_tool_installed(name):
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None

def run_airgeddon():
    """
    Launches the Airgeddon script.
    
    Returns:
        dict: A dictionary containing the status of the launch attempt.
    """
    print(f"{Fore.CYAN}[*] Initializing Airgeddon...{Style.RESET_ALL}")

    # 1. Check if Airgeddon is installed
    if not is_tool_installed('airgeddon'):
        print(f"{Fore.RED}[!] Error: airgeddon is not installed or not in the system's PATH.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Please install it from https://github.com/v1s1t0r1sh3r3/airgeddon{Style.RESET_ALL}")
        return {'status': 'error', 'message': 'Airgeddon not found.'}

    print(f"{Fore.BLUE}[+] Launching Airgeddon. Please follow the on-screen instructions.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}    Note: This will open an interactive session. The toolkit will resume once Airgeddon is closed.{Style.RESET_ALL}")

    try:
        # 2. Execute the Airgeddon script
        # We run it directly, allowing it to take over the terminal
        process = subprocess.run(['airgeddon'])

        if process.returncode == 0:
            print(f"\n{Fore.GREEN}[+] Airgeddon session finished.{Style.RESET_ALL}")
            return {'status': 'success'}
        else:
            print(f"\n{Fore.RED}[!] Airgeddon exited with a non-zero status code: {process.returncode}{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'Airgeddon exited with code {process.returncode}'}
            
    except FileNotFoundError:
        # This is a fallback
        return {'status': 'error', 'message': 'Airgeddon command not found.'}
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred while running Airgeddon: {e}{Style.RESET_ALL}")
        return {'status': 'error', 'message': str(e)}

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running Airgeddon wrapper test...")
    results = run_airgeddon()
    print("\nTest results:", results)
