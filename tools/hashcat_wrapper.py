#!/usr/bin/env python3
"""
Hashcat Wrapper Tool
This script provides a Python wrapper for executing Hashcat commands to perform password cracking attacks.
"""

import subprocess
import os
from colorama import Fore, Style

def is_tool_installed(name):
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None

def run_hashcat_attack(hash_file, hash_type, wordlist, output_file, attack_mode=0, extra_args=None):
    """
    Run a Hashcat attack with specified parameters.
    
    Args:
        hash_file (str): Path to the file containing hashes.
        hash_type (int): The Hashcat hash type code.
        wordlist (str): Path to the wordlist file.
        output_file (str): Path to the output file for cracked hashes.
        attack_mode (int): Hashcat attack mode (default: 0, Straight).
        extra_args (list): Optional list of additional arguments for Hashcat.
        
    Returns:
        dict: A dictionary containing the status and results of the attack.
    """
    print(f"{Fore.CYAN}[*] Initializing Hashcat attack...{Style.RESET_ALL}")

    # 1. Check if Hashcat is installed
    if not is_tool_installed('hashcat'):
        print(f"{Fore.RED}[!] Error: Hashcat is not installed or not in the system's PATH.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Please install it from https://hashcat.net/hashcat/{Style.RESET_ALL}")
        return {'status': 'error', 'message': 'Hashcat not found.'}

    # 2. Validate input files
    if not os.path.exists(hash_file):
        return {'status': 'error', 'message': f"Hash file not found: {hash_file}"}
    if not os.path.exists(wordlist):
        return {'status': 'error', 'message': f"Wordlist not found: {wordlist}"}

    # 3. Construct the Hashcat command
    command = [
        'hashcat',
        '-m', str(hash_type),
        '-a', str(attack_mode),
        hash_file,
        wordlist,
        '-o', output_file,
        '--force'  # Use --force to suppress warnings and run
    ]

    if extra_args:
        command.extend(extra_args)

    print(f"{Fore.BLUE}[+] Executing command: {' '.join(command)}{Style.RESET_ALL}")

    try:
        # 4. Execute the command
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # Stream output in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                # Print Hashcat's output, but remove excessive newlines
                print(output.strip())

        # Wait for the process to complete
        process.wait()

        if process.returncode == 0 or process.returncode == 1:  # Hashcat exits with 1 on success sometimes
            print(f"\n{Fore.GREEN}[+] Hashcat attack completed successfully.{Style.RESET_ALL}")
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    cracked_hashes = f.read().splitlines()
                print(f"{Fore.GREEN}    Cracked {len(cracked_hashes)} hash(es). See '{output_file}' for details.{Style.RESET_ALL}")
                return {'status': 'success', 'cracked_count': len(cracked_hashes), 'output_file': output_file}
            else:
                print(f"{Fore.YELLOW}    No hashes were cracked in this session.{Style.RESET_ALL}")
                return {'status': 'success', 'cracked_count': 0, 'output_file': output_file}
        else:
            print(f"\n{Fore.RED}[!] Hashcat exited with error code: {process.returncode}{Style.RESET_ALL}")
            return {'status': 'error', 'message': f'Hashcat exited with error code {process.returncode}.'}

    except FileNotFoundError:
        # This is a fallback, though is_tool_installed should catch it.
        return {'status': 'error', 'message': 'Hashcat command not found.'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running Hashcat wrapper test...")
    # Create dummy files for testing
    if not os.path.exists('test_hashes.txt'):
        with open('test_hashes.txt', 'w') as f:
            f.write("21232f297a57a5a743894a0e4a801fc3\n") # MD5 for "admin"
    if not os.path.exists('test_wordlist.txt'):
        with open('test_wordlist.txt', 'w') as f:
            f.write("admin\npassword\n123456\n")

    results = run_hashcat_attack(
        hash_file='test_hashes.txt',
        hash_type=0, # MD5
        wordlist='test_wordlist.txt',
        output_file='cracked.txt'
    )
    print("\nTest results:", results)

    # Clean up dummy files
    if os.path.exists('test_hashes.txt'):
        os.remove('test_hashes.txt')
    if os.path.exists('test_wordlist.txt'):
        os.remove('test_wordlist.txt')
    if os.path.exists('cracked.txt'):
        os.remove('cracked.txt')
