#!/usr/bin/env python3
"""
Email Verifier Tool
This script provides functionality to verify email addresses and check their validity.
"""

import re
import dns.resolver
import smtplib
import socket
from colorama import Fore, Style

def validate_email_format(email):
    """
    Validate email format using regex.
    
    Args:
        email (str): The email address to validate.
        
    Returns:
        bool: True if email format is valid, False otherwise.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def check_mx_record(domain):
    """
    Check if a domain has MX records.
    
    Args:
        domain (str): The domain to check.
        
    Returns:
        dict: A dictionary containing MX record information.
    """
    try:
        # Query MX records
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record_list = []
        
        for record in mx_records:
            mx_record_list.append({
                'priority': record.preference,
                'exchange': str(record.exchange)
            })
        
        return {
            'status': 'success',
            'has_mx_records': True,
            'mx_records': mx_record_list
        }
    except dns.resolver.NoAnswer:
        return {
            'status': 'error',
            'has_mx_records': False,
            'message': 'No MX records found'
        }
    except dns.resolver.NXDOMAIN:
        return {
            'status': 'error',
            'has_mx_records': False,
            'message': 'Domain does not exist'
        }
    except Exception as e:
        return {
            'status': 'error',
            'has_mx_records': False,
            'message': str(e)
        }

def verify_email_exists(email, smtp_timeout=10):
    """
    Verify if an email address exists by connecting to the mail server.
    
    Args:
        email (str): The email address to verify.
        smtp_timeout (int): Timeout for SMTP connection.
        
    Returns:
        dict: A dictionary containing verification results.
    """
    print(f"{Fore.CYAN}[*] Verifying email existence: {email}{Style.RESET_ALL}")
    
    try:
        # Extract domain from email
        domain = email.split('@')[1]
        
        # Check MX records
        mx_result = check_mx_record(domain)
        
        if not mx_result['has_mx_records']:
            return {
                'status': 'invalid',
                'email': email,
                'message': 'No MX records found for domain',
                'details': mx_result
            }
        
        # Get the highest priority MX record
        mx_records = sorted(mx_result['mx_records'], key=lambda x: x['priority'])
        mx_server = mx_records[0]['exchange']
        
        # Try to connect to the mail server
        try:
            # Create SMTP connection
            server = smtplib.SMTP(timeout=smtp_timeout)
            server.connect(mx_server)
            
            # Say hello to the server
            server.helo('verify.example.com')
            
            # Try to verify the email address
            # Note: Many servers don't support VRFY command for privacy reasons
            try:
                code, message = server.verify(email)
                server.quit()
                
                if code == 250:
                    return {
                        'status': 'valid',
                        'email': email,
                        'message': 'Email address verified',
                        'smtp_code': code,
                        'smtp_message': str(message)
                    }
                else:
                    # Try RCPT TO method
                    server.mail('verify@example.com')
                    code, message = server.rcpt(email)
                    server.quit()
                    
                    if code == 250:
                        return {
                            'status': 'valid',
                            'email': email,
                            'message': 'Email address accepted by server',
                            'smtp_code': code,
                            'smtp_message': str(message)
                        }
                    else:
                        return {
                            'status': 'unknown',
                            'email': email,
                            'message': 'Could not verify email existence (server may not support verification)',
                            'smtp_code': code,
                            'smtp_message': str(message)
                        }
            except:
                # If VRFY fails, try RCPT TO method
                server.mail('verify@example.com')
                code, message = server.rcpt(email)
                server.quit()
                
                if code == 250:
                    return {
                        'status': 'valid',
                        'email': email,
                        'message': 'Email address accepted by server',
                        'smtp_code': code,
                        'smtp_message': str(message)
                    }
                else:
                    return {
                        'status': 'unknown',
                        'email': email,
                        'message': 'Could not verify email existence (server may not support verification)',
                        'smtp_code': code,
                        'smtp_message': str(message)
                    }
                    
        except Exception as e:
            return {
                'status': 'error',
                'email': email,
                'message': f'Could not connect to mail server: {str(e)}'
            }
            
    except Exception as e:
        return {
            'status': 'error',
            'email': email,
            'message': str(e)
        }

def run_email_verification(email, check_existence=True):
    """
    Run email verification.
    
    Args:
        email (str): The email address to verify.
        check_existence (bool): Whether to check if email exists on server.
        
    Returns:
        dict: Verification results.
    """
    print(f"{Fore.CYAN}[*] Verifying email: {email}{Style.RESET_ALL}")
    
    # 1. Validate email format
    is_valid_format = validate_email_format(email)
    
    if not is_valid_format:
        return {
            'status': 'invalid',
            'email': email,
            'message': 'Invalid email format'
        }
    
    # 2. Check domain validity
    domain = email.split('@')[1]
    try:
        socket.gethostbyname(domain)
        domain_valid = True
    except:
        domain_valid = False
    
    if not domain_valid:
        return {
            'status': 'invalid',
            'email': email,
            'message': 'Domain does not exist'
        }
    
    # 3. Check MX records
    mx_result = check_mx_record(domain)
    
    if not mx_result['has_mx_records']:
        return {
            'status': 'invalid',
            'email': email,
            'message': 'No MX records found for domain',
            'details': mx_result
        }
    
    # 4. Check email existence if requested
    if check_existence:
        existence_result = verify_email_exists(email)
        return existence_result
    else:
        return {
            'status': 'valid_format',
            'email': email,
            'message': 'Email format is valid and domain exists',
            'details': mx_result
        }

def verify_email_list(email_list, output_file=None):
    """
    Verify a list of email addresses.
    
    Args:
        email_list (list): List of email addresses to verify.
        output_file (str): Optional file to save results.
        
    Returns:
        dict: Verification results for all emails.
    """
    print(f"{Fore.CYAN}[*] Verifying {len(email_list)} email addresses{Style.RESET_ALL}")
    
    results = {
        'total_emails': len(email_list),
        'verified_emails': [],
        'invalid_emails': [],
        'unknown_emails': [],
        'errors': []
    }
    
    for i, email in enumerate(email_list, 1):
        print(f"{Fore.BLUE}[+] Verifying email {i}/{len(email_list)}: {email}{Style.RESET_ALL}")
        
        result = run_email_verification(email)
        
        if result['status'] == 'valid' or result['status'] == 'valid_format':
            results['verified_emails'].append(result)
        elif result['status'] == 'invalid':
            results['invalid_emails'].append(result)
        elif result['status'] == 'unknown':
            results['unknown_emails'].append(result)
        else:
            results['errors'].append(result)
    
    # Summary
    print(f"{Fore.GREEN}[+] Verification complete:{Style.RESET_ALL}")
    print(f"    Valid emails: {len(results['verified_emails'])}")
    print(f"    Invalid emails: {len(results['invalid_emails'])}")
    print(f"    Unknown emails: {len(results['unknown_emails'])}")
    print(f"    Errors: {len(results['errors'])}")
    
    # Save to file if requested
    if output_file:
        try:
            import json
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.BLUE}[+] Results saved to: {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {str(e)}{Style.RESET_ALL}")
    
    return results

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running email verifier test...")
    
    # Test email addresses
    test_emails = [
        "test@example.com",
        "invalid.email",
        "user@gmail.com",
        "noreply@github.com"
    ]
    
    results = verify_email_list(
        email_list=test_emails,
        output_file="output/email_verification_test.json"
    )
    
    print("\nTest results summary:")
    print(f"  Total emails: {results['total_emails']}")
    print(f"  Valid emails: {len(results['verified_emails'])}")
    print(f"  Invalid emails: {len(results['invalid_emails'])}")
    print(f"  Unknown emails: {len(results['unknown_emails'])}")
    print(f"  Errors: {len(results['errors'])}")
