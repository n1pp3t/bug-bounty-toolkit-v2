#!/usr/bin/env python3
"""
Phone Number Validator Tool
This script provides functionality to validate and gather information about phone numbers.
"""

import re
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from colorama import Fore, Style

def validate_phone_number(phone_number, region=None):
    """
    Validate a phone number and gather information about it.
    
    Args:
        phone_number (str): The phone number to validate.
        region (str): Optional region code (e.g., 'US', 'GB').
        
    Returns:
        dict: A dictionary containing validation results and information.
    """
    print(f"{Fore.CYAN}[*] Validating phone number: {phone_number}{Style.RESET_ALL}")
    
    try:
        # Parse the phone number
        if region:
            parsed_number = phonenumbers.parse(phone_number, region)
        else:
            # Try to parse without region (assuming it's in international format)
            parsed_number = phonenumbers.parse(phone_number, None)
        
        # Validate the phone number
        is_valid = phonenumbers.is_valid_number(parsed_number)
        is_possible = phonenumbers.is_possible_number(parsed_number)
        
        if not is_valid:
            return {
                'status': 'invalid',
                'phone_number': phone_number,
                'is_possible': is_possible,
                'message': 'Invalid phone number'
            }
        
        # Gather information about the phone number
        results = {
            'status': 'valid',
            'phone_number': phone_number,
            'is_valid': is_valid,
            'is_possible': is_possible,
            'country_code': parsed_number.country_code,
            'national_number': parsed_number.national_number,
            'formatted_international': phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'formatted_national': phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL),
            'formatted_e164': phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
        }
        
        # Get country information
        try:
            country = geocoder.description_for_number(parsed_number, "en")
            results['country'] = country
        except:
            results['country'] = 'Unknown'
        
        # Get carrier information
        try:
            carrier_name = carrier.name_for_number(parsed_number, "en")
            results['carrier'] = carrier_name
        except:
            results['carrier'] = 'Unknown'
        
        # Get timezone information
        try:
            timezones = timezone.time_zones_for_number(parsed_number)
            results['timezones'] = list(timezones)
        except:
            results['timezones'] = []
        
        # Get number type
        try:
            number_type = phonenumbers.number_type(parsed_number)
            number_type_names = {
                0: 'Fixed line',
                1: 'Mobile',
                2: 'Fixed line or mobile',
                3: 'Toll free',
                4: 'Premium rate',
                5: 'Shared cost',
                6: 'VOIP',
                7: 'Personal number',
                8: 'Pager',
                9: 'UAN',
                10: 'Voicemail',
                20: 'Unknown'
            }
            results['number_type'] = number_type_names.get(number_type, 'Unknown')
        except:
            results['number_type'] = 'Unknown'
        
        print(f"{Fore.GREEN}[+] Phone number is valid: {results['formatted_international']}{Style.RESET_ALL}")
        return results
        
    except phonenumbers.NumberParseException as e:
        return {
            'status': 'error',
            'phone_number': phone_number,
            'message': f'Parse error: {str(e)}'
        }
    except Exception as e:
        return {
            'status': 'error',
            'phone_number': phone_number,
            'message': str(e)
        }

def format_phone_number(phone_number, format_type='international'):
    """
    Format a phone number in a specific format.
    
    Args:
        phone_number (str): The phone number to format.
        format_type (str): Format type ('international', 'national', 'e164', 'rfc3966').
        
    Returns:
        dict: A dictionary containing the formatted phone number.
    """
    try:
        # Parse the phone number
        parsed_number = phonenumbers.parse(phone_number, None)
        
        # Format based on type
        if format_type == 'international':
            formatted = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        elif format_type == 'national':
            formatted = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)
        elif format_type == 'e164':
            formatted = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
        elif format_type == 'rfc3966':
            formatted = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.RFC3966)
        else:
            formatted = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        
        return {
            'status': 'success',
            'original': phone_number,
            'formatted': formatted,
            'format_type': format_type
        }
        
    except phonenumbers.NumberParseException as e:
        return {
            'status': 'error',
            'phone_number': phone_number,
            'message': f'Parse error: {str(e)}'
        }
    except Exception as e:
        return {
            'status': 'error',
            'phone_number': phone_number,
            'message': str(e)
        }

def validate_phone_list(phone_list, region=None, output_file=None):
    """
    Validate a list of phone numbers.
    
    Args:
        phone_list (list): List of phone numbers to validate.
        region (str): Optional region code for parsing.
        output_file (str): Optional file to save results.
        
    Returns:
        dict: Validation results for all phone numbers.
    """
    print(f"{Fore.CYAN}[*] Validating {len(phone_list)} phone numbers{Style.RESET_ALL}")
    
    results = {
        'total_numbers': len(phone_list),
        'valid_numbers': [],
        'invalid_numbers': [],
        'errors': []
    }
    
    for i, phone in enumerate(phone_list, 1):
        print(f"{Fore.BLUE}[+] Validating phone {i}/{len(phone_list)}: {phone}{Style.RESET_ALL}")
        
        result = validate_phone_number(phone, region)
        
        if result['status'] == 'valid':
            results['valid_numbers'].append(result)
        elif result['status'] == 'invalid':
            results['invalid_numbers'].append(result)
        else:
            results['errors'].append(result)
    
    # Summary
    print(f"{Fore.GREEN}[+] Validation complete:{Style.RESET_ALL}")
    print(f"    Valid numbers: {len(results['valid_numbers'])}")
    print(f"    Invalid numbers: {len(results['invalid_numbers'])}")
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

def extract_phone_numbers(text):
    """
    Extract phone numbers from text using regex patterns.
    
    Args:
        text (str): Text to search for phone numbers.
        
    Returns:
        dict: A dictionary containing extracted phone numbers.
    """
    print(f"{Fore.CYAN}[*] Extracting phone numbers from text{Style.RESET_ALL}")
    
    # Common phone number patterns
    patterns = [
        r'\+?1?[ -]?\(?[0-9]{3}\)?[ -]?[0-9]{3}[ -]?[0-9]{4}',  # US format
        r'\+?[0-9]{1,3}[ -]?[0-9]{1,4}[ -]?[0-9]{1,4}[ -]?[0-9]{1,9}',  # International format
        r'\+?[0-9]{1,3}[0-9]{1,14}',  # E.164 format
    ]
    
    extracted_numbers = []
    
    for pattern in patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            # Clean up the match
            clean_match = re.sub(r'[^\d\+]', '', match)
            if clean_match not in extracted_numbers:
                extracted_numbers.append(clean_match)
    
    # Validate extracted numbers
    valid_numbers = []
    for number in extracted_numbers:
        result = validate_phone_number(number)
        if result['status'] == 'valid':
            valid_numbers.append(result)
    
    results = {
        'status': 'success',
        'total_extracted': len(extracted_numbers),
        'total_valid': len(valid_numbers),
        'extracted_numbers': extracted_numbers,
        'valid_numbers': valid_numbers
    }
    
    print(f"{Fore.GREEN}[+] Extracted {len(extracted_numbers)} potential phone numbers, {len(valid_numbers)} are valid{Style.RESET_ALL}")
    return results

if __name__ == '__main__':
    # Example usage for direct execution and testing
    print("Running phone validator test...")
    
    # Test phone numbers
    test_numbers = [
        "+14155552671",  # Valid US number
        "+442071838750",  # Valid UK number
        "invalid-number",  # Invalid
        "+33123456789"   # Valid French number
    ]
    
    results = validate_phone_list(
        phone_list=test_numbers,
        output_file="output/phone_validation_test.json"
    )
    
    print("\nTest results summary:")
    print(f"  Total numbers: {results['total_numbers']}")
    print(f"  Valid numbers: {len(results['valid_numbers'])}")
    print(f"  Invalid numbers: {len(results['invalid_numbers'])}")
    print(f"  Errors: {len(results['errors'])}")
