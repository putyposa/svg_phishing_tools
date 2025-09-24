#!/usr/bin/env python3
"""
Dynamic SVG URL Extractor - Decodes obfuscated URLs from malicious SVG files
Uses pattern recognition instead of hardcoded variable names
"""

import re
import sys
import argparse
import base64

def identify_hex_strings(content):
    """
    Find all potential hex strings in the content
    Returns dict with variable names as keys and hex strings as values
    """
    hex_vars = {}
    
    # Pattern to find any variable assignment with a long hex string
    pattern = r'(?:var|const|let)\s+(\w+)\s*=\s*["\']([0-9a-fA-F]{24,})["\']'
    matches = re.findall(pattern, content)
    
    for var_name, hex_value in matches:
        hex_vars[var_name] = hex_value
    
    return hex_vars

def find_xor_decode_pattern(content):
    """
    Find XOR decoding patterns in the JavaScript
    Returns list of (hex_data, xor_key) tuples
    """
    results = []
    
    # Find all hex string variables
    hex_strings = {}
    hex_pattern = r'(?:var|const|let)\s+(\w+)\s*=\s*["\']([0-9a-fA-F]+)["\']'
    for match in re.finditer(hex_pattern, content):
        var_name = match.group(1)
        hex_value = match.group(2)
        hex_strings[var_name] = hex_value
    
    # Strategy 1: Look for specific secretkey pattern
    if 'String.fromCharCode(115,101,99,114,101,116,107,101,121)' in content:
        # This decodes to "secretkey"
        for var_name, hex_val in hex_strings.items():
            if len(hex_val) > 100:  # Long hex string
                results.append((hex_val, 'secretkey'))
                break
    
    # Strategy 2: Look for XOR loop patterns and pair long/short hex strings
    if not results and re.search(r'for\s*\([^)]+\)[^{]*\{[^}]*parseInt[^}]*\^[^}]*\}', content):
        long_hex = []
        short_hex = []
        
        for var_name, hex_val in hex_strings.items():
            if len(hex_val) > 100:
                long_hex.append(hex_val)
            elif 16 <= len(hex_val) <= 50:
                short_hex.append(hex_val)
        
        # Pair each long with each short (try all combinations)
        for long in long_hex:
            for short in short_hex:
                results.append((long, short))
    
    # Strategy 3: General pairing of long and short hex strings
    if not results:
        long_hex = []
        short_hex = []
        
        for var_name, hex_val in hex_strings.items():
            if len(hex_val) > 100:
                long_hex.append(hex_val)
            elif 16 <= len(hex_val) <= 50:
                short_hex.append(hex_val)
        
        if long_hex and short_hex:
            results.append((long_hex[0], short_hex[0]))
    
    return results

def decode_hex_xor(hex_string, xor_key):
    """
    Decode a hex string XORed with a key
    """
    result = ""
    key_index = 0
    
    for i in range(0, len(hex_string), 2):
        if i + 1 < len(hex_string):
            byte_val = int(hex_string[i:i+2], 16)
            key_char = ord(xor_key[key_index % len(xor_key)])
            result += chr(byte_val ^ key_char)
            key_index += 1
    
    return result

def find_character_arithmetic(content):
    """
    Find patterns where characters are built using arithmetic
    """
    results = []
    
    # Find object definitions with numeric properties
    obj_pattern = r'(?:var|const|let)\s+(\w+)\s*=\s*\{([^}]+)\}'
    obj_matches = re.findall(obj_pattern, content)
    
    for obj_name, obj_content in obj_matches:
        props = {}
        prop_pattern = r'(\w+)\s*:\s*(\d+)'
        for prop_name, prop_value in re.findall(prop_pattern, obj_content):
            props[prop_name] = int(prop_value)
        
        # Look for String.fromCharCode using this object
        fromchar_pattern = rf'String\.fromCharCode\s*\([^)]*{obj_name}[^)]+\)'
        if re.search(fromchar_pattern, content):
            decoded = ""
            char_usage = re.findall(rf'{obj_name}\.(\w+)\s*\+\s*{obj_name}\.(\w+)', content)
            for prop1, prop2 in char_usage:
                if prop1 in props and prop2 in props:
                    decoded += chr(props[prop1] + props[prop2])
            
            if decoded:
                results.append(f"Character arithmetic decoded: {decoded}")
    
    return results

def extract_urls_from_decoded(decoded_text):
    """
    Extract URLs from decoded JavaScript
    """
    urls = []
    
    # Method 1: Array join pattern for URLs
    array_pattern = r'fetch\s*\(\s*\[((?:["\'][^"\']*["\'],?\s*)+)\]\.join'
    match = re.search(array_pattern, decoded_text)
    if match:
        chars = re.findall(r'["\']([^"\']*)["\']', match.group(1))
        if chars:
            url = ''.join(chars)
            if url.startswith('http') and 'w3.org' not in url:
                urls.append(url)
    
    # Method 2: Base64 encoded URLs with concatenation
    atob_pattern = r'atob\s*\(((?:[\'"`][^\'"`]+[\'"`][\s+]*)+)\)'
    for match in re.finditer(atob_pattern, decoded_text):
        parts = re.findall(r'[\'"`]([^\'"`]+)[\'"`]', match.group(1))
        if parts:
            try:
                b64_string = ''.join(parts)
                decoded_url = base64.b64decode(b64_string).decode('utf-8', errors='ignore')
                if decoded_url.startswith('http') and 'w3.org' not in decoded_url.lower():
                    urls.append(decoded_url)
            except:
                pass
    
    # Method 3: Direct URLs (excluding w3.org)
    url_pattern = r'https?://[^\s\'"<>{}|\\^`\[\])]+'
    for url in re.findall(url_pattern, decoded_text):
        if 'w3.org' not in url.lower() and url not in urls:
            urls.append(url)
    
    return urls

def find_data_uri_base64(content):
    """
    Find and decode base64 content from data: URIs in script src attributes
    """
    results = []
    
    # Pattern: <script src="data:...;base64,<base64content>"></script>
    data_uri_pattern = r'<script[^>]+src=["\']data:[^;]+;base64,([^"\']+)["\']'
    
    for match in re.finditer(data_uri_pattern, content):
        b64_content = match.group(1)
        try:
            # Fix base64 padding if needed
            missing_padding = len(b64_content) % 4
            if missing_padding:
                b64_content += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(b64_content).decode('utf-8', errors='ignore')
            if args.debug:
                print(f"  Decoded data URI script: {decoded[:100]}...")
            results.append(decoded)
        except Exception as e:
            if args.debug:
                print(f"  Failed to decode data URI: {e}")
    
    return results

def extract_nested_atob_urls(js_content, email_vars):
    """
    Extract URLs from nested atob() calls with variable concatenation
    Pattern: atob("base64") + variableName
    """
    urls = []
    
    # Pattern: atob("base64string") + variableName
    pattern = r'atob\s*\(\s*["\']([^"\']+)["\']\s*\)\s*\+\s*(\w+)'
    
    for match in re.finditer(pattern, js_content):
        b64_string = match.group(1)
        var_name = match.group(2)
        
        try:
            # Fix base64 padding if needed
            missing_padding = len(b64_string) % 4
            if missing_padding:
                b64_string += '=' * (4 - missing_padding)
            
            decoded_base = base64.b64decode(b64_string).decode('utf-8', errors='ignore')
            if args.debug:
                print(f"  Decoded atob base: {decoded_base}")
                print(f"  Variable to append: {var_name}")
            
            # Check if variable is in our email vars
            if var_name in email_vars:
                full_url = decoded_base + email_vars[var_name]
                if full_url.startswith('http'):
                    urls.append(full_url)
                    if args.debug:
                        print(f"  Constructed URL: {full_url}")
                        
        except Exception as e:
            if args.debug:
                print(f"  Failed to decode nested atob: {e}")
    
    return urls

def find_email_variables(content):
    """
    Find email addresses in variable assignments
    """
    emails = {}
    # Multiple patterns to catch different email variable formats
    patterns = [
        r'(?:var|const|let)\s+(\w+)\s*=\s*["\']?\$?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']?',
        r'(\w+)\s*=\s*["\']?\$?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']?'
    ]
    
    for pattern in patterns:
        for match in re.finditer(pattern, content):
            var_name = match.group(1)
            email = match.group(2)
            emails[var_name] = email
    
    if args.debug and emails:
        print(f"Found email variables:")
        for var_name, email in emails.items():
            print(f"  {var_name}: ${email}")
    
    return emails

def check_email_usage(decoded_text, email_vars):
    """
    Check if email variables are used in the decoded content
    """
    if args.debug and email_vars:
        print(f"  Checking for email usage in decoded content...")
        print(f"  Email variables to check: {list(email_vars.keys())}")
    
    for var_name, email in email_vars.items():
        # Check various concatenation patterns
        patterns = [
            f'+{var_name}',
            f'+ {var_name}',
            f'){var_name}',
            f') {var_name}',
            f'+ {var_name};',
            f'+{var_name};',
            f'){var_name};',
            f') + {var_name}'
        ]
        for pattern in patterns:
            if pattern in decoded_text:
                if args.debug:
                    print(f"  Found email usage: {pattern}")
                return var_name, email
    
    if args.debug:
        print(f"  No email concatenation found in decoded content")
    
    return None, None

def analyze_svg(svg_content):
    """
    Dynamically analyze SVG and extract obfuscated URLs
    """
    results = []
    
    # Find email variables
    email_vars = find_email_variables(svg_content)
    
    # Method 1: Check for data: URI base64 scripts (new pattern from Check8028_Approval.svg)
    data_uri_scripts = find_data_uri_base64(svg_content)
    for script_content in data_uri_scripts:
        if args.debug:
            print(f"  Processing data URI script content...")
        
        # Look for nested atob() + variable patterns
        nested_urls = extract_nested_atob_urls(script_content, email_vars)
        if nested_urls:
            results.append({
                'type': 'Data URI + nested atob() + variable concatenation',
                'decoded': script_content,
                'urls': nested_urls,
                'email_info': None
            })
        else:
            # Fall back to regular URL extraction
            urls = extract_urls_from_decoded(script_content)
            if urls:
                results.append({
                    'type': 'Data URI base64 script',
                    'decoded': script_content,
                    'urls': urls,
                    'email_info': None
                })
    
    # Method 2: Find XOR patterns (existing functionality)
    xor_patterns = find_xor_decode_pattern(svg_content)
    
    for hex_data, xor_key in xor_patterns:
        try:
            decoded = decode_hex_xor(hex_data, xor_key)
            urls = extract_urls_from_decoded(decoded)
            
            # Check if email is used
            email_var, email_value = check_email_usage(decoded, email_vars)
            
            # If email is used, append it to URLs to show the complete URL
            if email_var and email_value:
                updated_urls = []
                for url in urls:
                    # Only append if not already included
                    if email_value not in url:
                        # Create the complete URL as it would be constructed
                        updated_urls.append(f"{url}${email_value}")
                    else:
                        updated_urls.append(url)
                urls = updated_urls
            
            if urls or 'location' in decoded:
                result = {
                    'type': f'XOR decoding (key length: {len(xor_key)})',
                    'decoded': decoded,
                    'urls': urls,
                    'email_info': {'var': email_var, 'value': email_value} if email_var else None
                }
                results.append(result)
        except Exception as e:
            pass
    
    # Method 3: Find character arithmetic patterns
    char_results = find_character_arithmetic(svg_content)
    for char_result in char_results:
        results.append({
            'type': 'Character arithmetic',
            'decoded': char_result,
            'urls': [],
            'email_info': None
        })
    
    return results

def main():
    """
    Main function
    """
    global args
    
    parser = argparse.ArgumentParser(description='Dynamic SVG URL Extractor')
    parser.add_argument('-i', '--input', help='Input SVG file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show decoded JavaScript')
    parser.add_argument('-d', '--debug', action='store_true', help='Show debug information')
    
    args = parser.parse_args()
    
    # Read input
    if args.input:
        try:
            with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    else:
        print("Paste SVG content (Ctrl+D when done):")
        content = sys.stdin.read()
    
    if not content.strip():
        print("No content provided")
        sys.exit(1)
    
    # Process SVGs
    svg_parts = re.split(r'(?=<\?xml)', content)
    
    print("\n" + "="*60)
    print("DYNAMIC SVG URL EXTRACTOR")
    print("="*60)
    
    all_urls = []
    svg_count = 0
    
    for part in svg_parts:
        if '<svg' not in part.lower():
            continue
        
        svg_count += 1
        
        if args.debug:
            print(f"\nDEBUG - SVG #{svg_count} Analysis:")
            print("-" * 40)
            
            hex_vars = identify_hex_strings(part)
            if hex_vars:
                print("Found hex variables:")
                for var_name, hex_val in hex_vars.items():
                    print(f"  {var_name}: {hex_val[:50]}... (length: {len(hex_val)})")
            
            email_vars = find_email_variables(part)
            if email_vars:
                print("Found email variables:")
                for var_name, email in email_vars.items():
                    print(f"  {var_name}: ${email}")
            
            xor_patterns = find_xor_decode_pattern(part)
            if xor_patterns:
                print(f"Found {len(xor_patterns)} XOR pattern(s)")
        
        results = analyze_svg(part)
        
        if results:
            print(f"\nSVG #{svg_count} Results:")
            print("-" * 40)
            
            for result in results:
                print(f"Obfuscation: {result['type']}")
                
                if result['urls']:
                    print("Extracted URLs:")
                    for url in result['urls']:
                        if 'w3.org' not in url.lower():
                            print(f"  → {url}")
                            all_urls.append(url)
                elif 'decoded' in result and 'location' in result.get('decoded', ''):
                    print("  [Found location redirect but couldn't extract URL - use -v flag]")
                
                if args.verbose and 'decoded' in result:
                    print("\nDecoded JavaScript:")
                    clean = str(result['decoded']).replace('\x00', '').strip()
                    if len(clean) > 300:
                        if 'location' in clean:
                            start = max(0, clean.find('location') - 20)
                            end = min(len(clean), start + 200)
                            print(f"  ...{clean[start:end]}...")
                        else:
                            print(f"  {clean[:300]}...")
                    else:
                        print(f"  {clean}")
        else:
            print(f"\nSVG #{svg_count}: No patterns detected")
    
    if all_urls:
        print("\n" + "="*60)
        print("ALL EXTRACTED URLs:")
        print("="*60)
        seen = set()
        for url in all_urls:
            if url not in seen and 'w3.org' not in url.lower():
                print(f"  • {url}")
                seen.add(url)
        print("\n")
    else:
        print("\nNo malicious URLs extracted. Use -d flag for debug output.")

if __name__ == "__main__":
    main()
