# SVG Security Analysis Toolkit - Tool Documentation

This toolkit contains specialized Python tools for analyzing potentially malicious SVG files and detecting security mechanisms.

## Overview

The toolkit consists of four main tools:

1. **extract.py** - Static analysis for obfuscated URL extraction
2. **extract_dynamic.py** - Dynamic analysis using box-js for JavaScript execution
3. **cf_probe.py** - Cloudflare protection detection (Turnstile, CAPTCHA, etc.)
4. **encoder.py** - Test case generator for creating obfuscated SVG samples

---

## Tool #1: extract.py - Static SVG URL Extractor

### Purpose
A pattern-based static analysis tool that decodes obfuscated URLs from malicious SVG files **without executing any code**. This is the safer option for initial analysis.

### Key Features
- **XOR Decoding**: Automatic detection and decoding of XOR-encrypted payloads
- **Character Arithmetic**: Decodes `String.fromCharCode` patterns with numeric calculations
- **Base64 Extraction**: Finds and decodes Base64-encoded URLs
- **Email Detection**: Identifies email addresses used in URL concatenation
- **Multiple Obfuscation Strategies**: Handles various deobfuscation techniques

### Usage
```bash
# Analyze a single SVG file
python3 extract.py -i malicious.svg

# Verbose output showing decoded JavaScript
python3 extract.py -i malicious.svg -v

# Debug mode with detailed analysis steps
python3 extract.py -i malicious.svg -d

# Read from stdin
python3 extract.py < malicious.svg
```

### Key Detection Patterns
1. **Secretkey XOR Pattern**: Detects `String.fromCharCode(115,101,99,...)` ("secretkey")
2. **XOR Loop Detection**: Identifies `for` loops with `parseInt` and XOR operations
3. **Data URI Scripts**: Extracts and decodes Base64 content from `data:` URIs
4. **Nested atob() + Variable**: Handles `atob("base64") + variableName` patterns

### Dependencies
- Python 3.6+ (uses only standard library)

### Example Output
```
DYNAMIC SVG URL EXTRACTOR
=========================================================
SVG #1 Results:
----------------------------------------
Obfuscation: XOR decoding (key length: 9)
Extracted URLs:
  → https://malicious.example.com/c2$victim@email.com
```

---

## Tool #2: extract_dynamic.py - Dynamic SVG JavaScript Analyzer

### Purpose
A sophisticated dynamic analysis tool that extracts and analyzes JavaScript embedded in SVG files using box-js. **This tool executes JavaScript in a sandboxed environment** and is designed to extract final, complete URLs even when built through complex obfuscation.

### Key Features
- **JavaScript Execution**: Uses box-js to safely execute SVG scripts
- **Advanced Hook System**: 300+ line JavaScript payload with comprehensive monitoring
- **URL Construction Tracking**: Captures URLs built dynamically through string concatenation
- **Final URL Prioritization**: Distinguishes between complete URLs and partial components
- **ActiveX/WScript Monitoring**: Specialized Windows script object detection
- **Multiple Sink Detection**: Monitors `location`, `window.open`, `fetch`, `XHR`, `Image.src`, etc.

### Dependencies
```bash
# Required: box-js must be installed globally
npm install -g box-js

# Python requirements (optional)
pip install -r requirements.txt
```

### Usage
```bash
# Basic analysis of a single SVG
python3 extract_dynamic.py -i malicious.svg

# Analyze with custom output directory
python3 extract_dynamic.py -i malicious.svg -o analysis_results

# Analyze directory of SVGs with extended timeout
python3 extract_dynamic.py -i svg_samples/ -t 60

# Keep temporary files for debugging
python3 extract_dynamic.py -i malicious.svg --keep-temp

# Save URL blocklist to file
python3 extract_dynamic.py -i malicious.svg --blocklist-out urls.txt

# Mask email addresses for privacy
python3 extract_dynamic.py -i malicious.svg --mask-emails
```

### Advanced Features

#### Hook System (PRELUDE_JS)
The tool injects a comprehensive JavaScript payload that hooks:
- **Location Operations**: `location.href`, `location.assign()`, `location.replace()`
- **Window Methods**: `window.open()`, navigation methods
- **HTTP Requests**: `fetch()`, `XMLHttpRequest.open()`
- **String Operations**: `String.prototype.concat`, string manipulation
- **Decoders**: `atob()`, `decodeURI()`, `unescape()`
- **Dynamic Execution**: `eval()`, `Function()`, `setTimeout()`

#### Pattern Recognition
Automatically detects and handles:
- Simple hex decoding patterns
- Hex-encoded dynamic execution
- XOR + dynamic eval construction
- Character mapping + find() execution
- Arithmetic character code patterns
- Common obfuscation techniques

### Example Output
```
=== Processing: malicious.svg ===
  Wrote temp JS -> /tmp/boxjs_svg_ABC/test.boxed.js
  Running box-js (timeout 30s) with sink hooks...
  [+] box-js finished. Results in: boxjs_out/malicious.svg.boxjs_results

  *** FINAL COMPLETE URLs FOUND ***:
    → https://evil.example.com/payload$victim@email.com
  
  Emails found:
    → victim@email.com

=== FINAL ANALYSIS SUMMARY ===
🎯 COMPLETE URLs EXTRACTED (1 total):
======================================================
  → https://evil.example.com/payload$victim@email.com
======================================================
```

---

## Tool #3: cf_probe.py - Cloudflare Protection Detection

### Purpose
A web reconnaissance tool for detecting Cloudflare security mechanisms including Turnstile, CAPTCHA systems, browser verification, and other protection measures across redirect chains.

### Key Features
- **Redirect Chain Following**: Automatically follows HTTP redirects and meta-refresh redirects
- **Multiple Detection Patterns**: Detects Turnstile through various methods
- **JavaScript File Scanning**: Analyzes linked JS files for additional sitekeys
- **Compression Support**: Handles gzip, deflate, and brotli compression
- **Comprehensive Protection Detection**: Identifies multiple Cloudflare protection types

### Dependencies
```bash
pip install requests
pip install brotli  # Optional for brotli support
```

### Usage
```bash
# Check single URL for Cloudflare protections
python3 cf_probe.py https://example.com

# Scan with JavaScript file analysis
python3 cf_probe.py https://example.com --scan-js

# Process multiple URLs from file
python3 cf_probe.py -i urls.txt

# Custom User-Agent and timeout
python3 cf_probe.py https://example.com -A "Custom-Agent" -t 30

# Disable TLS verification (for testing)
python3 cf_probe.py https://example.com --insecure

# Dump HTML/JS for analysis
python3 cf_probe.py https://example.com --dump analysis_dump/
```

### Detection Capabilities

#### Turnstile Detection
- `data-sitekey` attributes
- `turnstile.render()` JavaScript calls
- `turnstile.create()` JavaScript calls
- Turnstile API script references
- `cf-turnstile` CSS classes

#### Other Cloudflare Protection
- Custom CAPTCHA systems
- Browser verification pages
- CF challenge containers
- CF headers (CF-Ray, server headers)
- DDoS protection messages

### Example Output
```
=== Redirect/Navigation Chain (3 steps) ===

[0] URL: https://example.com
    Status: 301
    Cloudflare Protection: YES (CF Headers)
    CF Header: cf-ray: 123abc456def789

[1] URL: https://protected.example.com
    Status: 200
    Cloudflare Protection: YES (Turnstile, Custom CAPTCHA)
    Turnstile Site key(s): 0x1AAA000000000000000
    CAPTCHA Evidence: Click the computer to verify

=== Summary ===
Cloudflare Protection Detected: Turnstile with key(s): 0x1AAA000000000000000 | Custom CAPTCHA
```

---

## Tool #4: encoder.py - SVG Test Case Generator

### Purpose
Generates obfuscated SVG files with various encoding patterns for testing the analysis tools.

### Key Features
- **Multiple Obfuscation Patterns**: 6 different encoding techniques
- **Dynamic Variability**: Randomized variable names, structures, and encoding parameters
- **Realistic Test Data**: Generates random domains and email addresses
- **Batch Generation**: Can create complete test suites

### Usage
```bash
# Generate single pattern
python3 encoder.py -u "https://evil.com/c2" -p 1 -o test.svg

# Generate all patterns in directory
python3 encoder.py --random-all -o test_patterns/

# Custom email address
python3 encoder.py -u "https://evil.com" -e "victim@test.com" -p 3 -o custom.svg
```

### Obfuscation Patterns

1. **XOR + Proxy Pattern**: Enhanced XOR encoding with ES6 Proxy for execution
2. **Hex Function Pattern**: Hex-encoded dynamic execution via `Function` constructor
3. **Object Keys Pattern**: XOR + dynamic eval construction using object properties
4. **Character Mapping Pattern**: Character mapping with `Array.find()` execution
5. **Arithmetic Pattern**: Arithmetic character code evaluation
6. **Data URI Pattern**: Base64 encoded scripts in data URIs

### Example Output
```bash
$ python3 encoder.py --random-all -o test_suite/
Generated xor_proxy_enhanced: test_suite/pattern_01_xor_proxy_enhanced.svg
  URL: https://r4nd0m.example.com/malware$test123@fake.com

Generated hex_function: test_suite/pattern_02_hex_function.svg  
  URL: https://evil-site.org/payload$victim@target.net

[... 4 more patterns ...]
```

---

## Testing Workflow

### Recommended Analysis Workflow:
```bash
# Step 1: Generate test cases
python3 encoder.py --random-all -o test_cases/

# Step 2: Static analysis first (safer)
python3 extract.py -i test_cases/pattern_01_*.svg -v > static_results.txt

# Step 3: Dynamic analysis (in isolated environment)
python3 extract_dynamic.py -i test_cases/ -o dynamic_results/ --blocklist-out malicious_urls.txt

# Step 4: Verify Cloudflare protection on extracted URLs (if safe to do so)
python3 cf_probe.py -i malicious_urls.txt
```

## Installation

```bash
# Clone or download the toolkit
cd svg_tools/

# Install Python dependencies
pip install -r requirements.txt

# Install box-js globally (for dynamic analysis)
npm install -g box-js

# Verify installation
python3 extract.py --help
python3 extract_dynamic.py --help
python3 cf_probe.py --help
python3 encoder.py --help
```
