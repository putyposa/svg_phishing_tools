#!/usr/bin/env python3
from __future__ import annotations
import argparse
import gzip
import os
import re
import sys
import zlib
from typing import List, Tuple, Set
from urllib.parse import urljoin, urlparse

import requests

# Optional brotli (pip install brotli or brotlicffi)
try:
    import brotli  # type: ignore
except Exception:
    brotli = None

TURNSTILE_HOST_FRAG = "challenges.cloudflare.com/turnstile"

# --- Regexes ---
RGX_DATA_SITEKEY = re.compile(r'data-sitekey=["\']([^"\']+)["\']', re.I)
RGX_CF_CLASS = re.compile(r'class=["\'][^"\']*\bcf-turnstile\b[^"\']*["\']', re.I)
RGX_RENDER_SITEKEY = re.compile(r'turnstile\.render\([^)]*?sitekey\s*:\s*["\']([^"\']+)["\']', re.I | re.S)
RGX_CREATE_SITEKEY = re.compile(r'turnstile\.create\([^)]*?sitekey\s*:\s*["\']([^"\']+)["\']', re.I | re.S)
RGX_APIJS_SITEKEY = re.compile(
    r'<script[^>]+src=["\']https?://[^"\']*?/turnstile/[^"\']*?/api\.js[^"\']*["\'][^>]*?data-sitekey=["\']([^"\']+)["\']',
    re.I | re.S
)
RGX_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
RGX_META_REFRESH = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*?content=["\']\s*\d+\s*;\s*url=([^"\']+)["\']',
    re.I
)

def parse_header_kv(h: str) -> Tuple[str, str]:
    if ":" not in h:
        raise argparse.ArgumentTypeError("Header must be 'Key: Value'")
    k, v = h.split(":", 1)
    return k.strip(), v.strip()

def read_body(resp: requests.Response) -> str:
    raw = resp.content or b""
    enc = (resp.headers.get("Content-Encoding") or "").lower().strip()
    try:
        if enc == "br" and brotli:
            raw = brotli.decompress(raw)
        elif enc == "gzip":
            raw = gzip.decompress(raw)
        elif enc == "deflate":
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        pass
    encoding = resp.encoding or getattr(resp, "apparent_encoding", None) or "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except Exception:
        return raw.decode("utf-8", errors="replace")

def detect_cloudflare_protection(html: str, headers: dict = None) -> dict:
    """
    Detect various Cloudflare protection mechanisms including Turnstile,
    custom CAPTCHAs, and other challenge types.
    
    Returns a dict with detected protection types and evidence.
    """
    result = {
        'turnstile': {'found': False, 'sitekeys': set(), 'evidence': []},
        'custom_captcha': {'found': False, 'evidence': []},
        'cf_challenge': {'found': False, 'evidence': []},
        'cf_headers': {'found': False, 'evidence': []},
        'other_protection': {'found': False, 'evidence': []}
    }
    
    if not html:
        html = ""
    
    # 1. Detect Turnstile
    sitekeys, evidence = set(), []
    for rgx, label in [
        (RGX_DATA_SITEKEY, "data-sitekey"),
        (RGX_RENDER_SITEKEY, "turnstile.render"),
        (RGX_CREATE_SITEKEY, "turnstile.create"),
        (RGX_APIJS_SITEKEY, "api.js data-sitekey"),
    ]:
        hits = rgx.findall(html)
        if hits:
            uniq = sorted(set(hits))
            sitekeys.update(uniq)
            evidence.append(f"{label}: {', '.join(uniq)}")
    
    host_present = TURNSTILE_HOST_FRAG in html
    cf_class_present = bool(RGX_CF_CLASS.search(html))
    
    if sitekeys or host_present or cf_class_present:
        result['turnstile']['found'] = True
        result['turnstile']['sitekeys'] = sitekeys
        result['turnstile']['evidence'] = evidence
        if host_present and not sitekeys:
            result['turnstile']['evidence'].append("turnstile script present (no explicit sitekey)")
        if cf_class_present and not sitekeys:
            result['turnstile']['evidence'].append("cf-turnstile container present (no explicit sitekey)")
    
    # 2. Detect Custom CAPTCHA (emoji-based, human verification, etc.)
    captcha_indicators = [
        (r'CAPTCHA\s*Verification', 'CAPTCHA Verification text found'),
        (r'Human\s*Verification', 'Human Verification text found'),
        (r'Click\s*the\s*(computer|phone|book|chart|printer|pen|file|binder)', 'Emoji CAPTCHA pattern detected'),
        (r'custom-captcha-resp', 'Custom CAPTCHA response field found'),
        (r'generateCaptcha|humanSignalsPass|setVerifiedUI', 'CAPTCHA JavaScript functions detected'),
        (r'Click\s*the\s*box\s*to\s*verify', 'Click-to-verify CAPTCHA detected'),
        (r'honeypot|hp_field', 'Honeypot field detected (bot protection)'),
    ]
    
    for pattern, desc in captcha_indicators:
        if re.search(pattern, html, re.I):
            result['custom_captcha']['found'] = True
            result['custom_captcha']['evidence'].append(desc)
    
    # 3. Detect Cloudflare Challenge Pages
    cf_challenge_indicators = [
        (r'cf-browser-verification', 'Cloudflare browser verification'),
        (r'cf-captcha-container', 'Cloudflare CAPTCHA container'),
        (r'cf_clearance', 'Cloudflare clearance cookie'),
        (r'Checking your browser', 'Browser check message'),
        (r'DDoS protection by Cloudflare', 'DDoS protection message'),
        (r'Ray ID:\s*[a-f0-9]{16}', 'Cloudflare Ray ID in page'),
        (r'cloudflare-static/email-decode', 'Cloudflare email obfuscation'),
    ]
    
    for pattern, desc in cf_challenge_indicators:
        if re.search(pattern, html, re.I):
            result['cf_challenge']['found'] = True
            result['cf_challenge']['evidence'].append(desc)
    
    # 4. Check Headers for Cloudflare indicators
    if headers:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check for Cloudflare server header
        if 'server' in headers_lower and 'cloudflare' in headers_lower['server'].lower():
            result['cf_headers']['found'] = True
            result['cf_headers']['evidence'].append(f"Cloudflare server header: {headers_lower['server']}")
        
        # Check for CF-Ray header
        if 'cf-ray' in headers_lower:
            result['cf_headers']['found'] = True
            result['cf_headers']['evidence'].append(f"CF-Ray ID: {headers_lower['cf-ray']}")
        
        # Check for other CF headers
        cf_header_prefixes = ['cf-', 'report-to', 'nel', 'alt-svc']
        for header, value in headers_lower.items():
            for prefix in cf_header_prefixes:
                if header.startswith(prefix):
                    result['cf_headers']['found'] = True
                    result['cf_headers']['evidence'].append(f"{header}: {value[:100]}...")
                    break
    
    # 5. Detect other protection mechanisms
    other_indicators = [
        (r'laravel_session', 'Laravel session cookie (application framework)'),
        (r'XSRF-TOKEN', 'XSRF token present (CSRF protection)'),
        (r'tailwindcss|Tailwind', 'Tailwind CSS framework detected'),
        (r'Poppins|googleapis.*fonts', 'Google Fonts usage detected'),
    ]
    
    for pattern, desc in other_indicators:
        if re.search(pattern, html, re.I):
            result['other_protection']['found'] = True
            result['other_protection']['evidence'].append(desc)
    
    return result

def detect_turnstile(html: str) -> Tuple[bool, Set[str], List[str]]:
    """Legacy function for backward compatibility - calls new detection function"""
    detection = detect_cloudflare_protection(html)
    return (
        detection['turnstile']['found'],
        detection['turnstile']['sitekeys'],
        detection['turnstile']['evidence']
    )


def get_chain(session: requests.Session, start_url: str, max_hops: int, timeout: int):
    chain = []
    current = start_url
    seen = set()
    for _ in range(max_hops):
        if current in seen:
            break
        seen.add(current)
        r = session.get(current, allow_redirects=False, timeout=timeout)
        body = read_body(r)
        chain.append({"url": r.url, "status": r.status_code, "headers": dict(r.headers), "text": body})
        if r.is_redirect or r.is_permanent_redirect:
            loc = r.headers.get("Location")
            if not loc:
                break
            current = urljoin(r.url, loc)
            continue
        meta = extract_meta_refresh_url(r.url, body)
        if meta and meta != r.url:
            current = meta
            continue
        break
    return chain


def scan_linked_js(session: requests.Session, page_url: str, html: str, timeout: int, dump_dir: str | None):
    sitekeys, evidence, scanned = set(), [], set()
    for src in RGX_SCRIPT_SRC.findall(html or ""):
        abs_src = urljoin(page_url, src.strip())
        if abs_src in scanned:
            continue
        scanned.add(abs_src)
        if not same_origin(page_url, abs_src):
            continue
        try:
            r = session.get(abs_src, timeout=timeout)
            js = read_body(r)
        except requests.RequestException:
            continue
        if dump_dir:
            fn = os.path.join(dump_dir, f"asset_js_{len(scanned)}.js")
            try:
                with open(fn, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(js)
            except Exception:
                pass
        for rgx, label in [(RGX_RENDER_SITEKEY, "turnstile.render(JS)"),
                           (RGX_CREATE_SITEKEY, "turnstile.create(JS)"),
                           (RGX_DATA_SITEKEY, "data-sitekey(JS)")]:
            hits = rgx.findall(js)
            if hits:
                uniq = sorted(set(hits))
                sitekeys.update(uniq)
                evidence.append(f"{label} in {abs_src}: {', '.join(uniq)}")
        if TURNSTILE_HOST_FRAG in js:
            evidence.append(f"{TURNSTILE_HOST_FRAG} referenced in {abs_src}")
    return sitekeys, evidence

def main():
    ap = argparse.ArgumentParser(description="Probe URLs for Cloudflare protections including Turnstile, CAPTCHA, and other security mechanisms across redirects.")
    ap.add_argument("url", nargs="?", help="Single URL to check (quote/escape $, !, `)")
    ap.add_argument("-i", "--input", help="File containing list of URLs (one per line)")
    ap.add_argument("--user-agent", "-A", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", 
                    help="User-Agent (default: Windows 11 Chrome)")
    ap.add_argument("--timeout", "-t", type=int, default=20, help="Per-request timeout seconds")
    ap.add_argument("--max-hops", "-m", type=int, default=100, help="Max hops including meta-refresh (default: 100)")
    ap.add_argument("--insecure", "-k", action="store_true", help="Disable TLS verification")
    ap.add_argument("--scan-js", action="store_true", help="Fetch & scan same-origin JS referenced by pages")
    ap.add_argument("--dump", metavar="DIR", help="Dump fetched HTML/JS into DIR")
    ap.add_argument("--header", "-H", action="append", type=parse_header_kv,
                    help="Additional header (repeatable), e.g. -H 'Accept: */*'")
    ap.add_argument("--peek", type=int, default=0, help="Print first N chars of each body for debugging")
    args = ap.parse_args()
    
    # Validate input: need either URL or input file
    if not args.url and not args.input:
        print("Error: Either provide a URL or use -i/--input to specify a file with URLs", file=sys.stderr)
        ap.print_help()
        sys.exit(1)
    
    # Build list of URLs to process
    urls_to_process = []
    if args.url:
        urls_to_process.append(args.url)
    if args.input:
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls_to_process.append(line)
        except FileNotFoundError:
            print(f"Error: Input file '{args.input}' not found", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading input file: {e}", file=sys.stderr)
            sys.exit(1)
    
    if not urls_to_process:
        print("Error: No valid URLs found to process", file=sys.stderr)
        sys.exit(1)

    if args.dump:
        os.makedirs(args.dump, exist_ok=True)

    s = requests.Session()
    # Default to headers that closely resemble your curl run
    s.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "*/*",  # curl default
        "Connection": "close",
    })

    # Apply any user-provided headers (override defaults)
    if args.header:
        for k, v in args.header:
            if v == "":
                # allow unsetting a header by specifying empty value
                s.headers.pop(k, None)
            else:
                s.headers[k] = v

    # Inject verify flag per --insecure
    orig_get = requests.Session.get
    def patched_get(self, url, *a, **kw):
        if args.insecure:
            kw.setdefault("verify", False)
        return orig_get(self, url, *a, **kw)
    requests.Session.get = patched_get

    # Process each URL
    overall_results = []
    for url_idx, target_url in enumerate(urls_to_process):
        if len(urls_to_process) > 1:
            print(f"\n{'='*60}")
            print(f"Processing URL {url_idx + 1}/{len(urls_to_process)}: {target_url}")
            print(f"{'='*60}")
        
        try:
            chain = get_chain(s, target_url, args.max_hops, args.timeout)
        except requests.RequestException as e:
            print(f"[!] Request error for {target_url}: {e}", file=sys.stderr)
            if len(urls_to_process) > 1:
                overall_results.append({'url': target_url, 'error': str(e)})
                continue  # Process next URL
            else:
                sys.exit(2)

        any_found = False
        all_keys = set()

        print(f"\n=== Redirect/Navigation Chain ({len(chain)} step{'s' if len(chain)!=1 else ''}) ===")
        for i, step in enumerate(chain):
            html = step["text"] or ""
            if args.dump:
                fn = os.path.join(args.dump, f"step_{i}.html")
                try:
                    with open(fn, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(html)
                except Exception:
                    pass

            if args.peek:
                clip = html[:args.peek].replace("\n", "\\n")
                print(f"\n[{i}] URL: {step['url']}")
                print(f"    Status: {step['status']}")
                print(f"    Peek({args.peek}): {clip}")
            else:
                print(f"\n[{i}] URL: {step['url']}")
                print(f"    Status: {step['status']}")

            # Use enhanced detection
            detection = detect_cloudflare_protection(html, step.get("headers"))
            
            # Legacy turnstile detection for backward compatibility
            found, keys, evidence = detect_turnstile(html)
            js_keys, js_evidence = set(), []
            if args.scan_js:
                js_keys, js_evidence = scan_linked_js(s, step["url"], html, args.timeout, args.dump)

            keys |= js_keys
            evidence += js_evidence
            all_keys.update(keys)
            
            # Check if any Cloudflare protection was detected
            cf_detected = any([
                detection['turnstile']['found'],
                detection['custom_captcha']['found'],
                detection['cf_challenge']['found'],
                detection['cf_headers']['found']
            ])
            
            any_found = any_found or cf_detected or bool(keys)
            
            # Display detection results
            protection_types = []
            if detection['turnstile']['found']:
                protection_types.append("Turnstile")
            if detection['custom_captcha']['found']:
                protection_types.append("Custom CAPTCHA")
            if detection['cf_challenge']['found']:
                protection_types.append("CF Challenge")
            if detection['cf_headers']['found']:
                protection_types.append("CF Headers")
                
            if protection_types:
                print(f"    Cloudflare Protection: YES ({', '.join(protection_types)})")
            else:
                print(f"    Cloudflare Protection: NO")
            
            # Show Turnstile keys if found
            if keys:
                print(f"    Turnstile Site key(s): {', '.join(sorted(keys))}")
            
            # Show evidence for each type of protection
            if detection['custom_captcha']['found']:
                for ev in detection['custom_captcha']['evidence'][:3]:
                    print(f"    CAPTCHA Evidence: {ev}")
                    
            if detection['cf_challenge']['found']:
                for ev in detection['cf_challenge']['evidence'][:3]:
                    print(f"    CF Challenge: {ev}")
                    
            if detection['cf_headers']['found']:
                for ev in detection['cf_headers']['evidence'][:3]:
                    print(f"    CF Header: {ev}")
            
            # Show turnstile evidence if present
            for ev in evidence[:3]:
                print(f"    Turnstile Evidence: {ev}")
            if len(evidence) > 3:
                print(f"    Evidence: (+{len(evidence)-3} more)")

        print("\n=== Summary ===")
        if any_found:
            summary_parts = []
            if all_keys:
                summary_parts.append(f"Turnstile with key(s): {', '.join(sorted(all_keys))}")
            elif detection['turnstile']['found']:
                summary_parts.append("Turnstile (no keys)")
            if detection['custom_captcha']['found']:
                summary_parts.append("Custom CAPTCHA")
            if detection['cf_challenge']['found']:
                summary_parts.append("CF Challenge Page")
            if detection['cf_headers']['found']:
                summary_parts.append("CF Headers/Infrastructure")
                
            print(f"Cloudflare Protection Detected: {' | '.join(summary_parts)}")
            overall_results.append({
                'url': target_url, 
                'cf_protection': True,
                'turnstile': detection['turnstile']['found'] or bool(all_keys),
                'keys': list(all_keys),
                'protection_types': summary_parts
            })
        else:
            print("No Cloudflare protection detected across the chain.")
            overall_results.append({
                'url': target_url,
                'cf_protection': False,
                'turnstile': False,
                'keys': [],
                'protection_types': []
            })
    
    # Print overall summary if processing multiple URLs
    if len(urls_to_process) > 1:
        print("\n" + "="*60)
        print("OVERALL SUMMARY")
        print("="*60)
        for result in overall_results:
            if 'error' in result:
                print(f"✗ {result['url']}: ERROR - {result['error']}")
            elif result.get('cf_protection'):
                protection_desc = ' | '.join(result.get('protection_types', []))
                if result.get('keys'):
                    print(f"✓ {result['url']}: {protection_desc}")
                else:
                    print(f"⚠ {result['url']}: {protection_desc}")
            else:
                print(f"✗ {result['url']}: No Cloudflare protection detected")
    
    # Exit with appropriate code
    if len(urls_to_process) == 1:
        if overall_results and overall_results[0].get('cf_protection'):
            sys.exit(0)
        else:
            sys.exit(1)

if __name__ == "__main__":
    main()
