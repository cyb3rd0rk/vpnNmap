#!/usr/bin/env python3
"""
Developed by CoeurStrike
Version 1.2   7/11/2025

Port 443 Service Detection Script
Checks if port 443 is open and identifies the service type:
- SSTP (Secure Socket Tunneling Protocol)
- DNS over HTTPS (DoH)
- DNS over TLS (DoT)
- SSL/TLS VPN
"""

import subprocess
import socket
import ssl
import json
import re
import sys
import argparse
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def run_nmap_scan(target, timeout=30):
    """Run nmap scan on port 443 with service detection"""
    try:
        cmd = [
            'nmap', '-p', '443', '--script', 
            'ssl-enum-ciphers,http-methods,http-headers,ssl-cert',
            '-sV', '--version-intensity', '9',
            '--script-timeout', str(timeout),
            target
        ]
        
        print(f"Running nmap scan on {target}:443...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+10)
        
        if result.returncode != 0:
            print(f"Nmap scan failed: {result.stderr}")
            return None
            
        return result.stdout
        
    except subprocess.TimeoutExpired:
        print("Nmap scan timed out")
        return None
    except FileNotFoundError:
        print("Error: nmap not found. Please install nmap.")
        return None

def analyze_ssl_certificate(target, port=443):
    """Analyze SSL certificate for clues about the service"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                
                # Extract subject and issuer information
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                
                # Get Subject Alternative Names
                san_list = []
                for ext in cert.get('subjectAltName', []):
                    if ext[0] == 'DNS':
                        san_list.append(ext[1])
                
                return {
                    'common_name': subject.get('commonName', ''),
                    'organization': subject.get('organizationName', ''),
                    'issuer': issuer.get('commonName', ''),
                    'san_list': san_list,
                    'serial_number': cert.get('serialNumber', '')
                }
    except Exception as e:
        print(f"SSL certificate analysis failed: {e}")
        return None

def test_http_service(target, port=443):
    """Test if the service responds to HTTP requests"""
    try:
        session = requests.Session()
        retry_strategy = Retry(total=2, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        
        url = f"https://{target}:{port}"
        
        # Test basic HTTPS connection
        response = session.get(url, timeout=10, verify=False)
        
        headers = dict(response.headers)
        return {
            'status_code': response.status_code,
            'headers': headers,
            'content_preview': response.text[:500] if response.text else '',
            'url': url
        }
        
    except Exception as e:
        print(f"HTTP service test failed: {e}")
        return None

def test_doh_service(target, port=443):
    """Test if service supports DNS over HTTPS"""
    try:
        session = requests.Session()
        
        # Common DoH endpoints
        doh_paths = ['/dns-query', '/resolve', '/dns']
        
        for path in doh_paths:
            url = f"https://{target}:{port}{path}"
            
            # Test with a simple DNS query for google.com
            params = {
                'name': 'google.com',
                'type': 'A'
            }
            
            headers = {
                'Accept': 'application/dns-json'
            }
            
            try:
                response = session.get(url, params=params, headers=headers, 
                                     timeout=5, verify=False)
                
                if response.status_code == 200:
                    try:
                        json_response = response.json()
                        if 'Answer' in json_response or 'Status' in json_response:
                            return {'doh_endpoint': url, 'response': json_response}
                    except:
                        pass
                        
            except:
                continue
                
        return None
        
    except Exception as e:
        print(f"DoH test failed: {e}")
        return None

def test_dot_service(target, port=443):
    """Test if service supports DNS over TLS (usually on port 853, but checking 443)"""
    try:
        # DoT typically uses port 853, but some services might use 443
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock) as ssock:
                # Try to send a simple DNS query
                # This is a basic A record query for google.com
                dns_query = bytes.fromhex('0001010000010000000000000006676f6f676c6503636f6d0000010001')
                
                # Send length prefix (2 bytes) + query
                query_with_length = len(dns_query).to_bytes(2, 'big') + dns_query
                ssock.send(query_with_length)
                
                # Try to receive response
                response = ssock.recv(1024)
                
                if len(response) > 2:
                    return {'dot_response': True, 'response_length': len(response)}
                    
    except Exception as e:
        # This is expected for non-DoT services
        pass
        
    return None

def detect_sstp_service(nmap_output, cert_info):
    """Detect if service is SSTP based on various indicators"""
    sstp_indicators = []
    
    # Check nmap output for SSTP indicators
    if nmap_output:
        if 'sstp' in nmap_output.lower():
            sstp_indicators.append("SSTP detected in nmap output")
        
        if 'microsoft' in nmap_output.lower():
            sstp_indicators.append("Microsoft service detected")
    
    # Check certificate information
    if cert_info:
        cn = cert_info.get('common_name', '').lower()
        org = cert_info.get('organization', '').lower()
        
        if 'vpn' in cn or 'tunnel' in cn or 'sstp' in cn:
            sstp_indicators.append(f"VPN/Tunnel/SSTP in certificate CN: {cn}")
            
        if 'microsoft' in org:
            sstp_indicators.append(f"Microsoft in certificate organization: {org}")
    
    return sstp_indicators

def analyze_service_type(target, nmap_output, cert_info, http_response, doh_test, dot_test):
    """Analyze all collected data to determine service type"""
    analysis = {
        'target': target,
        'service_type': 'Unknown',
        'confidence': 'Low',
        'indicators': [],
        'recommendations': []
    }
    
    # Check for DNS over HTTPS
    if doh_test:
        analysis['service_type'] = 'DNS over HTTPS (DoH)'
        analysis['confidence'] = 'High'
        analysis['indicators'].append(f"DoH endpoint found: {doh_test['doh_endpoint']}")
        return analysis
    
    # Check for DNS over TLS
    if dot_test:
        analysis['service_type'] = 'DNS over TLS (DoT)'
        analysis['confidence'] = 'Medium'
        analysis['indicators'].append("Service responds to DNS over TLS queries")
        return analysis
    
    # Check for SSTP
    sstp_indicators = detect_sstp_service(nmap_output, cert_info)
    if sstp_indicators:
        analysis['service_type'] = 'SSTP VPN'
        analysis['confidence'] = 'Medium'
        analysis['indicators'].extend(sstp_indicators)
        return analysis
    
    # Analyze HTTP response for other VPN types
    if http_response:
        headers = http_response.get('headers', {})
        content = http_response.get('content_preview', '').lower()
        
        # Check for common VPN web interfaces
        vpn_keywords = ['vpn', 'tunnel', 'openvpn', 'anyconnect', 'pulse', 'fortigate', 
                       'checkpoint', 'palo alto', 'sophos', 'watchguard']
        
        for keyword in vpn_keywords:
            if keyword in content:
                analysis['service_type'] = 'SSL/TLS VPN Web Interface'
                analysis['confidence'] = 'Medium'
                analysis['indicators'].append(f"VPN keyword '{keyword}' found in response")
                return analysis
        
        # Check server headers
        server_header = headers.get('server', '').lower()
        if any(vpn in server_header for vpn in ['fortigate', 'checkpoint', 'palo alto']):
            analysis['service_type'] = 'SSL/TLS VPN Web Interface'
            analysis['confidence'] = 'Medium'
            analysis['indicators'].append(f"VPN server header: {server_header}")
            return analysis
    
    # Default analysis for regular HTTPS
    if http_response and http_response.get('status_code') == 200:
        analysis['service_type'] = 'Regular HTTPS Web Service'
        analysis['confidence'] = 'Medium'
        analysis['indicators'].append("Service responds to HTTP requests normally")
        analysis['recommendations'].append("This appears to be a regular web service")
    
    return analysis

def main():
    parser = argparse.ArgumentParser(description='Detect service type on port 443')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout for scans (default: 30)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print(f"=== Port 443 Service Detection for {args.target} ===\n")
    
    # Step 1: Run nmap scan
    print("1. Running nmap scan...")
    nmap_output = run_nmap_scan(args.target, args.timeout)
    
    if args.verbose and nmap_output:
        print("Nmap output:")
        print(nmap_output)
        print("-" * 50)
    
    # Step 2: Analyze SSL certificate
    print("2. Analyzing SSL certificate...")
    cert_info = analyze_ssl_certificate(args.target)
    
    if args.verbose and cert_info:
        print("Certificate info:")
        for key, value in cert_info.items():
            print(f"  {key}: {value}")
        print("-" * 50)
    
    # Step 3: Test HTTP service
    print("3. Testing HTTP service...")
    http_response = test_http_service(args.target)
    
    if args.verbose and http_response:
        print("HTTP response info:")
        print(f"  Status: {http_response.get('status_code')}")
        print(f"  Headers: {list(http_response.get('headers', {}).keys())}")
        print("-" * 50)
    
    # Step 4: Test DoH service
    print("4. Testing DNS over HTTPS...")
    doh_test = test_doh_service(args.target)
    
    if args.verbose and doh_test:
        print("DoH test result:")
        print(f"  Endpoint: {doh_test.get('doh_endpoint')}")
        print("-" * 50)
    
    # Step 5: Test DoT service
    print("5. Testing DNS over TLS...")
    dot_test = test_dot_service(args.target)
    
    if args.verbose and dot_test:
        print("DoT test result:")
        print(f"  Response received: {dot_test.get('response_length')} bytes")
        print("-" * 50)
    
    # Step 6: Analyze and determine service type
    print("6. Analyzing service type...")
    analysis = analyze_service_type(args.target, nmap_output, cert_info, 
                                  http_response, doh_test, dot_test)
    
    # Output final results
    print("\n=== RESULTS ===")
    print(f"Target: {analysis['target']}")
    print(f"Service Type: {analysis['service_type']}")
    print(f"Confidence: {analysis['confidence']}")
    print("\nIndicators:")
    for indicator in analysis['indicators']:
        print(f"  • {indicator}")
    
    if analysis['recommendations']:
        print("\nRecommendations:")
        for rec in analysis['recommendations']:
            print(f"  • {rec}")

if __name__ == "__main__":
    main()
