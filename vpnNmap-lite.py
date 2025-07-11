# Developed by CoeurStrike
# VPN Detection Tool - lite 
# Version 1.1   7/11/2025

import nmap
import sys
import argparse
import ssl
import socket

def check_port_443(host):
    # Initialize nmap scanner
    nm = nmap.PortScanner()
    
    try:
        # Scan port 443 with service detection
        print(f"Scanning {host} on port 443...")
        nm.scan(host, '443', arguments='-sV --version-intensity 9')
        
        # Check if host is up and port 443 is open
        if host in nm.all_hosts():
            if 'tcp' in nm[host] and 443 in nm[host]['tcp']:
                port_state = nm[host]['tcp'][443]['state']
                if port_state == 'open':
                    print(f"Port 443 is open on {host}")
                    
                    # Get service details
                    service = nm[host]['tcp'][443].get('name', 'unknown')
                    product = nm[host]['tcp'][443].get('product', '')
                    version = nm[host]['tcp'][443].get('version', '')
                    extra_info = nm[host]['tcp'][443].get('extrainfo', '')
                    
                    print(f"Service: {service}")
                    print(f"Product: {product}")
                    print(f"Version: {version}")
                    print(f"Extra Info: {extra_info}")
                    
                    # Check for SSTP
                    if 'sstp' in service.lower() or 'sstp' in extra_info.lower():
                        print("Detected SSTP protocol")
                        return analyze_sstp(host)
                    elif 'https' in service.lower() or 'ssl' in service.lower():
                        print("Detected HTTPS or SSL/TLS service")
                        return analyze_ssl_service(host)
                    else:
                        print("Unknown service on port 443")
                        return "Unknown service"
                else:
                    print(f"Port 443 is {port_state}")
                    return f"Port 443 is {port_state}"
            else:
                print("Port 443 not found in scan results")
                return "Port 443 not found"
        else:
            print(f"Host {host} is down or unresponsive")
            return "Host down"
            
    except nmap.PortScannerError as e:
        print(f"Nmap error: {e}")
        return "Scan error"
    except Exception as e:
        print(f"Error: {e}")
        return "Error"

def analyze_sstp(host):
    # SSTP is typically a VPN protocol using SSL/TLS over port 443
    try:
        # Attempt to connect and check SSL certificate
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                print("SSL/TLS certificate obtained")
                
                # SSTP typically uses Microsoft-specific OIDs or server configurations
                # Check for common SSTP indicators in certificate
                if cert.get('issuer') and 'Microsoft' in str(cert.get('issuer')):
                    return "Likely SSTP (SSL/TLS VPN)"
                else:
                    return "SSL/TLS VPN (non-specific SSTP indicators)"
    except ssl.SSLError:
        return "SSL/TLS VPN (failed to verify certificate)"
    except Exception as e:
        print(f"Error analyzing SSTP: {e}")
        return "Unable to confirm SSTP"

def analyze_ssl_service(host):
    # Try to distinguish between DoH, DoT, and other SSL/TLS services
    try:
        # Connect to the server and check for HTTP/2 (common for DoH)
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Check protocol version
                protocol = ssock.version()
                print(f"SSL/TLS Protocol: {protocol}")
                
                # Send a simple HTTP request to check for DoH
                http_request = f"GET /dns-query HTTP/1.1\r\nHost: {host}\r\n\r\n"
                ssock.send(http_request.encode())
                response = ssock.recv(1024).decode('utf-8', errors='ignore')
                
                if 'HTTP' in response and ('200 OK' in response or 'DNS' in response):
                    print("HTTP response received, likely DNS over HTTPS (DoH)")
                    return "DNS over HTTPS (DoH)"
                elif protocol in ['TLSv1.2', 'TLSv1.3']:
                    # DoT typically uses a dedicated ALPN protocol
                    alpn_protocols = context.get_alpn_protocols() or []
                    if 'dot' in alpn_protocols:
                        print("ALPN indicates DNS over TLS (DoT)")
                        return "DNS over TLS (DoT)"
                    else:
                        print("Generic SSL/TLS service, likely not DoH or DoT")
                        return "Generic SSL/TLS service (possibly VPN)"
                else:
                    return "Unknown SSL/TLS service"
    except ssl.SSLError:
        return "SSL/TLS service (failed to verify certificate)"
    except Exception as e:
        print(f"Error analyzing SSL service: {e}")
        return "Unable to analyze SSL service"

def main():
    parser = argparse.ArgumentParser(description="Check if port 443 is open and analyze service")
    parser.add_argument("host", help="Target host to scan (e.g., example.com)")
    args = parser.parse_args()
    
    result = check_port_443(args.host)
    print(f"Final result: {result}")

if __name__ == "__main__":
    main()
