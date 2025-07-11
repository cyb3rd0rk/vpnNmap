# VPN Service Detection Tool & Research Documents

A Python script that uses nmap to analyze port 443 and intelligently determine what type of service is running. This tool can distinguish between regular HTTPS websites, DNS over HTTPS (DoH), DNS over TLS (DoT), SSTP VPN, and other SSL/TLS VPN services.

## Features

- **Comprehensive Service Detection**: Identifies multiple service types on port 443
- **SSL Certificate Analysis**: Examines certificates for service indicators
- **DNS Service Testing**: Tests for DoH and DoT capabilities
- **VPN Detection**: Identifies SSTP and other SSL/TLS VPN services
- **Confidence Scoring**: Provides confidence levels for detections
- **Detailed Reporting**: Shows specific indicators and recommendations

## Service Types Detected

- **DNS over HTTPS (DoH)**: Detects DoH endpoints and validates functionality
- **DNS over TLS (DoT)**: Tests for DNS over TLS communication
- **SSTP VPN**: Microsoft's Secure Socket Tunneling Protocol
- **SSL/TLS VPN Web Interfaces**: FortiGate, Cisco AnyConnect, Pulse Secure, etc.
- **Regular HTTPS**: Standard web services

## Prerequisites

### System Requirements
- Python 3.6+
- nmap (Network Mapper)

### Installing nmap

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install nmap
# or for newer versions
sudo dnf install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
Download from [nmap.org](https://nmap.org/download.html) and add to PATH

### Python Dependencies
```bash
pip install requests urllib3
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/port443-detector.git
cd port443-detector
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Make the script executable (Linux/macOS):
```bash
chmod +x port443_detector.py
```

## Usage

### Basic Usage
```bash
python port443_detector.py <target>
```

### Command Line Options
```bash
python port443_detector.py [-h] [--timeout TIMEOUT] [--verbose] target
```

**Arguments:**
- `target`: Target IP address or hostname (required)
- `--timeout TIMEOUT`: Timeout for scans in seconds (default: 30)
- `--verbose, -v`: Enable verbose output showing detailed scan results

### Examples

**Basic scan:**
```bash
python port443_detector.py example.com
```

**Scan with verbose output:**
```bash
python port443_detector.py -v 192.168.1.1
```

**Custom timeout:**
```bash
python port443_detector.py --timeout 60 vpn.company.com
```

**Scanning a DoH service:**
```bash
python port443_detector.py cloudflare-dns.com
```

## Sample Output

### DoH Service Detection
```
=== Port 443 Service Detection for cloudflare-dns.com ===

1. Running nmap scan...
2. Analyzing SSL certificate...
3. Testing HTTP service...
4. Testing DNS over HTTPS...
5. Testing DNS over TLS...
6. Analyzing service type...

=== RESULTS ===
Target: cloudflare-dns.com
Service Type: DNS over HTTPS (DoH)
Confidence: High

Indicators:
  • DoH endpoint found: https://cloudflare-dns.com:443/dns-query
```

### SSTP VPN Detection
```
=== Port 443 Service Detection for vpn.company.com ===

=== RESULTS ===
Target: vpn.company.com
Service Type: SSTP VPN
Confidence: Medium

Indicators:
  • Microsoft service detected
  • VPN/Tunnel/SSTP in certificate CN: vpn.company.com
```

### SSL/TLS VPN Web Interface
```
=== Port 443 Service Detection for firewall.company.com ===

=== RESULTS ===
Target: firewall.company.com
Service Type: SSL/TLS VPN Web Interface
Confidence: Medium

Indicators:
  • VPN keyword 'fortigate' found in response
  • VPN server header: fortigate
```

## Detection Methods

### DNS over HTTPS (DoH)
- Tests common DoH endpoints: `/dns-query`, `/resolve`, `/dns`
- Sends DNS queries with proper headers
- Validates JSON responses for DNS structure

### DNS over TLS (DoT)
- Attempts TLS connection on port 443
- Sends DNS queries over TLS
- Validates DNS response format

### SSTP VPN
- Analyzes nmap output for SSTP indicators
- Examines SSL certificates for Microsoft/VPN keywords
- Checks certificate organization and common names

### SSL/TLS VPN Web Interfaces
- Tests HTTP responses for VPN keywords
- Analyzes server headers for VPN appliances
- Detects common VPN web interfaces

## Troubleshooting

### Common Issues

**"nmap not found" error:**
- Ensure nmap is installed and in your PATH
- Try running `nmap --version` to verify installation

**Permission denied errors:**
- Some nmap scans require root privileges
- Try running with `sudo` on Linux/macOS

**Connection timeouts:**
- Increase timeout with `--timeout` parameter
- Check if target is accessible from your network
- Verify firewall rules aren't blocking the scan

**SSL certificate errors:**
- Script uses unverified SSL connections for analysis
- This is normal behavior for service detection

### Verbose Mode
Use `-v` flag to see detailed information about each detection step:
```bash
python port443_detector.py -v target.com
```

## Limitations

- Requires nmap to be installed and accessible
- Some VPN services may not be detected if they don't follow standard patterns
- DoT detection on port 443 is less common (usually port 853)
- Requires network connectivity to target
- Some corporate firewalls may block nmap scans

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and legitimate security testing purposes only. Only use this tool on systems you own or have explicit permission to test. The authors are not responsible for any misuse of this tool.

## Support

If you encounter issues or have questions:
2. Create a new issue with detailed information about your problem
3. Include the verbose output (`-v` flag) when reporting bugs

## Acknowledgments

- Built using the powerful nmap network scanning tool
- Inspired by the need to distinguish between various services on port 443
- Thanks to the open-source community for Python libraries used
