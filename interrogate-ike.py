# Developed by CoeurStrike
# Version: 1.1   7/11/2025
# EXAMPLE CODE FOR RESEARCH AND ACADEMIC PURPOSES

import socket
import binascii
import struct
import argparse
from typing import Optional, Tuple

class IKEVPNSDetector:
    """Class to detect VPN products by interrogating IKE on port 500."""
    
    def __init__(self, target: str, port: int = 500, timeout: float = 5.0):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.sock = None
        
    def create_ike_packet(self) -> bytes:
        """Create a basic IKEv1 SA proposal packet."""
        # IKE Header: Initiator SPI (8 bytes), Responder SPI (8 bytes), etc.
        initiator_spi = b'\x01\x23\x45\x67\x89\xab\xcd\xef'
        responder_spi = b'\x00' * 8
        next_payload = 1  # SA payload
        version = 0x10    # IKEv1
        exchange_type = 2 # Identity Protection (Main Mode)
        flags = 0
        message_id = 0
        length = 0        # Will be updated after payload construction
        
        # SA Payload (simplified)
        sa_payload = (
            b'\x00' +              # Next payload (none)
            b'\x00' +              # Reserved
            b'\x00\x24' +          # Payload length (36 bytes for this example)
            b'\x00\x00\x00\x01' +  # DOI: IPsec
            b'\x00\x00\x00\x01' +  # Situation: SIT_IDENTITY_ONLY
            b'\x00' +              # Proposal next payload
            b'\x00' +              # Reserved
            b'\x00\x18' +          # Proposal length
            b'\x01' +              # Proposal number
            b'\x01' +              # Protocol ID: ISAKMP
            b'\x00' +              # SPI size
            b'\x01' +              # Number of transforms
            b'\x00' +              # Transform next payload
            b'\x00' +              # Reserved
            b'\x00\x0c' +          # Transform length
            b'\x01' +              # Transform ID: KEY_IKE
            b'\x00\x00' +          # Reserved
            b'\x01\x01\x80\x01\x01'  # Attribute: Encryption (DES)
        )
        
        # Pack IKE header
        header = struct.pack(
            '!8s8sBBBBB4sI',
            initiator_spi,
            responder_spi,
            next_payload,
            version,
            exchange_type,
            flags,
            message_id,
            len(sa_payload) + 28  # Header (28 bytes) + SA payload
        )
        
        return header + sa_payload
    
    def send_ike_packet(self) -> Optional[Tuple[bytes, str]]:
        """Send IKE packet and receive response."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
            packet = self.create_ike_packet()
            self.sock.sendto(packet, (self.target, self.port))
            
            response, addr = self.sock.recvfrom(1024)
            return response, addr[0]
        except socket.timeout:
            print(f"No response from {self.target}:{self.port}")
            return None
        except socket.error as e:
            print(f"Socket error: {e}")
            return None
        finally:
            if self.sock:
                self.sock.close()
    
    def analyze_response(self, response: bytes) -> str:
        """Analyze IKE response to identify VPN product."""
        if not response:
            return "No response received"
        
        try:
            # Unpack IKE header
            header = struct.unpack('!8s8sBBBBB4sI', response[:28])
            initiator_spi, responder_spi, next_payload, version, exchange_type, flags, message_id, length = header
            
            # Basic fingerprinting based on response characteristics
            vendor_id_payload = b'\x00\x00\x00\x00'  # Placeholder for Vendor ID check
            if b'\x90\xcb\x80\x91' in response:
                return "Possible Cisco VPN (Vendor ID detected)"
            elif b'\x40\x48\xb7\xd5' in response:
                return "Possible Check Point VPN (Vendor ID detected)"
            elif version == 0x20:
                return "IKEv2 detected, possible modern VPN implementation"
            else:
                return f"Unknown VPN product (Version: {hex(version)}, Exchange Type: {exchange_type})"
        except Exception as e:
            return f"Error analyzing response: {e}"
    
    def detect(self) -> str:
        """Main method to perform VPN detection."""
        print(f"Probing {self.target}:{self.port}...")
        result = self.send_ike_packet()
        if result:
            response, addr = result
            print(f"Received response from {addr}")
            return self.analyze_response(response)
        return "No valid response"

def main():
    parser = argparse.ArgumentParser(description="Detect VPN products via IKE port 500 interrogation")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--port", type=int, default=500, help="Target port (default: 500)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds")
    args = parser.parse_args()
    
    detector = IKEVPNSDetector(args.target, args.port, args.timeout)
    result = detector.detect()
    print(f"Detection Result: {result}")

if __name__ == "__main__":
    main()
