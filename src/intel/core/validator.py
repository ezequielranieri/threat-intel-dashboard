import re
from ipaddress import ip_address, ip_network, AddressValueError
from typing import Annotated
from pydantic import AfterValidator, HttpUrl

# Security Constants
REDES_RESERVADAS = [
    ip_network("0.0.0.0/8"),
    ip_network("127.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("169.254.0.0/16"),
    ip_network("224.0.0.0/4"),
    ip_network("240.0.0.0/4"),
]

def is_public_ip(ip: str) -> str:
    """Validates if the IP is public and not reserved/private.
    
    Args:
        ip: IPv4 or IPv6 address string.
        
    Returns:
        The validated IP string.
        
    Raises:
        ValueError: If the IP is invalid or private/reserved.
    """
    try:
        addr = ip_address(ip)
    except (AddressValueError, ValueError):
        raise ValueError(f"Invalid IP address format: {ip}")

    if any(addr in red for red in REDES_RESERVADAS):
        raise ValueError(f"IP {ip} is private or reserved and cannot be analyzed.")
    
    return str(addr)

def validate_domain(domain: str) -> str:
    """Validates domain name format.
    
    Args:
        domain: Domain name string.
        
    Returns:
        The validated domain string.
        
    Raises:
        ValueError: If the domain format is invalid.
    """
    patron = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$',
        re.IGNORECASE
    )
    if not patron.match(domain) or domain.lower() == "localhost":
        raise ValueError(f"Invalid domain format: {domain}")
    return domain.lower()

def validate_hash(hash_val: str) -> str:
    """Validates MD5, SHA1, or SHA256 hash format.
    
    Args:
        hash_val: Hash string.
        
    Returns:
        The validated hash string.
        
    Raises:
        ValueError: If the hash format is invalid.
    """
    # MD5 (32), SHA1 (40), SHA256 (64)
    lengths = {32, 40, 64}
    if len(hash_val) not in lengths or not all(c in "0123456789abcdefABCDEF" for c in hash_val):
        raise ValueError(f"Invalid hash format (must be MD5, SHA1 or SHA256): {hash_val}")
    return hash_val.lower()

def validate_url(url: str) -> str:
    """Validates URL format (must be http or https).
    
    Args:
        url: URL string.
        
    Returns:
        The validated URL string.
        
    Raises:
        ValueError: If the URL is invalid or uses unsupported schemes.
    """
    # Simple check for scheme, Pydantic's HttpUrl handles the rest in models
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"Invalid URL scheme: {url}. Only HTTP/HTTPS supported.")
    return url
