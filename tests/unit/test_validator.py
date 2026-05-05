import pytest
from src.intel.core.validator import (
    is_public_ip, 
    validate_domain, 
    validate_hash, 
    validate_url
)

class TestValidators:
    """Unit tests for indicator validators."""

    def test_ip_validation_public(self):
        """Valid public IPs should pass."""
        assert is_public_ip("8.8.8.8") == "8.8.8.8"
        assert is_public_ip("1.1.1.1") == "1.1.1.1"

    def test_ip_validation_private_reserved(self):
        """Private or reserved IPs should raise ValueError."""
        with pytest.raises(ValueError, match="private or reserved"):
            is_public_ip("127.0.0.1")
        with pytest.raises(ValueError, match="private or reserved"):
            is_public_ip("192.168.1.1")
        with pytest.raises(ValueError, match="private or reserved"):
            is_public_ip("10.0.0.1")

    def test_ip_validation_invalid_format(self):
        """Invalid IP formats should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid IP address format"):
            is_public_ip("999.999.999.999")
        with pytest.raises(ValueError, match="Invalid IP address format"):
            is_public_ip("not-an-ip")

    def test_domain_validation_valid(self):
        """Valid domains should pass and be lowercased."""
        assert validate_domain("GOOGLE.COM") == "google.com"
        assert validate_domain("my-domain.co.uk") == "my-domain.co.uk"

    def test_domain_validation_invalid(self):
        """Invalid domains should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("invalid_domain")
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("localhost")

    def test_hash_validation_valid(self):
        """Valid MD5, SHA1, and SHA256 hashes should pass."""
        # MD5
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        assert validate_hash(md5) == md5
        # SHA1
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert validate_hash(sha1) == sha1
        # SHA256
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert validate_hash(sha256) == sha256

    def test_hash_validation_invalid(self):
        """Invalid hashes should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid hash format"):
            validate_hash("short")
        with pytest.raises(ValueError, match="Invalid hash format"):
            validate_hash("g" * 32)  # invalid hex

    def test_url_validation_valid(self):
        """Valid URLs should pass."""
        assert validate_url("https://google.com") == "https://google.com"
        assert validate_url("http://example.org/path?q=1") == "http://example.org/path?q=1"

    def test_url_validation_invalid_scheme(self):
        """Unsupported schemes should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid URL scheme"):
            validate_url("ftp://files.com")
