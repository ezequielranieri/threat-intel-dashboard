import pytest
from pydantic import ValidationError
from src.intel.models.indicators import Indicator, IndicatorType

class TestIndicatorModel:
    """Unit tests for the Indicator Pydantic model."""

    def test_indicator_ip_valid(self):
        """Valid IP indicator should be accepted."""
        ind = Indicator(type=IndicatorType.IP, value="8.8.8.8")
        assert ind.value == "8.8.8.8"
        assert ind.type == IndicatorType.IP

    def test_indicator_ip_invalid(self):
        """Invalid IP should trigger validation error."""
        with pytest.raises(ValidationError) as excinfo:
            Indicator(type=IndicatorType.IP, value="127.0.0.1")
        assert "private or reserved" in str(excinfo.value)

    def test_indicator_domain_valid(self):
        """Valid domain indicator should be accepted and lowercased."""
        ind = Indicator(type=IndicatorType.DOMAIN, value="GOOGLE.COM")
        assert ind.value == "google.com"

    def test_indicator_hash_valid(self):
        """Valid hash indicator should be accepted."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        ind = Indicator(type=IndicatorType.HASH, value=md5)
        assert ind.value == md5

    def test_indicator_url_valid(self):
        """Valid URL indicator should be accepted."""
        url = "https://malicious-site.com/login"
        ind = Indicator(type=IndicatorType.URL, value=url)
        assert ind.value == url

    def test_indicator_mismatch_type_value(self):
        """Should fail if value doesn't match the type."""
        with pytest.raises(ValidationError):
            Indicator(type=IndicatorType.IP, value="not-an-ip")
        
        with pytest.raises(ValidationError):
            Indicator(type=IndicatorType.HASH, value="short")
