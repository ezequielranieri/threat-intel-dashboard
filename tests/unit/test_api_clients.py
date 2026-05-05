import pytest
import respx
import httpx
from src.intel.api.virustotal import VirusTotalClient
from src.intel.api.abuseipdb import AbuseIPDBClient
from src.intel.api.shodan import ShodanClient
from src.intel.models.indicators import IndicatorType
from src.intel.models.results import ThreatLevel

@pytest.mark.asyncio
async def test_virustotal_success(respx_mock):
    """Test successful VirusTotal IP analysis."""
    client = VirusTotalClient()
    client.api_key = "fake_key"
    
    mock_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 10,
                    "suspicious": 2,
                    "harmless": 50,
                    "undetected": 10,
                    "timeout": 0
                }
            }
        }
    }
    
    respx_mock.get(f"{VirusTotalClient.BASE_URL}/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(200, json=mock_response)
    )
    
    result = await client.analyze(IndicatorType.IP, "8.8.8.8")
    
    assert result is not None
    assert result.malicious == 10
    assert result.threat_level == ThreatLevel.MALICIOUS
    assert result.detection_ratio == "10/72"

@pytest.mark.asyncio
async def test_virustotal_rate_limit(respx_mock):
    """Test VirusTotal rate limit handling."""
    client = VirusTotalClient()
    client.api_key = "fake_key"
    
    respx_mock.get(f"{VirusTotalClient.BASE_URL}/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(429)
    )
    
    result = await client.analyze(IndicatorType.IP, "8.8.8.8")
    assert result is None

@pytest.mark.asyncio
async def test_abuseipdb_success(respx_mock):
    """Test successful AbuseIPDB analysis."""
    client = AbuseIPDBClient()
    client.api_key = "fake_key"
    
    mock_response = {
        "data": {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 90,
            "totalReports": 150,
            "lastReportedAt": "2024-05-05T12:00:00Z",
            "countryCode": "US",
            "isp": "Google"
        }
    }
    
    respx_mock.get(f"{AbuseIPDBClient.BASE_URL}/check").mock(
        return_value=httpx.Response(200, json=mock_response)
    )
    
    result = await client.analyze_ip("1.2.3.4")
    
    assert result is not None
    assert result.abuse_score == 90
    assert result.threat_level == ThreatLevel.MALICIOUS
    assert result.country == "US"

@pytest.mark.asyncio
async def test_shodan_success(respx_mock):
    """Test successful Shodan analysis."""
    client = ShodanClient()
    client.api_key = "fake_key"
    
    mock_response = {
        "ports": [80, 443],
        "country_name": "United States",
        "isp": "Google",
        "data": [{"transport": "tcp"}, {"transport": "tcp"}]
    }
    
    respx_mock.get(f"{ShodanClient.BASE_URL}/shodan/host/8.8.8.8").mock(
        return_value=httpx.Response(200, json=mock_response)
    )
    
    result = await client.analyze_ip("8.8.8.8")
    
    assert result is not None
    assert 80 in result.open_ports
    assert result.country == "United States"
