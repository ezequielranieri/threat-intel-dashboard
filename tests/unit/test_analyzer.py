import pytest
from unittest.mock import AsyncMock, patch
from src.intel.core.analyzer import ThreatAnalyzer
from src.intel.models.indicators import Indicator, IndicatorType
from src.intel.models.results import (
    ThreatLevel, 
    VirusTotalResult, 
    AbuseIPDBResult, 
    ShodanResult
)

@pytest.fixture
def analyzer(tmp_path):
    db_file = tmp_path / "test_analyzer_cache.db"
    with patch("src.intel.core.analyzer.ThreatCache") as mock_cache_class:
        from src.intel.core.cache import ThreatCache
        # Create a real cache instance pointing to the temp db
        real_cache = ThreatCache(db_path=str(db_file))
        mock_cache_class.return_value = real_cache
        return ThreatAnalyzer()

class TestThreatAnalyzer:
    """Unit tests for the ThreatAnalyzer core logic."""

    @pytest.mark.asyncio
    async def test_analyze_ip_malicious_correlation(self, analyzer):
        """Test correlation when both VT and AbuseIPDB report malicious activity."""
        indicator = Indicator(type=IndicatorType.IP, value="8.8.8.8")
        
        vt_mock = VirusTotalResult(
            malicious=10, suspicious=0, clean=62, 
            total_engines=72, detection_ratio="10/72", 
            threat_level=ThreatLevel.MALICIOUS
        )
        abuse_mock = AbuseIPDBResult(
            abuse_score=95, total_reports=1000, 
            threat_level=ThreatLevel.MALICIOUS
        )
        shodan_mock = ShodanResult(open_ports=[80, 443])

        with patch.object(analyzer.vt_client, 'analyze', new_callable=AsyncMock) as mock_vt, \
             patch.object(analyzer.abuse_client, 'analyze_ip', new_callable=AsyncMock) as mock_abuse, \
             patch.object(analyzer.shodan_client, 'analyze_ip', new_callable=AsyncMock) as mock_shodan:
            
            mock_vt.return_value = vt_mock
            mock_abuse.return_value = abuse_mock
            mock_shodan.return_value = shodan_mock

            report = await analyzer.analyze(indicator)

            assert report.overall_threat_level == ThreatLevel.MALICIOUS
            assert "CRITICAL" in report.summary
            assert "10/72" in report.summary
            assert "abuse score of 95/100" in report.summary.lower()
            assert "80, 443" in report.summary

    @pytest.mark.asyncio
    async def test_analyze_graceful_degradation(self, analyzer):
        """Test that the analyzer works even if some APIs fail (return None)."""
        indicator = Indicator(type=IndicatorType.IP, value="8.8.8.8")
        
        vt_mock = VirusTotalResult(
            malicious=0, suspicious=0, clean=72, 
            total_engines=72, detection_ratio="0/72", 
            threat_level=ThreatLevel.CLEAN
        )

        with patch.object(analyzer.vt_client, 'analyze', new_callable=AsyncMock) as mock_vt, \
             patch.object(analyzer.abuse_client, 'analyze_ip', new_callable=AsyncMock) as mock_abuse, \
             patch.object(analyzer.shodan_client, 'analyze_ip', new_callable=AsyncMock) as mock_shodan:
            
            mock_vt.return_value = vt_mock
            mock_abuse.return_value = None  # API Failure/Rate limit
            mock_shodan.return_value = None # API Failure/Rate limit

            report = await analyzer.analyze(indicator)

            assert report.overall_threat_level == ThreatLevel.CLEAN
            assert report.virustotal is not None
            assert report.abuseipdb is None
            assert report.shodan is None
            assert "No significant threats detected" in report.summary

    def test_threat_level_calculation(self, analyzer):
        """Test the logic for calculating the overall threat level."""
        vt_mal = VirusTotalResult(malicious=1, suspicious=0, clean=0, total_engines=1, detection_ratio="1/1", threat_level=ThreatLevel.MALICIOUS)
        vt_sus = VirusTotalResult(malicious=0, suspicious=1, clean=0, total_engines=1, detection_ratio="0/1", threat_level=ThreatLevel.SUSPICIOUS)
        vt_cln = VirusTotalResult(malicious=0, suspicious=0, clean=1, total_engines=1, detection_ratio="0/1", threat_level=ThreatLevel.CLEAN)
        
        abuse_mal = AbuseIPDBResult(abuse_score=100, total_reports=1, threat_level=ThreatLevel.MALICIOUS)
        abuse_cln = AbuseIPDBResult(abuse_score=0, total_reports=0, threat_level=ThreatLevel.CLEAN)

        # Malicious wins
        assert analyzer._calculate_overall_threat_level(vt_mal, abuse_cln) == ThreatLevel.MALICIOUS
        assert analyzer._calculate_overall_threat_level(vt_cln, abuse_mal) == ThreatLevel.MALICIOUS
        
        # Suspicious wins over clean
        assert analyzer._calculate_overall_threat_level(vt_sus, abuse_cln) == ThreatLevel.SUSPICIOUS
        
        # Both clean
        assert analyzer._calculate_overall_threat_level(vt_cln, abuse_cln) == ThreatLevel.CLEAN
        
        # One None (graceful degradation)
        assert analyzer._calculate_overall_threat_level(vt_mal, None) == ThreatLevel.MALICIOUS
        assert analyzer._calculate_overall_threat_level(None, None) == ThreatLevel.UNKNOWN
