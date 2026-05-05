import pytest
from typer.testing import CliRunner
from src.intel.cli import app
from unittest.mock import patch, AsyncMock
from src.intel.models.results import ThreatIntelReport, ThreatLevel, IndicatorType
from datetime import datetime

runner = CliRunner()

class TestCLIIntegration:
    """Integration tests for the CLI."""

    def test_analyze_invalid_indicator_type(self):
        """Should fail with exit code 1 when indicator type is invalid."""
        result = runner.invoke(app, ["analyze", "invalid_type", "8.8.8.8"])
        assert result.exit_code == 1
        assert "Invalid input" in result.stdout

    def test_analyze_invalid_ip_format(self):
        """Should fail when IP format is invalid."""
        result = runner.invoke(app, ["analyze", "ip", "999.999.999.999"])
        assert result.exit_code == 1
        assert "Invalid input" in result.stdout

    @patch("src.intel.core.analyzer.ThreatAnalyzer.analyze", new_callable=AsyncMock)
    def test_analyze_success_path(self, mock_analyze):
        """Should display the report when analysis is successful."""
        mock_report = ThreatIntelReport(
            indicator="8.8.8.8",
            indicator_type=IndicatorType.IP,
            scan_timestamp=datetime.now(),
            overall_threat_level=ThreatLevel.CLEAN,
            summary="Test Summary"
        )
        mock_analyze.return_value = mock_report

        result = runner.invoke(app, ["analyze", "ip", "8.8.8.8"])
        
        assert result.exit_code == 0
        assert "THREAT INTELLIGENCE REPORT" in result.stdout
        assert "8.8.8.8" in result.stdout
        assert "CLEAN" in result.stdout
        assert "Test Summary" in result.stdout
