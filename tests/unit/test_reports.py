import pytest
from pathlib import Path
from src.intel.models.results import ThreatIntelReport, ThreatLevel, IndicatorType
from src.intel.reports.json_report import JSONReporter
from src.intel.reports.pdf_report import PDFReporter
from datetime import datetime

@pytest.fixture
def sample_report():
    return ThreatIntelReport(
        indicator="8.8.8.8",
        indicator_type=IndicatorType.IP,
        scan_timestamp=datetime.now(),
        overall_threat_level=ThreatLevel.CLEAN,
        summary="Test summary for reports."
    )

def test_json_report_generation(sample_report, tmp_path):
    """Test that JSON report is correctly generated."""
    output = tmp_path / "report.json"
    reporter = JSONReporter()
    reporter.generate(sample_report, output)
    
    assert output.exists()
    content = output.read_text()
    assert "8.8.8.8" in content
    assert "clean" in content

def test_pdf_report_generation(sample_report, tmp_path):
    """Test that PDF report is correctly generated."""
    output = tmp_path / "report.pdf"
    reporter = PDFReporter()
    reporter.generate(sample_report, output)
    
    assert output.exists()
    assert output.stat().st_size > 0
