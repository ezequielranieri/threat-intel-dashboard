import pytest
import os
from datetime import datetime, timedelta
from src.intel.core.cache import ThreatCache
from src.intel.models.results import ThreatIntelReport, ThreatLevel, IndicatorType

@pytest.fixture
def cache(tmp_path):
    db_file = tmp_path / "test_cache.db"
    return ThreatCache(db_path=str(db_file))

@pytest.fixture
def sample_report():
    return ThreatIntelReport(
        indicator="8.8.8.8",
        indicator_type=IndicatorType.IP,
        scan_timestamp=datetime.now(),
        overall_threat_level=ThreatLevel.CLEAN,
        summary="Test summary."
    )

class TestThreatCache:
    """Unit tests for the SQLite cache logic."""

    def test_cache_set_and_get(self, cache, sample_report):
        """Storing and retrieving a report should work."""
        cache.set("8.8.8.8", "ip", sample_report)
        retrieved = cache.get("8.8.8.8")
        
        assert retrieved is not None
        assert retrieved.indicator == sample_report.indicator
        assert retrieved.overall_threat_level == sample_report.overall_threat_level

    def test_cache_expiration(self, cache, sample_report):
        """Expired entries should return None."""
        # Manually insert an old record
        import sqlite3
        with sqlite3.connect(cache.db_path) as conn:
            old_time = datetime.now() - timedelta(hours=25)
            conn.execute(
                "INSERT INTO cache (indicator, indicator_type, data, timestamp) VALUES (?, ?, ?, ?)",
                ("1.1.1.1", "ip", sample_report.model_dump_json(), old_time.isoformat())
            )
            conn.commit()
            
        # Should be None because 25h > 24h default TTL
        assert cache.get("1.1.1.1") is None

    def test_cache_miss(self, cache):
        """Non-existent indicators should return None."""
        assert cache.get("non-existent") is None
