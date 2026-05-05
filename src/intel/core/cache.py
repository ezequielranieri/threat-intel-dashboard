import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
import structlog

from src.intel.models.results import ThreatIntelReport

logger = structlog.get_logger(__name__)

class ThreatCache:
    """SQLite-based cache for threat intelligence reports."""

    def __init__(self, db_path: str = "threat_cache.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initializes the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    indicator TEXT PRIMARY KEY,
                    indicator_type TEXT,
                    data TEXT,
                    timestamp DATETIME
                )
            """)
            conn.commit()

    def get(self, indicator: str, ttl_hours: int = 24) -> Optional[ThreatIntelReport]:
        """Retrieves a cached report if it's within the TTL.
        
        Args:
            indicator: The indicator value (key).
            ttl_hours: Time-to-live in hours.
            
        Returns:
            ThreatIntelReport if found and valid, None otherwise.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT data, timestamp FROM cache WHERE indicator = ?",
                    (indicator,)
                )
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                data_json, timestamp_str = row
                cached_time = datetime.fromisoformat(timestamp_str)
                
                if datetime.now() - cached_time > timedelta(hours=ttl_hours):
                    logger.debug("Cache expired for indicator", indicator=indicator)
                    return None
                
                logger.info("Cache hit", indicator=indicator)
                return ThreatIntelReport.model_validate_json(data_json)
                
        except Exception as e:
            logger.error("Error reading from cache", error=str(e))
            return None

    def set(self, indicator: str, indicator_type: str, report: ThreatIntelReport) -> None:
        """Stores a report in the cache.
        
        Args:
            indicator: The indicator value (key).
            indicator_type: The type of indicator.
            report: The report model to store.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cache (indicator, indicator_type, data, timestamp)
                    VALUES (?, ?, ?, ?)
                    """,
                    (indicator, indicator_type, report.model_dump_json(), datetime.now().isoformat())
                )
                conn.commit()
        except Exception as e:
            logger.error("Error writing to cache", error=str(e))
