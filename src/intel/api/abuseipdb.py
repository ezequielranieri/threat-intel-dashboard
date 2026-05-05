import httpx
import structlog
from datetime import datetime
from src.intel.config import settings
from src.intel.models.results import AbuseIPDBResult, ThreatLevel

logger = structlog.get_logger(__name__)

class AbuseIPDBClient:
    """Async client for AbuseIPDB API v2."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self) -> None:
        self.api_key = settings.abuseipdb_api_key
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }

    def _get_threat_level(self, score: int) -> ThreatLevel:
        """Determines threat level based on abuse confidence score."""
        if score >= 75:
            return ThreatLevel.MALICIOUS
        if score >= 25:
            return ThreatLevel.SUSPICIOUS
        return ThreatLevel.CLEAN

    async def analyze_ip(self, ip: str) -> AbuseIPDBResult | None:
        """Checks an IP reputation using AbuseIPDB.
        
        Args:
            ip: IPv4 or IPv6 address.
            
        Returns:
            AbuseIPDBResult if successful, None otherwise.
        """
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
            return None

        url = f"{self.BASE_URL}/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=self.headers, params=params)
                
                if response.status_code == 429:
                    logger.warning("AbuseIPDB rate limit exceeded", status_code=429)
                    return None
                if response.status_code in (401, 403):
                    logger.error("AbuseIPDB API key invalid or unauthorized", status_code=response.status_code)
                    return None
                
                response.raise_for_status()
                data = response.json()["data"]
                
                last_reported = None
                if data.get("lastReportedAt"):
                    # Format: 2024-05-05T12:00:00+00:00
                    last_reported = datetime.fromisoformat(data["lastReportedAt"].replace("Z", "+00:00"))

                score = data["abuseConfidenceScore"]
                
                return AbuseIPDBResult(
                    abuse_score=score,
                    total_reports=data["totalReports"],
                    last_reported=last_reported,
                    country=data.get("countryCode"),
                    isp=data.get("isp"),
                    threat_level=self._get_threat_level(score)
                )

        except httpx.HTTPStatusError as e:
            logger.error("AbuseIPDB API error", error=str(e), status_code=e.response.status_code)
            return None
        except Exception as e:
            logger.exception("Unexpected error querying AbuseIPDB", error=str(e))
            return None
