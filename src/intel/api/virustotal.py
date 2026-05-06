import httpx
import structlog
import base64
import asyncio
from urllib.parse import quote
from typing import Any
from src.intel.config import settings
from src.intel.models.results import VirusTotalResult, ThreatLevel
from src.intel.models.indicators import IndicatorType

logger = structlog.get_logger(__name__)

class VirusTotalClient:
    """Async client for VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self) -> None:
        self.api_key = settings.virustotal_api_key
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    def _get_threat_level(self, malicious: int, total: int) -> ThreatLevel:
        """Determines threat level based on detection ratio."""
        if total == 0:
            return ThreatLevel.UNKNOWN
        ratio = malicious / total
        if ratio > 0.1:  # More than 10% malicious
            return ThreatLevel.MALICIOUS
        if ratio > 0:
            return ThreatLevel.SUSPICIOUS
        return ThreatLevel.CLEAN

    async def analyze(self, type: IndicatorType, value: str) -> VirusTotalResult | None:
        """Analyzes an indicator using VirusTotal.
        
        Args:
            type: Indicator type (ip, domain, url, hash).
            value: The indicator value.
            
        Returns:
            VirusTotalResult if successful, None otherwise.
        """
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None

        # VT v3 endpoints: /ip_addresses/{ip}, /domains/{domain}, /urls/{id}, /files/{hash}
        if type == IndicatorType.IP:
            endpoint = f"ip_addresses/{value}"
        elif type == IndicatorType.DOMAIN:
            endpoint = f"domains/{value}"
        elif type == IndicatorType.HASH:
            endpoint = f"files/{value}"
        elif type == IndicatorType.URL:
            # For URLs, VT v3 requires base64 encoding without padding for the ID
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            endpoint = f"urls/{url_id}"
        else:
            return None

        url = f"{self.BASE_URL}/{endpoint}"
        
        max_retries = 3
        for attempt in range(max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(url, headers=self.headers)
                    
                    if response.status_code == 429:
                        if attempt < max_retries:
                            wait_time = 2**attempt
                            logger.warning(
                                "VirusTotal rate limit exceeded, retrying...",
                                attempt=attempt + 1,
                                wait_time=wait_time
                            )
                            await asyncio.sleep(wait_time)
                            continue
                        else:
                            logger.warning("VirusTotal rate limit exceeded, max retries reached", status_code=429)
                            return None

                    if response.status_code in (401, 403):
                        logger.error("VirusTotal API key invalid or unauthorized", status_code=response.status_code)
                        return None
                    
                    response.raise_for_status()
                    data = response.json()
                    
                    stats = data["data"]["attributes"]["last_analysis_stats"]
                    malicious = stats["malicious"]
                    suspicious = stats["suspicious"]
                    clean = stats["harmless"] + stats["undetected"]
                    total = sum(stats.values())
                    
                    return VirusTotalResult(
                        malicious=malicious,
                        suspicious=suspicious,
                        clean=clean,
                        total_engines=total,
                        detection_ratio=f"{malicious}/{total}",
                        threat_level=self._get_threat_level(malicious, total)
                    )

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.info("Indicator not found in VirusTotal", indicator=value)
                else:
                    logger.error("VirusTotal API error", error=str(e), status_code=e.response.status_code)
                return None
            except Exception as e:
                logger.exception("Unexpected error querying VirusTotal", error=str(e))
                return None
        
        return None
