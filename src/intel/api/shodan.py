import httpx
import structlog
from src.intel.config import settings
from src.intel.models.results import ShodanResult

logger = structlog.get_logger(__name__)

class ShodanClient:
    """Async client for Shodan API."""

    BASE_URL = "https://api.shodan.io"

    def __init__(self) -> None:
        self.api_key = settings.shodan_api_key

    async def analyze_ip(self, ip: str) -> ShodanResult | None:
        """Gets information about an IP from Shodan.
        
        Args:
            ip: IPv4 address.
            
        Returns:
            ShodanResult if successful, None otherwise.
        """
        if not self.api_key:
            logger.warning("Shodan API key not configured")
            return None

        url = f"{self.BASE_URL}/shodan/host/{ip}"
        params = {"key": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url, params=params)
                
                if response.status_code == 429:
                    logger.warning("Shodan rate limit exceeded", status_code=429)
                    return None
                if response.status_code in (401, 403):
                    logger.error("Shodan API key invalid or unauthorized", status_code=response.status_code)
                    return None
                
                response.raise_for_status()
                data = response.json()
                
                return ShodanResult(
                    open_ports=data.get("ports", []),
                    services=[item.get("transport", "") for item in data.get("data", []) if item.get("transport")],
                    country=data.get("country_name"),
                    city=data.get("city"),
                    isp=data.get("isp"),
                    last_update=data.get("last_update")
                )

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.info("IP not found in Shodan", ip=ip)
            else:
                logger.error("Shodan API error", error=str(e), status_code=e.response.status_code)
            return None
        except Exception as e:
            logger.exception("Unexpected error querying Shodan", error=str(e))
            return None
