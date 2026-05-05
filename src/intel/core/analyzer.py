import asyncio
import structlog
from datetime import datetime
from typing import Any

from src.intel.api.virustotal import VirusTotalClient
from src.intel.api.abuseipdb import AbuseIPDBClient
from src.intel.api.shodan import ShodanClient
from src.intel.core.cache import ThreatCache
from src.intel.models.indicators import Indicator, IndicatorType
from src.intel.models.results import (
    ThreatIntelReport, 
    ThreatLevel, 
    VirusTotalResult, 
    AbuseIPDBResult, 
    ShodanResult
)

logger = structlog.get_logger(__name__)

class ThreatAnalyzer:
    """Core engine for correlating threat intelligence from multiple sources."""

    def __init__(self) -> None:
        self.vt_client = VirusTotalClient()
        self.abuse_client = AbuseIPDBClient()
        self.shodan_client = ShodanClient()
        self.cache = ThreatCache()

    def _calculate_overall_threat_level(
        self, 
        vt: VirusTotalResult | None, 
        abuse: AbuseIPDBResult | None
    ) -> ThreatLevel:
        """Calculates the weighted overall threat level.
        
        Logic:
        - If any source says MALICIOUS -> MALICIOUS
        - If both are SUSPICIOUS or one is SUSPICIOUS and other is unknown/clean -> SUSPICIOUS
        - If both are CLEAN -> CLEAN
        - Otherwise UNKNOWN
        """
        levels = []
        if vt:
            levels.append(vt.threat_level)
        if abuse:
            levels.append(abuse.threat_level)

        if not levels:
            return ThreatLevel.UNKNOWN

        if ThreatLevel.MALICIOUS in levels:
            return ThreatLevel.MALICIOUS
        
        if ThreatLevel.SUSPICIOUS in levels:
            return ThreatLevel.SUSPICIOUS

        if all(level == ThreatLevel.CLEAN for level in levels):
            return ThreatLevel.CLEAN

        return ThreatLevel.UNKNOWN

    def _generate_summary(
        self, 
        indicator: Indicator, 
        overall_level: ThreatLevel,
        vt: VirusTotalResult | None,
        abuse: AbuseIPDBResult | None,
        shodan: ShodanResult | None
    ) -> str:
        """Generates a human-readable summary of the findings."""
        if overall_level == ThreatLevel.MALICIOUS:
            summary = f"CRITICAL: The {indicator.type} {indicator.value} is highly likely to be malicious. "
        elif overall_level == ThreatLevel.SUSPICIOUS:
            summary = f"WARNING: The {indicator.type} {indicator.value} shows suspicious activity. "
        else:
            summary = f"INFO: No significant threats detected for {indicator.value}. "

        details = []
        if vt and vt.malicious > 0:
            details.append(f"Flagged by {vt.detection_ratio} engines on VirusTotal")
        
        if abuse and abuse.abuse_score > 0:
            details.append(f"Abuse score of {abuse.abuse_score}/100 with {abuse.total_reports} reports on AbuseIPDB")

        if shodan and shodan.open_ports:
            details.append(f"Exposed ports: {', '.join(map(str, shodan.open_ports))}")

        if details:
            summary += "Key findings: " + "; ".join(details) + "."
        else:
            summary += "No specific malicious details found in analyzed sources."

        return summary

    async def analyze(self, indicator: Indicator) -> ThreatIntelReport:
        """Orchestrates async analysis across all enabled APIs.
        
        Args:
            indicator: The validated security indicator to analyze.
            
        Returns:
            A correlated ThreatIntelReport.
        """
        # 1. Check Cache
        cached_report = self.cache.get(indicator.value)
        if cached_report:
            return cached_report

        logger.info("Starting fresh analysis", type=indicator.type.value, value=indicator.value)

        # Run API calls in parallel
        tasks = [
            self.vt_client.analyze(indicator.type, indicator.value)
        ]
        
        # AbuseIPDB and Shodan currently only support IP analysis in our implementation
        if indicator.type == IndicatorType.IP:
            tasks.append(self.abuse_client.analyze_ip(indicator.value))
            tasks.append(self.shodan_client.analyze_ip(indicator.value))
        else:
            tasks.append(asyncio.sleep(0, result=None)) # Placeholder for AbuseIPDB
            tasks.append(asyncio.sleep(0, result=None)) # Placeholder for Shodan

        vt_res, abuse_res, shodan_res = await asyncio.gather(*tasks)

        overall_level = self._calculate_overall_threat_level(vt_res, abuse_res)
        summary = self._generate_summary(indicator, overall_level, vt_res, abuse_res, shodan_res)

        report = ThreatIntelReport(
            indicator=indicator.value,
            indicator_type=indicator.type,
            scan_timestamp=datetime.now(),
            overall_threat_level=overall_level,
            virustotal=vt_res,
            abuseipdb=abuse_res,
            shodan=shodan_res,
            summary=summary
        )

        # 2. Store in Cache
        self.cache.set(indicator.value, indicator.type.value, report)
        
        return report
