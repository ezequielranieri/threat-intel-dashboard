from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
from src.intel.models.indicators import IndicatorType

class ThreatLevel(str, Enum):
    """Standardized threat levels."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"

class VirusTotalResult(BaseModel):
    """Result from VirusTotal API."""
    malicious: int
    suspicious: int
    clean: int
    total_engines: int
    detection_ratio: str
    threat_level: ThreatLevel

class AbuseIPDBResult(BaseModel):
    """Result from AbuseIPDB API."""
    abuse_score: int = Field(ge=0, le=100)
    total_reports: int
    last_reported: datetime | None = None
    country: str | None = None
    isp: str | None = None
    threat_level: ThreatLevel

class ShodanResult(BaseModel):
    """Result from Shodan API."""
    open_ports: list[int] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    country: str | None = None
    city: str | None = None
    isp: str | None = None
    last_update: str | None = None

class ThreatIntelReport(BaseModel):
    """Correlated report from multiple intelligence sources."""
    indicator: str
    indicator_type: IndicatorType
    scan_timestamp: datetime = Field(default_factory=datetime.now)
    overall_threat_level: ThreatLevel
    virustotal: VirusTotalResult | None = None
    abuseipdb: AbuseIPDBResult | None = None
    shodan: ShodanResult | None = None
    summary: str
