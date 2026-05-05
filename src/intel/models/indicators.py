from enum import Enum
from pydantic import BaseModel, Field, field_validator
from src.intel.core.validator import is_public_ip, validate_domain, validate_hash, validate_url

class IndicatorType(str, Enum):
    """Supported security indicator types."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"

class Indicator(BaseModel):
    """Base model for a security indicator.
    
    Attributes:
        type: The type of indicator.
        value: The indicator value (IP, domain, etc.).
    """
    type: IndicatorType
    value: str

    @field_validator("value")
    @classmethod
    def validate_indicator_value(cls, v: str, info) -> str:
        """Surgical validation based on indicator type."""
        indicator_type = info.data.get("type")
        if not indicator_type:
            return v
            
        if indicator_type == IndicatorType.IP:
            return is_public_ip(v)
        if indicator_type == IndicatorType.DOMAIN:
            return validate_domain(v)
        if indicator_type == IndicatorType.URL:
            return validate_url(v)
        if indicator_type == IndicatorType.HASH:
            return validate_hash(v)
        return v
