from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Centralized configuration for the Threat Intelligence Dashboard.
    
    Attributes:
        app_name: Name of the application.
        debug: Debug mode flag.
        virustotal_api_key: API key for VirusTotal.
        abuseipdb_api_key: API key for AbuseIPDB.
        shodan_api_key: API key for Shodan.
    """
    app_name: str = "threat-intel"
    debug: bool = False
    
    # API Keys
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    shodan_api_key: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
