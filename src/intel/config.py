from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from rich import print as rprint

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

    @model_validator(mode="after")
    def check_api_keys(self) -> "Settings":
        """Warns the user if any API keys are missing."""
        missing = []
        if not self.virustotal_api_key:
            missing.append("VIRUSTOTAL_API_KEY")
        if not self.abuseipdb_api_key:
            missing.append("ABUSEIPDB_API_KEY")
        if not self.shodan_api_key:
            missing.append("SHODAN_API_KEY")
        
        if missing:
            rprint(f"[bold yellow]WARNING:[/] Missing API keys: {', '.join(missing)}")
            rprint("[dim]Analysis for these sources will be skipped. Update your .env file.[/]")
        
        return self

settings = Settings()
