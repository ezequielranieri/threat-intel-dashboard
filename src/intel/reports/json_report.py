import json
from pathlib import Path
from src.intel.models.results import ThreatIntelReport

class JSONReporter:
    """Generates JSON reports from threat intelligence results."""

    def generate(self, report: ThreatIntelReport, output_path: Path) -> Path:
        """Saves the report as a JSON file.
        
        Args:
            report: The analysis report model.
            output_path: Target file path.
            
        Returns:
            The path to the generated report.
        """
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Serialize report using Pydantic's model_dump_json
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=4))
            
        return output_path
