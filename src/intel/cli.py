import asyncio
import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from pydantic import ValidationError
from src.intel.models.indicators import Indicator, IndicatorType
from src.intel.models.results import ThreatLevel, ThreatIntelReport
from src.intel.core.analyzer import ThreatAnalyzer
from src.intel.reports.json_report import JSONReporter
from src.intel.reports.pdf_report import PDFReporter

app = typer.Typer(
    help="Threat Intelligence Dashboard - Analyze IPs, domains, URLs and hashes.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()
analyzer = ThreatAnalyzer()

# Persistence for "last analysis" (simple file-based)
LAST_REPORT_PATH = Path(".last_report.json")

def get_level_color(level: ThreatLevel) -> str:
    """Returns the color associated with a threat level."""
    colors = {
        ThreatLevel.MALICIOUS: "red",
        ThreatLevel.SUSPICIOUS: "yellow",
        ThreatLevel.CLEAN: "green",
        ThreatLevel.UNKNOWN: "white",
    }
    return colors.get(level, "white")

def display_report(report: ThreatIntelReport):
    """Displays the correlated threat report using Rich."""
    
    # Header Panel
    color = get_level_color(report.overall_threat_level)
    emoji = "🔴" if report.overall_threat_level == ThreatLevel.MALICIOUS else "🟡" if report.overall_threat_level == ThreatLevel.SUSPICIOUS else "🟢"
    
    console.print(Panel(
        f"[bold]Indicator:[/] {report.indicator} ({report.indicator_type.value.upper()})\n"
        f"[bold]Threat Level:[/] [{color}]{emoji} {report.overall_threat_level.value.upper()}[/]",
        title="[bold blue]THREAT INTELLIGENCE REPORT[/]",
        expand=False,
        border_style=color
    ))

    # VirusTotal Table
    if report.virustotal:
        vt = report.virustotal
        vt_color = get_level_color(vt.threat_level)
        vt_table = Table(title="📊 VirusTotal", box=None, show_header=False, padding=(0, 2))
        vt_table.add_row("Detection", f"{vt.detection_ratio} engines flagged as malicious")
        vt_table.add_row("Threat Level", f"[{vt_color}]{vt.threat_level.value.upper()}[/]")
        console.print(vt_table)

    # AbuseIPDB Table (only for IP)
    if report.abuseipdb:
        abuse = report.abuseipdb
        abuse_color = get_level_color(abuse.threat_level)
        abuse_table = Table(title="🚨 AbuseIPDB", box=None, show_header=False, padding=(0, 2))
        abuse_table.add_row("Abuse Score", f"{abuse.abuse_score}/100")
        abuse_table.add_row("Total Reports", str(abuse.total_reports))
        if abuse.country:
            abuse_table.add_row("Country", abuse.country)
        if abuse.isp:
            abuse_table.add_row("ISP", abuse.isp)
        abuse_table.add_row("Threat Level", f"[{abuse_color}]{abuse.threat_level.value.upper()}[/]")
        console.print(abuse_table)

    # Shodan Table (only for IP)
    if report.shodan:
        shodan = report.shodan
        shodan_table = Table(title="🔍 Shodan", box=None, show_header=False, padding=(0, 2))
        if shodan.open_ports:
            shodan_table.add_row("Open Ports", ", ".join(map(str, shodan.open_ports)))
        if shodan.services:
            shodan_table.add_row("Services", ", ".join(shodan.services))
        if shodan.isp:
            shodan_table.add_row("ISP", shodan.isp)
        console.print(shodan_table)

    # Summary
    console.print(Panel(
        report.summary,
        title="[bold]📝 Summary[/]",
        border_style="blue",
        expand=False
    ))

@app.command()
def analyze(
    type: str = typer.Argument(..., help="Type of indicator: ip, domain, url, hash"),
    value: str = typer.Argument(..., help="The indicator value to analyze"),
    format: Optional[str] = typer.Option(None, "--format", "-f", help="Export format: json, pdf"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """Analyze a security indicator (IP, domain, URL, or hash)."""
    
    # 1. Validate Input
    try:
        indicator = Indicator(type=IndicatorType(type.lower()), value=value)
    except (ValueError, ValidationError) as e:
        console.print(f"[bold red]Error:[/] Invalid input. {str(e)}")
        raise typer.Exit(code=1)

    # 2. Run Analysis with Progress
    async def run_analysis():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            progress.add_task(description=f"Analyzing {indicator.type.value}: [bold blue]{indicator.value}[/]...", total=None)
            return await analyzer.analyze(indicator)

    report = asyncio.run(run_analysis())

    # 3. Save as last report
    with open(LAST_REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json())

    # 4. Display Results
    console.print("\n")
    display_report(report)

    # 5. Handle immediate export if requested
    if format:
        _export_report(report, format, output)

@app.command()
def report(
    format: str = typer.Option("pdf", "--format", "-f", help="Export format: json, pdf"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file path"),
):
    """Generate a report from the last analysis."""
    if not LAST_REPORT_PATH.exists():
        console.print("[bold red]Error:[/] No previous analysis found. Run 'analyze' first.")
        raise typer.Exit(code=1)

    try:
        with open(LAST_REPORT_PATH, "r", encoding="utf-8") as f:
            report_data = f.read()
            report = ThreatIntelReport.model_validate_json(report_data)
        
        _export_report(report, format, output)
    except Exception as e:
        console.print(f"[bold red]Error:[/] Failed to generate report. {str(e)}")
        raise typer.Exit(code=1)

def _export_report(report: ThreatIntelReport, format: str, output: Optional[Path]):
    """Helper to export report to file."""
    if not output:
        output = Path(f"report_{report.indicator}.{format.lower()}")

    console.print(f"Generating [bold]{format.upper()}[/] report...")
    
    if format.lower() == "json":
        JSONReporter().generate(report, output)
    elif format.lower() == "pdf":
        PDFReporter().generate(report, output)
    else:
        console.print(f"[bold red]Error:[/] Unsupported format: {format}")
        raise typer.Exit(code=1)

    console.print(f"[bold green]Success![/] Report saved to: [blue]{output}[/]")

@app.callback()
def main():
    """
    Threat Intelligence Dashboard - Portfolio Project
    Consumes public security APIs to provide actionable intelligence.
    """
    pass

if __name__ == "__main__":
    app()
