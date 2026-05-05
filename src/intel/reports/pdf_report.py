from pathlib import Path
from reportlab.lib.pagesizes import LETTER
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from src.intel.models.results import ThreatIntelReport, ThreatLevel

class PDFReporter:
    """Generates professional PDF reports from threat intelligence results."""

    def _get_color(self, level: ThreatLevel) -> colors.Color:
        """Maps threat level to ReportLab colors."""
        if level == ThreatLevel.MALICIOUS:
            return colors.red
        if level == ThreatLevel.SUSPICIOUS:
            return colors.orange
        if level == ThreatLevel.CLEAN:
            return colors.green
        return colors.grey

    def generate(self, report: ThreatIntelReport, output_path: Path) -> Path:
        """Generates a PDF report.
        
        Args:
            report: The analysis report model.
            output_path: Target file path.
            
        Returns:
            The path to the generated report.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        doc = SimpleDocTemplate(str(output_path), pagesize=LETTER)
        styles = getSampleStyleSheet()
        elements = []

        # Title
        title_style = styles["Title"]
        elements.append(Paragraph("Threat Intelligence Report", title_style))
        elements.append(Spacer(1, 12))

        # Main Info
        level_color = self._get_color(report.overall_threat_level)
        info_data = [
            ["Indicator", report.indicator],
            ["Type", report.indicator_type.value.upper()],
            ["Timestamp", report.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S")],
            ["Overall Threat Level", Paragraph(f"<font color={level_color.hexval()}>{report.overall_threat_level.value.upper()}</font>", styles["Normal"])]
        ]
        
        info_table = Table(info_data, colWidths=[150, 300])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 24))

        # VirusTotal
        if report.virustotal:
            elements.append(Paragraph("VirusTotal Findings", styles["Heading2"]))
            vt = report.virustotal
            vt_data = [
                ["Detection Ratio", vt.detection_ratio],
                ["Malicious", str(vt.malicious)],
                ["Suspicious", str(vt.suspicious)],
                ["Clean/Undetected", str(vt.clean)],
                ["Total Engines", str(vt.total_engines)],
                ["Threat Level", Paragraph(f"<font color={self._get_color(vt.threat_level).hexval()}>{vt.threat_level.value.upper()}</font>", styles["Normal"])]
            ]
            vt_table = Table(vt_data, colWidths=[150, 300])
            vt_table.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.grey)]))
            elements.append(vt_table)
            elements.append(Spacer(1, 12))

        # AbuseIPDB
        if report.abuseipdb:
            elements.append(Paragraph("AbuseIPDB Reputation", styles["Heading2"]))
            abuse = report.abuseipdb
            abuse_data = [
                ["Abuse Confidence Score", f"{abuse.abuse_score}/100"],
                ["Total Reports", str(abuse.total_reports)],
                ["ISP", abuse.isp or "Unknown"],
                ["Country", abuse.country or "Unknown"],
                ["Threat Level", Paragraph(f"<font color={self._get_color(abuse.threat_level).hexval()}>{abuse.threat_level.value.upper()}</font>", styles["Normal"])]
            ]
            abuse_table = Table(abuse_data, colWidths=[150, 300])
            abuse_table.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.grey)]))
            elements.append(abuse_table)
            elements.append(Spacer(1, 12))

        # Summary
        elements.append(Paragraph("Executive Summary", styles["Heading2"]))
        elements.append(Paragraph(report.summary, styles["Normal"]))

        doc.build(elements)
        return output_path
