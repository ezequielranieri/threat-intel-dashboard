# Threat Intel Dashboard

**A professional CLI tool for rapid security indicator analysis and correlation.**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

---

## 🔍 Why this project?

In the fast-paced world of cybersecurity, security researchers and sysadmins often need to quickly assess the reputation of an IP, domain, or file hash. Manually visiting multiple websites is time-consuming. 

**Threat Intel Dashboard** solves this by:
- **Correlating Data:** Fetching data from VirusTotal, AbuseIPDB, and Shodan simultaneously.
- **Intelligent Assessment:** Automatically calculating a unified threat level.
- **Professional Reporting:** Generating actionable summaries and PDF/JSON reports directly from the terminal.
- **Graceful Degradation:** Providing results even if one source is down or rate-limited.

---

## ✨ Features

- 🚀 **Async Analysis:** Blazing fast parallel API queries.
- 🛡️ **Surgical Validation:** Strict input sanitization (blocks private IPs, validates hash formats).
- 🎨 **Rich UI:** Beautifully formatted terminal output with tables and progress bars.
- 📊 **Dual Reporting:** Export results to professional PDF documents or structured JSON.
- 🔒 **Security First:** Environment-based configuration and masked API keys in logs.

---

## 🛠️ Stack & Architecture

- **Language:** Python 3.12+
- **CLI Framework:** [Typer](https://typer.tiangolo.com/)
- **UI & Formatting:** [Rich](https://rich.readthedocs.io/)
- **Async HTTP:** [httpx](https://www.python-httpx.org/)
- **Data Validation:** [Pydantic v2](https://docs.pydantic.dev/)
- **Configuration:** [Pydantic-Settings](https://docs.pydantic.dev/latest/usage/pydantic_settings/)
- **Logging:** [structlog](https://www.structlog.org/)
- **PDF Generation:** [ReportLab](https://www.reportlab.com/)
- **Testing:** [pytest](https://docs.pytest.org/) & [respx](https://lungze.github.io/respx/)

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.12 or higher.

### 2. Obtain Free API Keys
This tool uses the free tiers of the following services:
1. **VirusTotal:** [Join here](https://www.virustotal.com/gui/join-us) to get your API key.
2. **AbuseIPDB:** [Register here](https://www.abuseipdb.com/register) to get your API key.
3. **Shodan:** [Sign up here](https://account.shodan.io/register) to get your API key.
### 3. Installation
```bash
# Clone the repository
git clone https://github.com/ezequielranieri/threat-intel-dashboard.git
cd threat-intel-dashboard

# Install the package in editable mode
pip install -e .
```

---

## 4. Configuration
Create a `.env` file in the root directory (use `.env.example` as a template):
```env
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
```

---

## 📖 Usage Examples

### Analyze an IP Address
```bash
threat-intel analyze ip 8.8.8.8
```

### Analyze and Export to PDF
```bash
threat-intel analyze domain malicious.com --format pdf --output analysis.pdf
```

### Generate a JSON report from the last analysis
```bash
threat-intel report --format json --output report.json
```

### Expected Output
The tool provides a clean, color-coded summary:
- **Red (Critical):** High confidence malicious indicator.
- **Yellow (Warning):** Suspicious activity detected.
- **Green (Clean):** No threats found in enabled sources.

---

## 🧪 Testing
The project includes unit and integration tests covering validators, API clients, and the CLI.
```bash
# Run all tests
pytest
```

---

## 👨‍💻 About the Author

**Ezequiel Ranieri**  
*Self-Taught Backend & Security Developer*

I am a passionate developer dedicated to building secure, efficient, and well-architected software. This project reflects my journey in mastering Python's async ecosystem, data validation patterns, and my deep interest in cybersecurity tools. I believe in writing clean, documented code that solves real-world problems.

- **Email:** ez.ranieri@gmail.com
- **GitHub:** [ezequielranieri](https://github.com/ezequielranieri)
- **LinkedIn:** [ezequielranieri](https://linkedin.com/in/ezequielranieri)

---

## ⚖️ License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
