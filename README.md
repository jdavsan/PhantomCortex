# 🛡️ PhantomCortex

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**Open Source Cyber Threat Intelligence Platform**

🌐 Automated threat collection • 🤖 Offline translation • 📊 Intelligence reports • 🚨 Real-time alerts

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 📖 Overview

**PhantomCortex** is an open-source Cyber Threat Intelligence (CTI) platform designed for security teams, researchers, and students. It automatically collects, analyzes, and reports on emerging cybersecurity threats from multiple RSS feeds worldwide.

### 🎯 Purpose

- **Automate** threat intelligence gathering from 17+ public sources
- **Translate** threat descriptions to multiple languages using offline AI
- **Analyze** vulnerabilities based on severity and affected technologies
- **Alert** security teams via email with actionable intelligence
- **Report** monthly executive summaries in professional formats

---

## ✨ Features

### 🔍 **Threat Collection**
- Multi-source RSS feed aggregation (CISA, NVD, security blogs, vendors)
- Intelligent deduplication and filtering
- CVE tracking and correlation
- Technology-specific monitoring (Windows, Linux, Apache, Docker, etc.)

### 🤖 **Offline Translation**
- Powered by [Argos Translate](https://github.com/argosopentech/argos-translate)
- No API keys or internet required for translation
- English → Spanish (easily extensible to other languages)
- Privacy-focused: all processing happens locally

### 📊 **Intelligence Analysis**
- Severity classification (Critical, High, Medium)
- CVSS score estimation
- Impact assessment
- Remediation recommendations in local language

### 🚨 **Alert System**
- HTML email alerts with responsive design
- Configurable severity thresholds
- Daily digest of critical threats
- Executive summaries with actionable insights

### 📄 **Reporting**
- Automated monthly Word documents
- Professional formatting with charts and tables
- Detailed vulnerability analysis
- Technology impact breakdown

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     PhantomCortex                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌─────────────┐    │
│  │   RSS Feeds  │───▶│  Collection  │───▶│  Analysis  │    │
│  │   (17+)      │    │   Engine     │    │   Engine    │    │
│  └──────────────┘    └──────────────┘    └─────────────┘    │
│                             │                     │         │
│                             ▼                     ▼         │
│                      ┌──────────────┐    ┌─────────────┐    │
│                      │ Translation  │    │  Filtering  │    │
│                      │   (Argos)    │    │  & Dedup    │    │
│                      └──────────────┘    └─────────────┘    │
│                             │                     │         │
│                             └──────────┬──────────┘         │
│                                        ▼                    │
│                              ┌──────────────────┐           │
│                              │  Intelligence    │           │
│                              │    Database      │           │
│                              └──────────────────┘           │
│                                        │                    │
│                    ┌───────────────────┼───────────────┐    │
│                    ▼                   ▼               ▼    │
│            ┌─────────────┐    ┌─────────────┐  ┌─────────┐  │
│            │   Alerts    │    │   Reports   │  │  API    │  │
│            │   (Email)   │    │   (Word)    │  │ (Future)│  │
│            └─────────────┘    └─────────────┘  └─────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- 2GB free disk space
- SMTP server access (for email alerts)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/PhantomCortex.git
cd PhantomCortex

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download translation model (English → Spanish)
python scripts/setup_translation.py

# Configure your environment
cp config/config.example.yaml config/config.yaml
nano config/config.yaml  # Edit with your settings
```

### Basic Usage

```bash
# Collect threats from all sources
python core/collector.py

# Translate threats to target language
python modules/translator.py

# Send email alert with latest threats
python modules/alerting.py

# Generate monthly report
python modules/reporting.py --month 2025-01

# Run full pipeline
./scripts/run_daily.sh
```

### Docker Installation (Alternative)

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## 📋 Configuration

### Main Configuration File

Edit `config/config.yaml`:

```yaml
# RSS Feed Sources
feeds:
  enabled: true
  max_age_days: 30
  sources_file: config/sources.yaml

# Technologies to Monitor
technologies:
  - windows
  - linux
  - apache
  - nginx
  - docker
  # Add your infrastructure technologies here

# Email Alerts
email:
  enabled: true
  smtp_server: smtp.example.com
  smtp_port: 587
  from: alerts@example.com
  to: 
    - security@example.com
  severity_threshold: HIGH  # CRITICAL, HIGH, MEDIUM, LOW

# Translation
translation:
  enabled: true
  source_lang: en
  target_lang: es
  offline: true  # Uses Argos Translate

# Reports
reports:
  format: docx  # docx, pdf (future)
  monthly: true
  output_dir: data/reports
```

### Customizable Files

| File | Purpose | What to Modify |
|------|---------|----------------|
| `config/config.yaml` | Main settings | Email, thresholds, technologies |
| `config/sources.yaml` | RSS feed list | Add/remove threat sources |
| `config/technologies.yaml` | Tech keywords | Your infrastructure stack |
| `config/email_template.html` | Alert design | Colors, layout, branding |
| `core/severity_rules.py` | Severity logic | Keyword rules, CVSS thresholds |

---

## 🎓 Use Cases

### 1. **Small Security Team**
Monitor threats relevant to your infrastructure without expensive SIEM tools.

### 2. **Security Researcher**
Aggregate threat intelligence from multiple sources for analysis and correlation.

### 3. **Educational Environment**
Learn about CTI, RSS parsing, NLP, and security automation.

### 4. **Red Team / Pentest**
Stay updated on latest exploits and vulnerabilities for testing.

### 5. **Compliance & Reporting**
Generate executive reports for audits and stakeholder communication.

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Language** | Python 3.8+ | Core development |
| **Translation** | Argos Translate | Offline AI translation |
| **RSS Parsing** | feedparser | Feed aggregation |
| **Email** | smtplib + email.mime | Alert delivery |
| **Reports** | python-docx | Word document generation |
| **Data** | JSON | Local storage |
| **Scheduling** | cron / Task Scheduler | Automation |

---

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md) - Detailed setup instructions
- [Configuration Guide](docs/CONFIGURATION.md) - All configuration options
- [Architecture](docs/ARCHITECTURE.md) - System design and data flow
- [API Reference](docs/API.md) - Future REST API documentation
- [FAQ](docs/FAQ.md) - Common questions and troubleshooting

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution

- 🌐 Additional language translations
- 📡 New threat feed sources
- 🎨 Alert template designs
- 📊 Report formats (PDF, HTML)
- 🔌 Integrations (Slack, Teams, SIEM)
- 🧪 Unit tests and CI/CD

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

PhantomCortex is an educational and research tool. Users are responsible for:
- Compliance with local laws and regulations
- Respecting rate limits of RSS feed providers
- Proper handling of security intelligence data
- Not using this tool for malicious purposes

---

## 🙏 Acknowledgments

- [CISA](https://www.cisa.gov/) for public threat advisories
- [NVD](https://nvd.nist.gov/) for CVE database
- [Argos Translate](https://github.com/argosopentech/argos-translate) for offline translation
- The entire cybersecurity community sharing threat intelligence

---

<div align="center">

**Made with ❤️ by the Security Community**


</div>
