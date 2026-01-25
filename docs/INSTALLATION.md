# 📦 Installation Guide

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation Methods](#installation-methods)
3. [Post-Installation](#post-installation)
4. [Verification](#verification)
5. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Requirements

- **OS**: Linux (Ubuntu 20.04+), macOS (10.14+), Windows 10+
- **Python**: 3.8 or higher
- **RAM**: 2GB minimum, 4GB recommended
- **Disk**: 2GB free space (includes translation models)
- **Network**: Internet connection for RSS feeds

### Recommended Setup

- **OS**: Ubuntu 22.04 LTS or Debian 11+
- **Python**: 3.10+
- **RAM**: 8GB
- **Disk**: 10GB (for logs and reports storage)

---

## Installation Methods

### Method 1: Standard Installation (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/PhantomCortex.git
cd PhantomCortex

# 2. Create virtual environment
python3 -m venv venv

# 3. Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# 4. Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 5. Download translation model
python scripts/setup_translation.py

# 6. Create configuration
cp config/config.example.yaml config/config.yaml
```

### Method 2: Docker Installation (Coming Soon)

```bash
# Pull and run
docker pull phantomcortex/threat-intel:latest
docker-compose up -d
```

---

## Post-Installation

### 1. Configure Email Settings

Edit `config/config.yaml`:

```yaml
email:
  enabled: true
  smtp_server: smtp.gmail.com  # Your SMTP server
  smtp_port: 587
  smtp_tls: true
  username: your-email@gmail.com
  password: your-app-password  # Use app passwords, not your real password
  from_address: alerts@example.com
  to_addresses:
    - security-team@example.com
```

### 2. Configure Technologies

Add technologies you want to monitor in `config/technologies.yaml`:

```yaml
technologies:
  # Operating Systems
  - windows
  - linux
  - ubuntu
  - debian
  - centos
  
  # Web Servers
  - apache
  - nginx
  - iis
  
  # Databases
  - mysql
  - postgresql
  - mongodb
  
  # Containers & Orchestration
  - docker
  - kubernetes
  - podman
  
  # Add your specific technologies here
```

### 3. Review RSS Sources

Check `config/sources.yaml` and enable/disable sources:

```yaml
sources:
  - name: CISA Advisories
    url: https://www.cisa.gov/cybersecurity-advisories/all.xml
    enabled: true
    type: government
    
  - name: NVD Recent CVEs
    url: https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml
    enabled: true
    type: database
```

### 4. Test Installation

```bash
# Test threat collection
python core/collector.py --test

# Test translation
python modules/translator.py --test

# Test email (will send test email)
python modules/alerting.py --test
```

---

## Scheduling Automation

### Linux/macOS (cron)

```bash
# Edit crontab
crontab -e

# Add these lines:
# Daily collection at 8 AM
0 8 * * * cd /path/to/PhantomCortex && ./scripts/run_daily.sh >> logs/cron.log 2>&1

# Monthly report on last day of month at 6 PM
0 18 28-31 * * [ "$(date +\%d -d tomorrow)" = "01" ] && cd /path/to/PhantomCortex && ./scripts/run_monthly.sh >> logs/cron.log 2>&1

# Weekly cleanup of old logs
0 3 * * 1 find /path/to/PhantomCortex/logs -name "*.log" -mtime +30 -delete
```

### Windows (Task Scheduler)

```powershell
# Create daily task
schtasks /create /tn "PhantomCortex Daily" /tr "C:\PhantomCortex\scripts\run_daily.bat" /sc daily /st 08:00

# Create monthly task
schtasks /create /tn "PhantomCortex Monthly" /tr "C:\PhantomCortex\scripts\run_monthly.bat" /sc monthly /d 28 /st 18:00
```

---

## Verification

### Check Installation

```bash
# Run verification script
python scripts/verify_installation.py

# Expected output:
# ✅ Python version: 3.10.x
# ✅ All dependencies installed
# ✅ Translation model ready
# ✅ Configuration file found
# ✅ Data directories created
# ✅ SMTP connection successful
```

### Manual Checks

```bash
# Check Python version
python --version  # Should be 3.8+

# Check installed packages
pip list | grep -E "feedparser|argostranslate|python-docx|pyyaml"

# Check directories
ls -la data/ config/ logs/

# Test import
python -c "import feedparser, argostranslate, docx, yaml; print('All imports OK')"
```

---

## Troubleshooting

### Issue: Translation model fails to download

**Solution**:
```bash
# Manual download
cd venv/lib/python3.*/site-packages/argostranslate/
python3 -c "from argostranslate import package; package.install_from_path('translate-en_es-1_5.argosmodel')"
```

### Issue: SMTP authentication fails

**Causes**:
- Incorrect credentials
- 2FA enabled without app password
- Firewall blocking port 587/465

**Solutions**:
```bash
# Test SMTP connection
python scripts/test_smtp.py

# For Gmail: Enable "Less secure app access" or use App Passwords
# For Office365: Use modern authentication
```

### Issue: No threats collected

**Checks**:
1. Internet connection working?
2. RSS feeds responding? (check `logs/collection.log`)
3. Technologies list configured?
4. Date filters correct?

```bash
# Debug mode
python core/collector.py --debug --verbose
```

### Issue: Permission denied

```bash
# Fix permissions
chmod +x scripts/*.sh
chmod 600 config/config.yaml  # Protect credentials
```

---

## Uninstallation

```bash
# Remove virtual environment
deactivate
rm -rf venv/

# Remove cron jobs
crontab -e  # Delete PhantomCortex lines

# Remove project
cd ..
rm -rf PhantomCortex/
```

---

## Next Steps

✅ Installation complete!

Now proceed to:
- [Configuration Guide](CONFIGURATION.md) - Customize for your environment
- [User Guide](USER_GUIDE.md) - Learn how to use the platform
- [Architecture](ARCHITECTURE.md) - Understand the system design

---

**Need help?** Open an issue on [GitHub](https://github.com/yourusername/PhantomCortex/issues)
