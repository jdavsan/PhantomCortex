# 🔧 Customization Guide

Complete guide to personalizing PhantomCortex for your environment.

## 📋 Table of Contents

1. [Quick Start Customization](#quick-start-customization)
2. [Configuration Files](#configuration-files)
3. [Adding Custom Technologies](#adding-custom-technologies)
4. [Adding RSS Sources](#adding-rss-sources)
5. [Email Configuration](#email-configuration)
6. [Severity Rules](#severity-rules)
7. [Translation Settings](#translation-settings)
8. [Advanced Customization](#advanced-customization)

---

## 🚀 Quick Start Customization

### Minimum Required Changes

These are the **essential** files you MUST customize:

1. **`config/config.yaml`** - Main configuration
   ```bash
   cp config/config.example.yaml config/config.yaml
   nano config/config.yaml
   ```

2. **Email settings** - Update SMTP credentials
3. **Technologies** - Add your infrastructure components
4. **RSS sources** - Enable/disable feeds

---

## 📁 Configuration Files

### Main Configuration: `config/config.yaml`

**Location**: `config/config.yaml`

**What to modify**:

```yaml
# === REQUIRED CHANGES ===

# Email Settings (MUST CHANGE)
email:
  smtp:
    server: smtp.your-company.com      # Your SMTP server
    port: 587                           # 587 for TLS, 465 for SSL
    username: alerts@your-company.com   # Your email
    password: ""                        # Use env var: PHANTOMCORTEX_EMAIL_PASSWORD
    
  from_address: phantomcortex@your-company.com
  from_name: Your Company Threat Intel
  
  to_addresses:
    - security-team@your-company.com    # Primary recipients
    - soc@your-company.com
    
  cc_addresses:
    - manager@your-company.com          # Optional CC

# Severity Threshold
email:
  severity_threshold: HIGH   # Options: CRITICAL, HIGH, MEDIUM, LOW

# === OPTIONAL CHANGES ===

# Timezone
general:
  timezone: America/New_York  # Your timezone

# Data Retention
general:
  data_retention_days: 90  # How long to keep data

# Translation
translation:
  enabled: true
  source_lang: en
  target_lang: es  # Change to your language (en, es, fr, de, etc.)
```

**Using Environment Variables (Recommended for passwords)**:

```bash
# Set in your shell or .bashrc
export PHANTOMCORTEX_EMAIL_PASSWORD="your-secure-password"

# Or create a .env file
echo "PHANTOMCORTEX_EMAIL_PASSWORD=your-password" > .env
```

---

## 🖥️ Adding Custom Technologies

### File: `config/technologies.yaml`

**Location**: `config/technologies.yaml`

**How to customize**:

1. Open the file:
   ```bash
   nano config/technologies.yaml
   ```

2. Add your technologies at the end:
   ```yaml
   technologies:
     # ... existing technologies ...
     
     # === YOUR CUSTOM TECHNOLOGIES ===
     - your-custom-app
     - internal-crm-system
     - proprietary-software-v2
     - legacy-application
     - vendor-specific-product
   ```

3. **Tips**:
   - Use lowercase for better matching
   - Include product versions if specific
   - Add common abbreviations
   - Include both vendor and product names

**Example for specific environment**:

```yaml
# Your Company Infrastructure
technologies:
  # Operating Systems
  - windows server 2019
  - ubuntu 22.04
  - rhel 8
  
  # Applications
  - sharepoint 2019
  - exchange server 2019
  - sql server 2019
  
  # Custom Apps
  - company-erp-v3
  - customer-portal
  - internal-wiki
  
  # Vendors
  - cisco asa
  - fortinet fortigate
  - vmware esxi 7.0
```

---

## 📡 Adding RSS Sources

### File: `config/sources.yaml`

**Location**: `config/sources.yaml`

**How to add a new source**:

1. Find the RSS feed URL (usually `/feed`, `/rss`, or `/rss.xml`)

2. Add to `sources.yaml`:
   ```yaml
   sources:
     # ... existing sources ...
     
     - name: Your Custom Source
       url: https://example.com/feed.xml
       type: news  # or: government, vendor, blog, research, exploits
       enabled: true
       description: Brief description of source
   ```

3. **Example - Adding a vendor blog**:
   ```yaml
   - name: Your Vendor Security Blog
       url: https://vendor.com/security/rss
       type: vendor
       enabled: true
       description: Security updates from VendorName
   ```

**How to disable a source**:

```yaml
- name: Source to Disable
  url: https://example.com/feed
  type: news
  enabled: false  # Just set to false
  description: Disabled because too much noise
```

**Testing new sources**:

```bash
python scripts/test_feed.py --url https://example.com/feed.xml
```

---

## 📧 Email Configuration

### SMTP Settings

**Common SMTP configurations**:

#### Gmail
```yaml
email:
  smtp:
    server: smtp.gmail.com
    port: 587
    use_tls: true
    username: your-email@gmail.com
    password: ""  # Use App Password, not regular password
```

**Gmail setup**:
1. Enable 2FA on your Google account
2. Go to https://myaccount.google.com/apppasswords
3. Create an app password
4. Use that password in config or env var

#### Office 365 / Outlook
```yaml
email:
  smtp:
    server: smtp.office365.com
    port: 587
    use_tls: true
    username: your-email@company.com
    password: ""  # Use app password or modern auth
```

#### Custom SMTP Server
```yaml
email:
  smtp:
    server: mail.your-company.com
    port: 587  # or 465 for SSL
    use_tls: true  # or use_ssl: true for port 465
    username: alerts@your-company.com
    password: ""
```

**Testing email**:

```bash
python scripts/test_email.py
```

---

## ⚠️ Severity Rules

### File: `config/config.yaml`

**Location**: `config/config.yaml` → `severity` section

**Customize severity classification**:

```yaml
severity:
  # CRITICAL Keywords
  critical_keywords:
    - critical
    - rce
    - remote code execution
    - zero-day
    - actively exploited
    - ransomware
    # Add your custom critical keywords
    - your-critical-keyword
    - urgent-patch-required
    
  # HIGH Keywords
  high_keywords:
    - high
    - privilege escalation
    - sql injection
    - authentication bypass
    # Add your custom high keywords
    - data exposure
    - credential theft
    
  # CVSS Thresholds
  cvss_critical: 9.0  # CVSS >= 9.0 = CRITICAL
  cvss_high: 7.0      # CVSS >= 7.0 = HIGH
  cvss_medium: 4.0    # CVSS >= 4.0 = MEDIUM
```

**How severity is determined**:

1. Checks for critical keywords → CRITICAL
2. Checks for high keywords → HIGH
3. Falls back to CVSS score
4. Default → MEDIUM

---

## 🌐 Translation Settings

### Supported Languages

**Location**: `config/config.yaml` → `translation` section

```yaml
translation:
  enabled: true
  source_lang: en  # Source language (usually 'en')
  target_lang: es  # Your language
  offline: true    # Use offline Argos Translate
```

**Supported language codes**:
- `en` - English
- `es` - Spanish
- `fr` - French
- `de` - German
- `it` - Italian
- `pt` - Portuguese
- `ru` - Russian
- `zh` - Chinese
- `ja` - Japanese
- `ar` - Arabic

**To add a new language**:

```bash
# Download translation model
python scripts/setup_translation.py --from-lang en --to-lang fr

# Update config
nano config/config.yaml
# Change: target_lang: fr
```

**Disable translation**:

```yaml
translation:
  enabled: false  # Threats will remain in English
```

---

## 🔧 Advanced Customization

### Custom Severity Logic

**File**: `core/severity_classifier.py` (create if needed)

```python
def custom_severity_logic(threat: dict) -> str:
    """Custom severity classification logic"""
    
    # Example: Prioritize threats to your critical systems
    critical_systems = ['payment-gateway', 'customer-database']
    
    for tech in threat.get('technologies', []):
        if any(sys in tech.lower() for sys in critical_systems):
            return 'CRITICAL'
    
    # Your custom rules here
    if 'your-product' in threat.get('title', '').lower():
        return 'HIGH'
    
    # Fall back to default logic
    return default_severity(threat)
```

### Custom Alert Templates

**File**: `config/templates/alert_email.html`

Create your own HTML email template:

```html
<!DOCTYPE html>
<html>
<head>
    <style>
        /* Your custom styles */
        .critical { color: #d32f2f; }
        .company-header { background-color: #your-color; }
    </style>
</head>
<body>
    <!-- Your custom email template -->
    <div class="company-header">
        <h1>{{ company_name }} Threat Alert</h1>
    </div>
    <!-- ... -->
</body>
</html>
```

### Custom Report Formats

**File**: `modules/custom_report.py`

Create your own report generator:

```python
def generate_custom_report(threats, month):
    """Generate report in your company format"""
    # Your custom report logic
    pass
```

---

## 🎯 Environment-Specific Configurations

### Development Environment

**File**: `config/config.dev.yaml`

```yaml
general:
  log_level: DEBUG

email:
  enabled: false  # Don't send real emails

feeds:
  max_age_days: 7  # Only recent threats

storage:
  data_retention_days: 7
```

### Production Environment

**File**: `config/config.prod.yaml`

```yaml
general:
  log_level: INFO

email:
  enabled: true

feeds:
  max_age_days: 30

storage:
  data_retention_days: 90
```

**Switch between environments**:

```bash
# Development
python core/collector.py --config config/config.dev.yaml

# Production
python core/collector.py --config config/config.prod.yaml
```

---

## 📊 Customization Checklist

Before running PhantomCortex, ensure you've customized:

- [ ] `config/config.yaml` - Main configuration
- [ ] Email SMTP settings
- [ ] Email recipients (to, cc, bcc)
- [ ] `config/technologies.yaml` - Your infrastructure
- [ ] `config/sources.yaml` - Enable/disable feeds
- [ ] Severity thresholds
- [ ] Translation language (if needed)
- [ ] Timezone setting
- [ ] Data retention period

---

## 🔒 Security Best Practices

1. **Never commit passwords** to git
   - Use environment variables
   - Use `.env` file (add to `.gitignore`)

2. **Protect configuration files**:
   ```bash
   chmod 600 config/config.yaml
   ```

3. **Use strong passwords**:
   - SMTP passwords
   - API keys (if future features)

4. **Limit email recipients**:
   - Only send to authorized personnel
   - Use BCC for larger distributions

---

## 🆘 Need Help?

- **Configuration issues**: Check [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- **Questions**: Open a [GitHub Discussion](https://github.com/yourusername/PhantomCortex/discussions)
- **Bugs**: Report an [Issue](https://github.com/yourusername/PhantomCortex/issues)

---

**Happy customizing! 🎉**
