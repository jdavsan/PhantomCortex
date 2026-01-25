# 🏗️ PhantomCortex Architecture

Technical architecture and design documentation.

## 📋 Table of Contents

1. [System Overview](#system-overview)
2. [Component Architecture](#component-architecture)
3. [Data Flow](#data-flow)
4. [Module Descriptions](#module-descriptions)
5. [Technology Stack](#technology-stack)
6. [Security Architecture](#security-architecture)
7. [Scalability Considerations](#scalability-considerations)

---

## 🎯 System Overview

PhantomCortex is a modular, event-driven threat intelligence platform designed for:

- **Automation**: Scheduled collection and analysis
- **Modularity**: Independent, replaceable components
- **Extensibility**: Easy to add new sources and formats
- **Privacy**: Offline processing where possible

### Design Principles

1. **Separation of Concerns**: Each module has a single responsibility
2. **Configuration-Driven**: Behavior controlled via YAML files
3. **Fail-Safe**: Errors in one component don't crash the system
4. **Observable**: Comprehensive logging and monitoring
5. **Portable**: Runs on any Python 3.8+ environment

---

## 🧩 Component Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       PhantomCortex                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                    CORE LAYER                             │ │
│  ├───────────────────────────────────────────────────────────┤ │
│  │  • Configuration Manager                                  │ │
│  │  • Logging System                                         │ │
│  │  • Threat Collector                                       │ │
│  │  • Data Storage Manager                                   │ │
│  └───────────────────────────────────────────────────────────┘ │
│                            ▲                                    │
│                            │                                    │
│  ┌────────────────────────┴────────────────────────────────┐  │
│  │                    MODULE LAYER                          │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │  │
│  │  │ Translation │  │  Alerting   │  │   Reporting     │ │  │
│  │  │   Module    │  │   Module    │  │    Module       │ │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘ │  │
│  │                                                          │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │  │
│  │  │  Analysis   │  │ Deduplicati-│  │   Severity      │ │  │
│  │  │   Engine    │  │     on      │  │ Classification  │ │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            ▲                                    │
│                            │                                    │
│  ┌────────────────────────┴────────────────────────────────┐  │
│  │                    DATA LAYER                            │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │  • RSS Feed Sources (External)                           │  │
│  │  • JSON Storage (Local)                                  │  │
│  │  • Configuration Files (YAML)                            │  │
│  │  • Logs (Text Files)                                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Data Flow

### Collection Flow

```
[RSS Feeds] 
    ↓
[Feed Parser] → Parse RSS/XML
    ↓
[Technology Matcher] → Filter by monitored tech
    ↓
[Deduplication] → Check seen_threats.json
    ↓
[Severity Classifier] → Assign CRITICAL/HIGH/MEDIUM
    ↓
[Translation] → Argos Translate (offline)
    ↓
[Storage] → Save to daily_threats.json
    ↓
[Monthly Aggregation] → Append to monthly_threats_{YYYY_MM}.json
```

### Alert Flow

```
[Daily Threats JSON]
    ↓
[Alert Filter] → Severity >= threshold
    ↓
[Template Engine] → Generate HTML email
    ↓
[SMTP Client] → Send via configured server
    ↓
[Log Result] → Record in alerts.log
```

### Report Flow

```
[Monthly Threats JSON]
    ↓
[Report Generator]
    ├─→ Group by severity
    ├─→ Sort by date
    ├─→ Generate statistics
    ↓
[Document Builder] → python-docx
    ↓
[Output] → monthly_report_{YYYY_MM}.docx
    ↓
[Email] → Optional auto-send
```

---

## 📦 Module Descriptions

### Core Modules

#### `core/collector.py`
**Purpose**: Main threat collection engine

**Responsibilities**:
- Parse RSS feeds from configured sources
- Extract threat data (CVE, severity, technologies)
- Match against monitored technologies
- Deduplicate threats
- Store in JSON format

**Key Functions**:
- `collect_from_feed()` - Process single RSS feed
- `collect_all()` - Orchestrate collection from all feeds
- `match_technologies()` - Find relevant technologies
- `classify_severity()` - Determine threat severity

#### `core/config_manager.py` (Future)
**Purpose**: Centralized configuration management

**Responsibilities**:
- Load and validate YAML configuration
- Provide type-safe config access
- Handle environment variable substitution
- Validate configuration schema

### Module Layer

#### `modules/translator.py`
**Purpose**: Offline translation using Argos Translate

**Responsibilities**:
- Translate threat titles and descriptions
- Clean and normalize text before translation
- Handle translation errors gracefully
- Cache translations to avoid duplication

**Key Functions**:
- `translate_text()` - Translate single text
- `translate_threat_batch()` - Batch translation
- `clean_text()` - Text normalization

#### `modules/alerting.py`
**Purpose**: Email alert generation and delivery

**Responsibilities**:
- Filter threats by severity threshold
- Generate HTML email from template
- Send via SMTP with attachments
- Track alert history

**Key Functions**:
- `create_alert_email()` - Generate HTML
- `send_alert()` - SMTP delivery
- `format_threat_for_email()` - Threat formatting

#### `modules/reporting.py`
**Purpose**: Monthly report generation

**Responsibilities**:
- Aggregate monthly threat data
- Generate statistics and charts
- Create professional Word documents
- Optional PDF export (future)

**Key Functions**:
- `generate_monthly_report()` - Main report generator
- `create_summary_statistics()` - Calculate metrics
- `add_threat_table()` - Formatted threat table

---

## 🛠️ Technology Stack

### Core Technologies

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Runtime** | Python | 3.8+ | Core language |
| **RSS Parsing** | feedparser | 6.0+ | Feed processing |
| **Translation** | Argos Translate | 1.9+ | Offline AI translation |
| **Documents** | python-docx | 1.1+ | Word generation |
| **Configuration** | PyYAML | 6.0+ | YAML parsing |
| **HTTP** | requests | 2.31+ | Web requests |

### Optional Technologies

| Component | Technology | Use Case |
|-----------|-----------|----------|
| **Testing** | pytest | Unit testing |
| **Type Checking** | mypy | Static analysis |
| **Code Quality** | flake8 | Linting |
| **Formatting** | black | Code formatting |

### External Dependencies

- **RSS Feeds**: Public threat intelligence sources
- **SMTP Server**: Email delivery
- **OS**: Linux, macOS, or Windows

---

## 🔒 Security Architecture

### Security Considerations

#### 1. **Data Privacy**
- All threat processing happens locally
- No data sent to external APIs (except email)
- Translation is completely offline
- Configuration stored locally

#### 2. **Credential Management**
- SMTP passwords via environment variables
- Configuration files in `.gitignore`
- No hardcoded credentials in code
- File permissions: `chmod 600 config.yaml`

#### 3. **Input Validation**
- RSS feed validation
- Configuration schema validation
- SQL injection N/A (no database)
- XSS prevention in HTML templates

#### 4. **Network Security**
- HTTPS for RSS feed connections
- TLS/SSL for SMTP connections
- Timeout controls to prevent hanging
- Rate limiting for feed requests

#### 5. **Logging Security**
- No sensitive data in logs
- Passwords never logged
- PII (personally identifiable information) filtered
- Log rotation to prevent disk fill

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| **Malicious RSS Content** | Input sanitization, timeout controls |
| **SMTP Credential Theft** | Environment variables, file permissions |
| **Data Exposure** | Local storage only, encrypted configs (future) |
| **DoS via Feed Spam** | Deduplication, rate limiting |
| **Code Injection** | Input validation, no eval() usage |

---

## 📈 Scalability Considerations

### Current Limitations

- **Storage**: JSON files (good for < 100K threats)
- **Concurrent Processing**: Single-threaded
- **Feed Sources**: ~20 feeds optimal

### Scaling Strategies

#### For More Feeds (20-50)
```python
# Enable parallel processing
parallel:
  enabled: true
  max_workers: 4
```

#### For More Data (100K+ threats)
- Consider migrating to SQLite or PostgreSQL
- Implement data archival strategy
- Use database indexes for queries

#### For High Availability
- Deploy on multiple servers
- Share data via NFS or S3
- Use message queue (RabbitMQ) for async processing

#### For Enterprise Scale
- Kubernetes deployment
- Elasticsearch for threat storage
- Redis for caching
- REST API for integrations

---

## 🔮 Future Enhancements

### Planned Features

1. **REST API**
   - Query threats programmatically
   - Webhook notifications
   - Third-party integrations

2. **Web Dashboard**
   - Real-time threat visualization
   - Interactive filtering
   - Customizable widgets

3. **Machine Learning**
   - Threat prioritization
   - False positive reduction
   - Trend prediction

4. **STIX/TAXII Support**
   - Industry-standard format support
   - Threat sharing with partners
   - Integration with SIEM platforms

5. **Multi-Tenancy**
   - Support multiple organizations
   - Role-based access control
   - Isolated data per tenant

---

## 📊 Performance Metrics

### Benchmarks (typical setup)

- **Collection Time**: ~15-30 seconds for 17 feeds
- **Translation**: ~2-3 seconds per threat
- **Memory Usage**: ~100-200 MB during collection
- **Disk Usage**: ~500 MB (including translation models)
- **Network Bandwidth**: ~5-10 MB per collection

### Optimization Tips

1. **Reduce Collection Time**:
   - Enable parallel processing
   - Reduce timeout values
   - Disable slow feeds

2. **Reduce Memory Usage**:
   - Process feeds sequentially
   - Clear cache after each feed
   - Limit translation batch size

3. **Reduce Disk Usage**:
   - Enable data compression
   - Archive old threats
   - Rotate logs more frequently

---

## 🏗️ Development Workflow

```
[Local Development]
     ↓
[Feature Branch]
     ↓
[Unit Tests]
     ↓
[Pull Request]
     ↓
[Code Review]
     ↓
[Merge to Main]
     ↓
[CI/CD Pipeline]
     ↓
[Staging Deployment]
     ↓
[Integration Tests]
     ↓
[Production Release]
```

---

## 📚 Additional Resources

- [Installation Guide](INSTALLATION.md)
- [Configuration Guide](CONFIGURATION.md)
- [Customization Guide](CUSTOMIZATION.md)
- [API Documentation](API.md) (future)
- [Contributing Guide](../CONTRIBUTING.md)

---

**Questions about the architecture?** Open a [Discussion](https://github.com/yourusername/PhantomCortex/discussions)
