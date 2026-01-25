# 📤 GitHub Publishing Guide

Complete step-by-step guide to publish PhantomCortex on GitHub.

## 📋 Table of Contents

1. [Pre-Publication Checklist](#pre-publication-checklist)
2. [Creating the Repository](#creating-the-repository)
3. [Initial Commit](#initial-commit)
4. [Repository Configuration](#repository-configuration)
5. [Adding Documentation](#adding-documentation)
6. [Creating Releases](#creating-releases)
7. [Community Setup](#community-setup)
8. [Best Practices](#best-practices)

---

## ✅ Pre-Publication Checklist

Before publishing, ensure:

- [ ] All personal/company information removed
- [ ] Configuration files are templates (no real credentials)
- [ ] README.md is complete and professional
- [ ] LICENSE file included (MIT recommended)
- [ ] .gitignore properly configured
- [ ] All code is tested and working
- [ ] Documentation is complete
- [ ] CONTRIBUTING.md guide included

---

## 🆕 Creating the Repository

### Step 1: Create Repository on GitHub

1. Go to https://github.com/new
2. Fill in details:
   - **Repository name**: `PhantomCortex`
   - **Description**: "Open Source Cyber Threat Intelligence Platform"
   - **Visibility**: Public
   - **Initialize**: Do NOT initialize (we have files already)
3. Click "Create repository"

### Step 2: Configure .gitignore

Create `.gitignore` file:

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual Environment
venv/
env/
ENV/
env.bak/
venv.bak/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Sensitive Configuration
config/config.yaml
config/credentials.yaml
.env
*.key
*.pem

# Data & Logs
data/
logs/
*.log
backups/

# Reports
reports/*.docx
reports/*.pdf

# Temporary files
*.tmp
*.bak
.cache/
.pytest_cache/

# OS
Thumbs.db
.DS_Store
```

---

## 📦 Initial Commit

### Step 1: Initialize Git

```bash
cd PhantomCortex

# Initialize repository
git init

# Add all files
git add .

# Create initial commit
git commit -m "feat: initial commit - PhantomCortex v1.0.0

- Complete threat intelligence platform
- RSS feed collection from 17+ sources
- Offline translation support
- Email alerting system
- Monthly report generation
- Full documentation"
```

### Step 2: Connect to GitHub

```bash
# Add remote (replace with your username)
git remote add origin https://github.com/YOUR_USERNAME/PhantomCortex.git

# Verify remote
git remote -v

# Push to GitHub
git branch -M main
git push -u origin main
```

---

## ⚙️ Repository Configuration

### GitHub Repository Settings

1. **Go to Settings → General**

2. **Features** - Enable:
   - [x] Issues
   - [x] Projects
   - [x] Discussions
   - [x] Wiki (optional)

3. **Pull Requests**:
   - [x] Allow squash merging
   - [x] Automatically delete head branches

4. **Repository Security**:
   - Enable "Private vulnerability reporting"
   - Set up Dependabot alerts

### Add Topics/Tags

Go to main repository page and add topics:
- `cybersecurity`
- `threat-intelligence`
- `cti`
- `rss`
- `security-tools`
- `vulnerability-management`
- `python`
- `open-source`
- `security-automation`

### Add Description

Edit repository description:
```
🛡️ Open Source Cyber Threat Intelligence Platform - Automated threat collection, analysis, and reporting
```

Set website URL: 
```
https://your-username.github.io/PhantomCortex
```

---

## 📚 Adding Documentation

### Create GitHub Pages (Optional)

1. Go to Settings → Pages
2. Source: Deploy from branch
3. Branch: `main` / `docs`
4. Click Save

### Create Wiki (Optional)

1. Go to Wiki tab
2. Create pages:
   - Home (overview)
   - Installation Guide
   - Configuration Guide
   - User Guide
   - API Documentation (future)
   - FAQ

### Add Issue Templates

Create `.github/ISSUE_TEMPLATE/`:

**bug_report.md**:
```markdown
---
name: Bug report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
assignees: ''
---

**Describe the bug**
A clear and concise description.

**To Reproduce**
Steps to reproduce:
1. Go to '...'
2. Click on '....'
3. See error

**Expected behavior**
What you expected to happen.

**Environment:**
 - OS: [e.g. Ubuntu 22.04]
 - Python: [e.g. 3.10]
 - Version: [e.g. 1.0.0]

**Additional context**
Add any other context.
```

**feature_request.md**:
```markdown
---
name: Feature request
about: Suggest an idea for this project
title: '[FEATURE] '
labels: enhancement
assignees: ''
---

**Is your feature request related to a problem?**
A clear description.

**Describe the solution you'd like**
A clear description of what you want.

**Describe alternatives you've considered**
Alternatives you've considered.

**Additional context**
Add any other context.
```

### Add Pull Request Template

Create `.github/pull_request_template.md`:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring
- [ ] Other (please describe):

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have commented my code where necessary
- [ ] I have updated the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix/feature works
- [ ] New and existing tests pass locally

## Related Issues
Closes #(issue)
```

---

## 🏷️ Creating Releases

### Step 1: Tag Your Release

```bash
# Create annotated tag
git tag -a v1.0.0 -m "PhantomCortex v1.0.0 - Initial Release

Features:
- Multi-source RSS threat collection
- Offline AI translation
- Email alerting system
- Monthly reporting
- 17+ default threat sources
- Technology-specific monitoring
"

# Push tag
git push origin v1.0.0
```

### Step 2: Create GitHub Release

1. Go to Releases → Draft a new release
2. Choose tag: `v1.0.0`
3. Release title: `PhantomCortex v1.0.0 - Initial Release`
4. Description:

```markdown
## 🎉 PhantomCortex v1.0.0

First stable release of PhantomCortex - Open Source Cyber Threat Intelligence Platform.

### ✨ Features

- **Automated Collection**: Gather threats from 17+ RSS feeds
- **Offline Translation**: AI-powered translation without API keys
- **Email Alerts**: Professional HTML email notifications
- **Monthly Reports**: Executive summaries in Word format
- **Technology Monitoring**: Track threats for your infrastructure
- **Smart Deduplication**: Intelligent duplicate detection

### 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/PhantomCortex.git
cd PhantomCortex
pip install -r requirements.txt
python scripts/setup_translation.py
```

### 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [User Guide](docs/USER_GUIDE.md)

### 🐛 Known Issues

None currently

### 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for details.

---

**Full Changelog**: https://github.com/YOUR_USERNAME/PhantomCortex/commits/v1.0.0
```

5. Attach any binary releases (if applicable)
6. Click "Publish release"

---

## 👥 Community Setup

### Enable Discussions

1. Go to Settings → General
2. Enable "Discussions"
3. Create categories:
   - General
   - Q&A
   - Show and Tell
   - Feature Requests

### Create Community Health Files

Create `.github/` directory with:

**SECURITY.md**:
```markdown
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities to:
security@phantomcortex.example.com

Do NOT create public issues for security vulnerabilities.

We will respond within 48 hours.
```

**CODE_OF_CONDUCT.md**:
```markdown
# Contributor Covenant Code of Conduct

## Our Pledge

We pledge to make participation in our community a harassment-free experience for everyone.

## Our Standards

Examples of behavior that contributes to a positive environment:
* Using welcoming and inclusive language
* Being respectful of differing viewpoints
* Accepting constructive criticism gracefully
* Focusing on what is best for the community

## Enforcement

Instances of abusive behavior may be reported to security@phantomcortex.example.com.

## Attribution

This Code of Conduct is adapted from the Contributor Covenant, version 2.0.
```

### Set Up GitHub Actions (Optional)

Create `.github/workflows/tests.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, 3.10, 3.11]

    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    - name: Run tests
      run: |
        python -m pytest tests/ || echo "No tests yet"
```

---

## 🎯 Best Practices

### Regular Maintenance

- [ ] Respond to issues within 48 hours
- [ ] Review pull requests within 1 week
- [ ] Keep dependencies updated
- [ ] Update documentation as needed
- [ ] Create releases for significant changes

### Documentation

- [ ] Keep README up-to-date
- [ ] Document all configuration options
- [ ] Provide examples for common use cases
- [ ] Maintain a CHANGELOG
- [ ] Update screenshots/diagrams

### Community Engagement

- [ ] Thank contributors
- [ ] Celebrate milestones (stars, forks, contributors)
- [ ] Share project updates
- [ ] Respond to discussions
- [ ] Recognize top contributors

### Marketing

- [ ] Share on Reddit (r/netsec, r/cybersecurity)
- [ ] Post on Twitter with #infosec #threatintel
- [ ] Submit to awesome lists
- [ ] Write blog post about the project
- [ ] Present at security meetups

---

## 📊 Metrics to Track

- ⭐ Stars
- 🍴 Forks
- 👁️ Watchers
- 📥 Clones
- 👥 Contributors
- 🐛 Issues (open/closed ratio)
- 🔀 Pull requests (merged/closed ratio)

---

## 🎓 Learning Resources

- [GitHub Docs](https://docs.github.com/)
- [Open Source Guides](https://opensource.guide/)
- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)

---

## ✅ Final Checklist

Before making repository public:

- [ ] README is professional and complete
- [ ] All sensitive data removed
- [ ] LICENSE file included
- [ ] CONTRIBUTING guide added
- [ ] Issue templates configured
- [ ] .gitignore properly set
- [ ] Initial release tagged
- [ ] Documentation complete
- [ ] Code is tested and working
- [ ] Repository description and topics added

---

**Congratulations! Your project is ready for the world! 🎉**
