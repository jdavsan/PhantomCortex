# Contributing to PhantomCortex

Thank you for your interest in contributing to PhantomCortex! This document provides guidelines for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)

---

## 📜 Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow:

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

---

## 🤝 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the behavior
- **Expected vs actual behavior**
- **Environment details** (OS, Python version, etc.)
- **Logs** (if applicable)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title and description**
- **Use case** explaining why this enhancement would be useful
- **Possible implementation** (if you have ideas)

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Add tests if applicable
5. Ensure code follows style guidelines
6. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
7. Push to the branch (`git push origin feature/AmazingFeature`)
8. Open a Pull Request

---

## 🛠️ Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/PhantomCortex.git
cd PhantomCortex

# Add upstream remote
git remote add upstream https://github.com/original-owner/PhantomCortex.git

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies including dev tools
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If exists

# Install pre-commit hooks (if using)
pre-commit install
```

---

## 📐 Coding Standards

### Python Style Guide

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use 4 spaces for indentation
- Maximum line length: 100 characters
- Use type hints where appropriate

### Example:

```python
def process_threat(threat_data: Dict[str, Any]) -> ThreatIntelligence:
    """
    Process raw threat data into structured intelligence.
    
    Args:
        threat_data: Raw threat data from RSS feed
        
    Returns:
        ThreatIntelligence object
        
    Raises:
        ValueError: If threat_data is invalid
    """
    # Implementation here
    pass
```

### Documentation

- All modules should have docstrings
- All classes should have docstrings
- All public functions should have docstrings
- Use Google-style or NumPy-style docstrings

### Testing

- Write unit tests for new functionality
- Ensure existing tests pass
- Aim for >80% code coverage

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=core --cov=modules tests/
```

---

## 📝 Submitting Changes

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): subject

body

footer
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**

```
feat(collector): add support for STIX feeds

Add ability to parse STIX 2.1 formatted threat intelligence feeds
alongside existing RSS feeds.

Closes #123
```

```
fix(alerting): correct email template encoding

UTF-8 encoding was not properly handled for non-ASCII characters
in threat descriptions.

Fixes #456
```

### Pull Request Process

1. **Update Documentation**: If your changes affect user-facing features, update docs
2. **Add Tests**: Include unit tests for new functionality
3. **Update Changelog**: Add entry to CHANGELOG.md (if exists)
4. **Link Issues**: Reference related issues in PR description
5. **Request Review**: Wait for maintainer review

---

## 🐛 Reporting Bugs

Use the bug report template:

```markdown
**Describe the bug**
A clear and concise description.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Run '....'
3. See error

**Expected behavior**
What you expected to happen.

**Environment:**
 - OS: [e.g. Ubuntu 22.04]
 - Python Version: [e.g. 3.10.5]
 - PhantomCortex Version: [e.g. 1.0.0]

**Logs**
```
Paste relevant logs here
```

**Additional context**
Add any other context about the problem.
```

---

## ✨ Suggesting Enhancements

Use the feature request template:

```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution you'd like**
A clear description of what you want to happen.

**Describe alternatives you've considered**
Alternative solutions or features you've considered.

**Additional context**
Add any other context or screenshots.
```

---

## 🎨 Areas for Contribution

We especially welcome contributions in these areas:

### High Priority
- 🌐 Additional language support for translation
- 📡 New threat feed integrations
- 🧪 Unit and integration tests
- 📚 Documentation improvements

### Medium Priority
- 🎨 Email template designs
- 📊 Report format enhancements
- 🔌 SIEM integrations (Splunk, Elastic, etc.)
- 💬 Chat platform integrations (Slack, Teams)

### Future Features
- 🌐 REST API implementation
- 📱 Web dashboard
- 🤖 Machine learning for threat prioritization
- 🔍 Threat hunting capabilities

---

## 📫 Questions?

- **GitHub Discussions**: For general questions
- **GitHub Issues**: For bugs and feature requests
- **Email**: security@phantomcortex.example.com (for security issues only)

---

## 🙏 Thank You!

Your contributions make PhantomCortex better for everyone. We appreciate your time and effort!

---

**Remember**: Quality over quantity. Well-tested, documented contributions are more valuable than hasty submissions.
