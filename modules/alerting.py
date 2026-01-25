#!/usr/bin/env python3
"""
PhantomCortex - Alerting Module
Email alert generation and delivery
"""

import json
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import logging
import yaml

logger = logging.getLogger(__name__)


class EmailAlerter:
    """Email alert system"""

    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize alerter with configuration"""
        self.config = self._load_config(config_path)
        self.smtp_config = self.config.get("email", {}).get("smtp", {})
        self.email_config = self.config.get("email", {})

        logger.info("Email alerter initialized")

    def _load_config(self, path: str) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {path}")
            return {"email": {"enabled": False}}

    def create_html_alert(self, threats: List[Dict]) -> str:
        """
        Create HTML email from threats

        Args:
            threats: List of threat dictionaries

        Returns:
            HTML string
        """
        # Count by severity
        critical = [t for t in threats if t.get("severity") == "CRITICAL"]
        high = [t for t in threats if t.get("severity") == "HIGH"]
        medium = [t for t in threats if t.get("severity") == "MEDIUM"]

        # Generate HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhantomCortex Threat Alert</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 28px;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .summary {{
            display: flex;
            justify-content: space-around;
            padding: 20px;
            background-color: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }}
        .stat {{
            text-align: center;
        }}
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
            margin: 0;
        }}
        .stat-label {{
            font-size: 14px;
            color: #6c757d;
            margin: 5px 0 0 0;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .content {{
            padding: 20px;
        }}
        .threat-card {{
            background-color: #ffffff;
            border-left: 4px solid #dee2e6;
            margin: 20px 0;
            padding: 15px;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .threat-card.critical {{
            border-left-color: #dc3545;
            background-color: #fff5f5;
        }}
        .threat-card.high {{
            border-left-color: #fd7e14;
            background-color: #fff8f0;
        }}
        .threat-card.medium {{
            border-left-color: #ffc107;
            background-color: #fffbf0;
        }}
        .threat-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .threat-title {{
            font-size: 16px;
            font-weight: 600;
            color: #212529;
            margin: 0;
        }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            color: white;
        }}
        .severity-badge.critical {{ background-color: #dc3545; }}
        .severity-badge.high {{ background-color: #fd7e14; }}
        .severity-badge.medium {{ background-color: #ffc107; color: #000; }}
        .threat-meta {{
            font-size: 14px;
            color: #6c757d;
            margin: 8px 0;
        }}
        .threat-description {{
            margin: 10px 0;
            font-size: 14px;
            line-height: 1.5;
        }}
        .tech-tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            margin-top: 10px;
        }}
        .tech-tag {{
            background-color: #e9ecef;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            color: #495057;
        }}
        .footer {{
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #6c757d;
            border-top: 2px solid #e9ecef;
        }}
        .footer a {{
            color: #667eea;
            text-decoration: none;
        }}
        @media (max-width: 600px) {{
            .summary {{
                flex-direction: column;
                gap: 15px;
            }}
            .threat-header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ PhantomCortex Threat Alert</h1>
            <p>Cyber Threat Intelligence Report</p>
            <p>{datetime.now().strftime('%B %d, %Y at %H:%M UTC')}</p>
        </div>
        
        <div class="summary">
            <div class="stat">
                <p class="stat-number critical">{len(critical)}</p>
                <p class="stat-label">CRITICAL</p>
            </div>
            <div class="stat">
                <p class="stat-number high">{len(high)}</p>
                <p class="stat-label">HIGH</p>
            </div>
            <div class="stat">
                <p class="stat-number medium">{len(medium)}</p>
                <p class="stat-label">MEDIUM</p>
            </div>
        </div>
        
        <div class="content">
            <h2>⚠️ Threats Detected</h2>
            <p>The following threats have been identified and require your attention:</p>
"""

        # Add threat cards (limit to 15 for email size)
        display_threats = threats[:15]

        for threat in display_threats:
            severity = threat.get("severity", "MEDIUM").lower()
            title = threat.get(
                "title_translated", threat.get("title", "Unknown Threat")
            )
            cve = threat.get("cve", "N/A")
            cvss = threat.get("cvss_score", 0.0)
            description = threat.get(
                "description_translated", threat.get("description", "")
            )[:300]
            technologies = threat.get("technologies", [])
            source_url = threat.get("source_url", "#")

            html += f"""
            <div class="threat-card {severity}">
                <div class="threat-header">
                    <h3 class="threat-title">{title}</h3>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                </div>
                <div class="threat-meta">
                    <strong>CVE:</strong> {cve} | <strong>CVSS:</strong> {cvss} | 
                    <strong>Source:</strong> {threat.get('source_name', 'Unknown')}
                </div>
                <div class="threat-description">
                    {description}{'...' if len(description) >= 300 else ''}
                </div>
                <div class="tech-tags">
"""

            for tech in technologies[:5]:
                html += f'<span class="tech-tag">{tech}</span>'

            html += f"""
                </div>
                <div style="margin-top: 10px;">
                    <a href="{source_url}" style="color: #667eea; text-decoration: none; font-size: 14px;">
                        🔗 View Details →
                    </a>
                </div>
            </div>
"""

        if len(threats) > 15:
            html += f"""
            <div style="background-color: #fff3cd; padding: 15px; border-radius: 4px; margin: 20px 0; text-align: center;">
                <strong>Note:</strong> {len(threats) - 15} additional threats not shown. 
                Check your threat intelligence platform for complete details.
            </div>
"""

        html += """
        </div>
        
        <div class="footer">
            <p><strong>PhantomCortex</strong> - Open Source Threat Intelligence Platform</p>
            <p>This is an automated alert. For questions, contact your security team.</p>
            <p style="margin-top: 15px;">
                <a href="https://github.com/yourusername/PhantomCortex">GitHub</a> | 
                <a href="https://github.com/yourusername/PhantomCortex/issues">Report Issue</a>
            </p>
        </div>
    </div>
</body>
</html>
"""

        return html

    def send_alert(self, threats: List[Dict]) -> bool:
        """
        Send email alert with threats

        Args:
            threats: List of threat dictionaries

        Returns:
            True if successful, False otherwise
        """
        if not self.email_config.get("enabled", False):
            logger.warning("Email alerts disabled in configuration")
            return False

        if not threats:
            logger.info("No threats to alert")
            return True

        # Filter by severity threshold
        threshold = self.email_config.get("severity_threshold", "HIGH")
        severity_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        min_severity = severity_order.get(threshold, 2)

        filtered_threats = [
            t
            for t in threats
            if severity_order.get(t.get("severity", "LOW"), 0) >= min_severity
        ]

        if not filtered_threats:
            logger.info(f"No threats meeting severity threshold: {threshold}")
            return True

        logger.info(f"Sending alert for {len(filtered_threats)} threats")

        # Create email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = (
            f"🚨 PhantomCortex Alert: {len(filtered_threats)} Threats Detected"
        )
        msg["From"] = self.email_config.get("from_address", "phantomcortex@example.com")
        msg["To"] = ", ".join(self.email_config.get("to_addresses", []))

        if self.email_config.get("cc_addresses"):
            msg["Cc"] = ", ".join(self.email_config.get("cc_addresses", []))

        # Create HTML content
        html_content = self.create_html_alert(filtered_threats)

        # Attach HTML
        html_part = MIMEText(html_content, "html")
        msg.attach(html_part)

        # Send email
        try:
            context = ssl.create_default_context()

            server = self.smtp_config.get("server")
            port = self.smtp_config.get("port", 587)
            username = self.smtp_config.get("username")
            password = self.smtp_config.get("password")

            if not all([server, username, password]):
                logger.error("SMTP credentials not configured")
                return False

            # Determine if SSL or TLS
            use_ssl = self.smtp_config.get("use_ssl", False)

            if use_ssl:
                # Use SMTP_SSL for port 465
                with smtplib.SMTP_SSL(
                    server, port, context=context, timeout=30
                ) as smtp:
                    smtp.login(username, password)

                    recipients = self.email_config.get("to_addresses", [])
                    recipients.extend(self.email_config.get("cc_addresses", []))

                    smtp.send_message(msg)

                    logger.info(f"✅ Alert sent to {len(recipients)} recipients")
                    return True
            else:
                # Use STARTTLS for port 587
                with smtplib.SMTP(server, port, timeout=30) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=context)
                    smtp.ehlo()
                    smtp.login(username, password)

                    recipients = self.email_config.get("to_addresses", [])
                    recipients.extend(self.email_config.get("cc_addresses", []))

                    smtp.send_message(msg)

                    logger.info(f"✅ Alert sent to {len(recipients)} recipients")
                    return True

        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
            return False


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="PhantomCortex Email Alerter")
    parser.add_argument(
        "--input", default="data/daily_threats.json", help="Input threats JSON file"
    )
    parser.add_argument(
        "--config", default="config/config.yaml", help="Configuration file"
    )
    parser.add_argument("--test", action="store_true", help="Send test email")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    # Initialize alerter
    alerter = EmailAlerter(args.config)

    if args.test:
        # Send test email with dummy data
        test_threats = [
            {
                "title": "Test Threat",
                "title_translated": "Test Threat",
                "severity": "HIGH",
                "cve": "CVE-2025-0001",
                "cvss_score": 8.5,
                "description": "This is a test threat alert from PhantomCortex",
                "description_translated": "This is a test threat alert from PhantomCortex",
                "technologies": ["Windows", "Linux"],
                "source_name": "Test Source",
                "source_url": "https://example.com",
            }
        ]

        success = alerter.send_alert(test_threats)
        return 0 if success else 1

    # Load threats
    try:
        with open(args.input, "r") as f:
            data = json.load(f)

        threats = data.get("threats", [])

        if not threats:
            logger.info("No threats found in file")
            return 0

        # Send alert
        success = alerter.send_alert(threats)
        return 0 if success else 1

    except FileNotFoundError:
        logger.error(f"File not found: {args.input}")
        return 1
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
