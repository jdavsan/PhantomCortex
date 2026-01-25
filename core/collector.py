#!/usr/bin/env python3
"""
PhantomCortex - Threat Intelligence Collector
Collects threats from multiple RSS feeds and analyzes them.
"""

import feedparser
import json
import hashlib
import re
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional
import yaml
import logging
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelligence:
    """Data class for threat intelligence"""
    id: str
    cve: Optional[str]
    title: str
    title_translated: str
    description: str
    description_translated: str
    severity: str
    cvss_score: float
    technologies: List[str]
    published_date: str
    detected_date: str
    source_url: str
    source_name: str
    requires_alert: bool
    references: List[str]


class ThreatCollector:
    """Main threat intelligence collector"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize the collector with configuration"""
        self.config = self._load_config(config_path)
        self.feeds = self._load_sources()
        self.technologies = self._load_technologies()
        self.seen_threats: Set[str] = self._load_seen_threats()
        
        logger.info(f"Initialized collector with {len(self.feeds)} feeds")
        logger.info(f"Monitoring {len(self.technologies)} technologies")
    
    def _load_config(self, path: str) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {path}")
            logger.info("Using default configuration")
            return self._default_config()
    
    def _default_config(self) -> dict:
        """Return default configuration"""
        return {
            'feeds': {'enabled': True, 'timeout': 30, 'max_age_days': 30},
            'technologies': {'case_sensitive': False},
            'severity': {
                'critical_keywords': ['critical', 'rce', 'zero-day'],
                'high_keywords': ['high', 'privilege escalation'],
                'cvss_critical': 9.0,
                'cvss_high': 7.0
            },
            'storage': {'data_dir': 'data'}
        }
    
    def _load_sources(self) -> List[Dict]:
        """Load RSS feed sources"""
        sources_file = self.config.get('feeds', {}).get('sources_file', 'config/sources.yaml')
        
        try:
            with open(sources_file, 'r') as f:
                data = yaml.safe_load(f)
                return [s for s in data.get('sources', []) if s.get('enabled', True)]
        except FileNotFoundError:
            logger.warning(f"Sources file not found: {sources_file}")
            return self._default_sources()
    
    def _default_sources(self) -> List[Dict]:
        """Return default RSS sources"""
        return [
            {
                'name': 'CISA Advisories',
                'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
                'type': 'government',
                'enabled': True
            },
            {
                'name': 'NVD Recent CVEs',
                'url': 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml',
                'type': 'database',
                'enabled': True
            }
        ]
    
    def _load_technologies(self) -> List[str]:
        """Load technologies to monitor"""
        tech_file = self.config.get('technologies', {}).get('technologies_file', 
                                                            'config/technologies.yaml')
        
        try:
            with open(tech_file, 'r') as f:
                data = yaml.safe_load(f)
                return data.get('technologies', [])
        except FileNotFoundError:
            logger.warning(f"Technologies file not found: {tech_file}")
            return self._default_technologies()
    
    def _default_technologies(self) -> List[str]:
        """Return default technologies list"""
        return [
            'windows', 'linux', 'ubuntu', 'debian',
            'apache', 'nginx', 'iis',
            'mysql', 'postgresql', 'mongodb',
            'docker', 'kubernetes',
            'wordpress', 'joomla', 'drupal'
        ]
    
    def _load_seen_threats(self) -> Set[str]:
        """Load previously seen threats"""
        data_dir = Path(self.config.get('storage', {}).get('data_dir', 'data'))
        seen_file = data_dir / 'seen_threats.json'
        
        if seen_file.exists():
            try:
                with open(seen_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('threats', []))
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON in seen threats file")
                return set()
        
        return set()
    
    def _save_seen_threats(self):
        """Save seen threats to file"""
        data_dir = Path(self.config.get('storage', {}).get('data_dir', 'data'))
        data_dir.mkdir(parents=True, exist_ok=True)
        
        seen_file = data_dir / 'seen_threats.json'
        
        data = {
            'last_updated': datetime.now().isoformat(),
            'count': len(self.seen_threats),
            'threats': list(self.seen_threats)
        }
        
        with open(seen_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    @staticmethod
    def extract_cve(text: str) -> Optional[str]:
        """Extract CVE identifier from text"""
        if not text:
            return None
        
        match = re.search(r'CVE-\d{4}-\d{4,}', text.upper())
        return match.group(0) if match else None
    
    @staticmethod
    def generate_threat_id(title: str, date: str) -> str:
        """Generate unique ID for threat"""
        content = f"{title}_{date}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def match_technologies(self, text: str) -> List[str]:
        """Find matching technologies in text"""
        case_sensitive = self.config.get('technologies', {}).get('case_sensitive', False)
        
        if not case_sensitive:
            text = text.lower()
        
        matched = []
        for tech in self.technologies:
            search_tech = tech if case_sensitive else tech.lower()
            if search_tech in text:
                if tech not in matched:
                    matched.append(tech)
        
        return matched
    
    def classify_severity(self, title: str, description: str) -> tuple:
        """Classify threat severity and estimate CVSS score"""
        text = (title + " " + description).lower()
        
        severity_config = self.config.get('severity', {})
        
        critical_keywords = severity_config.get('critical_keywords', [])
        high_keywords = severity_config.get('high_keywords', [])
        
        # Check for critical severity
        for keyword in critical_keywords:
            if keyword.lower() in text:
                return ('CRITICAL', 9.5)
        
        # Check for high severity
        for keyword in high_keywords:
            if keyword.lower() in text:
                return ('HIGH', 7.5)
        
        return ('MEDIUM', 5.0)
    
    def is_recent(self, pub_date) -> bool:
        """Check if threat is recent based on configuration"""
        if not pub_date:
            return True
        
        max_age = self.config.get('feeds', {}).get('max_age_days', 30)
        
        try:
            from time import mktime
            pub_datetime = datetime.fromtimestamp(mktime(pub_date))
            cutoff_date = datetime.now() - timedelta(days=max_age)
            return pub_datetime >= cutoff_date
        except:
            return True
    
    def collect_from_feed(self, source: Dict) -> List[ThreatIntelligence]:
        """Collect threats from a single RSS feed"""
        threats = []
        
        logger.info(f"Collecting from: {source['name']}")
        
        try:
            timeout = self.config.get('feeds', {}).get('timeout', 30)
            feed = feedparser.parse(source['url'], timeout=timeout)
            
            if feed.bozo and not feed.entries:
                logger.warning(f"Failed to parse feed: {source['name']}")
                return threats
            
            logger.info(f"  Found {len(feed.entries)} entries")
            
            for entry in feed.entries:
                # Check if entry is recent
                if hasattr(entry, 'published_parsed'):
                    if not self.is_recent(entry.published_parsed):
                        continue
                
                title = entry.get('title', 'No title')
                description = entry.get('summary', entry.get('description', ''))
                link = entry.get('link', source['url'])
                
                # Extract CVE
                cve = self.extract_cve(title) or self.extract_cve(description)
                
                # Generate unique ID
                pub_date = entry.get('published', datetime.now().isoformat())
                threat_id = self.generate_threat_id(title, pub_date)
                
                # Skip if already seen
                if threat_id in self.seen_threats:
                    continue
                
                # Match technologies
                tech_text = f"{title} {description}"
                technologies = self.match_technologies(tech_text)
                
                # Skip if no relevant technologies
                if not technologies:
                    continue
                
                # Classify severity
                severity, cvss = self.classify_severity(title, description)
                
                # Create threat intelligence object
                threat = ThreatIntelligence(
                    id=threat_id,
                    cve=cve or f"THREAT-{datetime.now().strftime('%Y%m%d')}-{threat_id[:8]}",
                    title=title,
                    title_translated=title,  # Will be translated by translator module
                    description=description[:1500],
                    description_translated=description[:1500],  # Will be translated
                    severity=severity,
                    cvss_score=cvss,
                    technologies=technologies,
                    published_date=pub_date,
                    detected_date=datetime.now().isoformat(),
                    source_url=link,
                    source_name=source['name'],
                    requires_alert=severity in ['CRITICAL', 'HIGH'],
                    references=[link]
                )
                
                if cve and cve.startswith('CVE-'):
                    threat.references.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
                
                threats.append(threat)
                self.seen_threats.add(threat_id)
                
                logger.debug(f"  Collected: {title[:60]}...")
        
        except Exception as e:
            logger.error(f"Error collecting from {source['name']}: {e}")
        
        return threats
    
    def collect_all(self) -> List[ThreatIntelligence]:
        """Collect threats from all configured feeds"""
        logger.info("="*70)
        logger.info("Starting threat collection")
        logger.info("="*70)
        
        all_threats = []
        
        for source in self.feeds:
            threats = self.collect_from_feed(source)
            all_threats.extend(threats)
        
        # Save seen threats
        self._save_seen_threats()
        
        logger.info("="*70)
        logger.info(f"Collection complete: {len(all_threats)} new threats")
        logger.info("="*70)
        
        return all_threats
    
    def save_threats(self, threats: List[ThreatIntelligence]):
        """Save collected threats to JSON files"""
        if not threats:
            logger.info("No threats to save")
            return
        
        data_dir = Path(self.config.get('storage', {}).get('data_dir', 'data'))
        data_dir.mkdir(parents=True, exist_ok=True)
        
        # Save daily threats
        daily_file = data_dir / 'daily_threats.json'
        daily_data = {
            'timestamp': datetime.now().isoformat(),
            'count': len(threats),
            'threats': [asdict(t) for t in threats]
        }
        
        with open(daily_file, 'w') as f:
            json.dump(daily_data, f, indent=2)
        
        logger.info(f"Saved {len(threats)} threats to {daily_file}")
        
        # Append to monthly threats
        monthly_file = data_dir / f"monthly_threats_{datetime.now().strftime('%Y_%m')}.json"
        
        if monthly_file.exists():
            with open(monthly_file, 'r') as f:
                monthly_data = json.load(f)
        else:
            monthly_data = {
                'month': datetime.now().strftime('%Y-%m'),
                'threats': []
            }
        
        monthly_data['threats'].extend([asdict(t) for t in threats])
        monthly_data['last_updated'] = datetime.now().isoformat()
        monthly_data['total_count'] = len(monthly_data['threats'])
        
        with open(monthly_file, 'w') as f:
            json.dump(monthly_data, f, indent=2)
        
        logger.info(f"Updated monthly file: {monthly_file}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='PhantomCortex Threat Collector')
    parser.add_argument('--config', default='config/config.yaml', help='Configuration file')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--test', action='store_true', help='Test mode (dry run)')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize collector
    collector = ThreatCollector(args.config)
    
    # Collect threats
    threats = collector.collect_all()
    
    if args.test:
        logger.info("TEST MODE: Not saving threats")
        for threat in threats[:5]:  # Show first 5
            logger.info(f"  - {threat.title[:60]}... [{threat.severity}]")
    else:
        # Save threats
        collector.save_threats(threats)
    
    logger.info("Collection complete!")


if __name__ == '__main__':
    main()
