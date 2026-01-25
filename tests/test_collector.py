#!/usr/bin/env python3
"""
PhantomCortex - Unit Tests for Collector
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.collector import ThreatCollector


class TestThreatCollector(unittest.TestCase):
    """Test cases for ThreatCollector"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.collector = ThreatCollector()
    
    def test_extract_cve(self):
        """Test CVE extraction"""
        # Test valid CVE
        text = "Critical vulnerability CVE-2025-1234 discovered"
        cve = ThreatCollector.extract_cve(text)
        self.assertEqual(cve, "CVE-2025-1234")
        
        # Test no CVE
        text = "No CVE in this text"
        cve = ThreatCollector.extract_cve(text)
        self.assertIsNone(cve)
        
        # Test empty text
        cve = ThreatCollector.extract_cve("")
        self.assertIsNone(cve)
    
    def test_generate_threat_id(self):
        """Test threat ID generation"""
        title = "Test Threat"
        date = "2025-01-01"
        
        id1 = ThreatCollector.generate_threat_id(title, date)
        id2 = ThreatCollector.generate_threat_id(title, date)
        
        # Same input should generate same ID
        self.assertEqual(id1, id2)
        
        # ID should be 16 characters
        self.assertEqual(len(id1), 16)
        
        # Different input should generate different ID
        id3 = ThreatCollector.generate_threat_id("Different", date)
        self.assertNotEqual(id1, id3)
    
    def test_match_technologies(self):
        """Test technology matching"""
        text = "Vulnerability in Windows Server and Apache"
        
        technologies = self.collector.match_technologies(text)
        
        self.assertIn('windows', [t.lower() for t in technologies])
        self.assertIn('apache', [t.lower() for t in technologies])
    
    def test_classify_severity(self):
        """Test severity classification"""
        # Test critical
        title = "Critical RCE vulnerability"
        description = "Remote code execution in unauthenticated context"
        severity, cvss = self.collector.classify_severity(title, description)
        self.assertEqual(severity, 'CRITICAL')
        self.assertGreater(cvss, 8.0)
        
        # Test high
        title = "SQL Injection vulnerability"
        description = "Allows privilege escalation"
        severity, cvss = self.collector.classify_severity(title, description)
        self.assertEqual(severity, 'HIGH')
        
        # Test medium (default)
        title = "Minor bug"
        description = "Low impact issue"
        severity, cvss = self.collector.classify_severity(title, description)
        self.assertEqual(severity, 'MEDIUM')


class TestConfiguration(unittest.TestCase):
    """Test configuration loading"""
    
    def test_default_config(self):
        """Test default configuration"""
        collector = ThreatCollector()
        
        # Should have default config
        self.assertIsNotNone(collector.config)
        self.assertIn('feeds', collector.config)
    
    def test_default_sources(self):
        """Test default RSS sources"""
        collector = ThreatCollector()
        
        # Should have default sources
        self.assertGreater(len(collector.feeds), 0)
        
        # Check structure
        for feed in collector.feeds:
            self.assertIn('name', feed)
            self.assertIn('url', feed)
            self.assertIn('type', feed)
    
    def test_default_technologies(self):
        """Test default technologies"""
        collector = ThreatCollector()
        
        # Should have default technologies
        self.assertGreater(len(collector.technologies), 0)
        
        # Common technologies should be present
        tech_lower = [t.lower() for t in collector.technologies]
        self.assertIn('windows', tech_lower)
        self.assertIn('linux', tech_lower)


if __name__ == '__main__':
    unittest.main()
