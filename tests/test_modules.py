#!/usr/bin/env python3
"""
PhantomCortex - Unit Tests for Modules
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.translator import OfflineTranslator
from modules.alerting import EmailAlerter


class TestTranslator(unittest.TestCase):
    """Test cases for OfflineTranslator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.translator = OfflineTranslator('en', 'es')
    
    def test_initialization(self):
        """Test translator initialization"""
        self.assertEqual(self.translator.source_lang, 'en')
        self.assertEqual(self.translator.target_lang, 'es')
    
    def test_clean_text(self):
        """Test text cleaning"""
        # Test whitespace removal
        text = "Text   with    excessive    spaces"
        cleaned = self.translator.clean_text(text)
        self.assertNotIn('   ', cleaned)
        
        # Test HTML removal
        text = "<p>Text with <strong>HTML</strong> tags</p>"
        cleaned = self.translator.clean_text(text)
        self.assertNotIn('<', cleaned)
        self.assertNotIn('>', cleaned)
        
        # Test URL replacement
        text = "Check https://example.com for details"
        cleaned = self.translator.clean_text(text)
        self.assertIn('[URL]', cleaned)
    
    def test_empty_translation(self):
        """Test translation of empty text"""
        result = self.translator.translate("")
        self.assertTrue(result.success)
        self.assertEqual(result.translated_text, "")
    
    def test_threat_translation(self):
        """Test threat dictionary translation"""
        threat = {
            'title': 'Test Threat',
            'description': 'Test Description'
        }
        
        translated = self.translator.translate_threat(threat)
        
        self.assertIn('title_translated', translated)
        self.assertIn('description_translated', translated)


class TestAlerter(unittest.TestCase):
    """Test cases for EmailAlerter"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Note: This requires a config file
        # For testing, we'll just test initialization
        pass
    
    def test_html_generation(self):
        """Test HTML email generation"""
        # Create a mock alerter without config
        alerter = EmailAlerter.__new__(EmailAlerter)
        alerter.config = {'email': {'enabled': False}}
        alerter.email_config = {}
        
        # Test data
        threats = [
            {
                'title': 'Test Threat',
                'title_translated': 'Amenaza de Prueba',
                'severity': 'CRITICAL',
                'cve': 'CVE-2025-0001',
                'cvss_score': 9.8,
                'description': 'Test description',
                'description_translated': 'Descripción de prueba',
                'technologies': ['Windows', 'Linux'],
                'source_name': 'Test Source',
                'source_url': 'https://example.com'
            }
        ]
        
        html = alerter.create_html_alert(threats)
        
        # Check HTML contains key elements
        self.assertIn('<!DOCTYPE html>', html)
        self.assertIn('PhantomCortex', html)
        self.assertIn('Amenaza de Prueba', html)
        self.assertIn('CRITICAL', html)


class TestReporting(unittest.TestCase):
    """Test cases for ReportGenerator"""
    
    def test_report_generator_init(self):
        """Test report generator initialization"""
        from modules.reporting import ReportGenerator
        
        generator = ReportGenerator()
        self.assertIsNone(generator.doc)


if __name__ == '__main__':
    unittest.main()
