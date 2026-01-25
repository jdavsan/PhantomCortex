#!/usr/bin/env python3
"""
PhantomCortex - Reporting Module
Generate monthly threat intelligence reports in Word format
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Monthly report generator"""
    
    def __init__(self):
        """Initialize report generator"""
        self.doc = None
        logger.info("Report generator initialized")
    
    def _add_header(self, title: str, subtitle: str):
        """Add report header"""
        # Title
        heading = self.doc.add_heading(title, level=0)
        heading.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        # Format title
        for run in heading.runs:
            run.font.size = Pt(24)
            run.font.color.rgb = RGBColor(51, 51, 51)
        
        # Subtitle
        subheading = self.doc.add_paragraph(subtitle)
        subheading.alignment = WD_ALIGN_PARAGRAPH.CENTER
        for run in subheading.runs:
            run.font.size = Pt(14)
            run.font.color.rgb = RGBColor(102, 102, 102)
        
        # Add spacing
        self.doc.add_paragraph()
    
    def _add_summary_section(self, threats: List[Dict]):
        """Add executive summary section"""
        self.doc.add_heading('📊 Executive Summary', level=1)
        
        # Count by severity
        critical = [t for t in threats if t.get('severity') == 'CRITICAL']
        high = [t for t in threats if t.get('severity') == 'HIGH']
        medium = [t for t in threats if t.get('severity') == 'MEDIUM']
        low = [t for t in threats if t.get('severity') == 'LOW']
        
        # Summary text
        summary_text = f"""
This report covers {len(threats)} cyber threats detected during the reporting period. 
The threats have been categorized by severity and analyzed for potential impact on organizational infrastructure.

Key Findings:
• {len(critical)} CRITICAL threats requiring immediate action
• {len(high)} HIGH severity threats requiring prompt attention
• {len(medium)} MEDIUM severity threats for scheduled remediation
• {len(low)} LOW severity informational threats
"""
        
        para = self.doc.add_paragraph(summary_text.strip())
        para.paragraph_format.space_after = Pt(12)
        
        # Add severity breakdown table
        self.doc.add_heading('Threat Breakdown', level=2)
        
        table = self.doc.add_table(rows=5, cols=3)
        table.style = 'Light Grid Accent 1'
        
        # Header row
        header_cells = table.rows[0].cells
        header_cells[0].text = 'Severity'
        header_cells[1].text = 'Count'
        header_cells[2].text = 'Percentage'
        
        # Make header bold
        for cell in header_cells:
            for paragraph in cell.paragraphs:
                for run in paragraph.runs:
                    run.font.bold = True
        
        # Data rows
        total = len(threats) or 1  # Avoid division by zero
        
        rows_data = [
            ('CRITICAL', len(critical), f'{len(critical)/total*100:.1f}%'),
            ('HIGH', len(high), f'{len(high)/total*100:.1f}%'),
            ('MEDIUM', len(medium), f'{len(medium)/total*100:.1f}%'),
            ('LOW', len(low), f'{len(low)/total*100:.1f}%'),
        ]
        
        for idx, (severity, count, percentage) in enumerate(rows_data, 1):
            cells = table.rows[idx].cells
            cells[0].text = severity
            cells[1].text = str(count)
            cells[2].text = percentage
        
        self.doc.add_paragraph()
    
    def _add_threat_details(self, threats: List[Dict]):
        """Add detailed threat information"""
        self.doc.add_heading('🔍 Detailed Threat Analysis', level=1)
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_threats = sorted(
            threats,
            key=lambda t: severity_order.get(t.get('severity', 'LOW'), 3)
        )
        
        for idx, threat in enumerate(sorted_threats, 1):
            # Threat heading
            title = threat.get('title_translated', threat.get('title', 'Unknown Threat'))
            severity = threat.get('severity', 'MEDIUM')
            
            heading = self.doc.add_heading(f"{idx}. {title}", level=2)
            
            # Color code by severity
            severity_colors = {
                'CRITICAL': RGBColor(220, 53, 69),
                'HIGH': RGBColor(253, 126, 20),
                'MEDIUM': RGBColor(255, 193, 7),
                'LOW': RGBColor(40, 167, 69)
            }
            
            for run in heading.runs:
                run.font.color.rgb = severity_colors.get(severity, RGBColor(0, 0, 0))
            
            # Metadata table
            meta_table = self.doc.add_table(rows=5, cols=2)
            meta_table.style = 'Light List'
            
            meta_data = [
                ('Severity', severity),
                ('CVE', threat.get('cve', 'N/A')),
                ('CVSS Score', str(threat.get('cvss_score', 'N/A'))),
                ('Detected', threat.get('detected_date', 'N/A')),
                ('Source', threat.get('source_name', 'Unknown'))
            ]
            
            for row_idx, (label, value) in enumerate(meta_data):
                cells = meta_table.rows[row_idx].cells
                cells[0].text = label
                cells[0].paragraphs[0].runs[0].font.bold = True
                cells[1].text = value
            
            # Description
            self.doc.add_heading('Description', level=3)
            description = threat.get('description_translated', 
                                    threat.get('description', 'No description available'))
            self.doc.add_paragraph(description[:500])
            
            # Affected Technologies
            technologies = threat.get('technologies', [])
            if technologies:
                self.doc.add_heading('Affected Technologies', level=3)
                tech_para = self.doc.add_paragraph()
                tech_para.add_run(', '.join(technologies[:10]))
            
            # References
            if threat.get('references'):
                self.doc.add_heading('References', level=3)
                for ref in threat['references'][:3]:
                    self.doc.add_paragraph(ref, style='List Bullet')
            
            # Page break after each threat (except last)
            if idx < len(sorted_threats):
                self.doc.add_page_break()
    
    def _add_footer(self):
        """Add report footer"""
        self.doc.add_paragraph()
        
        footer_para = self.doc.add_paragraph()
        footer_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        footer_run = footer_para.add_run(
            f"\n\nGenerated by PhantomCortex on {datetime.now().strftime('%B %d, %Y at %H:%M')}\n"
            "Open Source Cyber Threat Intelligence Platform\n"
            "https://github.com/yourusername/PhantomCortex"
        )
        
        footer_run.font.size = Pt(9)
        footer_run.font.color.rgb = RGBColor(128, 128, 128)
    
    def generate_report(self, threats: List[Dict], output_path: str, 
                       month: str = None) -> bool:
        """
        Generate monthly threat report
        
        Args:
            threats: List of threat dictionaries
            output_path: Output file path
            month: Month string (e.g., "2025-01")
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Generating report for {len(threats)} threats")
            
            # Create document
            self.doc = Document()
            
            # Set margins
            sections = self.doc.sections
            for section in sections:
                section.top_margin = Inches(1)
                section.bottom_margin = Inches(1)
                section.left_margin = Inches(1)
                section.right_margin = Inches(1)
            
            # Add cover page
            if month:
                month_display = datetime.strptime(month, '%Y-%m').strftime('%B %Y')
            else:
                month_display = datetime.now().strftime('%B %Y')
            
            self._add_header(
                'Cyber Threat Intelligence Report',
                f'Monthly Analysis - {month_display}'
            )
            
            # Add generation info
            info_para = self.doc.add_paragraph()
            info_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            
            info_run = info_para.add_run(
                f"Generated: {datetime.now().strftime('%B %d, %Y')}\n"
                f"Total Threats: {len(threats)}\n"
                f"Classification: CONFIDENTIAL"
            )
            info_run.font.size = Pt(10)
            info_run.font.color.rgb = RGBColor(102, 102, 102)
            
            # Page break
            self.doc.add_page_break()
            
            # Add sections
            self._add_summary_section(threats)
            self.doc.add_page_break()
            
            self._add_threat_details(threats)
            
            self._add_footer()
            
            # Save document
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            self.doc.save(output_path)
            
            logger.info(f"✅ Report saved: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return False


def generate_monthly_report(input_file: str = None, output_file: str = None):
    """
    Generate monthly report from threats JSON
    
    Args:
        input_file: Input JSON file (default: auto-detect current month)
        output_file: Output DOCX file (default: auto-generate)
    """
    # Auto-detect input file if not provided
    if not input_file:
        current_month = datetime.now().strftime('%Y_%m')
        input_file = f"data/monthly_threats_{current_month}.json"
    
    # Auto-generate output file if not provided
    if not output_file:
        month_str = datetime.now().strftime('%Y_%m')
        output_file = f"reports/Monthly_Report_{month_str}.docx"
    
    logger.info(f"Generating report from {input_file}")
    
    # Load threats
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        threats = data.get('threats', [])
        
        if not threats:
            logger.warning("No threats found in file")
            return False
        
        # Generate report
        generator = ReportGenerator()
        
        # Extract month from data or filename
        month = data.get('month', datetime.now().strftime('%Y-%m'))
        
        success = generator.generate_report(threats, output_file, month)
        
        return success
    
    except FileNotFoundError:
        logger.error(f"File not found: {input_file}")
        return False
    except Exception as e:
        logger.error(f"Error: {e}")
        return False


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PhantomCortex Report Generator')
    parser.add_argument('--input', help='Input threats JSON file')
    parser.add_argument('--output', help='Output report file')
    parser.add_argument('--month', help='Month in YYYY-MM format')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Use provided files or auto-detect
    input_file = args.input
    output_file = args.output
    
    if args.month:
        # Generate for specific month
        input_file = input_file or f"data/monthly_threats_{args.month.replace('-', '_')}.json"
        output_file = output_file or f"reports/Monthly_Report_{args.month.replace('-', '_')}.docx"
    
    # Generate report
    success = generate_monthly_report(input_file, output_file)
    
    return 0 if success else 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
