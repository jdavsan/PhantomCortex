#!/usr/bin/env python3
"""
PhantomCortex - Pre-Publication Verification Script
Checks that project is ready for GitHub publication
"""

import os
import sys
from pathlib import Path
import re


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'


def check_file_exists(filepath: str, required: bool = True) -> bool:
    """Check if a file exists"""
    exists = Path(filepath).exists()
    
    status = f"{Colors.GREEN}✅{Colors.END}" if exists else f"{Colors.RED}❌{Colors.END}"
    req_label = "[REQUIRED]" if required else "[OPTIONAL]"
    
    print(f"  {status} {filepath} {req_label}")
    
    if required and not exists:
        return False
    return True


def check_no_sensitive_data(filepath: str) -> bool:
    """Check file for sensitive data patterns"""
    if not Path(filepath).exists():
        return True
    
    sensitive_patterns = [
        r'password\s*=\s*["\'][^"\']+["\']',
        r'api_key\s*=\s*["\'][^"\']+["\']',
        r'secret\s*=\s*["\'][^"\']+["\']',
        r'token\s*=\s*["\'][^"\']+["\']',
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Emails (except example.com)
    ]
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                # Filter out example domains
                matches = [m for m in matches if 'example.com' not in str(m)]
                matches = [m for m in matches if 'your-' not in str(m)]
                matches = [m for m in matches if '""' not in str(m)]  # Empty passwords OK
                
                if matches:
                    print(f"  {Colors.RED}⚠️  Found sensitive data in {filepath}:{Colors.END}")
                    for match in matches[:3]:  # Show first 3
                        print(f"     → {match}")
                    return False
    except:
        pass
    
    return True


def check_company_references() -> bool:
    """Check for company-specific references"""
    # List of sensitive files to check
    files_to_check = [
        'README.md',
        'core/collector.py',
        'modules/alerting.py',
        'config/config.example.yaml'
    ]
    
    # Patterns to avoid (add your company name here)
    company_patterns = [
        'jaime torres',
        'jaimetorres',
        'jtc',
        # Add other company-specific terms
    ]
    
    issues_found = False
    
    for filepath in files_to_check:
        if not Path(filepath).exists():
            continue
            
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().lower()
            
            for pattern in company_patterns:
                if pattern.lower() in content:
                    print(f"  {Colors.RED}⚠️  Found '{pattern}' in {filepath}{Colors.END}")
                    issues_found = True
    
    return not issues_found


def main():
    print("="*70)
    print(f"{Colors.BLUE}🛡️  PhantomCortex - Pre-Publication Verification{Colors.END}")
    print("="*70)
    print()
    
    all_checks_passed = True
    
    # Check 1: Essential Files
    print(f"{Colors.BLUE}📋 Check 1: Essential Files{Colors.END}")
    essential_files = [
        ('README.md', True),
        ('LICENSE', True),
        ('requirements.txt', True),
        ('.gitignore', True),
        ('CONTRIBUTING.md', True),
        ('config/config.example.yaml', True),
        ('config/sources.yaml', True),
        ('config/technologies.yaml', True),
        ('core/collector.py', True),
        ('docs/INSTALLATION.md', True),
        ('docs/GITHUB_PUBLISHING.md', True),
        ('scripts/setup_translation.py', True),
        ('scripts/run_daily.sh', True),
    ]
    
    for filepath, required in essential_files:
        if not check_file_exists(filepath, required):
            all_checks_passed = False
    print()
    
    # Check 2: Directory Structure
    print(f"{Colors.BLUE}📁 Check 2: Directory Structure{Colors.END}")
    required_dirs = ['core', 'modules', 'config', 'docs', 'scripts', 'data', 'logs']
    
    for dirname in required_dirs:
        exists = Path(dirname).is_dir()
        status = f"{Colors.GREEN}✅{Colors.END}" if exists else f"{Colors.RED}❌{Colors.END}"
        print(f"  {status} {dirname}/")
        if not exists:
            all_checks_passed = False
    print()
    
    # Check 3: No Sensitive Data
    print(f"{Colors.BLUE}🔒 Check 3: No Sensitive Data{Colors.END}")
    files_to_scan = [
        'README.md',
        'config/config.example.yaml',
        'core/collector.py',
        'docs/INSTALLATION.md'
    ]
    
    sensitive_data_found = False
    for filepath in files_to_scan:
        if not check_no_sensitive_data(filepath):
            sensitive_data_found = True
            all_checks_passed = False
    
    if not sensitive_data_found:
        print(f"  {Colors.GREEN}✅ No sensitive data found{Colors.END}")
    print()
    
    # Check 4: No Company References
    print(f"{Colors.BLUE}🏢 Check 4: No Company References{Colors.END}")
    if check_company_references():
        print(f"  {Colors.GREEN}✅ No company references found{Colors.END}")
    else:
        print(f"  {Colors.RED}❌ Company references found - please remove{Colors.END}")
        all_checks_passed = False
    print()
    
    # Check 5: Git Configuration
    print(f"{Colors.BLUE}📦 Check 5: Git Configuration{Colors.END}")
    git_files = [
        ('.gitignore', True),
        ('.github/ISSUE_TEMPLATE/bug_report.md', False),
        ('.github/ISSUE_TEMPLATE/feature_request.md', False),
        ('.github/pull_request_template.md', False),
    ]
    
    for filepath, required in git_files:
        check_file_exists(filepath, required)
    print()
    
    # Check 6: Documentation Completeness
    print(f"{Colors.BLUE}📚 Check 6: Documentation{Colors.END}")
    
    # Check README sections
    if Path('README.md').exists():
        with open('README.md', 'r') as f:
            readme = f.read()
            
            required_sections = [
                'Overview',
                'Features',
                'Installation',
                'Usage',
                'Configuration',
                'Contributing',
                'License'
            ]
            
            for section in required_sections:
                if section.lower() in readme.lower():
                    print(f"  {Colors.GREEN}✅{Colors.END} README has '{section}' section")
                else:
                    print(f"  {Colors.YELLOW}⚠️{Colors.END} README missing '{section}' section")
    print()
    
    # Final Summary
    print("="*70)
    if all_checks_passed:
        print(f"{Colors.GREEN}✅ ALL CHECKS PASSED - Ready for publication!{Colors.END}")
        print()
        print("Next steps:")
        print("  1. git init")
        print("  2. git add .")
        print("  3. git commit -m 'feat: initial commit'")
        print("  4. git remote add origin https://github.com/USERNAME/PhantomCortex.git")
        print("  5. git push -u origin main")
        print()
        print("See docs/GITHUB_PUBLISHING.md for detailed instructions")
    else:
        print(f"{Colors.RED}❌ SOME CHECKS FAILED - Fix issues before publishing{Colors.END}")
        print()
        print("Review the output above and fix any issues marked with ❌")
        return 1
    print("="*70)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
