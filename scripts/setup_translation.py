#!/usr/bin/env python3
"""
PhantomCortex - Translation Setup Script
Downloads and installs Argos Translate language models
"""

import sys
import argparse
from pathlib import Path

try:
    import argostranslate.package
    import argostranslate.translate
except ImportError:
    print("❌ Error: argostranslate not installed")
    print("Run: pip install argostranslate")
    sys.exit(1)


def download_model(from_lang: str, to_lang: str):
    """Download and install translation model"""
    print(f"📥 Downloading {from_lang} → {to_lang} translation model...")
    
    try:
        # Update package index
        argostranslate.package.update_package_index()
        available_packages = argostranslate.package.get_available_packages()
        
        # Find the package
        package_to_install = None
        for pkg in available_packages:
            if pkg.from_code == from_lang and pkg.to_code == to_lang:
                package_to_install = pkg
                break
        
        if package_to_install is None:
            print(f"❌ No package found for {from_lang} → {to_lang}")
            return False
        
        # Download and install
        print(f"   Downloading: {package_to_install.package_version}")
        download_path = package_to_install.download()
        argostranslate.package.install_from_path(download_path)
        
        print(f"✅ Successfully installed {from_lang} → {to_lang} model")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_translation(from_lang: str, to_lang: str):
    """Test if translation works"""
    print(f"\n🧪 Testing translation...")
    
    try:
        test_text = "Critical vulnerability detected in Windows Server"
        translated = argostranslate.translate.translate(test_text, from_lang, to_lang)
        
        print(f"   Original: {test_text}")
        print(f"   Translated: {translated}")
        print(f"✅ Translation working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Translation test failed: {e}")
        return False


def list_installed_languages():
    """List installed language packages"""
    print("\n📋 Installed language packages:")
    
    installed = argostranslate.translate.get_installed_languages()
    
    if not installed:
        print("   No language packages installed")
        return
    
    for lang in installed:
        print(f"   - {lang.name} ({lang.code})")
    
    print(f"\n   Total: {len(installed)} languages")


def main():
    parser = argparse.ArgumentParser(description='Setup translation for PhantomCortex')
    parser.add_argument('--from-lang', default='en', help='Source language (default: en)')
    parser.add_argument('--to-lang', default='es', help='Target language (default: es)')
    parser.add_argument('--list', action='store_true', help='List installed languages')
    parser.add_argument('--test-only', action='store_true', help='Only test translation')
    
    args = parser.parse_args()
    
    print("="*70)
    print("🛡️  PhantomCortex - Translation Setup")
    print("="*70)
    
    if args.list:
        list_installed_languages()
        sys.exit(0)
    
    if args.test_only:
        success = test_translation(args.from_lang, args.to_lang)
        sys.exit(0 if success else 1)
    
    # Download model
    success = download_model(args.from_lang, args.to_lang)
    
    if success:
        # Test it
        test_translation(args.from_lang, args.to_lang)
    
    print("\n="*70)
    print("✅ Setup complete!" if success else "❌ Setup failed")
    print("="*70)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
