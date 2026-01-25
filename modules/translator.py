#!/usr/bin/env python3
"""
PhantomCortex - Translation Module
Offline translation using Argos Translate
"""

import json
import re
import logging
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass

try:
    import argostranslate.package
    import argostranslate.translate

    ARGOS_AVAILABLE = True
except ImportError:
    ARGOS_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class TranslationResult:
    """Translation result data class"""

    original_text: str
    translated_text: str
    source_lang: str
    target_lang: str
    success: bool
    error_message: Optional[str] = None


class OfflineTranslator:
    """Offline translation engine using Argos Translate"""

    def __init__(self, source_lang: str = "en", target_lang: str = "es"):
        """
        Initialize translator

        Args:
            source_lang: Source language code (ISO 639-1)
            target_lang: Target language code (ISO 639-1)
        """
        self.source_lang = source_lang
        self.target_lang = target_lang
        self.enabled = ARGOS_AVAILABLE

        if not self.enabled:
            logger.warning("Argos Translate not available - translations disabled")
        else:
            logger.info(f"Translator initialized: {source_lang} → {target_lang}")

    def is_available(self) -> bool:
        """Check if translation is available"""
        return self.enabled

    def clean_text(self, text: str) -> str:
        """
        Clean text before translation

        Args:
            text: Text to clean

        Returns:
            Cleaned text
        """
        if not text:
            return ""

        # Remove excessive whitespace
        text = re.sub(r"\s+", " ", text)

        # Remove HTML tags
        text = re.sub(r"<[^>]+>", "", text)

        # Remove URLs (keep them as [URL] placeholder)
        text = re.sub(
            r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
            "[URL]",
            text,
        )

        # Remove email addresses
        text = re.sub(r"\S+@\S+", "[EMAIL]", text)

        # Trim
        text = text.strip()

        return text

    def translate(self, text: str, max_length: int = 2000) -> TranslationResult:
        """
        Translate text from source to target language

        Args:
            text: Text to translate
            max_length: Maximum text length (characters)

        Returns:
            TranslationResult object
        """
        # Validate
        if not text or not text.strip():
            return TranslationResult(
                original_text=text,
                translated_text=text,
                source_lang=self.source_lang,
                target_lang=self.target_lang,
                success=True,
                error_message="Empty text",
            )

        # Check if translation is available
        if not self.enabled:
            return TranslationResult(
                original_text=text,
                translated_text=text,
                source_lang=self.source_lang,
                target_lang=self.target_lang,
                success=False,
                error_message="Argos Translate not available",
            )

        # Clean text
        cleaned_text = self.clean_text(text)

        # Truncate if too long
        if len(cleaned_text) > max_length:
            cleaned_text = cleaned_text[:max_length] + "..."

        # Translate
        try:
            translated = argostranslate.translate.translate(
                cleaned_text, self.source_lang, self.target_lang
            )

            return TranslationResult(
                original_text=text,
                translated_text=translated,
                source_lang=self.source_lang,
                target_lang=self.target_lang,
                success=True,
            )

        except Exception as e:
            logger.error(f"Translation error: {e}")
            return TranslationResult(
                original_text=text,
                translated_text=text,
                source_lang=self.source_lang,
                target_lang=self.target_lang,
                success=False,
                error_message=str(e),
            )

    def translate_batch(self, texts: List[str]) -> List[TranslationResult]:
        """
        Translate multiple texts

        Args:
            texts: List of texts to translate

        Returns:
            List of TranslationResult objects
        """
        results = []

        for text in texts:
            result = self.translate(text)
            results.append(result)

        return results

    def translate_threat(self, threat: Dict) -> Dict:
        """
        Translate threat title and description

        Args:
            threat: Threat dictionary

        Returns:
            Updated threat dictionary with translations
        """
        # Translate title
        if "title" in threat:
            result = self.translate(threat["title"])
            threat["title_translated"] = (
                result.translated_text if result.success else threat["title"]
            )

        # Translate description
        if "description" in threat:
            result = self.translate(threat["description"])
            threat["description_translated"] = (
                result.translated_text if result.success else threat["description"]
            )

        return threat


def translate_file(
    input_file: str, output_file: str, source_lang: str = "en", target_lang: str = "es"
):
    """
    Translate threats from input JSON file and save to output file

    Args:
        input_file: Input JSON file path
        output_file: Output JSON file path
        source_lang: Source language code
        target_lang: Target language code
    """
    logger.info(f"Translating {input_file} → {output_file}")

    # Load threats
    with open(input_file, "r") as f:
        data = json.load(f)

    threats = data.get("threats", [])

    if not threats:
        logger.warning("No threats found in file")
        return

    # Initialize translator
    translator = OfflineTranslator(source_lang, target_lang)

    if not translator.is_available():
        logger.error("Translation not available")
        return

    # Translate each threat
    logger.info(f"Translating {len(threats)} threats...")

    for idx, threat in enumerate(threats):
        threat = translator.translate_threat(threat)

        if (idx + 1) % 10 == 0:
            logger.info(f"  Translated {idx + 1}/{len(threats)} threats")

    # Save translated data
    data["threats"] = threats
    data["translation"] = {
        "source_lang": source_lang,
        "target_lang": target_lang,
        "translated_count": len(threats),
    }

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.info(f"✅ Translation complete: {output_file}")


def main():
    """Main entry point for CLI usage"""
    import argparse

    parser = argparse.ArgumentParser(description="PhantomCortex Translator")
    parser.add_argument(
        "--input", default="data/daily_threats.json", help="Input JSON file"
    )
    parser.add_argument(
        "--output",
        default="data/daily_threats_translated.json",
        help="Output JSON file",
    )
    parser.add_argument("--source-lang", default="en", help="Source language")
    parser.add_argument("--target-lang", default="es", help="Target language")
    parser.add_argument("--test", action="store_true", help="Test translation")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if args.test:
        logger.info("Testing translation...")
        translator = OfflineTranslator(args.source_lang, args.target_lang)

        if not translator.is_available():
            logger.error("❌ Translation not available")
            logger.info("Install: pip install argostranslate")
            logger.info("Setup: python scripts/setup_translation.py")
            return 1

        test_text = (
            "Critical vulnerability in Windows Server allows remote code execution"
        )
        result = translator.translate(test_text)

        logger.info(f"Original: {result.original_text}")
        logger.info(f"Translated: {result.translated_text}")
        logger.info(f"Success: {result.success}")

        if result.success:
            logger.info("✅ Translation working!")
            return 0
        else:
            logger.error(f"❌ Translation failed: {result.error_message}")
            return 1

    # Translate file
    try:
        translate_file(args.input, args.output, args.source_lang, args.target_lang)
        return 0
    except FileNotFoundError:
        logger.error(f"File not found: {args.input}")
        return 1
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
