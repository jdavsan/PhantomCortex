"""Logging estructurado.

Dos salidas a la vez:
  * consola  -> legible por una persona (lo que se ve en el log de cron)
  * archivo  -> una linea JSON por evento, grepeable y apto para Wazuh/Zabbix

Sustituye a los `print()` con emojis del sistema anterior, que no tenian
niveles ni campos y no se podian filtrar.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from typing import Optional

from .paths import LOGS_DIR, ensure_dirs

_CONFIGURED = False

# Claves internas de LogRecord que no son campos del evento
_RESERVED = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name",
    "pathname", "process", "processName", "relativeCreated", "stack_info",
    "thread", "threadName", "taskName",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc)
                      .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                try:
                    json.dumps(value)
                    payload[key] = value
                except (TypeError, ValueError):
                    payload[key] = repr(value)
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """Formato compacto para la consola, con el detalle relevante en linea."""

    LEVELS = {
        "DEBUG": "  ",
        "INFO": "  ",
        "WARNING": "! ",
        "ERROR": "X ",
        "CRITICAL": "XX",
    }
    SKIP = {"run_id", "kind"}

    def format(self, record: logging.LogRecord) -> str:
        stamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        marker = self.LEVELS.get(record.levelname, "  ")
        extras = {
            k: v for k, v in record.__dict__.items()
            if k not in _RESERVED and not k.startswith("_") and k not in self.SKIP
        }
        line = f"{stamp} {marker} {record.getMessage()}"
        if extras:
            rendered = " ".join(f"{k}={v}" for k, v in extras.items())
            line = f"{line}  [{rendered}]"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def setup(name: str = "threatintel", level: str = "INFO",
          log_file: Optional[str] = None, console: bool = True) -> logging.Logger:
    """Configura el logging global. Idempotente dentro del mismo proceso."""
    global _CONFIGURED
    ensure_dirs()

    root = logging.getLogger()
    if _CONFIGURED:
        return logging.getLogger(name)

    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    for handler in list(root.handlers):
        root.removeHandler(handler)

    target = LOGS_DIR / (log_file or "threatintel.jsonl")
    file_handler = logging.handlers.RotatingFileHandler(
        target, maxBytes=20 * 1024 * 1024, backupCount=10, encoding="utf-8"
    )
    file_handler.setFormatter(JsonFormatter())
    root.addHandler(file_handler)

    if console:
        stream = logging.StreamHandler(sys.stdout)
        stream.setFormatter(ConsoleFormatter())
        root.addHandler(stream)

    # Bibliotecas ruidosas. ArgosTranslate registra a nivel INFO cada frase que
    # traduce, con su tokenizacion completa: en una recoleccion con 800 entradas
    # eso son decenas de miles de lineas que hacen el log inservible.
    for ruidoso, nivel in (
            ("urllib3", logging.WARNING),
            ("charset_normalizer", logging.WARNING),
            ("requests", logging.WARNING),
            ("argostranslate", logging.WARNING),
            ("argostranslate.utils", logging.WARNING),
            ("stanza", logging.ERROR),
            ("ctranslate2", logging.WARNING),
            ("sentencepiece", logging.WARNING),
            ("filelock", logging.WARNING),
            ("PIL", logging.WARNING)):
        registro = logging.getLogger(ruidoso)
        registro.setLevel(nivel)
        registro.propagate = False

    _CONFIGURED = True
    return logging.getLogger(name)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"threatintel.{name}")
