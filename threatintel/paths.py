"""Rutas base del proyecto. Todo lo demas las importa desde aqui."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"
HISTORICAL_REPORTS_DIR = REPORTS_DIR / "historical"
BACKUPS_DIR = BASE_DIR / "backups"
EMAIL_TEMPLATES_DIR = Path(__file__).resolve().parent / "emails"

CREDENTIALS_FILE = CONFIG_DIR / "credentials.env"
DB_FILE = DATA_DIR / "threat_intel.db"

# Exportaciones JSON que se mantienen por compatibilidad con lo anterior
DAILY_JSON = DATA_DIR / "daily_collected_threats.json"
ANALYZED_JSON = DATA_DIR / "analyzed_threats.json"
LAST_EXECUTION_JSON = DATA_DIR / "last_execution.json"


def ensure_dirs() -> None:
    """Crea los directorios de trabajo con permisos restrictivos."""
    for d in (DATA_DIR, LOGS_DIR, REPORTS_DIR, HISTORICAL_REPORTS_DIR, BACKUPS_DIR):
        d.mkdir(parents=True, exist_ok=True)
        try:
            d.chmod(0o700)
        except PermissionError:
            pass


def monthly_json(month: str) -> Path:
    """month en formato 'YYYY-MM' -> data/monthly_threats_YYYY_MM.json"""
    return DATA_DIR / f"monthly_threats_{month.replace('-', '_')}.json"


def report_file(month: str) -> Path:
    """month en formato 'YYYY-MM' -> reports/Informe_Mensual_YYYY_MM.docx"""
    return REPORTS_DIR / f"Informe_Mensual_{month.replace('-', '_')}.docx"
