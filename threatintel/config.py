"""Configuracion del sistema.

Dos niveles, a proposito:
  * SECRETOS   -> config/credentials.env (permisos 600, nunca en la GUI en claro)
  * AJUSTES    -> tabla `settings` de SQLite (editables desde la GUI)

`load()` valida al arrancar y falla ruidosamente si falta algo obligatorio, en
lugar de caer a un valor por defecto silencioso como hacia el sistema anterior.
"""
from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from typing import Any, Optional

from dotenv import dotenv_values

from . import db
from .paths import CREDENTIALS_FILE

# Ajustes no secretos con sus valores por defecto. La GUI los edita en `settings`.
DEFAULT_SETTINGS: dict[str, Any] = {
    # --- alertas ---
    "alert_min_severity": "High",        # Critical | High | Medium | Low
    "alert_max_items": 25,               # cuantas amenazas se detallan en el email
    "alert_enabled": True,
    "alert_only_affected_versions": False,  # si True, descarta version_verdict='not_affected'
    # Precision del filtro (2026-09-04): se alerta por relevancia, no por severidad
    "alert_min_relevance": 50,           # 0-100; KEV alerta siempre
    "alert_require_identifier": True,    # sin CVE ni id de aviso (DSA, USN...) no hay alerta
    "alert_defer_heuristic_hours": 24,   # severidad estimada: esperar al dato oficial
    "alert_min_match_confidence": 0.6,   # coincidencias mas debiles = mencion, no exposicion
    "digest_enabled": True,              # resumen semanal con lo no alertado
    "digest_weekday": 1,                 # 1 = lunes (isoweekday)
    "digest_max_items": 60,
    "debian_packages_file": "",          # lista de paquetes instalados (dpkg-query), opcional
    "ignore_low_severity": True,         # severidad Baja: fuera de alertas, resumen e informe
    "ignore_low_criticality": True,      # tecnologias de criticidad baja: solo mencion
    # --- activos (OCS Inventory) y aplicabilidad por activo (2026-09-04) ---
    "ocs_sync_enabled": True,            # sincronizar los dos OCS en la ejecucion diaria
    "ocs_stale_days": 30,                # activo «sin reportar» si su inventario es mas antiguo
    # Informe de inventario sin reportar, para Redes (2026-09-07).
    # Vacio = no se envia. Es un correo aparte del de seguridad a proposito.
    "inventario_destinatarios": [],
    "inventario_informe_activo": False,
    "ocs_update_inventory": True,        # rellenar systems_count/version_installed desde OCS
    "ocs_dmz_networks": [],              # CIDR de la zona perimetral (p. ej. 10.0.5.0/24)
    "ocs_internet_networks": [],         # CIDR de activos expuestos a Internet
    # Etiquetas de OCS que designan el mismo proceso de negocio («etiqueta = proceso»).
    # El usuario indico el 2026-09-06 que «admin» y «Proxmox»/«PVE» son «Administración técnica»;
    # eso va en el mapa base de threatintel/ocs.py y aqui se anaden o corrigen mas sin tocar codigo.
    "ocs_procesos_alias": [],
    "ocs_risk_software": ["tightvnc", "dwagent", "java 7", "java(tm) 7", "java 6",
                          "teamviewer", "anydesk", "ammyy", "ultravnc"],
    "ocs_edr_pattern": "sophos",         # software de proteccion esperado en cada equipo de computo
    "alert_skip_without_assets": True,   # no alertar si ningun activo tiene la version vulnerable
    # Afectacion real (2026-09-08): el usuario solo quiere que se le avise de lo que
    # afecta a alguna de sus maquinas. Sin un activo presente con veredicto
    # 'afectado' no se alerta, aunque la relevancia sea alta.
    "alert_solo_con_activos_afectados": True,
    # Excepcion para la explotacion activa confirmada (KEV): alertar aunque no se haya
    # confirmado ningun activo. APAGADA desde el 2026-09-10 por orden del usuario tras el
    # correo de ese dia: «me debe alertar lo que realmente me este afectando, de lo
    # contrario no». Se conserva el ajuste porque la decision es reversible: con el
    # encendido, una KEV vuelve a alertarse sin afectacion confirmada y el correo lo dice
    # con todas sus letras. Lo que NO se pierde nunca es el aviso de administracion cuando
    # la plataforma no ha podido evaluar una candidata (aplicabilidad.avisar_sin_evaluar).
    "alert_kev_sin_activos": False,
    "alert_send_when_empty": True,       # enviar el correo diario aunque no haya novedades
    "applicability_enabled": True,       # evaluar amenazas con CVE contra los activos
    "applicability_max_osv_per_run": 300,       # consultas de red a OSV.dev por ejecucion
    "applicability_max_threats_per_run": 150,   # amenazas evaluadas por ejecucion
    "applicability_reevaluate_days": 7,  # reevaluar cada N dias (salen correcciones nuevas)
    "osv_cache_hours": 168,
    "vuxml_cache_hours": 24,
    "eol_cache_hours": 168,
    # --- informe mensual ---
    "report_detail_severities": ["Critical", "High"],
    "report_summary_severities": ["Medium", "Low"],
    "report_max_detail_items": 30,
    "report_max_anexo_items": 250,
    # --- recoleccion ---
    "collect_lookback_days": 45,         # ventana movil; sustituye al filtro "mes actual"
    "collect_require_technology": True,  # solo amenazas que tocan el inventario
    "http_user_agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "http_timeout_s": 30,
    "http_retries": 2,
    # --- enriquecimiento ---
    "enrich_nvd_enabled": True,
    "enrich_kev_enabled": True,
    "enrich_epss_enabled": True,
    "enrich_max_per_run": 150,
    "nvd_rate_limit_sleep_s": 6.5,       # sin API key: 5 req / 30 s
    # --- traduccion ---
    "translate_engine": "hybrid",        # none | argos | ollama | hybrid
    "ollama_url": "http://localhost:11434",
    "ollama_model": "llama3.1:8b",
    "ollama_timeout_s": 120,
    "ollama_max_calls_per_run": 40,
    "ollama_severities": ["Critical", "High"],
    # --- salud de fuentes ---
    "health_fail_streak_alert": 3,       # avisar tras N ejecuciones fallidas seguidas
    "health_zero_entries_is_failure": True,
    "health_notice_cooldown_h": 24,
    # --- envio de correos ---
    "email_method": "smtp",                # smtp | gmail
    # --- rotacion de credenciales SMTP ---
    "smtp_rotation_days": 30,
    "smtp_warn_days_before": [7, 3, 1],
    "smtp_verify_on_daily_run": True,
    # --- retencion ---
    "data_retention_days": 400,
    "log_retention_days": 30,
    # --- personalización ---
    "empresa_nombre": "Mi Organización",  # nombre de la empresa/organización mostrado en la interfaz
    "tema_modo": "sistema",               # sistema | claro | oscuro
    "tema_paleta": "viva",                # viva | corporativa | oscura | pastel
    # --- GUI ---
    "webui_host": "127.0.0.1",
    "webui_port": 9090,
    # Detras de nginx (2026-09-08): la aplicacion escucha solo en 127.0.0.1 y nginx hace
    # la terminacion TLS en el 443. Con «webui_tras_proxy» la direccion real del cliente
    # se toma de X-Forwarded-For (UN salto, el de nginx); sin proxy esa cabecera se
    # ignora, porque cualquiera podria enviarla. «webui_https» pone la cookie de sesion
    # con «Secure» y genera enlaces https. «webui_url» es la direccion publica que
    # llevan los correos (con el nombre DNS cuando resuelva).
    "webui_https": False,
    "webui_tras_proxy": False,
    "webui_url": "",
    # Certificado TLS que sirve nginx: la plataforma vigila su caducidad (pagina de
    # Credenciales, /salud.json y correo de administracion con esta antelacion en dias).
    "tls_certificado_ruta": "/etc/ssl/inteligencia-amenazas/servidor.crt",
    "tls_aviso_dias": 30,
    # --- v13 (2026-09-10): excepciones con vencimiento ---
    "excepciones_aviso_dias": 15,   # antelacion del aviso de aceptaciones de riesgo por vencer
    # --- v15 (2026-09-10): excepciones permanentes (sin fecha de vencimiento) ---
    # Una permanente no caduca, asi que en su lugar se REVISA: pasados estos dias desde
    # el registro o desde la ultima revision confirmada, entra en el correo diario de
    # administracion hasta que alguien confirme que sigue valiendo o la revoque. Es un
    # recordatorio, no un vencimiento: la excepcion sigue vigente conteste quien conteste.
    "excepciones_revision_dias": 180,
    "webui_max_failed_logins": 5,
    "webui_lockout_minutes": 15,
    # --- sesion opaca en servidor y rotacion de credenciales (2026-09-08) ---
    # «webui_session_hours» ya no se lee: lo sustituyen estos tres. La sesion caduca a los
    # «webui_session_minutos» sin actividad (cada peticion la renueva), nunca dura mas de
    # «webui_session_maximo_horas» desde el acceso y cada «webui_session_rotacion_minutos»
    # de actividad se emite un token nuevo (el anterior deja de valer en ese instante).
    "webui_session_minutos": 30,
    "webui_session_maximo_horas": 12,
    "webui_session_rotacion_minutos": 15,
    # Contrasenas de la interfaz: caducan a los «password_max_dias» dias (0 = sin caducidad)
    # y no se puede repetir ninguna de las ultimas «password_historial».
    "password_max_dias": 30,
    "password_historial": 12,
    # --- v6 (2026-09-05) ---
    "mfa_obligatorio_admin": False,      # exigir segundo factor (TOTP) a los administradores
    "msrc_enabled": True,                # evaluar Windows con las correcciones publicadas por Microsoft
    "msrc_meses": 18,                    # boletines mensuales de Microsoft que se descargan
    "msrc_cache_hours": 24,              # horas entre descargas del boletin del mes en curso
    "alert_procesos_enabled": True,      # interruptor general de las alertas por proceso de negocio
    "remediacion_dias_resumen": 30,      # ventana del resumen de remediaciones corregidas
    # --- v7 (2026-09-06) ---
    "alert_detalle_top": 3,              # vulnerabilidades con detalle completo en el correo
    # Filas de la tabla «Prioridad de actuacion» del correo diario (2026-09-15):
    # el correo listaba las 76 alertadas del dia y el usuario pidio un top 10.
    "alert_tabla_top": 10,
    "alert_adjuntar_excel": True,        # adjuntar la hoja de calculo con una pestana por vulnerabilidad
    "alert_excel_max_activos": 500,      # activos por pestana en la hoja de calculo
    "descripcion_completar": True,       # sustituir las descripciones de relleno por la real de NVD o CVE.org
    "descripcion_repaso_limite": 25,     # amenazas ya guardadas que se repasan en cada ejecucion diaria
    "parches_buscar_diario": True,       # buscar cada dia la version que corrige cuando falta
    "parches_max_consultas": 150,        # consultas de red por ejecucion al buscar parches
}

REQUIRED_SECRETS = ("SMTP_SERVER", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD")


class ConfigError(RuntimeError):
    pass


@dataclass
class SmtpConfig:
    server: str
    port: int
    user: str
    password: str
    use_ssl: bool = True
    use_tls: bool = False
    from_addr: str = ""
    from_name: str = "Sistema de Inteligencia de Amenazas"
    reply_to: str = ""

    def __post_init__(self):
        if not self.from_addr:
            self.from_addr = self.user


@dataclass
class GmailConfig:
    """Configuracion para envio via Gmail API (OAuth2 con refresh_token)."""
    client_id: str
    client_secret: str
    refresh_token: str


@dataclass
class Config:
    smtp: SmtpConfig
    alert_to: list[str] = field(default_factory=list)
    alert_cc: list[str] = field(default_factory=list)
    report_to: list[str] = field(default_factory=list)
    report_cc: list[str] = field(default_factory=list)
    admin_to: list[str] = field(default_factory=list)
    nvd_api_key: Optional[str] = None
    gmail: Optional[GmailConfig] = None  # None si SMTP, GmailConfig si Gmail OAuth
    settings: dict[str, Any] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        if key in self.settings:
            return self.settings[key]
        if key in DEFAULT_SETTINGS:
            return DEFAULT_SETTINGS[key]
        return default


_EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")


def split_emails(raw: Optional[str]) -> list[str]:
    """'a@x.com, b@y.com;c@z.com' -> ['a@x.com','b@y.com','c@z.com'].

    Acepta coma, punto y coma y espacios. Descarta lo que no parezca un correo:
    el bug del sistema anterior era pasar la cadena entera como un solo destinatario.
    """
    if not raw:
        return []
    parts = re.split(r"[,;\s]+", raw.strip())
    out: list[str] = []
    for p in parts:
        p = p.strip().strip("<>").strip()
        if p and _EMAIL_RE.match(p) and p.lower() not in {o.lower() for o in out}:
            out.append(p)
    return out


def _as_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "si", "sí", "on"}


def read_secrets() -> dict[str, str]:
    if not CREDENTIALS_FILE.exists():
        raise ConfigError(f"No existe el archivo de credenciales: {CREDENTIALS_FILE}")
    values = {k: v for k, v in dotenv_values(CREDENTIALS_FILE).items() if v is not None}
    # No contaminar con el entorno del proceso: el archivo es la fuente de verdad.
    return values


def load(conn=None, *, db_path=None) -> Config:
    """Carga y valida la configuracion completa.

    `db_path` permite apuntar a una base de datos distinta de la de produccion
    (pruebas, migraciones). Si se pasa `conn`, se usa esa conexion y `db_path`
    se ignora.
    """
    secrets = read_secrets()

    missing = [k for k in REQUIRED_SECRETS if not secrets.get(k)]
    if missing:
        raise ConfigError(
            "Faltan credenciales obligatorias en config/credentials.env: "
            + ", ".join(missing)
        )

    try:
        port = int(secrets["SMTP_PORT"])
    except ValueError as exc:
        raise ConfigError(f"SMTP_PORT no es un numero: {secrets['SMTP_PORT']!r}") from exc

    smtp = SmtpConfig(
        server=secrets["SMTP_SERVER"].strip(),
        port=port,
        user=secrets["SMTP_USER"].strip(),
        password=secrets["SMTP_PASSWORD"],
        use_ssl=_as_bool(secrets.get("SMTP_USE_SSL"), port == 465),
        use_tls=_as_bool(secrets.get("SMTP_USE_TLS"), port in (587, 25)),
        from_addr=(secrets.get("EMAIL_FROM") or "").strip(),
        from_name=(secrets.get("EMAIL_FROM_NAME") or "Sistema de Inteligencia de Amenazas").strip(),
        reply_to=(secrets.get("EMAIL_REPLY_TO") or "").strip(),
    )

    # Destinatarios. REPORT_EMAIL_TO ahora SI se respeta (antes se ignoraba).
    alert_to = split_emails(secrets.get("ALERT_EMAIL_TO"))
    report_to = split_emails(secrets.get("REPORT_EMAIL_TO")) or alert_to
    admin_to = split_emails(secrets.get("ADMIN_EMAIL")) or alert_to

    if not alert_to:
        raise ConfigError("ALERT_EMAIL_TO no tiene ningun destinatario valido")

    own_conn = conn is None
    conn = conn or db.connect(db_path)
    try:
        stored = {}
        for row in conn.execute("SELECT key, value FROM settings"):
            try:
                import json as _json
                stored[row["key"]] = _json.loads(row["value"])
            except Exception:
                stored[row["key"]] = row["value"]
    finally:
        if own_conn:
            conn.close()

    settings = dict(DEFAULT_SETTINGS)
    settings.update(stored)

    # Gmail OAuth (opcional): si estan las tres credenciales, usar Gmail API en lugar de SMTP.
    gmail: Optional[GmailConfig] = None
    gmail_keys = ("GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET", "GMAIL_REFRESH_TOKEN")
    if all(secrets.get(k) for k in gmail_keys):
        gmail = GmailConfig(
            client_id=secrets["GMAIL_CLIENT_ID"].strip(),
            client_secret=secrets["GMAIL_CLIENT_SECRET"].strip(),
            refresh_token=secrets["GMAIL_REFRESH_TOKEN"].strip(),
        )

    return Config(
        smtp=smtp,
        alert_to=alert_to,
        alert_cc=split_emails(secrets.get("ALERT_EMAIL_CC")),
        report_to=report_to,
        report_cc=split_emails(secrets.get("REPORT_EMAIL_CC")),
        admin_to=admin_to,
        nvd_api_key=(secrets.get("NIST_NVD_API_KEY") or "").strip() or None,
        gmail=gmail,
        settings=settings,
        secrets=secrets,
    )


def seed_settings(conn) -> int:
    """Escribe en `settings` los valores por defecto que aun no existan."""
    created = 0
    for key, value in DEFAULT_SETTINGS.items():
        row = conn.execute("SELECT 1 FROM settings WHERE key=?", (key,)).fetchone()
        if row is None:
            db.set_setting(conn, key, value)
            created += 1
    return created


# --------------------------------------------------------------------------
# Escritura de secretos (la GUI rota la contrasena SMTP cada mes)
# --------------------------------------------------------------------------
_SECRET_LINE_RE_TMPL = r"^(\s*)({key})(\s*)=(.*)$"


def update_secret(key: str, value: str, *, backup: bool = True) -> None:
    """Reescribe una clave en credentials.env preservando comentarios y orden.

    Hace copia previa y escritura atomica (tmp + replace) para que un fallo a
    mitad no deje el archivo de credenciales truncado.
    """
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
        raise ValueError(f"Nombre de clave no valido: {key!r}")
    if "\n" in value or "\r" in value:
        raise ValueError("El valor no puede contener saltos de linea")

    if not CREDENTIALS_FILE.exists():
        raise ConfigError(f"No existe {CREDENTIALS_FILE}")

    original = CREDENTIALS_FILE.read_text(encoding="utf-8")

    if backup:
        bak = CREDENTIALS_FILE.with_suffix(".env.bak")
        shutil.copy2(CREDENTIALS_FILE, bak)
        try:
            bak.chmod(0o600)
        except PermissionError:
            pass

    pattern = re.compile(_SECRET_LINE_RE_TMPL.format(key=re.escape(key)), re.MULTILINE)
    replacement = rf"\g<1>{key}\g<3>={value}"

    if pattern.search(original):
        updated = pattern.sub(replacement, original, count=1)
    else:
        sep = "" if original.endswith("\n") else "\n"
        updated = f"{original}{sep}{key}={value}\n"

    tmp = CREDENTIALS_FILE.with_suffix(".env.tmp")
    tmp.write_text(updated, encoding="utf-8")
    tmp.chmod(0o600)
    os.replace(tmp, CREDENTIALS_FILE)
    CREDENTIALS_FILE.chmod(0o600)


def mask(value: Optional[str], keep: int = 2) -> str:
    """Enmascara un secreto para mostrarlo en la GUI o en logs."""
    if not value:
        return "(vacio)"
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * max(4, len(value) - keep)


def url_publica(cfg: Any, ruta: str = "") -> str:
    """Direccion publica de la plataforma con ``ruta`` anexada.

    Un solo sitio para construir los enlaces de los correos (2026-09-08, revision del
    despliegue HTTPS): antes cada modulo repetia «webui_url o http://host:puerto» y, con
    ``webui_url`` definido, dos correos perdian su ruta profunda (/credenciales/, /fuentes/).
    Con nginx delante ``webui_host`` es 127.0.0.1, asi que el respaldo por host y puerto solo
    vale sin proxy; el esquema sigue a ``webui_https``.
    """
    base = str(cfg.get("webui_url") or "").strip()
    if not base:
        esquema = "https" if cfg.get("webui_https") else "http"
        base = f"{esquema}://{cfg.get('webui_host') or '127.0.0.1'}:{cfg.get('webui_port') or 9090}"
    base = base.rstrip("/")
    ruta = str(ruta or "")
    if ruta and not ruta.startswith("/"):
        ruta = "/" + ruta
    return base + ruta
