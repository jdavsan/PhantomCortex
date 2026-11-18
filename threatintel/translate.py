"""Traduccion al espanol. Un solo motor, con terminos protegidos y cache.

El sistema anterior tenia DOS traductores incompatibles: ArgosTranslate en la
recoleccion y, encima, un diccionario de 200+ terminos con `re.IGNORECASE` que
el generador de informes aplicaba sobre el texto YA traducido. Resultados reales
en los datos de agosto de 2026:

    chromium      -> "cromo"
    Patch Tuesday -> "Patch Martes"

Aqui hay un unico pipeline:

    limpiar HTML -> proteger terminos -> traducir -> restaurar -> cachear

Los nombres de producto, siglas e identificadores nunca llegan al traductor: se
sustituyen por marcadores opacos y se reponen al final. La cache en base de datos
garantiza que un mismo texto no se traduzca dos veces, lo que importa porque
Ollama tarda unos 19 segundos por llamada en esta maquina.
"""
from __future__ import annotations

import hashlib
import html as html_mod
import re
import sqlite3
from typing import Any, Optional

from . import db
from .logging_setup import get_logger

log = get_logger("translate")

# Formato del marcador de proteccion. Se eligio empiricamente: los caracteres
# del area de uso privado de Unicode (\ue000) NO sobreviven a ArgosTranslate,
# que los descarta o los deforma (verificado el 2026-09-02: 2 de 3 marcadores
# perdidos, con "Moodle 4.3" convertido en "Moodle 0" y "Patch Tuesday"
# desaparecido). Una secuencia ASCII improbable sobrevive 3 de 3.
MARCADOR_INICIO = "ZPZ"
MARCADOR_FIN = "ZPZ"

# --------------------------------------------------------------------------
# Terminos que NUNCA se traducen
# --------------------------------------------------------------------------
# Se comprueban en orden de longitud descendente, para que "Microsoft Edge"
# gane a "Edge" y "Patch Tuesday" no se parta en dos.
TERMINOS_PROTEGIDOS: tuple[str, ...] = (
    # --- eventos y expresiones propias del sector ---
    "Patch Tuesday", "Zero Trust", "Bug Bounty", "Red Team", "Blue Team",
    "Purple Team", "Threat Intelligence", "Threat Hunting", "Bill of Materials",
    "Living off the Land", "Supply Chain", "Man-in-the-Middle",
    # --- navegadores y motores ---
    "Chromium", "Google Chrome", "Chrome", "Microsoft Edge", "EdgeHTML",
    "WebView2", "Mozilla Firefox", "Firefox", "Thunderbird", "Safari", "WebKit",
    "Brave", "Opera", "Blink", "Gecko", "V8", "ANGLE", "WebGL", "WebRTC",
    # --- sistemas operativos ---
    "Microsoft Windows", "Windows Server", "Windows", "Active Directory",
    "Linux", "Debian", "Ubuntu", "Red Hat Enterprise Linux", "Red Hat",
    "CentOS", "Rocky Linux", "AlmaLinux", "SUSE", "openSUSE", "FreeBSD",
    "OpenBSD", "NetBSD", "Android", "iOS", "iPadOS", "macOS", "ChromeOS",
    "Solaris", "AIX",
    # --- servidores y bases de datos ---
    "Apache HTTP Server", "Apache Tomcat", "Apache Struts", "Apache OFBiz",
    "Apache NetBeans", "Apache JMeter", "Apache Subversion", "Apache", "Nginx",
    "JBoss", "WildFly", "IIS", "PostgreSQL", "MySQL", "MariaDB", "MongoDB",
    "SQLite", "Microsoft SQL Server", "SQL Server", "Oracle Database", "Redis",
    "Elasticsearch", "Memcached",
    # --- red, seguridad e infraestructura ---
    "pfSense", "OPNsense", "Check Point", "Check Point VPN", "Gaia", "Sophos",
    "Fortinet", "FortiOS", "FortiGate", "Palo Alto Networks", "PAN-OS",
    "Cisco IOS", "Cisco ASA", "Cisco", "Juniper", "Wazuh", "Suricata", "Snort",
    "OpenVPN", "WireGuard", "IPsec", "Kerberos", "OpenLDAP", "LDAP", "RADIUS",
    "OpenSSH", "OpenSSL", "LibreSSL", "GnuTLS", "BIND", "Squid", "HAProxy",
    # --- virtualizacion y contenedores ---
    "Proxmox VE", "Proxmox", "VMware", "vCenter", "ESXi", "Hyper-V", "KVM",
    "QEMU", "VirtualBox", "Docker", "Kubernetes", "containerd", "Podman", "LXC",
    "Incus", "LXD",
    # --- aplicaciones de la organizacion ---
    "Moodle", "GitLab", "GitHub", "Mattermost", "Carbonio", "Zextras",
    "Zimbra", "Tuleap", "dotProject", "Chatwoot", "Live Helper Chat",
    "ManicTime", "KAWAK", "DocuSign", "Asterisk", "FreePBX", "ownCloud",
    "Nextcloud", "WordPress", "Joomla", "Drupal", "Jenkins", "Nagios", "Zabbix",
    "Grafana", "Prometheus",
    # --- escritorio y utilidades ---
    "LibreOffice", "Microsoft Office", "Microsoft 365", "Outlook", "Excel",
    "Word", "PowerPoint", "OneDrive", "SharePoint", "Teams", "Microsoft Access",
    "Microsoft Defender", "Microsoft Exchange", "Exchange Server", "Adobe Acrobat",
    "Adobe Reader", "Acrobat Reader", "Adobe", "KeePass", "KeePassXC",
    "Notepad++", "TextPad", "7-Zip", "WinRAR", "PDF24", "CrystalDiskInfo",
    "Linphone", "GNU Aspell", "VLC", "PuTTY", "FileZilla",
    # --- desarrollo ---
    "Eclipse", "IntelliJ IDEA", "Visual Studio Code", "Visual Studio",
    "NetBeans", "Angular", "React", "Vue.js", "Node.js", "npm", "PyPI",
    "Maven", "Gradle", "Spring Boot", "Spring", "Laravel", "Django", "Flask",
    "Git", "Subversion", "Jira", "Confluence",
    # --- lenguajes y plataformas ---
    "JavaScript", "TypeScript", "Python", "PHP", "Java", "Kotlin", "Swift",
    "Golang", "Rust", "Ruby", "Perl", ".NET", "ASP.NET", "PowerShell",
    # --- siglas tecnicas ---
    "RCE", "LPE", "EoP", "SSRF", "CSRF", "XSS", "XXE", "SQLi", "LFI", "RFI",
    "DoS", "DDoS", "MFA", "2FA", "SSO", "OAuth", "SAML", "JWT", "TLS", "SSL",
    "SSH", "SMB", "RDP", "DNS", "DHCP", "SMTP", "IMAP", "POP3", "HTTP", "HTTPS",
    "FTP", "SFTP", "SNMP", "NTLM", "UEFI", "BIOS", "TPM", "ASLR", "DEP",
    "TOCTOU", "UAF", "OOB", "PoC", "IoC", "TTP", "APT", "C2", "EDR", "XDR",
    "SIEM", "SOAR", "WAF", "IDS", "IPS", "VPN", "NAT", "API", "REST", "GraphQL",
    "JSON", "XML", "YAML", "CSV", "PDF", "URL", "URI", "CPE", "SBOM",
    # --- clases de vulnerabilidad: NO se traducen (revision de claridad del 2026-09-15) ---
    # El traductor las vertia palabra por palabra y el resultado no significaba nada:
    # «use-after-free» salia como «uso despues de la compra» y «hardcoded» como «codificado
    # duro». Son terminos que el sector escribe en ingles incluso en documentos en espanol.
    "use-after-free", "use after free", "double free", "heap overflow",
    "heap buffer overflow", "buffer overflow", "stack overflow",
    "integer overflow", "out-of-bounds", "out of bounds", "off-by-one",
    "null pointer dereference", "race condition", "privilege escalation",
    "hardcoded", "hard-coded", "sandbox escape", "type confusion",
    "memory corruption", "path traversal", "command injection",
    # --- marcos y catalogos ---
    "CVSS", "CVE", "CWE", "CAPEC", "KEV", "EPSS", "MITRE", "MITRE ATT&CK",
    "ATT&CK", "NIST", "CISA", "NVD", "OWASP", "FIRST", "ISO 27001", "PCI DSS",
    "GDPR", "RGPD",
)

# Patrones (no literales) que tambien se protegen. El orden importa: los mas
# largos van antes para que el corto no rompa el largo por dentro.
_PATRONES_PROTEGIDOS = (
    re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    re.compile(r"\bCWE-\d{1,4}\b", re.IGNORECASE),
    # Identificador de aviso + nombre del paquete que corrige: «DSA-6476-1
    # chromium» debe llegar intacto. Sin esto Argos traducia el paquete como
    # palabra corriente («cromo», «burbujas», «cable») y el informe perdia
    # credibilidad. Se excluyen las palabras que no son paquete (security...).
    re.compile(r"\b(?:DSA|DLA|USN|RHSA|ELSA|GHSA|ICSA)-\d{3,5}(?:[:-]\d+)?[:\s]+"
               r"(?!(?:security|update|updates|regression|new|the|vulnerabilit)\b)"
               r"[A-Za-z][A-Za-z0-9.+_-]*", re.IGNORECASE),
    re.compile(r"\b(?:DSA|DLA|USN)-\d{3,5}(?:-\d+)?\b", re.IGNORECASE),
    # Resto de identificadores de aviso: sin esto el traductor los partia en palabras
    # («SUSE-SU-2026:4032-1» salia como «SUSE-SU-2026: 4032-1 importante») y el titular
    # dejaba de ser citable (revision de claridad del 2026-09-15).
    re.compile(r"\bRHSA-\d{4}:\d+\b", re.IGNORECASE),
    re.compile(r"\bSUSE-SU-\d{4}:\d+(?:-\d+)?\b", re.IGNORECASE),
    re.compile(r"\bFreeBSD-(?:SA|EN)-[\w:.-]+", re.IGNORECASE),
    re.compile(r"\bZDI-(?:CAN-)?\d{2}-\d{3,4}\b", re.IGNORECASE),
    re.compile(r"\bLSN-\d{4}-\d+\b", re.IGNORECASE),
    re.compile(r"\bMS\d{2}-\d{3}\b", re.IGNORECASE),
    re.compile(r"\bADV\d{6}\b", re.IGNORECASE),
    re.compile(r"\bKB\d{6,7}\b", re.IGNORECASE),
    # Nombres de paquete o producto con guion o digito pegado (libdbi-perl,
    # gst-plugins-bad1.0, webkit2gtk, openssh-server): no son palabras del idioma.
    re.compile(r"\b[a-z][a-z0-9]*(?:-[a-z0-9.]+)+\b"),
    re.compile(r"\b[a-z]+\d+[a-z]+[a-z0-9]*\b"),
    # Una sola palabra entre comillas simples o dobles: un nombre, no una frase.
    re.compile(r"(?<=[\'\"«])[A-Za-z][A-Za-z0-9._+-]{1,40}(?=[\'\"»])"),
    re.compile(r"\b(?:RHSA|RHBA|SUSE-SU|SUSE-RU)-\d{4}[:-]\d{3,5}\b", re.IGNORECASE),
    re.compile(r"\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", re.IGNORECASE),
    re.compile(r"\bICSA-\d{2}-\d{3}-\d{2}\b", re.IGNORECASE),
    re.compile(r"\bCVSS:\d\.\d/[A-Z:/]+\b"),
    re.compile(r"\bcpe:2\.3:[^\s]+"),
    re.compile(r"https?://\S+"),
    re.compile(r"\b\d+\.\d+(?:\.\d+){0,3}(?:-[A-Za-z0-9.]+)?\b"),   # versiones
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
)

_LITERALES_ORDENADOS = sorted(TERMINOS_PROTEGIDOS, key=len, reverse=True)
_REGEX_LITERALES = re.compile(
    r"(?<![\w])(" + "|".join(re.escape(t) for t in _LITERALES_ORDENADOS) + r")(?![\w])",
    re.IGNORECASE)


# --------------------------------------------------------------------------
# Proteccion y restauracion
# --------------------------------------------------------------------------
def proteger(texto: str) -> tuple[str, dict[str, str]]:
    """Sustituye terminos protegidos por marcadores opacos.

    Devuelve (texto_con_marcadores, mapa). El traductor puede reordenar los
    marcadores dentro de la frase, pero no debe alterarlos.
    """
    if not texto:
        return texto, {}

    mapa: dict[str, str] = {}
    contador = 0

    def _sustituir(match: re.Match) -> str:
        nonlocal contador
        original = match.group(0)
        marcador = f"{MARCADOR_INICIO}{contador}{MARCADOR_FIN}"
        mapa[marcador] = original
        contador += 1
        return marcador

    resultado = texto
    # Primero los patrones (CVE, versiones, URL): son mas especificos
    for patron in _PATRONES_PROTEGIDOS:
        resultado = patron.sub(_sustituir, resultado)
    # Despues los literales, de mas largo a mas corto
    resultado = _REGEX_LITERALES.sub(_sustituir, resultado)
    return resultado, mapa


def restaurar(texto: str, mapa: dict[str, str]) -> str:
    """Repone los terminos protegidos. Tolera marcadores deformados.

    La limpieza de marcadores huerfanos se ejecuta SIEMPRE, incluso con el mapa
    vacio: si por cualquier motivo se pierde la correspondencia, es preferible
    quedarse sin el termino que publicar "ZPZ0ZPZ" en un correo o un informe.
    """
    if not texto:
        return texto

    resultado = texto
    for marcador, original in (mapa or {}).items():
        if marcador in resultado:
            resultado = resultado.replace(marcador, original)
            continue
        # El traductor puede introducir espacios o cambiar la caja
        numero = marcador[len(MARCADOR_INICIO):-len(MARCADOR_FIN)]
        laxo = re.compile(
            re.escape(MARCADOR_INICIO) + r"\s*" + re.escape(numero) + r"\s*"
            + re.escape(MARCADOR_FIN), re.IGNORECASE)
        resultado = laxo.sub(lambda _m, o=original: o, resultado)

    # Limpiar marcadores huerfanos que no se pudieron mapear
    resultado = re.sub(
        re.escape(MARCADOR_INICIO) + r"\s*\d*\s*" + re.escape(MARCADOR_FIN),
        "", resultado, flags=re.IGNORECASE)
    return re.sub(r"\s{2,}", " ", resultado).strip()


def limpiar_html(texto: Optional[str]) -> str:
    """Quita etiquetas y entidades HTML, y normaliza espacios."""
    if not texto:
        return ""
    limpio = html_mod.unescape(str(texto))
    limpio = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", limpio,
                    flags=re.IGNORECASE | re.DOTALL)
    limpio = re.sub(r"<br\s*/?>|</p>|</div>|</li>", " ", limpio, flags=re.IGNORECASE)
    limpio = re.sub(r"<[^>]+>", " ", limpio)
    limpio = limpio.replace("\xa0", " ")
    limpio = re.sub(r"[\r\n\t]+", " ", limpio)
    return re.sub(r"\s{2,}", " ", limpio).strip()


# --------------------------------------------------------------------------
# Correccion de errores conocidos de ArgosTranslate
# --------------------------------------------------------------------------
# Lista CORTA y dirigida, aplicada una sola vez sobre la salida de Argos. No es
# el diccionario de 200+ terminos del sistema anterior, que se aplicaba encima de
# texto ya traducido y destrozaba nombres de producto: aqui solo se corrigen
# expresiones que Argos traduce mal de forma reproducible, verificadas en los
# datos reales de agosto de 2026.
_CORRECCIONES_ARGOS: tuple[tuple[re.Pattern, str], ...] = tuple(
    (re.compile(patron, re.IGNORECASE), reemplazo) for patron, reemplazo in (
        # buffer overflow
        (r"\bflujo de amortiguaci[oó]n\b", "desbordamiento de búfer"),
        (r"\breflujo de amortiguaci[oó]n\b", "desbordamiento de búfer"),
        (r"\bdesbordamiento del b[uú]fer\b", "desbordamiento de búfer"),
        (r"\bsobrecarga de(?:l)? b[uú]fer\b", "desbordamiento de búfer"),
        # man-in-the-middle
        (r"\bataques? (?:masculinos?|humanos?) en (?:el )?medio\b",
         "ataque de intermediario (man-in-the-middle)"),
        (r"\bhombre en el medio\b", "intermediario"),
        # flaw / fallo
        (r"\befecto cr[ií]tico\b", "fallo crítico"),
        (r"\bdefecto cr[ií]tico\b", "fallo crítico"),
        # authentication
        (r"\bno secuestrad[oa]\b", "no autenticado"),
        (r"\bsin certificaci[oó]n\b(?= remota)", "sin autenticación"),
        # race condition
        (r"\bpunto de uso del tiempo de cheque\b", "condición de carrera (TOCTOU)"),
        (r"\bcondici[oó]n de la carrera\b", "condición de carrera"),
        # denial of service / execution
        (r"\b(?:de)?negaci[oó]n del servicio\b", "denegación de servicio"),
        (r"\bnegaci[oó]n de servicio\b", "denegación de servicio"),
        (r"\bejecuci[oó]n del c[oó]digo\b", "ejecución de código"),
        (r"\binyecci[oó]n del comando\b", "inyección de comandos"),
        (r"\binyecci[oó]n de la SQL\b", "inyección SQL"),
        (r"\bscripting de sitio cruzado\b", "cross-site scripting (XSS)"),
        (r"\bfalsificaci[oó]n de petici[oó]n en sitios cruzados\b",
         "falsificación de peticiones entre sitios (CSRF)"),
        # privilege
        (r"\bescalada del privilegio\b", "escalada de privilegios"),
        (r"\belevaci[oó]n del privilegio\b", "elevación de privilegios"),
        # use after free
        (r"\b(?:uso|utilizar|usar) despu[eé]s de(?:l)? (?:libre|gratis|liberaci[oó]n)\b",
         "uso después de liberar (use-after-free)"),
        # remotely exploitable
        (r"\bexplotable remotamente\b", "explotable de forma remota"),
        # concordancias que Argos rompe
        (r"\bun una\b", "una"),
        (r"\bel la\b", "la"),
        (r"\blos las\b", "las"),
        (r"\bde el\b", "del"),
        (r"\ba el\b", "al"),
    )
)


def corregir_argos(texto: str) -> str:
    """Aplica las correcciones conocidas sobre la salida de ArgosTranslate."""
    if not texto:
        return texto
    salida = texto
    for patron, reemplazo in _CORRECCIONES_ARGOS:
        salida = patron.sub(reemplazo, salida)
    return re.sub(r"\s{2,}", " ", salida).strip()


# --------------------------------------------------------------------------
# Deteccion de idioma
# --------------------------------------------------------------------------
# La heuristica anterior contaba 3 coincidencias en una lista de 9 palabras, asi
# que cualquier texto ingles con 'sistema' o 'virus' se consideraba espanol.
_STOP_ES = frozenset("""
el la los las un una unos unas de del al a en con por para sin sobre entre
que se su sus lo le les es son fue fueron ser sido siendo esta este estos
estas ese esa aquel como cuando donde porque si no ni pero mas muy tambien
puede pueden podria deberia debe han haber hay desde hasta durante mediante
permite permiten afecta afectan vulnerabilidad atacante usuario version
actualizacion seguridad codigo sistema aplicacion servidor
""".split())

_STOP_EN = frozenset("""
the a an of to in on at by for with from and or but if then than that this
these those it its is are was were be been being has have had do does did
can could should would may might will shall must not no nor as such which
who whom whose when where why how allows allow affected affects attacker
user version update security code system application server remote
""".split())


def parece_espanol(texto: Optional[str]) -> bool:
    """True si el texto ya esta en espanol, por proporcion de palabras funcion."""
    if not texto:
        return False
    palabras = re.findall(r"[a-zA-ZáéíóúüñÁÉÍÓÚÜÑ]{2,}", texto.lower())
    if len(palabras) < 4:
        return False

    es = sum(1 for p in palabras if p in _STOP_ES)
    en = sum(1 for p in palabras if p in _STOP_EN)

    # Acentos y la letra ñ son senal fuerte de espanol
    tildes = len(re.findall(r"[áéíóúüñ¿¡]", texto.lower()))
    if tildes >= 2 and es >= en:
        return True
    if es + en == 0:
        return False
    return es > en * 1.3


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------
def _hash(texto: str, motor: str) -> str:
    return hashlib.sha256(f"{motor}\x00{texto}".encode("utf-8")).hexdigest()


def cache_get(conn: Optional[sqlite3.Connection], texto: str,
              motor: str) -> Optional[str]:
    if conn is None or not texto:
        return None
    try:
        fila = conn.execute(
            "SELECT target_txt FROM translation_cache WHERE hash=?",
            (_hash(texto, motor),)).fetchone()
    except sqlite3.Error as exc:
        log.debug("cache de traduccion no disponible", extra={"error": str(exc)})
        return None
    return fila["target_txt"] if fila else None


def cache_put(conn: Optional[sqlite3.Connection], texto: str,
              traduccion: str, motor: str) -> None:
    if conn is None or not texto or not traduccion:
        return
    try:
        conn.execute(
            """INSERT INTO translation_cache(hash, source_txt, target_txt, engine,
                                             created_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(hash) DO UPDATE SET target_txt=excluded.target_txt""",
            (_hash(texto, motor), texto[:4000], traduccion, motor, db.utcnow()))
    except sqlite3.Error as exc:
        log.debug("no se pudo escribir la cache de traduccion",
                  extra={"error": str(exc)})


# --------------------------------------------------------------------------
# Motores
# --------------------------------------------------------------------------
_ARGOS_DISPONIBLE: Optional[bool] = None


def argos_disponible() -> bool:
    global _ARGOS_DISPONIBLE
    if _ARGOS_DISPONIBLE is None:
        try:
            import argostranslate.package
            import argostranslate.translate  # noqa: F401
            paquetes = argostranslate.package.get_installed_packages()
            _ARGOS_DISPONIBLE = any(
                p.from_code == "en" and p.to_code == "es" for p in paquetes)
            if not _ARGOS_DISPONIBLE:
                log.warning("ArgosTranslate esta instalado pero falta el modelo en->es")
        except ImportError as exc:
            _ARGOS_DISPONIBLE = False
            log.warning("ArgosTranslate no disponible", extra={"error": str(exc)})
    return bool(_ARGOS_DISPONIBLE)


def traducir_argos(texto: str, *, max_chars: int = 2500) -> tuple[str, str]:
    """Traduce con ArgosTranslate. Devuelve (texto, motor_usado)."""
    if not texto or not argos_disponible():
        return texto, "none"
    try:
        import argostranslate.translate
        recorte = texto[:max_chars]
        salida = argostranslate.translate.translate(recorte, "en", "es")
        if not salida or not salida.strip():
            return texto, "none"
        if len(texto) > max_chars:
            salida = salida.rstrip() + "…"
        return corregir_argos(salida), "argos"
    except Exception as exc:  # noqa: BLE001 - el traductor no debe romper la recoleccion
        log.warning("fallo de ArgosTranslate", extra={"error": str(exc)[:160]})
        return texto, "none"


# Ollama a veces envuelve la respuesta en preambulos o comillas
_PREAMBULOS = re.compile(
    r"^\s*(?:aqu[ií]\s+(?:te\s+dejo|est[aá])\s+la\s+traducci[oó]n\s*:?|"
    r"la\s+traducci[oó]n\s+(?:es|ser[ií]a)\s*:?|"
    r"traducci[oó]n\s*:?|traducido\s*:?|"
    r"here\s+is\s+the\s+translation\s*:?|translation\s*:?)\s*",
    re.IGNORECASE)


def _limpiar_respuesta_ollama(texto: str) -> str:
    salida = (texto or "").strip()
    salida = _PREAMBULOS.sub("", salida).strip()
    # Quitar comillas envolventes si abarcan todo el texto
    for apertura, cierre in (('"', '"'), ("«", "»"), ("'", "'"),
                             ("\u201c", "\u201d")):
        if salida.startswith(apertura) and salida.endswith(cierre) and len(salida) > 2:
            interior = salida[1:-1]
            if apertura not in interior and cierre not in interior:
                salida = interior.strip()
    # Ollama a veces anade una nota final entre parentesis o tras un salto
    salida = re.split(r"\n\s*(?:nota|note|explicaci[oó]n)\s*:", salida,
                      flags=re.IGNORECASE)[0]
    return salida.strip().rstrip(".").strip() + ("." if salida.endswith(".") else "")


def ollama_disponible(cfg) -> tuple[bool, Optional[str]]:
    """Comprueba si Ollama responde y si el modelo configurado esta cargado."""
    import requests
    url = str(cfg.get("ollama_url", "http://localhost:11434")).rstrip("/")
    modelo = str(cfg.get("ollama_model", "llama3.1:8b"))
    try:
        respuesta = requests.get(f"{url}/api/tags", timeout=8)
        respuesta.raise_for_status()
        modelos = [m.get("name") for m in respuesta.json().get("models", [])]
        if modelo in modelos:
            return True, modelo
        if modelos:
            return False, (f"el modelo '{modelo}' no esta descargado; "
                           f"disponibles: {', '.join(map(str, modelos[:4]))}")
        return False, "Ollama responde pero no tiene ningun modelo"
    except Exception as exc:  # noqa: BLE001
        return False, f"Ollama no responde: {type(exc).__name__}"


def traducir_ollama(texto: str, *, cfg,
                    timeout: Optional[int] = None) -> tuple[Optional[str], Optional[str]]:
    """Traduce con Ollama. Devuelve (traduccion, error)."""
    if not texto:
        return texto, None

    import requests
    url = str(cfg.get("ollama_url", "http://localhost:11434")).rstrip("/")
    modelo = str(cfg.get("ollama_model", "llama3.1:8b"))
    espera = int(timeout or cfg.get("ollama_timeout_s", 120))

    prompt = (
        "Traduce al espanol de Espana el siguiente texto tecnico de "
        "ciberseguridad.\n"
        "Reglas estrictas:\n"
        "- Responde UNICAMENTE con la traduccion, sin preambulo ni comillas.\n"
        "- NO traduzcas nombres de producto, marcas ni versiones: Chromium, "
        "Microsoft Edge, Patch Tuesday, Apache HTTP Server, Moodle, GitLab, "
        "pfSense y similares se escriben igual.\n"
        "- NO traduzcas siglas tecnicas (RCE, XSS, CSRF, SSRF, CVSS, KEV, EPSS, "
        "TLS, SMB, RDP) ni identificadores (CVE-2026-1234, DSA-6408-1).\n"
        "- NO expandas ni interpretes siglas que no conozcas: dejalas tal cual.\n"
        "- NO traduzcas los nombres de clase de vulnerabilidad: use-after-free, "
        "double free, heap overflow, buffer overflow, out-of-bounds, race condition, "
        "privilege escalation, hardcoded, type confusion y similares se escriben igual "
        "en ingles.\n"
        "- «fix» en un aviso de nucleo significa «corregir», NUNCA «fijar».\n"
        "- No anadas informacion que no este en el texto original.\n"
        "- Manten el registro formal propio de un informe de seguridad.\n\n"
        f"Texto:\n{texto}"
    )

    try:
        respuesta = requests.post(
            f"{url}/api/generate",
            json={"model": modelo, "prompt": prompt, "stream": False,
                  # Mantener el modelo en memoria entre llamadas: el arranque en
                  # frio cuesta unos 60 s en esta maquina (CPU, sin GPU).
                  "keep_alive": "30m",
                  "options": {"temperature": 0.1, "top_p": 0.9,
                              "num_predict": min(1024, len(texto) + 240)}},
            timeout=espera)
        respuesta.raise_for_status()
        crudo = (respuesta.json() or {}).get("response") or ""
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {str(exc)[:120]}"

    limpio = _limpiar_respuesta_ollama(crudo)
    if not limpio or len(limpio) < max(8, len(texto) // 12):
        return None, "respuesta vacia o demasiado corta"
    return limpio, None


# --------------------------------------------------------------------------
# Contador de llamadas por ejecucion
# --------------------------------------------------------------------------
class ContadorLlamadas:
    """Limita las llamadas a Ollama de una ejecucion.

    A ~19 s por llamada en esta maquina, sin tope una recoleccion con 300
    amenazas altas tardaria hora y media y podria solaparse con la siguiente.
    """

    def __init__(self, maximo: int) -> None:
        self.maximo = max(0, int(maximo))
        self.usadas = 0
        self.rechazadas = 0

    def permitir(self) -> bool:
        if self.usadas < self.maximo:
            self.usadas += 1
            return True
        self.rechazadas += 1
        return False

    @property
    def agotado(self) -> bool:
        return self.usadas >= self.maximo

    def resumen(self) -> dict[str, int]:
        return {"usadas": self.usadas, "maximo": self.maximo,
                "rechazadas": self.rechazadas}


# --------------------------------------------------------------------------
# Punto de entrada
# --------------------------------------------------------------------------
# Titulos de aviso con forma fija: se traducen por plantilla, sin motor. Es
# exacto (el nombre del paquete queda intacto y el orden no se altera) y evita
# resultados como «vulnerabilidades USN-8724-1: rabbitmq-c».
_PLANTILLAS_AVISO = (
    (re.compile(r"^\s*((?:DSA|DLA)-\d{3,5}(?:-\d+)?)\s+(\S+)\s*-\s*security update\s*$", re.I),
     lambda m: f"{m.group(1).upper()} {m.group(2)} - actualización de seguridad"),
    (re.compile(r"^\s*((?:DSA|DLA)-\d{3,5}(?:-\d+)?)\s+(\S+)\s*-\s*(?:regression|update)\s*$", re.I),
     lambda m: f"{m.group(1).upper()} {m.group(2)} - actualización por regresión"),
    (re.compile(r"^\s*(USN-\d{3,5}(?:-\d+)?):\s*(.+?)\s+vulnerability\s*$", re.I),
     lambda m: f"{m.group(1).upper()}: vulnerabilidad en {m.group(2)}"),
    (re.compile(r"^\s*(USN-\d{3,5}(?:-\d+)?):\s*(.+?)\s+vulnerabilities\s*$", re.I),
     lambda m: f"{m.group(1).upper()}: vulnerabilidades en {m.group(2)}"),
    (re.compile(r"^\s*(USN-\d{3,5}(?:-\d+)?):\s*(.+?)\s+regression\s*$", re.I),
     lambda m: f"{m.group(1).upper()}: regresión en {m.group(2)}"),
    (re.compile(r"^\s*(USN-\d{3,5}(?:-\d+)?):\s*(.+?)\s+update\s*$", re.I),
     lambda m: f"{m.group(1).upper()}: actualización de {m.group(2)}"),
)


def traducir_aviso_plantilla(texto: Optional[str]) -> Optional[str]:
    """Traduccion exacta de un titulo de aviso con forma fija, o None."""
    if not texto:
        return None
    for patron, plantilla in _PLANTILLAS_AVISO:
        m = patron.match(texto)
        if m:
            return plantilla(m)
    return None


#: Palabras inglesas frecuentes en los titulares de vulnerabilidad. Si mas de un tercio de
#: las palabras del resultado siguen siendo de esta lista, la traduccion no sirvio: lo que
#: sale es un hibrido del tipo «Subsistema de uso despues de la libre escal...», que parece
#: espanol y no lo es, y es lo PRIMERO que se lee en el correo diario (revision de claridad
#: del 2026-09-15). Mas vale el titulo en ingles, marcado como tal, que un espanol falso.
_PALABRAS_INGLESAS = frozenset("""
the of and in on for with to from by out over under into
is are was were be been being has have had can could may might will would
vulnerability vulnerabilities disclosure information execution privilege privileges
escalation overflow bounds use after free code remote local denial service
reporting handling subsystem kernel driver memory corruption injection bypass
elevation improper insufficient unauthenticated authenticated arbitrary
buffer heap stack write read pointer null race condition request query directory
security update advisory patch flaw issue attacker allows could result
""".split())

#: Por encima de esta proporcion el resultado NO se considera una traduccion. Medido con
#: los titulares reales del correo del 15 de septiembre de 2026: el ingles integro da 0,70;
#: el hibrido «Windows Error reportando Elevacion de Privilege Vulnerability» da 0,33; un
#: titular bien traducido da 0,00. Con 0,30 se cortan los dos primeros y no el tercero.
UMBRAL_SIN_TRADUCIR = 0.30

#: Traducciones que demuestran por si solas que el motor no entendio el texto: son terminos
#: tecnicos vertidos palabra por palabra. Una proporcion de palabras inglesas no las detecta,
#: porque el resultado esta integramente en espanol; simplemente no significa nada. La lista
#: sale de los titulares reales revisados el 2026-09-15 («use-after-free» -> «uso despues de
#: la compra», «hardcoded» -> «codificado duro»).
_TRADUCCIONES_ROTAS = (
    re.compile(r"uso despu[eé]s de la (?:compra|libre|liberaci[oó]n gratuita)", re.IGNORECASE),
    re.compile(r"codificado duro|codificaci[oó]n dura", re.IGNORECASE),
    re.compile(r"fuera de los l[ií]mites escriba", re.IGNORECASE),
    re.compile(r"\bdecree\b|\bdecreto por\b", re.IGNORECASE),
    re.compile(r"desbordamiento de mont[oó]n de la pila", re.IGNORECASE),
    re.compile(r"condici[oó]n de la raza", re.IGNORECASE),
    re.compile(r"\blibre escalada\b|\bde la libre\b", re.IGNORECASE),
)

#: Lo que se anade al titulo cuando se devuelve el original en ingles.
MARCA_SIN_TRADUCIR = " (sin traducir)"


def _proporcion_en_ingles(texto: str) -> float:
    """Que parte de las palabras del texto siguen siendo inglesas (0 a 1)."""
    palabras = [p.lower() for p in re.findall(r"[A-Za-zÁÉÍÓÚÑáéíóúñ]{2,}", texto or "")]
    if not palabras:
        return 0.0
    return sum(1 for p in palabras if p in _PALABRAS_INGLESAS) / len(palabras)


def _traduccion_rota(texto: str) -> bool:
    """True si el texto contiene una traduccion literal de un termino tecnico."""
    return any(p.search(texto or "") for p in _TRADUCCIONES_ROTAS)


def _hay_ingles_seguido(texto: str) -> bool:
    """True si quedan DOS palabras inglesas seguidas: «Privilege Vulnerability».

    La proporcion sola no basta con los titulares a medio traducir: «Windows Error
    reportando Elevacion de Privilege Vulnerability» tiene solo dos palabras inglesas de
    siete (0,29) y aun asi es ilegible. Dos seguidas son siempre un trozo sin traducir,
    mientras que una suelta suele ser un nombre de producto legitimo («kernel de Linux»).
    """
    palabras = [p.lower() for p in re.findall(r"[A-Za-zÁÉÍÓÚÑáéíóúñ]{2,}", texto or "")]
    return any(a in _PALABRAS_INGLESAS and b in _PALABRAS_INGLESAS
               for a, b in zip(palabras, palabras[1:]))


def _sirve_como_traduccion(texto: str) -> bool:
    """False cuando el resultado no se puede publicar como espanol.

    Tres motivos, y basta uno: que conserve demasiado ingles en conjunto, que queden dos
    palabras inglesas seguidas, o que contenga una traduccion literal que deja la frase sin
    sentido. El ultimo caso no lo detecta ninguna proporcion, porque todas las palabras son
    espanolas; simplemente no significan nada.
    """
    palabras = [p.lower() for p in re.findall(r"[A-Za-zÁÉÍÓÚÑáéíóúñ]{2,}", texto or "")]
    # Una palabra inglesa SUELTA suele ser un nombre de producto legitimo, pero si es la
    # ULTIMA del titular es casi siempre una cola sin traducir: «…Elevacion de Vulnerabilidad
    # Privilege». Un titular bien traducido no termina en una de estas palabras.
    cola_inglesa = bool(palabras) and palabras[-1] in _PALABRAS_INGLESAS
    return (_proporcion_en_ingles(texto) <= UMBRAL_SIN_TRADUCIR
            and not _hay_ingles_seguido(texto)
            and not cola_inglesa
            and not _traduccion_rota(texto))


def traducir(texto: Optional[str], *, cfg,
             conn: Optional[sqlite3.Connection] = None,
             severidad: Optional[str] = None,
             contador: Optional[ContadorLlamadas] = None,
             permitir_ollama: bool = True) -> tuple[str, str]:
    """Traduce un texto al espanol. Devuelve (traduccion, motor).

    Estrategia segun el ajuste `translate_engine`:
      none    -> devuelve el original
      argos   -> solo ArgosTranslate
      ollama  -> Ollama, con respaldo en Argos si falla
      hybrid  -> Ollama solo si la severidad esta en `ollama_severities` y queda
                 cuota; el resto con Argos
    """
    limpio = limpiar_html(texto)
    if not limpio:
        return "", "none"

    motor_cfg = str(cfg.get("translate_engine", "hybrid")).lower()
    if motor_cfg == "none":
        return limpio, "none"

    if parece_espanol(limpio):
        return limpio, "none"

    por_plantilla = traducir_aviso_plantilla(limpio)
    if por_plantilla:
        return por_plantilla, "plantilla"

    usar_ollama = False
    if permitir_ollama and motor_cfg in ("ollama", "hybrid"):
        if motor_cfg == "ollama":
            usar_ollama = True
        else:
            severidades = cfg.get("ollama_severities", ["Critical", "High"]) or []
            if severidad in severidades:
                usar_ollama = contador is None or contador.permitir()

    # --- cache ---
    for motor in (("ollama", "argos") if usar_ollama else ("argos",)):
        guardada = cache_get(conn, limpio, motor)
        if guardada:
            return guardada, motor

    # Estrategias distintas por motor, a proposito:
    #
    #   Argos es un traductor estadistico y NO entiende instrucciones, asi que
    #   los terminos que no deben traducirse se sustituyen por marcadores.
    #
    #   Ollama SI entiende instrucciones, y en cambio los marcadores le
    #   perjudican: verificado el 2026-09-02, interpreto el marcador "ZPZ0ZPZ"
    #   como una sigla y se invento "zona de procesamiento de datos (ZPZ)".
    #   Por eso recibe el texto original con instrucciones explicitas.
    if usar_ollama:
        salida, error = traducir_ollama(limpio, cfg=cfg)
        if salida and MARCADOR_INICIO not in salida:
            if not _sirve_como_traduccion(salida):
                log.warning("la traduccion conserva demasiado ingles: se marca sin traducir",
                            extra={"motor": "ollama",
                                   "proporcion": round(_proporcion_en_ingles(salida), 2)})
                return limpio + MARCA_SIN_TRADUCIR, "sin_traducir"
            cache_put(conn, limpio, salida, "ollama")
            return salida, "ollama"
        if salida:
            log.warning("la respuesta de Ollama contenia marcadores, se descarta",
                        extra={"severidad": severidad})
        else:
            log.warning("Ollama fallo, se usa ArgosTranslate",
                        extra={"error": error, "severidad": severidad})

    protegido, mapa = proteger(limpio)
    salida, motor = traducir_argos(protegido)
    final = restaurar(salida, mapa)
    # El resultado se publica SOLO si de verdad esta en espanol. Si no, se devuelve el
    # original marcado y NO se cachea, para volver a intentarlo cuando el motor cuidado
    # este disponible (revision de claridad del 2026-09-15).
    if motor != "none" and not _sirve_como_traduccion(final):
        log.warning("la traduccion conserva demasiado ingles: se marca sin traducir",
                    extra={"motor": motor, "proporcion": round(_proporcion_en_ingles(final), 2)})
        return limpio + MARCA_SIN_TRADUCIR, "sin_traducir"
    if motor != "none":
        cache_put(conn, limpio, final, motor)
    return final, motor


# --------------------------------------------------------------------------
# Impacto y remediacion
# --------------------------------------------------------------------------
_PLAZOS = {
    "Critical": ("0-24 horas", "inmediata"),
    "High": ("1-7 dias", "prioritaria"),
    "Medium": ("7-30 dias", "programada"),
    "Low": ("proxima ventana de mantenimiento", "ordinaria"),
}


def _describir_tecnologias(tecnologias: list[dict]) -> str:
    if not tecnologias:
        return "los sistemas afectados"
    partes = []
    for t in tecnologias[:4]:
        nombre = t.get("name") or "sistema"
        version = t.get("version_installed")
        sistemas = t.get("systems_count") or 0
        pieza = nombre
        if version:
            pieza += f" {version}"
        if sistemas:
            pieza += f" ({sistemas} sistema{'s' if sistemas != 1 else ''})"
        partes.append(pieza)
    texto = ", ".join(partes)
    if len(tecnologias) > 4:
        texto += f" y {len(tecnologias) - 4} más"
    return texto


def generar_impacto(vista: dict, *, cfg,
                    conn: Optional[sqlite3.Connection] = None) -> str:
    """Redacta el impacto en espanol.

    El sistema anterior repetia el mismo parrafo para todas las criticas. Aqui el
    texto cita las tecnologias y versiones concretas, el veredicto de version y
    la explotacion confirmada.
    """
    severidad = vista.get("severity") or "Medium"
    tecnologias = vista.get("technologies") or []
    afectadas = [t for t in tecnologias if t.get("version_verdict") == "affected"]
    no_afectadas = [t for t in tecnologias
                    if t.get("version_verdict") == "not_affected"]
    expuestas = [t for t in tecnologias if t.get("exposure") == "internet"]

    frases: list[str] = []

    if severidad == "Critical":
        frases.append(
            "Esta vulnerabilidad permite comprometer los sistemas afectados con "
            "un impacto grave sobre la confidencialidad, la integridad o la "
            "disponibilidad de la información.")
    elif severidad == "High":
        frases.append(
            "Esta vulnerabilidad puede aprovecharse para obtener acceso no "
            "autorizado o elevar privilegios en los sistemas afectados.")
    elif severidad == "Medium":
        frases.append(
            "Esta vulnerabilidad presenta un riesgo moderado y requiere "
            "atención, aunque su explotación exige condiciones concretas.")
    else:
        frases.append(
            "Esta vulnerabilidad presenta un riesgo bajo en el contexto actual "
            "de la organización.")

    if vista.get("in_kev"):
        plazo = vista.get("kev_due_date")
        frase = ("Se ha confirmado su explotación activa: figura en el catálogo "
                 "KEV de CISA")
        if plazo:
            frase += f", con fecha límite de corrección {plazo}"
        frases.append(frase + ".")

    epss = vista.get("epss_score")
    if epss is not None and epss >= 0.1:
        frases.append(
            f"La probabilidad estimada de explotación en los próximos 30 días es "
            f"del {epss * 100:.1f} % (EPSS).")

    if afectadas:
        frases.append(
            f"Afecta de forma confirmada a {_describir_tecnologias(afectadas)}, "
            f"cuya versión instalada es vulnerable.")
    elif tecnologias:
        frases.append(
            f"Se relaciona con {_describir_tecnologias(tecnologias)}. No se ha "
            f"podido determinar si la versión instalada es vulnerable, por lo que "
            f"debe verificarse.")
    else:
        frases.append(
            "No se ha establecido correlación con el inventario tecnológico "
            "registrado.")

    if expuestas:
        frases.append(
            f"Parte de los sistemas implicados está expuesta a Internet "
            f"({', '.join(t['name'] for t in expuestas[:3])}), lo que eleva la "
            f"probabilidad de explotación.")

    if no_afectadas and not afectadas:
        frases.append(
            f"La versión instalada de {', '.join(t['name'] for t in no_afectadas[:3])} "
            f"no está dentro del rango vulnerable según el aviso.")

    return " ".join(frases)


def generar_remediacion(vista: dict, *, cfg,
                        conn: Optional[sqlite3.Connection] = None) -> str:
    """Redacta la remediacion recomendada con plazo segun severidad."""
    severidad = vista.get("severity") or "Medium"
    plazo, urgencia = _PLAZOS.get(severidad, _PLAZOS["Medium"])
    tecnologias = vista.get("technologies") or []
    afectadas = [t for t in tecnologias if t.get("version_verdict") == "affected"]
    responsables = sorted({t.get("owner") for t in tecnologias if t.get("owner")})

    lineas = [f"Actuación {urgencia} ({plazo}):"]
    paso = 1

    objetivo = _describir_tecnologias(afectadas or tecnologias)
    lineas.append(f"{paso}. Aplicar la actualización del fabricante en {objetivo}.")
    paso += 1

    if vista.get("in_kev"):
        lineas.append(
            f"{paso}. Prioridad máxima: existe explotación confirmada. Si no hay "
            f"parche disponible, aislar o restringir el acceso al servicio.")
        paso += 1

    for t in tecnologias:
        if t.get("version_installed") and t.get("version_verdict") == "affected":
            lineas.append(
                f"{paso}. Verificar que {t['name']} pasa de la versión "
                f"{t['version_installed']} a una versión corregida.")
            paso += 1
            break

    if severidad in ("Critical", "High"):
        lineas.append(f"{paso}. Revisar registros en busca de indicios de "
                      f"explotación previa a la corrección.")
        paso += 1
        lineas.append(f"{paso}. Si no existe parche, aplicar controles "
                      f"compensatorios: segmentación, reglas en el WAF o "
                      f"restricción de acceso por origen.")
        paso += 1
    else:
        lineas.append(f"{paso}. Incluir la corrección en la próxima ventana de "
                      f"mantenimiento planificada.")
        paso += 1

    lineas.append(f"{paso}. Documentar la actuación y la fecha de aplicación.")

    if responsables:
        lineas.append("")
        lineas.append(f"Responsable(s) del inventario: {', '.join(responsables)}.")

    referencias = [s.get("url") for s in (vista.get("sources") or [])
                   if s.get("url")][:3]
    if referencias:
        lineas.append("")
        lineas.append("Referencias:")
        lineas.extend(f"  - {u}" for u in referencias)

    return "\n".join(lineas)


def resumen_ejecutivo(datos: dict, *, cfg,
                      conn: Optional[sqlite3.Connection] = None) -> tuple[str, str]:
    """Redacta el parrafo del resumen ejecutivo del informe mensual.

    Con Ollama disponible pide la redaccion al modelo; si no, compone un texto
    deterministico. Devuelve (texto, motor).
    """
    total = datos.get("total", 0)
    criticas = datos.get("criticas", 0)
    altas = datos.get("altas", 0)
    kev = datos.get("en_kev", 0)
    con_cvss = datos.get("sev_nvd", 0)
    periodo = datos.get("periodo", "")
    top = datos.get("top_tecnologias") or []
    afectadas = datos.get("confirmadas_afectadas", 0)

    tecnologias_txt = ", ".join(t.get("name", "") for t in top[:3]) or "—"

    base = (
        f"Durante {periodo} el sistema de inteligencia de amenazas registró "
        f"{total} vulnerabilidades relacionadas con el inventario tecnológico de "
        f"la organización, de las cuales {criticas} son de severidad crítica y "
        f"{altas} de severidad alta. "
    )
    if kev:
        base += (f"{kev} de ellas cuentan con explotación activa confirmada en el "
                 f"catálogo KEV de CISA, lo que las convierte en prioridad "
                 f"absoluta. ")
    else:
        base += ("Ninguna presenta explotación activa confirmada en el catálogo "
                 "KEV de CISA. ")

    if afectadas:
        base += (f"En {afectadas} casos se ha confirmado que la versión instalada "
                 f"es vulnerable. ")

    base += (f"Las tecnologías con mayor concentración de hallazgos son "
             f"{tecnologias_txt}. ")
    base += (f"{con_cvss} de los registros cuentan con puntuación CVSS oficial "
             f"de NVD; el resto se clasificó mediante estimación por indicios, "
             f"circunstancia que se indica de forma explícita en cada ficha.")

    if str(cfg.get("translate_engine", "hybrid")).lower() not in ("ollama", "hybrid"):
        return base, "plantilla"

    disponible, _ = ollama_disponible(cfg)
    if not disponible:
        return base, "plantilla"

    import requests
    url = str(cfg.get("ollama_url", "http://localhost:11434")).rstrip("/")
    prompt = (
        "Eres analista de ciberseguridad y escribes el resumen ejecutivo de un "
        "informe mensual dirigido a la dirección de una empresa.\n"
        "Reescribe los datos siguientes en dos o tres párrafos en espanol formal, "
        "claros y sin alarmismo. No inventes ningún dato ni cifra que no aparezca. "
        "No uses listas ni titulos. Responde solo con el texto.\n\n"
        f"Datos:\n{base}"
    )
    try:
        respuesta = requests.post(
            f"{url}/api/generate",
            json={"model": str(cfg.get("ollama_model", "llama3.1:8b")),
                  "prompt": prompt, "stream": False,
                  "options": {"temperature": 0.25, "num_predict": 700}},
            timeout=int(cfg.get("ollama_timeout_s", 120)) * 3)
        respuesta.raise_for_status()
        texto = _limpiar_respuesta_ollama((respuesta.json() or {}).get("response") or "")
    except Exception as exc:  # noqa: BLE001
        log.warning("no se pudo redactar el resumen con Ollama",
                    extra={"error": str(exc)[:140]})
        return base, "plantilla"

    if len(texto) < 120:
        return base, "plantilla"
    return texto, "ollama"
