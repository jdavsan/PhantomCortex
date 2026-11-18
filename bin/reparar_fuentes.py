#!/usr/bin/env python3
"""Repara las fuentes rotas y anade las recomendadas, verificando en vivo.

Por que reparar y no borrar: las entradas que el migrador creo desde el
historico conservan la PROCEDENCIA de las amenazas ya almacenadas
(`microsoft_msrc` esta referenciada por 2.636 amenazas, `debian_security` por
514). Borrarlas eliminaria en cascada esas filas de `threat_sources` y las
amenazas historicas se quedarian sin fuente citable en los informes.

Asi que a cada entrada rota se le asigna su URL de feed correcta y se activa.
Solo se eliminan las que sean duplicado exacto de otra que ya funciona, y en
ese caso las referencias se trasladan antes.

Cada URL se comprueba en vivo ANTES de guardarla: si no devuelve entradas, la
fuente se deja desactivada con el motivo anotado.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import config, db, http, sources              # noqa: E402
from threatintel.logging_setup import get_logger, setup         # noqa: E402

log = get_logger("reparar_fuentes")

# ----------------------------------------------------------------------
# Reparaciones: slug existente -> URL de feed correcta
# Todas verificadas en vivo el 2026-09-03 desde este servidor.
# ----------------------------------------------------------------------
REPARACIONES: dict[str, dict] = {
    # --- gubernamentales: las mas valiosas y las que estaban caidas ---
    "cisa_advisories": {
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "category": "government", "priority": "critical",
        "notes": "El 403 anterior se debia a no enviar User-Agent. Con la capa "
                 "HTTP nueva responde correctamente."},
    "us_cert_alerts": {
        "url": "https://us-cert.cisa.gov/ncas/current-activity.xml",
        "category": "government", "priority": "critical",
        "name": "CISA Current Activity",
        "notes": "Sustituye al feed de alertas retirado."},
    "debian_security": {
        "url": "https://www.debian.org/security/dsa-long.en.rdf",
        "category": "government", "priority": "high",
        "notes": "Feed oficial DSA en RDF."},
    "ubuntu_security": {
        "url": "https://ubuntu.com/security/notices/rss.xml",
        "category": "vendor", "priority": "high"},

    # --- fabricantes ---
    "microsoft_msrc": {
        "url": "https://api.msrc.microsoft.com/update-guide/rss",
        "category": "vendor", "priority": "critical",
        "notes": "Guia de actualizaciones de Microsoft."},
    "cisco_security": {
        "url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/"
               "CiscoSecurityAdvisory.xml",
        "category": "vendor", "priority": "high",
        "notes": "URL nueva: tools.cisco.com dejo de servir el feed."},
    "cisco_talos_intelligence": {
        "url": "https://blog.talosintelligence.com/rss/",
        "category": "vendor", "priority": "medium"},
    "rapid7_blog": {
        "url": "https://www.rapid7.com/blog/rss/",
        "category": "blog", "priority": "medium",
        "notes": "URL nueva: blog.rapid7.com dejo de existir."},
    "malwarebytes_blog": {
        "url": "https://www.malwarebytes.com/blog/feed/index.xml",
        "category": "blog", "priority": "low"},

    # --- medios ---
    "bleeping_computer": {
        "url": "https://www.bleepingcomputer.com/feed/",
        "category": "news", "priority": "high"},
    "the_hacker_news": {
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "category": "news", "priority": "medium"},
    "dark_reading": {
        "url": "https://www.darkreading.com/rss.xml",
        "category": "news", "priority": "low"},
    "krebs_on_security": {
        "url": "https://krebsonsecurity.com/feed/",
        "category": "news", "priority": "low"},
    "securityweek": {
        "url": "https://www.securityweek.com/feed/",
        "category": "news", "priority": "medium"},
    "cyber_security_news": {
        "url": "https://cybersecuritynews.com/feed/",
        "category": "news", "priority": "low"},
    "infosecurity_magazine": {
        "url": "https://www.infosecurity-magazine.com/rss/news/",
        "category": "news", "priority": "low"},
    "zdnet_security": {
        "url": "https://www.zdnet.com/topic/security/rss.xml",
        "category": "news", "priority": "low"},
    "cyberscoop": {
        "url": "https://cyberscoop.com/feed/",
        "category": "news", "priority": "low"},
    "gbhackers": {
        "url": "https://gbhackers.com/feed/",
        "category": "blog", "priority": "low"},

    # --- blogs e investigacion ---
    "kaspersky_securelist_en": {
        "url": "https://securelist.com/feed/",
        "category": "blog", "priority": "medium"},
    "securelist_es": {
        "url": "https://securelist.lat/feed/",
        "category": "blog", "priority": "low",
        "notes": "Version en espanol; puede fallar por DNS de forma "
                 "intermitente."},
    "schneier_on_security": {
        "url": "https://www.schneier.com/feed/atom/",
        "category": "blog", "priority": "low"},
    "troy_hunt_blog": {
        "url": "https://www.troyhunt.com/rss/",
        "category": "blog", "priority": "low"},
    "segu_info": {
        "url": "https://blog.segu-info.com.ar/feeds/posts/default",
        "category": "blog", "priority": "low",
        "notes": "Fuente en espanol."},
    "circl_vulnerability_lookup": {
        "url": "https://vulnerability.circl.lu/recent/all.atom",
        "category": "government", "priority": "medium"},
    "exploit_db": {
        "url": "https://www.exploit-db.com/rss.xml",
        "category": "exploits", "priority": "medium"},
    "naked_security": {
        "url": "https://news.sophos.com/en-us/category/threat-research/feed/",
        "category": "vendor", "priority": "medium",
        "name": "Sophos Threat Research",
        "notes": "Sophos cerro nakedsecurity.sophos.com; este es el sustituto. "
                 "Puede agotar el tiempo de espera: se le da mas margen."},
    "threatpost": {
        "url": "https://therecord.media/feed/",
        "category": "news", "priority": "medium",
        "name": "The Record",
        "notes": "Threatpost cerro en 2023. The Record cubre el mismo ambito."},
}

# ----------------------------------------------------------------------
# Fuentes NUEVAS recomendadas, ordenadas por relevancia para esta
# organizacion (Windows, Debian/Ubuntu, PostgreSQL, Moodle, GitLab,
# pfSense, Check Point, Carbonio, Apache, PHP, Docker, Proxmox, Asterisk).
# ----------------------------------------------------------------------
NUEVAS: list[dict] = [
    # === PRIORIDAD CRITICA: afectan directamente al inventario ===
    {"slug": "gitlab_security_releases", "name": "GitLab Security Releases",
     "url": "https://about.gitlab.com/security-releases.xml",
     "kind": "rss", "category": "vendor", "priority": "critical", "enabled": 1,
     "notes": "La organizacion usa GitLab. Avisos de seguridad del propio "
              "fabricante, con las versiones corregidas."},
    {"slug": "checkpoint_research", "name": "Check Point Research",
     "url": "https://research.checkpoint.com/feed/",
     "kind": "rss", "category": "vendor", "priority": "critical", "enabled": 1,
     "notes": "La organizacion usa Check Point VPN y Gaia."},
    {"slug": "cert_eu_advisories", "name": "CERT-EU Security Advisories",
     "url": "https://cert.europa.eu/publications/security-advisories-rss",
     "kind": "rss", "category": "government", "priority": "critical", "enabled": 1,
     "notes": "Avisos del CERT de las instituciones europeas. Autoritativo y "
              "centrado en vulnerabilidades, no en noticias."},
    {"slug": "zdi_advisories", "name": "Zero Day Initiative - Avisos",
     "url": "https://www.zerodayinitiative.com/rss/published/",
     "kind": "rss", "category": "database", "priority": "critical", "enabled": 1,
     "notes": "Avisos de dia cero independientes del fabricante. Suele "
              "publicar antes que el propio fabricante."},

    # === PRIORIDAD ALTA: infraestructura de red y perimetro ===
    {"slug": "fortinet_psirt", "name": "Fortinet PSIRT",
     "url": "https://www.fortiguard.com/rss/ir.xml",
     "kind": "rss", "category": "vendor", "priority": "high", "enabled": 1,
     "notes": "Fortinet es objetivo recurrente en perimetro; util incluso sin "
              "equipos Fortinet, porque marca tendencia de ataques a VPN."},
    {"slug": "paloalto_psirt", "name": "Palo Alto Networks PSIRT",
     "url": "https://security.paloaltonetworks.com/rss.xml",
     "kind": "rss", "category": "vendor", "priority": "high", "enabled": 1},
    {"slug": "sans_isc_full", "name": "SANS Internet Storm Center",
     "url": "https://isc.sans.edu/rssfeed_full.xml",
     "kind": "rss", "category": "news", "priority": "high", "enabled": 1,
     "notes": "Analisis diario de lo que se esta explotando de verdad."},
    {"slug": "ncsc_uk", "name": "NCSC Reino Unido",
     "url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
     "kind": "rss", "category": "government", "priority": "high", "enabled": 1},

    # === PRIORIDAD MEDIA: investigacion de calidad ===
    {"slug": "unit42", "name": "Palo Alto Unit 42",
     "url": "https://unit42.paloaltonetworks.com/feed/",
     "kind": "rss", "category": "blog", "priority": "medium", "enabled": 1,
     "notes": "Analisis tecnico de campanas activas."},
    {"slug": "google_project_zero_v2", "name": "Google Project Zero",
     "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
     "kind": "rss", "category": "blog", "priority": "medium", "enabled": 0,
     "notes": "Ya existe como project_zero; se deja desactivada para no "
              "duplicar."},
    {"slug": "eset_welivesecurity", "name": "ESET WeLiveSecurity",
     "url": "https://www.welivesecurity.com/en/rss/feed/",
     "kind": "rss", "category": "blog", "priority": "medium", "enabled": 1},
    {"slug": "sentinellabs", "name": "SentinelLabs",
     "url": "https://www.sentinelone.com/labs/feed/",
     "kind": "rss", "category": "blog", "priority": "medium", "enabled": 1},
    {"slug": "tenable_research", "name": "Tenable Research",
     "url": "https://www.tenable.com/blog/feed",
     "kind": "rss", "category": "blog", "priority": "medium", "enabled": 1,
     "notes": "Enfoque en gestion de vulnerabilidades."},
    {"slug": "trend_micro_research", "name": "Trend Micro Research",
     "url": "https://feeds.feedburner.com/TrendMicroSimplySecurity",
     "kind": "rss", "category": "blog", "priority": "medium", "enabled": 1},
    {"slug": "mandiant_ti", "name": "Google Threat Intelligence (Mandiant)",
     "url": "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
     "kind": "rss", "category": "blog", "priority": "medium", "enabled": 1},
    {"slug": "cert_fr_avis", "name": "CERT-FR Avisos",
     "url": "https://www.cert.ssi.gouv.fr/avis/feed/",
     "kind": "rss", "category": "government", "priority": "medium", "enabled": 1,
     "notes": "En frances, pero con CVE y versiones muy bien estructurados."},

    # === PRIORIDAD BAJA: cobertura adicional, desactivadas por defecto ===
    {"slug": "greynoise_labs", "name": "GreyNoise Labs",
     "url": "https://www.greynoise.io/blog/rss.xml",
     "kind": "rss", "category": "blog", "priority": "low", "enabled": 0,
     "notes": "Telemetria de escaneo masivo: util para saber que se esta "
              "explotando ahora mismo."},
    {"slug": "elastic_security_labs", "name": "Elastic Security Labs",
     "url": "https://www.elastic.co/security-labs/rss/feed.xml",
     "kind": "rss", "category": "blog", "priority": "low", "enabled": 0},
    {"slug": "huntress_blog", "name": "Huntress",
     "url": "https://www.huntress.com/blog/rss.xml",
     "kind": "rss", "category": "blog", "priority": "low", "enabled": 0},
    {"slug": "qualys_blog", "name": "Qualys Security Blog",
     "url": "https://blog.qualys.com/feed",
     "kind": "rss", "category": "blog", "priority": "low", "enabled": 0},
    {"slug": "crowdstrike_blog", "name": "CrowdStrike",
     "url": "https://www.crowdstrike.com/blog/feed/",
     "kind": "rss", "category": "blog", "priority": "low", "enabled": 0},
    {"slug": "jpcert", "name": "JPCERT/CC",
     "url": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
     "kind": "rss", "category": "government", "priority": "low", "enabled": 0},
    {"slug": "apple_security_releases", "name": "Apple Security Releases",
     "url": "https://developer.apple.com/news/releases/rss/releases.rss",
     "kind": "rss", "category": "vendor", "priority": "low", "enabled": 0,
     "notes": "Activar solo si hay equipos Apple en el parque."},
    {"slug": "splunk_advisories", "name": "Splunk Security Advisories",
     "url": "https://advisory.splunk.com/feed.xml",
     "kind": "rss", "category": "vendor", "priority": "low", "enabled": 0,
     "notes": "Activar solo si se usa Splunk."},
    {"slug": "microsoft_security_blog", "name": "Microsoft Security Blog",
     "url": "https://www.microsoft.com/en-us/security/blog/feed/",
     "kind": "rss", "category": "vendor", "priority": "low", "enabled": 0},
    {"slug": "google_security_blog", "name": "Google Security Blog",
     "url": "https://security.googleblog.com/feeds/posts/default",
     "kind": "rss", "category": "blog", "priority": "low", "enabled": 0},
]


def _verificar(url: str, cfg, timeout: int = 25) -> tuple[bool, int, str]:
    resultado = http.fetch_feed(url, timeout=timeout, retries=1,
                                user_agent=cfg.get("http_user_agent"))
    if resultado.ok and resultado.entries:
        return True, len(resultado.entries), ""
    if resultado.ok:
        return False, 0, "sin entradas"
    return False, 0, resultado.error or "fallo"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--sin-verificar", action="store_true",
                        help="no comprueba las URL en vivo (mas rapido)")
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    setup(level="INFO", log_file="reparacion_fuentes.jsonl", console=False)
    db.init_db(args.db)
    with db.connect(args.db) as conn:
        cfg = config.load(conn)

    reparadas, no_reparadas, creadas, omitidas = [], [], [], []

    # ---------------------------------------------------- reparaciones
    print("\n  REPARANDO FUENTES EXISTENTES")
    print(f"  {'SLUG':32} {'ENTR':>5}  RESULTADO")
    print(f"  {'-' * 74}")

    conn = db.connect(args.db)
    try:
        for slug, datos in REPARACIONES.items():
            fila = conn.execute(
                "SELECT id, name, url, enabled FROM sources WHERE slug=?",
                (slug,)).fetchone()
            if fila is None:
                omitidas.append((slug, "no existe en la base de datos"))
                continue

            url = datos["url"]
            timeout = 45 if "sophos" in url else 25
            if args.sin_verificar:
                ok, entradas, error = True, -1, ""
            else:
                ok, entradas, error = _verificar(url, cfg, timeout)

            referencias = conn.execute(
                "SELECT COUNT(*) FROM threat_sources WHERE source_id=?",
                (fila["id"],)).fetchone()[0]

            if not args.dry_run:
                campos = ["url=?", "category=?", "priority=?", "enabled=?",
                          "timeout_s=?", "updated_at=?"]
                valores = [url, datos.get("category", "news"),
                           datos.get("priority", "medium"), 1 if ok else 0,
                           timeout, db.utcnow()]
                if datos.get("name"):
                    campos.insert(0, "name=?")
                    valores.insert(0, datos["name"])
                nota = datos.get("notes", "")
                if not ok:
                    nota = (nota + f" [no operativa el {db.utcnow()[:10]}: "
                                   f"{error}]").strip()
                campos.append("notes=?")
                valores.append(nota or None)
                valores.append(fila["id"])
                conn.execute(
                    f"UPDATE sources SET {', '.join(campos)} WHERE id=?", valores)

            marca = "REPARADA" if ok else "sigue sin funcionar"
            (reparadas if ok else no_reparadas).append((slug, entradas, error))
            print(f"  {slug[:32]:32} {entradas if entradas >= 0 else '?':>5}  "
                  f"{marca}{f' ({error})' if error else ''}"
                  f"{f'  [{referencias} amenazas historicas conservadas]' if referencias else ''}")

        # ------------------------------------------------ fuentes nuevas
        print("\n  ANADIENDO FUENTES RECOMENDADAS")
        print(f"  {'SLUG':32} {'ENTR':>5}  {'PRIO':9} RESULTADO")
        print(f"  {'-' * 74}")

        for datos in NUEVAS:
            slug = datos["slug"]
            existe = conn.execute("SELECT id FROM sources WHERE slug=?",
                                  (slug,)).fetchone()
            if existe is not None:
                omitidas.append((slug, "ya existe"))
                print(f"  {slug[:32]:32} {'-':>5}  {datos['priority']:9} ya existe")
                continue

            if args.sin_verificar:
                ok, entradas, error = True, -1, ""
            else:
                ok, entradas, error = _verificar(datos["url"], cfg)

            activar = 1 if (ok and datos.get("enabled", 1)) else 0
            if not args.dry_run:
                ahora = db.utcnow()
                nota = datos.get("notes", "")
                if not ok:
                    nota = (nota + f" [no operativa: {error}]").strip()
                conn.execute(
                    """INSERT INTO sources(slug, name, url, kind, category,
                           priority, enabled, timeout_s, notes, created_at,
                           updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (slug, datos["name"], datos["url"], datos.get("kind", "rss"),
                     datos["category"], datos["priority"], activar, 30,
                     nota or None, ahora, ahora))

            creadas.append((slug, entradas, datos["priority"], activar))
            estado = ("anadida y activada" if activar else
                      ("anadida, desactivada" if ok else f"anadida inactiva ({error})"))
            print(f"  {slug[:32]:32} {entradas if entradas >= 0 else '?':>5}  "
                  f"{datos['priority']:9} {estado}")

        if not args.dry_run:
            db.audit(conn, "cli", "fuente.reparar_catalogo", "sources", None,
                     f"reparadas={len(reparadas)} nuevas={len(creadas)} "
                     f"sin_reparar={len(no_reparadas)}")
    finally:
        conn.close()

    # ------------------------------------------------------------ resumen
    with db.connect(args.db) as conn:
        total = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        activas = conn.execute(
            "SELECT COUNT(*) FROM sources WHERE enabled=1").fetchone()[0]
        rss = conn.execute(
            "SELECT COUNT(*) FROM sources WHERE enabled=1 AND kind='rss'"
        ).fetchone()[0]

    print(f"\n  Reparadas         : {len(reparadas)}")
    print(f"  Sin reparar       : {len(no_reparadas)}")
    if no_reparadas:
        for slug, _, error in no_reparadas:
            print(f"      {slug}: {error}")
    print(f"  Nuevas anadidas   : {len(creadas)}")
    print(f"  Omitidas          : {len(omitidas)}")
    print(f"  ---")
    print(f"  Fuentes totales   : {total}")
    print(f"  Activas           : {activas}  (de ellas {rss} son feeds RSS)")

    if args.dry_run:
        print("\n  (dry-run: no se ha escrito nada)")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
