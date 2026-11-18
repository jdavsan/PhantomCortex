#!/usr/bin/env python3
"""Importa el historico de data/monthly_threats_*.json a SQLite.

Colapsa duplicados: el sistema anterior guardaba un registro por (titulo, fecha),
asi que la misma vulnerabilidad vista en cinco fuentes generaba cinco filas.
Aqui se unifica por (mes, CVE) y las apariciones extra se acumulan en
`times_seen` y en `threat_sources`.

Los CVSS del sistema viejo eran inventados (constantes 9.0/7.5/5.0 por palabras
clave), asi que NO se importan: severity_source queda en 'heuristic' y
cvss_score en NULL. El enriquecimiento contra NVD los rellena despues con datos
reales.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import db, identity                      # noqa: E402
from threatintel.logging_setup import get_logger, setup    # noqa: E402
from threatintel.paths import DATA_DIR                     # noqa: E402

# Los cvss_score que el sistema viejo asignaba por palabra clave, no medidos.
CVSS_INVENTADOS = {9.0, 7.5, 5.0}


def slugificar(texto: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", (texto or "").lower()).strip("_")
    return base or "desconocido"


def asegurar_fuente(conn, nombre: str, url_muestra: str, cache: dict) -> int:
    """Crea la fuente si no existe. Las importadas quedan enabled=0: el catalogo
    real lo define threatintel/sources.py, esto solo preserva la procedencia."""
    slug = slugificar(nombre)
    if slug in cache:
        return cache[slug]

    row = conn.execute("SELECT id FROM sources WHERE slug=?", (slug,)).fetchone()
    if row:
        cache[slug] = row["id"]
        return row["id"]

    ahora = db.utcnow()
    dominio = ""
    if url_muestra:
        match = re.match(r"https?://([^/]+)", url_muestra)
        dominio = f"https://{match.group(1)}/" if match else ""

    cur = conn.execute(
        """INSERT INTO sources(slug, name, url, kind, category, priority, enabled,
                               timeout_s, notes, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (slug, nombre or slug, dominio or "https://desconocido.invalid/", "rss",
         "news", "medium", 0, 30,
         "Importada del historico JSON; revisar y activar si procede.", ahora, ahora),
    )
    cache[slug] = cur.lastrowid
    return cur.lastrowid


def asegurar_tecnologia(conn, nombre: str, cache: dict) -> int:
    """Crea la tecnologia si no existe, para no perder la correlacion historica."""
    slug = slugificar(nombre)
    if slug in cache:
        return cache[slug]

    row = conn.execute("SELECT id FROM technologies WHERE slug=?", (slug,)).fetchone()
    if row:
        cache[slug] = row["id"]
        return row["id"]

    ahora = db.utcnow()
    cur = conn.execute(
        """INSERT INTO technologies(slug, name, category, criticality, systems_count,
                                    exposure, enabled, notes, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (slug, nombre, "aplicacion", "medium", 0, "interna", 1,
         "Detectada en el historico importado; completar version y criticidad.",
         ahora, ahora),
    )
    cache[slug] = cur.lastrowid
    return cur.lastrowid


def importar_archivo(conn, ruta: Path, *, log, caches: dict) -> dict:
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    amenazas = datos.get("amenazas_acumuladas") or datos.get("amenazas") or []
    mes_archivo = datos.get("mes") or re.search(r"(\d{4})_(\d{2})", ruta.name)

    if isinstance(mes_archivo, re.Match):
        mes_archivo = f"{mes_archivo.group(1)}-{mes_archivo.group(2)}"

    stats = {"leidas": len(amenazas), "nuevas": 0, "fusionadas": 0, "omitidas": 0}

    for item in amenazas:
        titulo_en = (item.get("titulo_en") or item.get("nombre") or "").strip()
        titulo_es = (item.get("titulo_es") or "").strip() or None
        if not titulo_en and not titulo_es:
            stats["omitidas"] += 1
            continue

        cve_bruto = item.get("cve") or ""
        cve = identity.extraer_cve(cve_bruto, titulo_en, item.get("descripcion_en"))
        mes = mes_archivo or identity.mes_de(item.get("fecha_publicacion"))

        try:
            huella = identity.fingerprint(
                month=mes, cve=cve, titulo=titulo_en or titulo_es,
                url=item.get("fuente_original"))
        except ValueError:
            stats["omitidas"] += 1
            continue

        severidad = item.get("severidad") or "Medium"
        if severidad not in ("Critical", "High", "Medium", "Low"):
            severidad = "Medium"

        # El CVSS viejo era una constante por palabra clave: no se importa.
        cvss = item.get("cvss_score")
        cvss = None if (cvss is None or float(cvss) in CVSS_INVENTADOS) else float(cvss)

        detectada = item.get("fecha_deteccion") or item.get("fecha") or db.utcnow()
        publicada = item.get("fecha_publicacion")

        existente = conn.execute(
            "SELECT id, times_seen FROM threats WHERE fingerprint=?", (huella,)
        ).fetchone()

        if existente:
            threat_id = existente["id"]
            conn.execute(
                """UPDATE threats
                      SET times_seen = times_seen + 1,
                          last_seen_at = MAX(last_seen_at, ?),
                          title_es  = COALESCE(title_es, ?),
                          summary_es= COALESCE(summary_es, ?),
                          summary_en= COALESCE(summary_en, ?)
                    WHERE id = ?""",
                (str(detectada), titulo_es, item.get("descripcion_es"),
                 item.get("descripcion_en"), threat_id),
            )
            stats["fusionadas"] += 1
        else:
            cur = conn.execute(
                """INSERT INTO threats(
                       fingerprint, cve, title_en, title_es, summary_en, summary_es,
                       severity, severity_source, cvss_score, epss_score, in_kev,
                       published_at, first_seen_at, last_seen_at, times_seen,
                       impact_es, remediation_es, translation_engine, month,
                       alerted_at, relevance, raw_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (huella, cve, titulo_en or titulo_es, titulo_es,
                 item.get("descripcion_en"), item.get("descripcion_es"),
                 severidad, "heuristic", cvss, None, 0,
                 str(publicada) if publicada else None,
                 str(detectada), str(detectada), 1,
                 item.get("impacto_es"), item.get("mitigacion_es"),
                 "argos" if titulo_es and titulo_es != titulo_en else "none",
                 mes,
                 # Historico: se marca como ya alertado para no re-alertar el pasado.
                 str(detectada), 0.0,
                 json.dumps({"importado_de": ruta.name}, ensure_ascii=False)),
            )
            threat_id = cur.lastrowid
            stats["nuevas"] += 1

        # Procedencia
        nombre_fuente = item.get("fuente_nombre") or "Historico importado"
        url = item.get("fuente_original") or ""
        source_id = asegurar_fuente(conn, nombre_fuente, url, caches["fuentes"])
        if url:
            conn.execute(
                """INSERT OR IGNORE INTO threat_sources(threat_id, source_id, url, seen_at)
                   VALUES(?,?,?,?)""",
                (threat_id, source_id, url, str(detectada)),
            )

        # Correlacion tecnologica historica
        for nombre_tec in (item.get("tecnologias_afectadas") or []):
            if not nombre_tec:
                continue
            tec_id = asegurar_tecnologia(conn, str(nombre_tec), caches["tecnologias"])
            conn.execute(
                """INSERT OR IGNORE INTO threat_technologies(
                       threat_id, technology_id, matched_alias, confidence,
                       version_verdict, version_evidence)
                   VALUES(?,?,?,?,?,?)""",
                (threat_id, tec_id, str(nombre_tec), 0.5, "unknown",
                 "importado del historico, sin verificacion de version"),
            )

    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patron", default="monthly_threats_*.json")
    parser.add_argument("--db", default=None, help="ruta alternativa de base de datos")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    setup(level="INFO", log_file="migracion.jsonl")
    log = get_logger("migracion")

    archivos = sorted(DATA_DIR.glob(args.patron))
    if not archivos:
        log.error("no se encontraron archivos", extra={"patron": args.patron})
        return 1

    db.init_db(args.db)
    total = {"leidas": 0, "nuevas": 0, "fusionadas": 0, "omitidas": 0}
    caches = {"fuentes": {}, "tecnologias": {}}

    log.info("inicio de migracion", extra={"archivos": len(archivos)})

    for ruta in archivos:
        with db.session(args.db) as conn:
            stats = importar_archivo(conn, ruta, log=log, caches=caches)
            if args.dry_run:
                raise SystemExit("dry-run: no implementado con rollback, use --db /tmp/x.db")
        log.info("archivo importado", extra={"archivo": ruta.name, **stats})
        for clave in total:
            total[clave] += stats[clave]

    with db.connect(args.db) as conn:
        filas = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        con_cve = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE cve IS NOT NULL").fetchone()[0]
        meses = conn.execute("SELECT COUNT(DISTINCT month) FROM threats").fetchone()[0]
        tecs = conn.execute("SELECT COUNT(*) FROM technologies").fetchone()[0]
        fuentes = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]

    log.info("migracion terminada", extra={
        **total, "filas_finales": filas, "con_cve": con_cve,
        "meses": meses, "tecnologias": tecs, "fuentes": fuentes,
    })

    ahorro = total["fusionadas"]
    print()
    print(f"  Registros leidos del JSON : {total['leidas']}")
    print(f"  Amenazas unicas creadas   : {total['nuevas']}")
    print(f"  Duplicados fusionados     : {ahorro}"
          f" ({ahorro * 100 // max(total['leidas'], 1)}% del total)")
    print(f"  Omitidos (sin titulo)     : {total['omitidas']}")
    print(f"  Meses de historico        : {meses}")
    print(f"  Tecnologias detectadas    : {tecs}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
