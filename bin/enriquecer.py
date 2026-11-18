#!/usr/bin/env python3
"""Enriquece las amenazas con datos oficiales de NVD, CISA KEV y EPSS.

Sustituye el CVSS inventado del sistema anterior por la puntuacion oficial.
Es incremental: cada ejecucion toma las que aun no tienen datos.

Sin clave de API de NVD el limite es de 5 peticiones cada 30 segundos, asi que
enriquecer todo el historico lleva horas. Con una clave valida (gratuita, en
https://nvd.nist.gov/developers/request-an-api-key) el limite es 10 veces mayor.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import config, db, enrich                   # noqa: E402
from threatintel.logging_setup import get_logger, setup      # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limite", type=int, default=None,
                        help="numero maximo de CVE (por defecto, el ajuste "
                             "enrich_max_per_run)")
    parser.add_argument("--todo", action="store_true",
                        help="procesa todo el pendiente, sin limite")
    parser.add_argument("--reenriquecer", action="store_true",
                        help="vuelve a consultar tambien las ya enriquecidas")
    parser.add_argument("--solo-relevancia", action="store_true",
                        help="no consulta APIs, solo recalcula la relevancia")
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    setup(level="INFO", log_file="enriquecimiento.jsonl")
    log = get_logger("enriquecimiento")

    db.init_db(args.db)
    with db.connect(args.db) as conn:
        cfg = config.load(conn)

    if args.solo_relevancia:
        with db.session(args.db) as conn:
            n = enrich.recalcular_relevancia(conn)
        print(f"  Relevancia recalculada en {n} amenazas.")
        return 0

    ok, mensaje = enrich.validar_clave_nvd(cfg)
    print(f"\n  Clave NVD: {'valida' if ok else 'NO se usara'}")
    print(f"  {mensaje}")

    limite = None
    if args.todo:
        with db.connect(args.db) as conn:
            limite = conn.execute(
                "SELECT COUNT(*) FROM threats WHERE cve IS NOT NULL"
                + ("" if args.reenriquecer else " AND enriched_at IS NULL")
            ).fetchone()[0]
        segundos = limite * (0.8 if ok else 6.6)
        print(f"  Pendientes: {limite}  (estimado {segundos/60:.0f} min)")
    else:
        limite = args.limite

    # Conexion en autocommit: las esperas del limite de NVD no deben mantener
    # ningun bloqueo de escritura mientras la interfaz web esta en uso.
    conn = db.connect(args.db)
    try:
        stats = enrich.enriquecer_pendientes(
            conn, cfg=cfg, limite=limite, reenriquecer=args.reenriquecer)
    finally:
        conn.close()

    print()
    etiquetas = {
        "candidatas": "CVE procesados", "consultadas": "consultas a NVD",
        "con_cvss_real": "con CVSS oficial", "sin_dato": "sin dato en NVD",
        "en_kev": "en CISA KEV (explotacion confirmada)",
        "con_epss": "con probabilidad EPSS",
        "reclasificadas": "cambiaron de severidad",
        "subidas": "  subieron de severidad", "bajadas": "  bajaron de severidad",
        "errores": "errores",
    }
    for clave, etiqueta in etiquetas.items():
        print(f"  {etiqueta:40} {stats.get(clave, 0)}")

    with db.connect(args.db) as conn:
        pend = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE cve IS NOT NULL "
            "AND enriched_at IS NULL").fetchone()[0]
    print(f"\n  Quedan pendientes: {pend}")

    log.info("ejecucion de enriquecimiento terminada",
             extra={**stats, "pendientes": pend})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
