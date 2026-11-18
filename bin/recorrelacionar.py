#!/usr/bin/env python3
"""Vuelve a correlacionar las amenazas contra el inventario corregido.

Las correlaciones que trae el historico las produjo el matcher antiguo, que
buscaba subcadenas sin limites de palabra: 'edge' casaba dentro de 'knowledge'
y 'java' dentro de 'javascript'. Este script recalcula todas las asignaciones
con el matcher nuevo (limites de palabra, alias, exclusiones, contexto exigido y
veredicto de version) e informa de la diferencia.

Es idempotente y se puede volver a ejecutar cada vez que se corrija el
inventario o se registren versiones nuevas.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import config, db, matching                 # noqa: E402
from threatintel.logging_setup import get_logger, setup      # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default=None)
    parser.add_argument("--mes", default=None,
                        help="limitar a un periodo 'YYYY-MM' (por defecto, todos)")
    parser.add_argument("--lote", type=int, default=500)
    parser.add_argument("--dry-run", action="store_true",
                        help="calcula e informa, pero no escribe")
    args = parser.parse_args()

    setup(level="INFO", log_file="recorrelacion.jsonl")
    log = get_logger("recorrelacion")

    # ---------------------------------------------------------- estado previo
    with db.connect(args.db) as conn:
        cfg = config.load(conn)
        antes_por_tec = Counter({
            r["name"]: r["n"] for r in conn.execute(
                """SELECT t.name, COUNT(*) n FROM threat_technologies tt
                     JOIN technologies t ON t.id = tt.technology_id
                    GROUP BY t.id""")
        })
        antes_total = conn.execute(
            "SELECT COUNT(*) FROM threat_technologies").fetchone()[0]
        antes_con_tec = conn.execute(
            """SELECT COUNT(DISTINCT threat_id) FROM threat_technologies"""
        ).fetchone()[0]

        sql = ("SELECT id, title_en, title_es, summary_en, summary_es, month "
               "FROM threats")
        params: list = []
        if args.mes:
            sql += " WHERE month=?"
            params.append(args.mes)
        sql += " ORDER BY id"
        amenazas = [dict(r) for r in conn.execute(sql, params)]

        inventario = matching.compilar_inventario(conn, cfg=cfg)

    total_tec = len(getattr(inventario, "tecnologias", {}) or {})
    print(f"\n  Amenazas a recorrelacionar : {len(amenazas)}")
    print(f"  Tecnologias en inventario  : {total_tec}")
    print(f"  Correlaciones actuales     : {antes_total}")

    if not amenazas:
        print("  Nada que hacer.")
        return 0

    # ------------------------------------------------------------- recalculo
    despues_por_tec: Counter = Counter()
    sin_tecnologia = 0
    veredictos: Counter = Counter()
    nuevas_total = 0

    conn = db.connect(args.db)
    try:
        if not args.dry_run:
            conn.execute("BEGIN")

        for indice, amenaza in enumerate(amenazas, 1):
            texto = " ".join(filter(None, (
                amenaza["title_es"], amenaza["title_en"],
                amenaza["summary_es"], amenaza["summary_en"])))
            titulo = amenaza["title_es"] or amenaza["title_en"]

            coincidencias = matching.encontrar(texto, inventario, titulo=titulo)

            if not coincidencias:
                sin_tecnologia += 1
            for c in coincidencias:
                despues_por_tec[c.name] += 1
                veredictos[c.version_verdict] += 1
            nuevas_total += len(coincidencias)

            if not args.dry_run:
                matching.aplicar(conn, amenaza["id"], coincidencias)

            if indice % args.lote == 0:
                if not args.dry_run:
                    conn.execute("COMMIT")
                    conn.execute("BEGIN")
                print(f"    procesadas {indice}/{len(amenazas)}", end="\r", flush=True)

        if not args.dry_run:
            conn.execute("COMMIT")
            with db.session(args.db) as c2:
                db.audit(c2, "cli", "amenazas.recorrelacionar", "threats", None,
                         f"amenazas={len(amenazas)} correlaciones={nuevas_total}")
    except Exception:
        if not args.dry_run:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
        raise
    finally:
        conn.close()

    print(" " * 50, end="\r")

    # ------------------------------------------------------------- informe
    print(f"\n  Correlaciones nuevas       : {nuevas_total}"
          f"  ({nuevas_total - antes_total:+d})")
    print(f"  Amenazas sin tecnologia    : {sin_tecnologia} de {len(amenazas)}"
          f"  ({sin_tecnologia * 100 // max(len(amenazas), 1)}%)")
    print(f"  Amenazas con tecnologia    : {len(amenazas) - sin_tecnologia}"
          f"  (antes {antes_con_tec})")

    print("\n  Veredicto de version:")
    for veredicto in ("affected", "not_affected", "unknown"):
        etiqueta = {"affected": "version afectada",
                    "not_affected": "version NO afectada (descartable)",
                    "unknown": "sin determinar"}[veredicto]
        print(f"    {etiqueta:36} {veredictos.get(veredicto, 0)}")

    nombres = set(antes_por_tec) | set(despues_por_tec)
    cambios = sorted(
        ((n, antes_por_tec.get(n, 0), despues_por_tec.get(n, 0)) for n in nombres),
        key=lambda x: x[1] - x[2], reverse=True)

    print("\n  Mayores REDUCCIONES (falsos positivos eliminados):")
    print(f"    {'TECNOLOGIA':30} {'ANTES':>7} {'AHORA':>7} {'DIF':>8}")
    for nombre, antes, ahora in cambios[:12]:
        if antes - ahora <= 0:
            break
        print(f"    {nombre[:30]:30} {antes:>7} {ahora:>7} {ahora - antes:>+8}")

    subidas = [c for c in reversed(cambios) if c[2] - c[1] > 0][:8]
    if subidas:
        print("\n  Mayores AUMENTOS (detecciones que antes se perdian):")
        print(f"    {'TECNOLOGIA':30} {'ANTES':>7} {'AHORA':>7} {'DIF':>8}")
        for nombre, antes, ahora in subidas:
            print(f"    {nombre[:30]:30} {antes:>7} {ahora:>7} {ahora - antes:>+8}")

    log.info("recorrelacion terminada", extra={
        "amenazas": len(amenazas), "correlaciones_antes": antes_total,
        "correlaciones_despues": nuevas_total, "sin_tecnologia": sin_tecnologia,
        "dry_run": args.dry_run})

    if args.dry_run:
        print("\n  (dry-run: no se ha escrito nada)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
