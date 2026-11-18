#!/usr/bin/env python3
"""Aplica la politica de retencion de datos y de logs.

Existe para que los ajustes `data_retention_days` y `log_retention_days` tengan
efecto real. Antes el cron borraba logs con un `find -mtime +30` fijo, asi que
cambiar el ajuste en la interfaz no hacia nada: el mismo defecto que la
auditoria reprocho al sistema anterior.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import config, db, health                  # noqa: E402
from threatintel.logging_setup import get_logger, setup      # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--solo-logs", action="store_true",
                        help="no toca la base de datos, solo los ficheros de log")
    parser.add_argument("--dry-run", action="store_true",
                        help="informa de lo que borraria sin borrar nada")
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    setup(level="INFO", log_file="limpieza.jsonl", console=True)
    log = get_logger("limpieza")

    db.init_db(args.db)
    with db.connect(args.db) as conn:
        cfg = config.load(conn)

    print(f"\n  Retencion de datos : {cfg.get('data_retention_days')} dias")
    print(f"  Retencion de logs  : {cfg.get('log_retention_days')} dias")

    if args.dry_run:
        from datetime import datetime, timedelta, timezone
        from threatintel.paths import LOGS_DIR
        dias = int(cfg.get("log_retention_days", 30) or 30)
        limite = datetime.now(timezone.utc) - timedelta(days=dias)
        candidatos = []
        for f in LOGS_DIR.glob("*"):
            if not f.is_file():
                continue
            if f.suffix == ".jsonl" and not f.name[-1].isdigit():
                continue
            marca = datetime.fromtimestamp(f.stat().st_mtime, timezone.utc)
            if marca < limite:
                candidatos.append((f.name, f.stat().st_size))
        print(f"\n  Logs que se borrarian: {len(candidatos)}")
        for nombre, tamano in candidatos[:20]:
            print(f"    {nombre:44} {tamano // 1024} KB")
        with db.connect(args.db) as conn:
            from datetime import datetime as _dt
            corte = (datetime.now(timezone.utc)
                     - timedelta(days=int(cfg.get("data_retention_days", 400)))
                     ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            n = conn.execute("SELECT COUNT(*) FROM threats WHERE first_seen_at < ?",
                             (corte,)).fetchone()[0]
        print(f"  Amenazas que se borrarian: {n}")
        print("\n  (dry-run: no se ha borrado nada)\n")
        return 0

    if args.solo_logs:
        resultado = health.limpiar_logs(cfg)
        print(f"\n  Logs borrados: {resultado['borrados']} "
              f"({resultado['bytes_liberados'] // 1024} KB liberados)\n")
        return 0

    with db.session(args.db) as conn:
        borrados = health.limpiar_historico(conn, cfg=cfg)

    print()
    etiquetas = {"amenazas": "amenazas antiguas", "salud_fuentes": "historial de salud",
                 "ejecuciones": "registros de ejecucion", "avisos": "avisos enviados",
                 "auditoria": "entradas de auditoria",
                 "cache_traduccion": "traducciones en cache", "logs": "ficheros de log"}
    total = 0
    for clave, etiqueta in etiquetas.items():
        n = borrados.get(clave, 0)
        total += n
        print(f"  {etiqueta:26} {n:>6}")
    print(f"  {'-' * 34}\n  {'total eliminado':26} {total:>6}\n")

    log.info("limpieza terminada", extra=borrados)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
