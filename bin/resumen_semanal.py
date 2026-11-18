#!/usr/bin/env python3
"""Resumen semanal: lo que la alerta diaria no envio, con su porque.

Se ejecuta desde el cron de `si` el dia configurado en `digest_weekday`
(lunes por defecto) a las 08:30 y envia a los destinatarios de la alerta un
correo con cuatro apartados: seguimiento por tecnologia, informativo, lo que
el filtro descarto (con el motivo en lenguaje llano) y el recordatorio de lo
alertado en la semana. Las amenazas incluidas quedan marcadas con `digest_at`
para no repetirlas.

Codigos de salida: 0 exito (o nada que enviar), 1 fallo, 2 no procede (no es
el dia configurado o el resumen esta desactivado).

Uso:
    bin/resumen_semanal.py                 # envio real, solo el dia configurado
    bin/resumen_semanal.py --dry-run       # genera data/revision/semanal_prueba.html
    bin/resumen_semanal.py --forzar        # envia aunque no sea el dia configurado
"""
from __future__ import annotations

import argparse
import sys
import traceback
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import config, db, digest, notify              # noqa: E402
from threatintel.logging_setup import get_logger, setup          # noqa: E402
from threatintel.paths import DATA_DIR, ensure_dirs               # noqa: E402

DIAS_SEMANA = ("lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo")
SALIDA_PRUEBA = DATA_DIR / "revision" / "semanal_prueba.html"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true",
                        help="no envía correo ni marca digest_at; escribe el HTML en "
                             f"{SALIDA_PRUEBA.relative_to(DATA_DIR.parent)}")
    parser.add_argument("--forzar", action="store_true",
                        help="ejecuta aunque no sea el día configurado o el resumen "
                             "esté desactivado")
    parser.add_argument("--dias", type=int, default=7,
                        help="días que cubre el resumen (7 por defecto)")
    parser.add_argument("--salida", default=None,
                        help="ruta del HTML en --dry-run (por defecto "
                             "data/revision/semanal_prueba.html)")
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    ensure_dirs()
    setup(level="INFO", log_file="threatintel.jsonl")
    log = get_logger("semanal")

    db.init_db(args.db)
    conn = db.connect(args.db)

    try:
        cfg = config.load(conn)
    except config.ConfigError as exc:
        log.error("configuracion invalida", extra={"error": str(exc)})
        print(f"\n  ERROR de configuración: {exc}\n")
        conn.close()
        return 1

    try:
        if not cfg.get("digest_enabled", True) and not args.forzar:
            print("\n  El resumen semanal está desactivado en los ajustes "
                  "(digest_enabled). Use --forzar para enviarlo igualmente.\n")
            log.info("resumen semanal omitido: desactivado en ajustes")
            return 2

        dia_cfg = int(cfg.get("digest_weekday", 1) or 1)
        hoy = date.today().isoweekday()
        if hoy != dia_cfg and not args.forzar and not args.dry_run:
            print(f"\n  Hoy es {DIAS_SEMANA[hoy - 1]} y el resumen se envía los "
                  f"{DIAS_SEMANA[dia_cfg - 1]}. Use --forzar para enviarlo ahora "
                  f"o --dry-run para verlo sin enviar.\n")
            log.info("resumen semanal omitido: no es el dia configurado",
                     extra={"hoy": hoy, "configurado": dia_cfg})
            return 2

        # ------------------------------------------------------ 1. contenido
        print(f"\n  [1/2] Reuniendo las amenazas de los últimos {args.dias} días...")
        datos = digest.recopilar(conn, cfg=cfg, dias=args.dias)
        print(f"        {datos['seguimiento_total']} en seguimiento "
              f"({len(datos['seguimiento'])} tecnologías), "
              f"{len(datos['informativo'])} informativas, "
              f"{datos['descartadas_total']} descartadas por el filtro, "
              f"{len(datos['alertadas'])} alertadas en la semana")
        for d in datos["descartadas"]:
            print(f"          - {d['motivo']}: {d['n']}")
        if datos["omitidas"]:
            print(f"        {datos['omitidas']} no caben en el máximo de "
                  f"{datos['maximo']} y se omiten")

        if datos["vacio"]:
            print("\n  No hay nada que resumir esta semana: no se envía correo.\n")
            log.info("resumen semanal sin contenido")
            return 0

        html = digest.render(datos)
        asunto = digest.asunto(datos["desde"])

        # --------------------------------------------------------- 2. envío
        if args.dry_run:
            salida = Path(args.salida) if args.salida else SALIDA_PRUEBA
            salida.parent.mkdir(parents=True, exist_ok=True)
            salida.write_text(html, encoding="utf-8")
            try:
                salida.chmod(0o600)
            except PermissionError:
                pass
            print(f"\n  [2/2] Simulación: HTML escrito en {salida}")
            print(f"        asunto: {asunto}")

        mailer = notify.Mailer(cfg, dry_run=args.dry_run)
        if not args.dry_run:
            print("\n  [2/2] Enviando el resumen...")
        enviado = mailer.send(subject=asunto, html=html,
                              to=cfg.alert_to, cc=cfg.alert_cc)

        if not enviado:
            print("        ERROR: el resumen semanal no se pudo enviar\n")
            log.error("el resumen semanal no se envio",
                      extra={"incluidas": len(datos["ids_incluidas"])})
            return 1

        if args.dry_run:
            print("        envío simulado; digest_at no se marca\n")
        else:
            marcadas = digest.marcar_incluidas(conn, datos["ids_incluidas"])
            print(f"        enviado a {', '.join(cfg.alert_to)}; "
                  f"{marcadas} amenazas marcadas como incluidas\n")
            log.info("resumen semanal enviado",
                     extra={"incluidas": marcadas,
                            "seguimiento": datos["seguimiento_total"],
                            "informativo": len(datos["informativo"]),
                            "descartadas": datos["descartadas_total"],
                            "alertadas": len(datos["alertadas"])})
        return 0

    except Exception as exc:  # noqa: BLE001 - se informa y se registra
        log.error("el resumen semanal ha fallado",
                  extra={"error": str(exc)}, exc_info=True)
        print(f"\n  ERROR: {type(exc).__name__}: {exc}\n")
        print(traceback.format_exc()[-1500:])
        return 1

    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
