#!/usr/bin/env python3
"""Ejecucion mensual: genera el informe y lo envia.

Sustituye a `generate_and_send_monthly_report.sh` +
`generate_monthly_report_docx.py` + `send_monthly_report.py`.

Tres defectos corregidos del anterior:

  * Tenia un `read -p` interactivo. Bajo cron recibia EOF, la variable quedaba
    vacia y el script hacia `exit 0`: informaba de exito sin generar nada.
    Aqui la comprobacion de fin de mes es un argumento explicito.

  * Enviaba a la direccion incrustada en el codigo porque leia una variable
    (`EMAIL_TO`) que no existe en el fichero de configuracion, ignorando
    `REPORT_EMAIL_TO`.

  * Si el envio fallaba, el informe quedaba generado y nadie se enteraba.
"""
from __future__ import annotations

import argparse
import calendar
import sys
import traceback
from datetime import date, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import (collector, config, db, health, notify,  # noqa: E402
                         report)
from threatintel.logging_setup import get_logger, setup           # noqa: E402
from threatintel.paths import HISTORICAL_REPORTS_DIR, ensure_dirs  # noqa: E402


def es_ultimo_dia_del_mes(hoy: date | None = None) -> bool:
    hoy = hoy or date.today()
    return hoy.day == calendar.monthrange(hoy.year, hoy.month)[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mes", default=None,
                        help="periodo 'YYYY-MM' (por defecto, el mes en curso)")
    parser.add_argument("--solo-generar", action="store_true",
                        help="genera el informe sin enviarlo")
    parser.add_argument("--forzar", action="store_true",
                        help="ejecuta aunque no sea el ultimo dia del mes")
    parser.add_argument("--dry-run", action="store_true",
                        help="genera el informe y simula el envio")
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    ensure_dirs()
    setup(level="INFO", log_file="threatintel.jsonl")
    log = get_logger("mensual")

    mes = args.mes or datetime.now().strftime("%Y-%m")

    # La guardia de fin de mes es explicita y falla de forma visible, en lugar
    # de salir con codigo 0 como si todo hubiera ido bien.
    if not args.mes and not args.forzar and not es_ultimo_dia_del_mes():
        hoy = date.today()
        ultimo = calendar.monthrange(hoy.year, hoy.month)[1]
        print(f"\n  Hoy es dia {hoy.day} y el mes termina el {ultimo}.")
        print(f"  El informe se genera el ultimo dia del mes.")
        print(f"  Use --forzar para generarlo ahora, o --mes YYYY-MM para otro "
              f"periodo.\n")
        log.info("ejecucion mensual omitida: no es el ultimo dia del mes",
                 extra={"dia": hoy.day, "ultimo_dia": ultimo})
        return 2      # codigo propio: ni exito ni fallo, simplemente no procede

    db.init_db(args.db)
    conn = db.connect(args.db)
    execution_id: int | None = None

    try:
        cfg = config.load(conn)
    except config.ConfigError as exc:
        log.error("configuracion invalida", extra={"error": str(exc)})
        print(f"\n  ERROR de configuracion: {exc}\n")
        conn.close()
        return 1

    mailer = notify.Mailer(cfg, dry_run=args.dry_run)

    try:
        if not args.dry_run:
            execution_id = collector.iniciar_ejecucion(conn, "monthly")

        # ---------------------------------------------- comprobar que hay datos
        resumen = report.construir_resumen(conn, mes, cfg=cfg)
        print(f"\n  Periodo: {report.mes_largo(mes)}")
        print(f"  Amenazas registradas: {resumen['total']}")

        if resumen["total"] == 0:
            print("  No hay datos del periodo. El informe se generara indicando "
                  "que no hubo hallazgos.")
            log.warning("informe mensual sin datos", extra={"mes": mes})

        # ------------------------------------------------------- 1. generar
        print("\n  [1/3] Generando el informe mensual completo...")
        ruta = report.generar(conn, mes, cfg=cfg)
        tamano_kb = round(ruta.stat().st_size / 1024, 1)
        print(f"        {ruta.name}  ({tamano_kb} KB)")
        print(f"        criticas={resumen['criticas']} altas={resumen['altas']} "
              f"medias={resumen['medias']} bajas={resumen['bajas']}")

        # ------------------------------------- 2. informe ejecutivo (2026-09-15)
        # Peticion del usuario: «a final de mes tambien se genera un informe ejecutivo
        # sobre las amenazas del mes que no exceda las 10 paginas». Es un documento aparte
        # y se envia JUNTO al completo, no en su lugar. Si fallara, el mensual completo
        # tiene que salir igualmente: el correo de la direccion no puede perderse porque
        # el resumen corto no se haya podido componer.
        print("\n  [2/3] Generando el informe ejecutivo (diez paginas como maximo)...")
        ruta_ejecutivo = None
        ejecutivo_kb = 0.0
        try:
            ruta_ejecutivo = report.generar_ejecutivo(conn, mes, cfg=cfg)
            ejecutivo_kb = round(ruta_ejecutivo.stat().st_size / 1024, 1)
            print(f"        {ruta_ejecutivo.name}  ({ejecutivo_kb} KB)")
        except Exception as exc:  # noqa: BLE001
            log.error("el informe ejecutivo no se pudo generar",
                      extra={"mes": mes, "error": str(exc)}, exc_info=True)
            print(f"        ERROR: el informe ejecutivo no se pudo generar ({exc}); "
                  f"se envia solo el informe completo")

        # ------------------------------------------------------- 3. enviar
        if args.solo_generar:
            print("\n  [3/3] Envio omitido (--solo-generar)")
            enviado = True
        else:
            print("\n  [3/3] Enviando por correo...")
            resumen_correo = dict(
                resumen,
                nombre_archivo=ruta.name,
                tamano_kb=int(tamano_kb),
                # Solo cuando el segundo documento existe: la plantilla del correo lo usa
                # para anunciar dos adjuntos en vez de uno.
                ejecutivo_kb=int(ejecutivo_kb) if ruta_ejecutivo else 0,
                url_interfaz=config.url_publica(cfg, "/"))

            adjuntos = [ruta] + ([ruta_ejecutivo] if ruta_ejecutivo else [])
            html = notify.render_monthly_email(resumen_correo)
            enviado = mailer.send(
                subject=notify.asunto_mensual(mes), html=html,
                to=cfg.report_to, cc=cfg.report_cc, attachments=adjuntos)

            if enviado:
                print(f"        enviado a {', '.join(cfg.report_to)}")
                if cfg.report_cc:
                    print(f"        copia a {', '.join(cfg.report_cc)}")
            else:
                print("        ERROR: el informe se genero pero NO se envio")

        # ------------------------------------------- archivar el mes anterior
        try:
            # Los dos documentos del mes se archivan con la misma regla (2026-09-15):
            # el completo y el ejecutivo.
            vigentes = {ruta.name}
            if ruta_ejecutivo is not None:
                vigentes.add(ruta_ejecutivo.name)
            limite = datetime.now().replace(year=datetime.now().year - 1).strftime("%Y_%m")
            antiguos = [(a, "Informe_Mensual_") for a in ruta.parent.glob("Informe_Mensual_*.docx")]
            antiguos += [(a, "Informe_Ejecutivo_") for a in ruta.parent.glob("Informe_Ejecutivo_*.docx")]
            for antiguo, prefijo in antiguos:
                if antiguo.name in vigentes:
                    continue
                marca = antiguo.stem.replace(prefijo, "")
                # Se archivan los de hace mas de 12 meses
                if marca < limite:
                    HISTORICAL_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
                    antiguo.rename(HISTORICAL_REPORTS_DIR / antiguo.name)
                    log.info("informe archivado", extra={"archivo": antiguo.name})
        except OSError as exc:
            log.warning("no se pudieron archivar informes antiguos",
                        extra={"error": str(exc)})

        # --------------------------------------------------------- limpieza
        if not args.dry_run:
            try:
                borrados = health.limpiar_historico(conn, cfg=cfg)
                total_borrado = sum(borrados.values())
                if total_borrado:
                    print(f"\n  Limpieza de retencion: {total_borrado} "
                          f"registro(s) eliminado(s)")
            except Exception as exc:  # noqa: BLE001
                log.warning("la limpieza de retencion fallo",
                            extra={"error": str(exc)})

        estado = "success" if enviado else "partial"
        if execution_id is not None:
            collector.cerrar_ejecucion(
                conn, execution_id, status=estado,
                threats_alerted=resumen["total"],
                error=None if enviado else "el informe no se pudo enviar",
                detalle={"mes": mes, "archivo": ruta.name,
                         "kb": tamano_kb, "total": resumen["total"],
                         "ejecutivo": ruta_ejecutivo.name if ruta_ejecutivo else None,
                         "ejecutivo_kb": ejecutivo_kb or None})

            if not enviado:
                health.avisar_ejecucion_fallida(
                    conn, cfg=cfg, execution_id=execution_id,
                    error=("El informe mensual se genero correctamente pero no "
                           f"se pudo enviar por correo. Archivo: {ruta}"),
                    mailer=mailer)

        collector.registrar_ultima_ejecucion(estado, {
            "tipo": "monthly", "mes": mes, "archivo": str(ruta),
            "enviado": enviado, "total": resumen["total"]})

        print(f"\n  {'Completado' if enviado else 'Completado con errores'}\n")
        log.info("ejecucion mensual terminada",
                 extra={"mes": mes, "enviado": enviado,
                        "total": resumen["total"], "archivo": ruta.name,
                        "ejecutivo": ruta_ejecutivo.name if ruta_ejecutivo else None})
        return 0 if enviado else 1

    except Exception as exc:  # noqa: BLE001
        traza = traceback.format_exc()
        log.error("la ejecucion mensual ha fallado",
                  extra={"error": str(exc)}, exc_info=True)
        print(f"\n  ERROR: {type(exc).__name__}: {exc}\n")

        if execution_id is not None:
            try:
                collector.cerrar_ejecucion(
                    conn, execution_id, status="failed",
                    error=f"{type(exc).__name__}: {exc}")
                health.avisar_ejecucion_fallida(
                    conn, cfg=cfg, execution_id=execution_id,
                    error=traza[-1500:], mailer=mailer)
            except Exception:  # noqa: BLE001
                log.error("no se pudo avisar del fallo", exc_info=True)

        collector.registrar_ultima_ejecucion("failed", {
            "tipo": "monthly", "mes": mes,
            "error": f"{type(exc).__name__}: {exc}"})
        return 1

    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
