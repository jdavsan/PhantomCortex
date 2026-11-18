#!/usr/bin/env python3
"""Sincroniza el inventario real desde OCS Inventory y evalua la aplicabilidad.

Pasos:
  1. Lee los dos OCS (servidores y equipos de usuario) con el usuario de solo
     lectura de config/credentials.env y actualiza `activos` / `activo_software`.
  2. Aplica el mapa de nombres OCS -> tecnologia, actualiza el inventario de
     tecnologias (activos y versiones reales) y detecta hallazgos de politica
     (sin reportar, software de riesgo, sin agente de proteccion).
  3. Refresca los ciclos de fin de soporte (endoflife.date) y marca los activos
     fuera de soporte.
  4. Evalua las amenazas con CVE pendientes contra los activos (OSV.dev, VuXML,
     comparacion de version) y recalcula su relevancia.

Uso:
    bin/sincronizar_ocs.py                    # todo
    bin/sincronizar_ocs.py --origen servidores
    bin/sincronizar_ocs.py --sin-aplicabilidad
    bin/sincronizar_ocs.py --solo-aplicabilidad --max-amenazas 300
Codigo de salida: 0 correcto, 1 si algun origen no se pudo sincronizar.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import aplicabilidad, config, db, msrc, ocs, parches, remediacion  # noqa: E402
from threatintel.logging_setup import get_logger, setup    # noqa: E402
from threatintel.paths import ensure_dirs                  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--origen", choices=sorted(ocs.ORIGENES), help="sincronizar solo un origen")
    parser.add_argument("--sin-aplicabilidad", action="store_true", help="no evaluar amenazas")
    parser.add_argument("--solo-aplicabilidad", action="store_true", help="no leer OCS; solo evaluar")
    parser.add_argument("--max-amenazas", type=int, default=None, help="amenazas a evaluar en esta ejecucion")
    parser.add_argument("--max-osv", type=int, default=None, help="consultas de red a OSV.dev")
    parser.add_argument("--forzar-fin-soporte", action="store_true",
                        help="volver a descargar los ciclos de endoflife.date aunque la caché sea reciente")
    parser.add_argument("--reevaluar", action="store_true",
                        help="marcar todas las amenazas evaluadas como pendientes antes de evaluar")
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    ensure_dirs()
    setup(level="INFO", log_file="threatintel.jsonl")
    log = get_logger("sincronizar_ocs")
    db.init_db(args.db)
    conn = db.connect(args.db)
    fallos = 0
    inicio = time.perf_counter()
    try:
        cfg = config.load(conn)
        secretos = cfg.secrets

        if args.solo_aplicabilidad:
            creadas = ocs.sembrar_mapa(conn)
            nuevas = ocs.sembrar_tecnologias(conn)
            creadas += nuevas["reglas"]
            mapa = ocs.aplicar_mapa(conn)
            ocs.actualizar_inventario_desde_ocs(conn, cfg=cfg)
            print(f"\n  [1/4] Lectura de OCS omitida; mapa de nombres aplicado ({creadas} reglas base nuevas, "
                  f"{mapa['nombres_mapeados']} nombres clasificados)")
        else:
            print("\n  [1/4] Sincronizando con OCS Inventory...")
            resultados = ocs.sincronizar(conn, secretos=secretos, cfg=cfg,
                                         origenes=[args.origen] if args.origen else None)
            for r in resultados:
                if r.get("error"):
                    fallos += 1
                    print(f"        {r['origen']}: ERROR {r['error']}")
                else:
                    print(f"        {r['origen']}: {r['activos']} activos, {r['software']} programas, "
                          f"{r['nuevos']} nuevos, {r['cambiados']} cambiados, {r['desaparecidos']} "
                          f"desaparecidos ({r.get('duracion_ms', 0) / 1000:.1f} s)")
            if all(r.get("error") for r in resultados):
                print("        ningún origen sincronizado; se conserva el inventario anterior")
            else:
                creadas = ocs.sembrar_mapa(conn)
                nuevas = ocs.sembrar_tecnologias(conn)
                if creadas or nuevas["tecnologias"]:
                    print(f"        mapa de nombres: {creadas + nuevas['reglas']} reglas base nuevas, "
                          f"{nuevas['tecnologias']} tecnologías sugeridas creadas")
                mapa = ocs.aplicar_mapa(conn)
                pct = (mapa["instalaciones_mapeadas"] * 100.0 / mapa["instalaciones"]) if mapa["instalaciones"] else 0.0
                print(f"\n  [2/4] Mapa de nombres: {mapa['nombres_mapeados']} de {mapa['nombres']} nombres "
                      f"clasificados; {mapa['instalaciones_mapeadas']} de {mapa['instalaciones']} instalaciones "
                      f"({pct:.1f} %)")
                ocs.actualizar_inventario_desde_ocs(conn, cfg=cfg)
                hallazgos = ocs.detectar_hallazgos(conn, cfg=cfg)
                print("        hallazgos: " + ", ".join(
                    f"{h['abiertos']} {ocs.TIPO_HALLAZGO_ES[t].lower()}" for t, h in hallazgos.items()))

        print("\n  [3/4] Fin de soporte (endoflife.date)...")
        eol = aplicabilidad.actualizar_fin_soporte(conn, cfg=cfg, forzar=args.forzar_fin_soporte)
        if eol["actualizados"]:
            print(f"        ciclos actualizados: {', '.join(eol['actualizados'])}")
        else:
            print("        ciclos en caché (menos de una semana)")
        for e in eol["errores"]:
            print(f"        aviso: {e}")
        fs = aplicabilidad.hallazgos_fin_soporte(conn)
        print(f"        {fs['abiertos']} activo(s) fuera de soporte ({fs['nuevos']} nuevos, {fs['cerrados']} resueltos)")
        n = aplicabilidad.recalcular_resumenes(conn, cfg=cfg)
        print(f"        recuentos por amenaza actualizados ({n}) con el entorno y la presencia actuales de los activos")
        # v6: boletines de Microsoft (la evaluacion de los equipos Windows va DESPUES de
        # evaluar_pendientes, que borra las filas antiguas de cada amenaza reevaluada, y
        # ANTES de remediacion.sincronizar, que las necesita para no cerrar nada en falso).
        ms = {}
        if not args.sin_aplicabilidad:
            ms = msrc.actualizar(conn, cfg=cfg)
            if not ms.get("omitido"):
                print(f"        boletines de Microsoft: {len(ms.get('descargados', []))} descargado(s), "
                      f"{ms.get('correcciones', 0)} correcciones")
            for e in ms.get("errores", []):
                print(f"        aviso MSRC: {e}")

        if args.sin_aplicabilidad:
            print("\n  [4/4] Aplicabilidad omitida")
        else:
            print("\n  [4/4] Evaluando amenazas con CVE contra los activos...")
            if args.reevaluar:
                n = conn.execute("UPDATE aplicabilidad_amenaza SET evaluado_at='2000-01-01T00:00:00Z'").rowcount
                print(f"        {n} amenazas marcadas para reevaluar")
            osv = aplicabilidad.ClienteOSV(conn, cfg=cfg, max_peticiones=args.max_osv)
            stats = aplicabilidad.evaluar_pendientes(conn, cfg=cfg, limite=args.max_amenazas, osv=osv)
            if stats.get("omitido"):
                print(f"        omitida: {stats.get('motivo')}")
            else:
                print(f"        {stats['evaluadas']} de {stats['candidatas']} amenazas candidatas evaluadas; "
                      f"{stats['con_afectados']} con activos afectados ({stats['activos_afectados']} activos); "
                      f"{stats['incompletas']} incompletas; OSV: {stats['peticiones_osv']} consultas, "
                      f"{stats['cache_osv']} desde caché"
                      + (f"; cupo de OSV agotado: {stats.get('aplazadas', 0)} aplazadas a la próxima ejecución"
                         if stats.get("cupo_agotado") else ""))
        # v6: nivel de parche de Windows (siempre tras la evaluacion principal)
        ev = msrc.evaluar_activos(conn, cfg=cfg)
        if ev.get("omitido"):
            print(f"        parches de Windows: omitido ({ev.get('motivo')})")
        else:
            print(f"        parches de Windows: {ev['con_kb']} de {ev['activos']} equipos con KB conocida, "
                  f"{ev['filas']} veredictos ({ev['afectados']} afectados)")
        # v6: abrir y cerrar remediaciones segun los veredictos actuales (despues de msrc)
        rem = remediacion.sincronizar(conn)
        print(f"        remediación: {rem['abiertas_nuevas']} nuevas, {rem['cerradas']} corregidas, "
              f"{rem['activo_ausente']} de activos retirados, {rem['abiertas']} pendientes")
        # v7: correcciones que todavia no existen
        pp = parches.sincronizar(conn, cfg=cfg)
        print(f"        correcciones pendientes: {pp['nuevas']} nuevas, {pp['cerradas']} ya con versión, "
              f"{pp['en_seguimiento']} en seguimiento")
        print(f"\n  Terminado en {time.perf_counter() - inicio:.0f} s\n")
        log.info("sincronizacion OCS y aplicabilidad terminadas", extra={"fallos": fallos})
        return 1 if fallos else 0
    except Exception as exc:  # noqa: BLE001
        log.error("fallo sincronizar_ocs", extra={"error": str(exc)}, exc_info=True)
        print(f"\n  ERROR: {type(exc).__name__}: {exc}\n")
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
