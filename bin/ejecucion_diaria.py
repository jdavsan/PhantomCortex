#!/usr/bin/env python3
"""Ejecucion diaria: recolectar, enriquecer, correlacionar y alertar.

Sustituye a `sistema_produccion.sh` + `collect_threats_rss.py` +
`send_alert_now.py`. Diferencias operativas:

  * Si algo falla, se avisa al administrador por correo. El sistema anterior
    imprimia el error en el log y seguia como si nada, que es la razon de que
    10 de 35 fuentes llevaran 33 dias caidas sin que nadie lo supiera.

  * El codigo de salida distingue exito (0), exito parcial (0 con aviso) y
    fallo (1), para que el cron y la monitorizacion puedan actuar.

  * Verifica la credencial SMTP y avisa de su caducidad antes de que las
    alertas dejen de entregarse.
"""
from __future__ import annotations

import argparse
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import alertas_proceso, msrc, remediacion  # noqa: E402  (v6)
from threatintel import libro_alerta, parches  # noqa: E402  (v7)
from threatintel import programacion  # noqa: E402  (v9: horario del programador)
from threatintel import (aplicabilidad, collector, config, credentials, db,  # noqa: E402
                         enrich, health, notify, ocs, queries, scoring)
from threatintel.logging_setup import get_logger, setup            # noqa: E402
from threatintel.paths import LOGS_DIR, ensure_dirs                # noqa: E402


def _titulos(vistas: list[dict], maximo: int = 10) -> list[str]:
    lineas = []
    for i, a in enumerate(vistas[:maximo], start=1):
        titulo = (a.get("title_es") or a.get("title_en") or "")[:90]
        etiqueta = notify.severidad_texto(a.get("severity"))
        extra = " · KEV" if a.get("in_kev") else ""
        lineas.append(f"    {i:>2}. {titulo}  [{etiqueta}, relevancia "
                      f"{int(round(float(a.get('relevance') or 0)))}{extra}]")
    return lineas


def comparar_criterios(conn, cfg) -> dict:
    """Compara, sin escribir ni enviar nada, cuantas amenazas pendientes
    alertaria el criterio antiguo (severidad >= alert_min_severity) frente al
    nuevo (relevancia >= alert_min_relevance o KEV, con identificador y sin
    severidades estimadas recientes). Imprime los titulos de las 10 primeras
    de cada uno. Sirve para enseñar la diferencia al operador antes de activar.
    """
    minimo = cfg.get("alert_min_severity", "High") or "High"
    solo_afectadas = bool(cfg.get("alert_only_affected_versions"))
    antiguo = queries.pendientes_de_alerta(conn, min_severidad=minimo,
                                           solo_afectadas=solo_afectadas)
    clasificacion = queries.clasificar_pendientes(conn, cfg=cfg, persistir=False)
    nuevo = clasificacion["alertar"]
    # Efecto aislado del criterio de afectacion real (2026-09-08): la misma
    # clasificacion con el filtro apagado, para ver cuantas se dejan de alertar
    # por no afectar a ninguna maquina. No escribe nada (persistir=False).
    sin_afectacion = queries.clasificar_pendientes(
        conn, cfg=cfg, persistir=False, solo_con_activos=False)["alertar"]
    conteo = clasificacion["conteo"]
    pendientes_total = len(nuevo) + sum(conteo.values())

    umbral = int(float(cfg.get("alert_min_relevance", 50) or 0))
    horas = int(float(cfg.get("alert_defer_heuristic_hours", 24) or 0))
    ids_antiguo = {a["id"] for a in antiguo}
    ids_nuevo = {a["id"] for a in nuevo}
    kev_antiguo = sum(1 for a in antiguo if a.get("in_kev"))
    kev_nuevo = sum(1 for a in nuevo if a.get("in_kev"))

    print(f"\n  Comparación de criterios sobre las {pendientes_total} amenazas "
          f"pendientes de alertar (nunca alertadas)\n")
    print(f"  Criterio antiguo (severidad >= {notify.severidad_texto(minimo)}"
          f"{', solo versiones afectadas' if solo_afectadas else ''}): "
          f"{len(antiguo)} alertarían, {kev_antiguo} en KEV")
    print("\n".join(_titulos(antiguo)) or "    (ninguna)")
    print(f"\n  Criterio nuevo (afectación confirmada en alguna máquina del inventario; "
          f"relevancia >= {umbral} o KEV; con CVE o identificador de aviso; severidad "
          f"estimada con {horas} h de espera): "
          f"{len(nuevo)} alertarían, {kev_nuevo} en KEV")
    print("\n".join(_titulos(nuevo)) or "    (ninguna)")

    ids_sin_afectacion = {a["id"] for a in sin_afectacion}
    solo_por_afectacion = len(ids_sin_afectacion - ids_nuevo)
    kev_sin_confirmar = sum(1 for a in nuevo if a.get("kev_sin_activos_confirmados"))
    print(f"\n  Criterio de afectación real (2026-09-08): sin él alertarían "
          f"{len(sin_afectacion)}; con él, {len(nuevo)}. Se dejan de alertar "
          f"{solo_por_afectacion} por no tener la afectación confirmada en ninguna "
          f"máquina del inventario"
          f"{f'; {kev_sin_confirmar} en KEV se alertan sin activo confirmado' if kev_sin_confirmar else ''}")

    print(f"\n  Excluidas por el criterio nuevo: {sum(conteo.values())}")
    for motivo in queries.MOTIVOS_EXCLUSION:
        if conteo.get(motivo):
            print(f"    - {conteo[motivo]:>4} {motivo.replace('_', ' ')}: "
                  f"{queries.MOTIVO_EXCLUSION_ES[motivo]}")
    print(f"\n  Solo en el antiguo: {len(ids_antiguo - ids_nuevo)} · "
          f"solo en el nuevo: {len(ids_nuevo - ids_antiguo)} · "
          f"en ambos: {len(ids_antiguo & ids_nuevo)}")
    print("  No se ha escrito ni enviado nada.\n")
    return {"antiguo": len(antiguo), "nuevo": len(nuevo), "excluidas": dict(conteo),
            "kev_antiguo": kev_antiguo, "kev_nuevo": kev_nuevo,
            "sin_filtro_afectacion": len(sin_afectacion),
            "solo_por_afectacion": solo_por_afectacion,
            "kev_sin_confirmar": kev_sin_confirmar}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true",
                        help="no escribe en la base de datos ni envia correo")
    parser.add_argument("--solo-alerta", action="store_true",
                        help="solo clasificar y enviar la alerta: no consulta OCS, no recolecta, "
                             "no enriquece y no exporta. Es la segunda fase de las 08:00, "
                             "que se apoya en el trabajo que hizo la de las 07:30")
    parser.add_argument("--sin-ocs", action="store_true",
                        help="no consultar OCS Inventory (ya lo hizo otra ejecucion)")
    parser.add_argument("--sin-alerta", action="store_true",
                        help="recolecta y enriquece, pero no envia la alerta")
    parser.add_argument("--sin-enriquecer", action="store_true",
                        help="omite las consultas a NVD, KEV y EPSS")
    parser.add_argument("--fuente", default=None,
                        help="limita la recoleccion a una sola fuente (slug)")
    parser.add_argument("--comparar", action="store_true",
                        help="solo compara el criterio antiguo (severidad >= Alta) con "
                             "el nuevo (relevancia o KEV) sobre las pendientes; no "
                             "recolecta, no escribe ni envía nada")
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    ensure_dirs()
    marca = datetime.now().strftime("%Y%m%d_%H%M%S")
    setup(level="INFO", log_file="threatintel.jsonl")
    log = get_logger("diaria")

    db.init_db(args.db)
    conn = db.connect(args.db)
    execution_id: int | None = None
    stats: dict = {}
    alertadas = 0

    try:
        cfg = config.load(conn)
    except config.ConfigError as exc:
        log.error("configuracion invalida", extra={"error": str(exc)})
        print(f"\n  ERROR de configuracion: {exc}\n")
        conn.close()
        return 1

    mailer = notify.Mailer(cfg, dry_run=args.dry_run)

    if args.comparar:
        # Solo lectura: enseña la diferencia entre criterios antes de activar.
        try:
            comparar_criterios(conn, cfg)
            return 0
        finally:
            conn.close()

    try:
        if not args.dry_run:
            execution_id = collector.iniciar_ejecucion(
                conn, "daily", str(LOGS_DIR / f"threatintel.jsonl#{marca}"))

        # El horario del programador lo registra quien puede leerlo: la interfaz web no
        # puede (NoNewPrivileges impide que «crontab» tome su grupo) y la pagina de
        # «Consultas a OCS» necesita decir a que hora se ejecuta esto.
        try:
            programacion.registrar(conn)
        except Exception as exc:  # noqa: BLE001 - es informativo, no debe cortar nada
            log.warning("no se pudo registrar el horario del programador",
                        extra={"error": str(exc)})

        # --------------------------------------------- 0. inventario real (OCS)
        if args.dry_run or args.solo_alerta or args.sin_ocs or not cfg.get("ocs_sync_enabled", True):
            motivo = ("ya la hizo la ejecución de las 07:30" if (args.solo_alerta or args.sin_ocs)
                      else "simulación" if args.dry_run else "desactivada en Ajustes")
            print(f"\n  [0/6] Sincronización con OCS Inventory omitida ({motivo})")
            if args.solo_alerta or args.sin_ocs:
                # Que se vea con qué inventario se va a alertar: si la fase de las 07:30
                # falló, el correo saldría con datos viejos y hay que saberlo.
                fila = conn.execute(
                    "SELECT MAX(started_at) FROM sync_ocs WHERE status='success'").fetchone()
                ultima = fila[0] if fila else None
                if not ultima:
                    print("        AVISO: no hay ninguna consulta a OCS correcta registrada")
                    log.error("se va a alertar sin ninguna consulta a OCS previa")
                else:
                    from datetime import datetime as _dt, timezone as _tz
                    horas = (_dt.now(_tz.utc) - _dt.fromisoformat(
                        ultima.replace("Z", "+00:00"))).total_seconds() / 3600
                    print(f"        inventario de hace {horas:.1f} h (última consulta correcta: {ultima})")
                    if horas > 6:
                        print("        AVISO: el inventario tiene más de 6 horas; "
                              "revise la consulta de las 07:30 en Administración → Consultas a OCS")
                        log.error("inventario viejo al alertar",
                                  extra={"horas": round(horas, 1), "ultima": ultima})
        else:
            print("\n  [0/6] Sincronizando el inventario real desde OCS Inventory...")
            try:
                for r in ocs.sincronizar(conn, secretos=cfg.secrets, cfg=cfg):
                    if r.get("error"):
                        print(f"        {r['origen']}: ERROR {r['error']}")
                    else:
                        print(f"        {r['origen']}: {r['activos']} activos, {r['nuevos']} nuevos, "
                              f"{r['cambiados']} con cambios, {r['desaparecidos']} desaparecidos")
                eol = aplicabilidad.actualizar_fin_soporte(conn, cfg=cfg)
                fs = aplicabilidad.hallazgos_fin_soporte(conn)
                aplicabilidad.recalcular_resumenes(conn, cfg=cfg)
                print(f"        fin de soporte: {fs['abiertos']} activo(s) fuera de soporte"
                      + (f"; ciclos actualizados: {', '.join(eol['actualizados'])}" if eol["actualizados"] else ""))
                # v6: nivel de parche de Windows (boletines de Microsoft) y cierre de remediaciones
                try:
                    ms = msrc.actualizar(conn, cfg=cfg)
                    ev = msrc.evaluar_activos(conn, cfg=cfg)
                    if ev.get("omitido"):
                        print(f"        parches de Windows: omitido ({ev.get('motivo')})")
                    else:
                        print(f"        parches de Windows: {len(ms.get('descargados', []))} boletín(es) nuevo(s), "
                              f"{ev['con_kb']} de {ev['activos']} máquinas con Windows y KB conocida, "
                              f"{ev['afectados']} veredictos de afectado")
                except Exception as exc:  # noqa: BLE001
                    log.error("fallo el motor MSRC", extra={"error": str(exc)}, exc_info=True)
                    print(f"        ERROR en los parches de Windows: {exc}")
                rem = remediacion.sincronizar(conn)
                print(f"        remediación: {rem['abiertas_nuevas']} nuevas, {rem['cerradas']} corregidas, "
                      f"{rem['abiertas']} pendientes")
            except Exception as exc:  # noqa: BLE001 - el inventario anterior sigue valiendo
                log.error("fallo la sincronizacion OCS en la diaria", extra={"error": str(exc)}, exc_info=True)
                print(f"        ERROR en la sincronización: {exc} (se conserva el inventario anterior)")

        # ------------------------------------------------- 1. recoleccion
        stats: dict = {}
        if args.solo_alerta:
            print("\n  [1/6] Recolección omitida (ya la hizo la ejecución de las 07:30)")
        else:
            print("\n  [1/6] Recolectando desde las fuentes activas...")
            stats = collector.recolectar(conn, cfg=cfg, solo_fuente=args.fuente,
                                         dry_run=args.dry_run)
            print(f"        {stats['fuentes_ok']}/{stats['fuentes']} fuentes correctas, "
                  f"{stats['nuevas']} amenazas nuevas, "
                  f"{stats['reaparecidas']} reaparecidas")
            if stats["fuentes_fallo"]:
                print(f"        {stats['fuentes_fallo']} fuente(s) con fallo:")
                for f in stats["fuentes_con_fallo"][:8]:
                    print(f"          - {f['name']}: {f['error']}")

        # ------------------------------------------------ 2. enriquecimiento
        if args.sin_enriquecer or args.dry_run or args.solo_alerta:
            print("\n  [2/6] Enriquecimiento omitido"
                  + (" (ya lo hizo la ejecución de las 07:30)" if args.solo_alerta else ""))
            enriquecidas = {}
        else:
            print("\n  [2/6] Enriqueciendo con NVD, CISA KEV y EPSS...")
            enriquecidas = enrich.enriquecer_pendientes(conn, cfg=cfg)
            try:
                rep = enrich.repasar_descripciones(
                    conn, cfg=cfg, limite=int(cfg.get("descripcion_repaso_limite", 25) or 0))
                if rep.get("revisadas"):
                    print(f"        descripciones repasadas: {rep['revisadas']} de {rep.get('candidatas', 0)} "
                          f"con descripción de relleno; {rep.get('resueltas', 0)} completadas, "
                          f"{rep.get('sin_dato', 0)} sin publicar todavía")
            except Exception as exc:  # noqa: BLE001
                log.error("fallo el repaso de descripciones", extra={"error": str(exc)}, exc_info=True)
            print(f"        {enriquecidas.get('con_cvss_real', 0)} con CVSS oficial, "
                  f"{enriquecidas.get('en_kev', 0)} con explotacion confirmada, "
                  f"{enriquecidas.get('reclasificadas', 0)} reclasificadas")

            # Aplicabilidad por activo: ¿que equipos tienen de verdad la version vulnerable?
            try:
                apl = aplicabilidad.evaluar_pendientes(conn, cfg=cfg)
                if apl.get("omitido"):
                    print(f"        aplicabilidad por activo omitida: {apl.get('motivo')}")
                else:
                    print(f"        aplicabilidad por activo: {apl['evaluadas']} amenazas evaluadas, "
                          f"{apl['con_afectados']} con activos afectados ({apl['activos_afectados']} activos), "
                          f"{apl['peticiones_osv']} consultas a OSV.dev"
                          + (f"; cupo de OSV agotado, {apl.get('aplazadas', 0)} aplazadas" if apl.get("cupo_agotado") else ""))
            except Exception as exc:  # noqa: BLE001
                log.error("fallo la aplicabilidad por activo", extra={"error": str(exc)}, exc_info=True)
                print(f"        ERROR en la aplicabilidad por activo: {exc}")
            # v6: las amenazas nuevas de Windows se evaluan con MSRC y se abren sus remediaciones
            try:
                ev = msrc.evaluar_activos(conn, cfg=cfg)
                if not ev.get("omitido"):
                    print(f"        parches de Windows: {ev['filas']} veredictos, {ev['afectados']} afectados")
                rem = remediacion.sincronizar(conn)
                if rem["abiertas_nuevas"] or rem["cerradas"]:
                    print(f"        remediación: {rem['abiertas_nuevas']} nuevas, {rem['cerradas']} corregidas")
            except Exception as exc:  # noqa: BLE001
                log.error("fallo MSRC o remediacion tras el enriquecimiento", extra={"error": str(exc)}, exc_info=True)
            # v7: correcciones que todavia no existen: seguimiento y busqueda diaria
            try:
                pp = parches.sincronizar(conn, cfg=cfg)
                bus = parches.buscar(conn, cfg=cfg)
                if bus.get("omitido"):
                    print(f"        correcciones pendientes: {pp['en_seguimiento']} en seguimiento "
                          f"(búsqueda omitida: {bus.get('motivo')})")
                else:
                    print(f"        correcciones pendientes: {pp['en_seguimiento']} en seguimiento, "
                          f"{bus['consultadas']} consultadas, {bus['encontradas']} ya disponibles")
            except Exception as exc:  # noqa: BLE001
                log.error("fallo el seguimiento de parches", extra={"error": str(exc)}, exc_info=True)
                print(f"        ERROR en las correcciones pendientes: {exc}")

        # --------------------------------------------- 3. credencial de correo
        print("\n  [3/6] Comprobando la credencial de correo...")
        if args.dry_run:
            print("        omitido en dry-run")
            avisos_cred = []
        else:
            if cfg.get("smtp_verify_on_daily_run", True):
                ok_smtp, error_smtp = credentials.verificar(conn, cfg=cfg,
                                                            mailer=mailer)
                estado_cred = credentials.estado(conn, cfg=cfg)
                print(f"        {'correcta' if ok_smtp else 'FALLO'}: "
                      f"{estado_cred['mensaje']}")
            avisos_cred = credentials.revisar_y_avisar(conn, cfg=cfg, mailer=mailer)
            for a in avisos_cred:
                print(f"        aviso enviado: {a['titulo']}")

        # ------------------------------------------------- 4. salud de fuentes
        if args.solo_alerta:
            print("\n  [4/6] Salud de las fuentes omitida (ya la revisó la de las 07:30)")
        else:
            print("\n  [4/6] Revisando la salud de las fuentes...")
        if args.dry_run:
            print("        omitido en dry-run")
            avisos_salud = []
        else:
            avisos_salud = health.revisar_y_avisar(conn, cfg=cfg, mailer=mailer)
            # Caducidad del certificado HTTPS (2026-09-08): un aviso semanal con antelacion.
            try:
                from threatintel import certificado
                aviso_cert = certificado.avisar(conn, cfg=cfg, mailer=mailer)
                if aviso_cert:
                    avisos_salud = list(avisos_salud) + [aviso_cert]
            except Exception as exc:  # noqa: BLE001
                log.error("fallo el aviso de caducidad del certificado", extra={"error": str(exc)})
            # Excepciones con vencimiento (v13, 2026-09-10): avisa de las aceptaciones de
            # riesgo que caducan en los proximos «excepciones_aviso_dias» dias y de las ya
            # vencidas, como maximo una vez por semana cada una. Al vencer, la
            # vulnerabilidad vuelve sola a la cola: el aviso es para que nadie se entere
            # tarde. Va en la diaria y no en el semanal porque el semanal puede llegar seis
            # dias despues y dejar una excepcion de quince dias sin margen.
            try:
                from threatintel import excepciones as _excepciones
                aviso_exc = _excepciones.avisar(conn, cfg=cfg, mailer=mailer)
                if aviso_exc:
                    avisos_salud = list(avisos_salud) + [aviso_exc]
                    print(f"        excepciones: {aviso_exc['vencidas']} vencida(s), "
                          f"{aviso_exc['por_vencer']} por vencer y "
                          f"{aviso_exc.get('revision', 0)} permanente(s) sin revisar")
            except Exception as exc:  # noqa: BLE001
                log.error("fallo el aviso de excepciones con vencimiento",
                          extra={"error": str(exc)})
            resumen_f = health.resumen_fuentes(conn, ventana=10, cfg=cfg)
            caidas = [f for f in resumen_f if f["estado"] == "caida"]
            print(f"        {len(caidas)} caida(s), "
                  f"{sum(1 for f in resumen_f if f['estado'] == 'degradada')} "
                  f"degradada(s)")
            for a in avisos_salud:
                print(f"        aviso enviado: {a['titulo']}")

        # --------------------------------------------------------- 5. alerta
        print("\n  [5/6] Preparando la alerta...")
        # EVALUAR ANTES DE DECIDIR (2026-09-10). Peticion del usuario tras el correo de
        # ese dia: «me debe alertar lo que realmente me este afectando, de lo contrario
        # no». Se alertaron 35 amenazas y 4 no tenian ningun activo afectado confirmado:
        # las cuatro NUNCA se habian evaluado —el cupo de reparto de
        # `applicability_max_threats_per_run` (150) se lo llevaron las 923 amenazas nuevas
        # del dia— y el filtro se abstenia para no callar nada por un fallo propio.
        #
        # Ahora, antes de aplicar el filtro, se evaluan DIRIGIDAS las candidatas a alertar
        # que no tienen evaluacion utilizable: son unas pocas (7 ese dia, 4 con CVE), se
        # evaluan sin el cupo de reparto y con su propio tope de seguridad, y asi la
        # decision se toma con datos en la mano. Lo que despues de esto siga sin evaluar NO
        # se alerta (motivo `sin_evaluar_todavia`) y se avisa a administracion aparte.
        aviso_sin_evaluar = None
        sin_evaluar_tras_evaluar: list = []
        candidatas = queries.candidatas_sin_evaluacion(conn, cfg=cfg)
        if not candidatas:
            print("        todas las candidatas a alertar tienen su evaluación al día")
        elif args.dry_run:
            print(f"        {len(candidatas)} candidata(s) sin evaluación: "
                  f"evaluación dirigida omitida en dry-run")
        else:
            print(f"        {len(candidatas)} candidata(s) a alertar sin evaluación: "
                  f"evaluando dirigido antes de decidir...")
            t_dirigida = time.perf_counter()
            try:
                dirigida = aplicabilidad.evaluar_dirigido(
                    conn, [c["id"] for c in candidatas], cfg=cfg)
                segundos = time.perf_counter() - t_dirigida
                if dirigida.get("omitido"):
                    print(f"        evaluación dirigida omitida: {dirigida.get('motivo')}")
                else:
                    print(f"        evaluación dirigida: {dirigida['evaluadas']} evaluadas en "
                          f"{segundos:.1f} s, {dirigida['con_afectados']} con activos afectados "
                          f"({dirigida['activos_afectados']} activos), "
                          f"{dirigida['peticiones_osv']} consultas a OSV.dev")
                log.info("evaluacion dirigida antes de la alerta",
                         extra={"candidatas": len(candidatas), "segundos": round(segundos, 2),
                                **{k: v for k, v in dirigida.items() if k != "sin_evaluar"}})
                # Lo que no se pudo evaluar, con lo que se sabe de cada amenaza, para el
                # aviso de administracion: un fallo tecnico no puede callar nada en silencio.
                por_id = {c["id"]: c for c in candidatas}
                sin_evaluar_tras_evaluar = [
                    {**por_id.get(p["id"], {}), **p} for p in dirigida.get("sin_evaluar") or []]
                # Las remediaciones de lo que acabe de confirmarse tambien se abren ahora,
                # para que la cola no vaya un dia por detras del correo.
                if dirigida.get("con_afectados"):
                    remediacion.sincronizar(conn)
            except Exception as exc:  # noqa: BLE001 - la alerta se envia igual
                log.error("fallo la evaluacion dirigida previa a la alerta",
                          extra={"error": str(exc)}, exc_info=True)
                print(f"        ERROR en la evaluación dirigida: {exc}")
                sin_evaluar_tras_evaluar = [{**c, "motivo": "error", "error": str(exc)}
                                            for c in candidatas]
        # Criterio del 2026-09-04: relevancia minima o KEV, con identificador y
        # sin severidades estimadas recien llegadas. Desde el 2026-09-08 se anade
        # la afectacion real: sin ningun activo presente confirmado como afectado
        # no se alerta. Desde el 2026-09-10, tampoco se alerta lo que no se ha podido
        # evaluar (`sin_evaluar_todavia`) ni la explotacion activa sin afectacion
        # confirmada (ajuste `alert_kev_sin_activos`, apagado por omision). Las excluidas
        # quedan con su motivo en alert_skip_reason (salvo en dry-run, que no escribe).
        clasificacion = queries.clasificar_pendientes(
            conn, cfg=cfg, persistir=not args.dry_run)
        pendientes = clasificacion["alertar"][:500]
        excluidas = clasificacion["conteo"]
        total_excluidas = sum(excluidas.values())
        umbral = int(float(cfg.get("alert_min_relevance", 50) or 0))
        solo_con_activos = bool(cfg.get("alert_solo_con_activos_afectados", True))
        # Las KEV que se alertan sin que ningun activo lo confirme: el correo tiene
        # que decirlo para que nadie las lea como «tenemos esto y nos afecta».
        kev_sin_confirmar = sum(1 for a in pendientes
                                if a.get("kev_sin_activos_confirmados"))
        print(f"        {len(pendientes)} para alertar (relevancia >= {umbral} o KEV"
              f"{', y con la afectación confirmada en alguna máquina' if solo_con_activos else ''}), "
              f"{total_excluidas} excluidas por el filtro")
        if excluidas.get("sin_activos_confirmados"):
            print(f"        {excluidas['sin_activos_confirmados']} no se alertan porque no se ha "
                  f"confirmado la versión vulnerable en ninguna máquina del inventario")
        if kev_sin_confirmar:
            print(f"        {kev_sin_confirmar} en KEV se alertan sin activo confirmado "
                  f"(explotación activa)")
        for motivo in queries.MOTIVOS_EXCLUSION:
            if excluidas.get(motivo):
                print(f"          - {excluidas[motivo]} {motivo.replace('_', ' ')}: "
                      f"{queries.MOTIVO_EXCLUSION_ES[motivo]}")
        # Aviso de administracion por lo que no se pudo evaluar (2026-09-10). Se limita a
        # las que el filtro dejo fuera por ese motivo: si una candidata acabo alertandose
        # igual (por ejemplo porque el criterio de afectacion esta desactivado), no hay
        # nada que avisar. Va DESPUES de la clasificacion, con el resultado real delante.
        if sin_evaluar_tras_evaluar and not args.dry_run:
            ids_sin_evaluar = set(clasificacion["excluidas"].get("sin_evaluar_todavia") or [])
            pendientes_aviso = [p for p in sin_evaluar_tras_evaluar
                                if p.get("id") in ids_sin_evaluar]
            if pendientes_aviso:
                try:
                    aviso_sin_evaluar = aplicabilidad.avisar_sin_evaluar(
                        conn, cfg=cfg, pendientes=pendientes_aviso, mailer=mailer)
                    if aviso_sin_evaluar:
                        print(f"        aviso enviado: {aviso_sin_evaluar['titulo']}")
                    else:
                        print(f"        {len(pendientes_aviso)} sin evaluar: aviso ya enviado "
                              f"hoy o sin destinatarios de administración")
                except Exception as exc:  # noqa: BLE001
                    log.error("fallo el aviso de candidatas sin evaluar",
                              extra={"error": str(exc)}, exc_info=True)

        resumen_activos = {}
        try:
            # «En produccion o contingencia» la calcula ocs.resumen desde el 2026-09-10
            # (tarde), con la severidad baja y el riesgo aceptado fuera, igual que el resto
            # de sus cifras: antes esta consulta estaba copiada aqui, en bin/enviar_prueba.py
            # y en webui/vistas/panel.py, y las tres copias contaban con otro criterio.
            resumen_activos = ocs.resumen(conn, cfg=cfg)
        except Exception:  # noqa: BLE001
            resumen_activos = {}
        url_base = config.url_publica(cfg)
        url_base = str(url_base).rstrip("/").removesuffix("/amenazas")

        # Correcciones que aparecieron desde el ultimo correo. Se leen ANTES de decidir
        # si se envia el correo (2026-09-10): una correccion publicada es una novedad
        # accionable por si misma —es lo unico del correo que se puede hacer HOY— y hasta
        # hoy se perdia dos veces. Primero, porque el correo «sin novedades» se
        # renderizaba sin ellas; y segundo, porque con `alert_send_when_empty`
        # desactivado no se enviaba correo ninguno y las correcciones se quedaban sin
        # anunciar hasta el primer dia con amenazas nuevas. Sin sellar todavia: si el
        # envio falla, tienen que salir en el correo siguiente.
        try:
            parches_nuevos = parches.novedades(conn, marcar=False)
        except Exception as exc:  # noqa: BLE001
            log.error("fallo al leer las correcciones nuevas", extra={"error": str(exc)})
            parches_nuevos = []

        def _sellar_correcciones() -> None:
            """Marca las correcciones como avisadas, solo si el correo salio."""
            if parches_nuevos and not args.dry_run:
                try:
                    parches.novedades(conn, marcar=True)
                except Exception as exc:  # noqa: BLE001
                    log.error("no se pudieron marcar las correcciones avisadas",
                              extra={"error": str(exc)})

        if not cfg.get("alert_enabled", True):
            print("        las alertas están desactivadas en los ajustes")
        elif not pendientes and not cfg.get("alert_send_when_empty", True) and not parches_nuevos:
            print("        no hay amenazas nuevas que superen el criterio de alerta")
        elif not pendientes and args.sin_alerta:
            print("        sin novedades (envío omitido)")
        elif not pendientes:
            if parches_nuevos and not cfg.get("alert_send_when_empty", True):
                print(f"        sin amenazas nuevas, pero hay {len(parches_nuevos)} "
                      f"corrección(es) publicada(s) que anunciar: se envía igualmente")
            html = notify.render_alert_email([], {
                "periodo": datetime.now().strftime("%Y-%m"), "url_interfaz": f"{url_base}/amenazas/",
                "url_activos": f"{url_base}/activos/", "resumen_activos": resumen_activos,
                # La seccion «Ya se puede aplicar» va también en el correo sin amenazas
                # nuevas, que es justo el dia en que hay tiempo de aplicarlas.
                "parches_nuevos": parches_nuevos,
                "filtro": {"alertadas": 0, "excluidas": dict(excluidas), "umbral_relevancia": umbral,
                           "min_confianza": float(cfg.get("alert_min_match_confidence", 0.6) or 0.0),
                           "ignorar_criticidad_baja": bool(cfg.get("ignore_low_criticality", True)),
                           "solo_con_activos": solo_con_activos,
                           "sin_activos_confirmados": int(excluidas.get("sin_activos_confirmados", 0)),
                           "kev_sin_confirmar": kev_sin_confirmar}})
            if mailer.send(subject=notify.asunto_alerta(0, 0, 0), html=html, to=cfg.alert_to, cc=cfg.alert_cc):
                print(f"        correo «sin novedades» enviado -> {', '.join(cfg.alert_to)}")
                if parches_nuevos:
                    print(f"        incluye {len(parches_nuevos)} corrección(es) ya disponible(s)")
                _sellar_correcciones()
            else:
                print("        ERROR: el correo «sin novedades» no se pudo enviar")
        elif args.sin_alerta:
            print(f"        {len(pendientes)} amenazas pendientes (envio omitido)")
        else:
            criticas = sum(1 for a in pendientes if a["severity"] == "Critical")
            altas = sum(1 for a in pendientes if a["severity"] == "High")
            kev = sum(1 for a in pendientes if a["in_kev"])
            # Activos con la version vulnerable (OCS) para cada amenaza alertada: distintos
            aplicabilidad.adjuntar_activos(conn, pendientes, limite=10)
            activos_afectados = aplicabilidad.activos_distintos(conn, [a["id"] for a in pendientes])

            # Impacto y remediacion se redactan al alertar, no antes: dependen
            # de la severidad definitiva y de las tecnologias correlacionadas.
            from threatintel import translate
            # Se redactan para todas las que van al libro de calculo, no solo para las que
            # se detallan en el correo: el libro las lleva todas y «Sin redactar.» no sirve
            # a quien reparte el trabajo (revision del 2026-09-06).
            n_redactar = len(pendientes) if cfg.get("alert_adjuntar_excel", True) \
                else int(cfg.get("alert_max_items", 25) or 25)
            for amenaza in pendientes[:n_redactar]:
                if not amenaza.get("impact_es"):
                    amenaza["impact_es"] = translate.generar_impacto(
                        amenaza, cfg=cfg, conn=conn)
                if not amenaza.get("remediation_es"):
                    amenaza["remediation_es"] = translate.generar_remediacion(
                        amenaza, cfg=cfg, conn=conn)
                if not args.dry_run:
                    conn.execute(
                        "UPDATE threats SET impact_es=?, remediation_es=? WHERE id=?",
                        (amenaza["impact_es"], amenaza["remediation_es"],
                         amenaza["id"]))

            url = f"{url_base}/amenazas/"
            # v7: las correcciones nuevas ya se leyeron arriba, antes de decidir si se
            # envia el correo, para que no se pierdan los dias sin amenazas nuevas.
            # v7: hoja de calculo con una pestana por vulnerabilidad
            adjuntos = []
            if cfg.get("alert_adjuntar_excel", True):
                try:
                    libro = libro_alerta.generar(conn, pendientes, cfg=cfg,
                                                 meta={"url_base": url_base, "parches_nuevos": parches_nuevos})
                    if libro:
                        adjuntos.append(libro)
                        print(f"        hoja de cálculo adjunta: {libro.name}")
                    # Libro aparte solo con lo que ya se puede aplicar (peticion del 2026-09-06)
                    libro_corr = libro_alerta.generar_correcciones(
                        conn, parches_nuevos, cfg=cfg, meta={"url_base": url_base})
                    if libro_corr:
                        adjuntos.append(libro_corr)
                        print(f"        hoja de correcciones disponibles adjunta: {libro_corr.name}")
                except Exception as exc:  # noqa: BLE001
                    log.error("fallo la hoja de calculo de la alerta", extra={"error": str(exc)}, exc_info=True)
                    print(f"        ERROR al generar la hoja de cálculo: {exc}")
            html = notify.render_alert_email(pendientes, {
                "periodo": datetime.now().strftime("%Y-%m"),
                "max_detalle": int(cfg.get("alert_max_items", 25) or 25),
                # Top 10 de la tabla «Prioridad de actuación» (2026-09-15, peticion del
                # usuario). «alert_max_items» se conserva como tope de seguridad de la
                # tabla y «alert_tabla_top» decide cuantas filas se ven de verdad; el
                # correo dice cuantas quedan fuera y donde estan.
                "tabla_top": int(cfg.get("alert_tabla_top", 10) or 10),
                "max_tabla": int(cfg.get("alert_max_items", 25) or 25),
                "detalle_top": int(cfg.get("alert_detalle_top", 3) or 3),
                # Activos DISTINTOS de LAS AMENAZAS QUE VAN EN ESTE CORREO, no del parque
                # entero: la frase del correo dice «el detalle de cada uno, mas abajo», asi
                # que la cifra tiene que ser la de esas amenazas. `activos_distintos` ya lo
                # calculo arriba y es la misma cifra que se registra en la ejecucion; una
                # consulta del parque completo decia 746 donde eran 685 (revision de
                # seguridad del 2026-09-09). Antes se sumaba por amenaza y un servidor
                # afectado por doce amenazas contaba doce veces.
                "activos_afectados": activos_afectados,
                "parches_nuevos": parches_nuevos,
                # Lo que no se puede corregir todavia: sin version a la que actualizar
                # (el fabricante no la ha publicado, la distribucion no la ha empaquetado
                # o el aviso no la dice). Peticion del usuario del 2026-09-07.
                "sin_correccion": parches.sin_correccion(conn),
                "adjuntos": [p.name for p in adjuntos],
                "url_interfaz": url, "url_activos": f"{url_base}/activos/",
                "resumen_activos": resumen_activos,
                # Pie «Filtro de hoy» del correo: que se excluyo y con que umbrales
                "filtro": {
                    "alertadas": len(pendientes),
                    "excluidas": dict(excluidas),
                    "umbral_relevancia": umbral,
                    "min_confianza": float(
                        cfg.get("alert_min_match_confidence", 0.6) or 0.0),
                    "ignorar_criticidad_baja": bool(cfg.get("ignore_low_criticality", True)),
                    # Afectacion real (2026-09-08): cuantas se callaron por no afectar a
                    # ninguna maquina y cuantas KEV van sin activo confirmado.
                    "solo_con_activos": solo_con_activos,
                    "sin_activos_confirmados": int(excluidas.get("sin_activos_confirmados", 0)),
                    "kev_sin_confirmar": kev_sin_confirmar,
                }})

            enviado = mailer.send(
                subject=notify.asunto_alerta(criticas, altas, kev, total=len(pendientes),
                                             activos=activos_afectados),
                html=html, to=cfg.alert_to, cc=cfg.alert_cc, attachments=adjuntos or None)

            if enviado:
                # v7: ya avisadas; si el envio hubiera fallado seguirian pendientes
                _sellar_correcciones()
                # v6: correo propio para cada proceso de negocio configurado y activo
                if cfg.get("alert_procesos_enabled", True):
                    try:
                        for envio in alertas_proceso.enviar(conn, cfg, mailer, pendientes,
                                                            url_base=url_base, dry_run=args.dry_run):
                            if envio.get("enviado"):
                                print(f"        alerta del proceso «{envio['proceso']}» enviada a {envio['correo']}: "
                                      f"{envio['n_amenazas']} amenazas, {envio['n_activos']} servidores")
                            elif envio.get("error"):
                                print(f"        ERROR alerta del proceso «{envio['proceso']}»: {envio['error']}")
                    except Exception as exc:  # noqa: BLE001
                        log.error("fallo el envio por proceso", extra={"error": str(exc)}, exc_info=True)
                        print(f"        ERROR en las alertas por proceso: {exc}")
                if not args.dry_run:
                    alertadas = queries.marcar_alertadas(
                        conn, [a["id"] for a in pendientes])
                print(f"        alerta enviada: {criticas} criticas, {altas} altas"
                      f"{f', {kev} en KEV' if kev else ''}"
                      f"{f', {activos_afectados} activos afectados' if activos_afectados else ''} "
                      f"-> {', '.join(cfg.alert_to)}")
            else:
                print("        ERROR: la alerta no se pudo enviar")
                log.error("la alerta diaria no se envio",
                          extra={"pendientes": len(pendientes)})

        # ------------------------------------------------------ 6. exportaciones
        if args.solo_alerta:
            print("\n  [6/6] Exportación omitida (ya la hizo la de las 07:30)")
        else:
            print("\n  [6/6] Exportando...")
            if not args.dry_run:
                collector.exportar_json(conn)

        # ------------------------------------------------------------ cierre
        parcial = bool(stats.get("fuentes_fallo"))
        estado = "partial" if parcial else "success"

        if execution_id is not None:
            collector.cerrar_ejecucion(
                conn, execution_id, status=estado,
                sources_ok=stats.get("fuentes_ok", 0),
                sources_failed=stats.get("fuentes_fallo", 0),
                threats_new=stats.get("nuevas", 0),
                threats_alerted=alertadas,
                detalle={k: v for k, v in stats.items()
                         if k != "fuentes_con_fallo"})

        collector.registrar_ultima_ejecucion(estado, {
            "tipo": "alerta" if args.solo_alerta else "daily",
            "fuentes_ok": stats.get("fuentes_ok", 0),
            "fuentes_fallo": stats.get("fuentes_fallo", 0),
            "amenazas_nuevas": stats.get("nuevas", 0),
            "alertadas": alertadas,
        })

        print(f"\n  Ejecucion {'parcial' if parcial else 'completada'}: "
              f"{stats.get('nuevas', 0)} amenazas nuevas, {alertadas} alertadas\n")
        log.info("ejecucion diaria terminada",
                 extra={"estado": estado, "nuevas": stats.get("nuevas", 0),
                        "alertadas": alertadas})
        return 0

    except Exception as exc:  # noqa: BLE001 - se informa y se avisa
        traza = traceback.format_exc()
        log.error("la ejecucion diaria ha fallado",
                  extra={"error": str(exc)}, exc_info=True)
        print(f"\n  ERROR: {type(exc).__name__}: {exc}\n")

        if execution_id is not None:
            try:
                collector.cerrar_ejecucion(
                    conn, execution_id, status="failed",
                    sources_ok=stats.get("fuentes_ok", 0),
                    sources_failed=stats.get("fuentes_fallo", 0),
                    error=f"{type(exc).__name__}: {exc}")
                # Avisar al administrador: esto es lo que faltaba antes
                health.avisar_ejecucion_fallida(
                    conn, cfg=cfg, execution_id=execution_id,
                    error=traza[-1500:], mailer=mailer)
            except Exception:  # noqa: BLE001
                log.error("no se pudo registrar ni avisar del fallo", exc_info=True)

        collector.registrar_ultima_ejecucion("failed", {
            "tipo": "daily", "error": f"{type(exc).__name__}: {exc}"})
        return 1

    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
