#!/usr/bin/env python3
"""Envia a UNA direccion concreta una copia de prueba de la alerta diaria y del informe
mensual, sin tocar nada de la produccion.

Para que el equipo pueda ver como llega la informacion (maquetacion, adjuntos, longitud)
antes de cambiar la alerta real. Peticion del usuario del 2026-09-06.

Garantias:
  * NO escribe en la base de datos: la abre en modo solo lectura.
  * NO marca ninguna amenaza como alertada ni sella `avisado_at` de las correcciones.
  * NO cambia los destinatarios configurados: se envia solo a la direccion indicada.
  * El asunto lleva el prefijo «[PRUEBA]» para que nadie lo confunda con una alerta real.
  * El servidor de correo interno solo acepta destinatarios del dominio de la empresa.

Uso:
    sudo -n -u si .venv/bin/python bin/enviar_prueba.py --a usuario1@ejemplo.local
    sudo -n -u si .venv/bin/python bin/enviar_prueba.py --a … --solo alerta
    sudo -n -u si .venv/bin/python bin/enviar_prueba.py --a … --dry-run   (no envia; guarda el HTML)
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import aplicabilidad, config, db, notify, ocs, queries, report  # noqa: E402
from threatintel.logging_setup import get_logger, setup  # noqa: E402
from threatintel.paths import BASE_DIR, ensure_dirs  # noqa: E402

log = get_logger(__name__)
SALIDA = BASE_DIR / "data" / "revision"


def _conexion_solo_lectura() -> sqlite3.Connection:
    ruta = BASE_DIR / "data" / "threat_intel.db"
    conn = sqlite3.connect(f"file:{ruta}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _amenazas_de_la_ultima_alerta(conn, cfg, limite: int = 60) -> list[dict]:
    """Las amenazas del ultimo correo real; si no hay, las que hoy cumplirian el criterio."""
    filas = [dict(r) for r in conn.execute(
        """SELECT * FROM threats WHERE alerted_at IS NOT NULL
             AND date(alerted_at) = (SELECT date(MAX(alerted_at)) FROM threats WHERE alerted_at IS NOT NULL)
           ORDER BY relevance DESC, cvss_score DESC LIMIT ?""", (limite,))]
    if filas:
        return filas
    clasificacion = queries.clasificar_pendientes(conn, cfg=cfg, persistir=False)
    return list(clasificacion.get("alertar") or [])[:limite]


def _adjuntos_alerta(conn, amenazas, cfg, url_base: str, parches_nuevos) -> list[Path]:
    """Hojas de calculo de la alerta, si el modulo ya las genera."""
    adjuntos: list[Path] = []
    try:
        from threatintel import libro_alerta
    except ImportError:
        return adjuntos
    for nombre, funcion, argumento in (
            ("libro de vulnerabilidades", getattr(libro_alerta, "generar", None), amenazas),
            ("libro de correcciones disponibles", getattr(libro_alerta, "generar_correcciones", None), parches_nuevos)):
        if funcion is None:
            continue
        try:
            ruta = funcion(conn, argumento, cfg=cfg, meta={"url_base": url_base, "parches_nuevos": parches_nuevos})
        except TypeError:
            try:
                ruta = funcion(conn, argumento, cfg=cfg)
            except Exception as exc:  # noqa: BLE001
                print(f"        aviso: no se pudo generar el {nombre}: {exc}")
                continue
        except Exception as exc:  # noqa: BLE001
            print(f"        aviso: no se pudo generar el {nombre}: {exc}")
            continue
        if ruta:
            adjuntos.append(Path(ruta))
            print(f"        adjunto: {Path(ruta).name} ({round(Path(ruta).stat().st_size / 1024, 1)} KB)")
    return adjuntos


def _sin_correccion(conn) -> dict:
    """Lo que no se puede corregir todavia; vacio si el modulo aun no lo ofrece."""
    try:
        from threatintel import parches
        return parches.sin_correccion(conn)
    except Exception:  # noqa: BLE001
        return {}


def enviar_alerta(conn, cfg, mailer, destino: str, *, dry_run: bool) -> bool:
    print("\n  [1/2] Alerta diaria de prueba")
    amenazas = _amenazas_de_la_ultima_alerta(conn, cfg)
    if not amenazas:
        print("        no hay amenazas que mostrar; no se envía")
        return True
    aplicabilidad.adjuntar_activos(conn, amenazas, limite=10)
    activos_afectados = aplicabilidad.activos_distintos(conn, [a["id"] for a in amenazas])
    criticas = sum(1 for a in amenazas if a.get("severity") == "Critical")
    altas = sum(1 for a in amenazas if a.get("severity") == "High")
    kev = sum(1 for a in amenazas if a.get("in_kev"))

    resumen_activos = {}
    try:
        # «En produccion o contingencia» la calcula ocs.resumen desde el 2026-09-10
        # (tarde), con la severidad baja y el riesgo aceptado fuera, igual que el resto
        # de sus cifras: antes esta consulta estaba copiada aqui, en bin/enviar_prueba.py
        # y en webui/vistas/panel.py, y las tres copias contaban con otro criterio.
        resumen_activos = ocs.resumen(conn, cfg=cfg)
    except Exception:  # noqa: BLE001
        resumen_activos = {}

    parches_nuevos = []
    try:
        from threatintel import parches
        parches_nuevos = parches.novedades(conn, marcar=False)   # nunca se sella en una prueba
    except Exception:  # noqa: BLE001
        parches_nuevos = []

    url_base = config.url_publica(cfg)
    adjuntos = _adjuntos_alerta(conn, amenazas, cfg, url_base, parches_nuevos)
    html = notify.render_alert_email(amenazas, {
        "periodo": datetime.now().strftime("%Y-%m"),
        "max_detalle": int(cfg.get("alert_max_items", 25) or 25),
        "detalle_top": int(cfg.get("alert_detalle_top", 3) or 3),
        "tabla_top": int(cfg.get("alert_tabla_top", 10) or 10),
        "parches_nuevos": parches_nuevos,
        "sin_correccion": _sin_correccion(conn),
        "adjuntos": [a.name for a in adjuntos],
        "url_interfaz": f"{url_base}/amenazas/", "url_activos": f"{url_base}/activos/",
        "resumen_activos": resumen_activos,
        "filtro": {"alertadas": len(amenazas), "excluidas": {},
                   "umbral_relevancia": float(cfg.get("alert_min_relevance", 50) or 50),
                   "min_confianza": float(cfg.get("alert_min_match_confidence", 0.6) or 0.6),
                   "ignorar_criticidad_baja": bool(cfg.get("ignore_low_criticality", True))}})
    asunto = "[PRUEBA] " + notify.asunto_alerta(criticas, altas, kev, total=len(amenazas),
                                                activos=activos_afectados)
    print(f"        {len(amenazas)} amenazas · {activos_afectados} activos afectados · "
          f"{len(html):,} caracteres de correo".replace(",", "."))
    if dry_run:
        SALIDA.mkdir(parents=True, exist_ok=True)
        destino_html = SALIDA / f"prueba_alerta_{datetime.now():%Y%m%d-%H%M%S}.html"
        destino_html.write_text(html, encoding="utf-8")
        print(f"        simulación: HTML guardado en {destino_html}")
        return True
    if mailer.send(subject=asunto, html=html, to=[destino], attachments=adjuntos or None):
        print(f"        enviado a {destino}")
        return True
    print("        ERROR: no se pudo enviar la alerta de prueba")
    return False


def enviar_mensual(conn, cfg, mailer, destino: str, *, mes: str, dry_run: bool) -> bool:
    print("\n  [2/2] Informe mensual de prueba")
    # Mismo resumen que usa bin/ejecucion_mensual.py: la plantilla del correo necesita
    # bastante mas que las estadisticas basicas del mes.
    resumen = report.construir_resumen(conn, mes, cfg=cfg)
    print(f"        periodo {mes} · {resumen.get('total', 0)} amenazas registradas")
    ruta = report.generar(conn, mes, cfg=cfg)
    tamano_kb = round(ruta.stat().st_size / 1024, 1)
    print(f"        {ruta.name} ({tamano_kb} KB)")
    url = config.url_publica(cfg, "/")
    html = notify.render_monthly_email(dict(resumen, nombre_archivo=ruta.name,
                                            tamano_kb=int(tamano_kb), url_interfaz=url))
    if dry_run:
        SALIDA.mkdir(parents=True, exist_ok=True)
        destino_html = SALIDA / f"prueba_mensual_{mes}.html"
        destino_html.write_text(html, encoding="utf-8")
        print(f"        simulación: HTML guardado en {destino_html}")
        return True
    if mailer.send(subject="[PRUEBA] " + notify.asunto_mensual(mes), html=html,
                   to=[destino], attachments=[ruta]):
        print(f"        enviado a {destino}")
        return True
    print("        ERROR: no se pudo enviar el informe mensual de prueba")
    return False


def main() -> int:
    p = argparse.ArgumentParser(description="Envia una copia de prueba de la alerta y del informe mensual.")
    p.add_argument("--a", required=True, help="dirección de destino (del dominio de la empresa)")
    p.add_argument("--solo", choices=("alerta", "mensual"), help="enviar solo uno de los dos")
    p.add_argument("--mes", help="periodo del informe mensual (AAAA-MM); por defecto, el mes en curso")
    p.add_argument("--dry-run", action="store_true", help="no envía: guarda el HTML en data/revision/")
    args = p.parse_args()

    ensure_dirs()
    setup()
    cfg = config.load()
    mes = args.mes or datetime.now().strftime("%Y-%m")
    print("=" * 70)
    print(f"  Envío de PRUEBA a {args.a}" + ("  (simulación)" if args.dry_run else ""))
    print("  La base de datos se abre en modo solo lectura; no se marca nada como alertado.")
    print("=" * 70)

    mailer = notify.Mailer(cfg, dry_run=args.dry_run)
    conn = _conexion_solo_lectura()
    ok = True
    try:
        if args.solo != "mensual":
            ok = enviar_alerta(conn, cfg, mailer, args.a, dry_run=args.dry_run) and ok
        if args.solo != "alerta":
            ok = enviar_mensual(conn, cfg, mailer, args.a, mes=mes, dry_run=args.dry_run) and ok
    finally:
        conn.close()
    print("\n" + ("  Terminado." if ok else "  Terminado CON ERRORES."))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
