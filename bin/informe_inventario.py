#!/usr/bin/env python3
"""Informe de inventario sin reportar, para Redes.

Equipos que llevan mas de `ocs_stale_days` dias sin enviar su inventario a OCS Inventory,
separados por servidores y equipos de usuario.

Va en un correo APARTE del de alertamiento diario (peticion del usuario del 2026-09-07):
mantener el inventario al dia no es una tarea de seguridad, sino de Redes,
y mezclarlo con las vulnerabilidades hacia que se leyera como un hallazgo de seguridad.

Los destinatarios se configuran en Ajustes (`inventario_destinatarios`) y el envio se
activa con `inventario_informe_activo`. Mientras no se configuren, este guion no envia
nada: lo dice y termina sin error, para poder programarlo desde ya.

Desde el 2026-09-15 el correo lleva DOS FICHEROS ADJUNTOS, uno de servidores y otro de
equipos de computo, con la lista detallada de los que han dejado de reportar (nombre,
direccion IP, proceso de negocio, entorno, sistema operativo y version, zona de red,
usuario, dias sin reportar, fechas y vulnerabilidades confirmadas). Si un grupo no tiene
ninguna maquina sin reportar, su fichero NO se genera y el correo lo dice.

Uso:
    bin/informe_inventario.py                     # a los destinatarios configurados
    bin/informe_inventario.py --a alguien@…       # a una direccion concreta
    bin/informe_inventario.py --dry-run           # no envia; guarda el HTML y los ficheros
    bin/informe_inventario.py --ficheros          # SOLO los dos ficheros; no envia nada
    bin/informe_inventario.py --ficheros --en /ruta/carpeta
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import config, db, libro_inventario, notify, ocs  # noqa: E402
from threatintel.logging_setup import get_logger, setup  # noqa: E402
from threatintel.paths import BASE_DIR, ensure_dirs  # noqa: E402

log = get_logger(__name__)
SALIDA = BASE_DIR / "data" / "revision"


def _ahora() -> datetime:
    """Fecha de referencia para «sin reportar hace más de N días».

    Por omisión es el reloj real. La variable de entorno ``INFORME_INVENTARIO_AHORA``
    (fecha y hora ISO-8601, por ejemplo ``2026-09-15T12:00:00Z``) permite fijarla desde
    las pruebas automáticas, que lanzan este guion como subproceso y necesitan una fecha
    estable en vez de la del reloj del equipo donde corran (2026-11-15). En producción no
    se define y el comportamiento no cambia.
    """
    valor = os.environ.get("INFORME_INVENTARIO_AHORA")
    if valor:
        try:
            dt = datetime.fromisoformat(valor.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def destinatarios(cfg, argumento: str | None) -> list[str]:
    """La direccion indicada a mano, o las configuradas en Ajustes."""
    if argumento:
        return [d.strip() for d in argumento.split(",") if d.strip()]
    valor = cfg.get("inventario_destinatarios", []) or []
    if isinstance(valor, str):
        valor = [v.strip() for v in valor.replace(";", ",").split(",")]
    return [v for v in valor if v]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--a", default=None,
                   help="dirección o direcciones separadas por comas (por omisión, las de Ajustes)")
    p.add_argument("--dry-run", action="store_true",
                   help="no envía: guarda el HTML y los dos ficheros adjuntos")
    p.add_argument("--ficheros", action="store_true",
                   help="genera solo los dos ficheros (servidores y equipos de cómputo) "
                        "y termina, sin enviar ningún correo")
    p.add_argument("--en", default=None, metavar="DIRECTORIO",
                   help="dónde dejar los ficheros (por omisión, data/revision/inventario)")
    p.add_argument("--limite", type=int, default=200,
                   help="activos que se listan en el CUERPO del correo como máximo "
                        "(por omisión 200); los ficheros adjuntos los llevan todos")
    p.add_argument("--db", default=None)
    args = p.parse_args()

    ensure_dirs()
    setup()
    # db_path=args.db: sin esto, config.load() siempre leía los ajustes (tabla
    # settings) de la base de PRODUCCIÓN aunque --db apuntara a otra (una de
    # pruebas, por ejemplo), y fallaba con "no such table: settings" en
    # cualquier sitio donde la base de producción no existiera (encontrado en
    # CI, 2026-11-18: un clon nuevo no tiene data/threat_intel.db).
    cfg = config.load(db_path=args.db)
    print("=" * 70)
    print("  Informe de inventario sin reportar (Redes)")
    print("=" * 70)

    ahora = _ahora()
    with db.session(args.db) as conn:
        datos = ocs.inventario_sin_reportar(conn, cfg=cfg, limite=args.limite, ahora=ahora)
        # Lista COMPLETA (sin tope) para los dos ficheros adjuntos: el cuerpo del correo
        # sigue recortado, pero el fichero que abre Redes los lleva todos.
        detallado = ocs.inventario_sin_reportar_detallado(conn, cfg=cfg, ahora=ahora)

    print(f"\n  {notify.numero(datos['total'])} de "
          f"{notify.numero(datos['activos_presentes'])} activos sin reportar "
          f"hace más de {notify.numero(datos['dias'])} días")
    for g in datos["grupos"]:
        print(f"      {g['origen_es']}: {notify.numero(g['sin_reportar'])} de "
              f"{notify.numero(g['total'])} ({notify.decimal(g['pct'], 1)} %)")

    url_base = config.url_publica(cfg)
    url_activos = f"{url_base}/activos/?vista=sin_reportar"

    # --ficheros: solo las dos hojas de calculo, a demanda, sin enviar ni componer correo.
    if args.ficheros:
        carpeta = Path(args.en).expanduser() if args.en else SALIDA / "inventario"
        rutas = libro_inventario.generar(detallado, directorio=carpeta,
                                         url_activos=url_activos)
        if not rutas:
            print("\n  Ningún activo lleva más de "
                  f"{detallado['dias']} días sin reportar: no se genera ningún fichero.\n")
            return 0
        print("")
        for origen, ruta in rutas.items():
            grupo = next(g for g in detallado["grupos"] if g["origen"] == origen)
            print(f"  {grupo['origen_es']}: {notify.numero(grupo['sin_reportar'])} de "
                  f"{notify.numero(grupo['total'])} → {ruta} "
                  f"({notify.decimal(ruta.stat().st_size / 1024, 1)} KB)")
        for grupo in detallado["grupos"]:
            if grupo["origen"] not in rutas:
                print(f"  {grupo['origen_es']}: ninguno sin reportar, no se genera fichero")
        print("")
        return 0

    # Los dos ficheros adjuntos. Si un grupo esta vacio no se genera su fichero y el correo
    # lo dice con palabras (peticion del usuario del 2026-09-15).
    carpeta = Path(args.en).expanduser() if args.en else (SALIDA / "inventario" if args.dry_run else None)
    try:
        rutas = libro_inventario.generar(detallado, directorio=carpeta,
                                         url_activos=url_activos)
    except Exception as exc:  # noqa: BLE001 - el correo se envia igual, sin adjuntos
        log.error("fallaron los ficheros de inventario sin reportar",
                  extra={"error": str(exc)}, exc_info=True)
        print(f"  ERROR al generar los ficheros adjuntos: {exc}")
        rutas = {}
    adjuntos_correo = []
    for grupo in detallado["grupos"]:
        ruta = rutas.get(grupo["origen"])
        adjuntos_correo.append({
            "origen": grupo["origen"], "origen_es": grupo["origen_es"],
            "sin_reportar": grupo["sin_reportar"], "total": grupo["total"],
            "filas": len(grupo["filas"]), "fichero": ruta.name if ruta else ""})
        if ruta:
            print(f"      adjunto: {ruta.name} "
                  f"({notify.decimal(ruta.stat().st_size / 1024, 1)} KB, "
                  f"{notify.numero(len(grupo['filas']))} filas)")
        else:
            print(f"      sin adjunto de {grupo['origen_es'].lower()}: ninguno sin reportar")

    html = notify.render_inventario_email(datos, url_activos=url_activos,
                                          adjuntos=adjuntos_correo)
    asunto = notify.asunto_inventario(datos["total"], datos["dias"])
    print(f"\n  Asunto: {asunto}")
    print(f"  Cuerpo: {len(html):,} caracteres".replace(",", "."))

    if args.dry_run:
        SALIDA.mkdir(parents=True, exist_ok=True)
        destino = SALIDA / f"inventario_{datetime.now():%Y%m%d-%H%M%S}.html"
        destino.write_text(html, encoding="utf-8")
        print(f"  Simulación: HTML guardado en {destino}")
        for ruta in rutas.values():
            print(f"  Simulación: fichero generado en {ruta}")
        print("")
        return 0

    direcciones = destinatarios(cfg, args.a)
    if not direcciones:
        print("\n  No hay destinatarios configurados: no se envía nada.")
        print("  Configúrelos en Ajustes → «Destinatarios del informe de inventario»")
        print("  (o pase --a dirección@empresa). Este informe es para administración")
        print("  del inventario, no para Ciberseguridad.\n")
        return 0
    if not args.a and not bool(cfg.get("inventario_informe_activo", False)):
        print("\n  El envío del informe de inventario está desactivado en Ajustes")
        print("  («Enviar el informe de inventario»). No se envía nada.\n")
        return 0

    mailer = notify.Mailer(cfg)
    if mailer.send(subject=asunto, html=html, to=direcciones,
                   attachments=[rutas[o] for o in ("servidores", "equipos") if o in rutas]):
        print(f"\n  Enviado a {', '.join(direcciones)} con {len(rutas)} "
              f"fichero{'s' if len(rutas) != 1 else ''} adjunto"
              f"{'s' if len(rutas) != 1 else ''}\n")
        log.info("informe de inventario enviado",
                 extra={"destinatarios": len(direcciones), "sin_reportar": datos["total"],
                        "adjuntos": len(rutas)})
        return 0
    print("\n  ERROR: no se pudo enviar el informe de inventario\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
