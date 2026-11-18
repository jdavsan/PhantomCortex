#!/usr/bin/env python3
"""Vuelve a traducir los titulos de avisos con nombre de paquete mal traducido.

Hasta el 2026-09-04 Argos traducia el nombre del paquete de los avisos de
distribucion como si fuera una palabra corriente («DSA-6476-1 chromium» ->
«cromo», «bubblewrap» -> «burbujas», «wire» -> «Cable»). La proteccion de
terminos ya lo evita para lo nuevo; este script repara el historico reciente:
las amenazas de los ultimos N dias cuyo titulo lleva un identificador de aviso
(DSA, DLA, USN, RHSA, GHSA...). Si el titulo cambia, se vuelve a traducir
tambien el resumen (puede contener el mismo nombre).

Invalida la cache de traduccion de esos textos: si no, se devolveria la misma
traduccion vieja. Solo usa Argos (los titulos siempre se traducen con Argos).

Uso:
    bin/reparar_traducciones.py               # muestra antes/despues, no escribe
    bin/reparar_traducciones.py --aplicar     # escribe en la base
    bin/reparar_traducciones.py --dias 30
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import config, db, identity, translate   # noqa: E402


def _invalidar_cache(conn: sqlite3.Connection, texto: str) -> None:
    limpio = translate.limpiar_html(texto)
    for motor in ("argos", "ollama"):
        conn.execute("DELETE FROM translation_cache WHERE hash=?",
                     (translate._hash(limpio, motor),))


# Traducciones de nombre propio como palabra corriente: (fragmento en title_es,
# fragmento en title_en). Solo se retraduce si aparecen los dos.
SOSPECHOSOS = (("cromo", "chrom"), ("burbujas", "bubblewrap"), ("conejomq", "rabbitmq"),
               ("cabina", "cockpit"), ("Cable", "wire"), ("ventanas", "windows"))


def _sospechosa(fila: dict) -> bool:
    es, en = (fila.get("title_es") or "").lower(), (fila.get("title_en") or "").lower()
    return any(a.lower() in es and b in en for a, b in SOSPECHOSOS)


def reparar(conn: sqlite3.Connection, *, cfg, dias: int, aplicar: bool,
            salida=print, sospechosos: bool = False) -> dict:
    """Devuelve {'revisadas', 'cambiadas', 'ejemplos': [(antes, despues)]}.

    Por defecto revisa los titulos con identificador de aviso de los ultimos
    ``dias``. Con ``sospechosos`` revisa ademas, sin limite de fecha, los que
    tienen un nombre propio traducido como palabra corriente («cromo»)."""
    desde = (datetime.now(timezone.utc) - timedelta(days=dias)).replace(microsecond=0)
    desde_iso = desde.isoformat().replace("+00:00", "Z")
    filas = [dict(r) for r in conn.execute(
        "SELECT id, title_en, title_es, summary_en, summary_es, severity, first_seen_at FROM threats "
        "WHERE title_en IS NOT NULL ORDER BY id")]
    candidatas = [f for f in filas
                  if (f["first_seen_at"] >= desde_iso and identity.extraer_id_aviso(f["title_en"]))
                  or (sospechosos and _sospechosa(f))]
    resultado = {"revisadas": len(candidatas), "cambiadas": 0, "ejemplos": []}

    for fila in candidatas:
        _invalidar_cache(conn, fila["title_en"])
        nuevo_titulo, _ = translate.traducir(fila["title_en"], cfg=cfg, conn=conn,
                                             severidad=fila["severity"], permitir_ollama=False)
        if not nuevo_titulo or nuevo_titulo == (fila["title_es"] or ""):
            continue
        nuevo_resumen = fila["summary_es"]
        if fila["summary_en"]:
            _invalidar_cache(conn, fila["summary_en"])
            nuevo_resumen, _ = translate.traducir(fila["summary_en"], cfg=cfg, conn=conn,
                                                  severidad=fila["severity"], permitir_ollama=False)
        resultado["cambiadas"] += 1
        if len(resultado["ejemplos"]) < 25:
            resultado["ejemplos"].append((fila["title_es"], nuevo_titulo))
        salida(f"    #{fila['id']}: {fila['title_es']!r}\n          -> {nuevo_titulo!r}")
        if aplicar:
            conn.execute("UPDATE threats SET title_es=?, summary_es=? WHERE id=?",
                         (nuevo_titulo, nuevo_resumen or fila["summary_es"], fila["id"]))
    return resultado


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--aplicar", action="store_true", help="escribe los cambios en la base")
    parser.add_argument("--dias", type=int, default=90, help="antigüedad máxima (90 por defecto)")
    parser.add_argument("--sospechosos", action="store_true",
                        help="incluir, sin límite de fecha, títulos con nombres propios traducidos "
                             "como palabras («cromo» por Chromium)")
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    db.init_db(args.db)
    conn = db.connect(args.db)
    try:
        cfg = config.load(conn)
        if not translate.argos_disponible():
            print("\n  ArgosTranslate no está disponible: no se puede retraducir.\n")
            return 1
        print(f"\n  Revisando avisos de los últimos {args.dias} días"
              f"{' (sin escribir)' if not args.aplicar else ''}...\n")
        # Sin transaccion larga: cada UPDATE se confirma solo (conexion en
        # autocommit). Argos tarda ~1 s por titulo y una transaccion abierta
        # durante minutos bloquearia la interfaz web ("database is locked").
        res = reparar(conn, cfg=cfg, dias=args.dias, aplicar=args.aplicar,
                      sospechosos=args.sospechosos)
        if args.aplicar:
            db.audit(conn, "system", "traduccion.reparar", "threats", None,
                     f"revisadas={res['revisadas']} cambiadas={res['cambiadas']} dias={args.dias}"
                     f"{' sospechosos' if args.sospechosos else ''}", None)
        print(f"\n  {res['revisadas']} títulos con identificador de aviso revisados; "
              f"{res['cambiadas']} {'corregidos' if args.aplicar else 'cambiarían'}."
              f"{'' if args.aplicar else ' Repita con --aplicar para escribir.'}\n")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"\n  ERROR: {type(exc).__name__}: {exc}\n")
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
