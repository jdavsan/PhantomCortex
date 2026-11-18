#!/usr/bin/env python3
"""Aplica a la base existente las reglas de precision de la correlacion (2026-09-04).

Que hace, sin borrar ningun alias creado por el operador:

  * Contexto de vulnerabilidad en los alias genericos ('windows', 'linux',
    'chrome', 'java', 'php'...): solo cuentan si el texto habla de una
    vulnerabilidad (CVE, flaw, patch, security update...). Hasta ahora una
    noticia de malware que mencionaba Windows correlacionaba con el inventario.
  * Exclusiones base por tecnologia ("Chrome for Android", "Windows Phone",
    "edge computing"...).

Por defecto solo muestra lo que cambiaria. Con --aplicar escribe. Despues hay
que recorrelar (bin/recorrelacionar.py) para que el historico refleje las
reglas nuevas.

Uso:
    bin/actualizar_alias.py              # ver el diff
    bin/actualizar_alias.py --aplicar    # escribir
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import db, matching   # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--aplicar", action="store_true", help="escribe los cambios")
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    db.init_db(args.db)
    if args.aplicar:
        with db.session(args.db) as conn:
            cambios = matching.aplicar_precision_alias(conn, aplicar=True)
    else:
        conn = db.connect(args.db)
        try:
            cambios = matching.aplicar_precision_alias(conn, aplicar=False)
        finally:
            conn.close()

    verbo = "Aplicado" if args.aplicar else "Cambiaría"
    print(f"\n  {verbo}: {len(cambios['contexto'])} alias con contexto de vulnerabilidad, "
          f"{len(cambios['exclusiones'])} exclusiones nuevas\n")
    for slug, alias in cambios["contexto"]:
        print(f"    contexto    {slug:<18} «{alias}»")
    for slug, alias in cambios["exclusiones"]:
        print(f"    exclusión   {slug:<18} «{alias}»")
    if not (cambios["contexto"] or cambios["exclusiones"]):
        print("    (nada: la base ya está al día)")
    if not args.aplicar and (cambios["contexto"] or cambios["exclusiones"]):
        print("\n  Nada escrito. Repita con --aplicar y después ejecute bin/recorrelacionar.py.\n")
    elif args.aplicar:
        print("\n  Ahora ejecute bin/recorrelacionar.py para rehacer las correlaciones.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
