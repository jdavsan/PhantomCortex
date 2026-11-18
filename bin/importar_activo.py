#!/usr/bin/env python3
"""Importa en un activo un SBOM (CycloneDX/SPDX JSON) o resultados de OpenSCAP (XCCDF/ARF).

Uso:
    bin/importar_activo.py --activo srv-web-01 --sbom aplicacion.cdx.json
    bin/importar_activo.py --activo 470 --openscap resultados.xml
El activo se indica por nombre (como en OCS) o por su identificador numerico.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import config, db, openscap, sbom   # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--activo", required=True, help="nombre o identificador del activo")
    parser.add_argument("--sbom", help="fichero SBOM en JSON (CycloneDX o SPDX)")
    parser.add_argument("--openscap", help="fichero de resultados XCCDF o ARF")
    parser.add_argument("--db", default=None)
    args = parser.parse_args()
    if not args.sbom and not args.openscap:
        parser.error("indique --sbom o --openscap")
    db.init_db(args.db)
    conn = db.connect(args.db)
    try:
        cfg = config.load(conn)
        fila = conn.execute("SELECT id, nombre FROM activos WHERE id=? OR lower(nombre)=lower(?) ORDER BY presente DESC LIMIT 1",
                            (args.activo if str(args.activo).isdigit() else -1, args.activo)).fetchone()
        if fila is None:
            print(f"  No existe el activo «{args.activo}».")
            return 2
        print(f"\n  Activo: {fila['nombre']} (#{fila['id']})")
        conn.execute("BEGIN")
        if args.sbom:
            contenido = Path(args.sbom).read_bytes()
            r = sbom.importar(conn, fila["id"], contenido, fichero=Path(args.sbom).name)
            print(f"  SBOM {r['formato']}: {r['componentes']} componentes, {r['evaluables']} evaluables")
            ev = sbom.evaluar(conn, fila["id"], cfg=cfg)
            print(f"  OSV.dev: {ev['vulnerabilidades']} vulnerabilidades en componentes ({ev['consultas_osv']} consultas)")
            for e in ev["errores"][:5]:
                print(f"    aviso: {e}")
        if args.openscap:
            contenido = Path(args.openscap).read_bytes()
            r = openscap.importar(conn, fila["id"], contenido, fichero=Path(args.openscap).name)
            print(f"  OpenSCAP {r['perfil']}: {r['reglas']} reglas; cumplen {r['conteo'].get('pass', 0)}, "
                  f"no cumplen {r['conteo'].get('fail', 0)}")
        conn.execute("COMMIT")
        print()
        return 0
    except (sbom.ErrorSBOM, openscap.ErrorOpenSCAP, OSError) as exc:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        print(f"  ERROR: {exc}")
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
