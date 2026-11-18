#!/usr/bin/env python3
"""Crea o elimina el usuario temporal de solo lectura para las capturas de pantalla.

Uso (como el usuario si):  usuario_temporal.py crear [viewer|admin]   → imprime la contraseña
                           usuario_temporal.py borrar

Con «admin» el usuario temporal puede ver las páginas de administración (Usuarios, Ajustes,
Credenciales, Alertas por proceso); solo se usa para capturas y se borra siempre al terminar.
"""
from __future__ import annotations

import secrets
import string
import sys

PROYECTO = "/opt/inteligencia_amenazas"
sys.path.insert(0, PROYECTO)

from threatintel import db  # noqa: E402
from webui import auth  # noqa: E402

USUARIO = "revision@ejemplo.local"


def main() -> int:
    orden = sys.argv[1] if len(sys.argv) > 1 else ""
    with db.session(f"{PROYECTO}/data/threat_intel.db") as conn:
        fila = conn.execute("SELECT id FROM users WHERE username=?", (USUARIO,)).fetchone()
        if fila:
            conn.execute("DELETE FROM web_sessions WHERE username=?", (USUARIO,))
            conn.execute("DELETE FROM users WHERE id=?", (fila["id"],))
        if orden == "crear":
            rol = sys.argv[2] if len(sys.argv) > 2 else "viewer"
            if rol not in ("viewer", "admin"):
                print("rol no válido: use viewer o admin", file=sys.stderr)
                return 2
            alfabeto = string.ascii_letters + string.digits
            clave = "Rv" + "".join(secrets.choice(alfabeto) for _ in range(18)) + "#7"
            auth.crear_usuario(conn, USUARIO, clave, rol=rol, actor="revision visual temporal")
            print(clave)
            return 0
        if orden == "borrar":
            print("usuario temporal eliminado" if fila else "no había usuario temporal")
            return 0
    print("uso: usuario_temporal.py crear [viewer|admin] | borrar", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
