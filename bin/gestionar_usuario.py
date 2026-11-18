#!/usr/bin/env python3
"""Gestion de usuarios de la interfaz de administracion.

  crear <usuario> [--rol ...]            crea un usuario (pide la contrasena)
                                         admin | servicios_tecnologicos | viewer
  password <usuario>                     cambia la contrasena
  listar                                 lista los usuarios
  desactivar <usuario> / activar <usuario>
  desbloquear <usuario>                  quita el bloqueo por intentos fallidos
  2fa-restablecer <usuario>              quita el segundo factor (TOTP y codigos de
                                         recuperacion) de un usuario que perdio el
                                         telefono; cierra sus sesiones
"""
from __future__ import annotations

import argparse
import getpass
import secrets
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import db                    # noqa: E402
from webui import auth                        # noqa: E402


def pedir_password(generar: bool) -> tuple[str, bool]:
    if generar:
        alfabeto = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
        pw = "".join(secrets.choice(alfabeto) for _ in range(20))
        print(f"\n  Contrasena generada: {pw}")
        print("  Guardela ahora: no se volvera a mostrar.\n")
        return pw, False

    if not sys.stdin.isatty():
        raise SystemExit("Sin terminal interactiva. Use --generar.")

    while True:
        pw = getpass.getpass("  Contrasena nueva: ")
        ok, motivo = auth.fuerza_password(pw)
        if not ok:
            print(f"  {motivo}")
            continue
        if pw != getpass.getpass("  Repita la contrasena: "):
            print("  No coinciden.")
            continue
        return pw, False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="orden", required=True)

    p = sub.add_parser("crear")
    p.add_argument("usuario")
    p.add_argument("--nombre", help="nombre y apellidos de la persona; la barra superior "
                                    "y el perfil lo muestran en lugar del correo")
    p.add_argument("--rol", choices=list(auth.ROLES), default="admin",
                   help="admin: todo · servicios_tecnologicos: solo comprobar y "
                        "documentar remediaciones · viewer: solo consulta")
    p.add_argument("--generar", action="store_true",
                   help="genera una contrasena aleatoria en lugar de pedirla")

    p = sub.add_parser("password")
    p.add_argument("usuario")
    p.add_argument("--generar", action="store_true")

    sub.add_parser("listar")

    for orden in ("desactivar", "activar", "desbloquear"):
        p = sub.add_parser(orden)
        p.add_argument("usuario")

    p = sub.add_parser("2fa-restablecer",
                       help="quita el segundo factor de un usuario (recuperacion de emergencia)")
    p.add_argument("usuario")

    args = parser.parse_args()
    db.init_db()

    if args.orden == "listar":
        with db.connect() as conn:
            filas = conn.execute(
                "SELECT username, role, enabled, created_at, last_login_at, "
                "failed_logins, locked_until, totp_activado_at FROM users ORDER BY username").fetchall()
        if not filas:
            print("  No hay usuarios. Cree uno con: crear <usuario>")
            return 0
        print(f"\n  {'USUARIO':<20} {'ROL':<8} {'ESTADO':<12} {'ÚLTIMO ACCESO':<22} {'FALLOS':<7} SEGUNDO FACTOR")
        print("  " + "-" * 88)
        for f in filas:
            estado = "activo" if f["enabled"] else "desactivado"
            if f["locked_until"]:
                estado = "bloqueado"
            print(f"  {f['username']:<20} {f['role']:<8} {estado:<12} "
                  f"{str(f['last_login_at'] or 'nunca')[:19]:<22} {f['failed_logins']:<7} "
                  f"{'sí' if f['totp_activado_at'] else 'no'}")
        print()
        return 0

    usuario = args.usuario.strip().lower()

    if args.orden == "crear":
        pw, _ = pedir_password(getattr(args, "generar", False))
        try:
            with db.session() as conn:
                auth.crear_usuario(conn, usuario, pw, rol=args.rol, actor="cli",
                                   nombre=getattr(args, "nombre", None))
        except ValueError as exc:
            print(f"  Error: {exc}")
            return 1
        print(f"  Usuario '{usuario}' creado con perfil {args.rol}.")
        if not (getattr(args, "nombre", None) or "").strip():
            print("  Aviso: sin nombre de persona. La barra superior mostrará el correo "
                  "hasta que se complete desde Usuarios (o vuelva a crearlo con --nombre).")
        return 0

    if args.orden == "password":
        pw, _ = pedir_password(getattr(args, "generar", False))
        try:
            with db.session() as conn:
                auth.cambiar_password(conn, usuario, pw, actor="cli")
        except ValueError as exc:
            print(f"  Error: {exc}")
            return 1
        print(f"  Contrasena de '{usuario}' actualizada.")
        return 0

    if args.orden == "2fa-restablecer":
        try:
            with db.session() as conn:
                cerradas = auth.restablecer_2fa(conn, usuario, actor="cli")
        except ValueError as exc:
            print(f"  Error: {exc}")
            return 1
        print(f"  Segundo factor de '{usuario}' restablecido: podra entrar solo con la contrasena "
              f"y debera activarlo de nuevo desde «Cambiar mi contrasena». "
              f"Sesiones cerradas: {cerradas}.")
        return 0

    with db.session() as conn:
        if args.orden == "desbloquear":
            # Tambien los fallos del segundo factor (revision 2026-09-05).
            cur = conn.execute(
                "UPDATE users SET failed_logins=0, locked_until=NULL, totp_fallos=0 WHERE username=?",
                (usuario,))
            accion, mensaje = "usuario.desbloquear", "desbloqueado"
        else:
            activo = 1 if args.orden == "activar" else 0
            cur = conn.execute("UPDATE users SET enabled=? WHERE username=?",
                               (activo, usuario))
            accion = f"usuario.{args.orden}"
            mensaje = "activado" if activo else "desactivado"

        if not cur.rowcount:
            print(f"  Error: no existe el usuario «{usuario}».")
            return 1
        db.audit(conn, "cli", accion, "users", usuario)

    print(f"  Usuario '{usuario}' {mensaje}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
