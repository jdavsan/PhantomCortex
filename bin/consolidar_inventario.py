#!/usr/bin/env python3
"""Consolida el inventario tecnologico tras la migracion del historico.

Arregla tres problemas introducidos al importar los datos antiguos:

  1. El migrador creo tecnologias a partir de los nombres del historico
     ('Edge', 'Java', 'Debian'...) SIN ningun alias, de modo que nunca podian
     casar con ningun texto: eran entradas muertas en el inventario.

  2. El migrador usa guion bajo en el identificador ('active_directory') y el
     catalogo base usa guion ('active-directory'), asi que el sembrado creo
     duplicados en lugar de enriquecer las entradas existentes.

  3. Las categorias quedaron mezcladas: 53 entradas cayeron en 'aplicacion' por
     defecto, con las del catalogo base bien clasificadas.

Al fusionar se conserva SIEMPRE la entrada del catalogo base (que trae alias,
categoria, criticidad y exposicion) y se le trasladan los datos que solo estan
en la entrada importada: version instalada, numero de sistemas, responsable,
CPE y notas. Las correlaciones historicas de `threat_technologies` se repuntan
a la entrada superviviente.
"""
from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import db, matching                       # noqa: E402
from threatintel.logging_setup import get_logger, setup     # noqa: E402

# Nombres que el historico dejo mal escritos o incompletos
CORRECCIONES_NOMBRE = {
    "7zip": "7-Zip",
    "docusing": "DocuSign",
    "cristaldisk": "CrystalDiskInfo",
    "check point vpn": "Check Point VPN",
    "central telefonica": "Asterisk",
    "svn version control": "Subversion",
    "gestor clientes": "Gestor de Clientes",
    "sql server": "Microsoft SQL Server",
    "windows server": "Windows Server",
    "active directory": "Active Directory",
    "freebsd": "FreeBSD",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "mongodb": "MongoDB",
    "sqlite": "SQLite",
    "openssh": "OpenSSH",
    "openssl": "OpenSSL",
    "php": "PHP",
    "gitlab": "GitLab",
    "ldap": "LDAP",
    "jboss": "JBoss",
    "pfsense": "pfSense",
    "libreoffice": "LibreOffice",
    "owncloud": "ownCloud",
    "keepass": "KeePass",
    "winrar": "WinRAR",
    "manictime": "ManicTime",
    "livehelperchat": "Live Helper Chat",
    "dotproject": "dotProject",
    "ofbiz": "Apache OFBiz",
    "jmeter": "Apache JMeter",
    "netbeans": "Apache NetBeans",
    "textpad": "TextPad",
    "pdf24": "PDF24 Creator",
    "aspell": "GNU Aspell",
    "linphone": "Linphone",
    "thunderbird": "Mozilla Thunderbird",
    "firefox": "Mozilla Firefox",
    "chrome": "Google Chrome",
    "edge": "Microsoft Edge",
    "brave": "Brave",
    "adobe": "Adobe Acrobat Reader",
    "moodle": "Moodle",
    "carbonio": "Zextras Carbonio",
    "wazuh": "Wazuh",
    "proxmox": "Proxmox VE",
    "sophos": "Sophos",
    "kawak": "KAWAK",
    "gaia": "Check Point Gaia",
    "tuleap": "Tuleap",
    "chatwoot": "Chatwoot",
    "mattermost": "Mattermost",
    "asterisk": "Asterisk",
    "angular": "Angular",
    "java": "Java",
    "docker": "Docker",
    "nginx": "Nginx",
    "apache": "Apache HTTP Server",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "linux": "Linux",
    "windows": "Microsoft Windows",
    "eclipse": "Eclipse IDE",
    "git": "Git",
}

# Palabras demasiado genericas para usarlas como alias por si solas: si se
# generan automaticamente producen el ruido que se acaba de eliminar.
DEMASIADO_GENERICO = {
    "adobe", "java", "git", "gaia", "access", "office", "server", "cliente",
    "gestor", "gestor de clientes", "central", "sistema", "core", "base",
}


# No son productos instalables con version propia, sino protocolos o conceptos.
# Como alias de palabra generan ruido (cualquier articulo que mencione TLS), y no
# se pueden correlacionar por version. Se desactivan, no se borran: el operador
# puede reactivarlos desde la interfaz si le interesan.
NO_VERSIONABLES = {
    "tls", "ssl", "rdp", "smb", "smtp", "http", "https", "dns", "ldap_protocolo",
    "ftp", "snmp", "ipsec", "kerberos", "ntlm", "oauth", "saml", "tcp", "udp",
    "vpn", "wifi", "bluetooth", "zero_trust", "zero-trust", "ransomware",
    "phishing", "malware",
}


def normalizar_nombre(nombre: str) -> str:
    texto = unicodedata.normalize("NFKD", nombre or "")
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    texto = re.sub(r"[^a-z0-9]+", " ", texto.lower()).strip()
    return re.sub(r"\s+", " ", texto)


# Sufijos que SI distinguen productos distintos: 'Notepad' y 'Notepad++' no son
# lo mismo, ni 'C' y 'C++'. Se preservan en la clave de fusion.
_SUFIJOS_SIGNIFICATIVOS = ("++", "#", ".js", ".net")


def clave_fusion(nombre: str) -> str:
    """Clave con la que se detectan duplicados entre migrado y sembrado."""
    crudo = (nombre or "").lower().strip()
    marca = ""
    for suf in _SUFIJOS_SIGNIFICATIVOS:
        if suf in crudo:
            marca = "|" + suf.replace(".", "")
            break

    base = normalizar_nombre(nombre)
    # 'Microsoft Windows' y 'Windows' son la misma cosa a estos efectos
    for prefijo in ("microsoft ", "google ", "mozilla ", "apache ", "gnu ",
                    "zextras ", "oracle "):
        if base.startswith(prefijo) and len(base) > len(prefijo) + 2:
            base = base[len(prefijo):]
    return base.replace(" ", "") + marca


def puntuar(fila: dict, n_alias: int) -> tuple:
    """Ordena candidatos: gana el que mas informacion util aporta."""
    return (
        n_alias > 0,                                   # tener alias es decisivo
        fila.get("category") not in (None, "aplicacion"),
        bool(fila.get("vendor")),
        bool(fila.get("version_installed")),
        n_alias,
    )


def alias_por_defecto(nombre: str) -> list[dict]:
    """Genera alias razonables para una tecnologia que no tiene ninguno."""
    limpio = (nombre or "").strip()
    if not limpio:
        return []

    base = normalizar_nombre(limpio)
    if base in DEMASIADO_GENERICO:
        # Solo con contexto: evita reintroducir falsos positivos
        return [{"alias": limpio.lower(), "match_mode": "word",
                 "context_required": ["vulnerab", "cve", "exploit", "patch",
                                      "advisory", "security"]}]

    alias: list[dict] = []
    modo = "phrase" if " " in limpio else "word"
    alias.append({"alias": limpio.lower(), "match_mode": modo})

    # Si el nombre lleva fabricante delante, anadir tambien la forma corta
    for prefijo in ("microsoft ", "google ", "mozilla ", "apache ", "gnu ",
                    "zextras ", "oracle ", "check point "):
        if limpio.lower().startswith(prefijo):
            corto = limpio[len(prefijo):].strip()
            if corto and normalizar_nombre(corto) not in DEMASIADO_GENERICO and len(corto) > 3:
                alias.append({"alias": corto.lower(),
                              "match_mode": "phrase" if " " in corto else "word"})
    return alias


def escribir_alias(conn, tec_id: int, entradas: list[dict]) -> int:
    import json
    escritos = 0
    for e in entradas:
        contexto = e.get("context_required")
        conn.execute(
            """INSERT OR IGNORE INTO tech_aliases(technology_id, alias, match_mode,
                   is_exclusion, context_required) VALUES(?,?,?,?,?)""",
            (tec_id, e["alias"].lower(), e.get("match_mode", "word"),
             1 if e.get("is_exclusion") else 0,
             json.dumps(contexto, ensure_ascii=False) if contexto else None),
        )
        escritos += 1
    return escritos


def fusionar(conn, ganador: dict, perdedor: dict, log) -> None:
    """Traslada datos y correlaciones del perdedor al ganador, y lo elimina."""
    campos = []
    valores = []
    for columna in ("version_installed", "version_latest", "systems_count",
                    "owner", "cpe", "vendor"):
        valor_g = ganador.get(columna)
        valor_p = perdedor.get(columna)
        vacio_g = valor_g in (None, "", 0)
        if vacio_g and valor_p not in (None, "", 0):
            campos.append(f"{columna}=?")
            valores.append(valor_p)

    nota = (f"Fusionada con la entrada importada '{perdedor['name']}' "
            f"(slug {perdedor['slug']}).")
    notas_g = (ganador.get("notes") or "").strip()
    campos.append("notes=?")
    valores.append((notas_g + " " + nota).strip() if notas_g else nota)
    campos.append("updated_at=?")
    valores.append(db.utcnow())
    valores.append(ganador["id"])
    conn.execute(f"UPDATE technologies SET {', '.join(campos)} WHERE id=?", valores)

    # Repuntar correlaciones historicas, sin duplicar la clave primaria
    conn.execute(
        """INSERT OR IGNORE INTO threat_technologies(threat_id, technology_id,
               matched_alias, confidence, version_verdict, version_evidence)
           SELECT threat_id, ?, matched_alias, confidence, version_verdict,
                  version_evidence
             FROM threat_technologies WHERE technology_id=?""",
        (ganador["id"], perdedor["id"]),
    )
    movidas = conn.execute(
        "SELECT COUNT(*) FROM threat_technologies WHERE technology_id=?",
        (perdedor["id"],)).fetchone()[0]

    # Conservar los alias del perdedor: puede tener formas que el ganador no
    conn.execute(
        """INSERT OR IGNORE INTO tech_aliases(technology_id, alias, match_mode,
               is_exclusion, context_required)
           SELECT ?, alias, match_mode, is_exclusion, context_required
             FROM tech_aliases WHERE technology_id=?""",
        (ganador["id"], perdedor["id"]),
    )

    conn.execute("DELETE FROM technologies WHERE id=?", (perdedor["id"],))
    log.info("tecnologias fusionadas", extra={
        "conserva": ganador["slug"], "elimina": perdedor["slug"],
        "correlaciones_movidas": movidas})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default=None)
    parser.add_argument("--dry-run", action="store_true",
                        help="informa de lo que haria sin escribir nada")
    args = parser.parse_args()

    setup(level="INFO", log_file="consolidacion.jsonl")
    log = get_logger("consolidacion")

    with db.connect(args.db) as conn:
        filas = [dict(r) for r in conn.execute("SELECT * FROM technologies")]
        alias_por_tec = {
            r["technology_id"]: r["n"] for r in conn.execute(
                "SELECT technology_id, COUNT(*) n FROM tech_aliases "
                "GROUP BY technology_id")
        }

    grupos: dict[str, list[dict]] = {}
    for f in filas:
        grupos.setdefault(clave_fusion(f["name"]), []).append(f)

    duplicados = {k: v for k, v in grupos.items() if len(v) > 1}

    print(f"\n  Tecnologias en inventario : {len(filas)}")
    print(f"  Grupos de duplicados      : {len(duplicados)}")
    print(f"  Sin ningun alias          : "
          f"{sum(1 for f in filas if alias_por_tec.get(f['id'], 0) == 0)}")

    if args.dry_run:
        print("\n  --- FUSIONES QUE SE HARIAN ---")
        for clave, candidatos in sorted(duplicados.items()):
            ordenados = sorted(
                candidatos, key=lambda f: puntuar(f, alias_por_tec.get(f["id"], 0)),
                reverse=True)
            g = ordenados[0]
            print(f"    conserva '{g['name']}' ({g['slug']}, "
                  f"{alias_por_tec.get(g['id'], 0)} alias)")
            for p in ordenados[1:]:
                print(f"      absorbe '{p['name']}' ({p['slug']})")
        print("\n  --- ALIAS QUE SE GENERARIAN (muestra) ---")
        huerfanas = [f for f in filas if alias_por_tec.get(f["id"], 0) == 0]
        for f in huerfanas[:12]:
            nombre = CORRECCIONES_NOMBRE.get(normalizar_nombre(f["name"]), f["name"])
            print(f"    {nombre:28} -> {[a['alias'] for a in alias_por_defecto(nombre)]}")
        print()
        return 0

    fusionadas = renombradas = alias_creados = recategorizadas = 0
    desactivadas = 0

    with db.session(args.db) as conn:
        # ---------------------------------------------- 1. fusionar duplicados
        for candidatos in duplicados.values():
            ordenados = sorted(
                candidatos, key=lambda f: puntuar(f, alias_por_tec.get(f["id"], 0)),
                reverse=True)
            ganador = ordenados[0]
            for perdedor in ordenados[1:]:
                fusionar(conn, ganador, perdedor, log)
                fusionadas += 1

        # ------------------------------- 2. corregir nombres y categorias
        base_por_clave = {clave_fusion(e["name"]): e for e in matching.INVENTARIO_BASE}
        base_por_slug = {e["slug"]: e for e in matching.INVENTARIO_BASE}

        for f in [dict(r) for r in conn.execute("SELECT * FROM technologies")]:
            norma = normalizar_nombre(f["name"])
            nombre_bueno = CORRECCIONES_NOMBRE.get(norma)
            referencia = (base_por_slug.get(f["slug"])
                          or base_por_clave.get(clave_fusion(f["name"])))

            cambios, valores = [], []
            if nombre_bueno and nombre_bueno != f["name"]:
                cambios.append("name=?")
                valores.append(nombre_bueno)
                renombradas += 1

            if referencia:
                if f["category"] in (None, "aplicacion") and referencia.get("category"):
                    cambios.append("category=?")
                    valores.append(referencia["category"])
                    recategorizadas += 1
                if not f.get("vendor") and referencia.get("vendor"):
                    cambios.append("vendor=?")
                    valores.append(referencia["vendor"])
                if f["criticality"] == "medium" and referencia.get("criticality"):
                    cambios.append("criticality=?")
                    valores.append(referencia["criticality"])
                if f["exposure"] == "interna" and referencia.get("exposure"):
                    cambios.append("exposure=?")
                    valores.append(referencia["exposure"])

            if cambios:
                cambios.append("updated_at=?")
                valores.extend([db.utcnow(), f["id"]])
                conn.execute(
                    f"UPDATE technologies SET {', '.join(cambios)} WHERE id=?", valores)

        # --------- 2a. fusionar los que quedaron con nombre identico tras renombrar
        # El recorte de prefijos de clave_fusion separa 'Apache' de
        # 'Apache HTTP Server', pero tras aplicar CORRECCIONES_NOMBRE ambos pasan
        # a llamarse igual. Una pasada por nombre exacto es inequivoca.
        while True:
            grupo = conn.execute(
                """SELECT lower(name) AS clave, COUNT(*) AS n
                     FROM technologies GROUP BY lower(name)
                    HAVING n > 1 LIMIT 1""").fetchone()
            if grupo is None:
                break
            candidatos = [dict(r) for r in conn.execute(
                "SELECT * FROM technologies WHERE lower(name)=?", (grupo["clave"],))]
            conteo = {
                r["technology_id"]: r["n"] for r in conn.execute(
                    "SELECT technology_id, COUNT(*) n FROM threat_technologies "
                    "GROUP BY technology_id")
            }
            # Aqui gana el que arrastra el historico: perder correlaciones seria
            # perder informacion que no se puede reconstruir.
            ordenados = sorted(
                candidatos,
                key=lambda f: (conteo.get(f["id"], 0),
                               bool(f.get("version_installed")),
                               f.get("category") not in (None, "aplicacion")),
                reverse=True)
            for perdedor in ordenados[1:]:
                fusionar(conn, ordenados[0], perdedor, log)
                fusionadas += 1

        # ------------------- 2b. desactivar lo que no es un producto versionable
        for f in [dict(r) for r in conn.execute(
                "SELECT id, name, slug, enabled FROM technologies")]:
            clave = normalizar_nombre(f["name"]).replace(" ", "_")
            if clave in NO_VERSIONABLES and f["enabled"]:
                conn.execute(
                    "UPDATE technologies SET enabled=0, notes=?, updated_at=? "
                    "WHERE id=?",
                    ("Protocolo o concepto, no un producto con version propia: "
                     "desactivado para no generar falsos positivos. Reactivable "
                     "desde la interfaz si se desea seguirlo.",
                     db.utcnow(), f["id"]))
                desactivadas += 1

        # ------------------------------------ 3. generar alias a las huerfanas
        huerfanas = conn.execute(
            """SELECT t.id, t.name, t.slug FROM technologies t
                WHERE NOT EXISTS (SELECT 1 FROM tech_aliases a
                                   WHERE a.technology_id = t.id)""").fetchall()
        for h in huerfanas:
            referencia = base_por_slug.get(h["slug"]) or base_por_clave.get(
                clave_fusion(h["name"]))
            if referencia and referencia.get("aliases"):
                entradas = [
                    {"alias": a} if isinstance(a, str) else a
                    for a in referencia["aliases"]
                ]
            else:
                entradas = alias_por_defecto(h["name"])
            alias_creados += escribir_alias(conn, h["id"], entradas)

        db.audit(conn, "cli", "inventario.consolidar", "technologies", None,
                 f"fusionadas={fusionadas} renombradas={renombradas} "
                 f"alias={alias_creados} recategorizadas={recategorizadas} "
                 f"desactivadas={desactivadas}")

    with db.connect(args.db) as conn:
        total = conn.execute("SELECT COUNT(*) FROM technologies").fetchone()[0]
        sin_alias = conn.execute(
            """SELECT COUNT(*) FROM technologies t WHERE NOT EXISTS
               (SELECT 1 FROM tech_aliases a WHERE a.technology_id=t.id)"""
        ).fetchone()[0]
        alias_total = conn.execute("SELECT COUNT(*) FROM tech_aliases").fetchone()[0]
        correlaciones = conn.execute(
            "SELECT COUNT(*) FROM threat_technologies").fetchone()[0]

    log.info("consolidacion terminada", extra={
        "fusionadas": fusionadas, "renombradas": renombradas,
        "alias_creados": alias_creados, "recategorizadas": recategorizadas,
        "desactivadas": desactivadas, "total": total, "sin_alias": sin_alias})

    print(f"\n  Duplicados fusionados     : {fusionadas}")
    print(f"  Nombres corregidos        : {renombradas}")
    print(f"  Categorias corregidas     : {recategorizadas}")
    print(f"  Alias generados           : {alias_creados}")
    print(f"  Desactivadas (protocolos) : {desactivadas}")
    print(f"  ---")
    print(f"  Tecnologias finales       : {total}")
    print(f"  Sin alias (debe ser 0)    : {sin_alias}")
    print(f"  Alias totales             : {alias_total}")
    print(f"  Correlaciones preservadas : {correlaciones}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
