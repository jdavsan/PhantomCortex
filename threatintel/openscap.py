"""Resultados de OpenSCAP (XCCDF) por activo.

OpenSCAP evalua un sistema contra una guia de configuracion segura (perfil XCCDF
con reglas OVAL): particiones, permisos, servicios, contrasenas, auditoria...
Es complementario a la gestion de vulnerabilidades: aqui no hay CVE sino reglas
de endurecimiento que se cumplen o no. El fichero se genera en el propio equipo y
se sube a la ficha del activo:

    sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level1_server \\
        --results resultados.xml --report informe.html /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml

Se admite el XCCDF de resultados (``--results``) o un ARF (``--results-arf``): se
buscan los elementos TestResult y sus rule-result. Los titulos de las reglas se
toman del Benchmark si viene incluido; si no, se muestra el identificador
abreviado.

Alcance (2026-09-07)
--------------------
Este modulo solo lee lo que alguien haya subido: la plataforma no evalua por si
misma (en este servidor no esta instalada la herramienta ``oscap`` y no hay
agentes ni acceso remoto a los equipos). El apartado de validacion de hardening
del parque que se probo el 2026-09-07 se retiro a peticion del usuario; queda el
panel «Cumplimiento de configuracion» de la ficha del activo, con :func:`importar`,
:func:`resumen_activo` y :func:`fallos_activo`.
"""
from __future__ import annotations

import re
import sqlite3
import xml.etree.ElementTree as ET
from typing import Any, Optional

from . import db
from .logging_setup import get_logger

log = get_logger("openscap")

RESULTADOS = ("pass", "fail", "error", "unknown", "notapplicable", "notchecked", "notselected", "informational", "fixed")
RESULTADO_ES = {"pass": "Cumple", "fail": "No cumple", "error": "Error al comprobar", "unknown": "Desconocido",
                "notapplicable": "No aplica", "notchecked": "No comprobado", "notselected": "No seleccionada",
                "informational": "Informativo", "fixed": "Corregido"}
SEVERIDAD_ES = {"high": "Alta", "medium": "Media", "low": "Baja", "info": "Informativa", "unknown": "Sin severidad"}
#: Clase de insignia con la que la ficha del activo pinta cada severidad de regla.
SEVERIDAD_INSIGNIA = {"high": "high", "medium": "medium", "low": "low",
                      "info": "neutra", "unknown": "neutra"}
MAX_BYTES = 40 * 1024 * 1024


class ErrorOpenSCAP(ValueError):
    """El fichero no contiene resultados XCCDF."""


def _local(etiqueta: str) -> str:
    return etiqueta.rsplit("}", 1)[-1]


def _texto(elem: Optional[ET.Element]) -> str:
    return "".join(elem.itertext()).strip() if elem is not None else ""


def analizar(contenido: bytes | str) -> dict[str, Any]:
    """{"perfil", "evaluado_at", "objetivo", "reglas": [{regla, titulo, severidad, resultado}]}."""
    if isinstance(contenido, str):
        contenido = contenido.encode("utf-8")
    if len(contenido) > MAX_BYTES:
        raise ErrorOpenSCAP("el fichero supera los 40 MB")
    try:
        # Sin resolucion de entidades externas: el parser estandar de ElementTree no las carga.
        raiz = ET.fromstring(contenido)
    except ET.ParseError as exc:
        raise ErrorOpenSCAP(f"XML no válido: {exc}") from exc
    # Titulos y severidades de las reglas (Benchmark, si viene)
    titulos: dict[str, str] = {}
    severidades: dict[str, str] = {}
    for rule in raiz.iter():
        if _local(rule.tag) != "Rule":
            continue
        rid = rule.get("id") or ""
        if not rid:
            continue
        severidades[rid] = (rule.get("severity") or "unknown").lower()
        for hijo in rule:
            if _local(hijo.tag) == "title":
                titulos[rid] = _texto(hijo)[:300]
                break
    resultados = [e for e in raiz.iter() if _local(e.tag) == "TestResult"]
    if not resultados:
        raise ErrorOpenSCAP("no hay ningún TestResult: no es un fichero de resultados XCCDF ni ARF")
    tr = resultados[-1]
    perfil = None
    objetivo = None
    for hijo in tr:
        nombre = _local(hijo.tag)
        if nombre == "profile":
            perfil = hijo.get("idref")
        elif nombre == "target" and not objetivo:
            objetivo = _texto(hijo)
    reglas = []
    for rr in tr:
        if _local(rr.tag) != "rule-result":
            continue
        rid = rr.get("idref") or ""
        resultado = "unknown"
        for hijo in rr:
            if _local(hijo.tag) == "result":
                resultado = (_texto(hijo) or "unknown").lower()
        if resultado not in RESULTADOS:
            resultado = "unknown"
        reglas.append({"regla": rid[:300], "titulo": titulos.get(rid) or _titulo_abreviado(rid),
                       "severidad": (rr.get("severity") or severidades.get(rid) or "unknown").lower(),
                       "resultado": resultado})
    return {"perfil": (perfil or "sin perfil")[:200], "evaluado_at": tr.get("end-time") or tr.get("start-time"),
            "objetivo": objetivo, "reglas": reglas}


_RE_PREFIJO_REGLA = re.compile(r"^xccdf_[^_]+_rule_")


def _titulo_abreviado(rid: str) -> str:
    return _RE_PREFIJO_REGLA.sub("", rid).replace("_", " ")[:200] or rid


def importar(conn: sqlite3.Connection, activo_id: int, contenido: bytes | str, *, fichero: str = "") -> dict[str, Any]:
    datos = analizar(contenido)
    ahora = db.utcnow()
    conn.execute("DELETE FROM cumplimiento WHERE activo_id=? AND perfil=?", (activo_id, datos["perfil"]))
    for r in datos["reglas"]:
        conn.execute(
            """INSERT INTO cumplimiento(activo_id, perfil, regla, titulo, severidad, resultado, evaluado_at, fichero, importado_at)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(activo_id, perfil, regla) DO UPDATE SET titulo=excluded.titulo, severidad=excluded.severidad,
                   resultado=excluded.resultado, evaluado_at=excluded.evaluado_at, fichero=excluded.fichero,
                   importado_at=excluded.importado_at""",
            (activo_id, datos["perfil"], r["regla"], r["titulo"], r["severidad"], r["resultado"],
             datos["evaluado_at"], (fichero or "")[:200] or None, ahora))
    conteo = {k: 0 for k in RESULTADOS}
    for r in datos["reglas"]:
        conteo[r["resultado"]] += 1
    log.info("OpenSCAP importado", extra={"activo_id": activo_id, "perfil": datos["perfil"], "reglas": len(datos["reglas"]),
                                          "fail": conteo["fail"]})
    return {"perfil": datos["perfil"], "reglas": len(datos["reglas"]), "conteo": conteo,
            "objetivo": datos["objetivo"], "evaluado_at": datos["evaluado_at"]}


def resumen_activo(conn: sqlite3.Connection, activo_id: int) -> dict[str, Any]:
    perfiles = []
    for p in conn.execute(
            """SELECT perfil, COUNT(*) AS reglas, SUM(resultado='pass') AS cumple, SUM(resultado='fail') AS falla,
                      SUM(resultado='fail' AND severidad='high') AS falla_alta, MAX(evaluado_at) AS evaluado_at,
                      MAX(importado_at) AS importado_at
                 FROM cumplimiento WHERE activo_id=? GROUP BY perfil ORDER BY importado_at DESC""", (activo_id,)):
        d = dict(p)
        evaluadas = int(d["cumple"] or 0) + int(d["falla"] or 0)
        d["pct"] = round(int(d["cumple"] or 0) * 100.0 / evaluadas, 1) if evaluadas else None
        d["perfil_corto"] = re.sub(r"^xccdf_[^_]+_profile_", "", d["perfil"] or "")
        perfiles.append(d)
    return {"perfiles": perfiles}


def contar_fallos_activo(conn: sqlite3.Connection, activo_id: int) -> int:
    """Reglas que el equipo no cumple, sin recorte: el total para la paginacion."""
    return int(conn.execute(
        "SELECT COUNT(*) FROM cumplimiento WHERE activo_id=? AND resultado IN ('fail','error')",
        (activo_id,)).fetchone()[0] or 0)


def fallos_activo(conn: sqlite3.Connection, activo_id: int, *, limite: int = 200,
                  desplazamiento: int = 0) -> list[dict]:
    """Reglas que el equipo no cumple, de la peor severidad a la mejor.

    ``desplazamiento`` (2026-09-07) pagina la lista en la ficha del activo: un perfil
    del CIS trae mas de 200 reglas y antes solo se ensenaban las primeras.
    """
    filas = [dict(r) for r in conn.execute(
        """SELECT perfil, regla, titulo, severidad, resultado FROM cumplimiento
            WHERE activo_id=? AND resultado IN ('fail','error')
            ORDER BY CASE severidad WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,
                     titulo, regla
            LIMIT ? OFFSET ?""", (activo_id, max(1, int(limite or 1)), max(0, int(desplazamiento or 0))))]
    for f in filas:
        f["severidad_es"] = SEVERIDAD_ES.get(f["severidad"], f["severidad"])
        f["resultado_es"] = RESULTADO_ES.get(f["resultado"], f["resultado"])
        f["severidad_insignia"] = SEVERIDAD_INSIGNIA.get(f["severidad"], "neutra")
    return filas
