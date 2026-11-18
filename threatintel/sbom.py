"""Inventario de componentes de aplicacion (SBOM) por activo.

Un SBOM (lista de materiales de software) dice que bibliotecas y paquetes lleva
dentro una aplicacion, cosa que OCS Inventory no ve: OCS lista programas
instalados, no las dependencias de una aplicacion Java, Python o Node. Se importa
un fichero CycloneDX (JSON) o SPDX (JSON) generado con herramientas como
``syft``, ``cyclonedx-bom`` o ``trivy``, y cada componente se evalua contra
OSV.dev por su ecosistema (PyPI, npm, Maven, Go, crates.io, NuGet, RubyGems,
Packagist...). Los hallazgos van a ``aplicabilidad`` con motor ``sbom`` y
quedan en la ficha del activo junto a los del sistema operativo.

Como generar el fichero en el servidor de la aplicacion:
    syft /ruta/app -o cyclonedx-json > app.cdx.json
    trivy fs --format cyclonedx --output app.cdx.json /ruta/app
"""
from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Iterable, Optional
from urllib.parse import unquote

from . import db, http
from .logging_setup import get_logger

log = get_logger("sbom")

URL_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
LOTE_OSV = 500
MAX_COMPONENTES = 5000

#: Tipo de purl -> ecosistema OSV. Los paquetes del sistema (deb, rpm, apk) no se
#: evaluan aqui: ya lo hace el motor de aplicabilidad con el inventario de OCS.
ECOSISTEMAS = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go", "cargo": "crates.io",
               "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist", "hex": "Hex", "pub": "Pub",
               "swift": "SwiftURL", "cran": "CRAN", "hackage": "Hackage"}
_RE_PURL = re.compile(r"^pkg:([a-z0-9.+-]+)/(?:([^/]+)/)?([^@?#]+)(?:@([^?#]+))?")
_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


class ErrorSBOM(ValueError):
    """El fichero no es un SBOM reconocible."""


def _purl(cadena: Optional[str]) -> Optional[dict[str, str]]:
    m = _RE_PURL.match((cadena or "").strip())
    if not m:
        return None
    tipo, espacio, nombre, version = m.groups()
    nombre = unquote(nombre)
    if espacio:
        espacio = unquote(espacio)
        nombre = f"{espacio}:{nombre}" if tipo == "maven" else (f"{espacio}/{nombre}" if tipo in ("npm", "golang", "composer") else nombre)
    return {"tipo": tipo, "nombre": nombre, "version": unquote(version or "")}


def analizar(contenido: bytes | str) -> dict[str, Any]:
    """Devuelve {"formato", "aplicacion", "componentes": [{nombre, version, ecosistema, purl}]}."""
    texto = contenido.decode("utf-8", "replace") if isinstance(contenido, bytes) else contenido
    try:
        datos = json.loads(texto)
    except ValueError as exc:
        raise ErrorSBOM("el fichero no es JSON válido (se admiten CycloneDX y SPDX en JSON)") from exc
    if not isinstance(datos, dict):
        raise ErrorSBOM("el fichero no es un SBOM reconocible")
    componentes: list[dict] = []
    if datos.get("bomFormat") == "CycloneDX" or "components" in datos:
        formato = "CycloneDX"
        meta = datos.get("metadata") or {}
        aplicacion = ((meta.get("component") or {}).get("name")) or None
        for c in datos.get("components") or []:
            if not isinstance(c, dict) or not c.get("name"):
                continue
            purl = _purl(c.get("purl"))
            componentes.append({"nombre": str(purl["nombre"] if purl else c["name"])[:200],
                                "version": str(c.get("version") or (purl or {}).get("version") or "")[:100],
                                "ecosistema": ECOSISTEMAS.get((purl or {}).get("tipo", "")) or None,
                                "tipo_purl": (purl or {}).get("tipo"), "purl": (c.get("purl") or "")[:400] or None})
    elif datos.get("spdxVersion") or "packages" in datos:
        formato = "SPDX"
        aplicacion = datos.get("name")
        for pq in datos.get("packages") or []:
            if not isinstance(pq, dict) or not pq.get("name"):
                continue
            purl_txt = next((r.get("referenceLocator") for r in pq.get("externalRefs") or []
                             if r.get("referenceType") == "purl"), None)
            purl = _purl(purl_txt)
            componentes.append({"nombre": str(purl["nombre"] if purl else pq["name"])[:200],
                                "version": str(pq.get("versionInfo") or (purl or {}).get("version") or "")[:100],
                                "ecosistema": ECOSISTEMAS.get((purl or {}).get("tipo", "")) or None,
                                "tipo_purl": (purl or {}).get("tipo"), "purl": (purl_txt or "")[:400] or None})
    else:
        raise ErrorSBOM("el fichero no es CycloneDX ni SPDX")
    if len(componentes) > MAX_COMPONENTES:
        raise ErrorSBOM(f"demasiados componentes ({len(componentes)}); el límite es {MAX_COMPONENTES}")
    return {"formato": formato, "aplicacion": aplicacion, "componentes": componentes}


def importar(conn: sqlite3.Connection, activo_id: int, contenido: bytes | str, *, fichero: str = "",
             reemplazar: bool = True) -> dict[str, Any]:
    """Guarda los componentes en ``activo_componentes`` (sustituyendo los del mismo fichero)."""
    datos = analizar(contenido)
    ahora = db.utcnow()
    nombre_fichero = (fichero or datos.get("aplicacion") or "sbom")[:200]
    if reemplazar:
        conn.execute("DELETE FROM activo_componentes WHERE activo_id=? AND fichero=?", (activo_id, nombre_fichero))
    n = 0
    for c in datos["componentes"]:
        conn.execute(
            """INSERT INTO activo_componentes(activo_id, nombre, version, ecosistema, purl, fichero, importado_at)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(activo_id, nombre, version, ecosistema) DO UPDATE SET purl=excluded.purl,
                   fichero=excluded.fichero, importado_at=excluded.importado_at""",
            (activo_id, c["nombre"], c["version"], c["ecosistema"], c["purl"], nombre_fichero, ahora))
        n += 1
    evaluables = sum(1 for c in datos["componentes"] if c["ecosistema"] and c["version"])
    log.info("SBOM importado", extra={"activo_id": activo_id, "componentes": n, "evaluables": evaluables,
                                      "formato": datos["formato"]})
    return {"formato": datos["formato"], "aplicacion": datos.get("aplicacion"), "componentes": n,
            "evaluables": evaluables, "fichero": nombre_fichero}


def evaluar(conn: sqlite3.Connection, activo_id: int, *, cfg: Any = None, osv=None, post=None,
            max_registros: int = 300) -> dict[str, Any]:
    """Consulta OSV.dev por lotes para los componentes con ecosistema y version, trae
    el detalle de cada vulnerabilidad (con cache) y guarda los veredictos como
    ``afectado`` (motor ``sbom``). La correccion se toma del rango del ecosistema."""
    from .aplicabilidad import AFECTADO, ClienteOSV, _guardar_filas, marca_evaluacion
    post = post or http.post_json
    osv = osv or ClienteOSV(conn, cfg=cfg, max_peticiones=max_registros)
    componentes = [dict(r) for r in conn.execute(
        "SELECT id, nombre, version, ecosistema, purl FROM activo_componentes "
        "WHERE activo_id=? AND ecosistema IS NOT NULL AND version<>''", (activo_id,))]
    ahora = marca_evaluacion()
    filas: list[dict] = []
    vulns_total = 0
    errores: list[str] = []
    conn.execute("DELETE FROM aplicabilidad WHERE activo_id=? AND motor='sbom'", (activo_id,))
    for i in range(0, len(componentes), LOTE_OSV):
        lote = componentes[i:i + LOTE_OSV]
        cuerpo = {"queries": [{"package": {"name": c["nombre"], "ecosistema": c["ecosistema"]} | {"ecosystem": c["ecosistema"]},
                               "version": c["version"]} for c in lote]}
        for q in cuerpo["queries"]:
            q["package"].pop("ecosistema", None)
        res = post(URL_OSV_BATCH, cuerpo, timeout=40, user_agent=cfg.get("http_user_agent") if cfg is not None else None)
        if not res.ok or not isinstance(res.data, dict):
            errores.append(f"OSV.dev querybatch: {res.error or res.status}")
            break
        for c, resultado in zip(lote, res.data.get("results") or []):
            for v in (resultado or {}).get("vulns") or []:
                vulns_total += 1
                id_osv = str(v.get("id") or "")
                if not id_osv:
                    continue
                try:
                    registro = osv.registro(id_osv)
                except Exception as exc:  # noqa: BLE001 - cupo o red: se registra sin detalle
                    registro = None
                    errores.append(f"{id_osv}: {exc}")
                cves = [a for a in ((registro or {}).get("aliases") or []) if _RE_CVE.match(str(a))]
                if _RE_CVE.match(id_osv):
                    cves.insert(0, id_osv)
                identificador = (cves[0] if cves else id_osv).upper()
                corregida = None
                for a in (registro or {}).get("affected") or []:
                    if (a.get("package") or {}).get("ecosystem") != c["ecosistema"]:
                        continue
                    for r in a.get("ranges") or []:
                        for e in r.get("events") or []:
                            if e.get("fixed"):
                                corregida = e["fixed"]
                resumen = ((registro or {}).get("summary") or (registro or {}).get("details") or "")[:160]
                filas.append({"activo_id": activo_id, "threat_id": None, "cve": identificador,
                              "paquete": f"{c['ecosistema']}:{c['nombre']}"[:200], "version_instalada": c["version"],
                              "version_corregida": corregida, "veredicto": AFECTADO, "motor": "sbom",
                              "evidencia": (f"{c['nombre']} {c['version']} ({c['ecosistema']}) figura como vulnerable en OSV.dev"
                                            + (f"; corregido en {corregida}" if corregida else "; sin corrección publicada")
                                            + (f" · {resumen}" if resumen else "")),
                              "aviso": id_osv if id_osv != identificador else None, "evaluado_at": ahora})
    # Enlazar con amenazas conocidas por CVE
    for f in filas:
        fila = conn.execute("SELECT id FROM threats WHERE cve=? ORDER BY relevance DESC LIMIT 1", (f["cve"],)).fetchone()
        if fila:
            f["threat_id"] = fila["id"]
    _guardar_filas(conn, filas)
    return {"componentes": len(componentes), "vulnerabilidades": len(filas), "consultas_osv": osv.peticiones,
            "errores": errores, "evaluado_at": ahora}


def resumen_activo(conn: sqlite3.Connection, activo_id: int) -> dict[str, Any]:
    """Componentes importados de un activo y cuantas vulnerabilidades salieron de ellos.

    ``vulnerabilidades`` son CVE distintos con veredicto «afectado» del motor ``sbom``.
    No cuenta la severidad baja (2026-09-10, orden del usuario; ajuste
    ``ignore_low_severity``): la ficha del activo no puede decir una cifra de
    vulnerabilidades en la tarjeta del inventario de componentes y otra distinta, con
    otro criterio, en el resto de la pagina.
    """
    sin_bajas = ("" if not bool(db.get_setting(conn, "ignore_low_severity", True))
                 else " AND NOT EXISTS (SELECT 1 FROM threats tb WHERE tb.id = ap.threat_id "
                      "AND tb.severity = 'Low')")
    fila = conn.execute(
        """SELECT COUNT(*) AS componentes, SUM(ecosistema IS NOT NULL AND version<>'') AS evaluables,
                  COUNT(DISTINCT fichero) AS ficheros, MAX(importado_at) AS ultimo
             FROM activo_componentes WHERE activo_id=?""", (activo_id,)).fetchone()
    vul = conn.execute(
        f"""SELECT COUNT(DISTINCT ap.cve) FROM aplicabilidad ap
             WHERE ap.activo_id=? AND ap.motor='sbom' AND ap.veredicto='afectado'{sin_bajas}""",
        (activo_id,)).fetchone()[0]
    ficheros = [dict(r) for r in conn.execute(
        "SELECT fichero, COUNT(*) AS n, MAX(importado_at) AS importado_at FROM activo_componentes WHERE activo_id=? GROUP BY fichero",
        (activo_id,))]
    return {"componentes": int(fila["componentes"] or 0), "evaluables": int(fila["evaluables"] or 0),
            "ficheros": ficheros, "ultimo": fila["ultimo"], "vulnerabilidades": int(vul or 0)}
