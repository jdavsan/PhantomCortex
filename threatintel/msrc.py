"""Nivel de parche de Windows con los boletines de seguridad de Microsoft (MSRC).

Microsoft publica cada mes un documento CVRF (https://api.msrc.microsoft.com/cvrf/v3.0/)
que, para cada CVE, dice que compilacion (FixedBuild) y que actualizacion acumulativa (KB)
lo corrigen en cada producto Windows. OCS Inventory ve en cada equipo Windows las KB
instaladas («Security Update KB5123304»). Cruzando ambas cosas se deduce la compilacion
efectiva de cada equipo y se confirma o descarta cada CVE de Windows por equipo, con el
motor ``msrc`` de la tabla ``aplicabilidad``.

Como funciona, paso a paso:

1. ``actualizar`` lista los boletines mensuales, descarga los de los ultimos ``msrc_meses``
   que falten o hayan sido revisados (copia en ``data/cache/msrc/<ID>.json``) y guarda en
   ``msrc_correcciones`` una fila por (CVE, producto Windows) con la KB y la compilacion
   corregida mas baja que lo arregla. Solo productos «Windows 10», «Windows 11» y
   «Windows Server»; de cada CVE solo las remediaciones de tipo 2 con FixedBuild.
2. ``evaluar_activos`` asigna a cada equipo Windows su producto MSRC (el que tiene
   compilaciones que empiezan por su ``so_version``), cruza las KB que OCS ve instaladas con
   las KB de ese producto y toma la compilacion mas alta como compilacion efectiva
   (``activos.windows_build``). Despues, para cada amenaza abierta con CVE corregido en ese
   producto, escribe el veredicto: ``no_afectado`` si la compilacion instalada es igual o
   mayor que la corregida, ``afectado`` si es menor y ``sin_dato`` si no se reconoce ninguna
   KB. Las filas van con ``paquete='windows'`` para no pisar a los otros motores.
3. ``resumen_activo`` y ``resumen`` alimentan la ficha del activo y los paneles.

Tablas: ``msrc_documentos``, ``msrc_correcciones`` y las columnas ``windows_*`` de ``activos``
(esquema v6). Ajustes: ``msrc_enabled``, ``msrc_meses``, ``msrc_cache_hours``.

Orden de ejecucion. ``aplicabilidad.evaluar_amenaza`` borra TODAS las filas de una amenaza con
``evaluado_at`` anterior a su marca, tambien las de este motor. Por eso ``evaluar_activos`` debe
ejecutarse DESPUES de ``aplicabilidad.evaluar_pendientes`` y ANTES de ``remediacion.sincronizar``
(si no, las remediaciones de Windows se cerrarian como «paquete desinstalado» y se reabririan al
dia siguiente). Es barato (unos segundos con 40.000 correcciones) y idempotente, asi que puede
llamarse tantas veces como haga falta en la misma pasada.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from . import aplicabilidad, db, http
from .logging_setup import get_logger
from .notify import MESES, fecha_larga
from .paths import DATA_DIR

log = get_logger("msrc")

MOTOR = "msrc"
#: Valor de ``aplicabilidad.paquete`` de las filas de este motor: clave unica (activo, cve, paquete).
PAQUETE = "windows"
URL_LISTA = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
URL_DOCUMENTO = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{documento}"
CACHE_DIR = DATA_DIR / "cache" / "msrc"
PREFIJOS_WINDOWS = ("Windows 10", "Windows 11", "Windows Server")
TIMEOUT_S = 120
REINTENTOS = 2
#: Los boletines de hace mas de dos meses se revisan como mucho una vez por semana aunque
#: Microsoft los retoque (suele actualizar todos a la vez).
HORAS_REFRESCO_ANTIGUOS = 24 * 7
ESTADOS_CERRADOS_SQL = "('descartada','falso_positivo','mitigada')"
_MARCA_LINEA = "Boletín de seguridad de Microsoft (MSRC)"

_RE_KB = re.compile(r"\bKB\s?(\d{6,7})\b", re.I)
_RE_BUILD = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
_RE_ID_DOCUMENTO = re.compile(r"^\d{4}-[A-Z][a-z]{2}$")


# --------------------------------------------------------------------------
# Utilidades puras (sin base de datos)
# --------------------------------------------------------------------------
def _ajuste(cfg: Any, clave: str, defecto: Any) -> Any:
    if cfg is None:
        return defecto
    try:
        valor = cfg.get(clave, defecto)
    except AttributeError:
        return defecto
    return defecto if valor in (None, "") else valor


def _activado(cfg: Any) -> bool:
    valor = _ajuste(cfg, "msrc_enabled", True)
    if isinstance(valor, str):
        return valor.strip().lower() not in ("0", "false", "no", "off")
    return bool(valor)


def _ahora() -> datetime:
    """Instante actual en UTC (funcion aparte para poder fijarla en las pruebas)."""
    return datetime.now(timezone.utc)


def _a_datetime(valor: Any) -> Optional[datetime]:
    if isinstance(valor, datetime):
        return valor if valor.tzinfo else valor.replace(tzinfo=timezone.utc)
    if not valor:
        return None
    texto = str(valor).strip()
    try:
        dt = datetime.fromisoformat(texto.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = datetime.fromisoformat(texto[:19])
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(valor: Any) -> Optional[str]:
    """Fecha ISO-8601 UTC con sufijo Z (formato unico de la base), o None."""
    dt = _a_datetime(valor)
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def tupla_build(build: Optional[str]) -> Optional[tuple[int, ...]]:
    """'10.0.26200.9106' -> (10, 0, 26200, 9106) para comparar numericamente."""
    if not build:
        return None
    partes = str(build).strip().split(".")
    try:
        return tuple(int(p) for p in partes)
    except ValueError:
        return None


def comparar_builds(a: Optional[str], b: Optional[str]) -> Optional[int]:
    """-1, 0 o 1 segun ``a`` sea menor, igual o mayor que ``b``; None si alguna no es una compilacion."""
    ta, tb = tupla_build(a), tupla_build(b)
    if ta is None or tb is None:
        return None
    return (ta > tb) - (ta < tb)


def extraer_kbs(nombres: Iterable[str]) -> set[str]:
    """Numeros de KB (solo digitos) presentes en nombres de software de OCS:
    'Security Update KB5123304' -> {'5123304'}."""
    salida: set[str] = set()
    for nombre in nombres:
        for m in _RE_KB.finditer(str(nombre or "")):
            salida.add(m.group(1))
    return salida


def es_producto_windows(nombre: Optional[str]) -> bool:
    return bool(nombre) and str(nombre).startswith(PREFIJOS_WINDOWS)


def productos_windows(documento: dict) -> dict[str, str]:
    """ProductID -> nombre de los productos Windows 10, Windows 11 y Windows Server del documento."""
    arbol = (documento or {}).get("ProductTree") or {}
    salida: dict[str, str] = {}
    for p in arbol.get("FullProductName") or []:
        nombre = str((p or {}).get("Value") or "").strip()
        pid = str((p or {}).get("ProductID") or "").strip()
        if pid and es_producto_windows(nombre):
            salida[pid] = nombre
    return salida


def _texto(valor: Any) -> str:
    if isinstance(valor, dict):
        return str(valor.get("Value") or "").strip()
    return str(valor or "").strip()


def es_fila_catalogo(cve: Optional[str]) -> bool:
    """Las filas de ``msrc_correcciones`` cuyo ``cve`` empieza por «KB» no son CVE: forman el
    catalogo KB -> compilacion de cada producto (todas las acumulativas del boletin, tambien las
    reediciones fuera de ciclo que nunca son la primera correccion de ningun CVE)."""
    return str(cve or "").upper().startswith("KB")


def correcciones_de(documento: dict, *, documento_id: str, publicado_at: Optional[str]) -> list[dict]:
    """Filas para ``msrc_correcciones``: una por (CVE, producto Windows) con la compilacion
    corregida MAS BAJA que lo arregla (si el boletin lista varias, la primera ya lo corrige)
    y la KB que la instala; y ademas una fila de catalogo por (KB, producto) con ``cve``
    «KB<numero>» y la compilacion que esa KB instala en la rama del producto (ver
    ``es_fila_catalogo``): asi se reconoce la KB instalada aunque sea una reedicion."""
    productos = productos_windows(documento)
    if not productos:
        return []
    vulnerabilidades = (documento or {}).get("Vulnerability") or []

    def remediaciones():
        for vuln in vulnerabilidades:
            cve = str((vuln or {}).get("CVE") or "").strip().upper()
            if not cve.startswith("CVE-"):
                continue
            for rem in vuln.get("Remediations") or []:
                if (rem or {}).get("Type") != 2:
                    continue
                build = str(rem.get("FixedBuild") or "").strip()
                if not _RE_BUILD.match(build):
                    continue
                kb_texto = _texto(rem.get("Description"))
                kb = kb_texto if kb_texto.isdigit() else None
                for pid in rem.get("ProductID") or []:
                    pid = str(pid)
                    if pid in productos:
                        yield cve, pid, build, kb

    # Primera pasada: la rama (tres primeros componentes) de cada producto. Cada producto tiene
    # una sola («Windows 11 Version 24H2» es 10.0.26100); las demas son ruido del boletin
    # (p. ej. la KB compartida de 24H2 y 25H2 listada con las dos compilaciones).
    ramas: dict[str, dict[str, int]] = {}
    for _, pid, build, _ in remediaciones():
        rama = build.rsplit(".", 1)[0]
        ramas.setdefault(pid, {})[rama] = ramas.get(pid, {}).get(rama, 0) + 1
    dominante = {pid: max(conteo, key=conteo.get) for pid, conteo in ramas.items()}

    filas: dict[tuple[str, str], dict] = {}
    catalogo: dict[tuple[str, str], set[str]] = {}          # (pid, kb) -> compilaciones
    for cve, pid, build, kb in remediaciones():
        if build.rsplit(".", 1)[0] != dominante[pid]:
            continue
        if kb:
            catalogo.setdefault((pid, kb), set()).add(build)
        clave = (cve, pid)
        anterior = filas.get(clave)
        if anterior is not None:
            cmp = comparar_builds(build, anterior["build_corregida"])
            if cmp is None or cmp > 0:
                continue
            if cmp == 0 and (kb is None or (anterior["kb"] and int(kb) >= int(anterior["kb"]))):
                continue
        filas[clave] = {"cve": cve, "producto_id": pid, "producto": productos[pid], "kb": kb,
                        "build_corregida": build, "documento": documento_id, "publicado_at": publicado_at}
    salida = list(filas.values())
    for (pid, kb), builds in catalogo.items():
        # Varias compilaciones para la misma KB: la mas alta es la que instala.
        mejor = max(builds, key=lambda b: tupla_build(b) or ())
        salida.append({"cve": f"KB{kb}", "producto_id": pid, "producto": productos[pid], "kb": kb,
                       "build_corregida": mejor, "documento": documento_id, "publicado_at": publicado_at})
    return salida


def arquitectura_preferida(activo: dict) -> str:
    """Texto que identifica la edicion del producto MSRC segun la arquitectura que informa OCS:
    «arm64» (ARM64), «32-bit» («x86 32 bit», «i386») o «x64» (por defecto)."""
    arquitectura = str(activo.get("arquitectura") or "").lower()
    if "arm" in arquitectura:
        return "arm64"
    if "64" not in arquitectura and ("32" in arquitectura or "x86" in arquitectura or "i386" in arquitectura):
        return "32-bit"
    return "x64"


def elegir_producto(activo: dict, candidatos: Iterable[tuple[str, str]]) -> Optional[tuple[str, str]]:
    """Entre los productos MSRC con compilaciones de la misma rama que el activo, elige el que
    encaja. Servidor con servidor y puesto con puesto, sin cruzarlos nunca: si en la rama solo
    hay productos del otro tipo (un Windows 7 frente a Windows Server 2008 R2, que comparten la
    compilacion 6.1.7601) el activo se queda sin producto. Entre los compatibles se prefiere la
    edicion de la arquitectura que informa OCS (ARM64, 32 bits o, por defecto, x64) y se evita
    «Server Core». Si OCS no informa del nombre del sistema no se puede saber si es servidor y se
    admite cualquiera."""
    lista = list(candidatos)
    if not lista:
        return None
    so_nombre = str(activo.get("so_nombre") or "").lower()
    if so_nombre:
        activo_servidor = "server" in so_nombre
        lista = [par for par in lista if par[1].lower().startswith("windows server") == activo_servidor]
        if not lista:
            return None
    preferida = arquitectura_preferida(activo)

    def puntuar(par: tuple[str, str]) -> tuple[int, int, str]:
        nombre = par[1].lower()
        puntos = -10 if "server core" in nombre else 0
        if preferida in nombre:
            puntos += 5
        elif "x64" in nombre:
            puntos += 1          # sin edicion de su arquitectura, la x64 (mismas KB y compilaciones)
        return (puntos, -len(nombre), par[0])

    return max(lista, key=puntuar)


def candidatos_por_rama(productos: dict[str, tuple[str, dict[str, int]]], so_version: Optional[str]
                        ) -> list[tuple[str, str]]:
    """``productos``: pid -> (nombre, {rama: n filas}). Devuelve los (pid, nombre) cuya rama
    mayoritaria es ``so_version``; si ninguno la tiene por mayoria, los que la tengan siquiera."""
    base = str(so_version or "").strip()
    if not base:
        return []
    con_rama = [(pid, nombre, conteo.get(base, 0), sum(conteo.values()))
                for pid, (nombre, conteo) in productos.items() if conteo.get(base)]
    mayoritarios = [(pid, nombre) for pid, nombre, k, total in con_rama if k * 2 > total]
    return mayoritarios or [(pid, nombre) for pid, nombre, _, _ in con_rama]


def _meses_entre(desde: Optional[str], hasta: Optional[str]) -> Optional[int]:
    a, b = _a_datetime(desde), _a_datetime(hasta)
    if a is None or b is None:
        return None
    return max(0, (b.year - a.year) * 12 + (b.month - a.month))


def _mes_es(valor: Optional[str]) -> str:
    dt = _a_datetime(valor)
    if dt is None:
        return "fecha desconocida"
    return f"{MESES[dt.month - 1]} de {dt.year}"


def _kb_texto(kb: Optional[str]) -> str:
    if not kb:
        return "sin KB"
    kb = str(kb)
    return kb if kb.upper().startswith("KB") else f"KB{kb}"


# --------------------------------------------------------------------------
# Descarga y almacenamiento de los boletines
# --------------------------------------------------------------------------
#: Los documentos CVRF en JSON pesan de 8 a 13 MB (y en XML casi 20): por encima del limite de
#: 15 MB de ``http.fetch_json`` se descargan con ``requests`` directamente, con la misma
#: validacion de destino. El servicio devuelve XML si Accept no es exactamente application/json.
LIMITE_DOCUMENTO_BYTES = 96 * 1024 * 1024
_ACCEPT_JSON_ESTRICTO = {"Accept": "application/json"}


def _descargar_documento(url: str) -> http.JsonResult:
    """GET de un documento CVRF grande: destino validado (sin redirecciones), Accept JSON estricto,
    lectura acotada a ``LIMITE_DOCUMENTO_BYTES``, tiempo limite de 120 s y dos reintentos."""
    import requests
    inicio = time.perf_counter()
    try:
        http.validar_destino(url)
    except http.DestinoProhibido as exc:
        log.warning("destino rechazado por política de red", extra={"url_pedida": url, "motivo": str(exc)})
        return http.JsonResult(False, None, None, "destino_prohibido", 0)
    cabeceras = {"User-Agent": http.USER_AGENT_POR_DEFECTO, "Accept-Encoding": "gzip, deflate", **_ACCEPT_JSON_ESTRICTO}
    estado: Optional[int] = None
    error = "conexion"
    for intento in range(REINTENTOS + 1):
        try:
            with requests.get(url, headers=cabeceras, timeout=TIMEOUT_S, stream=True, allow_redirects=False) as resp:
                estado = resp.status_code
                if estado in (301, 302, 303, 307, 308):
                    return http.JsonResult(False, estado, None, "redirecciones", int((time.perf_counter() - inicio) * 1000))
                if estado != 200:
                    error = f"http_{estado}"
                    if estado not in (429, 500, 502, 503, 504):
                        break
                    raise requests.HTTPError(error)
                trozos: list[bytes] = []
                total = 0
                for trozo in resp.iter_content(chunk_size=1 << 16):
                    if not trozo:
                        continue
                    total += len(trozo)
                    if total > LIMITE_DOCUMENTO_BYTES:
                        return http.JsonResult(False, estado, None, "respuesta_demasiado_grande",
                                               int((time.perf_counter() - inicio) * 1000))
                    trozos.append(trozo)
            try:
                datos = json.loads(b"".join(trozos))
            except (ValueError, UnicodeDecodeError):
                return http.JsonResult(False, estado, None, "parse", int((time.perf_counter() - inicio) * 1000))
            return http.JsonResult(True, estado, datos, None, int((time.perf_counter() - inicio) * 1000))
        except requests.RequestException as exc:
            error = error if isinstance(exc, requests.HTTPError) else http.clasificar_excepcion(exc)
        if intento < REINTENTOS:
            time.sleep(2.0 * (intento + 1))
    return http.JsonResult(False, estado, None, error, int((time.perf_counter() - inicio) * 1000))


def _fetch_por_defecto(url: str) -> http.JsonResult:
    if url == URL_LISTA:
        return http.fetch_json(url, timeout=TIMEOUT_S, retries=REINTENTOS, api_key_header=_ACCEPT_JSON_ESTRICTO)
    return _descargar_documento(url)


def _cache_ruta(documento_id: str) -> Path:
    return CACHE_DIR / f"{documento_id}.json"


def _leer_cache(documento_id: str) -> Optional[dict]:
    ruta = _cache_ruta(documento_id)
    try:
        if not ruta.is_file():
            return None
        datos = json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("copia local del boletín ilegible", extra={"documento": documento_id, "error": str(exc)})
        return None
    return datos if isinstance(datos, dict) and "Vulnerability" in datos else None


def _escribir_cache(documento_id: str, datos: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        ruta = _cache_ruta(documento_id)
        tmp = ruta.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(datos, ensure_ascii=False), encoding="utf-8")
        tmp.replace(ruta)
        try:
            ruta.chmod(0o640)
        except OSError:
            pass
    except OSError as exc:
        log.warning("no se pudo guardar la copia local del boletín",
                    extra={"documento": documento_id, "error": str(exc)})


def _borrar_cache(documento_id: str) -> None:
    try:
        _cache_ruta(documento_id).unlink(missing_ok=True)
    except OSError:
        pass


def _revision_documento(datos: dict) -> Optional[str]:
    seguimiento = (datos or {}).get("DocumentTracking") or {}
    return _iso(seguimiento.get("CurrentReleaseDate") or seguimiento.get("InitialReleaseDate"))


def _ventana(ahora: datetime, meses: int) -> str:
    """Primer dia del mes que abre la ventana de ``meses`` boletines (ISO UTC)."""
    meses = max(1, int(meses))
    anio, mes = ahora.year, ahora.month - (meses - 1)
    while mes <= 0:
        mes += 12
        anio -= 1
    return f"{anio:04d}-{mes:02d}-01T00:00:00Z"


def _documentos_en_ventana(lista: list[dict], *, ahora: datetime, meses: int) -> list[dict]:
    limite = _ventana(ahora, meses)
    salida: list[dict] = []
    for e in lista or []:
        ident = str((e or {}).get("ID") or "").strip()
        publicado = _iso(e.get("InitialReleaseDate"))
        if not _RE_ID_DOCUMENTO.match(ident) or not publicado or publicado < limite:
            continue
        salida.append({"documento": ident, "publicado_at": publicado,
                       "revisado_at": _iso(e.get("CurrentReleaseDate")) or publicado,
                       "url": str(e.get("CvrfUrl") or URL_DOCUMENTO.format(documento=ident))})
    salida.sort(key=lambda d: d["publicado_at"])
    return salida


def _guardar_documento(conn: sqlite3.Connection, doc: dict, datos: dict, *, descargado_at: str) -> int:
    """Sustituye las correcciones del documento y anota el boletin. Devuelve las filas guardadas."""
    filas = correcciones_de(datos, documento_id=doc["documento"], publicado_at=doc["publicado_at"])
    conn.execute("DELETE FROM msrc_correcciones WHERE documento=?", (doc["documento"],))
    if filas:
        # Si un CVE se reedita en un boletin posterior, manda el mas reciente.
        conn.executemany(
            """INSERT INTO msrc_correcciones(cve, producto_id, producto, kb, build_corregida, documento, publicado_at)
               VALUES(:cve, :producto_id, :producto, :kb, :build_corregida, :documento, :publicado_at)
               ON CONFLICT(cve, producto_id) DO UPDATE SET
                   producto=excluded.producto, kb=excluded.kb, build_corregida=excluded.build_corregida,
                   documento=excluded.documento, publicado_at=excluded.publicado_at
               WHERE COALESCE(excluded.publicado_at, '') >= COALESCE(msrc_correcciones.publicado_at, '')""",
            filas)
    n_cve = len(datos.get("Vulnerability") or [])
    n_windows = len({f["cve"] for f in filas if not es_fila_catalogo(f["cve"])})
    conn.execute(
        """INSERT INTO msrc_documentos(documento, publicado_at, revisado_at, descargado_at, n_cve, n_windows, error)
           VALUES(?,?,?,?,?,?,NULL)
           ON CONFLICT(documento) DO UPDATE SET publicado_at=excluded.publicado_at, revisado_at=excluded.revisado_at,
               descargado_at=excluded.descargado_at, n_cve=excluded.n_cve, n_windows=excluded.n_windows, error=NULL""",
        (doc["documento"], doc["publicado_at"], doc["revisado_at"], descargado_at, n_cve, n_windows))
    return len(filas)


def _anotar_error(conn: sqlite3.Connection, doc: dict, error: str, *, ahora: str) -> None:
    conn.execute(
        """INSERT INTO msrc_documentos(documento, publicado_at, revisado_at, descargado_at, n_cve, n_windows, error)
           VALUES(?,?,NULL,?,0,0,?)
           ON CONFLICT(documento) DO UPDATE SET error=excluded.error""",
        (doc["documento"], doc["publicado_at"], ahora, error[:300]))


def actualizar(conn: sqlite3.Connection, *, cfg: Any = None, fetch=None, forzar: bool = False) -> dict[str, Any]:
    """Descarga (o refresca) los boletines mensuales que falten y guarda las correcciones
    de productos Windows en ``msrc_correcciones``. Devuelve un resumen:
    {"descargados": [...], "en_cache": n, "errores": [...], "correcciones": n, "omitido": bool}."""
    resumen_: dict[str, Any] = {"descargados": [], "en_cache": 0, "errores": [], "correcciones": 0,
                                "omitido": False, "eliminados": []}
    if not _activado(cfg):
        resumen_.update(omitido=True, motivo="desactivado en ajustes (msrc_enabled)")
        return resumen_
    fetch = fetch or _fetch_por_defecto
    meses = int(float(_ajuste(cfg, "msrc_meses", 18)))
    horas_cache = float(_ajuste(cfg, "msrc_cache_hours", 24))
    ahora_dt = _ahora()
    ahora = _iso(ahora_dt)

    lista = fetch(URL_LISTA)
    if not getattr(lista, "ok", False) or not isinstance(getattr(lista, "data", None), dict):
        error = getattr(lista, "error", None) or "respuesta no válida"
        resumen_["errores"].append(f"lista de boletines: {http.describir_error(error) if error in http.ERRORES else error}")
        log.warning("no se pudo listar los boletines de Microsoft", extra={"error": str(error)})
        resumen_["correcciones"] = conn.execute("SELECT COUNT(*) FROM msrc_correcciones").fetchone()[0]
        return resumen_
    documentos = _documentos_en_ventana(lista.data.get("value") or [], ahora=ahora_dt, meses=meses)
    guardados = {r["documento"]: dict(r) for r in conn.execute("SELECT * FROM msrc_documentos")}
    reciente = _ventana(ahora_dt, 2)          # boletines del mes actual y del anterior

    propia = not conn.in_transaction
    if propia:
        conn.execute("BEGIN")
    try:
        for doc in documentos:
            ident = doc["documento"]
            guardado = guardados.get(ident)
            horas_minimas = horas_cache if doc["publicado_at"] >= reciente else max(horas_cache, HORAS_REFRESCO_ANTIGUOS)
            if guardado is not None and not guardado.get("error") and not forzar:
                revisado = guardado.get("revisado_at") or ""
                desc_dt = _a_datetime(guardado.get("descargado_at"))
                hace_poco = desc_dt is not None and (ahora_dt - desc_dt) < timedelta(hours=horas_minimas)
                if doc["revisado_at"] <= revisado or hace_poco:
                    resumen_["en_cache"] += 1
                    continue
            datos: Optional[dict] = None
            desde_cache = False
            if not forzar and (guardado is None or guardado.get("error")):
                copia = _leer_cache(ident)
                if copia is not None and (_revision_documento(copia) or "") >= doc["revisado_at"]:
                    datos, desde_cache = copia, True
            if datos is None:
                try:
                    r = fetch(doc["url"])
                except Exception as exc:  # noqa: BLE001  (un fallo de red no aborta el resto)
                    r = None
                    error = f"{type(exc).__name__}: {exc}"
                else:
                    error = None if getattr(r, "ok", False) else (getattr(r, "error", None) or "respuesta no válida")
                if r is not None and getattr(r, "ok", False) and isinstance(getattr(r, "data", None), dict) \
                        and "Vulnerability" in r.data:
                    datos = r.data
                    _escribir_cache(ident, datos)
                else:
                    error = error or "el documento no tiene el formato CVRF esperado"
                    copia = _leer_cache(ident)
                    if copia is not None and guardado is None:
                        datos, desde_cache = copia, True
                        resumen_["errores"].append(f"{ident}: {error}; se usa la copia local anterior")
                    else:
                        resumen_["errores"].append(f"{ident}: {error}")
                        if guardado is None:
                            _anotar_error(conn, doc, str(error), ahora=ahora)
                        log.warning("no se pudo descargar el boletín", extra={"documento": ident, "error": str(error)})
                        continue
            n = _guardar_documento(conn, doc, datos, descargado_at=ahora)
            if desde_cache:
                resumen_["en_cache"] += 1
            else:
                resumen_["descargados"].append(ident)
            log.info("boletín MSRC procesado", extra={"documento": ident, "correcciones": n,
                                                     "origen": "cache" if desde_cache else "descarga"})
        # Boletines que salen de la ventana de meses
        vigentes = {d["documento"] for d in documentos}
        for ident in list(guardados):
            if ident not in vigentes:
                conn.execute("DELETE FROM msrc_correcciones WHERE documento=?", (ident,))
                conn.execute("DELETE FROM msrc_documentos WHERE documento=?", (ident,))
                _borrar_cache(ident)
                resumen_["eliminados"].append(ident)
        if propia:
            conn.execute("COMMIT")
    except Exception:
        if propia and conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    resumen_["correcciones"] = conn.execute("SELECT COUNT(*) FROM msrc_correcciones").fetchone()[0]
    return resumen_


# --------------------------------------------------------------------------
# Evaluacion de los activos
# --------------------------------------------------------------------------
class _Indice:
    """Correcciones en memoria: por producto, sus CVE y el mapa KB -> compilacion."""

    def __init__(self, filas: Iterable[dict]):
        self.por_producto: dict[str, dict[str, dict]] = {}     # pid -> cve -> fila (solo CVE)
        self.catalogo: dict[str, list[dict]] = {}              # pid -> filas KB -> compilacion
        self.nombres: dict[str, str] = {}                      # pid -> nombre
        self.ramas: dict[str, dict[str, int]] = {}             # pid -> rama (10.0.26100) -> filas
        for f in filas:
            pid = f["producto_id"]
            if es_fila_catalogo(f["cve"]):
                self.catalogo.setdefault(pid, []).append(f)
            else:
                self.por_producto.setdefault(pid, {})[f["cve"]] = f
            self.nombres[pid] = f["producto"]
            build = f.get("build_corregida")
            if build:
                rama = str(build).rsplit(".", 1)[0]
                self.ramas.setdefault(pid, {})[rama] = self.ramas.get(pid, {}).get(rama, 0) + 1

    def candidatos(self, so_version: Optional[str]) -> list[tuple[str, str]]:
        """Productos cuya rama es la compilacion base del activo. Se exige que sea su rama
        MAYORITARIA: una compilacion suelta de otra rama es ruido del boletin, no otro producto."""
        return candidatos_por_rama(
            {pid: (self.nombres[pid], conteo) for pid, conteo in self.ramas.items()}, so_version)

    def producto_de(self, activo: dict) -> Optional[str]:
        par = elegir_producto(activo, self.candidatos(activo.get("so_version")))
        return par[0] if par else None

    def mapa_kb(self, pid: str, so_version: Optional[str]) -> dict[str, tuple[str, Optional[str]]]:
        """KB -> (compilacion mas alta de la rama del activo que instala esa KB, fecha de publicacion)."""
        prefijo = f"{str(so_version or '').strip()}."
        salida: dict[str, tuple[str, Optional[str]]] = {}
        for f in list(self.por_producto.get(pid, {}).values()) + self.catalogo.get(pid, []):
            kb, build = f.get("kb"), f.get("build_corregida")
            if not kb or not build or not build.startswith(prefijo):
                continue
            build_act, fecha_act = salida.get(kb, (None, None))
            if build_act is None or (comparar_builds(build, build_act) or 0) > 0:
                build_act = build
            fecha = f.get("publicado_at")
            if fecha and (not fecha_act or fecha < fecha_act):
                fecha_act = fecha          # la fecha mas antigua en que se publico esa KB
            salida[kb] = (build_act, fecha_act)
        return salida

    def ultima(self, pid: str, so_version: Optional[str]) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """(compilacion mas alta publicada para la rama, su KB, su fecha)."""
        mejor: tuple[Optional[str], Optional[str], Optional[str]] = (None, None, None)
        for kb, (build, fecha) in self.mapa_kb(pid, so_version).items():
            if mejor[0] is None or (comparar_builds(build, mejor[0]) or 0) > 0:
                mejor = (build, kb, fecha)
        return mejor


def _cargar_indice(conn: sqlite3.Connection) -> _Indice:
    return _Indice(dict(r) for r in conn.execute(
        "SELECT cve, producto_id, producto, kb, build_corregida, documento, publicado_at FROM msrc_correcciones"))


def compilacion_efectiva(kbs_instaladas: Iterable[str], mapa_kb: dict[str, tuple[str, Optional[str]]]
                         ) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """(compilacion, KB, fecha) de la actualizacion acumulativa mas reciente instalada que
    aparece en los boletines; (None, None, None) si no se reconoce ninguna."""
    mejor: tuple[Optional[str], Optional[str], Optional[str]] = (None, None, None)
    for kb in kbs_instaladas:
        par = mapa_kb.get(str(kb))
        if par is None:
            continue
        build, fecha = par
        if mejor[0] is None or (comparar_builds(build, mejor[0]) or 0) > 0:
            mejor = (build, f"KB{kb}", fecha)
    return mejor


def _kbs_por_activo(conn: sqlite3.Connection, ids: list[int]) -> dict[int, set[str]]:
    salida: dict[int, set[str]] = {i: set() for i in ids}
    for lote in range(0, len(ids), 500):
        trozo = ids[lote:lote + 500]
        for r in conn.execute(
                f"SELECT activo_id, nombre FROM activo_software WHERE nombre LIKE '%KB%' "
                f"AND activo_id IN ({','.join('?' * len(trozo))})", trozo):
            salida[r["activo_id"]].update(extraer_kbs([r["nombre"]]))
    return salida


def _amenazas_por_cve(conn: sqlite3.Connection) -> dict[str, list[int]]:
    salida: dict[str, list[int]] = {}
    for r in conn.execute(f"SELECT id, cve FROM threats WHERE cve IS NOT NULL AND cve <> '' "
                          f"AND estado NOT IN {ESTADOS_CERRADOS_SQL} ORDER BY id"):
        for cve in aplicabilidad.cves_de({"cve": r["cve"]}):
            salida.setdefault(cve, []).append(r["id"])
    return salida


#: ``evaluado_at`` que fuerza a ``aplicabilidad.evaluar_pendientes`` a evaluar la amenaza en su
#: proxima pasada (la misma marca que usa ``bin/sincronizar_ocs.py --reevaluar``).
MARCA_PENDIENTE = "2000-01-01T00:00:00Z"


def _amenazas_recientes(conn: sqlite3.Connection, cfg: Any, ahora: datetime) -> set[int]:
    """Amenazas abiertas con CVE que ``aplicabilidad.evaluar_pendientes`` todavia puede evaluar
    (vistas por primera vez dentro de ``collect_lookback_days``)."""
    dias = int(float(_ajuste(cfg, "collect_lookback_days", 45)))
    desde = _iso(ahora - timedelta(days=dias))
    return {r[0] for r in conn.execute(
        f"SELECT id FROM threats WHERE cve IS NOT NULL AND cve <> '' AND estado NOT IN {ESTADOS_CERRADOS_SQL} "
        f"AND first_seen_at >= ?", (desde,))}


def _veredicto(build_instalada: Optional[str], kb_instalada: Optional[str], corr: dict, producto: str) -> dict:
    kb = _kb_texto(corr.get("kb"))
    corregida = corr.get("build_corregida")
    if not build_instalada:
        return {"veredicto": aplicabilidad.SIN_DATO,
                "evidencia": (f"El equipo no tiene ninguna actualización acumulativa reconocida de {producto} "
                              f"(OCS no informa de ninguna KB de los boletines de Microsoft), así que no se puede "
                              f"comparar con la compilación corregida {corregida} ({kb})")}
    cmp = comparar_builds(build_instalada, corregida)
    if cmp is None:
        return {"veredicto": aplicabilidad.SIN_DATO,
                "evidencia": f"Compilación no comparable: instalada {build_instalada}, corregida en {corregida} ({kb})"}
    if cmp >= 0:
        return {"veredicto": aplicabilidad.NO_AFECTADO,
                "evidencia": (f"Corregido por la actualización {kb} (compilación instalada {build_instalada}, "
                              f"corregida en {corregida}; el equipo lleva {kb_instalada or 'una acumulativa posterior'})")}
    fecha = fecha_larga(corr["publicado_at"]) if corr.get("publicado_at") else "fecha desconocida"
    return {"veredicto": aplicabilidad.AFECTADO,
            "evidencia": (f"Falta la actualización acumulativa {kb} publicada el {fecha}: compilación instalada "
                          f"{build_instalada}, corregida en {corregida}")}


def _totales_amenazas(conn: sqlite3.Connection, ids: list[int]) -> dict[int, dict[str, int]]:
    """Recuentos por amenaza con la misma regla que ``aplicabilidad.recalcular_resumenes``
    (solo activos presentes; un activo cuenta una vez, «afectado» manda)."""
    por_amenaza: dict[int, dict[int, dict]] = {}
    for lote in range(0, len(ids), 500):
        trozo = ids[lote:lote + 500]
        for r in conn.execute(
                f"""SELECT ap.threat_id, ap.activo_id, ap.veredicto, a.entorno,
                           (ap.version_corregida IS NOT NULL) AS parche
                      FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                     WHERE a.presente=1 AND ap.threat_id IN ({','.join('?' * len(trozo))})""", trozo):
            e = por_amenaza.setdefault(r["threat_id"], {}).setdefault(
                r["activo_id"], {"v": set(), "entorno": r["entorno"], "parche": False})
            e["v"].add(r["veredicto"])
            if r["veredicto"] == aplicabilidad.AFECTADO and r["parche"]:
                e["parche"] = True
    salida: dict[int, dict[str, int]] = {}
    for tid in ids:
        activos = por_amenaza.get(tid, {})
        af = [a for a in activos.values() if aplicabilidad.AFECTADO in a["v"]]
        no_af = [a for a in activos.values() if aplicabilidad.AFECTADO not in a["v"] and aplicabilidad.NO_AFECTADO in a["v"]]
        salida[tid] = {"afectados": len(af), "no_afectados": len(no_af),
                       "sin_dato": len(activos) - len(af) - len(no_af),
                       "afectados_expuestos": sum(1 for a in af if a["entorno"] in ("produccion", "contingencia")),
                       "parche_disponible": 1 if any(a["parche"] for a in af) else 0}
    return salida


def _linea_msrc(conteo: dict[str, int]) -> str:
    def plural(n: int, singular: str, plural_: str) -> str:
        return f"{n} {singular if n == 1 else plural_}"
    return (f"{_MARCA_LINEA}: {plural(conteo['afectado'], 'equipo Windows sin la actualización acumulativa', 'equipos Windows sin la actualización acumulativa')}, "
            f"{plural(conteo['no_afectado'], 'ya corregido', 'ya corregidos')} y "
            f"{plural(conteo['sin_dato'], 'sin KB reconocida', 'sin KB reconocida')}")


def _actualizar_resumenes(conn: sqlite3.Connection, ids: list[int], lineas: dict[int, dict[str, int]],
                          *, ahora: str, recientes: Optional[set[int]] = None) -> list[int]:
    """Crea o actualiza ``aplicabilidad_amenaza`` para las amenazas tocadas. Devuelve las que cambiaron.

    Si la amenaza aun no tenia fila (el motor principal no la ha evaluado), la fila nueva lleva
    ``evaluado_at`` = ``MARCA_PENDIENTE`` cuando la amenaza es reciente (``recientes``), para que
    ``evaluar_pendientes`` la evalue con OSV en su proxima pasada en vez de esperar
    ``applicability_reevaluate_days``; las antiguas, que ese motor ya no revisa, llevan ``ahora``.
    Las filas existentes conservan su fecha: es la del motor principal."""
    if not ids:
        return []
    recientes = recientes or set()
    totales = _totales_amenazas(conn, ids)
    existentes: dict[int, dict] = {}
    for lote in range(0, len(ids), 500):
        trozo = ids[lote:lote + 500]
        for r in conn.execute(f"SELECT * FROM aplicabilidad_amenaza WHERE threat_id IN ({','.join('?' * len(trozo))})", trozo):
            existentes[r["threat_id"]] = dict(r)
    cambiados: list[int] = []
    for tid in ids:
        t = totales[tid]
        previo = existentes.get(tid)
        try:
            detalle = json.loads((previo or {}).get("detalle") or "{}")
        except ValueError:
            detalle = {}
        if not isinstance(detalle, dict):
            detalle = {}
        lineas_previas = [ln for ln in (detalle.get("lineas") or []) if not str(ln).startswith(_MARCA_LINEA)]
        conteo = lineas.get(tid)
        if conteo and sum(conteo.values()):
            lineas_previas.append(_linea_msrc(conteo))
        detalle["lineas"] = lineas_previas
        detalle.setdefault("errores", [])
        detalle.setdefault("incompleta", 0)
        detalle["msrc"] = 1 if conteo and sum(conteo.values()) else 0
        detalle_json = json.dumps(detalle, ensure_ascii=False)
        if previo is None:
            conn.execute(
                """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados, no_afectados, sin_dato,
                       afectados_expuestos, parche_disponible, detalle) VALUES(?,?,?,?,?,?,?,?)""",
                (tid, MARCA_PENDIENTE if tid in recientes else ahora, t["afectados"], t["no_afectados"],
                 t["sin_dato"], t["afectados_expuestos"], t["parche_disponible"], detalle_json))
            cambiados.append(tid)
            continue
        distinto = any(int(previo.get(k) or 0) != int(t[k]) for k in
                       ("afectados", "no_afectados", "sin_dato", "afectados_expuestos", "parche_disponible"))
        if distinto or (previo.get("detalle") or "") != detalle_json:
            # La fecha de evaluacion no se toca: es la del motor principal y decide cuando reevaluar con OSV.
            conn.execute(
                """UPDATE aplicabilidad_amenaza SET afectados=?, no_afectados=?, sin_dato=?, afectados_expuestos=?,
                       parche_disponible=?, detalle=? WHERE threat_id=?""",
                (t["afectados"], t["no_afectados"], t["sin_dato"], t["afectados_expuestos"], t["parche_disponible"],
                 detalle_json, tid))
            if distinto:
                cambiados.append(tid)
    return cambiados


def evaluar_activos(conn: sqlite3.Connection, *, cfg: Any = None, solo_activo: Optional[int] = None,
                    ahora: Optional[str] = None) -> dict[str, Any]:
    """Para cada activo Windows: deduce la compilacion efectiva a partir de las KB instaladas
    (columnas ``windows_*`` de ``activos``) y escribe en ``aplicabilidad`` (motor ``msrc``) el
    veredicto de cada amenaza con CVE de Windows. Devuelve
    {"activos": n, "con_kb": n, "sin_kb": n, "filas": n, "afectados": n, "omitido": bool}."""
    resultado: dict[str, Any] = {"activos": 0, "con_kb": 0, "sin_kb": 0, "sin_producto": 0, "filas": 0,
                                 "afectados": 0, "no_afectados": 0, "sin_dato": 0, "amenazas": 0,
                                 "relevancia_recalculada": 0, "omitido": False}
    if not _activado(cfg):
        resultado.update(omitido=True, motivo="desactivado en ajustes (msrc_enabled)")
        return resultado
    indice = _cargar_indice(conn)
    if not indice.nombres:
        resultado.update(omitido=True, motivo="sin boletines de Microsoft descargados todavía")
        return resultado
    ahora = ahora or aplicabilidad.marca_evaluacion()
    filtro = " AND id=?" if solo_activo is not None else ""
    params: tuple = (solo_activo,) if solo_activo is not None else ()
    activos = [dict(r) for r in conn.execute(
        f"SELECT id, nombre, so_nombre, so_version, arquitectura, windows_build FROM activos "
        f"WHERE presente=1 AND so_familia='windows'{filtro}", params)]
    resultado["activos"] = len(activos)
    if not activos:
        return resultado
    kbs = _kbs_por_activo(conn, [a["id"] for a in activos])
    amenazas = _amenazas_por_cve(conn)
    recientes = _amenazas_recientes(conn, cfg, _a_datetime(ahora) or _ahora())

    filas: list[dict] = []
    conteo_amenaza: dict[int, dict[str, int]] = {}
    evaluados: list[int] = []
    propia = not conn.in_transaction
    if propia:
        conn.execute("BEGIN")
    try:
        for a in activos:
            pid = indice.producto_de(a)
            if pid is None:
                # Sin producto MSRC (version sin boletines, so_version vacio): se limpian las columnas
                # y, mas abajo, sus filas msrc anteriores, calculadas con una compilacion que ya no tiene.
                resultado["sin_producto"] += 1
                conn.execute("UPDATE activos SET windows_build=NULL, windows_kb=NULL, windows_kb_publicado=NULL, "
                             "windows_evaluado_at=? WHERE id=?", (ahora, a["id"]))
                evaluados.append(a["id"])
                continue
            producto = indice.nombres[pid]
            build, kb, fecha = compilacion_efectiva(kbs.get(a["id"], ()), indice.mapa_kb(pid, a["so_version"]))
            conn.execute("UPDATE activos SET windows_build=?, windows_kb=?, windows_kb_publicado=?, "
                         "windows_evaluado_at=? WHERE id=?", (build, kb, fecha, ahora, a["id"]))
            resultado["con_kb" if build else "sin_kb"] += 1
            evaluados.append(a["id"])
            for cve, corr in indice.por_producto[pid].items():
                tids = amenazas.get(cve)
                if not tids:
                    continue
                res = _veredicto(build, kb, corr, producto)
                tid = tids[0]
                filas.append({"activo_id": a["id"], "threat_id": tid, "cve": cve, "paquete": PAQUETE,
                              "version_instalada": build, "version_corregida": corr.get("build_corregida"),
                              "veredicto": res["veredicto"], "motor": MOTOR, "evidencia": res["evidencia"],
                              "aviso": _kb_texto(corr.get("kb")) if corr.get("kb") else None, "evaluado_at": ahora})
                resultado[{"afectado": "afectados", "no_afectado": "no_afectados", "sin_dato": "sin_dato"}[res["veredicto"]]] += 1
                for t in tids:
                    c = conteo_amenaza.setdefault(t, {"afectado": 0, "no_afectado": 0, "sin_dato": 0})
                    c[res["veredicto"]] += 1
        aplicabilidad._guardar_filas(conn, filas)
        # Filas de este motor que ya no se dan (correccion fuera de la ventana, producto cambiado o
        # perdido). Solo de amenazas abiertas: las cerradas conservan su historial.
        tocados = set(conteo_amenaza)
        if evaluados:
            for lote in range(0, len(evaluados), 500):
                trozo = evaluados[lote:lote + 500]
                marcas = ",".join("?" * len(trozo))
                for r in conn.execute(
                        f"""SELECT DISTINCT threat_id FROM aplicabilidad
                             WHERE motor=? AND paquete=? AND evaluado_at < ? AND activo_id IN ({marcas})
                               AND threat_id IN (SELECT id FROM threats WHERE estado NOT IN {ESTADOS_CERRADOS_SQL})""",
                        (MOTOR, PAQUETE, ahora, *trozo)):
                    if r[0] is not None:
                        tocados.add(r[0])
                conn.execute(
                    f"""DELETE FROM aplicabilidad WHERE motor=? AND paquete=? AND evaluado_at < ? AND activo_id IN ({marcas})
                          AND threat_id IN (SELECT id FROM threats WHERE estado NOT IN {ESTADOS_CERRADOS_SQL})""",
                    (MOTOR, PAQUETE, ahora, *trozo))
        cambiados = _actualizar_resumenes(conn, sorted(tocados), conteo_amenaza, ahora=ahora, recientes=recientes)
        if cambiados:
            from . import enrich
            n = 0
            for lote in range(0, len(cambiados), 500):
                n += int(enrich.recalcular_relevancia(conn, cfg, threat_ids=cambiados[lote:lote + 500]) or 0)
            resultado["relevancia_recalculada"] = n
        if propia:
            conn.execute("COMMIT")
    except Exception:
        if propia and conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    resultado["filas"] = len(filas)
    resultado["amenazas"] = len(tocados)
    log.info("parches de Windows evaluados", extra={"activos": len(activos), "con_kb": resultado["con_kb"],
                                                    "filas": len(filas), "afectados": resultado["afectados"]})
    return resultado


# --------------------------------------------------------------------------
# Resumenes para la interfaz
# --------------------------------------------------------------------------
def resumen_activo(conn: sqlite3.Connection, activo: dict) -> dict[str, Any]:
    """Datos para la ficha de un activo Windows (plantilla ``_windows_parches.html``):
    {"aplica": bool, "build": ..., "kb": ..., "kb_publicado": ..., "ultima_build": ..., "ultima_kb": ...,
     "meses_atraso": int|None, "al_dia": bool|None, "evaluado_at": ..., "explicacion": str}."""
    activo = dict(activo or {})
    if activo.get("so_familia") != "windows":
        return {"aplica": False}
    salida: dict[str, Any] = {
        "aplica": True, "producto": None, "build": activo.get("windows_build"), "kb": activo.get("windows_kb"),
        "kb_publicado": activo.get("windows_kb_publicado"), "ultima_build": None, "ultima_kb": None,
        "ultima_publicado": None, "meses_atraso": None, "al_dia": None, "evaluado_at": activo.get("windows_evaluado_at"),
        "explicacion": "", "n_afectados": 0, "n_corregidos": 0, "n_sin_dato": 0, "hay_boletines": False,
        "kbs_instaladas": 0}
    so_nombre = activo.get("so_nombre") or "Windows"
    so_version = activo.get("so_version") or "desconocida"
    salida["hay_boletines"] = conn.execute("SELECT 1 FROM msrc_correcciones LIMIT 1").fetchone() is not None
    if not salida["hay_boletines"]:
        salida["explicacion"] = ("Todavía no se han descargado los boletines de seguridad de Microsoft: el nivel de "
                                 "parche de este equipo se calculará en la próxima ejecución programada.")
        return salida
    ramas: dict[str, tuple[str, dict[str, int]]] = {}
    for r in conn.execute("SELECT producto_id, producto, build_corregida FROM msrc_correcciones WHERE build_corregida IS NOT NULL"):
        _, conteo = ramas.setdefault(r["producto_id"], (r["producto"], {}))
        rama = str(r["build_corregida"]).rsplit(".", 1)[0]
        conteo[rama] = conteo.get(rama, 0) + 1
    par = elegir_producto(activo, candidatos_por_rama(ramas, activo.get("so_version")))
    if par is None:
        salida["explicacion"] = (f"Microsoft no publica correcciones para la compilación {so_version} ({so_nombre}) en los "
                                 f"boletines de los últimos meses: esa versión de Windows ya no recibe actualizaciones "
                                 f"acumulativas, así que no se puede medir su nivel de parche ni confirmar sus CVE.")
        return salida
    pid, producto = par
    salida["producto"] = producto
    indice = _Indice(dict(r) for r in conn.execute(
        "SELECT cve, producto_id, producto, kb, build_corregida, documento, publicado_at FROM msrc_correcciones "
        "WHERE producto_id=?", (pid,)))
    ultima_build, ultima_kb, ultima_fecha = indice.ultima(pid, activo.get("so_version"))
    salida.update(ultima_build=ultima_build, ultima_kb=_kb_texto(ultima_kb) if ultima_kb else None,
                  ultima_publicado=ultima_fecha)
    if activo.get("id") is not None:
        salida["kbs_instaladas"] = len(extraer_kbs(
            r[0] for r in conn.execute("SELECT nombre FROM activo_software WHERE activo_id=? AND nombre LIKE '%KB%'",
                                       (activo["id"],))))
        # La severidad baja no cuenta en estas tres cifras (2026-09-10, orden del
        # usuario; ajuste ``ignore_low_severity``): la tarjeta de parches de Windows de
        # la ficha del activo tiene que decir el mismo numero de vulnerabilidades
        # confirmadas que la propia ficha y que la pagina de Activos.
        sin_bajas = (" AND (t.id IS NULL OR t.severity IS NULL OR t.severity <> 'Low')"
                     if bool(db.get_setting(conn, "ignore_low_severity", True)) else "")
        fila = conn.execute(
            f"""SELECT SUM(ap.veredicto='afectado') AS af, SUM(ap.veredicto='no_afectado') AS ok,
                       SUM(ap.veredicto='sin_dato') AS sd
                  FROM aplicabilidad ap LEFT JOIN threats t ON t.id=ap.threat_id
                 WHERE ap.activo_id=? AND ap.motor=? AND ap.paquete=?
                   AND (t.id IS NULL OR t.estado NOT IN {ESTADOS_CERRADOS_SQL}){sin_bajas}""",
            (activo["id"], MOTOR, PAQUETE)).fetchone()
        salida.update(n_afectados=int(fila["af"] or 0), n_corregidos=int(fila["ok"] or 0), n_sin_dato=int(fila["sd"] or 0))

    build = salida["build"]
    if not build:
        if salida["evaluado_at"] is None:
            salida["explicacion"] = ("Este equipo todavía no se ha evaluado con los boletines de Microsoft; "
                                     "se hará en la próxima sincronización con OCS.")
        else:
            salida["explicacion"] = (f"OCS no informa de ninguna actualización acumulativa reconocida en este equipo "
                                     f"(ninguna de las KB de {producto} publicadas en los últimos meses aparece entre "
                                     f"su software), así que no se sabe qué compilación tiene ni se pueden confirmar "
                                     f"o descartar sus CVE de Windows.")
        return salida
    cmp = comparar_builds(build, ultima_build) if ultima_build else None
    salida["al_dia"] = bool(cmp is not None and cmp >= 0)
    salida["meses_atraso"] = 0 if salida["al_dia"] else (_meses_entre(salida["kb_publicado"], ultima_fecha) or 0)
    mes_instalada = _mes_es(salida["kb_publicado"])
    if salida["al_dia"]:
        salida["explicacion"] = (f"Este equipo tiene instalada la actualización de {mes_instalada} ({salida['kb']}), "
                                 f"la última que Microsoft ha publicado para {producto}: está al día de parches.")
    elif salida["meses_atraso"] == 0:
        salida["explicacion"] = (f"Este equipo tiene instalada la actualización {salida['kb']} de {mes_instalada}; "
                                 f"Microsoft publicó ese mismo mes otra posterior ({salida['ultima_kb']}, compilación "
                                 f"{ultima_build}) que todavía no está instalada.")
    else:
        n = salida["meses_atraso"]
        salida["explicacion"] = (f"Este equipo tiene instalada la actualización de {mes_instalada} ({salida['kb']}); "
                                 f"Microsoft publicó otra en {_mes_es(ultima_fecha)} ({salida['ultima_kb']}): "
                                 f"le falta{'n' if n != 1 else ''} {n} mes{'es' if n != 1 else ''} de parches.")
    return salida


def resumen(conn: sqlite3.Connection) -> dict[str, Any]:
    """Recuento global para paneles: {"activos_windows": n, "al_dia": n, "atrasados": n, "sin_dato": n,
    "documentos": n, "ultimo_boletin": str|None}."""
    salida: dict[str, Any] = {"activos_windows": 0, "al_dia": 0, "atrasados": 0, "sin_dato": 0, "documentos": 0,
                              "ultimo_boletin": None}
    salida["documentos"] = conn.execute("SELECT COUNT(*) FROM msrc_documentos WHERE error IS NULL").fetchone()[0]
    fila = conn.execute("SELECT documento FROM msrc_documentos WHERE error IS NULL ORDER BY publicado_at DESC LIMIT 1").fetchone()
    salida["ultimo_boletin"] = fila[0] if fila else None
    indice = _cargar_indice(conn)
    for a in conn.execute("SELECT id, so_nombre, so_version, arquitectura, windows_build FROM activos "
                          "WHERE presente=1 AND so_familia='windows'"):
        a = dict(a)
        salida["activos_windows"] += 1
        pid = indice.producto_de(a) if indice.nombres else None
        if pid is None or not a.get("windows_build"):
            salida["sin_dato"] += 1
            continue
        ultima_build, _, _ = indice.ultima(pid, a.get("so_version"))
        cmp = comparar_builds(a["windows_build"], ultima_build)
        if cmp is not None and cmp >= 0:
            salida["al_dia"] += 1
        else:
            salida["atrasados"] += 1
    return salida
