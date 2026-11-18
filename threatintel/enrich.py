"""Enriquecimiento de CVE con datos autoritativos.

Tres fuentes, ninguna de ellas RSS (los feeds de NVD estan retirados desde 2024
y los de CISA bloquean la descarga automatica):

  * NVD API 2.0  -> puntuacion y vector CVSS oficiales
  * CISA KEV     -> catalogo de vulnerabilidades con explotacion CONFIRMADA
  * EPSS (FIRST) -> probabilidad de explotacion en los proximos 30 dias

Esto es lo que sustituye al `estimate_severity()` del sistema anterior, que
devolvia 9.0 / 7.5 / 5.0 por palabras clave y el informe presentaba como CVSS
oficial ante la direccion.

Desde la v7 (2026-09-06) el modulo tambien garantiza que NINGUNA vulnerabilidad
llegue al correo ni a la plataforma con una descripcion de relleno del tipo
«Informacion publicada.»: `es_descripcion_relleno` decide si el texto describe
algo, `completar_descripcion` busca el real (fuente, NVD, CVE.org y boletin de
Microsoft, por ese orden) y `repasar_descripciones` repasa lo ya guardado.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from . import db, http, scoring, translate
from .logging_setup import get_logger
from .paths import DATA_DIR

log = get_logger("enrich")

URL_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
URL_KEV = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
URL_EPSS = "https://api.first.org/data/v1/epss"

CACHE_DIR = DATA_DIR / "cache"
CACHE_KEV = CACHE_DIR / "kev.json"

LOTE_EPSS = 100          # la API acepta hasta 100 CVE por peticion

# El NIST emite claves con formato UUID de 36 caracteres. Enviar una cadena que
# no lo sea hace que la API responda 404 y se pierdan TODAS las consultas, que es
# peor que no enviar clave: sin ella la API funciona, solo con menos cuota.
# Verificado el 2026-09-02: la clave del fichero (21 caracteres, sin guiones)
# provocaba 404 en todas las peticiones.
_FORMATO_CLAVE_NVD = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# El aviso de clave invalida se emite una sola vez por proceso: con 150 CVE por
# ejecucion, repetirlo llenaria el log de ruido identico.
_AVISO_CLAVE_EMITIDO = False


def clave_nvd_utilizable(cfg) -> Optional[str]:
    """Devuelve la clave de NVD solo si tiene formato valido; None si no.

    Se comprueba el formato ANTES de usarla en cada peticion, para que una clave
    mal copiada degrade el sistema (menos cuota) en lugar de romperlo (404).
    """
    clave = (cfg.nvd_api_key or "").strip()
    if not clave:
        return None
    if not _FORMATO_CLAVE_NVD.match(clave):
        global _AVISO_CLAVE_EMITIDO
        if _AVISO_CLAVE_EMITIDO:
            return None
        _AVISO_CLAVE_EMITIDO = True
        log.warning(
            "la clave de NVD tiene un formato invalido y se ignora; se usara el "
            "limite publico de 5 peticiones cada 30 segundos",
            extra={"longitud": len(clave), "esperado": "UUID de 36 caracteres"})
        return None
    return clave


# --------------------------------------------------------------------------
# CISA KEV
# --------------------------------------------------------------------------
def cargar_kev(cfg, *, cache_horas: int = 12,
               forzar: bool = False) -> dict[str, dict[str, Any]]:
    """Devuelve {CVE: {due_date, vendor, product, notas, ransomware}}.

    El catalogo son varios megabytes, asi que se cachea en disco. Si la descarga
    falla pero hay cache, se usa la cache aunque este caducada: es mejor un dato
    de ayer que ningun dato.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if not forzar and CACHE_KEV.exists():
        edad = datetime.now(timezone.utc) - datetime.fromtimestamp(
            CACHE_KEV.stat().st_mtime, timezone.utc)
        if edad < timedelta(hours=cache_horas):
            try:
                return json.loads(CACHE_KEV.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("cache KEV ilegible, se vuelve a descargar",
                            extra={"error": str(exc)})

    resultado = http.fetch_json(
        URL_KEV, timeout=int(cfg.get("http_timeout_s", 30)) * 2,
        retries=int(cfg.get("http_retries", 2)),
        user_agent=cfg.get("http_user_agent"))

    if not resultado.ok or not isinstance(resultado.data, dict):
        log.error("no se pudo descargar el catalogo CISA KEV",
                  extra={"error": resultado.error, "status": resultado.status})
        if CACHE_KEV.exists():
            try:
                log.warning("se usa la cache KEV caducada")
                return json.loads(CACHE_KEV.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    indice: dict[str, dict[str, Any]] = {}
    for item in resultado.data.get("vulnerabilities", []):
        cve = str(item.get("cveID") or "").upper().strip()
        if not cve.startswith("CVE-"):
            continue
        indice[cve] = {
            "due_date": item.get("dueDate"),
            "date_added": item.get("dateAdded"),
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "notas": item.get("shortDescription"),
            "accion": item.get("requiredAction"),
            "ransomware": str(item.get("knownRansomwareCampaignUse") or
                              "").lower() == "known",
        }

    try:
        CACHE_KEV.write_text(json.dumps(indice, ensure_ascii=False),
                             encoding="utf-8")
        CACHE_KEV.chmod(0o600)
    except OSError as exc:
        log.warning("no se pudo escribir la cache KEV", extra={"error": str(exc)})

    log.info("catalogo CISA KEV cargado", extra={"cve": len(indice)})
    return indice


# --------------------------------------------------------------------------
# NVD API 2.0
# --------------------------------------------------------------------------
def validar_clave_nvd(cfg, clave: Optional[str] = None) -> tuple[bool, str]:
    """Comprueba si una clave de API de NVD sirve.

    Sin `clave` se valida la configurada; con ella, la candidata que el operador
    quiere guardar (la interfaz verifica ANTES de escribir en credentials.env).
    Comprobado en vivo el 2026-09-03: NVD responde 404 a una peticion con clave
    desconocida y 200 a la misma peticion sin clave, asi que un 404 con clave
    significa "clave invalida", no "recurso inexistente". 403 puede ser clave
    rechazada o cuota agotada. Sin clave el modulo funciona igual, solo mas
    despacio (5 peticiones cada 30 s en lugar de 50).
    """
    clave = (clave if clave is not None else (cfg.nvd_api_key or "")).strip()
    if not clave:
        return False, "no hay clave configurada; se usa el límite público (5 peticiones / 30 s)"
    if not _FORMATO_CLAVE_NVD.match(clave):
        return False, (
            f"la clave no tiene formato de clave NVD ({len(clave)} caracteres; se esperan "
            f"36 con guiones, p. ej. 12345678-abcd-4ef0-9876-0123456789ab). "
            f"Se ignora y se usa el límite público.")

    resultado = http.fetch_json(
        URL_NVD, timeout=30, retries=0,
        user_agent=cfg.get("http_user_agent"),
        params={"cveId": "CVE-2021-44228"}, api_key_header={"apiKey": clave})

    if resultado.ok:
        return True, "clave válida: NVD la acepta (50 peticiones cada 30 s)"
    if resultado.status == 404:
        return False, ("NVD no reconoce la clave (HTTP 404). Compruebe que la copió completa "
                       "y que pulsó el enlace de activación del correo del NIST.")
    if resultado.status in (401, 403):
        return False, (f"NVD rechaza la clave (HTTP {resultado.status}): clave inválida o "
                       f"cuota agotada. Espere 30 segundos y vuelva a verificar.")
    return False, f"no se pudo contactar con NVD para validar la clave: {resultado.error}"


def estado_clave_nvd(conn: sqlite3.Connection, cfg) -> dict[str, Any]:
    """Resumen de la clave NVD para la interfaz: nunca incluye la clave en claro."""
    from . import config as _config
    clave = (cfg.nvd_api_key or "").strip()
    pendientes = conn.execute(
        "SELECT COUNT(*) FROM threats WHERE cve IS NOT NULL AND enriched_at IS NULL"
    ).fetchone()[0]
    por_ejecucion = int(cfg.get("enrich_max_per_run", 150))
    ultimo_ok = db.get_setting(conn, "nvd_key_last_check_ok")
    if clave and _FORMATO_CLAVE_NVD.match(clave):
        situacion = "verificada" if ultimo_ok is True else ("rechazada" if ultimo_ok is False else "sin_verificar")
    elif clave:
        situacion = "formato_invalido"
    else:
        situacion = "ausente"
    return {
        "configurada": bool(clave),
        "longitud": len(clave),
        "formato_ok": bool(clave) and bool(_FORMATO_CLAVE_NVD.match(clave)),
        "mascara": _config.mask(clave) if clave else None,
        "situacion": situacion,
        "utilizable": situacion == "verificada" or (situacion == "sin_verificar"),
        "ultima_verificacion_at": db.get_setting(conn, "nvd_key_last_check_at"),
        "ultima_verificacion_ok": ultimo_ok,
        "ultima_verificacion_msg": db.get_setting(conn, "nvd_key_last_check_msg"),
        "pendientes": pendientes,
        "por_ejecucion": por_ejecucion,
        "dias_estimados": (pendientes + por_ejecucion - 1) // por_ejecucion if por_ejecucion else None,
        "segundos_por_cve_sin_clave": 6.5,
        "segundos_por_cve_con_clave": 0.65,
    }


def registrar_verificacion_nvd(conn: sqlite3.Connection, ok: bool, mensaje: str) -> None:
    db.set_setting(conn, "nvd_key_last_check_ok", bool(ok))
    db.set_setting(conn, "nvd_key_last_check_at", db.utcnow())
    db.set_setting(conn, "nvd_key_last_check_msg", mensaje[:300])


def _extraer_metricas(cve_item: dict) -> dict[str, Any]:
    """Saca la mejor metrica disponible, prefiriendo la version mas moderna."""
    metricas = (cve_item.get("metrics") or {})
    salida: dict[str, Any] = {"score": None, "vector": None, "version": None,
                              "severity": None}

    for clave, version in (("cvssMetricV40", "4.0"),
                           ("cvssMetricV31", "3.1"),
                           ("cvssMetricV30", "3.0"),
                           ("cvssMetricV2", "2.0")):
        entradas = metricas.get(clave) or []
        if not entradas:
            continue
        # La entrada del propio NIST (Primary) manda sobre la del fabricante
        entradas = sorted(entradas, key=lambda e: 0 if e.get("type") == "Primary" else 1)
        datos = entradas[0].get("cvssData") or {}
        salida["score"] = datos.get("baseScore")
        salida["vector"] = datos.get("vectorString")
        salida["version"] = datos.get("version") or version
        salida["severity"] = (datos.get("baseSeverity")
                              or entradas[0].get("baseSeverity"))
        break

    return salida


def consultar_nvd(cve: str, *, cfg) -> Optional[dict[str, Any]]:
    """Consulta un CVE en la API 2.0 de NVD. Devuelve None si no hay dato."""
    clave = clave_nvd_utilizable(cfg)
    cabeceras = {"apiKey": clave} if clave else None
    resultado = http.fetch_json(
        URL_NVD, timeout=int(cfg.get("http_timeout_s", 30)),
        retries=int(cfg.get("http_retries", 2)),
        user_agent=cfg.get("http_user_agent"),
        params={"cveId": cve}, api_key_header=cabeceras)

    if not resultado.ok:
        log.warning("consulta a NVD fallida",
                    extra={"cve": cve, "error": resultado.error,
                           "status": resultado.status})
        return None

    vulnerabilidades = (resultado.data or {}).get("vulnerabilities") or []
    if not vulnerabilidades:
        return {"encontrado": False}

    item = vulnerabilidades[0].get("cve") or {}
    metricas = _extraer_metricas(item)

    descripcion = ""
    for d in item.get("descriptions") or []:
        if d.get("lang") == "en":
            descripcion = d.get("value") or ""
            break

    cwe: list[str] = []
    for weakness in item.get("weaknesses") or []:
        for d in weakness.get("description") or []:
            valor = d.get("value") or ""
            if valor.startswith("CWE-") and valor not in cwe:
                cwe.append(valor)

    referencias = [r.get("url") for r in (item.get("references") or [])
                   if r.get("url")][:8]

    return {
        "encontrado": True,
        "cve": item.get("id") or cve,
        "score": metricas["score"],
        "vector": metricas["vector"],
        "version": metricas["version"],
        "severity": metricas["severity"],
        "descripcion": descripcion,
        "publicado": item.get("published"),
        "modificado": item.get("lastModified"),
        "estado": item.get("vulnStatus"),
        "cwe": cwe,
        "referencias": referencias,
    }


# --------------------------------------------------------------------------
# EPSS
# --------------------------------------------------------------------------
def consultar_epss(cves: Iterable[str], *, cfg) -> dict[str, float]:
    """Devuelve {CVE: probabilidad}. Consulta por lotes de 100."""
    lista = [c.upper() for c in cves if c and str(c).upper().startswith("CVE-")]
    if not lista:
        return {}

    salida: dict[str, float] = {}
    for inicio in range(0, len(lista), LOTE_EPSS):
        lote = lista[inicio:inicio + LOTE_EPSS]
        resultado = http.fetch_json(
            URL_EPSS, timeout=int(cfg.get("http_timeout_s", 30)),
            retries=int(cfg.get("http_retries", 2)),
            user_agent=cfg.get("http_user_agent"),
            params={"cve": ",".join(lote), "limit": len(lote)})

        if not resultado.ok:
            log.warning("consulta EPSS fallida",
                        extra={"lote": len(lote), "error": resultado.error})
            continue

        for fila in (resultado.data or {}).get("data") or []:
            cve = str(fila.get("cve") or "").upper()
            try:
                salida[cve] = float(fila.get("epss"))
            except (TypeError, ValueError):
                continue

    return salida


# --------------------------------------------------------------------------
# Enriquecimiento de una amenaza
# --------------------------------------------------------------------------
def enriquecer_cve(cve: str, *, cfg, kev_index: Optional[dict] = None,
                   epss_index: Optional[dict] = None) -> dict[str, Any]:
    """Reune los datos de las tres fuentes para un CVE."""
    cve = str(cve).upper()
    kev = (kev_index or {}).get(cve)
    epss = (epss_index or {}).get(cve)

    nvd = consultar_nvd(cve, cfg=cfg) if cfg.get("enrich_nvd_enabled", True) else None
    if nvd and not nvd.get("encontrado"):
        nvd = None

    return {
        "cve": cve,
        "nvd": nvd,
        "in_kev": kev is not None,
        "kev": kev,
        "epss": epss,
    }


def _fecha_iso(valor: Optional[str]) -> Optional[str]:
    if not valor:
        return None
    texto = str(valor).strip()
    for formato in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(texto[:26], formato).replace(
                tzinfo=timezone.utc).replace(microsecond=0).isoformat().replace(
                "+00:00", "Z")
        except ValueError:
            continue
    return texto


def enriquecer_pendientes(conn: sqlite3.Connection, *, cfg,
                          limite: Optional[int] = None,
                          reenriquecer: bool = False,
                          confirmar_cada: int = 10,
                          repasar_historico: bool = True) -> dict[str, Any]:
    """Enriquece las amenazas con CVE que aun no tienen datos oficiales.

    Recalcula severidad, origen, CVSS, EPSS, KEV y relevancia. Es incremental:
    solo toca lo que no tiene `enriched_at`, salvo que se pida reenriquecer.

    IMPORTANTE: la conexion debe estar en autocommit (`db.connect()`), NO dentro
    de `db.session()`. Con el limite publico de NVD hay una espera de 6,5 s por
    CVE, y mantener abierta una transaccion de escritura durante esas esperas
    bloquea a la interfaz web: la primera version de este modulo murio con
    "database is locked" por ese motivo. Aqui cada escritura se confirma sola y
    las esperas de red ocurren sin ningun bloqueo tomado.
    """
    tope = limite if limite is not None else int(cfg.get("enrich_max_per_run", 150))

    condicion = "cve IS NOT NULL"
    if not reenriquecer:
        condicion += " AND enriched_at IS NULL"

    filas = [dict(r) for r in conn.execute(
        f"""SELECT id, cve, title_en, title_es, summary_en, summary_es, severity,
                   descripcion_origen
              FROM threats WHERE {condicion}
             ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
                                    WHEN 'Medium' THEN 2 ELSE 3 END,
                      first_seen_at DESC
             LIMIT ?""", (tope,))]

    estadisticas = {
        "candidatas": len(filas), "consultadas": 0, "con_cvss_real": 0,
        "en_kev": 0, "con_epss": 0, "sin_dato": 0, "reclasificadas": 0,
        "subidas": 0, "bajadas": 0, "errores": 0,
        "descripciones_completadas": 0, "descripciones_sin_publicar": 0,
        "descripciones_repasadas": 0,
    }

    if not filas:
        log.info("no hay amenazas pendientes de enriquecer")
        if repasar_historico:
            _repasar_descripciones_del_historico(conn, cfg=cfg,
                                                 estadisticas=estadisticas)
        return estadisticas

    # KEV y EPSS se cargan una sola vez para todo el lote
    kev_index = (cargar_kev(cfg) if cfg.get("enrich_kev_enabled", True) else {})
    cves = [f["cve"] for f in filas]
    epss_index = (consultar_epss(cves, cfg=cfg)
                  if cfg.get("enrich_epss_enabled", True) else {})

    espera = float(cfg.get("nvd_rate_limit_sleep_s", 6.5))
    if clave_nvd_utilizable(cfg):
        espera = max(0.7, espera / 8)      # con clave el limite es 10 veces mayor

    consultar_nvd_activo = bool(cfg.get("enrich_nvd_enabled", True))
    # Las descripciones nuevas se traducen con el flujo normal del proyecto, con el
    # mismo tope de llamadas a Ollama por ejecucion que usa el recolector.
    contador_traduccion = translate.ContadorLlamadas(
        int(cfg.get("ollama_max_calls_per_run", 25) or 25))

    for indice, fila in enumerate(filas, 1):
        cve = fila["cve"]
        severidad_previa = fila["severity"]

        nvd = None
        if consultar_nvd_activo:
            try:
                nvd = consultar_nvd(cve, cfg=cfg)
                estadisticas["consultadas"] += 1
            except Exception as exc:  # noqa: BLE001
                estadisticas["errores"] += 1
                log.error("error consultando NVD", extra={"cve": cve,
                                                          "error": str(exc)})
            if indice < len(filas) and espera > 0:
                time.sleep(espera)

        if nvd and not nvd.get("encontrado"):
            nvd = None

        kev = kev_index.get(cve)
        epss = epss_index.get(cve)

        decision = scoring.decidir(
            nvd_score=(nvd or {}).get("score"),
            nvd_severity=(nvd or {}).get("severity"),
            vector=(nvd or {}).get("vector"),
            in_kev=kev is not None,
            epss=epss,
            titulo=fila["title_es"] or fila["title_en"] or "",
            resumen=fila["summary_es"] or fila["summary_en"] or "")

        if decision["cvss_score"] is not None:
            estadisticas["con_cvss_real"] += 1
        else:
            estadisticas["sin_dato"] += 1
        if kev:
            estadisticas["en_kev"] += 1
        if epss is not None:
            estadisticas["con_epss"] += 1

        if decision["severity"] != severidad_previa:
            estadisticas["reclasificadas"] += 1
            if scoring.orden_severidad(decision["severity"]) < \
                    scoring.orden_severidad(severidad_previa):
                estadisticas["subidas"] += 1
            else:
                estadisticas["bajadas"] += 1

        # Recalcular relevancia con las tecnologias ya correlacionadas
        tecnologias = [dict(r) for r in conn.execute(
            """SELECT t.criticality, t.exposure, t.systems_count,
                      tt.version_verdict
                 FROM threat_technologies tt
                 JOIN technologies t ON t.id = tt.technology_id
                WHERE tt.threat_id = ?""", (fila["id"],))]

        relevancia = scoring.relevancia(
            severity=decision["severity"], cvss_score=decision["cvss_score"],
            epss=epss, in_kev=kev is not None, tecnologias=tecnologias)

        _escribir_con_reintento(conn,
            """UPDATE threats
                  SET severity=?, severity_source=?, cvss_score=?, cvss_vector=?,
                      cvss_version=?, epss_score=?, in_kev=?, kev_due_date=?,
                      relevance=?, enriched_at=?,
                      summary_en=COALESCE(NULLIF(summary_en,''), ?),
                      published_at=COALESCE(published_at, ?)
                WHERE id=?""",
            (decision["severity"], decision["severity_source"],
             decision["cvss_score"], decision["cvss_vector"],
             decision["cvss_version"], epss, 1 if kev else 0,
             _fecha_iso((kev or {}).get("due_date")), relevancia, db.utcnow(),
             (nvd or {}).get("descripcion"),
             _fecha_iso((nvd or {}).get("publicado")),
             fila["id"]))

        # Ninguna vulnerabilidad debe llegar al correo con una descripcion de
        # relleno («Informacion publicada.»): si la que hay no describe nada, se
        # busca la real reutilizando la respuesta de NVD que se acaba de recibir.
        fila["summary_en"] = ((fila.get("summary_en") or "").strip()
                              or (nvd or {}).get("descripcion") or None)
        fila["severity"] = decision["severity"]
        # Si NVD ya se consulto (aunque no encontrara el CVE) se le pasa el
        # resultado para no repetir la peticion dentro de la busqueda.
        respuesta_nvd = nvd
        if respuesta_nvd is None and consultar_nvd_activo:
            respuesta_nvd = {"encontrado": False}
        try:
            hecho = completar_descripcion(conn, fila, cfg=cfg, nvd=respuesta_nvd,
                                          contador=contador_traduccion)
        except Exception as exc:  # noqa: BLE001
            estadisticas["errores"] += 1
            log.error("error completando la descripcion",
                      extra={"cve": cve, "error": str(exc)})
            hecho = None
        if hecho and hecho["cambiada"]:
            if hecho["origen"] == ORIGEN_SIN_DATO:
                estadisticas["descripciones_sin_publicar"] += 1
            else:
                estadisticas["descripciones_completadas"] += 1

        # Guardar referencias de NVD como fuente adicional
        if nvd and nvd.get("referencias"):
            _registrar_referencia_nvd(conn, fila["id"], cve)

    # Las amenazas que YA estaban guardadas con relleno no vuelven a pasar por aqui
    # (tienen `enriched_at`), asi que el repaso retroactivo viaja con el enriquecimiento.
    if repasar_historico:
        _repasar_descripciones_del_historico(conn, cfg=cfg, estadisticas=estadisticas)

    log.info("enriquecimiento terminado", extra=estadisticas)
    return estadisticas


def _repasar_descripciones_del_historico(conn: sqlite3.Connection, *, cfg,
                                         estadisticas: dict[str, Any]) -> None:
    """Repaso retroactivo de las descripciones ya guardadas, al final del enriquecimiento.

    Por que aqui: el enganche de `completar_descripcion` solo alcanza a las amenazas
    NUEVAS con identificador CVE (`enriched_at IS NULL`), asi que las 795 amenazas
    abiertas que el 6 de septiembre de 2026 ya estaban guardadas con relleno no se
    corregirian nunca solas (14 de las 36 alertadas por correo esos dos dias llevaban
    «Información publicada.» y todas tenian `enriched_at`). Como `enriquecer_pendientes`
    se ejecuta a diario desde `bin/ejecucion_diaria.py`, el repaso viaja con el: unas
    pocas amenazas por dia, empezando por las de mas relevancia y con tope de consultas,
    hasta limpiar el historico. Con `descripcion_repaso_limite` a 0 no se hace nada.
    """
    try:
        limite = int(cfg.get("descripcion_repaso_limite", 25) or 0)
    except (TypeError, ValueError):     # un ajuste mal escrito no detiene la ejecucion
        limite = 25
    if limite <= 0:
        return
    try:
        repaso = repasar_descripciones(conn, cfg=cfg, limite=limite)
    except Exception as exc:  # noqa: BLE001 - el repaso nunca rompe el enriquecimiento
        estadisticas["errores"] += 1
        log.error("error en el repaso retroactivo de descripciones",
                  extra={"error": str(exc)})
        return
    estadisticas["descripciones_repasadas"] = repaso["revisadas"]
    estadisticas["descripciones_completadas"] += repaso["resueltas"]
    estadisticas["descripciones_sin_publicar"] += repaso["sin_dato"]


def _escribir_con_reintento(conn: sqlite3.Connection, sql: str, params,
                            intentos: int = 5) -> None:
    """Ejecuta una escritura tolerando que la interfaz tenga la base ocupada.

    SQLite en modo WAL admite un solo escritor. La interfaz web escribe al
    guardar ajustes o inventario, asi que una ejecucion larga de fondo debe
    reintentar en lugar de abortar.
    """
    espera = 0.4
    for intento in range(intentos):
        try:
            conn.execute(sql, params)
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
            if intento == intentos - 1:
                log.error("no se pudo escribir tras varios reintentos",
                          extra={"error": str(exc)})
                raise
            time.sleep(espera)
            espera *= 2


def _registrar_referencia_nvd(conn: sqlite3.Connection, threat_id: int,
                              cve: str) -> None:
    """Anade NVD como fuente de la amenaza, para que el informe la cite."""
    fila = conn.execute("SELECT id FROM sources WHERE slug='nvd_api'").fetchone()
    if fila is None:
        ahora = db.utcnow()
        cur = conn.execute(
            """INSERT INTO sources(slug, name, url, kind, category, priority,
                                   enabled, timeout_s, notes, created_at, updated_at)
               VALUES('nvd_api','NVD (NIST)',?,'nvd_api','database','critical',1,30,
                      'Enriquecimiento de CVE via API 2.0',?,?)""",
            (URL_NVD, ahora, ahora))
        source_id = cur.lastrowid
    else:
        source_id = fila["id"]

    conn.execute(
        """INSERT OR IGNORE INTO threat_sources(threat_id, source_id, url, seen_at)
           VALUES(?,?,?,?)""",
        (threat_id, source_id, f"https://nvd.nist.gov/vuln/detail/{cve}",
         db.utcnow()))


def recalcular_relevancia(conn: sqlite3.Connection, cfg=None,
                          threat_ids: Optional[Iterable[int]] = None) -> int:
    """Recalcula la relevancia de todas las amenazas (o solo de ``threat_ids``).

    Necesario tras cambiar el inventario (versiones nuevas, criticidad,
    exposicion), el umbral de confianza de las coincidencias o la aplicabilidad
    por activo (OCS): la relevancia depende de esos datos.
    """
    min_conf = float(cfg.get("alert_min_match_confidence", 0.6)) if cfg is not None else 0.0
    ignorar_baja = bool(cfg.get("ignore_low_criticality", True)) if cfg is not None else False
    actualizadas = 0
    ids = list(threat_ids) if threat_ids is not None else None
    filtro = ""
    params: list = []
    if ids is not None:
        if not ids:
            return 0
        filtro = f" WHERE id IN ({','.join('?' * len(ids))})"
        params = ids
    filas = [dict(r) for r in conn.execute(
        f"SELECT id, severity, cvss_score, cvss_vector, epss_score, in_kev FROM threats{filtro}", params)]

    filtro_tt = f" WHERE tt.threat_id IN ({','.join('?' * len(ids))})" if ids else ""
    tecnologias_por_amenaza: dict[int, list[dict]] = {}
    for r in conn.execute(
            f"""SELECT tt.threat_id, t.criticality, t.exposure, t.systems_count,
                       tt.version_verdict, tt.confidence
                  FROM threat_technologies tt
                  JOIN technologies t ON t.id = tt.technology_id{filtro_tt}""", params):
        tecnologias_por_amenaza.setdefault(r["threat_id"], []).append(dict(r))

    activos_por_amenaza: dict[int, dict] = {}
    try:
        filtro_aa = f" WHERE threat_id IN ({','.join('?' * len(ids))})" if ids else ""
        for r in conn.execute(
                f"SELECT threat_id, afectados, no_afectados, sin_dato, afectados_expuestos, parche_disponible "
                f"FROM aplicabilidad_amenaza{filtro_aa}", params):
            activos_por_amenaza[r["threat_id"]] = {"afectados": r["afectados"],
                                                    "no_afectados": r["no_afectados"],
                                                    "sin_dato": r["sin_dato"],
                                                    "afectados_expuestos": r["afectados_expuestos"],
                                                    "parche_disponible": r["parche_disponible"]}
    except sqlite3.OperationalError:
        pass    # base anterior a la v4: sin aplicabilidad

    for fila in filas:
        nueva = scoring.relevancia(
            severity=fila["severity"], cvss_score=fila["cvss_score"],
            epss=fila["epss_score"], in_kev=bool(fila["in_kev"]),
            tecnologias=tecnologias_por_amenaza.get(fila["id"], []),
            min_confianza=min_conf, ignorar_criticidad_baja=ignorar_baja,
            activos=activos_por_amenaza.get(fila["id"]), cvss_vector=fila.get("cvss_vector"))
        conn.execute("UPDATE threats SET relevance=? WHERE id=?",
                     (nueva, fila["id"]))
        actualizadas += 1

    return actualizadas


# --------------------------------------------------------------------------
# Detalle del CVE segun CVE.org (CVE List 5.x): productos y versiones afectados
# --------------------------------------------------------------------------
URL_CVE_ORG = "https://cveawg.mitre.org/api/cve/{cve}"
_RE_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _resumir_cve_org(datos: dict) -> dict[str, Any]:
    """Extrae lo util para el analista del registro CVE 5.x: titulo, CNA, fecha,
    productos afectados con versiones, CWE, descripcion en ingles y referencias."""
    contenedores = (datos or {}).get("containers") or {}
    cna = contenedores.get("cna") or {}
    meta = (datos or {}).get("cveMetadata") or {}
    afectados: list[dict] = []
    for a in cna.get("affected") or []:
        versiones = []
        for v in a.get("versions") or []:
            if not isinstance(v, dict):
                continue
            estado = v.get("status")
            texto = str(v.get("version") or "").strip()
            if v.get("lessThan"):
                texto = f"desde {texto} hasta antes de {v['lessThan']}"
            elif v.get("lessThanOrEqual"):
                texto = f"desde {texto} hasta {v['lessThanOrEqual']}"
            if estado and estado != "affected":
                texto += f" ({'no afectada' if estado == 'unaffected' else estado})"
            if texto:
                versiones.append(texto)
        afectados.append({"fabricante": a.get("vendor"), "producto": a.get("product"),
                          "versiones": versiones[:12], "plataformas": a.get("platforms") or []})
    cwe: list[str] = []
    for pt in cna.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            if d.get("description") and d["description"] not in cwe:
                cwe.append(d["description"])
    descripcion = next((d.get("value") for d in cna.get("descriptions") or []
                        if str(d.get("lang", "")).lower().startswith("en") and d.get("value")), None)
    referencias = [r.get("url") for r in cna.get("references") or [] if r.get("url")]
    return {"titulo": cna.get("title"), "cna": (cna.get("providerMetadata") or {}).get("shortName"),
            "publicado": meta.get("datePublished"), "actualizado": meta.get("dateUpdated"),
            "estado": meta.get("state"), "afectados": afectados, "cwe": cwe[:5],
            "descripcion": descripcion, "referencias": referencias[:10]}


def detalle_cve(conn: sqlite3.Connection, cve: str, *, cfg=None, permitir_red: bool = True,
                ttl_horas: int = 168, fetch=None) -> Optional[dict[str, Any]]:
    """Detalle del CVE desde la cache ``cve_detalle`` o, si falta y ``permitir_red``,
    desde CVE.org (se guarda para la proxima vez). None si no hay dato."""
    cve = (cve or "").strip().upper()
    if not _RE_CVE_ID.match(cve):
        return None
    fila = conn.execute("SELECT encontrado, json, consultado_at FROM cve_detalle WHERE cve=?", (cve,)).fetchone()
    if fila is not None:
        try:
            consultado = datetime.fromisoformat(str(fila["consultado_at"]).replace("Z", "+00:00"))
        except ValueError:
            consultado = None
        fresco = consultado is not None and datetime.now(timezone.utc) - consultado < timedelta(hours=ttl_horas)
        if fresco or not permitir_red:
            if not fila["encontrado"] or not fila["json"]:
                return {"encontrado": False, "consultado_at": fila["consultado_at"]}
            datos = json.loads(fila["json"])
            datos.update(encontrado=True, consultado_at=fila["consultado_at"])
            return datos
    if not permitir_red:
        return None
    fetch = fetch or http.fetch_json
    res = fetch(URL_CVE_ORG.format(cve=cve), timeout=8, retries=0,
                user_agent=cfg.get("http_user_agent") if cfg is not None else None, silenciar_http=True)
    ahora = db.utcnow()
    if res.ok and isinstance(res.data, dict) and res.data.get("cveMetadata"):
        resumen = _resumir_cve_org(res.data)
        conn.execute("INSERT INTO cve_detalle(cve, encontrado, json, consultado_at) VALUES(?,1,?,?) "
                     "ON CONFLICT(cve) DO UPDATE SET encontrado=1, json=excluded.json, consultado_at=excluded.consultado_at",
                     (cve, json.dumps(resumen, ensure_ascii=False), ahora))
        resumen.update(encontrado=True, consultado_at=ahora)
        return resumen
    if res.status == 404:
        conn.execute("INSERT INTO cve_detalle(cve, encontrado, json, consultado_at) VALUES(?,0,NULL,?) "
                     "ON CONFLICT(cve) DO UPDATE SET encontrado=0, json=NULL, consultado_at=excluded.consultado_at",
                     (cve, ahora))
        return {"encontrado": False, "consultado_at": ahora}
    return None


# --------------------------------------------------------------------------
# Descripciones de relleno (v7, 2026-09-06)
# --------------------------------------------------------------------------
# El 6 de septiembre de 2026, 11 de las 25 vulnerabilidades detalladas del correo
# llevaban como descripcion el texto literal «Informacion publicada.»: el canal de
# Microsoft (MSRC) y algunos avisos de distribucion publican ese relleno cuando el
# boletin sale antes que el analisis, y el enriquecimiento solo rellenaba las
# descripciones VACIAS (COALESCE(NULLIF(summary_en,''), ?)), asi que nunca lo
# sustituia. Aqui se detecta el relleno y se busca la descripcion real.
#
# Criterio: CONSERVADOR. Ante la duda, la descripcion que ya hay se conserva; solo
# se sustituye por la frase honesta cuando el texto actual no aporta NADA (vacio,
# plantilla conocida, solo el identificador, solo un enlace o el titulo repetido).

LONGITUD_MINIMA_DESCRIPCION = 60     # por debajo, un texto sin vocabulario tecnico es relleno
MAX_LONGITUD_DESCRIPCION = 4000      # lo que cabe en threats.summary_en sin desbordar el informe
MAX_LONGITUD_TRADUCCION = 1800       # lo que se manda a traducir (igual que el recolector)
DIAS_REINTENTO_DESCRIPCION = 7       # espera antes de volver a preguntar por la misma amenaza

ORIGEN_SIN_DATO = "sin_dato"         # valor de threats.descripcion_origen con la frase honesta
ORIGENES_DESCRIPCION = ("fuente", "nvd", "cve.org", "msrc", ORIGEN_SIN_DATO)

# Motivos por los que un texto es relleno SIN NINGUN valor: se puede sustituir por la
# frase honesta sin perder informacion. El motivo «corta» no esta aqui a proposito:
# un texto corto puede ser una descripcion real y pobre, y se conserva si no se
# encuentra nada mejor.
_MOTIVOS_SIN_VALOR = ("vacia", "plantilla", "identificador", "enlace", "titulo")

_RE_URL = re.compile(r"https?://\S+", re.IGNORECASE)
_RE_SOLO_CVE = re.compile(r"^(?:cve[ -]?\d{4}[ -]?\d{4,}[\s,;:./|-]*)+$")

# Signos que separan una frase de plantilla de la siguiente (asteriscos de MITRE,
# puntuacion, guiones) y que no cuentan como contenido.
_RE_BORDE = re.compile(r"^[\s*.;:,_|/\\\-–—()\[\]<>\"'¿?!¡]+")

# Caracteres invisibles y de control que algunos avisos traen: anulacion de derecha a
# izquierda (U+202E), espacio de ancho cero (U+200B), marca de orden de bytes... Jinja
# escapa el HTML, asi que no hay ejecucion posible, pero esos caracteres cambian el
# ORDEN DE LECTURA del texto y son la forma clasica de disfrazar el nombre de un
# producto o de un fichero en un aviso. Se quitan de todo texto que se guarde o se
# compare (revision del 6 de septiembre de 2026).
_RE_INVISIBLES = re.compile(
    "[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u00ad"
    "\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069"
    "\ufeff\ufff9-\ufffb]")


def limpiar_invisibles(texto: Optional[str]) -> str:
    """Quita los caracteres de control e invisibles (incluidos los que alteran el
    sentido de lectura), conservando los saltos de linea y las tabulaciones."""
    if not texto:
        return ""
    return _RE_INVISIBLES.sub("", str(texto))

# Plantillas conocidas de relleno. Cada una con el motivo por el que no describe la
# vulnerabilidad. Se comparan contra el texto normalizado (minusculas, sin tildes,
# sin HTML y con los espacios colapsados) y anclados al principio: varias fuentes
# anaden detras la fecha de revision o el nombre del CNA.
_PLANTILLAS_RELLENO: tuple[tuple[re.Pattern, str], ...] = (
    # Microsoft MSRC publica el boletin antes del analisis con este texto exacto.
    (re.compile(r"^informacion publicada\b"),
     "«Información publicada.» es el relleno que envía el canal de Microsoft cuando "
     "aún no ha publicado el análisis"),
    (re.compile(r"^information published\b"),
     "«Information published.» es el mismo relleno de Microsoft en su versión original"),
    # NVD y CVE.org devuelven este texto mientras el CVE no tiene analisis.
    # Anclado tambien al final: «Sin descripción publicada todavía por la fuente...»
    # es la frase honesta de este modulo y NO debe darse por relleno (seria un bucle).
    (re.compile(r"^(no|sin) (description|descripcion)( (available|disponible))?"
                r"( (for this cve|para este cve))?$"),
     "«No description available» es lo que devuelve la base de datos nacional de "
     "vulnerabilidades de Estados Unidos (NVD) mientras el identificador CVE no tiene "
     "análisis"),
    (re.compile(r"^descripcion no disponible$"),
     "traducción del «No description available» de la base de datos nacional de "
     "vulnerabilidades de Estados Unidos (NVD)"),
    # CVE.org marca asi los identificadores reservados o retirados.
    (re.compile(r"^\*{0,2}\s*reserved\b"),
     "«** RESERVED **» significa que el identificador está reservado y todavía sin publicar"),
    (re.compile(r"^\*{0,2}\s*reject(ed)?\b"),
     "«** REJECT **» significa que el identificador fue retirado por el organismo emisor"),
    (re.compile(r"^this candidate (has been reserved|was withdrawn|is not valid)\b"),
     "texto fijo de MITRE para un identificador reservado o retirado"),
    (re.compile(r"^do not use this candidate\b"),
     "texto fijo de MITRE para un identificador que no debe usarse"),
    (re.compile(r"^duplicate of cve-\d{4}-\d{4,}"),
     "el registro solo remite a otro identificador duplicado"),
    # Revisiones administrativas del boletin: cambian creditos, no la vulnerabilidad.
    (re.compile(r"^(reconocimiento|acknowledge?ment)s? (actualizado|anadido|updated|added)\b"),
     "solo anuncia un cambio de créditos del boletín, no describe la vulnerabilidad"),
    (re.compile(r"^(se )?(actualizo|anadio|updated|added) un(a)? (reconocimiento|acknowledge?ment)\b"),
     "solo anuncia un cambio de créditos del boletín, no describe la vulnerabilidad"),
    (re.compile(r"^(esto es|this is)( solo| solamente| only)? (un|a)n? cambio informativo\b"),
     "solo anuncia un cambio informativo del boletín"),
    (re.compile(r"^(this is )?(an )?informational change only\b"),
     "solo anuncia un cambio informativo del boletín"),
    (re.compile(r"^(revision|revised) information\b"),
     "solo anuncia una revisión del boletín"),
    (re.compile(r"^(valor )?(cwe|cvss|puntuacion cvss)\b.{0,40}"
                r"\b(anadid[oa]|actualizad[oa]|added|updated|revisad[oa])\b"),
     "solo anuncia un cambio administrativo del boletín (la clasificación de la "
     "debilidad, CWE, o la puntuación de gravedad, CVSS), no describe la vulnerabilidad"),
    # Marcadores de ausencia de dato.
    (re.compile(r"^(n/?a|none|null|ninguno|ninguna|pendiente|pending|sin datos?|"
                r"no disponible|not available|por determinar|under analysis|"
                r"en analisis|awaiting analysis)$"),
     "es un marcador de ausencia de dato, no una descripción"),
)

# Palabreria fija que acompana a esas plantillas y que tampoco describe nada. Se recorta
# igual que las plantillas para poder comprobar si detras queda texto REAL: el aviso de
# MITRE para un identificador reservado, por ejemplo, son cuatro frases seguidas de
# relleno («** RESERVED ** This candidate has been reserved by an organization or
# individual that will use it when announcing a new security problem.»).
_CONTINUACIONES_RELLENO: tuple[re.Pattern, ...] = (
    re.compile(r"^by an organization or individual that will use it when announcing "
               r"a new security problem"),
    re.compile(r"^when the candidate has been publicized,? the details for this "
               r"candidate will be provided"),
    re.compile(r"^do not use this candidate( number)?"),
    re.compile(r"^consult ?ids?:?( *(none|ninguno|ninguna))?"),
    re.compile(r"^reasons?:?"),
    re.compile(r"^notes?:?( *(none|ninguno|ninguna))?"),
    re.compile(r"^number:?"),
    re.compile(r"^(este|esta) (candidato|identificador|numero) (no debe usarse|"
               r"fue retirado|esta reservado|ha sido reservado)"),
    re.compile(r"^(sera|seran) (publicado|publicados|proporcionados) (el|los) detalles?"),
    re.compile(r"^(cuando|una vez que) (el|este) candidato (se haya|sea) "
               r"(publicado|publicitado|anunciado)"),
    re.compile(r"^(por|de) parte de (una|la) (organizacion|entidad|persona)"),
    re.compile(r"^que lo usara cuando anuncie un nuevo problema de seguridad"),
)

# Vocabulario tecnico: si aparece, un texto corto se considera una descripcion real
# y NO se toca. La lista es deliberadamente amplia (espanol e ingles) porque el
# criterio es conservador: se prefiere conservar de mas a borrar de menos.
_TERMINOS_TECNICOS = (
    "desbordamiento", "buffer", "overflow", "over-read", "underflow",
    "use after free", "uso despues de liberar", "double free", "doble liberacion",
    "ejecucion de codigo", "ejecucion remota", "code execution", "execute code",
    "escalada", "elevacion de privilegios", "elevate privileg", "privileg",
    "denegacion de servicio", "denial of service", "cross-site", "xss", "csrf",
    "inyeccion", "injection", "sql", "deserializ", "traversal", "salto de directorio",
    "arbitrari", "autenticacion", "authentication", "autorizacion", "authorization",
    "bypass", "omision", "eludir", "suplantacion", "spoofing", "secuestro", "hijack",
    "fuga de informacion", "information disclosure", "divulgacion", "filtracion",
    "memoria", "memory", "kernel", "nucleo", "sandbox", "aislamiento",
    "cifrado", "criptograf", "crypto", "certificado", "certificate", "tls", "ssl",
    "condicion de carrera", "race condition", "puntero", "pointer", "heap", "stack",
    "pila", "monticulo", "entero", "integer", "validacion", "validation",
    "sanitiz", "saneamiento", "atacante", "attacker", "remoto", "remote",
    "vulnerabilidad de", "vulnerability in", "permite a", "allows an", "allows a",
    "actualice", "actualizacion a", "corrige", "fixed in", "parche", "patch",
    "cwe-", "denial", "dos ", "rce", "ssrf", "xxe", "lfi", "rfi",
)
_RE_TECNICO = re.compile(
    "|".join(re.escape(t) for t in _TERMINOS_TECNICOS) + r"|\d+\.\d+")


def _sin_tildes(texto: str) -> str:
    """Quita tildes y dieresis para comparar textos sin depender de la acentuacion."""
    descompuesto = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in descompuesto if not unicodedata.combining(c))


def normalizar_descripcion(texto: Optional[str]) -> str:
    """Texto comparable: sin HTML, sin tildes, en minusculas, sin signos en los
    extremos y con los espacios colapsados. Es lo que se compara con las plantillas."""
    limpio = limpiar_invisibles(translate.limpiar_html(texto))
    if not limpio:
        return ""
    limpio = _sin_tildes(limpio).lower()
    limpio = re.sub(r"\s+", " ", limpio).strip()
    return limpio.strip(" .;:,–—\"'()[]<>-")


def _tiene_contenido(normal: str) -> bool:
    """True si el texto normalizado aporta algo: es largo, o corto pero con vocabulario
    tecnico. Mismo criterio que el motivo «corta», aplicado a un trozo de texto."""
    return bool(normal) and (len(normal) >= LONGITUD_MINIMA_DESCRIPCION
                             or bool(_RE_TECNICO.search(normal)))


def _recortar_plantillas(normal: str) -> tuple[Optional[str], str]:
    """Recorta del principio las plantillas de relleno y la palabreria fija que las
    acompana, tantas veces como haga falta.

    Devuelve (motivo de la primera plantilla encontrada, texto que queda detras). Si el
    texto no empieza por ninguna plantilla, devuelve (None, texto entero)."""
    resto = normal
    motivo: Optional[str] = None
    recortado = normal
    for _ in range(8):      # tope: ningun relleno real encadena mas de cuatro frases
        recortado = _RE_BORDE.sub("", resto)
        encontrado = False
        for patron, motivo_patron in _PLANTILLAS_RELLENO:
            coincidencia = patron.match(recortado)
            if coincidencia and coincidencia.end() > 0:
                motivo = motivo or motivo_patron
                resto = recortado[coincidencia.end():]
                encontrado = True
                break
        if encontrado:
            continue
        if motivo is None:
            return None, normal
        for patron in _CONTINUACIONES_RELLENO:
            coincidencia = patron.match(recortado)
            if coincidencia and coincidencia.end() > 0:
                resto = recortado[coincidencia.end():]
                encontrado = True
                break
        if not encontrado:
            return motivo, recortado
    return motivo, _RE_BORDE.sub("", resto)


def _clasificar_descripcion(texto: Optional[str], *, titulo: Any = None,
                            cve: Optional[str] = None) -> Optional[tuple[str, str]]:
    """Devuelve (clave, motivo en espanol) si el texto es relleno; None si es valido.

    `titulo` puede ser una cadena o varias (titulo en espanol y en ingles)."""
    limpio = limpiar_invisibles(translate.limpiar_html(texto))
    normal = normalizar_descripcion(limpio)
    if not normal:
        return ("vacia", "no hay ningún texto de descripción")
    # Solo signos (asteriscos de MITRE, guiones, puntuacion): tampoco es una descripcion.
    if not re.search(r"\w", normal, re.UNICODE):
        return ("vacia", "el texto no tiene ninguna palabra, solo signos de puntuación")

    # Las plantillas estan ancladas al PRINCIPIO porque varias fuentes anaden detras la
    # fecha de revision o el nombre del organismo emisor. Anclarlas y nada mas borraria
    # descripciones REALES que empiezan por una de esas frases: comprobado el 6 de
    # septiembre de 2026 con la amenaza 2599 (CVE-2026-48566), cuyo texto «Información
    # publicada. Este CVE fue abordado por actualizaciones que fueron publicadas en mayo
    # de 2026...» explica al analista que ya esta corregido. Por eso se exige que,
    # quitando las plantillas y la palabreria conocida que las acompana, NO quede texto
    # con contenido: si queda, la descripcion es real y no se toca.
    motivo_plantilla, sobrante = _recortar_plantillas(normal)
    if motivo_plantilla and not _tiene_contenido(sobrante):
        return ("plantilla", motivo_plantilla)

    if _RE_SOLO_CVE.match(normal):
        return ("identificador", "el texto solo repite el identificador de la vulnerabilidad")

    if cve and normal == _sin_tildes(str(cve)).lower().strip():
        return ("identificador", "el texto solo repite el identificador de la vulnerabilidad")

    if _RE_URL.search(limpio) and not normalizar_descripcion(_RE_URL.sub(" ", limpio)):
        return ("enlace", "el texto solo contiene un enlace, sin ninguna explicación")

    titulos = titulo if isinstance(titulo, (list, tuple, set)) else (titulo,)
    for candidato in titulos:
        if candidato and normalizar_descripcion(candidato) == normal:
            return ("titulo", "el texto repite el título y no añade ninguna información")

    if len(limpio) < LONGITUD_MINIMA_DESCRIPCION and not _RE_TECNICO.search(normal):
        return ("corta",
                f"el texto tiene menos de {LONGITUD_MINIMA_DESCRIPCION} caracteres y no "
                f"menciona ningún detalle técnico")

    return None


def motivo_relleno(texto: Optional[str], *, titulo: Any = None,
                   cve: Optional[str] = None) -> Optional[str]:
    """Motivo, en espanol, por el que la descripcion es de relleno; None si es valida."""
    clase = _clasificar_descripcion(texto, titulo=titulo, cve=cve)
    return clase[1] if clase else None


def es_descripcion_relleno(texto: Optional[str], *, titulo: Any = None,
                           cve: Optional[str] = None) -> bool:
    """True si la descripcion no describe la vulnerabilidad y hay que buscar la real.

    Es la funcion publica que usan el enriquecimiento, el repaso retroactivo y las
    pruebas. Conservadora: un texto largo, o corto pero con vocabulario tecnico, se
    considera valido aunque sea pobre."""
    return _clasificar_descripcion(texto, titulo=titulo, cve=cve) is not None


def descripcion_honesta(*, cve: Optional[str] = None,
                        enlace: Optional[str] = None) -> str:
    """Frase que se escribe cuando NINGUNA fuente publica todavia la descripcion.

    Dice la verdad y deja al analista donde seguir mirando; nunca es un relleno como
    «Información publicada.»."""
    if not enlace and cve and _RE_CVE_ID.match(str(cve).upper()):
        enlace = f"https://nvd.nist.gov/vuln/detail/{str(cve).upper()}"
    if enlace:
        return ("Sin descripción publicada todavía por la fuente ni por la base de datos "
                "nacional de vulnerabilidades de Estados Unidos (NVD); consulte el aviso "
                f"original: {enlace}")
    return ("Sin descripción publicada todavía por la fuente ni por la base de datos "
            "nacional de vulnerabilidades de Estados Unidos (NVD), y no hay un aviso "
            "original registrado para esta amenaza; se revisará en los próximos días.")


def _enlace_amenaza(conn: sqlite3.Connection, threat_id: Optional[int]) -> Optional[str]:
    """Primer enlace registrado de la amenaza, para que la frase honesta sea util."""
    if not threat_id:
        return None
    fila = conn.execute(
        "SELECT url FROM threat_sources WHERE threat_id=? AND url <> '' "
        "ORDER BY seen_at LIMIT 1", (threat_id,)).fetchone()
    return fila["url"] if fila else None


# --------------------------------------------------------------------------
# Descripcion del boletin de Microsoft (documentos CVRF ya descargados)
# --------------------------------------------------------------------------
CACHE_MSRC = CACHE_DIR / "msrc"

_MESES_CVRF = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
               "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}

# Indice {CVE: descripcion} construido una sola vez por proceso y por directorio:
# son 18 documentos y unos 11.000 CVE, 0,8 segundos de lectura. Se hace de forma
# perezosa para no pagarlo cuando ninguna descripcion necesita al boletin.
_INDICE_MSRC: dict[str, dict[str, str]] = {}


def _orden_documento_msrc(ruta: Path) -> tuple[int, int]:
    """Clave para leer los boletines del mas reciente al mas antiguo («2026-Sep»)."""
    partes = ruta.stem.split("-")
    try:
        anio = int(partes[0])
    except (ValueError, IndexError):
        return (0, 0)
    mes = _MESES_CVRF.get(partes[1][:3].lower(), 0) if len(partes) > 1 else 0
    return (anio, mes)


def _indice_descripciones_msrc(cache_dir: Optional[Path] = None) -> dict[str, str]:
    """{CVE: descripcion} de todos los boletines CVRF guardados en disco.

    La descripcion de la vulnerabilidad esta en `Vulnerability -> Notes` con
    `Type` 2 («Description»); llega en HTML, asi que se limpia. Se lee del mas
    reciente al mas antiguo y gana la primera version encontrada (la revisada)."""
    directorio = Path(cache_dir) if cache_dir is not None else CACHE_MSRC
    clave = str(directorio)
    if clave in _INDICE_MSRC:
        return _INDICE_MSRC[clave]

    indice: dict[str, str] = {}
    try:
        rutas = sorted([r for r in directorio.glob("*.json") if r.is_file()],
                       key=_orden_documento_msrc, reverse=True)
    except OSError as exc:
        log.warning("no se pudieron listar los boletines de Microsoft",
                    extra={"error": str(exc)})
        rutas = []

    for ruta in rutas:
        try:
            documento = json.loads(ruta.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("boletín de Microsoft ilegible",
                        extra={"documento": ruta.stem, "error": str(exc)})
            continue
        if not isinstance(documento, dict):
            continue
        for vulnerabilidad in documento.get("Vulnerability") or []:
            cve = str((vulnerabilidad or {}).get("CVE") or "").strip().upper()
            if not cve.startswith("CVE-") or cve in indice:
                continue
            for nota in vulnerabilidad.get("Notes") or []:
                if str((nota or {}).get("Type")) != "2":
                    continue
                texto = translate.limpiar_html(nota.get("Value"))
                if texto:
                    indice[cve] = texto
                break
        del documento

    _INDICE_MSRC[clave] = indice
    log.info("descripciones de los boletines de Microsoft indexadas",
             extra={"cve": len(indice), "documentos": len(rutas)})
    return indice


def descripcion_msrc(cve: Optional[str], *,
                     cache_dir: Optional[Path] = None) -> Optional[str]:
    """Descripcion de un CVE segun los boletines de Microsoft ya descargados.

    No usa red: lee `data/cache/msrc/*.json`, la copia local que deja
    `threatintel.msrc`. Devuelve None si el CVE no esta o no trae descripcion."""
    cve = str(cve or "").strip().upper()
    if not _RE_CVE_ID.match(cve):
        return None
    return _indice_descripciones_msrc(cache_dir).get(cve)


def olvidar_indice_msrc() -> None:
    """Vacia el indice en memoria (tras descargar boletines nuevos o en pruebas)."""
    _INDICE_MSRC.clear()


# --------------------------------------------------------------------------
# Busqueda y escritura de la descripcion real
# --------------------------------------------------------------------------
def buscar_descripcion(conn: sqlite3.Connection, amenaza: dict, *, cfg,
                       nvd: Optional[dict] = None, permitir_red: bool = True,
                       fetch=None, cache_msrc: Optional[Path] = None) -> dict[str, Any]:
    """Busca la descripcion real de una amenaza. Devuelve
    {'texto', 'origen', 'consultas'} con `texto` None si ninguna fuente la publica.

    Orden: la propia fuente (si su texto en ingles si vale y solo falla el
    castellano), NVD, CVE.org y el boletin de Microsoft. Se acepta la primera que
    no sea, a su vez, relleno."""
    cve = str(amenaza.get("cve") or "").strip().upper()
    titulos = (amenaza.get("title_es"), amenaza.get("title_en"))
    consultas = 0

    def util(texto: Optional[str]) -> Optional[str]:
        limpio = limpiar_invisibles(translate.limpiar_html(texto))
        if not limpio or es_descripcion_relleno(limpio, titulo=titulos, cve=cve):
            return None
        return limpio[:MAX_LONGITUD_DESCRIPCION]

    # a) La fuente original: su texto en ingles puede ser bueno aunque el castellano
    #    guardado sea relleno (traduccion vieja o resumen recortado).
    texto = util(amenaza.get("summary_en"))
    if texto:
        return {"texto": texto, "origen": "fuente", "consultas": consultas}

    if not _RE_CVE_ID.match(cve):
        return {"texto": None, "origen": None, "consultas": consultas}

    # b) NVD: si el enriquecimiento acaba de consultarlo, se reutiliza su respuesta.
    datos_nvd = nvd
    if datos_nvd is None and permitir_red and cfg.get("enrich_nvd_enabled", True):
        try:
            datos_nvd = consultar_nvd(cve, cfg=cfg)
            consultas += 1
        except Exception as exc:  # noqa: BLE001
            log.warning("no se pudo consultar NVD para la descripción",
                        extra={"cve": cve, "error": str(exc)})
            datos_nvd = None
    if datos_nvd and datos_nvd.get("encontrado") is not False:
        texto = util(datos_nvd.get("descripcion"))
        if texto:
            return {"texto": texto, "origen": "nvd", "consultas": consultas}

    # c) CVE.org (CVE List 5.x), que ya se cachea en la tabla cve_detalle.
    #
    # Se cuentan las peticiones REALES, no el intento: `detalle_cve` sirve de la tabla
    # `cve_detalle` durante 168 horas, y contar una consulta que no ha salido a Internet
    # gastaria el tope del repaso y, peor, obligaria a esperar 6,5 segundos por el limite
    # publico de NVD sin ninguna necesidad (corregido el 6 de septiembre de 2026).
    peticiones = {"hechas": 0}

    def fetch_contado(url, **kwargs):
        peticiones["hechas"] += 1
        return (fetch or http.fetch_json)(url, **kwargs)

    try:
        detalle = detalle_cve(conn, cve, cfg=cfg, permitir_red=permitir_red,
                              fetch=fetch_contado)
        consultas += peticiones["hechas"]
    except Exception as exc:  # noqa: BLE001
        log.warning("no se pudo consultar CVE.org para la descripción",
                    extra={"cve": cve, "error": str(exc)})
        detalle = None
    if detalle and detalle.get("encontrado"):
        texto = util(detalle.get("descripcion"))
        if texto:
            return {"texto": texto, "origen": "cve.org", "consultas": consultas}

    # d) El boletin de Microsoft, sin red: los documentos CVRF ya estan en disco.
    texto = util(descripcion_msrc(cve, cache_dir=cache_msrc))
    if texto:
        return {"texto": texto, "origen": "msrc", "consultas": consultas}

    return {"texto": None, "origen": None, "consultas": consultas}


def _traducir_descripcion(conn: Optional[sqlite3.Connection], texto: str, *, cfg,
                          severidad: Optional[str] = None,
                          contador=None) -> tuple[Optional[str], str]:
    """Traduce la descripcion con el flujo normal del proyecto (translate.traducir:
    cache, plantillas, Ollama o Argos segun el ajuste).

    Devuelve (traduccion, motor). La traduccion es None si no se pudo traducir, para que
    el informe la marque «[texto original en inglés]»; el motor se guarda en
    `threats.translation_engine`, que es lo que la ficha de la vulnerabilidad ensena al
    analista («Traducción automática (argos) del texto original en inglés»): si no se
    devolviera, la ficha seguiria atribuyendo el texto nuevo a la traduccion anterior."""
    try:
        traducida, motor = translate.traducir(
            texto[:MAX_LONGITUD_TRADUCCION], cfg=cfg, conn=conn,
            severidad=severidad, contador=contador)
    except Exception as exc:  # noqa: BLE001
        log.warning("no se pudo traducir la descripción", extra={"error": str(exc)})
        return None, "none"
    traducida = limpiar_invisibles(traducida)
    if not traducida:
        return None, "none"
    if motor == "none" and not translate.parece_espanol(traducida):
        return None, "none"
    # Una traduccion que se queda en nada (el motor devolvio una frase suelta) seria
    # relleno otra vez: se descarta y el informe muestra el original en ingles.
    if es_descripcion_relleno(traducida) and not es_descripcion_relleno(texto):
        log.warning("la traducción de la descripción quedó vacía de contenido; "
                    "se conserva el texto original",
                    extra={"motor": motor, "longitud": len(traducida)})
        return None, "none"
    return traducida[:MAX_LONGITUD_DESCRIPCION], (motor or "none")


# Textos de auditoria por origen, para que el registro se lea sin conocer el codigo.
_AUDITORIA_ORIGEN = {
    "fuente": "se publica el texto en inglés que ya había enviado la fuente original",
    "nvd": "descripción tomada de la base de datos nacional de vulnerabilidades (NVD)",
    "cve.org": "descripción tomada del registro público CVE.org",
    "msrc": "descripción tomada del boletín de seguridad de Microsoft",
    ORIGEN_SIN_DATO: "ninguna fuente publica todavía la descripción: se deja constancia "
                     "de ello y del enlace al aviso original",
}


def _auditar_descripcion(conn: sqlite3.Connection, threat_id: Any,
                         origen: Optional[str], detalle: str) -> None:
    """Deja constancia en el registro de auditoria de cada descripcion sustituida.

    Cambiar la descripcion publicada de una vulnerabilidad es un cambio de dato
    relevante para el analista (de donde salio el texto que esta leyendo), asi que se
    anota amenaza por amenaza y no solo un resumen por ejecucion."""
    accion = ("descripcion.sin_dato" if origen == ORIGEN_SIN_DATO
              else "descripcion.completada")
    explicacion = _AUDITORIA_ORIGEN.get(origen or "", f"origen «{origen}»")
    try:
        db.audit(conn, "sistema", accion, "threats", threat_id,
                 f"{explicacion}; {detalle}"[:1000], None)
    except Exception as exc:  # noqa: BLE001 - la auditoria nunca rompe el proceso
        log.warning("no se pudo auditar la descripción",
                    extra={"threat_id": threat_id, "error": str(exc)})


def completar_descripcion(conn: sqlite3.Connection, amenaza: dict, *, cfg,
                          nvd: Optional[dict] = None, permitir_red: bool = True,
                          fetch=None, cache_msrc: Optional[Path] = None,
                          contador=None) -> dict[str, Any]:
    """Sustituye la descripcion de relleno de UNA amenaza por la real.

    `amenaza` es una fila de `threats` como diccionario (id, cve, title_en, title_es,
    summary_en, summary_es, severity, descripcion_origen). Devuelve
    {'cambiada', 'origen', 'motivo', 'consultas', 'texto'}.

    No toca las descripciones validas: es la garantia de que una descripcion buena
    nunca se pierde, y de que dos pasadas seguidas no consumen red."""
    resultado: dict[str, Any] = {"cambiada": False, "origen": None, "motivo": None,
                                 "consultas": 0, "texto": None}
    if not cfg.get("descripcion_completar", True):
        resultado["motivo"] = ("el ajuste «Completar las descripciones de relleno» "
                               "está desactivado")
        return resultado

    titulos = (amenaza.get("title_es"), amenaza.get("title_en"))
    cve = str(amenaza.get("cve") or "").strip().upper() or None
    visible = ((amenaza.get("summary_es") or "").strip()
               or (amenaza.get("summary_en") or "").strip())
    clase = _clasificar_descripcion(visible, titulo=titulos, cve=cve)
    reintento_honesta = (amenaza.get("descripcion_origen") == ORIGEN_SIN_DATO)

    if clase is None and not reintento_honesta:
        resultado["motivo"] = "la descripción actual describe la vulnerabilidad"
        return resultado

    resultado["motivo"] = clase[1] if clase else (
        "la descripción actual dice que ninguna fuente la había publicado todavía")

    # Sin identificador todas las escrituras serian «WHERE id=NULL»: no cambiarian nada,
    # no fallarian, y el repaso las contaria como resueltas. Se comprueba antes de gastar
    # una sola consulta de red (revision del 6 de septiembre de 2026).
    identificador = amenaza.get("id")
    if not identificador:
        resultado["motivo"] = ("la fila de la amenaza no trae su identificador, así que "
                               "no se puede escribir la descripción")
        log.warning("descripción no completada: la fila no trae identificador",
                    extra={"cve": cve})
        return resultado

    hallazgo = buscar_descripcion(conn, amenaza, cfg=cfg, nvd=nvd,
                                  permitir_red=permitir_red, fetch=fetch,
                                  cache_msrc=cache_msrc)
    resultado["consultas"] = hallazgo["consultas"]
    ahora = db.utcnow()

    if hallazgo["texto"]:
        texto = hallazgo["texto"]
        origen = hallazgo["origen"]
        traducida, motor = _traducir_descripcion(conn, texto, cfg=cfg,
                                                 severidad=amenaza.get("severity"),
                                                 contador=contador)
        # Con origen «fuente» el texto en ingles ya estaba guardado y es el bueno:
        # lo que faltaba era el castellano.
        resumen_en = amenaza.get("summary_en") if origen == "fuente" else texto
        _escribir_con_reintento(conn,
            """UPDATE threats SET summary_en=?, summary_es=?, descripcion_origen=?,
                                  descripcion_buscada_at=?, translation_engine=?
                            WHERE id=?""",
            (resumen_en, traducida, origen, ahora, motor if traducida else "none",
             identificador))
        _auditar_descripcion(conn, identificador, origen,
                             f"motivo del cambio: {resultado['motivo']}")
        resultado.update(cambiada=True, origen=origen, texto=traducida or texto)
        log.info("descripción de relleno sustituida",
                 extra={"threat_id": identificador, "cve": cve, "origen": origen})
        return resultado

    # Sin red no se puede afirmar que nadie publique la descripcion: si la amenaza
    # tiene CVE, quedan NVD y CVE.org por preguntar, asi que no se escribe nada y
    # tampoco se anota la fecha (la proxima ejecucion con red volvera a intentarlo).
    if hallazgo["texto"] is None and cve and not permitir_red and nvd is None:
        resultado["motivo"] = (resultado["motivo"] +
                               "; no se consultó la red, queda pendiente de preguntar a "
                               "la base de datos nacional de vulnerabilidades (NVD) y al "
                               "registro público CVE.org")
        return resultado

    # Ninguna fuente la publica. Solo se sustituye el texto actual si no aportaba
    # nada; un texto corto pero real se conserva.
    sin_valor = (clase is not None and clase[0] in _MOTIVOS_SIN_VALOR) or reintento_honesta
    if not sin_valor:
        _escribir_con_reintento(
            conn, "UPDATE threats SET descripcion_buscada_at=? WHERE id=?",
            (ahora, identificador))
        resultado["motivo"] = (resultado["motivo"] +
                               "; ninguna fuente publica otra mejor, se conserva la actual")
        return resultado

    frase = descripcion_honesta(cve=cve, enlace=_enlace_amenaza(conn, identificador))
    if (amenaza.get("summary_es") or "").strip() == frase:
        _escribir_con_reintento(
            conn, "UPDATE threats SET descripcion_buscada_at=? WHERE id=?",
            (ahora, identificador))
        resultado.update(origen=ORIGEN_SIN_DATO, texto=frase)
        return resultado

    # La frase la escribe el propio sistema y no es la traduccion de nada: el motor pasa
    # a «none» para que la ficha de la vulnerabilidad no la presente como «Traducción
    # automática (argos) del texto original en inglés».
    _escribir_con_reintento(conn,
        """UPDATE threats SET summary_es=?, descripcion_origen=?,
                              descripcion_buscada_at=?, translation_engine=?
                        WHERE id=?""",
        (frase, ORIGEN_SIN_DATO, ahora, "none", identificador))
    _auditar_descripcion(conn, identificador, ORIGEN_SIN_DATO,
                         f"motivo del cambio: {resultado['motivo']}")
    resultado.update(cambiada=True, origen=ORIGEN_SIN_DATO, texto=frase)
    log.info("sin descripción publicada: se escribe la frase honesta",
             extra={"threat_id": identificador, "cve": cve})
    return resultado


# Columnas que necesita `completar_descripcion` para decidir sin volver a consultar.
_COLUMNAS_DESCRIPCION = ("id, cve, title_en, title_es, summary_en, summary_es, "
                         "severity, descripcion_origen, descripcion_buscada_at")

# Preselección en SQL de las candidatas a relleno. Es un superconjunto barato (el
# criterio fino lo aplica `es_descripcion_relleno` en Python): descripcion visible
# vacia, corta, igual al titulo, o amenaza que ya quedo con la frase honesta.
_SQL_CANDIDATAS_DESCRIPCION = f"""
    SELECT {_COLUMNAS_DESCRIPCION}
      FROM threats
     WHERE estado NOT IN ('descartada','falso_positivo')
       AND (descripcion_buscada_at IS NULL OR descripcion_buscada_at <= ?)
       AND (
            LENGTH(TRIM(COALESCE(NULLIF(TRIM(summary_es),''),
                                 NULLIF(TRIM(summary_en),''), ''))) < 200
            OR LOWER(TRIM(COALESCE(summary_es,''))) = LOWER(TRIM(COALESCE(title_es,'')))
            OR LOWER(TRIM(COALESCE(summary_en,''))) = LOWER(TRIM(COALESCE(title_en,'')))
            OR descripcion_origen = ?
           )
     ORDER BY relevance DESC, in_kev DESC, first_seen_at DESC
     LIMIT ?"""


MAX_CANDIDATAS_DESCRIPCION = 5000    # filas que se traen de la preseleccion SQL


def repasar_descripciones(conn: sqlite3.Connection, *, cfg,
                          limite: int = 100, permitir_red: bool = True,
                          max_consultas: Optional[int] = None,
                          dias_reintento: int = DIAS_REINTENTO_DESCRIPCION,
                          max_candidatas: int = MAX_CANDIDATAS_DESCRIPCION,
                          fetch=None, cache_msrc: Optional[Path] = None) -> dict[str, Any]:
    """Repaso retroactivo: busca la descripcion real de las amenazas ABIERTAS que
    hoy llevan relleno, empezando por las de mas relevancia.

    `limite` amenazas por ejecucion y `max_consultas` peticiones de red como mucho
    (por defecto, dos por amenaza: NVD y CVE.org). Una amenaza ya revisada no se
    vuelve a mirar hasta `dias_reintento` dias despues, asi que dos pasadas seguidas
    no consumen red. Pensado para ejecutarse sobre la base real desde `bin/`.

    IMPORTANTE: como en `enriquecer_pendientes`, la conexion debe estar en
    autocommit (`db.connect()`), nunca dentro de `db.session()`: entre consulta y
    consulta hay esperas de segundos y una transaccion abierta bloquearia la
    interfaz web."""
    estadisticas: dict[str, Any] = {
        "candidatas": 0, "revisadas": 0, "resueltas": 0, "sin_dato": 0,
        "conservadas": 0, "consultas": 0, "por_origen": {}, "omitido": False,
        "ejemplos": [],
    }
    if not cfg.get("descripcion_completar", True):
        estadisticas["omitido"] = True
        log.info("repaso de descripciones omitido: ajuste descripcion_completar desactivado")
        return estadisticas

    tope_consultas = (max_consultas if max_consultas is not None
                      else max(0, int(limite)) * 2)
    corte = (datetime.now(timezone.utc) - timedelta(days=max(0, int(dias_reintento))))
    corte_iso = corte.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    # Se piden muchas mas filas que `limite` porque la preseleccion SQL es un
    # superconjunto amplio: la mayoria de las descripciones cortas si son validas y
    # se descartan en Python, y sin margen el repaso no llegaria nunca al fondo de
    # la lista. Son unas pocas miles de filas cortas, no un problema de volumen.
    candidatas = [dict(r) for r in conn.execute(
        _SQL_CANDIDATAS_DESCRIPCION,
        (corte_iso, ORIGEN_SIN_DATO, max(1, int(max_candidatas))))]
    estadisticas["candidatas"] = len(candidatas)

    contador = translate.ContadorLlamadas(
        int(cfg.get("ollama_max_calls_per_run", 25) or 25))

    espera = float(cfg.get("nvd_rate_limit_sleep_s", 6.5))
    if clave_nvd_utilizable(cfg):
        espera = max(0.7, espera / 8)

    for fila in candidatas:
        if estadisticas["revisadas"] >= int(limite):
            break
        if estadisticas["consultas"] >= tope_consultas and permitir_red:
            log.info("repaso de descripciones detenido: agotado el límite de consultas",
                     extra={"consultas": estadisticas["consultas"]})
            break
        visible = ((fila.get("summary_es") or "").strip()
                   or (fila.get("summary_en") or "").strip())
        if not es_descripcion_relleno(
                visible, titulo=(fila.get("title_es"), fila.get("title_en")),
                cve=fila.get("cve")) and fila.get("descripcion_origen") != ORIGEN_SIN_DATO:
            continue

        antes = visible
        resultado = completar_descripcion(conn, fila, cfg=cfg, permitir_red=permitir_red,
                                          fetch=fetch, cache_msrc=cache_msrc,
                                          contador=contador)
        estadisticas["revisadas"] += 1
        estadisticas["consultas"] += resultado["consultas"]

        if resultado["cambiada"] and resultado["origen"] != ORIGEN_SIN_DATO:
            estadisticas["resueltas"] += 1
            origen = resultado["origen"] or "desconocido"
            estadisticas["por_origen"][origen] = estadisticas["por_origen"].get(origen, 0) + 1
            if len(estadisticas["ejemplos"]) < 5:
                estadisticas["ejemplos"].append(
                    {"id": fila.get("id"), "cve": fila.get("cve"), "origen": origen,
                     "antes": antes, "despues": resultado["texto"]})
        elif resultado["origen"] == ORIGEN_SIN_DATO:
            estadisticas["sin_dato"] += 1
        else:
            estadisticas["conservadas"] += 1

        if permitir_red and resultado["consultas"] and espera > 0:
            time.sleep(espera)

    log.info("repaso de descripciones terminado",
             extra={k: v for k, v in estadisticas.items() if k != "ejemplos"})
    return estadisticas
