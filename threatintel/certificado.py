"""Estado del certificado con el que se sirve la plataforma (2026-09-08).

La plataforma va cifrada con un certificado en disco que caduca; cuando caduca, el navegador
bloquea la entrada y los correos enlazan a una pagina que nadie puede abrir. Nadie se acuerda
de una fecha a un ano vista, asi que la plataforma la vigila igual que vigila la contrasena
del correo: dias restantes en la pagina de Credenciales y en el punto de salud que consulta
la monitorizacion, y un correo de administracion con antelacion.

Revision de claridad del 2026-09-15: ni la pagina ni el correo nombran rutas de fichero,
propietarios, permisos ni ordenes del servidor. Se dice QUIEN lo hace (Servicios
Tecnologicos) y QUE pasa (se sustituye y se recarga el servidor web, sin cortar el
servicio); el dato exacto lo tiene quien va a ejecutarlo.

Se lee el fichero PEM con la orden ``openssl x509`` (no hay biblioteca de certificados en el
entorno y la orden esta en todo Ubuntu). El fichero lo puede leer el usuario ``si`` porque
es el certificado publico (644); la clave privada, que es 600 de root, no se toca.
"""
from __future__ import annotations

import os
import re
import sqlite3
import ssl
import subprocess
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from . import db
from .logging_setup import get_logger

log = get_logger("certificado")

RUTA_POR_OMISION = "/etc/ssl/inteligencia-amenazas/servidor.crt"
ESTADO_OK = "ok"
ESTADO_POR_CADUCAR = "por_caducar"
ESTADO_CADUCADO = "caducado"
ESTADO_SIN_CERTIFICADO = "sin_certificado"
ESTADO_ERROR = "error"

ESTADO_ES = {
    ESTADO_OK: "Vigente",
    ESTADO_POR_CADUCAR: "Por caducar",
    ESTADO_CADUCADO: "Caducado",
    ESTADO_SIN_CERTIFICADO: "Sin certificado",
    ESTADO_ERROR: "No se pudo leer",
}

#: Extensiones admitidas para la ruta del ajuste; cualquier otra cosa no se pasa a openssl.
_EXTENSIONES = (".crt", ".pem", ".cer")
#: Resultado en memoria por (ruta, fecha de modificacion), para no bifurcar un proceso en
#: cada consulta a /salud.json.
_CACHE: dict[str, tuple[float, float, dict[str, Any]]] = {}
_CACHE_SEGUNDOS = 60.0


def _ajuste(cfg: Any, clave: str, por_omision: Any) -> Any:
    try:
        valor = cfg.get(clave) if cfg is not None else None
    except Exception:  # noqa: BLE001
        valor = None
    return por_omision if valor in (None, "") else valor


def _fecha_openssl(texto: str) -> Optional[datetime]:
    """«Jan 29 23:59:59 2027 GMT» -> datetime con zona UTC.

    Con ``ssl.cert_time_to_seconds`` de la biblioteca estandar, que entiende el formato de
    openssl con independencia del idioma del proceso: ``strptime`` con «%b» dependia del
    idioma de Python y habria fallado en silencio en cuanto algo fijara un idioma en espanol
    (revision adversaria del 2026-09-08).
    """
    texto = re.sub(r"\s+", " ", (texto or "").strip())
    if not texto:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(texto), timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def leer(ruta: str) -> dict[str, Any]:
    """Sujeto, emisor, fechas y nombres (SAN) del primer certificado del fichero PEM."""
    salida = subprocess.run(
        ["openssl", "x509", "-in", ruta, "-noout", "-subject", "-issuer", "-enddate",
         "-startdate", "-ext", "subjectAltName", "-nameopt", "RFC2253"],
        capture_output=True, text=True, timeout=10, check=False)
    if salida.returncode != 0:
        raise ValueError((salida.stderr or "openssl no pudo leer el certificado").strip()[:200])
    datos: dict[str, Any] = {"nombres": []}
    for linea in salida.stdout.splitlines():
        linea = linea.strip()
        if linea.startswith("subject="):
            datos["sujeto"] = linea[len("subject="):].strip()
        elif linea.startswith("issuer="):
            datos["emisor"] = linea[len("issuer="):].strip()
        elif linea.startswith("notAfter="):
            datos["not_after"] = _fecha_openssl(linea[len("notAfter="):])
        elif linea.startswith("notBefore="):
            datos["not_before"] = _fecha_openssl(linea[len("notBefore="):])
        elif "DNS:" in linea or "IP Address:" in linea:
            for trozo in linea.split(","):
                trozo = trozo.strip()
                if trozo.startswith("DNS:"):
                    datos["nombres"].append(trozo[4:])
                elif trozo.startswith("IP Address:"):
                    datos["nombres"].append(trozo[len("IP Address:"):])
    cn = re.search(r"CN=([^,]+)", datos.get("sujeto", ""))
    datos["nombre_comun"] = cn.group(1) if cn else datos.get("sujeto", "")
    org = re.search(r"O=([^,]+)", datos.get("emisor", ""))
    datos["emisor_corto"] = org.group(1) if org else datos.get("emisor", "")
    return datos


def estado(*, cfg: Any = None, ruta: Optional[str] = None,
           ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Estado del certificado: dias restantes y situacion, sin lanzar excepciones.

    ``ahora`` se acepta para las pruebas (un certificado «caducado» se prueba con una fecha
    futura, no esperando a que caduque).
    """
    ruta = ruta or str(_ajuste(cfg, "tls_certificado_ruta", RUTA_POR_OMISION))
    aviso_dias = int(float(_ajuste(cfg, "tls_aviso_dias", 30)))
    ahora = ahora or datetime.now(timezone.utc)
    base = {"ruta": ruta, "aviso_dias": aviso_dias, "estado": ESTADO_SIN_CERTIFICADO,
            "estado_es": ESTADO_ES[ESTADO_SIN_CERTIFICADO], "dias_restantes": None,
            "not_after": None, "not_before": None, "sujeto": None, "emisor": None,
            "emisor_corto": None, "nombre_comun": None, "nombres": [], "mensaje": ""}
    if not os.path.isabs(ruta) or not ruta.lower().endswith(_EXTENSIONES):
        base.update(estado=ESTADO_ERROR, estado_es=ESTADO_ES[ESTADO_ERROR],
                    mensaje=("El certificado configurado no tiene la forma que espera la "
                             "plataforma, así que no se puede vigilar su caducidad. Revise el "
                             "ajuste «Certificado con el que se sirve la plataforma», en "
                             "Administración → Ajustes → Interfaz, con el dato que facilite "
                             "Redes."))
        return base
    if not os.path.isfile(ruta):
        base["mensaje"] = ("No se encuentra el certificado configurado, así que no se puede "
                           "vigilar su caducidad. Revise el ajuste «Certificado con el que se "
                           "sirve la plataforma», en Administración → Ajustes → Interfaz, con "
                           "el dato que facilite Redes.")
        return base
    try:
        mtime = os.stat(ruta).st_mtime
        en_cache = _CACHE.get(ruta)
        if en_cache and en_cache[0] == mtime and time.monotonic() - en_cache[1] < _CACHE_SEGUNDOS:
            datos = dict(en_cache[2])
        else:
            datos = leer(ruta)
            _CACHE[ruta] = (mtime, time.monotonic(), dict(datos))
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        base.update(estado=ESTADO_ERROR, estado_es=ESTADO_ES[ESTADO_ERROR],
                    mensaje=("No se pudo leer el certificado, así que no se puede vigilar su "
                             "caducidad. Avise a Redes; el detalle queda en "
                             "los registros de la plataforma."))
        log.warning("no se pudo leer el certificado TLS", extra={"ruta": ruta, "error": str(exc)})
        return base
    base.update({k: datos.get(k) for k in ("sujeto", "emisor", "emisor_corto", "nombre_comun", "nombres")})
    fin = datos.get("not_after")
    base["not_after"] = fin.isoformat().replace("+00:00", "Z") if fin else None
    inicio = datos.get("not_before")
    base["not_before"] = inicio.isoformat().replace("+00:00", "Z") if inicio else None
    if fin is None:
        base.update(estado=ESTADO_ERROR, estado_es=ESTADO_ES[ESTADO_ERROR],
                    mensaje="El certificado no tiene fecha de caducidad legible.")
        return base
    restantes = (fin - ahora).days
    base["dias_restantes"] = restantes
    fecha = fin.strftime("%d/%m/%Y")
    if restantes < 0:
        base.update(estado=ESTADO_CADUCADO, estado_es=ESTADO_ES[ESTADO_CADUCADO],
                    mensaje=(f"El certificado de {base['nombre_comun']} caducó el {fecha}, hace "
                             f"{-restantes} día{'s' if restantes != -1 else ''}: los navegadores "
                             f"bloquean la entrada. Debe renovarse ya."))
    elif restantes <= aviso_dias:
        base.update(estado=ESTADO_POR_CADUCAR, estado_es=ESTADO_ES[ESTADO_POR_CADUCAR],
                    mensaje=(f"El certificado de {base['nombre_comun']} caduca el {fecha}, en "
                             f"{restantes} día{'s' if restantes != 1 else ''}. Servicios "
                             f"Tecnológicos debe pedir el nuevo a {base['emisor_corto']}, "
                             f"sustituirlo y recargar el servidor web; el cambio no corta el "
                             f"servicio."))
    else:
        base.update(estado=ESTADO_OK, estado_es=ESTADO_ES[ESTADO_OK],
                    mensaje=(f"Certificado de {base['nombre_comun']} emitido por "
                             f"{base['emisor_corto']}; caduca el {fecha}, en {restantes} días."))
    return base


def avisar(conn: sqlite3.Connection, *, cfg: Any, mailer: Any = None,
           ahora: Optional[datetime] = None) -> Optional[dict[str, Any]]:
    """Correo de administracion cuando el certificado esta por caducar o caducado.

    Uno por semana mientras dure la situacion (``admin_notices``, tipo ``tls_expiry``), con
    el asunto de accion requerida si ya caduco. Lo llama la ejecucion diaria junto a los
    avisos de salud. Devuelve el aviso enviado o None.
    """
    est = estado(cfg=cfg, ahora=ahora)
    if est["estado"] not in (ESTADO_POR_CADUCAR, ESTADO_CADUCADO):
        return None
    destinatarios = list(getattr(cfg, "admin_to", None) or [])
    if not destinatarios:
        log.warning("certificado por caducar y sin destinatarios de administracion")
        return None
    from .notify import Mailer, asunto_admin, render_admin_email
    mailer = mailer or Mailer(cfg)
    ahora = ahora or datetime.now(timezone.utc)
    silencio = 24 * 7
    limite = (ahora - timedelta(hours=silencio)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    clave = f"{est['nombre_comun']}|{est['not_after']}"
    ya = conn.execute(
        "SELECT 1 FROM admin_notices WHERE kind='tls_expiry' AND subject_key=? AND sent_at >= ? LIMIT 1",
        (clave, limite)).fetchone()
    if ya:
        return None
    caducado = est["estado"] == ESTADO_CADUCADO
    severidad = "critical" if caducado else "warning"
    titulo = ("El certificado HTTPS de la plataforma ha caducado" if caducado
              else f"El certificado HTTPS de la plataforma caduca en {est['dias_restantes']} días")
    html = render_admin_email(
        titulo=titulo, intro=est["mensaje"], severidad=severidad,
        secciones=[{"cabeceras": ["Dato", "Valor"],
                    "filas": [["Nombre", est["nombre_comun"] or "—"],
                              ["Emisor", est["emisor_corto"] or "—"],
                              ["Caduca", (est["not_after"] or "")[:10]],
                              ["Nombres que cubre", ", ".join(est["nombres"]) or "—"],
                              ["Quién lo renueva", "Redes"]]}],
        # Ni rutas, ni propietarios, ni permisos, ni ordenes del servidor (2026-09-15):
        # quien va a ejecutarlo ya tiene el procedimiento; este correo dice QUE hay que
        # conseguir y COMO se comprueba que quedo bien.
        acciones=["Pedir a Redes que solicite el certificado renovado al "
                  "emisor, con el mismo nombre y los mismos nombres alternativos.",
                  "Redes lo sustituye en el servidor y recarga el servidor "
                  "web: el cambio no corta el servicio ni cierra las sesiones abiertas.",
                  "Comprobar en Administración → Credenciales que los días restantes ya "
                  "reflejan el certificado nuevo."],
        pie="Este aviso se repite una vez por semana mientras el certificado siga por caducar.")
    if not mailer.send(subject=asunto_admin(titulo, severidad), html=html, to=destinatarios):
        log.error("no se pudo enviar el aviso de caducidad del certificado")
        return None
    # Se registra con la misma referencia temporal con la que se midio el silencio
    # (``ahora``), que en produccion es el instante actual.
    conn.execute(
        "INSERT OR IGNORE INTO admin_notices(kind, subject_key, sent_at, detail) VALUES(?,?,?,?)",
        ("tls_expiry", clave, ahora.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
         f"dias_restantes={est['dias_restantes']}"))
    log.info("aviso de caducidad del certificado enviado",
             extra={"dias_restantes": est["dias_restantes"], "nombre": est["nombre_comun"]})
    return {"kind": "tls_expiry", "titulo": titulo, "severidad": severidad,
            "dias_restantes": est["dias_restantes"]}
