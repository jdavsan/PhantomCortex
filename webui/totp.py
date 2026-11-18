"""Segundo factor de autenticacion: codigos temporales TOTP (RFC 6238) y codigos de
recuperacion. Sin dependencias externas salvo ``segno`` para el codigo QR en SVG.

Decisiones de seguridad
-----------------------
* El algoritmo es el estandar que entienden todas las aplicaciones de codigos
  (Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP, 1Password...):
  HMAC-SHA1, pasos de 30 segundos, 6 digitos, secreto de 160 bits en Base32.
  Se implementa con ``hmac``/``hashlib``/``struct``/``base64`` de la biblioteca
  estandar; no hace falta ninguna dependencia.
* El secreto TOTP se guarda EN CLARO en la columna ``users.totp_secret``. No es
  un descuido: el servidor necesita el secreto original para calcular el codigo
  esperado en cada verificacion, asi que no puede almacenarse como hash (a
  diferencia de la contrasena). Cifrarlo con una clave que vive en la misma
  maquina y el mismo proceso no anade seguridad real frente a quien ya lee la
  base de datos, solo complejidad. La proteccion efectiva es la del fichero
  ``data/threat_intel.db`` (propietario ``si``, permisos 600) y que la interfaz
  nunca lo vuelve a mostrar tras la activacion.
* Los codigos de recuperacion SI se guardan como hash bcrypt (``auth.hash_password``):
  son equivalentes a una contrasena de un solo uso y solo hay que compararlos.
* La comparacion de codigos usa ``hmac.compare_digest`` (tiempo constante) y se
  toleran espacios y guiones que el usuario copie de la aplicacion.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from typing import Optional
from urllib.parse import quote

from markupsafe import Markup

EMISOR = "Inteligencia de Amenazas"
PERIODO = 30
DIGITOS = 6
#: Alfabeto de los codigos de recuperacion: minusculas y digitos sin los caracteres
#: que se confunden al leerlos o dictarlos (i, l, o, 0, 1).
_ALFABETO_RECUPERACION = "abcdefghjkmnpqrstuvwxyz23456789"
RE_CODIGO_RECUPERACION = re.compile(r"^[a-z0-9]{5}-[a-z0-9]{5}$")
LONGITUD_MAXIMA_ENTRADA = 40


def generar_secreto() -> str:
    """Secreto Base32 de 160 bits para la aplicacion de codigos.

    20 bytes aleatorios producen exactamente 32 caracteres Base32, sin relleno."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _clave(secreto: str) -> bytes:
    limpio = re.sub(r"[\s\-]", "", secreto or "").upper()
    if not limpio:
        raise ValueError("secreto vacio")
    limpio += "=" * (-len(limpio) % 8)
    return base64.b32decode(limpio, casefold=True)


def paso_actual(instante: Optional[float] = None) -> int:
    """Numero de paso de 30 s en el que estamos (o en el instante dado)."""
    if instante is None:
        instante = time.time()
    return int(instante // PERIODO)


def codigo_en_paso(secreto: str, paso: int) -> str:
    """Codigo TOTP de 6 digitos para un paso concreto (RFC 4226 §5.3 sobre el paso)."""
    resumen = hmac.new(_clave(secreto), struct.pack(">Q", paso), hashlib.sha1).digest()
    desplazamiento = resumen[-1] & 0x0F
    valor = struct.unpack(">I", resumen[desplazamiento:desplazamiento + 4])[0] & 0x7FFFFFFF
    return str(valor % (10 ** DIGITOS)).zfill(DIGITOS)


def normalizar_codigo(codigo: str) -> str:
    """Quita espacios y guiones y pasa a minusculas; limita la longitud."""
    texto = (codigo or "").strip()[:LONGITUD_MAXIMA_ENTRADA]
    return re.sub(r"\s+", "", texto)


def paso_valido(secreto: str, codigo: str, *, ventana: int = 1,
                instante: Optional[float] = None) -> Optional[int]:
    """Devuelve el paso en el que el codigo es correcto (con tolerancia de
    ``ventana`` pasos hacia atras y hacia delante) o None si no lo es.

    Se recorren TODOS los pasos de la ventana aunque ya haya coincidencia, para
    que el tiempo de respuesta no dependa de la posicion del acierto."""
    limpio = normalizar_codigo(codigo).replace("-", "")
    if not limpio.isdigit() or len(limpio) != DIGITOS:
        return None
    try:
        centro = paso_actual(instante)
        candidatos = [centro + d for d in range(-abs(ventana), abs(ventana) + 1)]
        acierto: Optional[int] = None
        for paso in candidatos:
            if hmac.compare_digest(codigo_en_paso(secreto, paso), limpio):
                acierto = paso
        return acierto
    except (ValueError, TypeError):
        return None


def verificar(secreto: str, codigo: str, *, ventana: int = 1) -> bool:
    """Comprueba un codigo de 6 digitos con tolerancia de ``ventana`` pasos de 30 s."""
    return paso_valido(secreto, codigo, ventana=ventana) is not None


def uri(secreto: str, usuario: str, *, emisor: str = EMISOR) -> str:
    """otpauth://totp/... para la aplicacion de codigos."""
    etiqueta = quote(emisor, safe="") + ":" + quote(usuario or "", safe="@")
    return (f"otpauth://totp/{etiqueta}?secret={quote(secreto, safe='')}"
            f"&issuer={quote(emisor, safe='')}&algorithm=SHA1&digits={DIGITOS}&period={PERIODO}")


def qr_svg(texto: str, *, descripcion: str = "Código QR para la aplicación de códigos") -> Markup:
    """Codigo QR como SVG en linea (sin atributos style=, compatible con la CSP).

    Colores fijos (modulos negros sobre blanco) para que la camara del movil lo
    lea igual con tema claro u oscuro; ``role="img"`` y ``aria-label`` para los
    lectores de pantalla."""
    import segno

    svg = segno.make(texto, error="m").svg_inline(
        scale=4, border=2, dark="#000000", light="#ffffff", svgclass="qr", lineclass=None)
    if "style=" in svg:
        # segno no emite style= con estos parametros; si alguna version lo hiciera,
        # mejor no mostrar el QR (queda el secreto en texto) que romper la CSP.
        raise ValueError("el SVG generado contiene style=")
    etiqueta = descripcion.replace("&", "&amp;").replace('"', "&quot;")
    svg = svg.replace("<svg ", f'<svg role="img" aria-label="{etiqueta}" focusable="false" ', 1)
    return Markup(svg)


def codigos_recuperacion(n: int = 8) -> list[str]:
    """Codigos de un solo uso para entrar sin la aplicacion (formato xxxxx-xxxxx)."""
    salida: list[str] = []
    while len(salida) < n:
        bloque = "".join(secrets.choice(_ALFABETO_RECUPERACION) for _ in range(10))
        codigo = f"{bloque[:5]}-{bloque[5:]}"
        if codigo not in salida:
            salida.append(codigo)
    return salida


def normalizar_recuperacion(codigo: str) -> Optional[str]:
    """Devuelve el codigo de recuperacion en su forma canonica o None si no tiene
    el formato esperado (asi no se ejecuta bcrypt sobre entradas arbitrarias)."""
    limpio = normalizar_codigo(codigo).lower()
    if len(limpio) == 10 and "-" not in limpio:
        limpio = f"{limpio[:5]}-{limpio[5:]}"
    return limpio if RE_CODIGO_RECUPERACION.match(limpio) else None


def agrupar_secreto(secreto: str) -> str:
    """'GEZDGNBVGY3TQOJQ...' -> 'GEZD GNBV GY3T QOJQ ...' para copiarlo a mano."""
    limpio = (secreto or "").upper()
    return " ".join(limpio[i:i + 4] for i in range(0, len(limpio), 4))
