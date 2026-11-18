"""Logo de la organizacion: validacion y normalizacion de lo que se sube.

Se re-codifica siempre con Pillow; nunca se guardan los bytes tal cual que mando el
navegador. Asi una extension .png mentirosa no llega a abrirse como imagen en ningun
sitio (la interfaz, el informe Word), y cualquier metadato o payload fuera de los
pixeles desaparece al recomprimir. El resultado siempre es PNG, un solo formato que
tanto la plantilla HTML como python-docx saben mostrar sin mas conversiones.
"""
from __future__ import annotations

import io

MAX_BYTES_ENTRADA = 5 * 1024 * 1024   # 5 MB: generoso para lo que alguien sube a mano
LADO_MAXIMO = 1000                    # de sobra para portada de informe e icono de la interfaz
LADO_MAXIMO_ENTRADA = 6000            # por encima, se rechaza ANTES de descomprimir el pixel
FORMATOS_ADMITIDOS = {"PNG", "JPEG", "WEBP", "GIF", "BMP"}


class LogoInvalido(ValueError):
    """El fichero subido no sirve como logo; el mensaje es para mostrarlo tal cual."""


def normalizar(datos: bytes) -> tuple[bytes, str]:
    """Valida ``datos`` como imagen y devuelve (png_normalizado, 'image/png').

    Lanza ``LogoInvalido`` con un mensaje en español listo para mostrar si el fichero
    no es una imagen utilizable. Nunca lanza otra excepcion: cualquier fallo de Pillow
    se traduce aqui.
    """
    if not datos:
        raise LogoInvalido("el fichero está vacío.")
    if len(datos) > MAX_BYTES_ENTRADA:
        raise LogoInvalido(f"el fichero supera los {MAX_BYTES_ENTRADA // (1024 * 1024)} MB.")

    from PIL import Image, UnidentifiedImageError

    try:
        imagen = Image.open(io.BytesIO(datos))
        imagen.verify()
        # verify() deja la imagen inservible para seguir leyendola: se reabre.
        imagen = Image.open(io.BytesIO(datos))
        formato = imagen.format
        ancho, alto = imagen.size
    except Image.DecompressionBombError as exc:
        raise LogoInvalido("la imagen es demasiado grande (demasiados píxeles).") from exc
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError) as exc:
        raise LogoInvalido("el fichero no es una imagen válida.") from exc

    if formato not in FORMATOS_ADMITIDOS:
        raise LogoInvalido(
            f"formato {formato or 'desconocido'} no admitido; use PNG, JPEG o WEBP.")
    if ancho < 16 or alto < 16:
        raise LogoInvalido("la imagen es demasiado pequeña (mínimo 16×16 píxeles).")
    if max(ancho, alto) > LADO_MAXIMO_ENTRADA:
        raise LogoInvalido(
            f"la imagen es demasiado grande (más de {LADO_MAXIMO_ENTRADA} píxeles de lado).")

    try:
        imagen.load()
        if imagen.mode not in ("RGB", "RGBA"):
            imagen = imagen.convert("RGBA" if imagen.mode in ("RGBA", "LA", "P") else "RGB")
        if max(ancho, alto) > LADO_MAXIMO:
            factor = LADO_MAXIMO / max(ancho, alto)
            nuevo = (max(1, round(ancho * factor)), max(1, round(alto * factor)))
            imagen = imagen.resize(nuevo, Image.LANCZOS)
        salida = io.BytesIO()
        imagen.save(salida, format="PNG", optimize=True)
    except (OSError, ValueError) as exc:
        raise LogoInvalido("no se pudo procesar la imagen.") from exc

    return salida.getvalue(), "image/png"
