"""Filtros y utilidades de plantilla.

Las fechas se formatean en espanol sin depender del locale del sistema: bajo
cron el locale puede no estar configurado, y era una de las fragilidades del
sistema anterior.
"""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional

from markupsafe import Markup, escape

MESES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
         "agosto", "septiembre", "octubre", "noviembre", "diciembre"]

DIAS = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]

ETIQUETA_SEVERIDAD = {
    "Critical": "Crítica", "High": "Alta", "Medium": "Media", "Low": "Baja",
}

ETIQUETA_ORIGEN = {
    "nvd": "CVSS oficial (NVD)",
    "vector": "CVSS calculado del vector",
    "kev": "explotación confirmada (CISA KEV)",
    "heuristic": "severidad estimada",
}

ETIQUETA_VEREDICTO = {
    "affected": "versión afectada",
    "not_affected": "versión no afectada",
    "unknown": "sin determinar",
}

ETIQUETA_ESTADO = {
    "ok": "Operativa", "degradada": "Degradada", "caida": "Caída",
    "desactivada": "Desactivada",
}


def _parse(valor: Any) -> Optional[datetime]:
    if isinstance(valor, datetime):
        return valor
    if not valor:
        return None
    texto = str(valor).strip().replace("Z", "+00:00")
    for intento in (texto, texto[:19], texto[:10]):
        for formato in (None, "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return (datetime.fromisoformat(intento) if formato is None
                        else datetime.strptime(intento, formato))
            except (ValueError, TypeError):
                continue
    # Fechas RFC 2822 tal como llegan en los RSS: «Mon, 08 Jun 2026 19:47:39 +0530».
    # Sin esto, ~85 % de las fechas de publicacion se mostraban como «-».
    try:
        return parsedate_to_datetime(texto.replace("+00:00", "Z") if texto.endswith("+00:00") else texto)
    except (TypeError, ValueError, IndexError):
        return None


def _es_fecha_civil(dt: datetime) -> bool:
    """Medianoche UTC exacta sin peticion de hora: es una fecha de calendario
    (p. ej. el plazo de correccion de CISA KEV), no un instante. Convertirla a la
    zona local (UTC-5) la retrasaria un dia entero."""
    return (dt.tzinfo is not None and dt.utcoffset() == timezone.utc.utcoffset(None)
            and dt.hour == 0 and dt.minute == 0 and dt.second == 0)


def fecha_es(valor: Any, *, con_hora: bool = False) -> str:
    """'2026-09-02T14:30:00Z' -> '2 de septiembre de 2026'"""
    dt = _parse(valor)
    if dt is None:
        return "-"
    if dt.tzinfo is not None and not (not con_hora and _es_fecha_civil(dt)):
        dt = dt.astimezone()
    salida = f"{dt.day} de {MESES[dt.month - 1]} de {dt.year}"
    if con_hora:
        salida += f", {dt.strftime('%H:%M')}"
    return salida


def fecha_corta(valor: Any) -> str:
    dt = _parse(valor)
    if dt is None:
        return "-"
    if dt.tzinfo is not None:
        dt = dt.astimezone()
    return dt.strftime("%d/%m/%Y %H:%M")


def mes_es(month: Optional[str]) -> str:
    """'2026-08' -> 'agosto de 2026'"""
    if not month or "-" not in str(month):
        return str(month or "-")
    anio, mes = str(month).split("-")[:2]
    try:
        return f"{MESES[int(mes) - 1]} de {anio}"
    except (ValueError, IndexError):
        return str(month)


def hace(valor: Any) -> str:
    """Tiempo relativo en espanol: 'hace 3 horas'."""
    dt = _parse(valor)
    if dt is None:
        return "nunca"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    seg = int(delta.total_seconds())
    if seg < 0:
        return "en el futuro"
    if seg < 60:
        return "hace unos segundos"
    if seg < 3600:
        m = seg // 60
        return f"hace {m} minuto{'s' if m != 1 else ''}"
    if seg < 86400:
        h = seg // 3600
        return f"hace {h} hora{'s' if h != 1 else ''}"
    d = seg // 86400
    if d < 31:
        return f"hace {d} día{'s' if d != 1 else ''}"
    if d < 365:
        m = d // 30
        return f"hace {m} mes{'es' if m != 1 else ''}"
    a = d // 365
    return f"hace {a} año{'s' if a != 1 else ''}"


def cvss_es(valor: Any) -> str:
    """Nunca inventa un numero: si no hay dato, lo dice."""
    if valor is None or valor == "":
        return "no disponible"
    try:
        return f"{float(valor):.1f}/10.0"
    except (TypeError, ValueError):
        return "no disponible"


def epss_es(valor: Any) -> str:
    if valor is None or valor == "":
        return "no disponible"
    try:
        return f"{float(valor) * 100:.1f}%"
    except (TypeError, ValueError):
        return "no disponible"


def severidad_es(valor: Any) -> str:
    return ETIQUETA_SEVERIDAD.get(str(valor), str(valor or "-"))


def origen_es(valor: Any) -> str:
    return ETIQUETA_ORIGEN.get(str(valor), str(valor or "-"))


def veredicto_es(valor: Any) -> str:
    return ETIQUETA_VEREDICTO.get(str(valor), "sin determinar")


def estado_es(valor: Any) -> str:
    return ETIQUETA_ESTADO.get(str(valor), str(valor or "-"))


def estado_amenaza_es(valor: Any) -> str:
    """Estado operativo de una amenaza en español ('en_analisis' -> 'En análisis')."""
    from threatintel.queries import ESTADO_ES
    return ESTADO_ES.get(str(valor or "nueva"), str(valor or "Nueva"))


def motivo_no_alerta_es(valor: Any) -> str:
    """Frase para alert_skip_reason ('relevancia_baja' -> 'No se alertó: relevancia…')."""
    from threatintel.queries import MOTIVO_EXCLUSION_ES
    if not valor:
        return ""
    texto = MOTIVO_EXCLUSION_ES.get(str(valor), str(valor).replace("_", " "))
    return "No se alertó: " + texto


def numero(valor: Any) -> str:
    try:
        return f"{int(valor):,}".replace(",", ".")
    except (TypeError, ValueError):
        return "0"


def tamano(bytes_: Any) -> str:
    try:
        n = float(bytes_)
    except (TypeError, ValueError):
        return "-"
    for unidad in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unidad}" if unidad == "B" else f"{n:.1f} {unidad}"
        n /= 1024
    return f"{n:.1f} PB"


def _cortar_por_palabra(texto: str, largo: int) -> str:
    """Recorta sin partir una palabra por la mitad.

    Si la última palabra no cabe entera se descarta, salvo cuando el resultado
    quedaría por debajo de la mitad del largo pedido (una palabra muy larga, como
    el nombre de un paquete): en ese caso se corta por caracteres, porque dejar
    tres letras informa menos que un corte duro.
    """
    if len(texto) <= largo:
        return texto
    duro = texto[:largo].rstrip()
    corte = duro.rfind(" ")
    if corte >= largo // 2:
        return duro[:corte].rstrip(" ,;:.-")
    return duro


def recortar(texto: Any, largo: int = 120) -> str:
    """Recorta a ``largo`` caracteres y deja el texto COMPLETO en el título emergente.

    Revisión de claridad del 2026-09-15: el recorte dejaba descripciones de fuentes
    y errores de sincronización cortados justo donde estaba la causa, sin ninguna
    manera de leer el resto. Ahora se corta por palabra y, cuando se ha recortado
    algo, el texto entero viaja en el atributo ``title`` del elemento, que el
    navegador muestra al pasar el ratón y los lectores de pantalla anuncian. El
    resultado es Markup ya escapado: Jinja2 no lo vuelve a escapar y no hace falta
    ninguna clase nueva en la hoja de estilos.
    """
    s = str(texto or "")
    if len(s) <= largo:
        return s
    corto = _cortar_por_palabra(s, largo - 1)
    return Markup('<span title="{completo}">{corto}…</span>').format(
        completo=s, corto=corto)


# --------------------------------------------------------------------------
# Auditoría y credenciales en español (revisión de claridad del 2026-09-15)
# --------------------------------------------------------------------------
# Las tablas de Auditoría y de Credenciales enseñaban el código interno de cada
# acción («login.2fa.ok», «nvd.verificar») y el detalle tal como lo escribió el
# código («usuario=… rol=admin», «ok=True», «anterior=OP*****»). Aquí se traduce a
# frases; el código original se conserva en el título emergente de la celda, que es
# lo que sirve para buscar en los registros del servidor.

#: Acción de auditoría -> frase en español. Las claves son las que escribe ``db.audit``.
ACCION_ES = {
    "login.ok": "Acceso correcto",
    "login.fallo": "Intento de acceso fallido",
    "login.password_ok": "Contraseña correcta, falta el segundo factor",
    "login.2fa.ok": "Segundo factor correcto",
    "login.2fa.fallo": "Segundo factor incorrecto",
    "logout": "Cierre de sesión",
    "sesion.unica": "Sesión anterior cerrada por un acceso nuevo",
    "sesion.caducada": "Sesión caducada por inactividad",
    "2fa.activar": "Segundo factor activado",
    "2fa.activar.inicio": "Segundo factor: inicio de la activación",
    "2fa.desactivar": "Segundo factor desactivado",
    "password.cambio_obligatorio": "Cambio obligatorio de contraseña",
    "usuario.crear": "Usuario creado",
    "usuario.editar": "Perfil o estado del usuario cambiados",
    "usuario.actualizar": "Datos del usuario actualizados",
    "usuario.eliminar": "Usuario eliminado",
    "usuario.password": "Contraseña cambiada por su titular",
    "usuario.restablecer": "Contraseña restablecida por un administrador",
    "usuario.restablecer_2fa": "Segundo factor restablecido por un administrador",
    "usuario.desbloquear": "Cuenta desbloqueada",
    "usuario.nombre": "Nombre de la persona actualizado",
    "usuario.renombrar": "Correo de acceso cambiado",
    "ajustes.guardar": "Ajustes guardados",
    "ajustes.cambio": "Ajustes cambiados",
    "ajustes.cambiado": "Ajuste cambiado",
    "ajustes.restaurar": "Ajustes restaurados a sus valores por defecto",
    "smtp.rotar": "Contraseña del servidor de correo renovada",
    "smtp.verificar": "Contraseña del servidor de correo verificada",
    "smtp.prueba": "Correo de prueba enviado",
    "destinatarios.guardar": "Destinatarios de los correos guardados",
    "nvd.guardar": "Clave de la base de datos nacional de vulnerabilidades guardada",
    "nvd.verificar": "Clave de la base de datos nacional de vulnerabilidades verificada",
    "nvd.quitar": "Clave de la base de datos nacional de vulnerabilidades retirada",
    "fuente.probar": "Fuente probada en vivo",
    "fuente.probar_todas": "Todas las fuentes probadas en vivo",
    "fuentes.crear": "Fuente dada de alta",
    "fuente.borrar": "Fuente eliminada",
    "fuente.deduplicar": "Fuentes repetidas desactivadas",
    "source.create": "Fuente dada de alta",
    "tecnologia.crear": "Tecnología del inventario creada",
    "tecnologia.borrar": "Tecnología del inventario eliminada",
    "tecnologia.version": "Versión instalada de una tecnología actualizada",
    "tecnologia.detectar_versiones": "Versiones detectadas en un activo",
    "ocs.sincronizar": "Inventario sincronizado con OCS Inventory",
    "remediacion.comprobar": "Remediación comprobada contra el inventario",
    "remediacion.sincronizar": "Cola de remediación sincronizada",
    "remediacion.nota": "Nota añadida a una remediación",
    "parches.buscar": "Búsqueda de correcciones pendientes",
    "parches.sincronizar": "Seguimiento de correcciones sincronizado",
    "descripcion.completada": "Descripción de una vulnerabilidad completada",
    "descripcion.sin_dato": "Descripción no publicada por ninguna fuente",
    "traduccion.reparar": "Traducciones revisadas",
    "amenazas.recorrelacionar": "Amenazas vueltas a correlacionar con el inventario",
    "inventario.consolidar": "Inventario de tecnologías consolidado",
    "excepcion.crear": "Excepción de riesgo registrada",
    "excepcion.revocar": "Excepción de riesgo revocada",
    "excepcion.revisar": "Revisión de una excepción confirmada",
    "informe.generar": "Informe generado",
}

#: Entidad sobre la que recae la acción, en singular y en español.
ENTIDAD_ES = {
    "users": "Usuario", "usuarios": "Usuario",
    "sources": "Fuente", "fuentes": "Fuente",
    "technologies": "Tecnología", "tech_aliases": "Alias de tecnología",
    "threats": "Amenaza", "settings": "Ajuste",
    "credentials": "Credencial", "credentials_meta": "Credencial",
    "web_sessions": "Sesión", "activos": "Activo",
    "remediaciones": "Remediación", "parches_pendientes": "Corrección pendiente",
    "excepciones": "Excepción",
}

#: Tipo de aviso de administración -> frase en español (tabla ``admin_notices``).
AVISO_ES = {
    "smtp_rotacion": "Contraseña del correo por caducar",
    "smtp_fallo": "Fallo al enviar correo",
    "tls_expiry": "Certificado HTTPS por caducar",
    "fuente_caida": "Fuente de consulta caída",
    "ejecucion_fallida": "Ejecución diaria fallida",
    "excepciones_vencimiento": "Excepciones de riesgo por vencer",
    "sin_evaluar": "Vulnerabilidades sin evaluar contra el inventario",
}

#: Trozos «clave=valor» del detalle de auditoría que se leen mejor traducidos.
_DETALLE_CLAVES = {
    "usuario": "usuario", "rol": "perfil", "nombre": "nombre",
    "habilitado": "habilitado", "sesiones_revocadas": "sesiones cerradas",
    "verificada": "verificada", "ok": "resultado", "dias": "días",
    "revisadas": "revisadas", "cambiadas": "cambiadas", "host": "activo",
    "actualizadas": "actualizadas", "version": "versión",
    "anterior": "valor anterior", "nueva": "valor nuevo",
    "dias_restantes": "días restantes", "estado": "estado",
    "excepcion": "excepción", "vence_at": "vence el",
}

_DETALLE_VALORES = {
    "true": "sí", "false": "no", "True": "sí", "False": "no",
    "admin": "Administrador", "ciberseguridad": "Ciberseguridad",
    "redes": "Redes", "mantenimiento": "Mantenimiento",
    # Roles retirados (2026-09-xx, de 6 a 4 perfiles): se conservan solo para traducir
    # cambios de rol YA REGISTRADOS en auditorías de instalaciones anteriores a la
    # migración; ningún usuario nuevo puede tener estos valores.
    "operador_soc": "Operador SOC (retirado)",
    "servicios_tecnologicos": "Redes (retirado)",
    "viewer": "Solo lectura (retirado)",
}

#: Claves cuyo 1 o 0 es un sí o un no, y no un recuento («sesiones_revocadas=0» son
#: cero sesiones, no un «no»).
_CLAVES_SI_NO = ("habilitado", "activa", "activo", "ok", "verificada", "enabled")

#: Claves cuyo valor es un secreto: se enmascara ENTERO, desde el primer carácter.
_CLAVES_SECRETAS = ("anterior", "nueva", "clave", "password", "contrasena",
                    "contraseña", "secreto", "token", "api_key")


def accion_es(valor: Any) -> str:
    """'login.2fa.ok' -> 'Segundo factor correcto'. Si no se conoce, se lee el código."""
    clave = str(valor or "").strip()
    if not clave:
        return "—"
    if clave in ACCION_ES:
        return ACCION_ES[clave]
    # Códigos puntuales de una tarea de mantenimiento: se leen sin puntos ni guiones
    # bajos en lugar de enseñar el identificador crudo.
    legible = clave.replace(".", " · ").replace("_", " ")
    return legible[0].upper() + legible[1:]


def entidad_es(entidad: Any, identificador: Any = None) -> str:
    """'users' + 106 -> 'Usuario n.º 106'; 'users' + correo -> 'Usuario juan@…'."""
    nombre = ENTIDAD_ES.get(str(entidad or ""), str(entidad or "").strip())
    if not nombre:
        return "—"
    ident = str(identificador if identificador is not None else "").strip()
    if not ident:
        return nombre
    return f"{nombre} n.º {ident}" if ident.isdigit() else f"{nombre} {ident}"


def aviso_es(valor: Any) -> str:
    """'smtp_rotacion' -> 'Contraseña del correo por caducar'."""
    clave = str(valor or "").strip()
    if not clave:
        return "—"
    if clave in AVISO_ES:
        return AVISO_ES[clave]
    legible = clave.replace("_", " ")
    return legible[0].upper() + legible[1:]


def enmascarar(valor: Any, visibles: int = 0) -> str:
    """Oculta un secreto DESDE EL PRIMER carácter.

    La página de Credenciales mostraba «anterior=OP***** nueva=85*****»: dos
    caracteres reales de cada clave, que es justo lo que no debe salir de la
    plataforma. Con ``visibles=0`` (lo normal) no se ve ninguno y solo se dice
    cuántos caracteres tenía, que es el único dato útil para comprobar que se pegó
    la clave entera.
    """
    texto = str(valor or "").strip()
    if not texto:
        return "sin valor"
    visibles = max(0, int(visibles or 0))
    if visibles:
        return texto[:visibles] + "•" * max(1, len(texto) - visibles)
    return "•" * min(len(texto), 12) + f" ({len(texto)} caracteres)"


def _valor_detalle(clave: str, valor: str) -> str:
    if clave.lower() in _CLAVES_SECRETAS:
        return enmascarar(valor)
    limpio = valor.strip().strip("«»")
    if limpio == "":
        return "vacío"
    if clave.lower() == "ok":
        return {"true": "correcto", "True": "correcto",
                "false": "fallido", "False": "fallido"}.get(limpio, valor.strip())
    if clave.lower() in _CLAVES_SI_NO and limpio in ("0", "1"):
        return "sí" if limpio == "1" else "no"
    return _DETALLE_VALORES.get(limpio, valor.strip())


def _etiquetas_de_ajuste() -> dict:
    """{clave interna del ajuste: etiqueta visible en la pantalla de Ajustes}.

    Se lee de la misma estructura que pinta la pantalla, así que no puede quedar
    desfasada. La importación es perezosa para no crear un ciclo entre los filtros y
    las vistas.
    """
    global _ETIQUETAS_AJUSTE
    if _ETIQUETAS_AJUSTE is None:
        try:
            from webui.vistas.ajustes import GRUPOS
            _ETIQUETAS_AJUSTE = {clave: etiqueta
                                 for _, items in GRUPOS
                                 for clave, etiqueta, _tipo, _ayuda in items}
        except Exception:  # noqa: BLE001 - sin las vistas se deja el código tal cual
            _ETIQUETAS_AJUSTE = {}
    return _ETIQUETAS_AJUSTE


_ETIQUETAS_AJUSTE = None


def ajuste_es(valor: Any) -> str:
    """'alert_min_relevance' -> 'Relevancia mínima para alertar (0-100)'."""
    clave = str(valor or "").strip()
    return _etiquetas_de_ajuste().get(clave, clave or "—")


def detalle_es(valor: Any) -> str:
    """Traduce los trozos «clave=valor» del detalle de auditoría a español.

    No inventa nada: lo que no reconoce se deja tal cual, porque el detalle también
    lleva frases ya redactadas. Los valores de claves secretas se enmascaran.
    """
    texto = str(valor or "").strip()
    if not texto:
        return "—"
    etiquetas = _etiquetas_de_ajuste()
    partes = []
    for trozo in texto.split(" "):
        # «alert_kev_sin_activos: true -> false»: la clave interna del ajuste se
        # sustituye por la etiqueta que se lee en la pantalla de Ajustes.
        if trozo.rstrip(":") in etiquetas:
            partes.append("«" + etiquetas[trozo.rstrip(":")] + "»"
                          + (":" if trozo.endswith(":") else ""))
            continue
        if "=" in trozo and not trozo.startswith("="):
            clave, _, resto = trozo.partition("=")
            if clave and clave.replace("_", "").isalpha():
                etiqueta = _DETALLE_CLAVES.get(clave.lower(), clave.replace("_", " "))
                partes.append(f"{etiqueta}: {_valor_detalle(clave, resto)}")
                continue
        # Valores sueltos de un cambio de ajuste: «true -> false» se lee «sí pasó a no».
        partes.append(_DETALLE_VALORES.get(trozo, trozo))
    salida = " ".join(partes)
    return salida.replace(" -> ", " pasó a ").replace("→", "pasó a")


# --------------------------------------------------------------------------
# Errores del motor de base de datos, traducidos a causa y remedio
# --------------------------------------------------------------------------
#: (marca que aparece en el error, causa en español, qué hacer).
_ERRORES_BASE_DATOS: tuple[tuple[str, str, str], ...] = (
    ("2003", "No se pudo abrir la conexión con el servidor de inventario.",
     "El servidor de inventario no respondió: puede estar apagado, reiniciándose o "
     "inalcanzable desde la red. El inventario anterior se conserva y la consulta se "
     "repite en la siguiente ejecución programada."),
    ("2013", "La conexión con el servidor de inventario se cortó a mitad de la consulta.",
     "Suele ocurrir cuando la consulta tarda más de lo que el servidor de inventario "
     "admite, o cuando hay un corte de red. No se ha perdido nada: se conserva el "
     "inventario de la última consulta correcta y se vuelve a intentar."),
    ("2006", "El servidor de inventario cerró la conexión antes de terminar.",
     "El servidor de inventario cerró la sesión por inactividad o se reinició durante "
     "la consulta. Se vuelve a intentar en la siguiente ejecución programada."),
    ("1045", "El servidor de inventario no aceptó el usuario de consulta.",
     "La credencial de solo lectura ya no sirve. Hay que pedir a quien administra el "
     "inventario que la restablezca; mientras tanto no se puede refrescar el inventario."),
    ("1044", "El usuario de consulta no tiene permiso sobre esa base de datos.",
     "Hace falta permiso de solo lectura sobre la base del inventario. Pídalo a quien "
     "administra el inventario."),
    ("1142", "El usuario de consulta no tiene permiso sobre esa tabla.",
     "Hace falta permiso de solo lectura sobre las tablas del inventario. Pídalo a "
     "quien administra el inventario."),
    ("1049", "La base de datos de inventario indicada no existe.",
     "El nombre de la base ha cambiado o se escribió mal. Revíselo con quien "
     "administra el inventario."),
    ("Name or service not known", "El nombre del servidor de inventario no se pudo resolver.",
     "El nombre no existe en el servicio de nombres o está mal escrito. Revíselo con "
     "quien administra la red."),
    ("timed out", "La consulta al inventario agotó el tiempo de espera.",
     "El servidor de inventario tardó más de lo admitido en responder. Se vuelve a "
     "intentar en la siguiente ejecución programada."),
)

_ERROR_GENERICO = ("La consulta al servidor de inventario terminó con un error.",
                   "El inventario anterior se conserva y la consulta se repite en la "
                   "siguiente ejecución programada. Si se repite varios días, avise a "
                   "quien administra el inventario con el detalle técnico.")


def error_consulta_es(valor: Any) -> str:
    """Error crudo del motor de base de datos -> causa, qué hacer y detalle plegado.

    La página de Consultas a OCS Inventory enseñaba el texto tal cual («OperationalError:
    (2013, 'Lost connection to MySQL server…')»), que no dice a nadie qué pasó ni qué
    hacer. Aquí se traduce y el original queda dentro de un desplegable «Detalle
    técnico», que es lo que hace falta para buscar en los registros del servidor.
    """
    texto = str(valor or "").strip()
    if not texto:
        return Markup('<span>Falló sin dejar ningún detalle.</span>')
    causa, remedio = _ERROR_GENERICO
    for marca, causa_es, remedio_es in _ERRORES_BASE_DATOS:
        if marca.lower() in texto.lower():
            causa, remedio = causa_es, remedio_es
            break
    return Markup(
        '<strong>{causa}</strong> <span>{remedio}</span>'
        '<details><summary>Detalle técnico</summary><span>{original}</span></details>'
    ).format(causa=causa, remedio=remedio, original=texto)


# Esquemas admitidos en un enlace. El autoescape de Jinja2 escapa caracteres
# pero NO valida el esquema: un href="javascript:..." procedente de una fuente
# RSS llegaria intacto al navegador del operador. Verificado el 2026-09-03 en
# /amenazas/<id>, donde la URL viene de threat_sources.url.
_ESQUEMAS_SEGUROS = ("http://", "https://", "mailto:")


def url_segura(valor: Any) -> str:
    """Devuelve la URL solo si su esquema es admisible; si no, cadena vacia."""
    import re as _re
    texto = str(valor or "").strip()
    if not texto:
        return ""
    texto = _re.sub(r"[\x00-\x20\x7f]", "", texto)
    return texto if texto.lower().startswith(_ESQUEMAS_SEGUROS) else ""


def celda_csv(valor: Any) -> str:
    """Neutraliza la inyeccion de formulas en CSV (A05:2025).

    Excel, LibreOffice y Google Sheets ejecutan celdas que empiezan por = + - @
    (y tambien por tabulador o retorno de carro). Verificado el 2026-09-03: un
    titulo de amenaza `=cmd|'/c calc'!A0` procedente de un feed llegaba tal cual
    a la exportacion. Se antepone un apostrofo, que las hojas de calculo
    interpretan como "tratar como texto" y no muestran.
    """
    texto = "" if valor is None else str(valor)
    if texto and texto[0] in "=+-@\t\r":
        # Un numero negativo legitimo ("-3") no debe alterarse
        import re as _re
        if _re.match(r"^-\d+(\.\d+)?$", texto):
            return texto
        return "'" + texto
    return texto


def registrar_filtros(app) -> None:
    for nombre, funcion in {
        "fecha_es": fecha_es, "fecha_corta": fecha_corta, "mes_es": mes_es,
        "hace": hace, "cvss_es": cvss_es, "epss_es": epss_es,
        "severidad_es": severidad_es, "origen_es": origen_es,
        "veredicto_es": veredicto_es, "estado_es": estado_es,
        "estado_amenaza_es": estado_amenaza_es, "motivo_no_alerta_es": motivo_no_alerta_es,
        "numero": numero, "tamano": tamano, "recortar": recortar,
        "url_segura": url_segura,
        # Revisión de claridad del 2026-09-15: códigos internos traducidos.
        "accion_es": accion_es, "entidad_es": entidad_es, "aviso_es": aviso_es,
        "detalle_es": detalle_es, "enmascarar": enmascarar, "ajuste_es": ajuste_es,
        "error_consulta_es": error_consulta_es,
    }.items():
        app.jinja_env.filters[nombre] = funcion
    # Modulo de graficos SVG como global de plantilla: {{ graficos.dona(...) }}.
    # Sus funciones devuelven Markup ya escapado, por lo que Jinja no lo vuelve
    # a escapar (rediseno 2026-09-03, seccion 5 de docs/DISENO_INTERFAZ).
    from webui import graficos
    app.jinja_env.globals["graficos"] = graficos
