"""Ajustes de comportamiento del sistema.

Cada ajuste que se muestra aqui lo lee el codigo de verdad: no hay ninguno decorativo.
La etiqueta de cada uno es su NOMBRE en toda la plataforma (paginas, correos e informes
citan esa etiqueta y su ruta de menu, nunca la clave interna), y la ayuda dice solo el
efecto y el valor recomendado. El historial de cada decision vive en docs/, no aqui
(revision de claridad del 2026-09-15).
"""
from __future__ import annotations

import json
import re

from flask import (Blueprint, Response, abort, current_app, flash, g, redirect,
                   render_template, request, url_for)

from threatintel import config, db, marca
from webui import auth

bp = Blueprint("ajustes", __name__, url_prefix="/ajustes")

# Solo se exponen los ajustes que el codigo consume de verdad, agrupados para
# que el operador entienda el efecto de cada uno.
GRUPOS = [
    ("Alertas diarias", [
        ("alert_enabled", "Enviar alertas", "bool",
         "Si se desactiva, la recolección sigue pero no se envía correo."),
        ("alert_min_relevance", "Relevancia mínima para alertar (0-100)", "int",
         "KEV alerta siempre. Con 50, en julio-agosto se habrían enviado 17-19 alertas "
         "al mes en lugar de 300. La relevancia combina la severidad técnica con la "
         "criticidad, la exposición y la versión instalada de las tecnologías afectadas."),
        ("alert_require_identifier", "Exigir CVE o identificador de aviso", "bool",
         "Sin CVE ni identificador de aviso (DSA, USN, RHSA…) la entrada es una noticia "
         "o un artículo, no una vulnerabilidad concreta, y no se alerta: eran 2.693 de "
         "las alertas enviadas hasta septiembre. Las KEV alertan siempre."),
        ("alert_defer_heuristic_hours", "Horas de espera con severidad estimada", "int",
         "Si la severidad se estimó por el texto (sin CVSS oficial), se espera este "
         "tiempo a que NVD publique la puntuación antes de decidir. El 23 % de las "
         "estimadas acabaron por debajo de Alta. Con 0 no se espera."),
        ("alert_min_match_confidence", "Confianza mínima de una coincidencia (0-1)", "decimal",
         "Por debajo, la coincidencia con el inventario cuenta como simple mención y no "
         "suma relevancia. Con 0,6 dejan de contar las 5.150 coincidencias por la palabra "
         "suelta «windows», «chrome» o «edge» en noticias. Al cambiarlo, la relevancia se "
         "recalcula en la siguiente ejecución diaria."),
        ("ignore_low_severity", "Ignorar la severidad baja", "bool",
         "Activo es lo recomendado: la severidad Baja deja de contar en toda la plataforma "
         "(alertas, resumen semanal, informe mensual, cifras, gráficas, remediación y sus "
         "descargas). Se sigue evaluando y guardando en silencio, así que si una sube de "
         "severidad conserva su fecha de detección real. Al desactivarlo vuelve a contarse en "
         "el acto, sin ninguna migración. Una vulnerabilidad con explotación activa confirmada "
         "alerta igualmente, sea cual sea su puntuación."),
        ("ignore_low_criticality", "Ignorar tecnologías de criticidad baja", "bool",
         "Las coincidencias con tecnologías de criticidad baja del inventario cuentan como "
         "simple mención: no suman relevancia ni figuran como afectadas. Al cambiarlo, la "
         "relevancia se recalcula en la siguiente ejecución diaria. Activo es lo recomendado."),
        ("alert_skip_without_assets", "No alertar si ningún activo tiene la versión vulnerable", "bool",
         "Cuando la evaluación contra OCS Inventory demuestra que todos los activos ya llevan la "
         "corrección (o que la distribución no está afectada), la amenaza se excluye de la alerta y "
         "pasa al resumen semanal, aunque el texto mencione una tecnología del inventario."),
        ("alert_solo_con_activos_afectados",
         "Alertar solo lo que se confirma en alguna máquina del inventario", "bool",
         "Activo es lo recomendado: solo se alerta una vulnerabilidad cuando al menos un activo "
         "presente en OCS Inventory tiene confirmada la versión vulnerable. Lo excluido no se "
         "pierde: queda pendiente y consultable con su motivo, se vuelve a valorar cada día, "
         "entra en el resumen semanal y se alerta en cuanto la evaluación confirme un activo. "
         "Si la evaluación todavía no ha llegado a una vulnerabilidad, o falla, se alerta "
         "igualmente: un fallo propio no puede silenciar nada."),
        ("alert_kev_sin_activos",
         "Alertar la explotación activa (KEV) aunque no se confirme ningún activo", "bool",
         "Desactivado es lo recomendado: la explotación activa confirmada por CISA se filtra "
         "igual que el resto, así que sin ninguna máquina con la versión vulnerable no entra "
         "en el correo diario; queda pendiente con su motivo, entra en el resumen semanal y se "
         "alerta en cuanto la evaluación confirme un activo. Si se activa, esas "
         "vulnerabilidades vuelven al correo sin afectación confirmada y el propio correo lo "
         "advierte, porque la ausencia puede ser real o un fallo de la evaluación. En ambos "
         "casos, si la plataforma no consigue evaluar una candidata a alertar, envía un aviso "
         "de administración con la lista y el motivo."),
        ("excepciones_aviso_dias", "Días de antelación del aviso de excepciones por vencer", "int",
         "Con cuántos días de antelación avisa el correo diario de administración de las "
         "excepciones de riesgo que están a punto de vencer y de las que ya vencieron sin "
         "decisión. Mientras una excepción está vigente su vulnerabilidad no cuenta en la cola "
         "de remediación ni en las cifras; al vencer vuelve sola. Cada excepción entra en un "
         "correo como mucho una vez por semana, así que subir el número no multiplica los "
         "correos. Valor recomendado: 15. Admite de 1 a 120 días."),
        ("excepciones_revision_dias", "Días entre revisiones de una excepción permanente", "int",
         "Una excepción permanente acepta el riesgo sin fecha de vencimiento, así que nada la "
         "devuelve sola a la cola de trabajo. Pasados estos días desde su registro o desde la "
         "última revisión confirmada, entra en el correo diario de administración y sube al "
         "principio de la página de Excepciones para que alguien confirme que sigue siendo "
         "válida o la revoque. Es un recordatorio, no un vencimiento: la excepción sigue "
         "vigente aunque nadie conteste. Valor recomendado: 180, que son dos revisiones al "
         "año. Admite de 30 a 730 días y no se puede desactivar."),
        ("alert_procesos_enabled", "Enviar alertas por proceso de negocio", "bool",
         "Cada proceso configurado en Administración → Alertas por proceso recibe su propio correo con "
         "solo sus servidores afectados, además del correo general. Este interruptor apaga todas; cada "
         "proceso se activa o desactiva por separado en su página."),
        ("alert_send_when_empty", "Enviar el correo diario aunque no haya novedades", "bool",
         "Un correo breve que confirma que la recolección se hizo, cuántas amenazas se excluyeron y "
         "el estado de los activos. Si se desactiva, los días sin hallazgos no llega ningún correo."),
        ("alert_max_items", "Amenazas detalladas por correo", "int",
         "El resto se resume. Evita correos interminables."),
        ("alert_tabla_top", "Vulnerabilidades en la tabla del correo diario", "int",
         "Cuántas filas tiene la tabla «Prioridad de actuación» del correo de alertamiento "
         "diario: las de mayor relevancia del día. El correo dice siempre cuántas quedan "
         "fuera y dónde verlas, en la hoja de cálculo adjunta y en la plataforma, y la "
         "cabecera sigue dando el total del día. Con 10 el correo se lee en una pantalla; "
         "subirlo lo alarga sin añadir información, porque todas están en la hoja de "
         "cálculo. «Amenazas detalladas por correo» sigue siendo el tope de seguridad: si "
         "es menor que este número, manda él."),
        ("alert_detalle_top", "Vulnerabilidades con detalle completo en el correo", "int",
         "Cuántas se explican por extenso (descripción, impacto, remediación y activos afectados) al "
         "principio del correo. Las demás van en la tabla de prioridad y en la hoja de cálculo adjunta. "
         "Con 3 el correo se lee en un minuto."),
        ("alert_adjuntar_excel", "Adjuntar la hoja de cálculo al correo", "bool",
         "Un libro con una pestaña por vulnerabilidad y todos sus detalles (identificadores, puntuaciones, "
         "tecnologías, activos afectados con versión instalada y corregida, impacto y remediación), más una "
         "pestaña de resumen. Sirve para repartir el trabajo sin entrar en la plataforma."),
        ("alert_excel_max_activos", "Activos por pestaña en la hoja de cálculo", "int",
         "Límite de filas de activos que se escriben en cada pestaña. El resto se consulta en la plataforma."),
        ("alert_only_affected_versions", "Excluir versiones no afectadas", "bool",
         "Descarta las amenazas cuya versión instalada no es vulnerable. Reduce el ruido, "
         "pero exige tener las versiones del inventario al día: con versiones viejas se "
         "descartaría algo que sí afecta. Valor recomendado: desactivado."),
        # La opción «Baja» se retiró el 2026-09-15: era el único desplegable de la
        # plataforma que nombraba esa severidad fuera de la ayuda de su propio ajuste.
        ("alert_min_severity", "Severidad mínima (criterio anterior)", "opcion:Critical,High,Medium",
         "No decide qué se alerta: eso lo decide la relevancia. Se conserva porque la tarjeta "
         "«Pendientes de alertar» del panel y la comparación entre el criterio actual y el "
         "anterior siguen midiéndose con ella. Valor recomendado: Alta."),
    ]),
    ("Activos e inventario real (OCS Inventory)", [
        ("ocs_sync_enabled", "Sincronizar OCS Inventory en la ejecución diaria", "bool",
         "Lee las dos bases de OCS Inventory (la de servidores y la de equipos de cómputo) con "
         "un usuario que solo puede leer, y actualiza la página Activos. También se puede "
         "lanzar a mano con «Actualizar inventario ahora», en Activos."),
        ("ocs_stale_days", "Días sin inventario para considerar un activo «sin reportar»", "int",
         "Un activo que no envía inventario en este plazo aparece como activo ciego: no se "
         "puede saber qué tiene instalado. Valor recomendado: 30 días."),
        ("ocs_update_inventory", "Rellenar el inventario de tecnologías desde OCS", "bool",
         "Número de sistemas y versión instalada (la más antigua, el peor caso) de cada tecnología "
         "con software mapeado. Si se desactiva, esos campos siguen siendo manuales."),
        ("ocs_dmz_networks", "Redes de la zona perimetral (DMZ)", "lista",
         "CIDR separados por comas (10.0.5.0/24). Un activo con IP en estas redes se marca como DMZ."),
        ("ocs_internet_networks", "Redes expuestas a Internet", "lista",
         "CIDR de los activos alcanzables desde Internet. Se usan para la zona del activo."),
        ("ocs_procesos_alias", "Etiquetas de OCS que son el mismo proceso", "lista",
         "Una línea por cada equivalencia, con el formato «etiqueta = proceso». Sirve cuando el "
         "campo TAG de OCS usa varios nombres para un mismo proceso de negocio: por ejemplo «admin = Administración técnica». Ya vienen agrupadas «admin», «administracion» y «proxmox»/«pve» en «Administración técnica»; lo que se escriba aquí tiene prioridad. El cambio se aplica en la siguiente sincronización con OCS y se refleja en la plataforma, los correos y los informes."),
        ("ocs_risk_software", "Software de riesgo en puestos de trabajo", "lista",
         "Prefijos del nombre de programa que generan un hallazgo por activo (TightVNC, DWAgent, "
         "Java 7…). Se comparan en minúsculas con el nombre que informa OCS."),
        ("descripcion_completar", "Completar las descripciones de relleno", "bool",
         "Algunas fuentes envían un texto genérico («Información publicada.») en lugar de la descripción "
         "real. Con esto activado se busca la descripción en la base de datos NVD y en CVE.org y se "
         "sustituye, para que el correo y la plataforma siempre expliquen de qué va la vulnerabilidad."),
        ("descripcion_repaso_limite", "Descripciones ya guardadas que se repasan cada día", "int",
         "Las vulnerabilidades registradas antes de esta mejora pueden tener una descripción de relleno. Cada ejecución diaria repasa esta cantidad, empezando por las más relevantes, hasta completarlas todas. Con 0 no se repasa nada."),
        ("inventario_informe_activo", "Enviar el informe de inventario sin reportar", "bool",
         "Correo aparte para Redes con las máquinas que llevan más días de los "
         "configurados sin enviar su inventario a OCS Inventory, separadas en servidores y "
         "equipos de cómputo. No es un informe de seguridad: mantener el inventario al día es "
         "tarea de quien administra esas máquinas."),
        ("inventario_destinatarios", "Destinatarios del informe de inventario", "lista",
         "Direcciones de Redes, separadas por comas. Si está vacío no se envía nada, aunque el informe esté activado."),
        ("parches_buscar_diario", "Buscar cada día las correcciones que faltan", "bool",
         "Cuando un aviso confirma que un paquete es vulnerable pero no dice en qué versión se corrige "
         "(o el fabricante no ha publicado el parche), la vulnerabilidad queda en seguimiento y se "
         "consulta a diario. Al aparecer la corrección se avisa en el correo del día."),
        ("parches_max_consultas", "Consultas de red por ejecución al buscar correcciones", "int",
         "Límite de peticiones a OSV.dev, NVD y los avisos de la distribución en cada búsqueda diaria."),
        ("msrc_enabled", "Evaluar Windows con las correcciones publicadas por Microsoft", "bool",
         "Descarga los boletines mensuales de seguridad de Microsoft (MSRC) y, con las actualizaciones "
         "acumulativas que OCS Inventory ve instaladas en cada activo con Windows, confirma o "
         "descarta cada vulnerabilidad de Windows activo por activo."),
        ("msrc_meses", "Meses de boletines de Microsoft que se conservan", "int",
         "Cuantos boletines mensuales hacia atrás se descargan y consultan. Con 18 se cubren las "
         "actualizaciones acumulativas de año y medio."),
        ("ocs_edr_pattern", "Software de protección esperado en cada equipo de cómputo", "texto",
         "Prefijo del nombre del programa (por ejemplo «sophos»). Los equipos de cómputo con "
         "Windows o Ubuntu que no lo tienen generan el hallazgo «sin agente de protección»."),
        ("applicability_enabled", "Evaluar la aplicabilidad de cada CVE por activo", "bool",
         "Cruza las amenazas con CVE contra los paquetes instalados: OSV.dev para Debian y Ubuntu, "
         "VuXML para FreeBSD y comparación de versión para el resto. Sin esto, la ficha del activo "
         "solo tiene la consulta manual."),
        ("applicability_max_osv_per_run", "Consultas a OSV.dev por ejecución", "int",
         "Cada CVE necesita como mucho dos (Ubuntu y Debian) y se guardan en caché una semana. "
         "Con 300 se cubren unas 150 amenazas nuevas al día."),
        ("applicability_max_threats_per_run", "Amenazas evaluadas por ejecución", "int",
         "Primero las nunca evaluadas y las KEV; el resto se reparte entre días."),
        ("applicability_reevaluate_days", "Días entre reevaluaciones de una amenaza", "int",
         "Las correcciones se publican días después del CVE: reevaluar recoge los paquetes que ya "
         "quedaron corregidos y los activos que se actualizaron."),
    ]),
    ("Resumen semanal", [
        ("digest_enabled", "Enviar el resumen semanal", "bool",
         "Correo con lo que la alerta diaria no envió: seguimiento por tecnología, "
         "informativo, lo que el filtro descartó y por qué, y recordatorio de lo alertado."),
        ("digest_weekday", "Día de envío (1 = lunes … 7 = domingo)", "int",
         "Hoy el resumen se prepara los lunes a las 08:30 y solo se envía si el día coincide "
         "con el que diga este ajuste. Cambiarlo aquí no cambia la hora del programador de "
         "tareas: para mover el día hay que avisar también a Redes."),
        ("digest_max_items", "Máximo de amenazas en el resumen", "int",
         "Entre seguimiento e informativo. Las que no caben se consultan en la interfaz."),
    ]),
    ("Informe mensual", [
        ("report_detail_severities", "Severidades con ficha detallada", "lista",
         "Las vulnerabilidades de estas severidades llevan una ficha propia en el informe; las "
         "demás van en el anexo resumido. Valor recomendado: Crítica y Alta, con las que el "
         "informe ocupa unas cuarenta páginas en lugar de más de mil ochocientas."),
        ("report_max_detail_items", "Máximo de fichas detalladas", "int",
         "Límite duro de fichas individuales."),
        ("report_max_anexo_items", "Máximo de filas en el anexo", "int",
         "El resto se consulta en la interfaz. Sin límite, el anexo añade "
         "decenas de páginas sin valor de decisión."),
    ]),
    ("Recolección", [
        ("collect_lookback_days", "Ventana de recolección (días)", "int",
         "Sustituye al filtro de 'mes actual', que perdía lo publicado a fin de mes."),
        ("collect_require_technology", "Solo amenazas que afectan al inventario", "bool",
         "Si se desactiva, se guarda todo (mucho más volumen)."),
        ("debian_packages_file", "Lista de paquetes instalados (Debian y Ubuntu)", "texto",
         "Lista de paquetes instalados en los servidores Debian y Ubuntu, uno por línea, que "
         "prepara Redes. Un aviso de seguridad de la distribución que nombre "
         "un paquete de la lista correlaciona con la máxima confianza. Si se deja vacío, la "
         "comprobación queda desactivada."),
        ("http_timeout_s", "Tiempo máximo de espera por fuente (segundos)", "int",
         "Cuánto espera la recolección a que una fuente responda antes de darla por caída en "
         "ese intento. Demasiado bajo marca como caídas fuentes que solo van lentas; demasiado "
         "alto alarga la ejecución diaria. Valor recomendado: 20 segundos."),
        ("http_retries", "Reintentos por fuente", "int",
         "Solo se reintentan errores de red y 5xx, nunca un 404."),
        ("http_user_agent", "User-Agent de las peticiones", "texto",
         "Enviar un User-Agent de navegador real es lo que recuperó las fuentes "
         "de CISA, que devolvían 403 al no recibirlo. Cambiarlo puede volver a "
         "romperlas."),
    ]),
    ("Enriquecimiento", [
        ("enrich_nvd_enabled", "Consultar NVD para CVSS real", "bool",
         "Sustituye la puntuación inventada por la oficial."),
        ("enrich_kev_enabled", "Consultar CISA KEV", "bool",
         "Marca las vulnerabilidades con explotación confirmada."),
        ("enrich_epss_enabled", "Consultar EPSS", "bool",
         "Probabilidad de explotación a 30 días."),
        ("enrich_max_per_run", "Máximo de CVE a enriquecer por ejecución", "int",
         "Protege frente al límite de peticiones de la API."),
        ("nvd_rate_limit_sleep_s", "Espera entre peticiones a NVD (s)", "int",
         "Sin clave de API el límite es de 5 peticiones cada 30 segundos. Con "
         "una clave válida el sistema divide esta espera automáticamente."),
    ]),
    # Traducción (revisión de claridad del 2026-09-15): las etiquetas hablan del EFECTO
    # («traducción cuidada», «traducción rápida») y no del producto que lo hace. El nombre
    # del modelo y la dirección del servicio siguen siendo campos editables, porque hay que
    # poder cambiarlos, pero la ayuda explica para qué sirven sin presuponer que quien lee
    # conoce el producto.
    ("Traducción de los textos al español", [
        ("translate_engine", "Cómo se traduce", "opcion:none,argos,ollama,hybrid",
         "«Cuidada en lo grave y rápida en el resto» es lo recomendado: la traducción cuidada "
         "cuesta unos veinte segundos por texto y se reserva para las severidades que se "
         "indiquen abajo; el resto se traduce al instante. Si el servicio de traducción "
         "cuidada no responde, se usa la rápida y queda un aviso: la ejecución nunca se "
         "detiene por esto."),
        ("ollama_model", "Modelo de la traducción cuidada", "texto",
         "Nombre del modelo de lenguaje instalado en el servidor que hace la traducción "
         "cuidada. Cambiarlo solo tiene sentido si Redes instala otro."),
        ("ollama_max_calls_per_run", "Máximo de traducciones cuidadas por ejecución", "int",
         "Tope de textos que pasan por la traducción cuidada en cada ejecución diaria. Cada "
         "uno cuesta unos veinte segundos, así que este número marca cuánto se alarga la "
         "ejecución. Valor recomendado: 40."),
        ("ollama_severities", "Severidades que reciben traducción cuidada", "lista",
         "Solo estas severidades pasan por la traducción cuidada; las demás usan la rápida. "
         "Valor recomendado: Crítica y Alta, que son las que se leen en el correo."),
        ("ollama_url", "Dirección del servicio de traducción cuidada", "texto",
         "Dirección interna del servicio que traduce. Si no responde, se usa la traducción "
         "rápida y queda un aviso; la ejecución no se detiene."),
        ("ollama_timeout_s", "Tiempo máximo por traducción cuidada (segundos)", "int",
         "Cuánto se espera a que vuelva cada texto traducido. Un texto largo puede tardar un "
         "minuto la primera vez del día. Valor recomendado: 180 segundos."),
    ]),
    ("Salud de fuentes", [
        ("health_fail_streak_alert", "Fallos seguidos para avisar", "int",
         "Con este control, las 10 fuentes que llevaban 33 días caídas se habrían "
         "detectado al tercer día."),
        ("health_zero_entries_is_failure", "Contar una fuente vacía como fallo", "bool",
         "Activo es lo recomendado: una fuente que responde pero no devuelve ninguna entrada "
         "suele estar rota (cambió de dirección o de formato), y sin esto se contaría como "
         "correcta y nadie se enteraría. Si se desactiva, solo se avisa cuando la fuente da un "
         "error de red o del servidor."),
        ("health_notice_cooldown_h", "Horas entre avisos repetidos", "int",
         "Evita inundar el buzón del administrador."),
    ]),
    ("Envío de correos", [
        ("email_method", "Método de envío", "opcion:smtp,gmail",
         "SMTP: servidor de correo tradicional con usuario y contraseña. Gmail: OAuth a través de Google Workspace. El cambio se aplica en la siguiente ejecución."),
    ]),
    ("Credenciales de correo", [
        # Esta etiqueta y la de «password_max_dias» eran idénticas y nombraban dos cosas
        # distintas (2026-09-15): ahora cada una dice de quién es la contraseña.
        ("smtp_rotation_days", "Días de validez de la contraseña del servidor de correo", "int",
         "Cada cuántos días caduca la contraseña con la que la plataforma envía los correos. "
         "La fija el proveedor del correo y hoy son 30 días."),
        ("smtp_warn_days_before", "Avisar con estos días de antelación", "lista",
         "Se envía un aviso por cada umbral, sin repetir."),
        ("smtp_verify_on_daily_run", "Verificar credencial en cada ejecución", "bool",
         "Detecta que la contraseña ha caducado antes de que falle una alerta."),
    ]),
    ("Retención de datos", [
        ("data_retention_days", "Días de histórico de amenazas", "int",
         "Se aplica en la ejecución mensual. El historial de salud de fuentes se "
         "limita aparte a 90 días."),
        ("log_retention_days", "Días que se conservan los registros de ejecución", "int",
         "Pasado este plazo, los registros de las ejecuciones se borran solos en la limpieza "
         "semanal. Los registros de auditoría de la plataforma no se tocan: esos se conservan "
         "siempre. Valor recomendado: 90 días."),
    ]),
    ("Personalización", [
        ("empresa_nombre", "Nombre de la organización", "texto",
         "Nombre que aparece en la interfaz, los correos y los informes. Por defecto: «Mi Organización»."),
    ]),
    ("Tema y colores", [
        ("tema_modo", "Preferencia de tema", "opcion:sistema,claro,oscuro",
         "Sistema: sigue la configuración del navegador y el sistema operativo. Claro: siempre "
         "tema claro. Oscuro: siempre tema oscuro. Los cambios se aplican en la próxima carga."),
        ("tema_paleta", "Paleta de colores", "opcion:viva,corporativa,oscura,pastel",
         "Viva: colores saturados y vibrantes (por defecto). Corporativa: tonos profesionales "
         "apagados. Oscura: para modo oscuro permanente. Pastel: tonos suaves y relajantes. "
         "Los cambios se aplican en tiempo real."),
    ]),
    ("Interfaz", [
        ("webui_max_failed_logins", "Intentos fallidos antes de bloquear", "int",
         "Cuántas contraseñas seguidas puede fallar una persona antes de que su cuenta quede "
         "bloqueada durante los minutos que fije «Minutos de bloqueo». Un acceso correcto pone "
         "el contador a cero y un administrador puede desbloquear la cuenta al momento desde "
         "Usuarios. Valor recomendado: 5."),
        ("webui_https", "La plataforma se sirve cifrada", "bool",
         "Activo es lo recomendado: la cookie de sesión solo viaja cifrada y los enlaces de los "
         "correos se generan cifrados. Cambiarlo exige que Redes reinicie el "
         "servicio de la plataforma."),
        ("webui_tras_proxy", "La plataforma está detrás de un servidor web", "bool",
         "Activo es lo recomendado en el despliegue actual: la dirección de quien entra, la que "
         "queda en la auditoría, se toma de lo que informa el servidor web que está delante. "
         "Solo debe activarse si la plataforma no es alcanzable directamente; en otro caso "
         "cualquiera podría falsear esa dirección. Cambiarlo exige que Redes "
         "reinicie el servicio de la plataforma."),
        ("tls_certificado_ruta", "Certificado con el que se sirve la plataforma", "texto",
         "Ubicación del certificado público en el servidor, que facilita Servicios "
         "Tecnológicos. La plataforma solo lee su fecha de caducidad, para enseñar los días que "
         "quedan en Credenciales y avisar por correo antes de que caduque. La clave privada no "
         "se toca nunca."),
        ("tls_aviso_dias", "Días de antelación del aviso de caducidad del certificado", "int",
         "Cuando al certificado le queden estos días o menos, Credenciales lo marca como «por "
         "caducar» y llega un correo de administración una vez por semana."),
        ("webui_url", "Dirección pública de la plataforma", "texto",
         "La que llevan los enlaces de los correos, sin barra final: https://ejemplo.ejemplo.local "
         "cuando el nombre resuelva; mientras tanto, https://127.0.0.1."),
        ("webui_lockout_minutes", "Minutos de bloqueo", "int",
         "Cuánto dura el bloqueo de una cuenta tras agotar los intentos de «Intentos fallidos "
         "antes de bloquear». Pasado ese tiempo la persona puede volver a intentarlo sin que "
         "nadie haga nada; un administrador puede levantarlo antes desde Usuarios. Valor "
         "recomendado: 15 minutos."),
        ("mfa_obligatorio_admin", "Exigir segundo factor a los administradores", "bool",
         "Un administrador sin segundo factor configurado tendrá que activarlo (aplicación de códigos "
         "temporales) en su siguiente acceso antes de poder usar la consola."),
        # Sesión opaca en servidor y rotación de credenciales (2026-09-08). Sustituyen a
        # «Duración de la sesión (horas)», que ya no se lee.
        ("webui_session_minutos", "Minutos de sesión sin actividad", "int",
         "La sesión caduca cuando pasan estos minutos sin ninguna petición; cada página que se abre "
         "la renueva. Al volver, la pantalla de acceso explica que caducó por inactividad. Entre 5 y 480."),
        ("webui_session_maximo_horas", "Duración máxima de la sesión (horas)", "int",
         "Tope absoluto desde el inicio de sesión, aunque la persona siga activa: pasadas estas horas "
         "debe identificarse de nuevo. Evita que la renovación por actividad sea infinita. Entre 1 y 168."),
        ("webui_session_rotacion_minutos", "Minutos entre renovaciones del identificador de sesión", "int",
         "Cada vez que pasan estos minutos de actividad, la plataforma emite un identificador de "
         "sesión nuevo y el anterior deja de valer (durante un minuto sigue sirviendo solo para "
         "leer, por si había una petición en curso), así que una cookie copiada sirve poco "
         "tiempo. 0 desactiva la renovación."),
        ("password_max_dias", "Días de validez de la contraseña de las personas", "int",
         "Pasados estos días desde el último cambio, cada persona debe cambiar su contraseña de "
         "acceso a la plataforma antes de poder seguir usándola; cinco días antes se le avisa "
         "al entrar. Con 0 la contraseña no caduca."),
        ("password_historial", "Contraseñas anteriores que no se pueden repetir", "int",
         "Al cambiar la contraseña se rechaza cualquiera igual a la actual o a estas últimas. Solo se "
         "guardan los resúmenes cifrados (bcrypt), nunca las contraseñas."),
    ]),
]

#: Severidades: valor interno <-> etiqueta que se lee y se escribe en la pantalla. Los
#: dos ajustes de lista que hablan de severidades enseñaban «Critical, High» en inglés
#: (revisión de claridad del 2026-09-15); ahora se leen y se admiten en español, sin dejar
#: de aceptar el valor interno por si alguien pega el de un documento antiguo.
SEVERIDAD_ES = {"Critical": "Crítica", "High": "Alta", "Medium": "Media", "Low": "Baja"}
SEVERIDAD_DESDE_ES = {
    "critica": "Critical", "crítica": "Critical", "criticas": "Critical", "críticas": "Critical",
    "alta": "High", "altas": "High",
    "media": "Medium", "medias": "Medium",
    "baja": "Low", "bajas": "Low",
    "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
}

#: Ajustes de lista cuyos elementos son severidades.
LISTAS_DE_SEVERIDAD = ("report_detail_severities", "ollama_severities")

# Ajustes que NO se exponen a proposito: cambiarlos exige reiniciar el servicio,
# asi que se editan en el fichero y no desde la propia interfaz que sirven.
NO_EDITABLES = ("webui_host", "webui_port", "report_summary_severities")

# Ajustes de texto que pueden quedar vacios a proposito (vacio = desactivado).
TEXTO_VACIO_PERMITIDO = ("debian_packages_file",)

# Rango admitido de los enteros que lo tienen: (minimo, maximo, mensaje).
RANGOS_ENTEROS = {
    "collect_lookback_days": (1, 365, "debe estar entre 1 y 365 días"),
    "alert_max_items": (1, 200, "debe estar entre 1 y 200"),
    "msrc_meses": (1, 36, "debe estar entre 1 y 36 meses"),
    "alert_detalle_top": (1, 25, "debe estar entre 1 y 25"),
    "alert_tabla_top": (1, 50, "debe estar entre 1 y 50"),
    "alert_excel_max_activos": (10, 5000, "debe estar entre 10 y 5.000"),
    "parches_max_consultas": (0, 1000, "debe estar entre 0 y 1.000"),
    "descripcion_repaso_limite": (0, 500, "debe estar entre 0 y 500"),
    "alert_min_relevance": (0, 100, "debe estar entre 0 y 100"),
    "digest_weekday": (1, 7, "debe estar entre 1 (lunes) y 7 (domingo)"),
    "digest_max_items": (1, 500, "debe estar entre 1 y 500"),
    # Excepciones con vencimiento (2026-09-10): un aviso a menos de un día no daría tiempo
    # a decidir nada y a más de 120 avisaría de lo que todavía no es un problema.
    "excepciones_aviso_dias": (1, 120, "debe estar entre 1 y 120 días"),
    # Excepciones permanentes (2026-09-10): por debajo de 30 días el recordatorio de
    # revisión sería ruido y por encima de 730 dejaría de ser una salvaguarda.
    "excepciones_revision_dias": (30, 730, "debe estar entre 30 y 730 días"),
    # Sesión y contraseñas (2026-09-08)
    "webui_session_minutos": (5, 480, "debe estar entre 5 y 480 minutos"),
    "webui_session_maximo_horas": (1, 168, "debe estar entre 1 y 168 horas"),
    "webui_session_rotacion_minutos": (0, 480, "debe estar entre 0 (sin rotación) y 480 minutos"),
    "password_max_dias": (0, 365, "debe estar entre 0 (sin caducidad) y 365 días"),
    "password_historial": (0, 50, "debe estar entre 0 y 50"),
}


@bp.route("/")
@auth.requiere_admin
def panel():
    actuales = {}
    for _, items in GRUPOS:
        for clave, _, tipo, _ in items:
            actuales[clave] = g.cfg.get(clave)
    logo_fila = db.get_logo(g.db)
    return render_template("ajustes.html", grupos=GRUPOS, actuales=actuales,
                           defectos=config.DEFAULT_SETTINGS,
                           listas_de_severidad=LISTAS_DE_SEVERIDAD,
                           logo_actual=logo_fila)


@bp.route("/guardar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def guardar():
    cambios: list[str] = []
    errores: list[str] = []

    with db.session(current_app.config.get("DB_PATH")) as conn:
        for _, items in GRUPOS:
            for clave, etiqueta, tipo, _ in items:
                anterior = g.cfg.get(clave)
                try:
                    nuevo = _convertir(clave, tipo, anterior)
                except ValueError as exc:
                    errores.append(f"{etiqueta}: {exc}")
                    continue
                if nuevo is not None and nuevo != anterior:
                    db.set_setting(conn, clave, nuevo)
                    # En la auditoría se deja la ETIQUETA visible del ajuste, no su clave
                    # interna: es el mismo nombre que se lee en esta pantalla, en los correos
                    # y en los informes (revisión de claridad del 2026-09-15).
                    cambios.append(f"«{etiqueta}»: {anterior} -> {nuevo}")

        if cambios:
            db.audit(conn, g.usuario, "ajustes.guardar", "settings", None,
                     "; ".join(cambios)[:1500], request.remote_addr)

    if cambios:
        flash(f"{len(cambios)} ajuste(s) actualizado(s).", "exito")
    if errores:
        for e in errores:
            flash(e, "error")
    if not cambios and not errores:
        flash("No había cambios que guardar.", "info")
    return redirect(url_for("ajustes.panel"))


@bp.route("/restaurar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def restaurar():
    with db.session(current_app.config.get("DB_PATH")) as conn:
        for clave, valor in config.DEFAULT_SETTINGS.items():
            db.set_setting(conn, clave, valor)
        db.audit(conn, g.usuario, "ajustes.restaurar", "settings", None,
                 "valores por defecto", request.remote_addr)
    flash("Ajustes restaurados a los valores por defecto.", "info")
    return redirect(url_for("ajustes.panel"))


def _convertir(clave: str, tipo: str, anterior):
    """Convierte y valida el valor del formulario segun su tipo declarado."""
    if tipo == "bool":
        # Una casilla desmarcada no llega en el POST: se usa el campo espejo.
        if f"__presente__{clave}" not in request.form:
            return None
        return request.form.get(clave) == "1"

    bruto = request.form.get(clave)
    if bruto is None:
        return None
    bruto = bruto.strip()

    # Textos con forma obligatoria (revision adversaria del 2026-09-08): un valor mal
    # escrito rompe los enlaces de todos los correos o deja la vigilancia del certificado
    # sin nada que vigilar, y hasta ahora se guardaban tal cual.
    if clave == "webui_url":
        if bruto == "":
            return ""
        if " " in bruto or not (bruto.startswith("https://") or bruto.startswith("http://")):
            raise ValueError("debe empezar por https:// (o http:// si la interfaz no va cifrada), "
                             "sin espacios; por ejemplo https://ejemplo.ejemplo.local")
        return bruto.rstrip("/")
    if clave == "tls_certificado_ruta":
        if not bruto.startswith("/") or not bruto.lower().endswith((".crt", ".pem", ".cer")):
            raise ValueError("no tiene la forma que espera la plataforma; pida el dato exacto a "
                             "Redes y péguelo tal cual")
        return bruto

    if tipo == "int":
        if bruto == "":
            raise ValueError("no puede estar vacío")
        try:
            valor = int(bruto)
        except ValueError:
            raise ValueError(f"'{bruto}' no es un número entero") from None
        if valor < 0:
            raise ValueError("no puede ser negativo")
        if clave.endswith("_hours") and valor > 168:
            raise ValueError("máximo 168 horas")
        rango = RANGOS_ENTEROS.get(clave)
        if rango and not rango[0] <= valor <= rango[1]:
            raise ValueError(rango[2])
        return valor

    if tipo == "decimal":
        # Se admite la coma decimal española ("0,6") ademas del punto.
        if bruto == "":
            raise ValueError("no puede estar vacío")
        try:
            valor = float(bruto.replace(",", "."))
        except ValueError:
            raise ValueError(f"'{bruto}' no es un número decimal") from None
        if clave == "alert_min_match_confidence" and not 0.0 <= valor <= 1.0:
            raise ValueError("debe estar entre 0 y 1")
        if valor < 0:
            raise ValueError("no puede ser negativo")
        return round(valor, 2)

    if tipo.startswith("opcion:"):
        opciones = tipo.split(":", 1)[1].split(",")
        if bruto not in opciones:
            raise ValueError(f"valor no permitido; use uno de: {', '.join(opciones)}")
        return bruto

    if tipo == "lista":
        elementos = [e.strip() for e in bruto.replace(";", ",").split(",") if e.strip()]
        if not elementos:
            raise ValueError("la lista no puede quedar vacía")
        if clave == "smtp_warn_days_before":
            try:
                elementos = sorted({int(e) for e in elementos}, reverse=True)
            except ValueError:
                raise ValueError("deben ser números de días") from None
        elif clave in LISTAS_DE_SEVERIDAD:
            normalizados, malos = [], []
            for elemento in elementos:
                interno = SEVERIDAD_DESDE_ES.get(elemento.strip().lower())
                (normalizados if interno else malos).append(interno or elemento)
            if malos:
                raise ValueError(
                    "no reconozco esta severidad: " + ", ".join(malos)
                    + ". Escriba Crítica, Alta, Media o Baja, separadas por comas")
            # Sin repetir y en orden de gravedad, para que la lista se lea siempre igual.
            orden = list(SEVERIDAD_ES)
            elementos = sorted(set(normalizados), key=orden.index)
        return elementos

    if clave in TEXTO_VACIO_PERMITIDO:
        return bruto
    return bruto or None


# --------------------------------------------------------------------------
# Logo de la organización
# --------------------------------------------------------------------------
MAX_FICHERO_LOGO = marca.MAX_BYTES_ENTRADA


@bp.route("/logo.png")
def logo():
    """Sirve el logo normalizado (siempre PNG), SIN exigir sesión: aparece en la
    cabecera de la interfaz para todos los perfiles y también en la pantalla de
    inicio de sesión, antes de que haya ninguna sesión que comprobar. No es un dato
    sensible (es la imagen de marca que cualquiera ve igualmente al abrir el login)."""
    fila = db.get_logo(g.db)
    if fila is None:
        abort(404)
    etiqueta = f'"{fila["actualizado_at"]}"'
    if request.headers.get("If-None-Match") == etiqueta:
        return Response(status=304)
    return Response(
        fila["logo_datos"], mimetype=fila["logo_tipo"],
        headers={"Cache-Control": "private, max-age=3600", "ETag": etiqueta})


@bp.route("/logo", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def logo_subir():
    archivo = request.files.get("logo")
    if not archivo or not archivo.filename:
        flash("Seleccione una imagen.", "error")
        return redirect(url_for("ajustes.panel") + "#logo")
    bruto = archivo.read(MAX_FICHERO_LOGO + 1)
    if len(bruto) > MAX_FICHERO_LOGO:
        flash(f"La imagen supera los {MAX_FICHERO_LOGO // (1024 * 1024)} MB.", "error")
        return redirect(url_for("ajustes.panel") + "#logo")
    try:
        datos, tipo = marca.normalizar(bruto)
    except marca.LogoInvalido as exc:
        flash(f"No se pudo usar la imagen: {exc}", "error")
        return redirect(url_for("ajustes.panel") + "#logo")
    nombre = re.sub(r"[^A-Za-z0-9_.\-]+", "_", archivo.filename)[:120]
    with db.session(current_app.config.get("DB_PATH")) as conn:
        db.set_logo(conn, datos, tipo, nombre, g.usuario)
        db.audit(conn, g.usuario, "ajustes.logo_subir", "marca", None, nombre, request.remote_addr)
    flash("Logo actualizado. Aparecerá en la interfaz y en los próximos informes.", "exito")
    return redirect(url_for("ajustes.panel") + "#logo")


@bp.route("/logo/borrar", methods=["POST"])
@auth.requiere_admin
@auth.requiere_csrf
def logo_borrar():
    with db.session(current_app.config.get("DB_PATH")) as conn:
        db.borrar_logo(conn)
        db.audit(conn, g.usuario, "ajustes.logo_borrar", "marca", None, None, request.remote_addr)
    flash("Logo eliminado; se vuelve al icono por defecto.", "info")
    return redirect(url_for("ajustes.panel") + "#logo")
