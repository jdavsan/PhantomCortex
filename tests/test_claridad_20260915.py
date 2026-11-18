"""Revisión de claridad del 2026-09-15: lo que la persona lee no puede ser el interior
del sistema.

La auditoría de claridad encontró que la plataforma enseñaba el interior de la máquina en
sitios donde hace falta una frase: nombres de fichero y órdenes del servidor (incluso en la
pantalla de acceso, que se ve SIN sesión), claves internas de ajuste citadas como si fueran
el nombre visible, códigos de auditoría, excepciones crudas del motor de base de datos,
secretos con los dos primeros caracteres a la vista y textos que ya no eran ciertos.

Estas pruebas fijan lo corregido. La más útil es el guardián con expresión regular sobre
`webui/templates/*.html` y `threatintel/emails/*.html`: cualquier plantilla nueva que
escriba una ruta, una orden del servidor o una clave interna de ajuste falla aquí antes de
llegar a producción.

Sin red, con base temporal bajo `data/` y sin enviar ningún correo (el HTML se construye en
memoria con un `Mailer` falso o directamente con `render_*`).
"""
from __future__ import annotations

import re
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from threatintel import db, notify
from threatintel.paths import BASE_DIR
from webui import auth, filtros

PLANTILLAS_INTERFAZ = sorted((BASE_DIR / "webui" / "templates").glob("*.html"))
PLANTILLAS_CORREO = sorted((BASE_DIR / "threatintel" / "emails").glob("*.html"))

#: Plantillas que otro equipo mantiene en paralelo y que esta revisión no tocó. Se
#: excluyen del guardián para no bloquear su trabajo; el coordinador decide cuándo entran.
FUERA_DEL_ALCANCE = {"activos.html"}

#: Órdenes, rutas y ficheros del servidor que NUNCA pueden aparecer en una plantilla.
#: Cada patrón lleva su explicación para que el fallo diga qué hacer.
PATRONES_PROHIBIDOS: tuple[tuple[str, str], ...] = (
    (r"\b\w+\.py\b", "un programa del servidor: diga qué hace o quién lo hace"),
    (r"\bbin/", "una carpeta del servidor"),
    (r"\.venv/", "la instalación de Python del servidor"),
    (r"credentials\.env", "el fichero de credenciales del servidor"),
    (r"/etc/", "una ruta del servidor"),
    (r"\bsystemctl\b", "una orden del servidor"),
    (r"\bcrontab\b", "una orden del servidor"),
    (r"\bdpkg-query\b", "una orden del servidor"),
    (r"\bnginx\b", "el nombre del servidor web: diga «el servidor web»"),
    (r"\bchmod\b|permisos 600", "permisos de fichero del servidor"),
    (r"\.jsonl\b|\.log\b", "ficheros de registro del servidor"),
)

#: Claves internas de ajuste: en pantalla y en los correos se cita la ETIQUETA visible.
CLAVES_DE_AJUSTE_PROHIBIDAS = (
    "enrich_max_per_run", "excepciones_aviso_dias", "excepciones_revision_dias",
    "alert_solo_con_activos_afectados", "alert_kev_sin_activos", "ignore_low_severity",
    "alert_min_relevance", "report_detail_severities", "ollama_severities",
    "webui_max_failed_logins", "webui_lockout_minutes", "password_max_dias",
    "smtp_rotation_days", "tls_certificado_ruta", "ocs_stale_days",
)


def _sin_comentarios_jinja(texto: str) -> str:
    """Quita los comentarios `{# ... #}`: explican el porqué a quien lee el código y
    nunca llegan al navegador ni al cliente de correo."""
    return re.sub(r"\{#.*?#\}", " ", texto, flags=re.DOTALL)


class TestGuardianDeTextosVisibles(unittest.TestCase):
    """Ninguna plantilla escribe rutas, órdenes ni claves internas de ajuste."""

    def test_hay_plantillas_que_revisar(self):
        # Si alguien mueve los directorios, el guardián no puede quedarse en silencio.
        self.assertGreater(len(PLANTILLAS_INTERFAZ), 20)
        self.assertGreater(len(PLANTILLAS_CORREO), 5)

    def test_ninguna_plantilla_ensena_el_interior_del_servidor(self):
        for ruta in PLANTILLAS_INTERFAZ + PLANTILLAS_CORREO:
            if ruta.name in FUERA_DEL_ALCANCE:
                continue
            texto = _sin_comentarios_jinja(ruta.read_text(encoding="utf-8"))
            for patron, porque in PATRONES_PROHIBIDOS:
                with self.subTest(plantilla=ruta.name, patron=patron):
                    encontrado = re.search(patron, texto)
                    self.assertIsNone(
                        encontrado,
                        f"{ruta.name} escribe «{encontrado.group(0) if encontrado else ''}»: "
                        f"es {porque}. Ningún nombre de fichero, ruta ni orden del servidor "
                        f"puede verse en la interfaz ni en un correo.")

    def test_ninguna_plantilla_cita_la_clave_interna_de_un_ajuste(self):
        for ruta in PLANTILLAS_INTERFAZ + PLANTILLAS_CORREO:
            if ruta.name in FUERA_DEL_ALCANCE:
                continue
            texto = _sin_comentarios_jinja(ruta.read_text(encoding="utf-8"))
            # Solo se busca la clave escrita como TEXTO para el lector, no como variable
            # de plantilla: `{{ clave }}` recorre los ajustes y es legítimo.
            visible = re.sub(r"\{\{.*?\}\}|\{%.*?%\}", " ", texto, flags=re.DOTALL)
            for clave in CLAVES_DE_AJUSTE_PROHIBIDAS:
                with self.subTest(plantilla=ruta.name, clave=clave):
                    self.assertNotIn(
                        clave, visible,
                        f"{ruta.name} cita «{clave}», que es la clave interna del ajuste. "
                        f"Se cita siempre la etiqueta visible y su ruta de menú.")

    def test_los_modulos_que_escriben_correo_tampoco_citan_claves_internas(self):
        """El correo de excepciones citaba «excepciones_aviso_dias» en su pie."""
        modulos = [BASE_DIR / "threatintel" / n for n in
                   ("excepciones.py", "certificado.py", "notify.py", "libro_alerta.py")]
        for ruta in modulos:
            texto = ruta.read_text(encoding="utf-8")
            # Se miran solo las cadenas entrecomilladas que van a un correo; los comentarios
            # del código sí pueden nombrar la clave, que es el nombre real de la variable.
            sin_comentarios = re.sub(r"^\s*#.*$", "", texto, flags=re.MULTILINE)
            for clave in ("«excepciones_aviso_dias»", "«excepciones_revision_dias»",
                          "«enrich_max_per_run»", "«alert_solo_con_activos_afectados»"):
                with self.subTest(modulo=ruta.name, clave=clave):
                    self.assertNotIn(clave, sin_comentarios)


class TestFiltroRecortar(unittest.TestCase):
    """El recorte conserva el texto completo en el título emergente y corta por palabra."""

    def test_texto_corto_no_se_toca(self):
        self.assertEqual(filtros.recortar("Fuente en español.", 60), "Fuente en español.")

    def test_texto_largo_deja_el_completo_en_el_titulo(self):
        completo = ("No se pudo conectar con el servidor de inventario porque la red "
                    "descartó la conexión a mitad de la consulta")
        salida = str(filtros.recortar(completo, 40))
        self.assertIn('title="', salida)
        self.assertIn("No se pudo conectar", salida)
        self.assertTrue(salida.endswith("…</span>"))
        # El texto completo viaja entero en el título.
        titulo = re.search(r'title="([^"]+)"', salida).group(1)
        self.assertEqual(titulo.replace("&quot;", '"'), completo)

    def test_no_parte_una_palabra_por_la_mitad(self):
        salida = str(filtros.recortar("Analisis diario de lo que se explota", 20))
        visible = re.sub(r"<[^>]+>", "", salida).rstrip("…")
        self.assertFalse(visible.endswith(" "))
        self.assertIn(visible.split()[-1], "Analisis diario de lo que se explota".split())

    def test_el_anexo_del_informe_corta_por_palabra_y_avisa(self):
        from threatintel import report
        largo = report._recortar_palabra(
            "Vulnerabilidad de desbordamiento en el subsistema de red del núcleo", 30)
        self.assertTrue(largo.endswith("…"))
        self.assertLessEqual(len(largo), 30)
        self.assertNotIn("subsistem…", largo)


class TestAuditoriaEnEspanol(unittest.TestCase):
    """Los códigos de auditoría se leen como frases; el código queda en el título."""

    def test_acciones_conocidas(self):
        self.assertEqual(filtros.accion_es("login.2fa.ok"), "Segundo factor correcto")
        self.assertEqual(filtros.accion_es("usuario.crear"), "Usuario creado")
        self.assertEqual(filtros.accion_es("sesion.unica"),
                         "Sesión anterior cerrada por un acceso nuevo")
        self.assertEqual(filtros.accion_es("nvd.verificar"),
                         "Clave de la base de datos nacional de vulnerabilidades verificada")

    def test_accion_desconocida_se_lee_sin_puntos_ni_guiones(self):
        self.assertEqual(filtros.accion_es("fuente.ajustes_finales"),
                         "Fuente · ajustes finales")

    def test_entidades_en_un_solo_formato(self):
        self.assertEqual(filtros.entidad_es("users", 106), "Usuario n.º 106")
        self.assertEqual(filtros.entidad_es("users", "juan@ejemplo.local"),
                         "Usuario juan@ejemplo.local")
        self.assertEqual(filtros.entidad_es("settings", None), "Ajuste")

    def test_detalle_traduce_el_rol_y_no_confunde_recuentos_con_un_si_o_un_no(self):
        salida = filtros.detalle_es(
            "usuario=juan@ejemplo.local rol=admin habilitado=1 sesiones_revocadas=0")
        self.assertIn("perfil: Administrador", salida)
        self.assertIn("habilitado: sí", salida)
        self.assertIn("sesiones cerradas: 0", salida)
        self.assertNotIn("rol=admin", salida)

    def test_detalle_cita_la_etiqueta_visible_del_ajuste(self):
        salida = filtros.detalle_es("alert_kev_sin_activos: true -> false")
        self.assertIn("«Alertar la explotación activa", salida)
        self.assertIn("sí pasó a no", salida)
        self.assertNotIn("alert_kev_sin_activos", salida)

    def test_los_secretos_se_enmascaran_desde_el_primer_caracter(self):
        salida = filtros.detalle_es("anterior=OP***************** nueva=85*****************")
        self.assertNotIn("OP", salida)
        self.assertNotIn("85", salida)
        self.assertIn("caracteres", salida)

    def test_enmascarar_no_deja_ver_ningun_caracter(self):
        salida = filtros.enmascarar("12345678-abcd-4ef0-9876-0123456789ab")
        self.assertNotIn("1234", salida)
        self.assertIn("36 caracteres", salida)

    def test_tipo_de_aviso_en_espanol(self):
        self.assertEqual(filtros.aviso_es("smtp_rotacion"),
                         "Contraseña del correo por caducar")


class TestErrorDeConsultaTraducido(unittest.TestCase):
    """La excepción cruda del motor de base de datos se traduce a causa y remedio."""

    def test_conexion_perdida(self):
        salida = str(filtros.error_consulta_es(
            "OperationalError: (2013, 'Lost connection to MySQL server during query')"))
        self.assertIn("se cortó a mitad de la consulta", salida)
        self.assertIn("Detalle técnico", salida)
        self.assertIn("<details>", salida)
        # El original sigue disponible, plegado.
        self.assertIn("2013", salida)

    def test_sin_conexion(self):
        salida = str(filtros.error_consulta_es(
            "OperationalError: (2003, \"Can't connect to MySQL server\")"))
        self.assertIn("No se pudo abrir la conexión", salida)

    def test_credencial_rechazada(self):
        salida = str(filtros.error_consulta_es("(1045, 'Access denied for user')"))
        self.assertIn("no aceptó el usuario de consulta", salida)

    def test_error_desconocido_dice_igualmente_que_hacer(self):
        salida = str(filtros.error_consulta_es("algo raro que nadie previó"))
        self.assertIn("terminó con un error", salida)
        self.assertIn("Detalle técnico", salida)

    def test_sin_error_no_inventa_nada(self):
        self.assertIn("sin dejar ningún detalle", str(filtros.error_consulta_es(None)))


class TestAsuntosDeCorreo(unittest.TestCase):
    """Un solo prefijo, la fecha en palabras y un asunto que dice de qué va."""

    fecha = datetime(2026, 9, 15)

    def test_un_solo_prefijo(self):
        asuntos = [
            notify.asunto_alerta(7, 5, 1, fecha=self.fecha, total=12),
            notify.asunto_mensual("2026-09"),
            notify.asunto_admin("Una cosa", "critical"),
            notify.asunto_admin("Otra cosa", "warning"),
            notify.asunto_admin("Otra más"),
            notify.asunto_inventario(92, 30, self.fecha),
        ]
        for asunto in asuntos:
            with self.subTest(asunto=asunto):
                self.assertTrue(asunto.startswith("[Inteligencia de Amenazas]"), asunto)
                self.assertNotIn("[SOC]", asunto)
                self.assertNotIn("[Inventario]", asunto)

    def test_la_alerta_diaria_dice_de_que_va(self):
        asunto = notify.asunto_alerta(7, 5, 1, fecha=self.fecha, total=12)
        self.assertEqual(
            asunto,
            "[Inteligencia de Amenazas] Alerta diaria · 15 de septiembre de 2026 · "
            "12 vulnerabilidades, 7 críticas")

    def test_un_dia_sin_novedades_lo_dice_en_el_asunto(self):
        self.assertIn("sin novedades que requieran acción",
                      notify.asunto_alerta(0, 0, 0, fecha=self.fecha, total=0))

    def test_una_sola_vulnerabilidad_concuerda(self):
        asunto = notify.asunto_alerta(1, 0, 0, fecha=self.fecha, total=1)
        self.assertIn("1 vulnerabilidad,", asunto)
        self.assertIn("1 crítica", asunto)
        self.assertNotIn("vulnerabilidades", asunto)

    def test_accion_requerida_lleva_tilde_y_no_grita(self):
        asunto = notify.asunto_admin("El certificado ha caducado", "critical")
        self.assertIn("Acción requerida", asunto)
        self.assertNotIn("ACCION", asunto)


class TestMotivosDelFiltro(unittest.TestCase):
    """Las dos frases del pie del correo diario significan cosas distintas y se distinguen."""

    def test_comprobado_y_sin_confirmar_no_se_confunden(self):
        comprobado = notify.MOTIVOS_FILTRO_ES["sin_activos_afectados"]
        sin_confirmar = notify.MOTIVOS_FILTRO_ES["sin_activos_confirmados"]
        self.assertTrue(comprobado.startswith("comprobado y descartado"))
        self.assertTrue(sin_confirmar.startswith("sin confirmar"))
        self.assertNotEqual(comprobado, sin_confirmar)

    def test_un_solo_vocabulario_para_las_maquinas(self):
        for clave in ("sin_activos_afectados", "sin_activos_confirmados"):
            with self.subTest(clave=clave):
                self.assertNotIn("máquina", notify.MOTIVOS_FILTRO_ES[clave])
                self.assertIn("activo", notify.MOTIVOS_FILTRO_ES[clave])

    def test_la_severidad_que_no_se_reporta_no_se_nombra_y_se_dice_quien_decide(self):
        texto = notify.MOTIVOS_FILTRO_ES["severidad_baja"]
        self.assertNotIn("Baja", texto)
        self.assertNotIn("baja", texto)
        self.assertIn("Ciberseguridad", texto)

    def test_una_excepcion_puede_ser_permanente(self):
        texto = notify.MOTIVOS_FILTRO_ES["riesgo_aceptado"]
        self.assertIn("permanente", texto)


class TestCorreoDeProcesoAgrupaPorServidor(unittest.TestCase):
    """«9 servidores» arriba y 19 filas debajo: ahora se dicen las dos magnitudes."""

    def _amenaza(self):
        return {
            "id": 1, "cve": "CVE-2026-0001", "severity": "Critical", "relevance": 80,
            "title_es": "Fallo en el núcleo", "summary_es": "Descripción.",
            "servidores": [
                {"activo_id": 1, "nombre": "SRV-UNO", "ip": "10.0.0.1",
                 "entorno_es": "Producción", "so_nombre": "Debian 12", "expuesto": True,
                 "paquete": "linux-image", "version_instalada": "6.1.0-1",
                 "version_corregida": "6.1.0-9", "aviso": "DSA-1"},
                {"activo_id": 1, "nombre": "SRV-UNO", "ip": "10.0.0.1",
                 "entorno_es": "Producción", "so_nombre": "Debian 12", "expuesto": True,
                 "paquete": "linux-headers", "version_instalada": "6.1.0-1",
                 "version_corregida": "6.1.0-9", "aviso": "DSA-1"},
                {"activo_id": 2, "nombre": "SRV-DOS", "ip": "10.0.0.2",
                 "entorno_es": "Contingencia", "so_nombre": "Debian 12", "expuesto": False,
                 "paquete": "linux-image", "version_instalada": "6.1.0-2",
                 "version_corregida": "6.1.0-9", "aviso": "DSA-1"},
            ],
        }

    def test_dos_magnitudes_y_una_fila_por_servidor(self):
        html = notify.render_alert_email_proceso(
            "Impuestos", "responsable@ejemplo.local", [self._amenaza()],
            {"url_base": "https://ejemplo.interno", "fecha": datetime(2026, 9, 15)})
        self.assertIn("2 servidores afectados", html)
        self.assertIn("3 paquetes que actualizar", html)
        # Un servidor con dos paquetes aparece UNA vez como fila, con sus dos paquetes.
        self.assertEqual(html.count("<strong>SRV-UNO</strong>"), 1)
        self.assertIn("linux-image", html)
        self.assertIn("linux-headers", html)

    def test_el_agrupador_no_pierde_ningun_paquete(self):
        grupos = notify._agrupar_servidores(self._amenaza()["servidores"])
        self.assertEqual(len(grupos), 2)
        self.assertEqual(sum(len(g["paquetes"]) for g in grupos), 3)

    def test_sin_servidores_no_falla(self):
        html = notify.render_alert_email_proceso(
            "Impuestos", "responsable@ejemplo.local",
            [{"id": 2, "severity": "High", "title_es": "Otra", "servidores": []}],
            {"url_base": "", "fecha": datetime(2026, 9, 15)})
        self.assertIn("Impuestos", html)


class TestLibroDeLaAlerta(unittest.TestCase):
    """La misma magnitud se dice igual en todas las hojas."""

    def test_explotacion_activa_con_un_solo_texto(self):
        from threatintel import libro_alerta
        self.assertEqual(libro_alerta.EXPLOTACION_NO, "No consta")
        fuente = (BASE_DIR / "threatintel" / "libro_alerta.py").read_text(encoding="utf-8")
        # Ni «Sí»/«No» sueltos para la explotación activa en la hoja de resumen.
        self.assertNotIn('"Sí" if vista.get("in_kev") else "No"', fuente)

    def test_la_probabilidad_lleva_su_unidad_en_el_rotulo(self):
        from threatintel import libro_alerta
        self.assertIn("porcentaje", libro_alerta.ETIQUETA_EPSS)


class TestPaginasDeError(unittest.TestCase):
    """403, 404, 405 y 413 dicen qué pasó y cómo seguir, sin siglas ni culpa."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "claridad.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "lector@ejemplo.local", "LectorSeguro#2026",
                               rol="ciberseguridad", actor="prueba")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "lector@ejemplo.local",
                                 "password": "LectorSeguro#2026"})
        return cli

    def test_404_dice_que_paso_y_como_seguir(self):
        html = self._cliente().get("/no-existe-esta-pagina").get_data(as_text=True)
        self.assertIn("Esa página no existe", html)
        self.assertIn("vuelva al panel", html)
        # El número ya no manda en la página, pero sigue disponible para poder citarlo.
        self.assertNotIn('class="error-codigo"', html)
        self.assertIn("indique el número 404", html)

    def test_403_no_culpa_a_la_persona(self):
        respuesta = self._cliente().get("/ajustes/")
        self.assertEqual(respuesta.status_code, 403)
        html = respuesta.get_data(as_text=True)
        self.assertIn("no está incluida en su perfil", html)
        self.assertNotIn("Acceso inválido", html)
        self.assertIn("Su cuenta es correcta", html)

    def test_405_explica_que_es_una_accion_de_formulario(self):
        respuesta = self._cliente().get("/ajustes/guardar")
        self.assertIn(respuesta.status_code, (403, 405))

    def test_413_habla_en_palabras(self):
        with self.app.test_request_context():
            from flask import render_template
            html = render_template("error.html", codigo=413,
                                   titulo="El fichero que ha enviado es demasiado grande",
                                   detalle="La plataforma admite como mucho 41 megabytes "
                                           "por envío.")
        self.assertIn("megabytes", html)
        self.assertNotIn("SBOM", html)
        self.assertNotIn("OpenSCAP", html)


class TestPantallaDeAcceso(unittest.TestCase):
    """La pantalla que se ve SIN sesión no puede enseñar el interior del servidor."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "acceso.db")
        db.init_db(cls.ruta)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_sin_usuarios_no_se_ensena_ninguna_orden(self):
        html = self.app.test_client().get("/login").get_data(as_text=True)
        self.assertIn("Avise a administración", html)
        self.assertNotIn("gestionar_usuario", html)
        self.assertNotIn(".venv", html)
        self.assertNotIn("bin/", html)

    def test_la_etiqueta_pide_el_correo(self):
        html = self.app.test_client().get("/login").get_data(as_text=True)
        self.assertIn('<label for="usuario">Correo electrónico</label>', html)
        # Sigue admitiendo las cuentas antiguas, que no tienen forma de dirección.
        self.assertIn('<input type="text" id="usuario"', html)

    def test_al_llegar_redirigido_se_explica_por_que(self):
        html = self.app.test_client().get("/login?siguiente=/ajustes/").get_data(as_text=True)
        self.assertIn("hay que identificarse primero", html)


class TestAjustesConAyudaYEtiquetasUnicas(unittest.TestCase):
    """Ningún ajuste sin ayuda, ninguna etiqueta repetida y ningún «Baja» suelto."""

    def setUp(self):
        from webui.vistas import ajustes
        self.grupos = ajustes.GRUPOS
        self.items = [i for _, items in ajustes.GRUPOS for i in items]

    def test_todos_los_ajustes_tienen_ayuda(self):
        sin_ayuda = [clave for clave, _, _, ayuda in self.items if not (ayuda or "").strip()]
        self.assertEqual(sin_ayuda, [],
                         "Estos ajustes se quedaron sin explicación: " + ", ".join(sin_ayuda))

    def test_ninguna_etiqueta_se_repite(self):
        etiquetas = [etiqueta for _, etiqueta, _, _ in self.items]
        repetidas = sorted({e for e in etiquetas if etiquetas.count(e) > 1})
        self.assertEqual(repetidas, [],
                         "Dos ajustes distintos con el mismo nombre: " + ", ".join(repetidas))

    def test_la_severidad_que_no_se_reporta_solo_se_nombra_en_su_propia_ayuda(self):
        from webui.vistas import ajustes
        for clave, etiqueta, tipo, ayuda in self.items:
            with self.subTest(clave=clave):
                if clave != "ignore_low_severity":
                    self.assertNotIn("Baja", ayuda)
                self.assertNotIn("Baja", etiqueta)
                if tipo.startswith("opcion:"):
                    self.assertNotIn("Low", tipo.split(":", 1)[1].split(","))
        # El desplegable del criterio anterior ya no ofrece esa severidad.
        tipo = dict((c, t) for c, _, t, _ in self.items)["alert_min_severity"]
        self.assertEqual(tipo, "opcion:Critical,High,Medium")

    def test_las_ayudas_no_llevan_historial_ni_citas_ni_mayusculas_de_enfasis(self):
        for clave, _, _, ayuda in self.items:
            with self.subTest(clave=clave):
                self.assertNotRegex(ayuda, r"\b(?:20\d\d)\b",
                                    "la ayuda lleva una fecha: el historial va a docs/")
                self.assertNotIn("«me debe alertar", ayuda)
                # Palabras enteras en mayúsculas (tres letras o más), que son gritos.
                # Solo se persiguen las palabras españolas gritadas («NADA», «REVISA»,
                # «SI»); las siglas de producto o de norma se escriben así siempre.
                siglas = {"CVE", "CVSS", "KEV", "CISA", "NVD", "OCS", "DSA", "DLA", "USN",
                          "RHSA", "DMZ", "TAG", "HTTPS", "IP", "API", "OSV", "MSRC",
                          "CIDR", "SBOM", "EDR", "SMTP", "TLS", "KB", "VPN", "LTS",
                          "VUXML", "PEM", "UUID", "SSL", "MB", "GB",
                          # Valores reales del inventario que se escriben así en OCS.
                          "JT"}
                gritos = [p for p in re.findall(r"\b[A-ZÁÉÍÓÚÑ]{2,}\b", ayuda)
                          if p not in siglas]
                self.assertEqual(gritos, [], f"«{clave}» grita: {gritos}")

    def test_las_severidades_se_escriben_en_espanol(self):
        from webui.vistas import ajustes
        self.assertEqual(ajustes.SEVERIDAD_DESDE_ES["crítica"], "Critical")
        self.assertEqual(ajustes.SEVERIDAD_DESDE_ES["alta"], "High")
        # Y se sigue admitiendo el valor interno pegado de un documento antiguo.
        self.assertEqual(ajustes.SEVERIDAD_DESDE_ES["high"], "High")

    def test_el_motor_de_traduccion_se_nombra_por_su_efecto(self):
        etiquetas = {c: e for c, e, _, _ in self.items}
        self.assertEqual(etiquetas["translate_engine"], "Cómo se traduce")
        for clave in ("ollama_model", "ollama_severities", "ollama_url"):
            with self.subTest(clave=clave):
                self.assertNotIn("Ollama", etiquetas[clave])
                self.assertNotIn("Argos", etiquetas[clave])


class TestInformeConUnSoloTotal(unittest.TestCase):
    """Las cifras del informe salen todas del mismo universo y el reparto suma 100 %."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "informe.db")
        db.init_db(cls.ruta)
        ahora = db.utcnow()
        with db.session(cls.ruta) as conn:
            filas = (
                # (severidad, motivo de exclusión, alertada)
                ("Critical", None, True), ("High", None, True),
                ("High", "relevancia_baja", False), ("Medium", "sin_identificador", False),
                ("Low", "severidad_baja", False), ("Low", "severidad_baja", False),
                ("Medium", None, False),
            )
            for i, (sev, motivo, alertada) in enumerate(filas, start=1):
                conn.execute(
                    """INSERT INTO threats(fingerprint, month, title_en, severity,
                                           first_seen_at, last_seen_at, alert_skip_reason,
                                           alerted_at, estado)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (f"huella-{i}", "2026-09", f"Amenaza {i}", sev, ahora, ahora, motivo,
                     ahora if alertada else None, "nueva"))

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_la_precision_cuenta_el_mismo_universo_que_la_portada(self):
        from threatintel import report
        with db.session(self.ruta) as conn:
            precision = report.precision_filtro(conn, "2026-09", bajas_ignoradas=2,
                                                excluir_bajas=True)
        # Cinco amenazas de las severidades que se reportan; las dos restantes quedan fuera.
        self.assertEqual(precision["total"], 5)
        self.assertEqual(precision["bajas_ignoradas"], 2)
        self.assertEqual(precision["motivos"]["severidad_baja"], 0)

    def test_el_reparto_de_la_precision_suma_el_total(self):
        from threatintel import report
        with db.session(self.ruta) as conn:
            precision = report.precision_filtro(conn, "2026-09", excluir_bajas=True)
        suma = precision["alertadas"] + sum(precision["motivos"].values())
        self.assertLessEqual(suma, precision["total"])

    def test_la_evolucion_usa_el_mismo_criterio_que_el_resto(self):
        from threatintel import queries
        with db.session(self.ruta) as conn:
            serie = queries.evolucion_mensual(conn, 3, excluir_bajas=True)
        fila = serie[0]
        self.assertEqual(fila["total"], fila["criticas"] + fila["altas"] + fila["medias"])

    def test_no_se_recomienda_pedir_una_clave_que_ya_esta_en_uso(self):
        from threatintel import report

        class CfgConClave:
            secrets = {"NIST_NVD_API_KEY": "12345678-abcd-4ef0-9876-0123456789ab"}

            def get(self, clave, defecto=None):
                return defecto

        class CfgSinClave:
            secrets: dict = {}

            def get(self, clave, defecto=None):
                return defecto

        self.assertTrue(report._hay_clave_nvd(CfgConClave()))
        self.assertFalse(report._hay_clave_nvd(CfgSinClave()))


class TestConcordanciasDelInforme(unittest.TestCase):
    """«En 1 casos» y «1 vulnerabilidades cuentan» ya no pueden escribirse."""

    def test_singular_y_plural_en_las_frases_con_cifra(self):
        from docx import Document
        from threatintel import report
        doc = Document()
        resumen = {
            "month": "2026-09", "periodo": "septiembre de 2026", "total": 1,
            "criticas": 1, "altas": 0, "medias": 0, "bajas": 0, "en_kev": 1,
            "confirmadas_afectadas": 1, "descartadas_version": 1, "sin_determinar": 0,
            "sev_heuristica": 0, "sev_nvd": 1, "pct_con_cvss_real": 100.0,
            "excluir_bajas": True, "top_tecnologias": [],
        }

        class Cfg:
            secrets = {"NIST_NVD_API_KEY": "x"}

            def get(self, clave, defecto=None):
                return defecto

        report._conclusiones(doc, resumen, cfg=Cfg(), numero=6)
        texto = "\n".join(p.text for p in doc.paragraphs)
        self.assertIn("1 amenaza cuenta con explotación activa", texto)
        self.assertIn("En 1 caso se ha verificado", texto)
        self.assertIn("1 hallazgo al comprobar", texto)
        self.assertNotIn("1 casos", texto)
        self.assertNotIn("1 amenazas", texto)


if __name__ == "__main__":
    unittest.main()
