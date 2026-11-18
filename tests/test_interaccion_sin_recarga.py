"""Interacción sin recarga: contrato de atributos y coherencia con el motor (2026-09-10).

Petición del usuario: «ajusta que el uso de funcionalidades se utilice sin que la página
se recargue porque eso es muy molesto». El motor vive en ``webui/static/app.js`` y las
páginas se apuntan a él con atributos ``data-*``; el contrato completo está en
``docs/INTERACCION_SIN_RECARGA_2026-09-10.md``.

Estas pruebas fijan lo que se puede comprobar sin navegador. Lo que necesita un navegador
de verdad (que la página NO se recargue) se comprueba con
``data/revision/verificar_sin_recarga.py``, que se ejecuta a mano contra una copia de la
base real.

Qué se comprueba aquí:

* **Coherencia motor ↔ plantillas.** Todo atributo del vocabulario de comportamiento que
  use una plantilla tiene que estar implementado en ``app.js``. Es el guardián que habría
  detectado el fallo del 2026-09-10: una plantilla con el atributo antiguo y un motor que
  ya no lo mira (o al revés) rompe la suite.
* **Zonas vivas coherentes en la página ya pintada.** Cada ``data-filtro-vivo``,
  ``data-accion-viva``, ``data-vivo-zonas`` y ``data-enlace-vivo`` nombra identificadores
  que existen en ESA página y que están marcados como zona viva; cada zona tiene
  identificador único.
* **El contenedor de mensajes** existe siempre, con región viva, para que el resultado de
  una acción se anuncie sin recargar.
* **La vista previa de Informes es viva en los DOS modos**: empezando de cero y con
  cualquiera de las plantillas preconfiguradas (petición del usuario del 2026-09-10:
  «quiero que cuando sea personalizado y plantillas lo deje previsualizar en vivo»).
* **Mejora progresiva**: ningún formulario vivo pierde su forma clásica de enviarse, la
  política de contenido sigue estricta y ninguna plantilla gana ``on*=``, ``style=`` ni
  un ``<script>`` en línea.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_interaccion_sin_recarga
"""
from __future__ import annotations

import re
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR

PLANTILLAS = BASE_DIR / "webui" / "templates"
ESTATICOS = BASE_DIR / "webui" / "static"
DOCUMENTO = BASE_DIR / "docs" / "INTERACCION_SIN_RECARGA_2026-09-10.md"

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)
RE_COMENTARIO_JINJA = re.compile(r"\{#.*?#\}", re.S)

#: Vocabulario del motor de actualización parcial. Un atributo que empiece por uno de
#: estos prefijos PROMETE un comportamiento: si el motor no lo implementa, la promesa es
#: falsa y la suite tiene que fallar.
PREFIJOS_MOTOR = ("data-zona-", "data-accion-", "data-enlace-", "data-vivo-",
                  "data-filtro-vivo", "data-sin-vivo")

#: Atributos de comportamiento anteriores al motor, que también atiende app.js. Se
#: comprueban por nombre exacto porque comparten prefijo con atributos que solo son datos
#: (por ejemplo «data-filtro-activos», que es una marca del inventario, no una promesa).
ATRIBUTOS_CON_COMPORTAMIENTO = (
    "data-toggle", "data-confirm", "data-confirm-si", "data-confirmar",
    "data-autosubmit", "data-copiar", "data-copiado-texto", "data-vulns",
    "data-tema-toggle", "data-iniciar-tour", "data-colapsar-nav", "data-abrir-nav",
    "data-atajo-busqueda", "data-tour", "data-tour-titulo", "data-tour-texto",
    "data-tour-estado", "data-tour-url",
)


def texto_de(nombre: str) -> str:
    """El contenido de una plantilla sin los comentarios de Jinja."""
    return RE_COMENTARIO_JINJA.sub("", (PLANTILLAS / nombre).read_text(encoding="utf-8"))


def javascript() -> str:
    return ((ESTATICOS / "app.js").read_text(encoding="utf-8")
            + (ESTATICOS / "tema.js").read_text(encoding="utf-8"))


def atributos_de(texto: str) -> set[str]:
    """Los atributos ``data-*`` que aparecen en las etiquetas de un HTML."""
    return {m.group(1) for m in re.finditer(r"[\s\"'](data-[a-z0-9-]+)[=\s>]", texto)}


class Recolector(HTMLParser):
    """Recoge de una página los identificadores, las zonas y los atributos vivos."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.zonas: list[str] = []
        self.referencias: list[tuple[str, str, str]] = []   # (atributo, valor, etiqueta)
        self.peligrosos: list[str] = []
        self.scripts_en_linea: list[str] = []
        self.mensajes: dict | None = None
        self._script_con_src = True

    def handle_starttag(self, tag, attrs):
        d = {k.lower(): (v or "") for k, v in attrs}
        for nombre in d:
            if nombre == "style" or nombre.startswith("on"):
                self.peligrosos.append(f"<{tag} {nombre}>")
        if tag == "script":
            self._script_con_src = "src" in d
            if not self._script_con_src:
                self.scripts_en_linea.append("<script> sin src")
        if d.get("id"):
            self.ids.append(d["id"])
            if d["id"] == "mensajes-plataforma":
                self.mensajes = d
        if "data-zona-viva" in d:
            self.zonas.append(d.get("id", ""))
        for atributo in ("data-filtro-vivo", "data-accion-viva", "data-vivo-zonas",
                         "data-enlace-vivo"):
            if atributo in d and d[atributo].strip():
                self.referencias.append((atributo, d[atributo].strip(), tag))


def analizar(html: str) -> Recolector:
    r = Recolector()
    r.feed(html)
    return r


# ==========================================================================
# 1. Coherencia entre el motor y las plantillas
# ==========================================================================
class TestContratoDelMotor(unittest.TestCase):
    """El guardián: una plantilla no puede prometer un comportamiento que no existe."""

    @classmethod
    def setUpClass(cls):
        cls.js = javascript()
        cls.enjs = set(re.findall(r"data-[a-z0-9-]+", cls.js))
        cls.plantillas = {p.name: texto_de(p.name)
                          for p in sorted(PLANTILLAS.glob("*.html"))}

    def test_todo_atributo_vivo_de_las_plantillas_lo_implementa_app_js(self):
        faltan = []
        for nombre, texto in self.plantillas.items():
            for atributo in sorted(atributos_de(texto)):
                if not atributo.startswith(PREFIJOS_MOTOR):
                    continue
                if atributo not in self.enjs:
                    faltan.append(f"{nombre}: {atributo}")
        self.assertEqual(faltan, [], "atributos del motor que app.js no implementa "
                                     "(o que cambiaron de nombre solo en un sitio)")

    def test_los_atributos_de_comportamiento_anteriores_siguen_atendidos(self):
        """El motor se generalizó el 2026-09-10; lo que ya funcionaba tiene que seguir."""
        faltan = []
        for nombre, texto in self.plantillas.items():
            usados = atributos_de(texto)
            for atributo in ATRIBUTOS_CON_COMPORTAMIENTO:
                if atributo in usados and atributo not in self.enjs:
                    faltan.append(f"{nombre}: {atributo}")
        self.assertEqual(faltan, [])

    def test_el_motor_escucha_por_delegacion_en_el_documento(self):
        """Con delegación no hay que volver a enganchar nada al sustituir una zona.

        Si alguien vuelve a enganchar los escuchadores elemento a elemento, las zonas
        que el motor sustituye se quedarían sin comportamiento (confirmaciones, plegables,
        copiar…), que es justo lo que costó el rediseño.
        """
        for suceso in ("\"input\"", "\"change\"", "\"submit\"", "\"click\"", "\"popstate\""):
            self.assertIn(f"addEventListener({suceso}", self.js.replace("window.", ""),
                          f"el motor no escucha {suceso} por delegación")
        # Las confirmaciones y los plegables ya no se enganchan uno a uno.
        self.assertNotIn('querySelectorAll("[data-toggle]").forEach', self.js)
        self.assertNotIn('querySelectorAll("form[data-confirm]").forEach', self.js)
        self.assertNotIn('querySelectorAll("[data-confirmar]").forEach', self.js)

    def test_el_motor_no_se_activa_sin_fetch_ni_historial(self):
        """Mejora progresiva: sin fetch o sin history el motor se aparta."""
        self.assertIn('typeof window.fetch === "function"', self.js)
        self.assertIn('typeof window.history.pushState === "function"', self.js)
        self.assertIn("if (!soportado) { return; }", self.js)

    def test_una_escritura_no_se_reintenta_sola(self):
        """Si una escritura falla no se puede repetir sin que lo decida una persona."""
        self.assertIn("Nunca se reintenta una escritura sola", self.js)

    def test_el_contrato_esta_documentado(self):
        doc = DOCUMENTO.read_text(encoding="utf-8")
        for atributo in ("data-zona-viva", "data-zona-nombre", "data-zona-foco",
                         "data-zona-resumen", "data-filtro-vivo",
                         "data-filtro-vivo-retardo", "data-vivo-fragmento",
                         "data-vivo-zonas", "data-enlace-vivo", "data-sin-vivo",
                         "data-accion-viva", "data-accion-espera", "data-accion-tiempo",
                         "mensajes-plataforma"):
            self.assertIn(atributo, doc, f"{atributo} no está documentado")

    def test_el_javascript_del_motor_no_lleva_nada_en_linea_en_las_plantillas(self):
        for nombre, texto in self.plantillas.items():
            with self.subTest(plantilla=nombre):
                self.assertIsNone(RE_ON.search(texto), f"{nombre}: atributo on*=")
                self.assertIsNone(RE_STYLE.search(texto), f"{nombre}: atributo style=")
                for etiqueta in re.findall(r"<script\b[^>]*>", texto):
                    self.assertIn("src=", etiqueta, f"{nombre}: <script> en línea")


# ==========================================================================
# 2. Las páginas ya pintadas
# ==========================================================================
class BasePaginas(unittest.TestCase):
    """Una base temporal con lo justo para pintar todas las páginas de la consola."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "sin_recarga.db")
        db.init_db(cls.ruta)
        from webui import auth
        ahora = db.utcnow()
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin@ejemplo.local", "AdminSeguro#2026", rol="admin",
                               nombre="Administradora", actor="pruebas")
            conn.execute(
                """INSERT INTO technologies(slug, name, vendor, category, criticality,
                        systems_count, exposure, version_installed, enabled, created_at,
                        updated_at)
                   VALUES('openssl','OpenSSL','OpenSSL','biblioteca','critical',3,
                          'internet','3.0.1',1,?,?)""", (ahora, ahora))
            cls.tec_id = conn.execute("SELECT id FROM technologies").fetchone()[0]
            conn.execute(
                """INSERT INTO sources(slug, name, url, kind, category, priority, enabled,
                        timeout_s, created_at, updated_at)
                   VALUES('cisa','CISA','https://x.invalid/rss','rss','advisory','high',1,
                          30,?,?)""", (ahora, ahora))
            cls.fuente_id = conn.execute("SELECT id FROM sources").fetchone()[0]
            for i in range(1, 61):
                conn.execute(
                    """INSERT INTO activos(origen, ocs_id, nombre, so_nombre, so_version,
                            so_familia, ip, usuario, entorno, proceso, zona, n_software,
                            presente, primera_vez_at, visto_at, ultimo_inventario)
                       VALUES('servidores',?,?,'Debian 12','12','debian',?,?,'produccion',
                              'Proceso Uno','interna',3,1,?,?,?)""",
                    (i, f"srv-{i:03d}", f"10.0.0.{i}", f"usuario{i}", ahora, ahora, ahora[:10]))
            cls.activo_id = conn.execute("SELECT id FROM activos ORDER BY id").fetchone()[0]
            for i in range(1, 41):
                conn.execute(
                    """INSERT INTO threats(fingerprint, cve, title_en, title_es, severity,
                            severity_source, first_seen_at, last_seen_at, month, relevance,
                            estado)
                       VALUES(?,?,?,?,'High','nvd',?,?,?,?,'nueva')""",
                    (f"fp-{i}", f"CVE-2026-{1000 + i}", f"Fallo {i}", f"Fallo {i}",
                     ahora, ahora, ahora[:7], 90 - i))
            cls.threat_id = conn.execute("SELECT id FROM threats ORDER BY id").fetchone()[0]
            conn.execute("INSERT INTO threat_technologies(threat_id, technology_id, confidence)"
                         " VALUES(?,?,0.9)", (cls.threat_id, cls.tec_id))
            conn.execute(
                """INSERT INTO aplicabilidad(threat_id, activo_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor,
                        evidencia, evaluado_at)
                   VALUES(?,?,'CVE-2026-1001','openssl','3.0.1','3.0.2','afectado','osv',
                          'la versión instalada es anterior a la corregida',?)""",
                (cls.threat_id, cls.activo_id, ahora))
            conn.execute(
                """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete,
                        version_vulnerable, version_corregida, motor, estado, detectado_at,
                        comprobado_at)
                   VALUES(?,?,?,'openssl','3.0.1','3.0.2','osv','abierta',?,?)""",
                (cls.activo_id, cls.threat_id, "CVE-2026-1001", ahora, ahora))
            conn.execute(
                """INSERT INTO parches_pendientes(cve, paquete, ecosistema, threat_id,
                        motivo, n_activos, n_activos_expuestos, detectado_at, intentos)
                   VALUES('CVE-2026-2001','curl','Debian:12',?,'sin_parche_publicado',
                          2,1,?,1)""", (cls.threat_id, ahora))
            for i in range(60):
                db.audit(conn, "admin@ejemplo.local", "prueba.paginacion", "threats", str(i),
                         "entrada de prueba", "127.0.0.1")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)
        cls.cli = cls.app.test_client()
        cls.cli.post("/login", data={"usuario": "admin@ejemplo.local",
                                     "password": "AdminSeguro#2026"})

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def html(self, url: str) -> str:
        r = self.cli.get(url)
        self.assertEqual(r.status_code, 200, url)
        return r.get_data(as_text=True)


#: Direcciones que se recorren enteras. Son las páginas de la consola con zonas vivas.
RUTAS = [
    "/", "/amenazas/", "/amenazas/tendencias", "/auditoria", "/activos/",
    "/activos/software", "/tecnologias/", "/fuentes/", "/excepciones/",
    "/remediaciones/", "/parches-pendientes/", "/informes/", "/usuarios/",
    "/ajustes/", "/credenciales/", "/sincronizaciones/", "/alertas-proceso/",
    "/perfil",
]


class TestPaginasVivas(BasePaginas):
    """Lo que promete cada página tiene que existir en esa misma página."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.paginas = {}
        for ruta in RUTAS:
            r = cls.cli.get(ruta, follow_redirects=True)
            if r.status_code == 200:
                cls.paginas[ruta] = analizar(r.get_data(as_text=True))
        cls.paginas["/amenazas/%d" % cls.threat_id] = analizar(
            cls.cli.get(f"/amenazas/{cls.threat_id}").get_data(as_text=True))
        cls.paginas["/activos/%d" % cls.activo_id] = analizar(
            cls.cli.get(f"/activos/{cls.activo_id}").get_data(as_text=True))

    def test_se_han_podido_pintar_todas_las_rutas(self):
        self.assertEqual(sorted(set(RUTAS) - set(self.paginas)), [],
                         "hay rutas del recorrido que no respondieron 200")

    def test_cada_referencia_apunta_a_una_zona_viva_de_la_misma_pagina(self):
        malas = []
        for ruta, pagina in self.paginas.items():
            for atributo, valor, etiqueta in pagina.referencias:
                for ident in valor.split():
                    if ident not in pagina.ids:
                        malas.append(f"{ruta}: <{etiqueta} {atributo}=\"{ident}\"> no existe")
                    elif ident not in pagina.zonas:
                        malas.append(f"{ruta}: «{ident}» no está marcado con data-zona-viva")
        self.assertEqual(malas, [])

    def test_las_zonas_vivas_tienen_identificador_unico(self):
        malas = []
        for ruta, pagina in self.paginas.items():
            for ident in pagina.zonas:
                if not ident:
                    malas.append(f"{ruta}: una zona viva sin identificador")
                elif pagina.ids.count(ident) > 1:
                    malas.append(f"{ruta}: el identificador «{ident}» está repetido")
        self.assertEqual(malas, [])

    def test_el_contenedor_de_mensajes_existe_con_su_region_viva(self):
        for ruta, pagina in self.paginas.items():
            with self.subTest(ruta=ruta):
                self.assertIsNotNone(pagina.mensajes,
                                     "falta <div id=mensajes-plataforma>")
                self.assertEqual(pagina.mensajes.get("role"), "status")
                self.assertEqual(pagina.mensajes.get("aria-live"), "polite")
                self.assertEqual(pagina.mensajes.get("aria-atomic"), "true")

    def test_ninguna_pagina_trae_estilos_ni_manejadores_en_linea(self):
        for ruta, pagina in self.paginas.items():
            with self.subTest(ruta=ruta):
                self.assertEqual(pagina.peligrosos, [])
                self.assertEqual(pagina.scripts_en_linea, [])

    def test_la_politica_de_contenido_sigue_estricta(self):
        r = self.cli.get("/amenazas/")
        csp = r.headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertNotIn("unsafe", csp)

    def test_las_paginas_de_listado_tienen_zona_viva_y_paginacion_viva(self):
        """Paginar es lo más molesto de todo: tiene que ser vivo en todos los listados."""
        esperado = {
            "/amenazas/": "resultados",
            "/auditoria": "registro-auditoria",
            "/activos/": "lista-activos",
            "/tecnologias/": "tabla-tecnologias",
            "/fuentes/": "catalogo-fuentes",
            "/excepciones/": "lista-excepciones",
            "/remediaciones/": "tabla-remediaciones",
            "/parches-pendientes/": "tabla-parches",
            "/activos/software": "sin-clasificar",
            "/sincronizaciones/": "tabla-sincronizaciones",
        }
        for ruta, zona in esperado.items():
            with self.subTest(ruta=ruta):
                pagina = self.paginas[ruta]
                self.assertIn(zona, pagina.zonas, f"{ruta} no declara la zona «{zona}»")

    def test_la_paginacion_pinta_enlaces_vivos_cuando_hay_varias_paginas(self):
        html = self.html("/auditoria")
        self.assertIn('data-enlace-vivo="registro-auditoria"', html)
        # Y el parcial no los pinta si la página no pasa la zona: la marca es explícita.
        self.assertNotIn('data-enlace-vivo=""', html)

    def test_los_formularios_de_filtro_conservan_su_envio_clasico(self):
        """Mejora progresiva: sin JavaScript el formulario se sigue pudiendo enviar."""
        for ruta in ("/amenazas/", "/tecnologias/", "/activos/", "/informes/"):
            with self.subTest(ruta=ruta):
                html = self.html(ruta)
                for m in re.finditer(r"<form[^>]*data-filtro-vivo[^>]*>", html):
                    etiqueta = m.group(0)
                    self.assertNotIn('method="post"', etiqueta,
                                     "un filtro vivo tiene que seguir siendo GET")

    def test_las_acciones_vivas_siguen_siendo_post_con_testigo_csrf(self):
        """El motor no cambia el modelo de seguridad: mismo método y mismo testigo."""
        for ruta in ("/usuarios/", "/ajustes/", "/remediaciones/"):
            with self.subTest(ruta=ruta):
                html = self.html(ruta)
                for m in re.finditer(r"<form[^>]*data-accion-viva[^>]*>(.{0,400})", html, re.S):
                    self.assertIn('method="post"', m.group(0))
                    self.assertIn('name="csrf"', m.group(1))


# ==========================================================================
# 3. Informes: la vista previa es viva en los dos modos
# ==========================================================================
class TestVistaPreviaViva(BasePaginas):
    """«Quiero que cuando sea personalizado y plantillas lo deje previsualizar en vivo»."""

    def test_el_formulario_pide_la_vista_previa_en_vivo_en_los_dos_modos(self):
        from threatintel import informe_seleccion as isel
        claves = [p.clave for p in isel.PLANTILLAS] + [isel.PLANTILLA_LIBRE]
        for clave in claves:
            with self.subTest(plantilla=clave):
                html = self.html(f"/informes/?plantilla={clave}")
                pagina = analizar(html)
                self.assertIn("campos-informe", pagina.zonas)
                self.assertIn("vista-previa-informe", pagina.zonas)
                self.assertIn('data-filtro-vivo="vista-previa-informe"', html)
                self.assertIn('data-vivo-fragmento="/informes/vista-previa"', html)
                # Los controles que cambian la forma del formulario actualizan las dos
                # zonas. El informe ejecutivo mensual (2026-09-15) no tiene ninguno: su
                # periodo, su alcance, sus severidades y sus apartados son fijos y el
                # formulario solo pide el mes y la portada, así que no hay nada que pueda
                # cambiar la forma del formulario y no lleva ese atributo. La vista previa
                # sí sigue siendo viva, que es lo que comprueba esta prueba.
                if clave != isel.PLANTILLA_EJECUTIVA:
                    self.assertIn('data-vivo-zonas="campos-informe vista-previa-informe"', html)

    def test_el_fragmento_devuelve_los_dos_trozos_y_nada_mas(self):
        r = self.cli.get("/informes/vista-previa?plantilla=direccion")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertNotIn("<html", html.lower())
        self.assertNotIn("<body", html.lower())
        pagina = analizar(html)
        self.assertEqual(sorted(pagina.zonas), ["campos-informe", "vista-previa-informe"])
        self.assertEqual(pagina.peligrosos, [])

    def test_el_fragmento_dice_lo_mismo_que_la_pagina_completa(self):
        consulta = "plantilla=kev&sev=Critical"
        completa = self.html(f"/informes/?{consulta}")
        fragmento = self.cli.get(f"/informes/vista-previa?{consulta}").get_data(as_text=True)
        for texto in ("Esquema del documento", "Generar y descargar en Word",
                      "Enlace de este informe"):
            self.assertIn(texto, completa)
            self.assertIn(texto, fragmento)

    def test_el_fragmento_exige_sesion_y_respeta_el_alcance_del_perfil(self):
        anonimo = self.app.test_client()
        r = anonimo.get("/informes/vista-previa")
        self.assertIn(r.status_code, (302, 401, 403))
        if r.status_code == 302:
            self.assertIn("/login", r.headers.get("Location", ""))
        # Un tipo de máquina que no existe no rompe nada.
        self.assertEqual(self.cli.get("/informes/vista-previa?alcance=tipo&tipo=x").status_code,
                         200)

    def test_empezar_de_cero_no_trae_ningun_apartado_marcado(self):
        from threatintel import informe_seleccion as isel
        html = self.html(f"/informes/?plantilla={isel.PLANTILLA_LIBRE}&apartados_enviados=1")
        self.assertIn("Informe personalizado, sin plantilla", html)
        self.assertNotIn('name="apartado" value="portada"\n                   checked', html)
        self.assertIn("Todavía no ha elegido ningún apartado", html)
        # Y el botón de generar está deshabilitado con la razón escrita.
        self.assertRegex(html, r"<button[^>]*disabled[^>]*>Generar y descargar en Word")
        self.assertIn("Marque al menos un apartado", html)

    def test_al_quitar_el_ultimo_apartado_no_vuelven_los_de_la_plantilla(self):
        html = self.html("/informes/?plantilla=mensual&apartados_enviados=1")
        self.assertIn("Todavía no ha elegido ningún apartado", html)

    def test_una_plantilla_modificada_se_llama_informe_personalizado(self):
        html = self.html("/informes/?plantilla=direccion&apartado=portada&apartados_enviados=1")
        self.assertIn("Informe personalizado a partir de la plantilla", html)
        # Sin tocar nada, la plantilla sigue siendo la plantilla.
        self.assertIn("sin cambios", self.html("/informes/?plantilla=direccion"))

    def test_el_esquema_lleva_la_numeracion_real_del_documento(self):
        html = self.html("/informes/?plantilla=mensual")
        self.assertIn("Esquema del documento", html)
        # La portada y el índice no se numeran; el resumen ejecutivo es el 1.
        self.assertRegex(html, r"<strong>Portada</strong>")
        self.assertRegex(html, r"<strong>1\. Resumen ejecutivo</strong>")

    def test_la_estimacion_se_escribe_en_espanol_y_como_aproximacion(self):
        html = self.html("/informes/?plantilla=mensual")
        self.assertIn("Estimación: unas", html)
        self.assertIn("Es una aproximación", html)
        self.assertNotRegex(html, r"\d+\.\d+ segundos")


if __name__ == "__main__":
    unittest.main()
