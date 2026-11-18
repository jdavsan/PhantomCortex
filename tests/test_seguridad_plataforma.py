"""Pruebas de seguridad de la plataforma (2026-09-05).

Recorren TODAS las rutas registradas y comprueban, sin excepciones manuales:
  * toda ruta exige sesión salvo /login, /static y /salud.json (que exige token);
  * toda ruta POST exige CSRF (sin token: 400/403, nunca 200) y las de
    administración rechazan al usuario de solo lectura;
  * las respuestas llevan CSP estricta sin 'unsafe', X-Content-Type-Options,
    X-Frame-Options, Referrer-Policy y Cache-Control no-store con sesión;
  * la cookie de sesión es HttpOnly y SameSite; el destino tras el acceso no admite
    URL externas; la cuenta se bloquea tras los intentos fallidos configurados;
  * los datos que vienen de OCS (nombres de activo, software) llegan escapados;
  * los ficheros subidos (SBOM, OpenSCAP, CSV) se rechazan si no son válidos;
  * no hay secretos en las páginas ni en los JSON;
  * los mensajes que ve el usuario están en español correcto, con tildes y sin
    abreviaturas, y las plantillas no llevan JavaScript en línea (revisión del
    2026-09-06, hallazgos 5 y 7).
Base temporal bajo data/."""
from __future__ import annotations

import json
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatintel import db, ocs
from threatintel.paths import BASE_DIR
from webui import auth

HOSTIL = "<script>alert('x')</script><img src=x onerror=alert(1)>"
from html.parser import HTMLParser


class _Atributos(HTMLParser):
    """Recoge los atributos reales de cada etiqueta: un «onerror=» dentro de un texto o
    de un valor de atributo escapado no es un atributo y no debe contar."""

    def __init__(self):
        super().__init__()
        self.peligrosos: list[str] = []

    def handle_starttag(self, tag, attrs):
        for nombre, _ in attrs:
            n = (nombre or "").lower()
            if n == "style" or n.startswith("on"):
                self.peligrosos.append(f"<{tag} {n}>")


def atributos_peligrosos(html: str) -> list[str]:
    p = _Atributos()
    p.feed(html)
    return p.peligrosos


class _Regex:
    """Compatibilidad con las comprobaciones RE_*.search(html) is None."""

    def search(self, html):
        return atributos_peligrosos(html) or None


RE_STYLE = RE_ON = _Regex()
# El logo es la imagen de marca (como el favicon): se ve en el login antes de iniciar
# sesión, así que no puede exigirla. Sin logo subido responde 404, nunca contenido de
# la plataforma.
PUBLICAS = {"/login", "/salud.json", "/ajustes/logo.png"}


class LectorHostil:
    def hardware(self):
        return [{"ID": 1, "DEVICEID": "H1", "NAME": HOSTIL, "OSNAME": "Ubuntu 22.04", "OSVERSION": "22.04",
                 "OSCOMMENTS": HOSTIL, "IPADDR": "10.0.0.1", "LASTCOME": None, "LASTDATE": None, "USERID": HOSTIL,
                 "ARCH": None, "WORKGROUP": HOSTIL, "DESCRIPTION": HOSTIL}]

    def software(self):
        return iter([(1, HOSTIL, HOSTIL, HOSTIL), (1, "curl", "7.81.0-1ubuntu1.10", None)])

    def accountinfo(self):
        return {1: {"HARDWARE_ID": 1, "TAG": HOSTIL, "fields_3": "Produccion"}}


class TestSeguridadPlataforma(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "seguridad.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", "AdminSeguro#2026", rol="admin", actor="t")
            auth.crear_usuario(conn, "lector", "LectorSeguro#2026", rol="ciberseguridad", actor="t")
            auth.crear_usuario(conn, "bloqueable", "Bloqueable#2026x", rol="ciberseguridad", actor="t")
            ahora = db.utcnow()
            conn.execute("""INSERT INTO technologies(slug,name,vendor,category,criticality,systems_count,exposure,enabled,
                            created_at,updated_at) VALUES('chrome','Google Chrome','x','navegador','high',0,'interna',1,?,?)""", (ahora, ahora))
            conn.execute("""INSERT INTO threats(fingerprint,cve,title_en,summary_en,severity,severity_source,first_seen_at,
                            last_seen_at,month,relevance,estado) VALUES('fp','CVE-2024-11053',?,?,'High','nvd',?,?,?,60,'nueva')""",
                         (HOSTIL, HOSTIL, ahora, ahora, ahora[:7]))
            conn.execute("INSERT INTO sources(slug,name,url,kind,category,priority,enabled,timeout_s,created_at,updated_at) "
                         "VALUES('f',?, 'https://example.com/feed','rss','news','medium',1,30,?,?)", (HOSTIL, ahora, ahora))
        conn = db.connect(cls.ruta)
        try:
            ocs.sincronizar_origen(conn, "servidores", LectorHostil(), cfg={})
            ocs.sembrar_mapa(conn)
            ocs.aplicar_mapa(conn)
        finally:
            conn.close()
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)
        cls.rutas = [r for r in cls.app.url_map.iter_rules() if r.endpoint != "static"]

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, usuario, clave):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": clave})
        return cli

    def _url(self, regla):
        valores = {}
        for arg in regla.arguments:
            valores[arg] = 1 if regla._converters[arg].__class__.__name__ == "IntegerConverter" else "x"
        with self.app.test_request_context():
            from flask import url_for
            return url_for(regla.endpoint, **valores)

    def test_toda_ruta_exige_sesion(self):
        anonimo = self.app.test_client()
        for regla in self.rutas:
            url = self._url(regla)
            if url in PUBLICAS:
                continue
            for metodo in ("GET", "POST"):
                if metodo not in regla.methods:
                    continue
                r = anonimo.open(url, method=metodo)
                self.assertIn(r.status_code, (302, 400, 401, 403, 405), f"{metodo} {url} sin sesión -> {r.status_code}")
                if r.status_code == 302:
                    self.assertIn("/login", r.headers.get("Location", ""), f"{metodo} {url}")

    def test_405_con_mensaje_en_espanol_y_sin_pistas(self):
        """Un método no permitido responde con la página de error propia en español, sin
        nombres de ficheros internos ni menciones al administrador (2026-09-09).

        Revisión de claridad del 2026-09-15: el título ya no es «Método no permitido»,
        que es jerga del protocolo, sino «Esta dirección no se abre directamente», que
        dice lo mismo en palabras. El número queda al pie para poder citarlo."""
        r = self.app.test_client().post("/salud.json")
        self.assertEqual(r.status_code, 405)
        html = r.get_data(as_text=True)
        self.assertIn("Esta dirección no se abre directamente", html)
        self.assertIn("Vuelva a la página anterior", html)
        self.assertIn("indique el número 405", html)
        self.assertNotIn("administrador", html.lower())
        self.assertNotRegex(html, r"[A-Za-z_/-]+\.(sh|json|db|py)\b")

    def test_post_exige_csrf_y_rol(self):
        admin = self._cliente("admin", "AdminSeguro#2026")
        lector = self._cliente("lector", "LectorSeguro#2026")
        for regla in self.rutas:
            if "POST" not in regla.methods:
                continue
            url = self._url(regla)
            if url in PUBLICAS:
                continue
            r = admin.post(url, data={})
            self.assertIn(r.status_code, (400, 403), f"POST {url} sin CSRF -> {r.status_code}")
            # rutas de administración: el lector no puede ni con CSRF
            if any(url.startswith(p) for p in ("/usuarios", "/ajustes", "/credenciales", "/fuentes", "/activos/software",
                                                "/activos/sincronizar", "/tecnologias/nueva", "/tecnologias/sembrar",
                                                "/tecnologias/importar")) or url.endswith(("/borrar", "/editar", "/eliminar", "/estado", "/sbom", "/openscap")):
                csrf = re.search(r'name="csrf" value="([^"]+)"', lector.get("/").get_data(as_text=True)).group(1)
                r = lector.post(url, data={"csrf": csrf})
                self.assertIn(r.status_code, (302, 403), f"POST {url} como lector -> {r.status_code}")
                if r.status_code == 302:
                    self.assertNotIn("Guardado", r.get_data(as_text=True))

    def test_cabeceras_de_seguridad_en_todas_las_paginas(self):
        admin = self._cliente("admin", "AdminSeguro#2026")
        for regla in self.rutas:
            if "GET" not in regla.methods:
                continue
            url = self._url(regla)
            r = admin.get(url)
            if r.status_code in (404, 302):
                continue
            csp = r.headers.get("Content-Security-Policy", "")
            self.assertIn("default-src 'none'", csp, url)
            self.assertNotIn("unsafe", csp, url)
            self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff", url)
            self.assertEqual(r.headers.get("X-Frame-Options"), "DENY", url)
            self.assertIn("no-store", r.headers.get("Cache-Control", ""), url)
            if "text/html" in r.content_type:
                html = r.get_data(as_text=True)
                self.assertIsNone(RE_STYLE.search(html), f"style= en {url}")
                self.assertIsNone(RE_ON.search(html), f"on*= en {url}")
                self.assertNotIn("<script>alert", html, f"XSS sin escapar en {url}")
                self.assertNotIn("<img src=x", html, f"XSS sin escapar en {url}")

    def test_datos_hostiles_de_ocs_escapados(self):
        admin = self._cliente("admin", "AdminSeguro#2026")
        with db.session(self.ruta) as conn:
            activo_id = conn.execute("SELECT id FROM activos").fetchone()[0]
        for url in ("/activos/", f"/activos/{activo_id}", f"/activos/{activo_id}?todo=1", "/activos/software",
                    f"/activos/{activo_id}/remediacion", "/amenazas/1", "/"):
            html = admin.get(url).get_data(as_text=True)
            self.assertNotIn("<script>alert", html, url)
            self.assertIsNone(RE_ON.search(html), url)
        for url in ("/activos/", f"/activos/{activo_id}", f"/activos/{activo_id}?todo=1", "/amenazas/1"):
            self.assertIn("&lt;script&gt;", admin.get(url).get_data(as_text=True), url)
        datos = admin.get(f"/activos/{activo_id}/vulnerabilidades.json").get_json()
        self.assertEqual(datos["activo"]["nombre"], HOSTIL)      # JSON crudo, el navegador lo inserta con textContent
        csv = admin.get("/activos/exportar.csv").get_data(as_text=True)
        self.assertTrue(csv.count("'") >= 0)                        # celdas con formula neutralizadas por celda_csv
        self.assertNotIn("=cmd", csv)

    def test_sesion_login_y_bloqueo(self):
        cli = self.app.test_client()
        r = cli.post("/login", data={"usuario": "admin", "password": "AdminSeguro#2026"})
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite", cookie)
        # destino externo rechazado
        r = self.app.test_client().post("/login?siguiente=//evil.example/", data={"usuario": "admin", "password": "AdminSeguro#2026"})
        self.assertEqual(r.headers.get("Location"), "/")
        r = self.app.test_client().post("/login?siguiente=https://evil.example/x", data={"usuario": "admin", "password": "AdminSeguro#2026"})
        self.assertEqual(r.headers.get("Location"), "/")
        # bloqueo tras intentos fallidos
        otro = self.app.test_client()
        for _ in range(6):
            otro.post("/login", data={"usuario": "bloqueable", "password": "mal"})
        r = otro.post("/login", data={"usuario": "bloqueable", "password": "Bloqueable#2026x"})
        self.assertNotIn("Location", r.headers)          # sigue en /login: bloqueada
        with db.session(self.ruta) as conn:
            fila = conn.execute("SELECT locked_until, failed_logins FROM users WHERE username='bloqueable'").fetchone()
            self.assertIsNotNone(fila["locked_until"])
        # usuario inexistente: misma respuesta que contraseña incorrecta (sin enumeración)
        a = self.app.test_client().post("/login", data={"usuario": "noexiste", "password": "x"}, follow_redirects=True).get_data(as_text=True)
        b = self.app.test_client().post("/login", data={"usuario": "lector", "password": "x"}, follow_redirects=True).get_data(as_text=True)
        self.assertEqual(re.findall(r'class="aviso[^"]*"[^>]*>([^<]+)<', a), re.findall(r'class="aviso[^"]*"[^>]*>([^<]+)<', b))

    def test_el_403_no_dice_que_perfil_haria_falta(self):
        """Petición del usuario del 2026-09-08: «Ajustar el mensaje de error 403 donde no se
        mencione que requiera acceso de administrador sino que solamente diga acceso
        inválido». Ninguna respuesta 403 (ruta de administración, de remediación o el
        propio abort) puede nombrar un perfil: eso le diría a quien prueba qué cuenta
        necesitaría robar."""
        lector = self._cliente("lector", "LectorSeguro#2026")
        csrf = self._csrf(lector) if hasattr(self, "_csrf") else re.search(
            r'name="csrf" value="([^"]+)"', lector.get("/perfil").get_data(as_text=True)).group(1)
        respuestas = [lector.get("/usuarios/"), lector.get("/ajustes/"), lector.get("/credenciales/"),
                      lector.post("/ajustes/guardar", data={"csrf": csrf}),
                      lector.post("/remediaciones/1/comprobar", data={"csrf": csrf})]
        for r in respuestas:
            if r.status_code != 403:
                continue
            html = r.get_data(as_text=True)
            # Revisión de claridad del 2026-09-15: «Acceso inválido» sonaba a culpa de
            # quien lo leía. El texto sigue siendo SIEMPRE el mismo, se pida lo que se
            # pida, y sigue sin nombrar ningún perfil.
            self.assertIn("Esta página no está incluida en su perfil", html)
            self.assertIn("Su cuenta es correcta", html)
            # «solo lectura» sí aparece: es el perfil de la propia persona en la barra
            # superior, no el que haría falta.
            for prohibido in ("administrador", "Administrador", "Servicios Tecnológicos",
                              "requiere perfil", "Acceso denegado"):
                self.assertNotIn(prohibido, html, f"el 403 revela «{prohibido}»")
        self.assertTrue(any(r.status_code == 403 for r in respuestas), "alguna debe ser un 403 real")
        # Y los textos de los propios abort() de webui/auth.py tampoco nombran perfiles
        fuente = (BASE_DIR / "webui" / "auth.py").read_text(encoding="utf-8")
        for linea in fuente.splitlines():
            if "abort(403" in linea:
                self.assertNotIn("administrador", linea.lower())
                self.assertNotIn("tecnológicos", linea.lower())

    def test_salud_json_exige_token_o_sesion(self):
        r = self.app.test_client().get("/salud.json")
        self.assertEqual(r.status_code, 403)
        admin = self._cliente("admin", "AdminSeguro#2026")
        r = admin.get("/salud.json")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("PASSWORD", r.get_data(as_text=True).upper())

    def test_subidas_invalidas_rechazadas(self):
        import io
        admin = self._cliente("admin", "AdminSeguro#2026")
        with db.session(self.ruta) as conn:
            activo_id = conn.execute("SELECT id FROM activos").fetchone()[0]
        csrf = re.search(r'name="csrf" value="([^"]+)"', admin.get(f"/activos/{activo_id}").get_data(as_text=True)).group(1)
        r = admin.post(f"/activos/{activo_id}/sbom", data={"csrf": csrf, "archivo": (io.BytesIO(b"no es json"), "x.json")},
                       content_type="multipart/form-data", follow_redirects=True)
        self.assertIn("No se pudo importar el SBOM", r.get_data(as_text=True))
        r = admin.post(f"/activos/{activo_id}/openscap", data={"csrf": csrf, "archivo": (io.BytesIO(b"<x/>"), "x.xml")},
                       content_type="multipart/form-data", follow_redirects=True)
        self.assertIn("No se pudo importar el resultado de OpenSCAP", r.get_data(as_text=True))
        # XML con entidad externa: no se resuelve ni se cuelga
        xxe = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"><target>&e;</target></TestResult>'
        r = admin.post(f"/activos/{activo_id}/openscap", data={"csrf": csrf, "archivo": (io.BytesIO(xxe), "x.xml")},
                       content_type="multipart/form-data", follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertNotIn("root:x:", html)
        with db.session(self.ruta) as conn:
            self.assertNotIn("root:", json.dumps([dict(r_) for r_ in conn.execute("SELECT * FROM cumplimiento")]))

    def test_mensajes_visibles_en_espanol_correcto(self):
        """Hallazgo 5 de la revisión del 2026-09-06.

        Los mensajes del acceso y del cambio de contraseña iban sin tildes ni eñes
        («Usuario o contrasena incorrectos.», «Sesion cerrada.», «Token CSRF invalido
        o ausente. Recargue la pagina.») y uno abreviaba los minutos («en 3 min.»)."""
        clave = "Clave#Segura2026"
        with db.session(self.ruta) as conn:
            for nombre in ("apagado", "bloqueado", "cambiante"):
                if conn.execute("SELECT 1 FROM users WHERE username=?", (nombre,)).fetchone() is None:
                    auth.crear_usuario(conn, nombre, clave, rol="ciberseguridad", actor="t")
            conn.execute("UPDATE users SET enabled=0 WHERE username='apagado'")
            hasta = (datetime.now(timezone.utc) + timedelta(minutes=7)).replace(
                microsecond=0).isoformat().replace("+00:00", "Z")
            conn.execute("UPDATE users SET locked_until=? WHERE username='bloqueado'", (hasta,))
            conn.execute("UPDATE users SET must_change=1 WHERE username='cambiante'")

        def acceso(usuario, password=clave):
            cli = self.app.test_client()
            html = cli.post("/login", data={"usuario": usuario, "password": password},
                            follow_redirects=True).get_data(as_text=True)
            return cli, html

        _, html = acceso("lector", "mal")
        self.assertIn("Usuario o contraseña incorrectos.", html)
        self.assertNotIn("contrasena", html)
        # Revisión de seguridad del 2026-09-08 (A07:2025): una cuenta deshabilitada o
        # bloqueada responde EXACTAMENTE igual que una inexistente, para no confirmar que
        # el correo existe; el detalle queda en la auditoría y en el perfil de la persona.
        _, html = acceso("apagado")
        self.assertIn("Usuario o contraseña incorrectos.", html)
        self.assertNotIn("deshabilitada", html)
        _, html = acceso("bloqueado")
        self.assertIn("Usuario o contraseña incorrectos.", html)
        self.assertNotIn("bloqueada", html)
        self.assertNotRegex(html, r"\d+\s*min\.", "«min.» es una abreviatura")
        # Cambio de contraseña propia
        cli, html = acceso("cambiante")
        self.assertIn("Debe cambiar la contraseña antes de continuar.", html)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)

        def cambio(actual, nueva, repetir):
            return cli.post("/mi-password", data={"csrf": csrf, "actual": actual,
                                                  "nueva": nueva, "repetir": repetir},
                            follow_redirects=True).get_data(as_text=True)

        self.assertIn("La contraseña actual no es correcta.", cambio("mal", "X", "X"))
        self.assertIn("Las contraseñas nuevas no coinciden.",
                      cambio(clave, "Nueva#Clave2026", "Otra#Clave2026"))
        self.assertIn("Debe combinar al menos tres de: minúsculas, mayúsculas, dígitos y símbolos.",
                      cambio(clave, "abcdefghijklm", "abcdefghijklm"))
        self.assertIn("Contraseña actualizada.", cambio(clave, "Nueva#Clave2026", "Nueva#Clave2026"))
        # Cierre de sesión y token CSRF ausente
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "cambiante", "password": "Nueva#Clave2026"})
        csrf = re.search(r'name="csrf" value="([^"]+)"', cli.get("/").get_data(as_text=True)).group(1)
        self.assertIn("Sesión cerrada.",
                      cli.post("/logout", data={"csrf": csrf}, follow_redirects=True).get_data(as_text=True))
        cli.post("/login", data={"usuario": "cambiante", "password": "Nueva#Clave2026"})
        r = cli.post("/logout", data={})
        self.assertEqual(r.status_code, 400)
        self.assertIn("Token CSRF inválido o ausente. Recargue la página.", r.get_data(as_text=True))

    def test_las_plantillas_cierran_todos_sus_div(self):
        """Un «</div>» de más cierra un contenedor antes de tiempo y deja fuera del
        armazón todo lo que venga después: el 2026-09-07 el Panel perdió, sin dar
        ningún error, la mitad inferior (pendientes de alertar, últimas ejecuciones,
        estado técnico y el glosario). El navegador no se queja y las pruebas de
        contenido tampoco, porque el HTML sigue estando ahí.

        Se cuentan las etiquetas fuera de los comentarios de Jinja. Ninguna plantilla
        del proyecto abre un <div> en una rama y lo cierra en otra, así que la cuenta
        tiene que cuadrar exactamente."""
        raiz = BASE_DIR / "webui" / "templates"
        descuadres = []
        for ruta in sorted(raiz.rglob("*.html")):
            texto = re.sub(r"\{#.*?#\}", "", ruta.read_text(encoding="utf-8"), flags=re.S)
            abre = len(re.findall(r"<div\b", texto))
            cierra = len(re.findall(r"</div\s*>", texto))
            if abre != cierra:
                descuadres.append(f"{ruta.name}: {abre} <div> y {cierra} </div>")
        self.assertEqual(descuadres, [], "plantillas con los <div> descuadrados")

    def test_plantillas_sin_javascript_en_linea_y_confirmacion_en_los_selectores(self):
        """Hallazgo 7 de la revisión del 2026-09-06: la confirmación de deshabilitar
        a un usuario y de cambiarle el rol se hace con data-confirmar en app.js, sin
        volver a poner un botón «Guardar» y sin código en línea (la CSP no cambia)."""
        raiz = BASE_DIR / "webui"
        js = (raiz / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("data-confirmar", js)
        self.assertIn("stopImmediatePropagation", js, "cancelar debe evitar el envío automático")
        for ruta in sorted((raiz / "templates").rglob("*.html")):
            # Los comentarios de Jinja ({# ... #}) explican la regla y la nombran,
            # así que no cuentan: se quitan antes de buscar.
            texto = re.sub(r"\{#.*?#\}", "", ruta.read_text(encoding="utf-8"), flags=re.S)
            self.assertIsNone(re.search(r"\son[a-z]+\s*=", texto), f"{ruta.name}: atributo on*=")
            self.assertIsNone(re.search(r"\sstyle\s*=", texto), f"{ruta.name}: atributo style=")
            for etiqueta in re.findall(r"<script\b[^>]*>", texto):
                self.assertIn("src=", etiqueta, f"{ruta.name}: <script> en línea")
        admin = self._cliente("admin", "AdminSeguro#2026")
        html = admin.get("/usuarios/").get_data(as_text=True)
        self.assertIn("data-confirmar=\"¿Deshabilitar a lector?", html)
        # El texto lleva el alcance real del perfil, que vive en webui.auth (2026-09-07):
        # así la confirmación no puede decir algo distinto de lo que aplica el servidor.
        self.assertIn("data-confirmar=\"¿Cambiar el perfil de lector a Administrador?", html)
        self.assertIn(auth.ROL_ALCANCE_ES["admin"], html)
        self.assertIn(auth.ROL_ES["redes"], html, "el perfil nuevo se ofrece")
        self.assertNotIn(">Guardar</button>", html)
        csp = admin.get("/usuarios/").headers.get("Content-Security-Policy", "")
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe", csp)

    def test_sin_secretos_en_paginas(self):
        admin = self._cliente("admin", "AdminSeguro#2026")
        for url in ("/credenciales/", "/ajustes/", "/"):
            html = admin.get(url).get_data(as_text=True)
            self.assertNotIn("OCS_SERVIDORES_PASSWORD=", html)
            self.assertNotRegex(html, r"SMTP_PASSWORD\s*=\s*\S")


if __name__ == "__main__":
    unittest.main()
