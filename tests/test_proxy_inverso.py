"""La aplicación detrás de nginx (2026-09-08): dirección real del cliente y cookies seguras.

Hasta hoy `webui/auth.py` leía la cabecera X-Forwarded-For tal cual, sin proxy delante:
cualquier cliente podía enviarla y falsear la dirección que queda en la auditoría. Ahora la
dirección la resuelve ProxyFix (un solo salto) y SOLO cuando el ajuste `webui_tras_proxy`
está activo, que es cuando la aplicación escucha únicamente en 127.0.0.1 y nadie salvo
nginx la alcanza. Con `webui_https` la cookie de sesión lleva «Secure».
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402

CLAVE = "ClaveSegura#2026"


def _app(**ajustes):
    d = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
    ruta = str(Path(d.name) / "proxy.db")
    db.init_db(ruta)
    with db.session(ruta) as conn:
        auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin", nombre="Jefa", actor="t")
        conn.execute("UPDATE users SET must_change=0")
        for clave, valor in ajustes.items():
            conn.execute("INSERT OR REPLACE INTO settings(key, value, updated_at) VALUES(?,?,?)",
                         (clave, "true" if valor is True else "false" if valor is False else str(valor),
                          db.utcnow()))
    from webui.app import crear_app
    return d, ruta, crear_app(db_path=ruta, testing=True)


class TestDireccionReal(unittest.TestCase):

    def _ip_del_ultimo_acceso(self, ruta):
        with db.connect(ruta) as conn:
            fila = conn.execute(
                "SELECT ip FROM audit_log WHERE action LIKE 'login%' ORDER BY id DESC LIMIT 1").fetchone()
        return fila[0] if fila else None

    def test_sin_proxy_la_cabecera_x_forwarded_for_se_ignora(self):
        d, ruta, app = _app(webui_tras_proxy=False)
        self.addCleanup(d.cleanup)
        cli = app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": "mala"},
                 headers={"X-Forwarded-For": "203.0.113.9"},
                 environ_base={"REMOTE_ADDR": "10.10.11.50"})
        ip = self._ip_del_ultimo_acceso(ruta)
        self.assertIsNotNone(ip, "el intento fallido se audita")
        self.assertEqual(ip, "10.10.11.50", "sin proxy, la cabecera falsificable no manda")

    def test_detras_de_nginx_se_toma_la_direccion_que_pone_nginx(self):
        d, ruta, app = _app(webui_tras_proxy=True)
        self.addCleanup(d.cleanup)
        cli = app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": "mala"},
                 headers={"X-Forwarded-For": "10.10.11.77"},
                 environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(self._ip_del_ultimo_acceso(ruta), "10.10.11.77")

    def test_detras_de_nginx_solo_se_confia_en_un_salto(self):
        """nginx envía UN valor (su $remote_addr); si llegaran dos, el de confianza es el
        último, el que puso nginx, no el que el cliente hubiera escrito antes."""
        d, ruta, app = _app(webui_tras_proxy=True)
        self.addCleanup(d.cleanup)
        cli = app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": "mala"},
                 headers={"X-Forwarded-For": "203.0.113.9, 10.10.11.78"},
                 environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(self._ip_del_ultimo_acceso(ruta), "10.10.11.78")


class TestCookiesYEsquema(unittest.TestCase):

    def test_con_https_la_cookie_de_sesion_es_secure_y_los_enlaces_https(self):
        d, _ruta, app = _app(webui_https=True, webui_tras_proxy=True)
        self.addCleanup(d.cleanup)
        self.assertTrue(app.config["SESSION_COOKIE_SECURE"])
        self.assertEqual(app.config["PREFERRED_URL_SCHEME"], "https")
        cli = app.test_client()
        r = cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE},
                     headers={"X-Forwarded-Proto": "https"}, base_url="https://omniguard.ejemplo.local")
        cookies = "\n".join(r.headers.getlist("Set-Cookie"))
        self.assertRegex(cookies, re.compile(r"session=[^;]+;.*Secure", re.I | re.S))
        self.assertRegex(cookies, re.compile(r"HttpOnly", re.I))

    def test_sin_https_la_cookie_no_lleva_secure(self):
        d, _ruta, app = _app(webui_https=False)
        self.addCleanup(d.cleanup)
        self.assertFalse(app.config["SESSION_COOKIE_SECURE"])
        self.assertEqual(app.config["PREFERRED_URL_SCHEME"], "http")

    def _eco(self, app):
        """Ruta de eco para leer lo que la aplicación cree del esquema y del Host."""
        from flask import jsonify, request, url_for
        if "eco" not in app.view_functions:
            @app.route("/_eco_pruebas")
            def eco():
                return jsonify(scheme=request.scheme, host=request.host,
                               externo=url_for("eco", _external=True))
        return app.test_client()

    def test_sin_proxy_las_cabeceras_de_esquema_y_host_se_ignoran(self):
        d, _ruta, app = _app(webui_tras_proxy=False)
        self.addCleanup(d.cleanup)
        cli = self._eco(app)
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        r = cli.get("/_eco_pruebas", headers={"X-Forwarded-Proto": "https",
                                              "X-Forwarded-Host": "evil.example"}).get_json()
        self.assertEqual(r["scheme"], "http")
        self.assertNotIn("evil.example", r["host"])
        self.assertNotIn("evil.example", r["externo"])

    def test_con_proxy_se_toma_el_esquema_pero_nunca_el_host_reenviado(self):
        """nginx fija el Host él mismo y solo admite los dos nombres conocidos; la
        aplicación confía en X-Forwarded-Proto (para los enlaces https) pero NO en
        X-Forwarded-Host ni X-Forwarded-Port, que serían una vía de inyección de Host."""
        d, _ruta, app = _app(webui_tras_proxy=True, webui_https=True)
        self.addCleanup(d.cleanup)
        cli = self._eco(app)
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        r = cli.get("/_eco_pruebas", base_url="http://omniguard.ejemplo.local",
                    headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "evil.example",
                             "X-Forwarded-Port": "8443"}).get_json()
        self.assertEqual(r["scheme"], "https")
        self.assertEqual(r["host"], "omniguard.ejemplo.local")
        self.assertTrue(r["externo"].startswith("https://omniguard.ejemplo.local/"), r["externo"])

    def test_la_cookie_lleva_samesite_lax(self):
        d, _ruta, app = _app(webui_https=True, webui_tras_proxy=True)
        self.addCleanup(d.cleanup)
        cli = app.test_client()
        r = cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE},
                     headers={"X-Forwarded-Proto": "https"}, base_url="https://omniguard.ejemplo.local")
        cookies = "\n".join(r.headers.getlist("Set-Cookie"))
        self.assertRegex(cookies, re.compile(r"SameSite=Lax", re.I))

    def test_un_cuerpo_demasiado_grande_tiene_pagina_de_error_en_espanol(self):
        d, _ruta, app = _app()
        self.addCleanup(d.cleanup)
        cli = app.test_client()
        # Sin sesión: la vista de acceso lee el formulario y ahí salta el límite. Con sesión
        # abierta /login redirige antes de leer el cuerpo y no habría 413 que comprobar.
        r = cli.post("/login", data=b"x" * (41 * 1024 * 1024 + 10),
                     content_type="application/x-www-form-urlencoded")
        self.assertEqual(r.status_code, 413)
        html = r.get_data(as_text=True)
        # Revisión de claridad del 2026-09-15: el título habla en palabras y la unidad se
        # escribe entera («41 megabytes»), sin las siglas de los formatos admitidos.
        self.assertIn("El fichero que ha enviado es demasiado grande", html)
        self.assertIn("41 megabytes", html)
        self.assertNotIn("Request Entity Too Large", html)
        self.assertNotIn("SBOM", html)

    def test_los_tres_ajustes_estan_en_administracion(self):
        from webui.vistas import ajustes
        claves = {c[0] for grupo in ajustes.GRUPOS for c in grupo[-1]} \
            if isinstance(ajustes.GRUPOS, (list, tuple)) else set()
        if not claves:      # forma alternativa del catálogo: se busca en el texto del módulo
            import inspect
            fuente = inspect.getsource(ajustes)
            claves = set(re.findall(r'\("(webui_[a-z_]+)"', fuente))
        for clave in ("webui_https", "webui_tras_proxy", "webui_url"):
            self.assertIn(clave, claves)


if __name__ == "__main__":
    unittest.main()


class TestDireccionPublica(unittest.TestCase):
    """Un solo sitio para construir los enlaces de los correos: con webui_url definido, dos
    correos perdían su ruta profunda (/credenciales/, /fuentes/)."""

    def test_con_webui_url(self):
        from threatintel.config import url_publica
        cfg = {"webui_url": "https://omniguard.ejemplo.local/", "webui_host": "127.0.0.1", "webui_port": 9090}
        self.assertEqual(url_publica(cfg), "https://omniguard.ejemplo.local")
        self.assertEqual(url_publica(cfg, "/credenciales/"), "https://omniguard.ejemplo.local/credenciales/")
        self.assertEqual(url_publica(cfg, "fuentes/"), "https://omniguard.ejemplo.local/fuentes/")

    def test_sin_webui_url_usa_host_puerto_y_esquema(self):
        from threatintel.config import url_publica
        self.assertEqual(url_publica({"webui_host": "192.0.2.10", "webui_port": 9090}, "/"),
                         "http://192.0.2.10:9090/")
        self.assertEqual(url_publica({"webui_host": "192.0.2.10", "webui_port": 9090, "webui_https": True}),
                         "https://192.0.2.10:9090")

    def test_los_correos_conservan_la_ruta_profunda(self):
        """El correo de credenciales enlaza a /credenciales/ y el de fuentes a /fuentes/."""
        import inspect
        from threatintel import credentials, health
        self.assertIn('url_publica(cfg, "/credenciales/")', inspect.getsource(credentials))
        self.assertIn('url_publica(cfg, "/fuentes/")', inspect.getsource(health))



class TestValidacionDeAjustes(unittest.TestCase):
    """La dirección pública y la ruta del certificado se validan al guardarlas."""

    def _convertir(self, app, clave, valor):
        from webui.vistas.ajustes import _convertir
        with app.test_request_context("/ajustes/", method="POST", data={clave: valor}):
            return _convertir(clave, "texto", None)

    def test_webui_url(self):
        d, _ruta, app = _app()
        self.addCleanup(d.cleanup)
        self.assertEqual(self._convertir(app, "webui_url", " https://omniguard.ejemplo.local/ "),
                         "https://omniguard.ejemplo.local")
        self.assertEqual(self._convertir(app, "webui_url", ""), "")
        for malo in ("omniguard.ejemplo.local", "ftp://x", "https://con espacio.net", "javascript:alert(1)"):
            with self.assertRaises(ValueError, msg=malo):
                self._convertir(app, "webui_url", malo)

    def test_tls_certificado_ruta(self):
        d, _ruta, app = _app()
        self.addCleanup(d.cleanup)
        self.assertEqual(self._convertir(app, "tls_certificado_ruta", "/etc/ssl/inteligencia-amenazas/ejemplo.crt"),
                         "/etc/ssl/inteligencia-amenazas/ejemplo.crt")
        for malo in ("relativa.crt", "/etc/passwd", "/etc/ssl/inteligencia-amenazas/ejemplo.key"):
            with self.assertRaises(ValueError, msg=malo):
                self._convertir(app, "tls_certificado_ruta", malo)
