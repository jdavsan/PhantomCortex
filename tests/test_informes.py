"""Módulo de informes de la interfaz (/informes/, 2026-09-08).

El usuario pidió «un módulo para crear informes donde solo tenga acceso el rol de
operador SOC». Tras la unificación a cuatro perfiles (2026-09-15, ``auth.ROLES_INFORMES``)
ese acceso quedó exclusivamente en administración. Estas pruebas fijan lo que ese módulo
promete:

* solo entran administradores; cualquier otro perfil recibe 403 tanto en la lista como en
  la descarga, aunque lleve un token CSRF válido;
* la descarga es un .docx real (cabecera «PK» de fichero ZIP, tamaño mayor que cero) con
  el nombre «informe_amenazas_AAAA-MM.docx», generado en memoria: no aparece ningún
  fichero nuevo en reports/ ni en data/ por generarlo desde la interfaz;
* cada descarga queda en audit_log con la acción «informe.generado», el mes y quién la
  pidió, y la lista lo refleja («Generado antes: Sí»);
* los meses que no existen o no tienen datos no generan nada ni se auditan;
* la página cumple la CSP estricta (sin style= ni on*=) y lleva recorrido guiado.

El blueprint se registra aquí mismo tras crear la aplicación porque el registro en
webui/app.py lo hace el coordinador; si ya estuviera registrado no se duplica.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_informes
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR, REPORTS_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402
from webui.vistas import informes  # noqa: E402

CLAVE = "ClaveSegura#2026"
#: Por mes: (críticas, altas, medias, bajas). Agosto tiene bajas para demostrar que no
#: cuentan en las cifras de la lista (regla interna ignore_low_severity, activa).
PLAN = {
    "2026-07": (2, 1, 3, 2),
    "2026-08": (1, 2, 1, 1),
}


def _sembrar(ruta: str) -> None:
    with db.session(ruta) as conn:
        auth.crear_usuario(conn, "admin@ejemplo.local", CLAVE, rol="admin",
                           nombre="Administradora", actor="t")
        auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                           nombre="Lectora", actor="t")
        if "ciberseguridad" in auth.ROLES:
            auth.crear_usuario(conn, "operador@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Operador SOC", actor="t")
        n = 0
        for mes, (criticas, altas, medias, bajas) in PLAN.items():
            plan = ([("Critical", 9.8)] * criticas + [("High", 7.5)] * altas
                    + [("Medium", 5.0)] * medias + [("Low", 3.1)] * bajas)
            for sev, cvss in plan:
                n += 1
                conn.execute(
                    """INSERT INTO threats(fingerprint,cve,title_en,summary_en,severity,
                           severity_source,cvss_score,in_kev,first_seen_at,last_seen_at,
                           times_seen,month,relevance,estado)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'nueva')""",
                    (f"fp-{n:04d}", f"CVE-2026-{n:04d}", f"Amenaza {n}", "Resumen de prueba",
                     sev, "nvd", cvss, 1 if n % 4 == 0 else 0,
                     f"{mes}-10 08:00:00", f"{mes}-10 08:00:00", 1, mes, 60.0))


def _app(ruta: str, *, registrar: bool = True):
    from webui.app import crear_app
    app = crear_app(db_path=ruta, testing=True)
    if registrar and "informes" not in app.blueprints:
        app.register_blueprint(informes.bp)
    return app


def _atributos_peligrosos(html: str) -> list[str]:
    from html.parser import HTMLParser

    class Recolector(HTMLParser):
        def __init__(self):
            super().__init__()
            self.malos: list[str] = []

        def handle_starttag(self, tag, attrs):
            for nombre, _ in attrs:
                n = (nombre or "").lower()
                if n == "style" or n.startswith("on"):
                    self.malos.append(f"<{tag} {n}>")

    r = Recolector()
    r.feed(html)
    return r.malos


class BaseInformes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "informes.db")
        db.init_db(cls.ruta)
        _sembrar(cls.ruta)
        cls.app = _app(cls.ruta)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, usuario: str):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": CLAVE})
        return cli

    def _csrf(self, cli, url: str = "/") -> str:
        html = cli.get(url, follow_redirects=True).get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def _auditoria(self) -> list[dict]:
        """Filas de audit_log de la acción del módulo. La base es común a toda la
        clase, así que cada prueba compara antes y después en vez de exigir que esté
        vacía."""
        with db.session(self.ruta) as conn:
            return [dict(f) for f in conn.execute(
                "SELECT * FROM audit_log WHERE action=? ORDER BY id",
                (informes.ACCION_AUDITORIA,))]


class TestPermiso(BaseInformes):
    """«Donde solo tenga acceso el rol de operador SOC» (y los administradores)."""

    def test_sin_sesion_redirige_al_acceso(self):
        r = self.app.test_client().get("/informes/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_solo_lectura_recibe_403_en_lista_y_descarga(self):
        lectora = self._cliente("lectora@ejemplo.local")
        antes = len(self._auditoria())
        self.assertEqual(lectora.get("/informes/").status_code, 403)
        csrf = self._csrf(lectora)
        r = lectora.post("/informes/2026-08/descargar", data={"csrf": csrf})
        self.assertEqual(r.status_code, 403, "ni con CSRF válido")
        self.assertEqual(len(self._auditoria()), antes, "un intento rechazado no cuenta como generado")

    def test_administrador_ve_la_lista(self):
        admin = self._cliente("admin@ejemplo.local")
        r = admin.get("/informes/")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("agosto de 2026", html)
        self.assertIn("julio de 2026", html)
        self.assertIn("Generar y descargar", html)
        # Agosto primero (más reciente) y julio después.
        self.assertLess(html.index("agosto de 2026"), html.index("julio de 2026"))

    def test_puede_generar_informes_sigue_al_perfil(self):
        """La regla está en una sola función, ``auth.ROLES_INFORMES`` (solo admin)."""
        with self.app.test_request_context():
            from flask import g
            g._sesion_fila = {"username": "x", "role": "admin", "csrf": "c",
                              "expires_at": "2999-01-01T00:00:00Z", "mfa_pendiente": 0}
            self.assertTrue(informes._puede_generar_informes())
            g._sesion_fila = dict(g._sesion_fila, role="ciberseguridad")
            self.assertFalse(informes._puede_generar_informes())
            g._sesion_fila = dict(g._sesion_fila, role="redes")
            self.assertFalse(informes._puede_generar_informes())
            g._sesion_fila = dict(g._sesion_fila, role="mantenimiento")
            self.assertFalse(informes._puede_generar_informes())


class TestDescarga(BaseInformes):

    def test_post_sin_csrf_se_rechaza(self):
        admin = self._cliente("admin@ejemplo.local")
        antes = len(self._auditoria())
        r = admin.post("/informes/2026-08/descargar", data={})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(len(self._auditoria()), antes)

    def test_descarga_docx_valido_y_queda_en_auditoria(self):
        admin = self._cliente("admin@ejemplo.local")
        csrf = self._csrf(admin)
        antes = sorted(p.name for p in REPORTS_DIR.glob("*.docx")) if REPORTS_DIR.exists() else []
        auditadas_antes = len(self._auditoria())
        r = admin.post("/informes/2026-08/descargar", data={"csrf": csrf})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.mimetype, informes.MIME_DOCX)
        self.assertIn('attachment; filename="informe_amenazas_2026-08.docx"',
                      r.headers.get("Content-Disposition", ""))
        self.assertTrue(r.data.startswith(b"PK"), "un .docx es un fichero ZIP: empieza por PK")
        self.assertGreater(len(r.data), 0)
        self.assertEqual(int(r.headers.get("Content-Length", "0")), len(r.data))
        # Se abre como documento Word y habla del mes pedido.
        import io
        from docx import Document
        doc = Document(io.BytesIO(r.data))
        texto = "\n".join(p.text for p in doc.paragraphs)
        self.assertIn("2026", texto)
        # En memoria: la generación desde la interfaz no deja ficheros en reports/.
        despues = sorted(p.name for p in REPORTS_DIR.glob("*.docx")) if REPORTS_DIR.exists() else []
        self.assertEqual(antes, despues)
        # Auditoría: quién, qué mes y qué acción.
        filas = self._auditoria()
        self.assertEqual(len(filas), auditadas_antes + 1)
        ultima = filas[-1]
        self.assertEqual(ultima["username"], "admin@ejemplo.local")
        self.assertEqual(ultima["entity_id"], "2026-08")
        self.assertEqual(ultima["entity"], "informes")
        self.assertIn("agosto de 2026", ultima["detail"])
        self.assertIn("informe_amenazas_2026-08.docx", ultima["detail"])
        # Y la lista lo dice: solo en la fila de agosto (julio no se ha generado desde la
        # interfaz; si en reports/ existe el .docx de la ejecución programada, la fila lo
        # atribuye a esa ejecución, no a una persona).
        html = admin.get("/informes/").get_data(as_text=True)
        self.assertEqual(html.count("por admin@ejemplo.local"), 1)
        fila_julio = html.split("julio de 2026", 1)[1]
        self.assertTrue("Todavía no" in fila_julio or "ejecución mensual programada" in fila_julio)

    def test_mes_invalido_o_sin_datos_no_genera_nada(self):
        admin = self._cliente("admin@ejemplo.local")
        csrf = self._csrf(admin)
        antes = len(self._auditoria())
        for mes in ("2026-13", "x", "2026-8", "2020-01"):
            with self.subTest(mes=mes):
                r = admin.post(f"/informes/{mes}/descargar", data={"csrf": csrf},
                               follow_redirects=True)
                self.assertEqual(r.status_code, 200)
                html = r.get_data(as_text=True)
                self.assertTrue("no es válido" in html or "No hay amenazas registradas" in html, mes)
        self.assertEqual(len(self._auditoria()), antes)

    def test_el_informe_de_la_interfaz_no_llama_al_modelo_de_lenguaje(self):
        """Medido el 2026-09-08: con Ollama activo la redacción del resumen ejecutivo
        tardó 200 segundos y nginx corta a los 120; la descarga nunca llegaría. La
        configuración envuelta apaga solo ese motor y deja intacto todo lo demás."""
        class Cfg:
            def get(self, key, default=None):
                return {"translate_engine": "hybrid", "ignore_low_severity": True}.get(key, default)
            report_to = ["soc@ejemplo.test"]

        envuelta = informes._cfg_para_interfaz(Cfg())
        self.assertEqual(envuelta.get("translate_engine"), "none")
        self.assertEqual(envuelta.get("translate_engine", "hybrid"), "none")
        self.assertTrue(envuelta.get("ignore_low_severity"))
        self.assertEqual(envuelta.get("otra_clave", 7), 7)
        self.assertEqual(envuelta.report_to, ["soc@ejemplo.test"])

    def test_nombre_de_fichero_y_validacion_de_mes(self):
        self.assertEqual(informes.nombre_fichero("2026-08"), "informe_amenazas_2026-08.docx")
        self.assertTrue(informes.mes_valido("2026-12"))
        for malo in ("2026-13", "2026-00", "202608", "../2026-08", "", None):
            self.assertFalse(informes.mes_valido(malo), repr(malo))


class TestListaYPlantilla(BaseInformes):

    def test_cifras_por_mes_sin_bajas_y_con_unidad(self):
        with db.session(self.ruta) as conn:
            filas = informes.meses_para_informe(conn, excluir_bajas=True)
        self.assertEqual([f["mes"] for f in filas], ["2026-08", "2026-07"])
        agosto = filas[0]
        self.assertEqual((agosto["criticas"], agosto["altas"], agosto["medias"]), (1, 2, 1))
        self.assertEqual(agosto["total"], 4, "las bajas no cuentan")
        self.assertEqual(agosto["nombre"], "agosto de 2026")
        self.assertIsNone(agosto["generado"])
        with db.session(self.ruta) as conn:
            con_bajas = informes.meses_para_informe(conn, excluir_bajas=False)
        self.assertEqual(con_bajas[0]["total"], 5)
        admin = self._cliente("admin@ejemplo.local")
        html = admin.get("/informes/").get_data(as_text=True)
        self.assertIn("amenazas", html)
        self.assertIn(">1 crítica<", html)
        self.assertIn(">2 altas<", html)

    def test_csp_estricta_y_recorrido(self):
        admin = self._cliente("admin@ejemplo.local")
        r = admin.get("/informes/")
        html = r.get_data(as_text=True)
        self.assertEqual(_atributos_peligrosos(html), [])
        self.assertNotIn("<script>", html.replace('<script src="', ""))
        self.assertIn("default-src 'none'", r.headers.get("Content-Security-Policy", ""))
        plantilla = (BASE_DIR / "webui" / "templates" / "informes.html").read_text(encoding="utf-8")
        pasos = re.findall(r'data-tour="(\d+)"', plantilla)
        self.assertGreaterEqual(len(pasos), 2)
        self.assertEqual(len(pasos), len(set(pasos)))
        for palabra in ("Informes", "Meses disponibles", "Generar y descargar"):
            self.assertIn(palabra, html)

    def test_lista_vacia_sin_amenazas(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as d:
            ruta = str(Path(d) / "vacia.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                auth.crear_usuario(conn, "admin@ejemplo.local", CLAVE, rol="admin", actor="t")
            app = _app(ruta)
            cli = app.test_client()
            cli.post("/login", data={"usuario": "admin@ejemplo.local", "password": CLAVE})
            r = cli.get("/informes/")
            self.assertEqual(r.status_code, 200)
            self.assertIn("Todavía no hay amenazas registradas", r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
