"""Alertas por proceso de negocio (v6, 2026-09-05): destino y activación propios por proceso.

Sin red ni correo real: el Mailer se sustituye por un doble que guarda los argumentos.
Base temporal bajo data/ con activos de dos procesos («Pila», con servidores en producción
y en desarrollo, y «Helpvoz», solo producción), tres amenazas y filas de aplicabilidad.
Cubre: recuentos por proceso, validación al guardar (correo inválido, activación sin
correo, varios correos, proceso inexistente), envío solo al proceso activo con solo sus
amenazas y servidores, filtro «solo producción y contingencia», dry_run sin registro,
registro de envíos y último envío, contenido del correo (servidores y enlaces con la URL
base), errores del Mailer capturados, y la página web (permisos, CSRF, guardar, prueba)."""
from __future__ import annotations

import dataclasses
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from threatintel import alertas_proceso as ap
from threatintel import config, db, notify
from threatintel.paths import BASE_DIR
from webui import auth

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)


class Cfg(dict):
    """Config mínima con .get, como la usa alertas_proceso.enviar."""

    def get(self, k, d=None):
        return super().get(k, d)


class MailerFalso:
    def __init__(self, resultado=True, excepcion=None):
        self.enviados: list[dict] = []
        self.resultado = resultado
        self.excepcion = excepcion

    def send(self, **kwargs):
        if self.excepcion:
            raise self.excepcion
        self.enviados.append(kwargs)
        return self.resultado


def _activo(conn, ocs_id, nombre, *, proceso, entorno, ip, presente=1, so="Ubuntu 22.04"):
    ahora = db.utcnow()
    conn.execute(
        """INSERT INTO activos(origen, ocs_id, nombre, so_nombre, so_familia, ip, entorno, proceso, presente,
                               primera_vez_at, visto_at)
           VALUES('servidores', ?, ?, ?, 'ubuntu', ?, ?, ?, ?, ?, ?)""",
        (ocs_id, nombre, so, ip, entorno, proceso, presente, ahora, ahora))
    return conn.execute("SELECT id FROM activos WHERE nombre=?", (nombre,)).fetchone()[0]


def _amenaza(conn, fp, cve, titulo, severidad, relevancia, kev=0):
    ahora = db.utcnow()
    conn.execute(
        """INSERT INTO threats(fingerprint, cve, title_en, title_es, summary_en, severity, severity_source,
                               first_seen_at, last_seen_at, month, relevance, estado, in_kev, impact_es)
           VALUES(?,?,?,?,?,?,'nvd',?,?,?,?,'nueva',?,?)""",
        (fp, cve, titulo, titulo, f"Descripción de {cve}", severidad, ahora, ahora, ahora[:7], relevancia, kev,
         f"Impacto de {cve} para la organización"))
    return conn.execute("SELECT id FROM threats WHERE fingerprint=?", (fp,)).fetchone()[0]


def _afectado(conn, activo_id, threat_id, cve, paquete, instalada, corregida):
    conn.execute(
        """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada, version_corregida,
                                     veredicto, motor, evaluado_at) VALUES(?,?,?,?,?,?,'afectado','osv',?)""",
        (activo_id, threat_id, cve, paquete, instalada, corregida, db.utcnow()))


class _BaseAlertasProceso(unittest.TestCase):
    """Base temporal y aplicación de prueba compartidas por las dos clases de pruebas
    (cada clase construye la suya en setUpClass)."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "alertas_proceso.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", "AdminSeguro#2026", rol="admin", actor="t")
            auth.crear_usuario(conn, "lector", "LectorSeguro#2026", rol="ciberseguridad", actor="t")
            cls.pila_pd = _activo(conn, 1, "srv-pila-pd", proceso="Pila", entorno="produccion", ip="10.1.1.10")
            cls.pila_ds = _activo(conn, 2, "srv-pila-ds", proceso="Pila", entorno="desarrollo", ip="10.1.9.10")
            cls.voz_pd = _activo(conn, 3, "srv-voz-pd", proceso="Helpvoz", entorno="produccion", ip="10.1.1.30")
            cls.sin_proceso = _activo(conn, 4, "srv-suelto", proceso=None, entorno="produccion", ip="10.1.1.40")
            cls.ausente = _activo(conn, 5, "srv-viejo-pd", proceso="Pila", entorno="produccion", ip="10.1.1.50",
                                  presente=0)
            cls.t1 = _amenaza(conn, "fp1", "CVE-2026-0001", "Ejecución remota en OpenSSL", "Critical", 92, kev=1)
            cls.t2 = _amenaza(conn, "fp2", "CVE-2026-0002", "Escalada de privilegios en sudo", "High", 71)
            cls.t3 = _amenaza(conn, "fp3", "CVE-2026-0003", "Denegación de servicio en curl", "Medium", 55)
            _afectado(conn, cls.pila_pd, cls.t1, "CVE-2026-0001", "openssl", "3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.18")
            _afectado(conn, cls.voz_pd, cls.t1, "CVE-2026-0001", "openssl", "3.0.2-0ubuntu1.12", "3.0.2-0ubuntu1.18")
            _afectado(conn, cls.pila_ds, cls.t2, "CVE-2026-0002", "sudo", "1.9.9-1ubuntu2.4", "1.9.9-1ubuntu2.5")
            _afectado(conn, cls.sin_proceso, cls.t3, "CVE-2026-0003", "curl", "7.81.0-1", "7.81.0-2")
            _afectado(conn, cls.ausente, cls.t3, "CVE-2026-0003", "curl", "7.81.0-1", "7.81.0-2")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        with db.session(self.ruta) as conn:
            conn.execute("DELETE FROM alertas_proceso")
            conn.execute("DELETE FROM alertas_proceso_envios")

    # ------------------------------------------------------------ utilidades
    def _pendientes(self, conn):
        filas = conn.execute("SELECT * FROM threats ORDER BY relevance DESC").fetchall()
        return [dict(r) for r in filas]

    def _cliente(self, usuario="admin", clave="AdminSeguro#2026"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": clave})
        return cli

    def _csrf(self, cli, url="/alertas-proceso/"):
        return re.search(r'name="csrf" value="([^"]+)"', cli.get(url).get_data(as_text=True)).group(1)


class TestAlertasProceso(_BaseAlertasProceso):
    # -------------------------------------------------------------- consulta
    def test_procesos_disponibles_y_listar(self):
        with db.session(self.ruta) as conn:
            disponibles = {p["proceso"]: p for p in ap.procesos_disponibles(conn)}
            self.assertEqual(set(disponibles), {"Pila", "Helpvoz"})   # sin proceso y ausentes no cuentan
            self.assertEqual(disponibles["Pila"]["servidores"], 2)
            self.assertEqual(disponibles["Pila"]["expuestos"], 1)
            self.assertEqual(disponibles["Pila"]["con_vulnerabilidades"], 2)
            self.assertEqual(disponibles["Helpvoz"], {"proceso": "Helpvoz", "servidores": 1, "expuestos": 1,
                                                      "con_vulnerabilidades": 1})
            lista = ap.listar(conn)
            self.assertEqual([p["proceso"] for p in lista], ["Helpvoz", "Pila"])
            for p in lista:
                self.assertFalse(p["activa"])
                self.assertEqual(p["correo"], "")
                self.assertFalse(p["configurado"])
                self.assertIsNone(p["ultimo_envio_at"])

    # --------------------------------------------------------------- guardar
    def test_guardar_valida(self):
        with db.session(self.ruta) as conn:
            with self.assertRaises(ValueError) as ctx:
                ap.guardar(conn, "Pila", correo="esto-no-es-un-correo", activa=False, actor="t")
            self.assertIn("no es un correo válido", str(ctx.exception))
            with self.assertRaises(ValueError):
                ap.guardar(conn, "Pila", correo="bien@ejemplo.local, mal@", activa=False, actor="t")
            with self.assertRaises(ValueError) as ctx:
                ap.guardar(conn, "Pila", correo="", activa=True, actor="t")
            self.assertIn("al menos un correo", str(ctx.exception))
            with self.assertRaises(ValueError) as ctx:
                ap.guardar(conn, "Inexistente", correo="a@ejemplo.local", activa=True, actor="t")
            self.assertIn("no existe en el inventario", str(ctx.exception))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alertas_proceso").fetchone()[0], 0)
            auditadas_antes = conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='alertas_proceso.guardar'").fetchone()[0]

            fila = ap.guardar(conn, "Pila", correo="pila@ejemplo.local; Jefe.Pila@ejemplo.local",
                              activa=True, solo_expuestos=True, actor="admin", ip="127.0.0.1")
            self.assertEqual(fila["correos"], ["pila@ejemplo.local", "Jefe.Pila@ejemplo.local"])
            self.assertEqual(fila["correo"], "pila@ejemplo.local, Jefe.Pila@ejemplo.local")
            self.assertTrue(fila["activa"])
            self.assertTrue(fila["solo_expuestos"])
            # actualizar sin duplicar (ON CONFLICT)
            fila2 = ap.guardar(conn, "Pila", correo="otro@ejemplo.local", activa=False, actor="admin")
            self.assertEqual(fila2["id"], fila["id"])
            self.assertFalse(fila2["activa"])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alertas_proceso").fetchone()[0], 1)
            # sin correo y desactivada: se admite (conserva la fila)
            fila3 = ap.guardar(conn, "Pila", correo=None, activa=False, actor="admin")
            self.assertIsNone(fila3["correo"])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='alertas_proceso.guardar'")
                             .fetchone()[0], auditadas_antes + 3)
            lista = {p["proceso"]: p for p in ap.listar(conn)}
            self.assertTrue(lista["Pila"]["configurado"])
            self.assertFalse(lista["Helpvoz"]["configurado"])

    # ---------------------------------------------------------------- enviar
    def test_enviar_solo_al_proceso_activo_con_sus_amenazas(self):
        cfg = Cfg(alert_procesos_enabled=True)
        with db.session(self.ruta) as conn:
            ap.guardar(conn, "Pila", correo="pila@ejemplo.local, jefe@ejemplo.local", activa=True, actor="t")
            ap.guardar(conn, "Helpvoz", correo="voz@ejemplo.local", activa=False, actor="t")
            pendientes = self._pendientes(conn)
            mailer = MailerFalso()
            resultados = ap.enviar(conn, cfg, mailer, pendientes, url_base="https://soc.ejemplo.local/",
                                   ahora="2026-09-05T12:00:00Z")
            self.assertEqual(len(resultados), 1)                      # Helpvoz inactiva ni aparece
            r = resultados[0]
            self.assertEqual(r["proceso"], "Pila")
            self.assertTrue(r["enviado"])
            self.assertIsNone(r["error"])
            self.assertEqual(r["n_amenazas"], 2)                     # t1 y t2; t3 no toca a Pila
            self.assertEqual(r["n_activos"], 2)
            self.assertEqual(len(mailer.enviados), 1)
            envio = mailer.enviados[0]
            self.assertEqual(envio["to"], ["pila@ejemplo.local", "jefe@ejemplo.local"])
            self.assertEqual(envio["subject"],
                             "[Inteligencia de Amenazas] Proceso Pila: 2 amenazas afectan a 2 servidores · "
                             "5 de septiembre de 2026")
            html = envio["html"]
            for texto in ("srv-pila-pd", "srv-pila-ds", "10.1.1.10", "Producción", "Desarrollo", "openssl", "sudo",
                          "3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.18", "Ejecución remota en OpenSSL",
                          "Escalada de privilegios en sudo", "CVE-2026-0001", "explotación activa",
                          "Impacto de CVE-2026-0001", "Por qué recibe este correo", "pila@ejemplo.local",
                          f"https://soc.ejemplo.local/amenazas/{self.t1}\"",
                          f"https://soc.ejemplo.local/amenazas/{self.t1}/remediacion\"",
                          "Ver la amenaza", "Plan de remediación", "equipo de ciberseguridad"):
                self.assertIn(texto, html, texto)
            for texto in ("srv-voz-pd", "srv-suelto", "srv-viejo-pd", "CVE-2026-0003", "10.1.1.30"):
                self.assertNotIn(texto, html, texto)
            # registro del envío y último envío
            envios = ap.envios_recientes(conn)
            self.assertEqual(len(envios), 1)
            self.assertEqual(envios[0]["proceso"], "Pila")
            self.assertEqual(envios[0]["n_amenazas"], 2)
            self.assertEqual(envios[0]["n_activos"], 2)
            self.assertEqual(sorted(envios[0]["threat_ids"]), sorted([self.t1, self.t2]))
            self.assertEqual(envios[0]["enviado_at"], "2026-09-05T12:00:00Z")
            fila = conn.execute("SELECT ultimo_envio_at, ultimo_envio_n FROM alertas_proceso WHERE proceso='Pila'").fetchone()
            self.assertEqual(fila["ultimo_envio_at"], "2026-09-05T12:00:00Z")
            self.assertEqual(fila["ultimo_envio_n"], 2)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='alertas_proceso.envio'")
                             .fetchone()[0], 1)
            lista = {p["proceso"]: p for p in ap.listar(conn)}
            self.assertEqual(lista["Pila"]["ultimo_envio_n"], 2)

    def test_solo_expuestos_filtra_desarrollo(self):
        with db.session(self.ruta) as conn:
            ap.guardar(conn, "Pila", correo="pila@ejemplo.local", activa=True, solo_expuestos=True, actor="t")
            mailer = MailerFalso()
            resultados = ap.enviar(conn, Cfg(), mailer, self._pendientes(conn), url_base="http://x")
            self.assertEqual(resultados[0]["n_amenazas"], 1)         # t2 solo afecta a desarrollo
            self.assertEqual(resultados[0]["n_activos"], 1)
            html = mailer.enviados[0]["html"]
            self.assertIn("srv-pila-pd", html)
            self.assertNotIn("srv-pila-ds", html)
            self.assertNotIn("CVE-2026-0002", html)
            self.assertIn("solo producción y contingencia", html)
            self.assertIn("1 amenaza afecta a 1 servidor ·", mailer.enviados[0]["subject"])

    def test_sin_amenazas_para_el_proceso_no_envia(self):
        with db.session(self.ruta) as conn:
            ap.guardar(conn, "Helpvoz", correo="voz@ejemplo.local", activa=True, actor="t")
            mailer = MailerFalso()
            pendientes = [a for a in self._pendientes(conn) if a["id"] != self.t1]   # t1 es la única de Helpvoz
            resultados = ap.enviar(conn, Cfg(), mailer, pendientes)
            self.assertEqual(len(resultados), 1)
            self.assertFalse(resultados[0]["enviado"])
            self.assertIsNone(resultados[0]["error"])
            self.assertEqual(mailer.enviados, [])
            self.assertEqual(ap.envios_recientes(conn), [])
            # sin pendientes ni configuración, lista vacía
            self.assertEqual(ap.enviar(conn, Cfg(), mailer, []), [])
            # interruptor general apagado
            self.assertEqual(ap.enviar(conn, Cfg(alert_procesos_enabled=False), mailer, self._pendientes(conn)), [])
            self.assertEqual(mailer.enviados, [])

    def test_dry_run_no_registra_y_errores_capturados(self):
        with db.session(self.ruta) as conn:
            ap.guardar(conn, "Pila", correo="pila@ejemplo.local", activa=True, actor="t")
            mailer = MailerFalso()
            resultados = ap.enviar(conn, Cfg(), mailer, self._pendientes(conn), dry_run=True)
            self.assertTrue(resultados[0]["enviado"])
            self.assertEqual(ap.envios_recientes(conn), [])
            fila = conn.execute("SELECT ultimo_envio_at FROM alertas_proceso WHERE proceso='Pila'").fetchone()
            self.assertIsNone(fila["ultimo_envio_at"])
            # el servidor rechaza: error, sin registro
            resultados = ap.enviar(conn, Cfg(), MailerFalso(resultado=False), self._pendientes(conn))
            self.assertFalse(resultados[0]["enviado"])
            self.assertIn("no aceptó", resultados[0]["error"])
            self.assertEqual(ap.envios_recientes(conn), [])
            # excepción del Mailer: capturada, nunca se propaga
            with mock.patch.object(ap.log, "error"):
                resultados = ap.enviar(conn, Cfg(), MailerFalso(excepcion=RuntimeError("caída SMTP")),
                                       self._pendientes(conn))
            self.assertFalse(resultados[0]["enviado"])
            self.assertIn("caída SMTP", resultados[0]["error"])

    def test_asunto_y_renderizado_directo(self):
        self.assertEqual(ap.asunto("Impuestos", 1, 1, "2026-01-02T10:00:00"),
                         "[Inteligencia de Amenazas] Proceso Impuestos: 1 amenaza afecta a 1 servidor · 2 de enero de 2026")
        self.assertIn("1.234 amenazas afectan a 12 servidores", ap.asunto("Pila", 1234, 12))
        html = notify.render_alert_email_proceso("Proyectos", "p@ejemplo.local", [{
            "id": 7, "title_es": "Fallo <script>", "severity": "High", "relevance": 66, "cve": "CVE-2026-0007",
            "servidores": [{"activo_id": 1, "nombre": "srv-a", "ip": "10.0.0.1", "entorno_es": "Producción",
                            "expuesto": True, "paquete": "nginx", "version_instalada": "1.18", "version_corregida": "1.20"}],
        }], {"url_base": "http://soc/", "es_prueba": True})
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertIn("http://soc/amenazas/7/remediacion", html)
        self.assertIn("Correo de prueba", html)
        # Revisión de claridad del 2026-09-15: la cabecera de cada amenaza dice las DOS
        # magnitudes (servidores afectados y paquetes que actualizar), porque la tabla de
        # debajo lleva una fila por servidor con todos sus paquetes dentro.
        self.assertIn("1 servidor afectado del proceso", html)
        self.assertIn("1 paquete que actualizar", html)
        # tope de amenazas detalladas: el resto se remite a la interfaz
        amenazas = [{"id": i, "title_es": f"Amenaza {i}", "severity": "Medium", "relevance": 50,
                     "servidores": [{"activo_id": 1, "nombre": "srv-a", "entorno_es": "Producción", "expuesto": True,
                                     "paquete": "p", "version_instalada": "1", "version_corregida": "2"}]} for i in range(4)]
        html = notify.render_alert_email_proceso("Pila", "p@ejemplo.local", amenazas,
                                                 {"url_base": "http://soc", "max_detalle": 3})
        self.assertIn("Amenaza 2", html)
        self.assertNotIn("Amenaza 3", html)
        self.assertIn("Las 1 restantes están disponibles en la interfaz de consulta", html)
        self.assertIn("http://soc/amenazas/\"", html)

    # ------------------------------------------------------------------ web
    def test_pagina_permisos_y_csrf(self):
        cli = self._cliente()
        r = cli.get("/alertas-proceso/")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        for texto in ("Alertas por proceso", "Pila", "Helpvoz", "Correo de destino", "Solo producción y contingencia",
                      "Enviar prueba", "Envíos recientes", "Todavía no se ha enviado", "data-tour=\"3\""):
            self.assertIn(texto, html)
        self.assertIsNone(RE_STYLE.search(html))
        self.assertIsNone(RE_ON.search(html))
        self.assertNotIn("Las alertas por proceso están desactivadas", html)
        lector = self._cliente("lector", "LectorSeguro#2026")
        self.assertEqual(lector.get("/alertas-proceso/").status_code, 403)
        csrf_lector = self._csrf(lector, "/")
        self.assertEqual(lector.post("/alertas-proceso/guardar", data={"csrf": csrf_lector, "proceso": "Pila",
                                                                        "correo": "x@ejemplo.local", "activa": "1"}).status_code, 403)
        # sin CSRF: rechazado
        self.assertEqual(cli.post("/alertas-proceso/guardar", data={"proceso": "Pila", "correo": "x@ejemplo.local"}).status_code, 400)
        self.assertEqual(cli.post("/alertas-proceso/probar", data={"proceso": "Pila"}).status_code, 400)
        self.assertEqual(self.app.test_client().get("/alertas-proceso/").status_code, 302)
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alertas_proceso").fetchone()[0], 0)

    def test_pagina_guardar_y_probar(self):
        cli = self._cliente()
        csrf = self._csrf(cli)
        r = cli.post("/alertas-proceso/guardar", data={"csrf": csrf, "proceso": "Pila", "correo": "pila@ejemplo.local",
                                                       "activa": "1", "solo_expuestos": "1"}, follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("Alerta del proceso «Pila» activada", html)
        self.assertIn("pila@ejemplo.local", html)
        self.assertIn('id="ap-2-activa" name="activa" value="1" form="ap-2" checked', html)  # Pila es la segunda fila
        with db.session(self.ruta) as conn:
            fila = conn.execute("SELECT * FROM alertas_proceso WHERE proceso='Pila'").fetchone()
            self.assertEqual(fila["correo"], "pila@ejemplo.local")
            self.assertEqual((fila["activa"], fila["solo_expuestos"]), (1, 1))
        # correo inválido: mensaje claro, nada guardado
        r = cli.post("/alertas-proceso/guardar", data={"csrf": csrf, "proceso": "Helpvoz", "correo": "sin-arroba",
                                                       "activa": "1"}, follow_redirects=True)
        self.assertIn("no es un correo válido", r.get_data(as_text=True))
        # activar sin correo
        r = cli.post("/alertas-proceso/guardar", data={"csrf": csrf, "proceso": "Helpvoz", "correo": "", "activa": "1"},
                     follow_redirects=True)
        self.assertIn("al menos un correo", r.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM alertas_proceso WHERE proceso='Helpvoz'").fetchone())
        # prueba de envío con un doble del Mailer
        class DobleMailer:
            enviados = []

            def __init__(self, cfg, dry_run=False):
                pass

            def send(self, **kw):
                DobleMailer.enviados.append(kw)
                return True

        with mock.patch.object(notify, "Mailer", DobleMailer):
            r = cli.post("/alertas-proceso/probar", data={"csrf": csrf, "proceso": "Pila"}, follow_redirects=True)
        self.assertIn("Correo de prueba del proceso «Pila» enviado a pila@ejemplo.local", r.get_data(as_text=True))
        self.assertEqual(len(DobleMailer.enviados), 1)
        self.assertEqual(DobleMailer.enviados[0]["to"], ["pila@ejemplo.local"])
        self.assertIn("Prueba de la alerta del proceso Pila", DobleMailer.enviados[0]["subject"])
        self.assertIn("Pila", DobleMailer.enviados[0]["html"])
        self.assertIsNone(RE_ON.search(DobleMailer.enviados[0]["html"]))
        # prueba a un proceso sin configuración
        with mock.patch.object(notify, "Mailer", DobleMailer):
            r = cli.post("/alertas-proceso/probar", data={"csrf": csrf, "proceso": "Helpvoz"}, follow_redirects=True)
        self.assertIn("no tiene configuración guardada", r.get_data(as_text=True))
        self.assertEqual(len(DobleMailer.enviados), 1)
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='alertas_proceso.prueba'")
                             .fetchone()[0], 1)
            self.assertEqual(ap.envios_recientes(conn), [])          # las pruebas no se registran como envíos

    def test_pagina_aviso_interruptor_general_y_envios(self):
        with db.session(self.ruta) as conn:
            db.set_setting(conn, "alert_procesos_enabled", False)
            ap.guardar(conn, "Pila", correo="pila@ejemplo.local", activa=True, actor="t")
            ap.enviar(conn, Cfg(), MailerFalso(), self._pendientes(conn), url_base="http://x",
                      ahora="2026-09-05T08:00:00Z")
        try:
            html = self._cliente().get("/alertas-proceso/").get_data(as_text=True)
            self.assertIn("Las alertas por proceso están desactivadas", html)
            self.assertIn("/ajustes/", html)
            self.assertIn("5 de septiembre de 2026", html)
            self.assertIn("Proceso Pila: 2 amenazas afectan a 2 servidores", html)
            self.assertIsNone(RE_STYLE.search(html))
        finally:
            with db.session(self.ruta) as conn:
                db.set_setting(conn, "alert_procesos_enabled", True)


class TestHallazgosRevision(_BaseAlertasProceso):
    """Hallazgos de la revisión del 2026-09-05: enviar() nunca lanza y acepta filas
    sqlite3.Row; no se reactiva un proceso sin servidores; textos cosméticos; aviso
    cuando el destino no es del dominio de la empresa."""

    def _proceso_antiguo(self, conn, correo="antiguo@ejemplo.local", activa=1):
        ahora = db.utcnow()
        conn.execute("INSERT INTO alertas_proceso(proceso, correo, activa, solo_expuestos, creado_at, actualizado_at) "
                     "VALUES('Antiguo', ?, ?, 0, ?, ?)", (correo, activa, ahora, ahora))

    # ------------------------------------------------------------ hallazgo 6
    def test_enviar_acepta_filas_sqlite_row(self):
        with db.session(self.ruta) as conn:
            ap.guardar(conn, "Pila", correo="pila@ejemplo.local", activa=True, actor="t")
            filas = conn.execute("SELECT * FROM threats ORDER BY relevance DESC").fetchall()
            self.assertFalse(hasattr(filas[0], "get"))                  # sqlite3.Row, sin .get
            mailer = MailerFalso()
            resultados = ap.enviar(conn, Cfg(), mailer, filas, url_base="http://x", ahora="2026-09-05T12:00:00Z")
            self.assertEqual(len(resultados), 1)
            self.assertTrue(resultados[0]["enviado"])
            self.assertIsNone(resultados[0]["error"])
            self.assertEqual(resultados[0]["n_amenazas"], 2)
            self.assertIn("srv-pila-pd", mailer.enviados[0]["html"])
            self.assertEqual(sorted(ap.envios_recientes(conn)[0]["threat_ids"]), sorted([self.t1, self.t2]))

    def test_enviar_nunca_lanza_con_pendientes_ilegibles(self):
        with db.session(self.ruta) as conn:
            ap.guardar(conn, "Pila", correo="pila@ejemplo.local", activa=True, actor="t")
            ap.guardar(conn, "Helpvoz", correo="voz@ejemplo.local", activa=True, actor="t")
            mailer = MailerFalso()
            with mock.patch.object(ap.log, "error"):
                # identificador no numérico: antes int(i) reventaba fuera del try
                resultados = ap.enviar(conn, Cfg(), mailer, [{"id": "no-numérico", "title_es": "x"}])
                self.assertEqual([r["proceso"] for r in resultados], ["Helpvoz", "Pila"])
                for r in resultados:
                    self.assertFalse(r["enviado"])
                    self.assertIn("amenazas pendientes no legibles", r["error"])
                    self.assertIn("ValueError", r["error"])
                # elementos que no son ni diccionario ni fila
                resultados = ap.enviar(conn, Cfg(), mailer, [42, None])
                self.assertEqual(len(resultados), 2)
                self.assertTrue(all(r["error"] for r in resultados))
                # sin identificador: se ignoran, no hay nada que enviar y no hay error
                resultados = ap.enviar(conn, Cfg(), mailer, [{"title_es": "sin id"}])
                self.assertEqual([(r["enviado"], r["error"]) for r in resultados], [(False, None)] * 2)
            self.assertEqual(mailer.enviados, [])
            self.assertEqual(ap.envios_recientes(conn), [])

    # ------------------------------------------------------------ hallazgo 7
    def test_no_se_reactiva_un_proceso_sin_servidores(self):
        with db.session(self.ruta) as conn:
            self._proceso_antiguo(conn)
            lista = {p["proceso"]: p for p in ap.listar(conn)}
            self.assertFalse(lista["Antiguo"]["disponible"])
            self.assertTrue(lista["Antiguo"]["activa"])
            with self.assertRaises(ValueError) as ctx:
                ap.guardar(conn, "Antiguo", correo="antiguo@ejemplo.local", activa=True, actor="t")
            self.assertIn("ya no tiene servidores en OCS Inventory", str(ctx.exception))
            self.assertIn("no se puede activar", str(ctx.exception))
            # desactivar conservando el correo: permitido
            fila = ap.guardar(conn, "Antiguo", correo="antiguo@ejemplo.local", activa=False, actor="t")
            self.assertFalse(fila["activa"])
            self.assertEqual(fila["correos"], ["antiguo@ejemplo.local"])
            # borrar el correo: permitido
            fila = ap.guardar(conn, "Antiguo", correo="", activa=False, actor="t")
            self.assertIsNone(fila["correo"])
            # un proceso que nunca existió sigue rechazándose aunque se desactive
            with self.assertRaises(ValueError) as ctx:
                ap.guardar(conn, "Fantasma", correo="", activa=False, actor="t")
            self.assertIn("no existe en el inventario", str(ctx.exception))
            # un proceso disponible sí se activa
            self.assertTrue(ap.guardar(conn, "Pila", correo="p@ejemplo.local", activa=True, actor="t")["activa"])

    def test_pagina_rechaza_reactivar_proceso_sin_servidores(self):
        with db.session(self.ruta) as conn:
            self._proceso_antiguo(conn, activa=0)
        cli = self._cliente()
        csrf = self._csrf(cli)
        r = cli.post("/alertas-proceso/guardar", data={"csrf": csrf, "proceso": "Antiguo",
                                                       "correo": "antiguo@ejemplo.local", "activa": "1"},
                     follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("ya no tiene servidores en OCS Inventory", html)
        self.assertIn('class="aviso error"', html)
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT activa FROM alertas_proceso WHERE proceso='Antiguo'").fetchone()[0], 0)

    # ------------------------------------------------------------ hallazgo 8
    def test_pagina_textos_sin_envios_y_metrica_de_procesos(self):
        with db.session(self.ruta) as conn:
            self._proceso_antiguo(conn)                                # configurado, sin servidores
        cli = self._cliente()
        html = cli.get("/alertas-proceso/").get_data(as_text=True)
        self.assertNotIn("Últimos 0 correos", html)
        self.assertIn("Todavía no se ha enviado ningún correo por proceso.", html)
        self.assertIn("Antiguo", html)
        self.assertIn("Ya no tiene servidores en OCS Inventory", html)
        # La métrica cuenta solo procesos con servidores presentes (Pila y Helpvoz), no «Antiguo»
        metrica = re.search(r'<div class="valor">(\d+)</div>\s*<div class="etiqueta">Procesos de negocio</div>', html)
        self.assertIsNotNone(metrica)
        self.assertEqual(metrica.group(1), "2")
        self.assertIn('id="ap-3"', html)                                # 3 filas de procesos (Antiguo al final)
        self.assertNotIn('id="ap-4"', html)
        # Con un envío: singular
        with db.session(self.ruta) as conn:
            ap.guardar(conn, "Pila", correo="pila@ejemplo.local", activa=True, actor="t")
            ap.enviar(conn, Cfg(), MailerFalso(), self._pendientes(conn), ahora="2026-09-05T08:00:00Z")
        html = cli.get("/alertas-proceso/").get_data(as_text=True)
        self.assertIn("El único correo por proceso enviado hasta ahora.", html)
        self.assertNotIn("Últimos 1 correos", html)
        self.assertIsNone(RE_STYLE.search(html))
        self.assertIsNone(RE_ON.search(html))

    # ------------------------------------------------------------ hallazgo 9
    def test_dominio_empresa_y_correos_fuera_de_dominio(self):
        class CfgPrueba:
            alert_to = ["Soc@Empresa.com.co", "otro@empresa.com.co"]

        self.assertEqual(ap.dominio_empresa(CfgPrueba()), "empresa.com.co")
        self.assertEqual(ap.dominio_empresa(Cfg(alert_to="soc@empresa.com.co")), "empresa.com.co")
        self.assertIsNone(ap.dominio_empresa(None))
        self.assertIsNone(ap.dominio_empresa(Cfg()))
        self.assertIsNone(ap.dominio_empresa(Cfg(alert_to=[])))
        fuera = ap.correos_fuera_de_dominio(
            ["a@empresa.com.co", "b@EMPRESA.com.co", "c@correo.empresa.com.co", "d@gmail.com", "e@empresa.com"],
            CfgPrueba())
        self.assertEqual(fuera, ["d@gmail.com", "e@empresa.com"])
        self.assertEqual(ap.correos_fuera_de_dominio(["d@gmail.com"], Cfg()), [])   # sin dominio conocido: sin aviso
        aviso = ap.aviso_dominio(["d@gmail.com"], CfgPrueba())
        self.assertEqual(aviso, "El servidor de correo interno solo acepta destinatarios del dominio empresa.com.co; "
                                "compruebe la dirección d@gmail.com: podría no recibir la alerta.")
        aviso = ap.aviso_dominio(["d@gmail.com", "e@empresa.com"], CfgPrueba())
        self.assertIn("compruebe las direcciones d@gmail.com, e@empresa.com: podrían", aviso)
        self.assertIsNone(ap.aviso_dominio(["a@empresa.com.co"], CfgPrueba()))
        self.assertIsNone(ap.aviso_dominio([], CfgPrueba()))

    def test_pagina_avisa_si_el_destino_no_es_del_dominio(self):
        cargar_real = config.load

        def cargar_de_prueba(*args, **kwargs):
            return dataclasses.replace(cargar_real(*args, **kwargs), alert_to=["soc@empresa-prueba.co"])

        cli = self._cliente()
        csrf = self._csrf(cli)
        with mock.patch.object(config, "load", side_effect=cargar_de_prueba):
            r = cli.post("/alertas-proceso/guardar", data={"csrf": csrf, "proceso": "Pila",
                                                           "correo": "pila@otro-dominio.com, jefe@empresa-prueba.co",
                                                           "activa": "1"}, follow_redirects=True)
            html = r.get_data(as_text=True)
            # Se guarda (éxito) y además se avisa (aviso, no error)
            self.assertIn("Alerta del proceso «Pila» activada", html)
            self.assertIn("El servidor de correo interno solo acepta destinatarios del dominio empresa-prueba.co; "
                          "compruebe la dirección pila@otro-dominio.com", html)
            self.assertIn('class="aviso aviso-nivel"', html)
            self.assertNotIn('class="aviso error"', html)
            # Destino del dominio: sin aviso
            r = cli.post("/alertas-proceso/guardar", data={"csrf": csrf, "proceso": "Helpvoz",
                                                           "correo": "voz@empresa-prueba.co", "activa": "1"},
                         follow_redirects=True)
            self.assertNotIn("solo acepta destinatarios del dominio", r.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            fila = conn.execute("SELECT correo, activa FROM alertas_proceso WHERE proceso='Pila'").fetchone()
            self.assertEqual(fila["correo"], "pila@otro-dominio.com, jefe@empresa-prueba.co")
            self.assertEqual(fila["activa"], 1)


if __name__ == "__main__":
    unittest.main()
