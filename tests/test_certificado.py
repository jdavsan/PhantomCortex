"""Vigilancia de la caducidad del certificado HTTPS (2026-09-08).

Se genera un certificado autofirmado con «openssl» en un directorio temporal y se prueba el
estado con fechas inyectadas (``ahora``): así se cubre «caducado» sin esperar a que caduque.
El aviso por correo usa un remitente falso y respeta el silencio de una semana.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatintel import certificado, db
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402

CLAVE = "ClaveSegura#2026"


def _certificado_temporal(directorio: str, dias: int = 90) -> str:
    ruta = os.path.join(directorio, "prueba.crt")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-days", str(dias), "-keyout", os.path.join(directorio, "prueba.key"),
         "-out", ruta, "-subj", "/CN=omniguard.ejemplo.local/O=Pruebas",
         "-addext", "subjectAltName=DNS:omniguard.ejemplo.local,IP:192.0.2.10"],
        check=True, capture_output=True)
    return ruta


class Cfg(dict):
    admin_to = ["admin@example.invalid"]


class RemitenteFalso:
    def __init__(self):
        self.enviados = []

    def send(self, *, subject, html, to, **_):
        self.enviados.append({"subject": subject, "html": html, "to": list(to)})
        return True


class TestEstadoDelCertificado(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.addCleanup(self.dir.cleanup)
        self.ruta = _certificado_temporal(self.dir.name, dias=90)

    def test_lee_sujeto_emisor_fechas_y_nombres(self):
        e = certificado.estado(cfg={}, ruta=self.ruta)
        self.assertEqual(e["estado"], "ok")
        self.assertEqual(e["nombre_comun"], "omniguard.ejemplo.local")
        self.assertEqual(e["emisor_corto"], "Pruebas")
        self.assertIn("omniguard.ejemplo.local", e["nombres"])
        self.assertIn("192.0.2.10", e["nombres"])
        self.assertTrue(88 <= e["dias_restantes"] <= 90)
        self.assertRegex(e["not_after"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertIn("caduca el", e["mensaje"])

    def test_por_caducar_y_caducado_con_fecha_inyectada(self):
        ahora = datetime.now(timezone.utc)
        e = certificado.estado(cfg={"tls_aviso_dias": 30}, ruta=self.ruta, ahora=ahora + timedelta(days=70))
        self.assertEqual(e["estado"], "por_caducar")
        # Revisión de claridad del 2026-09-15: el mensaje dice QUIÉN lo hace y ya no
        # nombra la carpeta del servidor donde hay que copiar los ficheros.
        self.assertIn("Servicios Tecnológicos debe pedir el nuevo", e["mensaje"])
        self.assertNotIn("/etc/", e["mensaje"])
        e = certificado.estado(cfg={}, ruta=self.ruta, ahora=ahora + timedelta(days=95))
        self.assertEqual(e["estado"], "caducado")
        self.assertLess(e["dias_restantes"], 0)
        self.assertIn("bloquean la entrada", e["mensaje"])

    def test_sin_fichero_y_fichero_ilegible(self):
        e = certificado.estado(cfg={}, ruta=os.path.join(self.dir.name, "no-existe.crt"))
        self.assertEqual(e["estado"], "sin_certificado")
        self.assertIsNone(e["dias_restantes"])
        basura = os.path.join(self.dir.name, "basura.crt")
        Path(basura).write_text("esto no es un certificado", encoding="utf-8")
        e = certificado.estado(cfg={}, ruta=basura)
        self.assertEqual(e["estado"], "error")
        self.assertNotIn("Traceback", e["mensaje"])

    def test_se_lee_el_primer_certificado_de_la_cadena(self):
        """El fichero real lleva servidor + intermedio + raíz: las fechas y el nombre son
        los del PRIMERO (el del servidor), no los de la raíz, que dura décadas."""
        raiz = _certificado_temporal(self.dir.name + "/raiz" if os.path.isdir(self.dir.name + "/raiz") else (os.makedirs(self.dir.name + "/raiz") or self.dir.name + "/raiz"), dias=3650)
        cadena = os.path.join(self.dir.name, "cadena.crt")
        Path(cadena).write_text(Path(self.ruta).read_text() + Path(raiz).read_text(), encoding="utf-8")
        e = certificado.estado(cfg={}, ruta=cadena)
        self.assertEqual(e["nombre_comun"], "omniguard.ejemplo.local")
        self.assertTrue(88 <= e["dias_restantes"] <= 90, e["dias_restantes"])

    def test_la_fecha_no_depende_del_idioma_del_proceso(self):
        """openssl escribe «Jan 29 23:59:59 2027 GMT»; el análisis no puede depender del
        idioma de Python (con «%b» y un idioma en español fallaba en silencio)."""
        import locale
        anterior = locale.setlocale(locale.LC_TIME)
        fijado = None
        for nombre in ("es_ES.UTF-8", "es_CO.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8"):
            try:
                locale.setlocale(locale.LC_TIME, nombre)
                fijado = nombre
                break
            except locale.Error:
                continue
        self.addCleanup(locale.setlocale, locale.LC_TIME, anterior)
        if fijado is None:
            self.skipTest("no hay ningún idioma distinto del inglés instalado en el sistema")
        self.assertEqual(certificado._fecha_openssl("Jan 29 23:59:59 2027 GMT").isoformat(),
                         "2027-01-29T23:59:59+00:00")
        self.assertEqual(certificado._fecha_openssl("Sep  8 17:24:47 2026 GMT").isoformat(),
                         "2026-09-08T17:24:47+00:00")
        self.assertEqual(certificado.estado(cfg={}, ruta=self.ruta)["estado"], "ok")

    def test_una_ruta_rara_no_llega_a_openssl(self):
        for ruta in ("relativa.crt", "/etc/passwd", "/dev/zero", "/etc/ssl/openssl.cnf"):
            e = certificado.estado(cfg={"tls_certificado_ruta": ruta})
            self.assertEqual(e["estado"], "error", ruta)
            # El ajuste se llama ahora «Certificado con el que se sirve la plataforma»
            # y el mensaje no repite la ruta que se intentó usar (2026-09-15).
            self.assertIn("Certificado con el que se sirve la plataforma", e["mensaje"])
            self.assertNotIn(ruta, e["mensaje"])
        e = certificado.estado(cfg={}, ruta=self.dir.name + "/no-hay.crt")
        self.assertEqual(e["estado"], "sin_certificado")

    def test_el_resultado_se_guarda_en_memoria_por_ruta_y_fecha(self):
        from unittest import mock
        certificado._CACHE.clear()
        certificado.estado(cfg={}, ruta=self.ruta)
        with mock.patch.object(certificado, "leer", side_effect=AssertionError("no debía leer")):
            e = certificado.estado(cfg={}, ruta=self.ruta)
        self.assertEqual(e["estado"], "ok")
        # si el fichero cambia, se vuelve a leer
        os.utime(self.ruta, (1, 1))
        with mock.patch.object(certificado, "leer", wraps=certificado.leer) as leer:
            certificado.estado(cfg={}, ruta=self.ruta)
        self.assertEqual(leer.call_count, 1)

    def test_la_ruta_sale_del_ajuste(self):
        e = certificado.estado(cfg={"tls_certificado_ruta": self.ruta})
        self.assertEqual(e["ruta"], self.ruta)
        self.assertEqual(e["estado"], "ok")


class TestAvisoPorCorreo(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.addCleanup(self.dir.cleanup)
        self.ruta_db = str(Path(self.dir.name) / "cert.db")
        db.init_db(self.ruta_db)
        self.cert = _certificado_temporal(self.dir.name, dias=90)

    def test_avisa_una_vez_por_semana_y_solo_si_hace_falta(self):
        cfg = Cfg(tls_certificado_ruta=self.cert, tls_aviso_dias=30)
        ahora = datetime.now(timezone.utc)
        remitente = RemitenteFalso()
        with db.session(self.ruta_db) as conn:
            # vigente: nada
            self.assertIsNone(certificado.avisar(conn, cfg=cfg, mailer=remitente, ahora=ahora))
            # por caducar: un aviso
            en_70_dias = ahora + timedelta(days=70)
            aviso = certificado.avisar(conn, cfg=cfg, mailer=remitente, ahora=en_70_dias)
            self.assertIsNotNone(aviso)
            self.assertEqual(aviso["severidad"], "warning")
            self.assertEqual(len(remitente.enviados), 1)
            self.assertIn("caduca en", remitente.enviados[0]["subject"])
            self.assertIn("omniguard.ejemplo.local", remitente.enviados[0]["html"])
            # el mismo dia, otra pasada: silencio
            self.assertIsNone(certificado.avisar(conn, cfg=cfg, mailer=remitente, ahora=en_70_dias))
            self.assertEqual(len(remitente.enviados), 1)
            # caducado: accion requerida, aunque se avisara hace poco no, porque han pasado > 7 dias
            aviso = certificado.avisar(conn, cfg=cfg, mailer=remitente, ahora=ahora + timedelta(days=95))
            self.assertEqual(aviso["severidad"], "critical")
            self.assertIn("Acción requerida", remitente.enviados[-1]["subject"])
            filas = conn.execute("SELECT COUNT(*) FROM admin_notices WHERE kind='tls_expiry'").fetchone()[0]
            self.assertEqual(filas, 2)

    def test_sin_destinatarios_no_envia(self):
        class SinDestino(dict):
            admin_to = []
        cfg = SinDestino(tls_certificado_ruta=self.cert)
        remitente = RemitenteFalso()
        with db.session(self.ruta_db) as conn:
            r = certificado.avisar(conn, cfg=cfg, mailer=remitente,
                                   ahora=datetime.now(timezone.utc) + timedelta(days=70))
        self.assertIsNone(r)
        self.assertEqual(remitente.enviados, [])


class TestSaludYPagina(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.addCleanup(self.dir.cleanup)
        self.ruta_db = str(Path(self.dir.name) / "cert_web.db")
        db.init_db(self.ruta_db)
        self.cert = _certificado_temporal(self.dir.name, dias=400)
        with db.session(self.ruta_db) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin", nombre="Jefa", actor="t")
            conn.execute("UPDATE users SET must_change=0")
            conn.execute("INSERT OR REPLACE INTO settings(key, value, updated_at) VALUES(?,?,?)",
                         ("tls_certificado_ruta", f'"{self.cert}"', db.utcnow()))

    def test_salud_json_lleva_las_metricas_del_certificado(self):
        from threatintel import config, health
        with db.connect(self.ruta_db) as conn:
            cfg = config.load(conn)
            resumen = health.resumen_sistema(conn, cfg=cfg)
            metricas = health.exportar_metricas(conn, cfg=cfg)
        self.assertEqual(resumen["certificado"]["estado"], "ok")
        self.assertEqual(metricas["ti.certificado.estado"], 0)
        self.assertGreater(metricas["ti.certificado.dias_restantes"], 300)

    def test_sin_certificado_legible_la_salud_pasa_a_atencion(self):
        from threatintel import config, health
        with db.session(self.ruta_db) as conn:
            conn.execute("INSERT OR REPLACE INTO settings(key, value, updated_at) VALUES(?,?,?)",
                         ("tls_certificado_ruta", '"/no/existe/certificado.crt"', db.utcnow()))
        with db.connect(self.ruta_db) as conn:
            cfg = config.load(conn)
            resumen = health.resumen_sistema(conn, cfg=cfg)
        self.assertEqual(resumen["certificado"]["estado"], "sin_certificado")
        self.assertIn(resumen["estado_global"], ("atencion", "critico"))
        self.assertTrue(any("certificado" in m for m in resumen["motivos"]))

    def test_la_pagina_de_credenciales_muestra_el_certificado(self):
        from webui.app import crear_app
        app = crear_app(db_path=self.ruta_db, testing=True)
        cli = app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        html = cli.get("/credenciales/").get_data(as_text=True)
        self.assertIn('id="certificado-tls"', html)
        self.assertIn("Certificado HTTPS", html)
        self.assertIn("omniguard.ejemplo.local", html)
        self.assertIn("Vigente", html)
        self.assertIn("Pruebas", html)              # emisor
        self.assertNotIn("prueba.key", html)         # la clave privada no aparece nunca


class TestSinHttpsNoHayIncidenciaDeCertificado(unittest.TestCase):
    """Sin HTTPS configurado, el certificado de fábrica ausente no es una incidencia
    (2026-11-15).

    Servir por HTTP sin cifrar en la red interna es una decisión aceptada de este
    proyecto (riesgo aceptado conocido, ``.claude/skills/auditoria-seguridad/SKILL.md``).
    Antes de este cambio, ``threatintel.health.resumen_sistema`` evaluaba el certificado
    de fábrica (``certificado.RUTA_POR_OMISION``) aunque nadie hubiera activado «La
    plataforma se sirve cifrada» (``webui_https``) ni señalado una ruta propia, así que
    una instalación recién creada, sin nada configurado, abría con «El sistema funciona,
    pero hay algo que atender» por un certificado que nadie había pedido vigilar
    (``tests/test_claridad_operacion.py::TestAvisoDeSaludConAccion``,
    ``test_sin_incidencias_no_se_habla_de_incidencias``). Esta prueba fija el contrato
    para que no se repita, en los dos sentidos: sin nada configurado no hay incidencia,
    y con algo configurado (``webui_https`` o una ruta propia) sigue habiéndola aunque
    el certificado no se encuentre.
    """

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.addCleanup(self.dir.cleanup)
        self.ruta_db = str(Path(self.dir.name) / "sin_tls.db")
        db.init_db(self.ruta_db)

    def _resumen(self):
        from threatintel import config, health
        with db.connect(self.ruta_db) as conn:
            cfg = config.load(conn)
            return cfg, health.resumen_sistema(conn, cfg=cfg)

    @staticmethod
    def _incidencias_certificado(resumen):
        return [i for i in resumen["incidencias"] if i["clave"] == "certificado"]

    def test_sin_nada_configurado_no_hay_incidencia_de_certificado(self):
        cfg, resumen = self._resumen()
        # La base recién creada no activa HTTPS ni señala una ruta propia: el ajuste
        # cae en el valor de fábrica, el mismo fichero que no existe en este servidor.
        self.assertFalse(cfg.get("webui_https"))
        self.assertEqual(cfg.get("tls_certificado_ruta"), certificado.RUTA_POR_OMISION)
        self.assertEqual(resumen["certificado"]["estado"], "sin_certificado")
        self.assertEqual(self._incidencias_certificado(resumen), [])
        self.assertEqual(resumen["estado_global"], "ok")

    def test_activar_webui_https_reactiva_la_incidencia(self):
        with db.session(self.ruta_db) as conn:
            db.set_setting(conn, "webui_https", True)
        _, resumen = self._resumen()
        self.assertTrue(self._incidencias_certificado(resumen),
                        "con «la plataforma se sirve cifrada» activado, el certificado "
                        "ausente sí es una incidencia")
        self.assertIn(resumen["estado_global"], ("atencion", "critico"))

    def test_senalar_una_ruta_propia_reactiva_la_incidencia_aunque_no_exista(self):
        with db.session(self.ruta_db) as conn:
            db.set_setting(conn, "tls_certificado_ruta", "/no/existe/propio.crt")
        _, resumen = self._resumen()
        self.assertTrue(self._incidencias_certificado(resumen),
                        "con una ruta de certificado propia configurada, aunque no "
                        "exista, el certificado sí importa")
        self.assertIn(resumen["estado_global"], ("atencion", "critico"))


if __name__ == "__main__":
    unittest.main()
