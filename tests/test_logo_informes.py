"""Logo de la organización: subida, validación y uso en la interfaz y en los informes.

Petición del usuario (2026-11-17): «necesito la opción de subir una imagen para ponerla
como logo de la plataforma y de los informes». Cada base de datos es propia de la prueba
(no se comparte con otras clases) porque el logo es un dato global: compartir base haría
que una prueba viera el logo que dejó otra.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_logo_informes
"""
from __future__ import annotations

import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from PIL import Image

from threatintel import config, db, marca, report
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from tests.test_informes import _sembrar  # noqa: E402

CLAVE = "ClaveSegura#2026"


def _png(ancho=300, alto=120, color=(10, 80, 200)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (ancho, alto), color).save(buf, format="PNG")
    return buf.getvalue()


class TestNormalizarLogo(unittest.TestCase):
    """threatintel.marca.normalizar: lo que se guarda nunca son los bytes originales."""

    def test_una_imagen_valida_se_normaliza_a_png(self):
        datos, tipo = marca.normalizar(_png())
        self.assertEqual(tipo, "image/png")
        self.assertTrue(Image.open(io.BytesIO(datos)).format, "PNG")

    def test_un_fichero_que_no_es_imagen_se_rechaza(self):
        with self.assertRaises(marca.LogoInvalido):
            marca.normalizar(b"esto no es una imagen, son bytes cualquiera" * 10)

    def test_un_fichero_vacio_se_rechaza(self):
        with self.assertRaises(marca.LogoInvalido):
            marca.normalizar(b"")

    def test_una_imagen_gigante_se_redimensiona_sin_fallar(self):
        datos, _ = marca.normalizar(_png(2000, 500))
        imagen = Image.open(io.BytesIO(datos))
        self.assertLessEqual(max(imagen.size), marca.LADO_MAXIMO)

    def test_una_imagen_con_el_lado_de_entrada_absurdo_se_rechaza_antes_de_abrirla(self):
        # Una imagen de 6500 px de ancho no es un logo: se rechaza por tamaño de
        # entrada (defensa contra una imagen hecha para agotar memoria al procesarla).
        datos_enormes = _png(6500, 100)
        with self.assertRaises(marca.LogoInvalido):
            marca.normalizar(datos_enormes)

    def test_un_png_disfrazado_de_jpg_tambien_se_detecta_por_el_contenido(self):
        # La extension nunca se mira aqui (el llamador ya la ignora): lo unico que
        # importa es si Pillow puede abrir los BYTES como imagen real.
        datos, tipo = marca.normalizar(_png())
        self.assertEqual(tipo, "image/png")


class _BaseLogoDB(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "logo.db")
        db.init_db(self.ruta)
        _sembrar(self.ruta)

    def tearDown(self):
        self.dir.cleanup()

    def _cfg(self, conn):
        return config.load(conn)


class TestLogoEnLosInformes(_BaseLogoDB):

    def test_sin_logo_el_informe_se_genera_igual_que_siempre(self):
        with db.connect(self.ruta) as conn:
            doc = report.construir_documento(conn, "2026-07", cfg=self._cfg(conn))
        salida = io.BytesIO()
        doc.save(salida)
        z = zipfile.ZipFile(salida)
        self.assertEqual([n for n in z.namelist() if n.startswith("word/media/")], [])

    def test_con_logo_configurado_el_informe_mensual_lo_incrusta(self):
        datos, tipo = marca.normalizar(_png())
        with db.session(self.ruta) as conn:
            db.set_logo(conn, datos, tipo, "logo.png", "admin@ejemplo.local")
        with db.connect(self.ruta) as conn:
            doc = report.construir_documento(conn, "2026-07", cfg=self._cfg(conn))
        salida = io.BytesIO()
        doc.save(salida)
        z = zipfile.ZipFile(salida)
        incrustadas = [n for n in z.namelist() if n.startswith("word/media/")]
        self.assertEqual(len(incrustadas), 1)

    def test_el_informe_ejecutivo_sigue_sin_ninguna_imagen_aunque_haya_logo(self):
        """Orden del usuario (2026-09-15): el informe ejecutivo sale entero en blanco y
        negro porque se imprime y se reenvía. Una imagen de marca en color en la portada
        rompería esa regla, así que el logo NO se incrusta aquí a propósito."""
        datos, tipo = marca.normalizar(_png())
        with db.session(self.ruta) as conn:
            db.set_logo(conn, datos, tipo, "logo.png", "admin@ejemplo.local")
        with db.connect(self.ruta) as conn:
            doc = report.construir_documento_ejecutivo(conn, "2026-07", cfg=self._cfg(conn))
        salida = io.BytesIO()
        doc.save(salida)
        z = zipfile.ZipFile(salida)
        self.assertEqual([n for n in z.namelist() if n.startswith("word/media/")], [])

    def test_el_nombre_de_la_organizacion_configurado_aparece_en_la_portada(self):
        with db.session(self.ruta) as conn:
            db.set_setting(conn, "empresa_nombre", "Organización de Prueba S.A.")
        with db.connect(self.ruta) as conn:
            doc = report.construir_documento(conn, "2026-07", cfg=self._cfg(conn))
        texto = "\n".join(p.text for p in doc.paragraphs)
        self.assertIn("Organización de Prueba S.A.", texto)
        self.assertNotIn("Mi Organización", texto)


class TestLogoEnLaInterfazWeb(_BaseLogoDB):

    def _app(self):
        sys.path.insert(0, str(BASE_DIR))
        from webui.app import crear_app
        return crear_app(db_path=self.ruta, testing=True)

    def test_sin_logo_la_ruta_responde_404_y_no_exige_sesion(self):
        cli = self._app().test_client()
        self.assertEqual(cli.get("/ajustes/logo.png").status_code, 404)

    def test_con_logo_la_ruta_lo_sirve_sin_sesion_como_el_favicon(self):
        datos, tipo = marca.normalizar(_png())
        with db.session(self.ruta) as conn:
            db.set_logo(conn, datos, tipo, "logo.png", "admin@ejemplo.local")
        cli = self._app().test_client()
        r = cli.get("/ajustes/logo.png")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.mimetype, "image/png")
        self.assertTrue(r.data.startswith(b"\x89PNG"))

    def test_subir_logo_exige_csrf(self):
        cli = self._app().test_client()
        cli.post("/login", data={"usuario": "admin@ejemplo.local", "password": CLAVE})
        archivo = (io.BytesIO(_png()), "logo.png")
        r = cli.post("/ajustes/logo", data={"logo": archivo}, content_type="multipart/form-data")
        # Sin csrf en el formulario: la petición se rechaza, igual que el resto de
        # formularios que escriben (misma regla que test_post_sin_csrf_se_rechaza).
        self.assertEqual(r.status_code, 400)

    def test_un_fichero_que_no_es_imagen_no_se_guarda(self):
        cli = self._app().test_client()
        cli.post("/login", data={"usuario": "admin@ejemplo.local", "password": CLAVE})
        html = cli.get("/ajustes/").get_data(as_text=True)
        import re
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        archivo = (io.BytesIO(b"no es una imagen" * 20), "logo.png")
        r = cli.post("/ajustes/logo", data={"csrf": csrf, "logo": archivo},
                     content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn("no se pudo usar la imagen", r.get_data(as_text=True).lower())
        with db.connect(self.ruta) as conn:
            self.assertIsNone(db.get_logo(conn))

    def test_un_perfil_sin_administracion_no_puede_subir_ni_borrar(self):
        cli = self._app().test_client()
        cli.post("/login", data={"usuario": "lectora@ejemplo.local", "password": CLAVE})
        archivo = (io.BytesIO(_png()), "logo.png")
        r = cli.post("/ajustes/logo", data={"logo": archivo}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 403)
        r = cli.post("/ajustes/logo/borrar")
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
