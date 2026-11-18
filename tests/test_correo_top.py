"""Correo de alerta acortado al top de vulnerabilidades más críticas (v7, 2026-09-06).

Petición del usuario: «el correo es muy largo, la idea es que se presente el top 3 de las
vulnerabilidades más críticas para no saturar el correo». Solo se explican en detalle las
``alert_detalle_top`` primeras por relevancia; el resto viaja en la hoja de cálculo adjunta
y está en la plataforma.

**Cambio del 2026-09-15 (v10).** Petición literal del usuario: «en el correo de alertamiento
diario dice que hay muchas vulnerabilidades o amenazas detectadas en el día, así que
necesito que esto se ajuste y se muestren solo el top 10». Hasta hoy la tabla «Prioridad de
actuación» era el índice COMPLETO: listaba todas las alertadas (76 filas el 11 de septiembre,
89 el día 9). Desde hoy lista las ``alert_tabla_top`` de mayor relevancia (10 por omisión) y
el correo dice cuántas quedan fuera y dónde están. Las pruebas de esta clase cambiaron por
eso, a propósito: ver ``TestTablaDePrioridadTopDiez``. El tope de seguridad ``max_tabla``
(``alert_max_items``) se conserva y sigue mandando cuando es menor que el top.

Sin red y sin correo: solo se renderizan plantillas Jinja.
"""
from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional
from unittest import mock

from jinja2 import ChoiceLoader, DictLoader

from threatintel import notify
from threatintel.paths import BASE_DIR

RE_SCRIPT = re.compile(r"<script", re.I)


def _plano(html: str) -> str:
    """El mismo HTML con los espacios normalizados: las frases de la plantilla se parten en
    varias líneas y buscarlas tal cual daría falsos negativos."""
    return re.sub(r"\s+", " ", html)


def _activo(**kw: Any) -> dict:
    datos = {"id": 1, "nombre": "srv-app-01", "ip": "10.1.2.11", "origen": "servidores",
             "so_nombre": "Ubuntu 22.04", "paquetes": ["curl"],
             "version_instalada": "7.81.0-1ubuntu1.15",
             "version_corregida": "7.81.0-1ubuntu1.20", "aviso": "USN-1234-1"}
    datos.update(kw)
    return datos


def _vista(indice: int, **kw: Any) -> dict:
    """ThreatView con la forma que produce ``queries.obtener_amenaza``."""
    datos: dict[str, Any] = {
        "id": indice, "fingerprint": f"huella-{indice}", "cve": f"CVE-2026-10{indice:02d}",
        "title_en": f"Remote code execution number {indice}",
        "title_es": f"Ejecución remota de código número {indice}",
        "summary_en": "English summary", "summary_es": "Descripción en español del fallo.",
        "severity": "Critical", "severity_source": "nvd", "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_version": "3.1",
        "epss_score": 0.42, "in_kev": True, "kev_due_date": "2026-09-20",
        "published_at": "2026-09-01T08:00:00Z", "first_seen_at": "2026-09-05T08:00:00Z",
        "last_seen_at": "2026-09-06T08:00:00Z", "times_seen": 2,
        "impact_es": "Permite tomar el control del servidor.",
        "remediation_es": "Actualizar el paquete a la versión que corrige.",
        "month": "2026-09", "relevance": 95.0 - indice, "estado": "nueva",
        "technologies": [{"name": "curl", "slug": "curl", "version_installed": "7.81.0",
                          "criticality": "critical", "systems_count": 4, "exposure": "internet",
                          "confidence": 1.0, "version_verdict": "affected",
                          "version_evidence": None}],
        "sources": [{"name": "NVD", "slug": "nvd",
                     "url": f"https://nvd.nist.gov/vuln/detail/CVE-2026-10{indice:02d}"}],
        "activos": {"evaluada": True, "n_afectados": 1, "n_no_afectados": 0, "n_sin_dato": 0,
                    "afectados": [_activo()], "mas": 0},
    }
    datos.update(kw)
    return datos


def _meta(**kw: Any) -> dict:
    base = {"periodo": "2026-09", "url_interfaz": "http://soc.ejemplo.local/amenazas/",
            "url_activos": "http://soc.ejemplo.local/activos/",
            "max_detalle": 25, "detalle_top": 3}
    base.update(kw)
    return base


def _render_sin_parches_nuevos(amenazas, meta: Optional[dict] = None) -> str:
    """Renderiza la alerta con ``_parches_nuevos.html`` vacío, como estaba el día en que se
    escribió esta sección: la inclusión no puede romper el correo."""
    entorno = notify.entorno()
    cargador = entorno.loader
    entorno.loader = ChoiceLoader([DictLoader({"_parches_nuevos.html": ""}), cargador])
    entorno.cache.clear()
    try:
        return notify.render_alert_email(amenazas, meta)
    finally:
        entorno.loader = cargador
        entorno.cache.clear()


class TestTopDelDetalle(unittest.TestCase):
    def setUp(self) -> None:
        self.amenazas = [_vista(i) for i in range(1, 11)]

    def _detalladas(self, html: str) -> int:
        return html.count("Por qué está aquí")

    def test_detalle_top_uno(self):
        html = notify.render_alert_email(self.amenazas, _meta(detalle_top=1))
        self.assertEqual(self._detalladas(html), 1)
        self.assertIn("La más crítica, en detalle", _plano(html))
        self.assertIn("9 quedan sin desarrollar aquí", _plano(html))

    def test_detalle_top_tres(self):
        html = notify.render_alert_email(self.amenazas, _meta(detalle_top=3))
        self.assertEqual(self._detalladas(html), 3)
        self.assertIn("Las 3 más críticas, en detalle", _plano(html))
        self.assertIn("7 quedan sin desarrollar aquí", _plano(html))
        # el detalle son las tres de mayor relevancia, en orden
        self.assertIn("Permite tomar el control del servidor", html)

    def test_detalle_top_mayor_que_el_numero_de_amenazas(self):
        html = notify.render_alert_email(self.amenazas, _meta(detalle_top=25))
        self.assertEqual(self._detalladas(html), 10)
        self.assertIn("Detalle", html)
        self.assertNotIn("más críticas, en detalle", html)
        self.assertNotIn("sin desarrollar aquí", html)

    def test_detalle_top_cero_deja_solo_el_indice(self):
        html = notify.render_alert_email(self.amenazas, _meta(detalle_top=0))
        self.assertEqual(self._detalladas(html), 0)
        for amenaza in self.amenazas:
            self.assertIn(amenaza["cve"], html)

    def test_el_correo_se_acorta_de_verdad(self):
        largo = notify.render_alert_email(self.amenazas, _meta(detalle_top=25))
        corto = notify.render_alert_email(self.amenazas, _meta(detalle_top=3))
        self.assertLess(len(corto), len(largo) * 0.7,
                        f"corto {len(corto)} frente a largo {len(largo)}")


class TestTablaDePrioridadTopDiez(unittest.TestCase):
    """La tabla es un top 10 y el correo dice cuántas quedan fuera (2026-09-15)."""

    def _filas(self, html: str) -> list[int]:
        """Los identificadores de las amenazas que tienen fila en la tabla de prioridad.

        Se leen de los enlaces «.../amenazas/<id>» que solo escribe esa tabla: contar
        etiquetas <tr> mediría también las tarjetas del detalle.
        """
        return [int(n) for n in re.findall(
            r'href="http://soc\.ejemplo\.local/amenazas/(\d+)"', html)]

    def test_la_tabla_trae_exactamente_diez_filas(self):
        amenazas = [_vista(i) for i in range(1, 31)]
        html = notify.render_alert_email(amenazas, _meta(detalle_top=3))
        filas = self._filas(html)
        self.assertEqual(len(filas), 10, f"la tabla trae {len(filas)} filas")
        # Y son las diez de MAYOR relevancia, en el orden en que llegan.
        self.assertEqual(filas, [a["id"] for a in amenazas[:10]])
        self.assertIn("Prioridad de actuación", html)

    def test_dice_cuantas_quedan_fuera_y_donde_estan(self):
        amenazas = [_vista(i) for i in range(1, 31)]
        html = notify.render_alert_email(amenazas, _meta(
            detalle_top=3, adjunto_excel="alerta_2026-09-15.xlsx"))
        plano = _plano(html)
        self.assertIn("Faltan 20 amenazas por ver", plano)
        self.assertIn("La tabla de arriba enseña las 10 de mayor relevancia de las 30 amenazas que requieren acción hoy", plano)
        self.assertIn("Las 20 restantes no se han descartado", plano)
        # Los dos sitios donde están, con el enlace de la plataforma.
        self.assertIn("hoja de cálculo adjunta a este correo", plano)
        self.assertIn("http://soc.ejemplo.local/amenazas/", html)
        # Y la cabecera sigue hablando del total, no de las diez.
        self.assertIn("30 amenazas detectadas hoy que requieren acción", plano)

    def test_con_menos_de_diez_no_miente(self):
        amenazas = [_vista(i) for i in range(1, 7)]
        html = notify.render_alert_email(amenazas, _meta(detalle_top=3))
        plano = _plano(html)
        self.assertEqual(len(self._filas(html)), 6)
        self.assertIn("Están todas en la tabla", plano)
        self.assertNotIn("Faltan", plano)
        self.assertNotIn("restantes no se listan", plano)

    def test_con_exactamente_diez_no_dice_que_falte_ninguna(self):
        amenazas = [_vista(i) for i in range(1, 11)]
        html = notify.render_alert_email(amenazas, _meta(detalle_top=3))
        self.assertEqual(len(self._filas(html)), 10)
        self.assertNotIn("Faltan", _plano(html))

    def test_el_ajuste_manda_sobre_el_valor_por_omision(self):
        amenazas = [_vista(i) for i in range(1, 31)]
        html = notify.render_alert_email(amenazas, _meta(detalle_top=3, tabla_top=5))
        self.assertEqual(len(self._filas(html)), 5)
        self.assertIn("Faltan 25 amenazas por ver", _plano(html))

    def test_tope_de_seguridad_de_la_tabla(self):
        """``max_tabla`` (``alert_max_items``) sigue mandando cuando es menor que el top."""
        amenazas = [_vista(i) for i in range(1, 13)]
        html = notify.render_alert_email(amenazas, _meta(detalle_top=2, max_tabla=5))
        plano = _plano(html)
        self.assertEqual(len(self._filas(html)), 5)
        self.assertIn("La tabla de arriba enseña las 5 de mayor relevancia de las 12 amenazas", plano)

    def test_las_tres_mas_criticas_siguen_en_detalle(self):
        amenazas = [_vista(i) for i in range(1, 31)]
        html = notify.render_alert_email(amenazas, _meta(detalle_top=3))
        plano = _plano(html)
        self.assertIn("Las 3 más críticas, en detalle", plano)
        # El detalle escribe «Por qué está aquí» una vez por tarjeta: tres, ni una más.
        self.assertEqual(html.count("Por qué está aquí"), 3)

    def test_el_correo_es_mas_corto_que_con_la_tabla_entera(self):
        amenazas = [_vista(i) for i in range(1, 77)]     # las 76 del 11 de septiembre
        top = notify.render_alert_email(amenazas, _meta(detalle_top=3))
        entera = notify.render_alert_email(amenazas, _meta(detalle_top=3, tabla_top=1000))
        self.assertLess(len(top), len(entera),
                        f"top {len(top)} frente a tabla entera {len(entera)}")

    def test_sin_url_de_interfaz_no_hay_enlaces_rotos(self):
        html = notify.render_alert_email([_vista(1)], {"detalle_top": 1})
        self.assertNotIn('href=""', html)


class TestAjusteDelTopDeLaTabla(unittest.TestCase):
    """El top de la tabla es un ajuste, con su valor por omisión y su tope de seguridad."""

    def test_por_omision_son_diez(self):
        """Sin «tabla_top» en meta, la tabla trae diez filas: es el valor pedido."""
        amenazas = [_vista(i) for i in range(1, 41)]
        html = notify.render_alert_email(amenazas, {"detalle_top": 3})
        filas = len(re.findall(r'font-size:12px; color:#8a939f;[^>]*>\s*\d+</td>', html))
        self.assertEqual(filas, 10)

    def test_un_valor_ilegible_cae_a_diez(self):
        amenazas = [_vista(i) for i in range(1, 41)]
        for valor in ("", None, "muchas", -5, 0):
            with self.subTest(valor=valor):
                html = notify.render_alert_email(
                    amenazas, _meta(detalle_top=1, tabla_top=valor))
                filas = len(re.findall(
                    r'href="http://soc\.ejemplo\.local/amenazas/\d+"', html))
                self.assertGreaterEqual(filas, 1)
                self.assertLessEqual(filas, 10)

    def test_la_ejecucion_diaria_lee_el_ajuste(self):
        """El ajuste tiene que llegar de verdad al correo, no quedarse en la plantilla."""
        codigo = (BASE_DIR / "bin" / "ejecucion_diaria.py").read_text(encoding="utf-8")
        self.assertIn('cfg.get("alert_tabla_top", 10)', codigo)
        self.assertIn('"tabla_top"', codigo)
        # Y «alert_max_items» sigue siendo el tope de seguridad de la tabla.
        self.assertIn('"max_tabla": int(cfg.get("alert_max_items", 25) or 25)', codigo)


class TestMotivoSinVersionCorregida(unittest.TestCase):
    def test_motivo_en_lugar_de_la_raya(self):
        amenaza = _vista(1)
        amenaza["activos"]["afectados"] = [
            _activo(version_corregida=None, sin_parche_motivo="sin_parche_publicado", aviso=None)]
        html = notify.render_alert_email([amenaza], _meta(detalle_top=1))
        self.assertIn("sin corrección publicada", html)

    def test_sin_motivo_dice_pendiente_de_publicar(self):
        amenaza = _vista(1)
        amenaza["activos"]["afectados"] = [_activo(version_corregida=None, aviso=None)]
        html = notify.render_alert_email([amenaza], _meta(detalle_top=1))
        self.assertIn("pendiente de publicar", html)

    def test_con_version_corregida_no_aparece_el_motivo(self):
        html = notify.render_alert_email([_vista(1)], _meta(detalle_top=1))
        self.assertIn("7.81.0-1ubuntu1.20", html)
        self.assertNotIn("pendiente de publicar", html)

    def test_filtro_motivo_sin_parche(self):
        self.assertEqual(notify.motivo_sin_parche("sin_parche_publicado"),
                         "sin corrección publicada")
        self.assertEqual(notify.motivo_sin_parche("distro_sin_empaquetar"),
                         "sin empaquetar en la distribución")
        self.assertEqual(notify.motivo_sin_parche("aviso_sin_version"),
                         "el aviso no indica la versión")
        self.assertEqual(notify.motivo_sin_parche("desconocido"), "pendiente de publicar")
        self.assertEqual(notify.motivo_sin_parche(None), "pendiente de publicar")
        self.assertEqual(notify.motivo_sin_parche(""), "pendiente de publicar")
        self.assertEqual(notify.motivo_sin_parche("texto propio"), "texto propio")


class TestSeccionDeCorrecciones(unittest.TestCase):
    correccion = {"cve": "CVE-2026-0900", "titulo": "Fallo en sudo sin parche hasta hoy",
                  "severidad": "High", "paquete": "sudo", "sistema": "Ubuntu 22.04",
                  "version_corregida": "1.9.9-1ubuntu2.4", "aviso": "USN-7000-1",
                  "dias_en_espera": 12, "n_activos": 5, "n_activos_expuestos": 3,
                  "motivo_es": "La distribución todavía no había empaquetado la corrección",
                  "in_kev": False}

    def test_con_la_plantilla_vacia_el_correo_sigue_saliendo(self):
        html = _render_sin_parches_nuevos([_vista(1)], _meta(detalle_top=1))
        self.assertIn("Prioridad de actuación", html)
        self.assertIn("Cómo leer esta alerta", html)

    def test_con_la_plantilla_vacia_y_correcciones_tampoco_falla(self):
        html = _render_sin_parches_nuevos(
            [_vista(1)], _meta(detalle_top=1, parches_nuevos=[self.correccion]))
        self.assertIn("Prioridad de actuación", html)

    def test_la_seccion_aparece_cuando_hay_correcciones(self):
        html = notify.render_alert_email(
            [_vista(1)], _meta(detalle_top=1, parches_nuevos=[self.correccion]))
        self.assertIn("sudo", html)
        self.assertIn("1.9.9-1ubuntu2.4", html)

    def test_sin_correcciones_no_se_pinta_nada(self):
        html = notify.render_alert_email([_vista(1)], _meta(detalle_top=1))
        self.assertNotIn("1.9.9-1ubuntu2.4", html)


class TestAvisoDelAdjunto(unittest.TestCase):
    def test_se_anuncia_solo_cuando_se_adjunta(self):
        amenazas = [_vista(i) for i in range(1, 11)]
        # Desde el 2026-09-06 hay UN solo anuncio en el pie: dice cuántos ficheros van y
        # para qué sirve cada libro. «adjunto_excel» sigue admitiéndose y alimenta la lista.
        con = notify.render_alert_email(
            amenazas, _meta(detalle_top=3, adjunto_excel="alerta_2026-09-06.xlsx"))
        plano = _plano(con)
        # Revisión de claridad del 2026-09-15: el cuerpo describe cada adjunto por lo que
        # es, sin escribir su nombre de fichero; el nombre real lo enseña el gestor de
        # correo junto al clip.
        self.assertIn("Ficheros adjuntos a este correo", plano)
        self.assertNotIn("alerta_2026-09-06.xlsx", plano)
        self.assertIn("Hoja de cálculo de las vulnerabilidades de esta alerta", plano)
        self.assertIn("una pestaña por vulnerabilidad", plano)
        self.assertIn("hoja de cálculo adjunta", con)
        # Los dos libros, cada uno con su explicación
        dos = notify.render_alert_email(amenazas, _meta(
            detalle_top=3, adjuntos=["alerta_2026-09-06.xlsx", "correcciones_disponibles_2026-09-06.xlsx"]))
        plano_dos = _plano(dos)
        self.assertNotIn("correcciones_disponibles_2026-09-06.xlsx", plano_dos)
        self.assertIn("las correcciones que ya se pueden aplicar", plano_dos)
        sin = notify.render_alert_email(amenazas, _meta(detalle_top=3))
        self.assertNotIn("Ficheros adjuntos a este correo", sin)
        self.assertNotIn("hoja de cálculo adjunta", sin)
        self.assertIn("En la plataforma", _plano(sin))


class TestSinNovedadesYSeguridad(unittest.TestCase):
    def test_correo_sin_novedades_sigue_funcionando(self):
        html = notify.render_alert_email([], {"url_interfaz": "http://soc/amenazas/",
                                              "detalle_top": 3})
        self.assertIn("Sin novedades que requieran acción", html)
        self.assertNotIn("Prioridad de actuación", html)
        self.assertNotIn("Hoja de cálculo adjunta", html)
        texto = notify.html_a_texto(html)
        self.assertIn("Sin novedades", texto)

    def test_sin_novedades_con_la_plantilla_de_parches_vacia(self):
        html = _render_sin_parches_nuevos([], {"detalle_top": 3})
        self.assertIn("Sin novedades que requieran acción", html)

    def test_resumen_semanal_intacto(self):
        """El resumen semanal usa su propia plantilla: nada de lo anterior lo toca."""
        from datetime import datetime

        from threatintel import digest
        html = digest.render({
            "desde": datetime(2026, 8, 30), "hasta": datetime(2026, 9, 6),
            "seguimiento": [], "seguimiento_total": 0, "informativo": [],
            "informativo_total": 0, "descartadas": [], "descartadas_total": 0,
            "alertadas": [], "alertadas_total": 0, "alertadas_omitidas": 0,
            "umbral_relevancia": 50, "min_confianza": 0.6, "horas_espera": 24,
            "maximo": 25, "url_interfaz": "http://soc/amenazas/", "vacio": True})
        self.assertIn("<!doctype html>", html.lower())
        self.assertNotIn("Hoja de cálculo adjunta", html)

    def test_nada_de_script_ni_manejadores_en_el_correo(self):
        html = notify.render_alert_email(
            [_vista(1, title_es="<script>alert(1)</script>",
                    summary_es="<img src=x onerror=alert(2)>")],
            _meta(detalle_top=1, adjunto_excel="alerta.xlsx"))
        self.assertIsNone(RE_SCRIPT.search(html))
        self.assertNotIn("<img", html.lower())      # queda escapado, no como etiqueta
        self.assertIn("&lt;script&gt;", html)

    def test_enlace_con_esquema_peligroso_se_descarta(self):
        html = notify.render_alert_email(
            [_vista(1, sources=[{"name": "X", "slug": "x", "url": "javascript:alert(1)"}])],
            _meta(detalle_top=1))
        self.assertNotIn("javascript:", html.lower())


class TestDatosIncompletos(unittest.TestCase):
    """Un campo sin calcular no puede dejar al SOC sin la alerta del día.

    Desde la v7 la tabla de prioridad lista TODAS las alertadas, así que una relevancia nula
    en la posición 26 tumbaría el correo entero, no solo una fila (hallazgo del revisor del
    2026-09-06)."""

    def test_relevancia_sin_calcular_no_rompe_el_correo(self):
        for valor in (None, "", 0, "88"):
            with self.subTest(relevancia=valor):
                html = notify.render_alert_email(
                    [_vista(1), _vista(2, relevance=valor)], _meta(detalle_top=1))
                self.assertIn("Prioridad de actuación", html)
                self.assertIn("CVE-2026-1002", html)

    def test_puntuaciones_ausentes_dicen_no_disponible(self):
        html = notify.render_alert_email(
            [_vista(1, cvss_score=None, epss_score=None)], _meta(detalle_top=1))
        self.assertIn("no disponible", html)

    def test_vista_a_la_que_le_faltan_claves(self):
        html = notify.render_alert_email(
            [{"id": 7, "cve": "CVE-2026-7777", "severity": "High", "relevance": None,
              "technologies": [], "sources": [], "activos": {}}], _meta(detalle_top=1))
        self.assertIn("CVE-2026-7777", html)
        self.assertIn("no disponible", html)


class TestTipoDelAdjunto(unittest.TestCase):
    """El adjunto se declara con su tipo real: con «application/octet-stream» algunos clientes
    de correo pintan un icono genérico y algunas pasarelas son más restrictivas."""

    HOJA = ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    def test_tipo_por_extension(self):
        self.assertEqual(notify.tipo_adjunto("/data/informes/alerta_2026-09-06.xlsx"), self.HOJA)
        self.assertEqual(notify.tipo_adjunto(Path("ALERTA.XLSX")), self.HOJA)
        self.assertEqual(notify.tipo_adjunto("informe.csv"), ("text", "csv"))
        self.assertEqual(notify.tipo_adjunto("cosa.desconocida"),
                         ("application", "octet-stream"))
        self.assertEqual(notify.tipo_adjunto(None), ("application", "octet-stream"))

    def test_el_mensaje_lleva_el_tipo_real(self):
        """Envío en ``dry_run``: nunca sale un correo real de las pruebas."""
        partes: list = []
        original = notify.MIMEBase

        def espia(tipo, subtipo, **kw):
            parte = original(tipo, subtipo, **kw)
            partes.append(parte)
            return parte

        smtp = SimpleNamespace(from_name="Inteligencia de Amenazas",
                               from_addr="soc@ejemplo.local", reply_to=None,
                               server="localhost", port=25, user="", password="",
                               use_ssl=False, use_tls=False)
        mailer = notify.Mailer(SimpleNamespace(smtp=smtp), dry_run=True)
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            ruta = Path(tmp) / "alerta_2026-09-06.xlsx"
            ruta.write_bytes(b"PK\x03\x04 libro de prueba")
            with mock.patch.object(notify, "MIMEBase", espia):
                enviado = mailer.send(subject="Alerta", html="<p>Hola</p>",
                                      to=["soc@ejemplo.local"], attachments=[ruta])
        self.assertTrue(enviado)
        self.assertEqual([p.get_content_type() for p in partes],
                         ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"])
        self.assertEqual(partes[0].get_filename(), "alerta_2026-09-06.xlsx")


if __name__ == "__main__":
    unittest.main(verbosity=2)
