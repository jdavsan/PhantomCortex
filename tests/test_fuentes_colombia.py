"""Fuentes colombianas: CSIRT Financiero (Asobancaria, RSS 2.0 de Plone con
<guid> y sin <link>) y ColCERT (listado HTML del CMS Newtenberg, sin RSS).

Sin red: las descargas se simulan con FetchResult ya construidos. Se comprueba
que las semillas validan, que el RSS con <guid> conserva enlace y fecha, que el
HTML de ColCERT (con cadena de meta refresh) se normaliza al mismo formato que
un RSS y que el recolector lo guarda en una base temporal."""
from __future__ import annotations

import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from threatintel import collector, db, http, identity, sources
from threatintel.paths import BASE_DIR

URL_RSS = "https://www.csirtasobancaria.com/rss.xml"
URL_COLCERT = "https://www.colcert.gov.co/800/w3-propertyvalue-412601.html"

RSS_MUESTRA = b"""<?xml version="1.0" encoding="utf-8" ?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>CSIRT Asobancaria</title>
    <link>http://www.csirtasobancaria.com/Plone</link>
    <description></description>
    <language>es</language>
    <item>
      <title>Nuevo malware BraZetsu dirigido a organizaciones de Latinoam\xc3\xa9rica</title>
      <description>Se observ\xc3\xb3 a BraZetsu, un framework de malware para Windows.</description>
      <pubDate>Wed, 02 Sep 2026 19:05:08 -0500</pubDate>
      <guid>http://www.csirtasobancaria.com/Plone/alertas-de-seguridad/nuevo-malware-brazetsu</guid>
    </item>
    <item>
      <title>Campa\xc3\xb1a de phishing contra PostgreSQL expuesto (CVE-2026-1111)</title>
      <description>Explotaci\xc3\xb3n activa de PostgreSQL 16.</description>
      <pubDate>Tue, 01 Sep 2026 10:00:00 -0500</pubDate>
      <guid>http://www.csirtasobancaria.com/Plone/alertas-de-seguridad/phishing-postgresql</guid>
    </item>
  </channel>
</rss>
"""

# Portada de ColCERT: solo un meta refresh hacia el canal.
HTML_PORTADA = b"""<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head><title>ColCERT</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<meta http-equiv="refresh" content="0;URL=./800/w3-channel.html">
</head><body></body></html>"""

# Segundo salto (redireccion de propertyvalue a articulo, tal cual la sirve el CMS).
# Lleva UN recuadro fechado («Aliados estratégicos», como el canal real): antes el
# recolector se detenía aquí con una entrada en vez de seguir hasta el listado.
HTML_SALTO = ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">'
              '<!--begin-box:ColCERT_redirect_eidox::16719:-->'
              '<meta http-equiv="refresh" content="0;URL=w3-propertyvalue-412601.html">'
              '<!--end-box--></head><body>'
              '<div class="recuadro"><div class="h5"><a href="w3-article-198651.html">Aliados estratégicos</a></div>'
              '<h6 class="fecha">1 de enero de 2026</h6></div>'
              '</body></html>').encode("utf-8")

# Listado real reducido: tres recuadros, un enlace de menu y otro de pie sin fecha,
# y un recuadro repetido (el CMS publica el mismo aviso dos veces a veces).
HTML_LISTADO = """<!DOCTYPE html><html><head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><title>Boletines</title>
<script>var x = "<a href='w3-article-1.html'>no</a>";</script>
</head><body>
<nav><a href="w3-propertyvalue-386765.html">Alertas de Seguridad</a>
<a href="w3-article-198656.html#formulario">Reporte Incidentes</a></nav>
<div id="paginador_portadilla" class="col-12 card_01">
 <div class="recuadro col-12 col-md-6 col-lg-4 py-3"><div class="p-4 card h-100">
  <div class="h5 font-weight-bold aid-440346 cid-699"><a href="w3-article-440346.html">COLCERT AL &#8211; 20260819 - 113 Alerta: Cisco Secure Firewall ASA y FTD CVE-2026-20349</a></div>
  <h6 class="fecha cid-699 aid-440346 pnid-567 iso8601-20260819T0800000500">19 de agosto de 2026</h6>
  <div class="tipo filtrar my-2"><span class="pv-branch"><span class="pvid-1040004">Alerta (AL)</span></span></div>
  <div class="anio filtrar badge"><span><span>2026</span></span></div>
 </div></div>
 <div class="recuadro col-12 col-md-6 col-lg-4 py-3"><div class="p-4 card h-100">
  <div class="h5 font-weight-bold"><a href="w3-article-440418.html">COLCERT AL – 20260826 - 116 Alerta: Reactivación del Troyano Bancario Grandoreiro en Latinoamérica</a></div>
  <h6 class="fecha">26 de agosto de 2026</h6>
  <div class="tipo filtrar my-2"><span><span>Alerta (AL)</span></span></div>
 </div></div>
 <div class="recuadro col-12 col-md-6 col-lg-4 py-3"><div class="p-4 card h-100">
  <div class="h5 font-weight-bold"><a href="w3-article-440418.html">COLCERT AL – 20260826 - 116 Alerta: Reactivación del Troyano Bancario Grandoreiro en Latinoamérica</a></div>
  <h6 class="fecha">26 de agosto de 2026</h6>
 </div></div>
 <div class="recuadro col-12 col-md-6 col-lg-4 py-3"><div class="p-4 card h-100">
  <div class="h5"><a href="w3-article-440104.html">COLCERT AL – 20260805 - 109 Alerta: Vulnerabilidad crítica en WordPress — cadena wp2shell</a></div>
  <h6 class="fecha iso8601-20260805T1230000500">05 de agosto de 2026</h6>
  <div class="tipo filtrar my-2"><span><span>Alerta (AL)</span></span></div>
 </div></div>
</div>
<footer><a href="w3-article-198654.html">colcert.gov.co</a></footer>
</body></html>""".encode("utf-8")


def _fetch(url: str, contenido: bytes, *, encoding: str | None = "ISO-8859-1") -> http.FetchResult:
    """Imita lo que devuelve http.fetch para text/html sin charset en la cabecera."""
    return http.FetchResult(True, 200, contenido, None, 12, url, content_type="text/html",
                            encoding=encoding)


def _fetch_colcert(url: str, **_kw) -> http.FetchResult:
    if url == "https://www.colcert.gov.co/":
        return _fetch(url, HTML_PORTADA)
    if url == "https://www.colcert.gov.co/800/w3-channel.html":
        return _fetch(url, HTML_SALTO)
    if url == URL_COLCERT:
        return _fetch(url, HTML_LISTADO)
    return http.FetchResult(False, 404, None, "http_404", 5, url)


class Cfg(dict):
    """Configuración mínima con `.get`, como la usan collector y translate."""


class TestSemillas(unittest.TestCase):
    def test_tipo_nuevo_registrado_en_todas_partes(self):
        from webui.vistas import fuentes as vista
        self.assertIn("html_colcert", sources.KINDS)
        self.assertIn("html_colcert", collector.TIPOS_RECOLECTABLES)
        self.assertIn("html_colcert", vista.TIPOS)
        self.assertIn("html_colcert", vista.TIPO_ES)
        self.assertRegex(vista.TIPO_ES["html_colcert"], r"ColCERT")
        # Todo tipo que la GUI ofrece debe ser un tipo que el modelo valida
        for tipo in vista.TIPOS:
            self.assertIn(tipo, sources.KINDS)

    def test_semillas_colombianas_validan(self):
        for slug, kind in (("csirt_financiero", "rss"), ("colcert", "html_colcert")):
            semilla = sources.CATALOGO_POR_SLUG[slug]
            datos = sources._validar(semilla, para_crear=True)
            self.assertEqual(datos["kind"], kind)
            self.assertEqual(datos["category"], "government")
            self.assertEqual(datos["priority"], "high")
            self.assertEqual(datos["enabled"], 1)
            self.assertTrue(datos["notes"])
            self.assertRegex(datos["notes"], r"Prueba en vivo del 2026-09-05")
        self.assertEqual(sources.CATALOGO_POR_SLUG["csirt_financiero"]["url"], URL_RSS)
        self.assertEqual(sources.CATALOGO_POR_SLUG["colcert"]["url"], URL_COLCERT)
        # Los slugs son únicos en el catálogo
        slugs = [f["slug"] for f in sources.CATALOGO]
        self.assertEqual(len(slugs), len(set(slugs)))

    def test_seed_crea_las_dos_fuentes_en_base_temporal(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as d:
            ruta = str(Path(d) / "semilla.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                sources.seed(conn, solo_nuevas=True)
                colcert = sources.obtener(conn, "colcert")
                csirt = sources.obtener(conn, "csirt_financiero")
            self.assertEqual(colcert["kind"], "html_colcert")
            self.assertTrue(colcert["enabled"])
            self.assertEqual(csirt["kind"], "rss")
            self.assertTrue(csirt["enabled"])


class TestRssConGuid(unittest.TestCase):
    def test_guid_sin_link_da_enlace_y_fecha(self):
        res = http.FetchResult(True, 200, RSS_MUESTRA, None, 20, URL_RSS,
                               content_type="application/atom+xml", encoding="utf-8")
        with mock.patch.object(http, "_descargar", return_value=res):
            feed = http.fetch_feed(URL_RSS, timeout=5, retries=0)
        self.assertTrue(feed.ok)
        self.assertEqual(len(feed.entries), 2)
        primera = feed.entries[0]
        self.assertEqual(primera["link"],
                         "http://www.csirtasobancaria.com/Plone/alertas-de-seguridad/nuevo-malware-brazetsu")
        self.assertEqual(primera["title"],
                         "Nuevo malware BraZetsu dirigido a organizaciones de Latinoamérica")
        self.assertIn("BraZetsu", primera["summary"])
        fecha = collector._fecha_entrada(primera)
        self.assertEqual(fecha, datetime(2026, 9, 3, 0, 5, 8, tzinfo=timezone.utc))
        segunda = feed.entries[1]
        self.assertEqual(identity.extraer_cve(segunda["title"], segunda["summary"]), "CVE-2026-1111")

    def test_probar_url_rss_da_muestra(self):
        res = http.FetchResult(True, 200, RSS_MUESTRA, None, 20, URL_RSS,
                               content_type="application/atom+xml", encoding="utf-8")
        with mock.patch.object(http, "_descargar", return_value=res):
            prueba = sources.probar_url(URL_RSS, kind="rss", timeout_s=5)
        self.assertTrue(prueba["ok"])
        self.assertEqual(prueba["entries"], 2)
        self.assertIn("BraZetsu", prueba["muestra"][0])


class TestAnalizadorColcert(unittest.TestCase):
    def test_listado_se_normaliza_como_un_rss(self):
        entradas, refresh = collector.analizar_html_colcert(HTML_LISTADO.decode("utf-8"), URL_COLCERT)
        self.assertIsNone(refresh)
        # Tres avisos: el repetido se funde, el menú y el pie (sin fecha) se descartan
        self.assertEqual(len(entradas), 3)
        self.assertEqual(set(entradas[0]), {"title", "summary", "link", "published",
                                             "published_parsed", "id"})
        cisco = entradas[0]
        self.assertEqual(cisco["title"],
                         "COLCERT AL – 20260819 - 113 Alerta: Cisco Secure Firewall ASA y FTD CVE-2026-20349")
        self.assertEqual(cisco["link"], "https://www.colcert.gov.co/800/w3-article-440346.html")
        self.assertEqual(cisco["id"], cisco["link"])
        self.assertEqual(cisco["published"], "2026-08-19T08:00:00-05:00")   # de la clase iso8601
        self.assertEqual(collector._fecha_entrada(cisco),
                         datetime(2026, 8, 19, 13, 0, tzinfo=timezone.utc))
        self.assertEqual(cisco["summary"], "Alerta (AL) publicada por ColCERT el 19 de agosto de 2026.")
        self.assertEqual(identity.extraer_cve(cisco["title"], cisco["summary"]), "CVE-2026-20349")
        # Sin clase iso8601: la fecha sale del texto en español
        grandoreiro = entradas[1]
        self.assertEqual(grandoreiro["published"], "2026-08-26T00:00:00-05:00")
        self.assertIn("Grandoreiro", grandoreiro["title"])
        self.assertEqual(grandoreiro["link"], "https://www.colcert.gov.co/800/w3-article-440418.html")
        enlaces = {e["link"] for e in entradas}
        self.assertNotIn("https://www.colcert.gov.co/800/w3-article-198654.html", enlaces)
        self.assertNotIn("https://www.colcert.gov.co/800/w3-article-198656.html", enlaces)
        self.assertNotIn("https://www.colcert.gov.co/800/w3-article-1.html", enlaces)

    def test_meta_refresh_se_detecta(self):
        entradas, refresh = collector.analizar_html_colcert(
            HTML_PORTADA.decode("utf-8"), "https://www.colcert.gov.co/")
        self.assertEqual(entradas, [])
        self.assertEqual(refresh, "https://www.colcert.gov.co/800/w3-channel.html")

    def test_fecha_en_espanol_y_numerica(self):
        self.assertEqual(collector._fecha_texto_colcert("Última actualización: 8 de julio de 2024").date(),
                         datetime(2024, 7, 8).date())
        self.assertEqual(collector._fecha_texto_colcert("26/08/2026").date(), datetime(2026, 8, 26).date())
        self.assertEqual(collector._fecha_texto_colcert("2026-08-26").date(), datetime(2026, 8, 26).date())
        self.assertIsNone(collector._fecha_texto_colcert("sin fecha"))
        self.assertIsNone(collector._fecha_texto_colcert("31 de febrero de 2026"))

    def test_descarga_sigue_la_cadena_de_meta_refresh(self):
        with mock.patch.object(collector.http, "fetch", side_effect=_fetch_colcert) as f:
            res = collector.descargar_html_colcert("https://www.colcert.gov.co/", timeout=5, retries=0)
        self.assertTrue(res.ok)
        self.assertEqual(len(res.entries), 3)
        self.assertEqual(res.final_url, URL_COLCERT)
        self.assertEqual(f.call_count, 3)
        # Las tildes sobreviven aunque requests suponga ISO-8859-1 (sin charset en la cabecera)
        self.assertIn("Reactivación", res.entries[1]["title"])

    def test_cadena_de_meta_refresh_demasiado_larga_se_corta(self):
        contador = {"n": 0}

        def sin_fin(url, **_kw):
            contador["n"] += 1
            siguiente = f"salto-{contador['n']}.html".encode()
            return _fetch(url, b'<html><head><meta http-equiv="refresh" content="0;URL='
                          + siguiente + b'"></head></html>')

        with mock.patch.object(collector.http, "fetch", side_effect=sin_fin) as f:
            res = collector.descargar_html_colcert("https://www.colcert.gov.co/a.html", timeout=5, retries=0)
        self.assertFalse(res.ok)
        self.assertEqual(res.error, "redirecciones")
        self.assertEqual(f.call_count, collector.MAX_META_REFRESH + 1)

    def test_meta_refresh_hacia_si_mismo_no_se_repite(self):
        propio = _fetch("https://www.colcert.gov.co/a.html",
                        b'<html><head><meta http-equiv="refresh" content="0;URL=a.html"></head></html>')
        with mock.patch.object(collector.http, "fetch", return_value=propio) as f:
            res = collector.descargar_html_colcert("https://www.colcert.gov.co/a.html", timeout=5, retries=0)
        self.assertFalse(res.ok)
        self.assertEqual(res.error, "redirecciones")
        self.assertEqual(f.call_count, 1)

    def test_errores_de_descarga_se_propagan(self):
        caido = http.FetchResult(False, 503, None, "http_503", 30, URL_COLCERT)
        with mock.patch.object(collector.http, "fetch", return_value=caido):
            res = collector.descargar_html_colcert(URL_COLCERT, timeout=5, retries=0)
        self.assertFalse(res.ok)
        self.assertEqual((res.status, res.error), (503, "http_503"))
        with mock.patch.object(collector.http, "fetch", return_value=_fetch(URL_COLCERT, b"   ")):
            self.assertEqual(collector.descargar_html_colcert(URL_COLCERT).error, "vacio")
        with mock.patch.object(collector.http, "fetch", return_value=_fetch(URL_COLCERT, b'{"a": 1}')):
            self.assertEqual(collector.descargar_html_colcert(URL_COLCERT).error, "parse")

    def test_pagina_sin_avisos_es_ok_con_cero_entradas(self):
        sin_avisos = _fetch(URL_COLCERT, b"<html><body><p>Sin recuadros</p></body></html>")
        with mock.patch.object(collector.http, "fetch", return_value=sin_avisos):
            res = collector.descargar_html_colcert(URL_COLCERT)
        self.assertTrue(res.ok)
        self.assertEqual(res.entries, [])

    def test_probar_url_html_colcert(self):
        with mock.patch.object(collector.http, "fetch", side_effect=_fetch_colcert):
            prueba = sources.probar_url(URL_COLCERT, kind="html_colcert", timeout_s=5)
        self.assertTrue(prueba["ok"])
        self.assertEqual(prueba["entries"], 3)
        self.assertIn("Cisco Secure Firewall", prueba["muestra"][0])


class TestHallazgosRevisionColcert(unittest.TestCase):
    """Hallazgos de la revisión del 2026-09-05: concordancia del resumen, elementos
    vacíos dentro del recuadro, cadena completa de meta refresh y enlaces ajenos."""

    FECHA = datetime(2026, 8, 19, tzinfo=collector._ZONA_COLOMBIA)

    def test_resumen_concuerda_con_el_genero_del_tipo(self):
        r = collector._resumen_colcert
        self.assertEqual(r("Alerta (AL)", self.FECHA), "Alerta (AL) publicada por ColCERT el 19 de agosto de 2026.")
        self.assertEqual(r("Advertencia (AD)", self.FECHA),
                         "Advertencia (AD) publicada por ColCERT el 19 de agosto de 2026.")
        self.assertEqual(r("Informe (IN)", self.FECHA), "Informe (IN) publicado por ColCERT el 19 de agosto de 2026.")
        self.assertEqual(r("Reporte semanal (RS)", self.FECHA),
                         "Reporte semanal (RS) publicado por ColCERT el 19 de agosto de 2026.")
        self.assertEqual(r("Boletín PMU CSIRT", self.FECHA),
                         "Boletín PMU CSIRT publicado por ColCERT el 19 de agosto de 2026.")
        self.assertEqual(r("Boletín PMU Ciber Electoral", self.FECHA),
                         "Boletín PMU Ciber Electoral publicado por ColCERT el 19 de agosto de 2026.")
        self.assertEqual(r("Aviso", self.FECHA), "Aviso publicado por ColCERT el 19 de agosto de 2026.")
        # Sin tipo: aviso genérico
        self.assertEqual(r("", self.FECHA), "Aviso publicado por ColCERT el 19 de agosto de 2026.")
        # Tipo desconocido o compuesto (el CMS pone dos tipos en un recuadro): redacción neutra
        self.assertEqual(r("Reporte semanal (RS) Advertencia (AD)", self.FECHA),
                         "ColCERT publicó este aviso (Reporte semanal (RS) Advertencia (AD)) el 19 de agosto de 2026.")
        self.assertEqual(r("Infografía", self.FECHA),
                         "ColCERT publicó este aviso (Infografía) el 19 de agosto de 2026.")
        # Nunca «publicada» con un tipo masculino ni «publicado» con uno femenino
        for tipo in ("Informe (IN)", "Reporte semanal (RS)", "Boletín PMU CSIRT"):
            self.assertNotIn("publicada", r(tipo, self.FECHA))
        for tipo in ("Alerta (AL)", "Advertencia (AD)"):
            self.assertNotIn("publicado", r(tipo, self.FECHA))

    def test_listado_con_informe_y_tipo_compuesto(self):
        html = """<html><body>
        <div class="recuadro"><div class="h5"><a href="w3-article-1.html">COLCERT IN – 20260810 - 05 Informe: panorama</a></div>
          <h6 class="fecha">10 de agosto de 2026</h6>
          <div class="tipo"><span><span>Informe (IN)</span></span></div></div>
        <div class="recuadro"><div class="h5"><a href="w3-article-2.html">COLCERT RS – 20260811 Reporte semanal</a></div>
          <h6 class="fecha">11 de agosto de 2026</h6>
          <div class="tipo"><span><span>Reporte semanal (RS)</span></span><span><span>Advertencia (AD)</span></span></div></div>
        </body></html>"""
        entradas, _ = collector.analizar_html_colcert(html, URL_COLCERT)
        self.assertEqual([e["summary"] for e in entradas], [
            "Informe (IN) publicado por ColCERT el 10 de agosto de 2026.",
            "ColCERT publicó este aviso (Reporte semanal (RS) Advertencia (AD)) el 11 de agosto de 2026.",
        ])

    def test_elementos_vacios_no_desfasan_la_captura(self):
        # <br/>, <img>, <input> dentro de la fecha y del tipo (el listado real los lleva):
        # la fecha y el tipo del primer recuadro se leen bien y el segundo recuadro no se pierde.
        html = """<html><body>
        <div class="recuadro"><div class="h5"><a href="w3-article-10.html">Primero</a></div>
          <h6 class="fecha">19 de<br/>agosto de <img src="x.png" alt=""> 2026<input type="hidden" value="1"></h6>
          <div class="tipo"><span>Alerta<br>(AL)</span><hr></div>
          <div class="anio"><span>2026</span></div></div>
        <div class="recuadro"><div class="h5"><a href="w3-article-11.html">Segundo</a></div>
          <h6 class="fecha iso8601-20260820T0800000500">20 de agosto de 2026</h6>
          <div class="tipo"><span><span>Informe (IN)</span></span></div></div>
        <div class="recuadro"><div class="h5"><a href="w3-article-12.html">Tercero</a></div>
          <h6 class="fecha">21 de agosto de 2026</br></h6></div>
        </body></html>"""
        entradas, _ = collector.analizar_html_colcert(html, URL_COLCERT)
        self.assertEqual([e["title"] for e in entradas], ["Primero", "Segundo", "Tercero"])
        self.assertEqual([e["published"][:10] for e in entradas], ["2026-08-19", "2026-08-20", "2026-08-21"])
        self.assertEqual(entradas[0]["summary"], "Alerta (AL) publicada por ColCERT el 19 de agosto de 2026.")
        self.assertEqual(entradas[1]["summary"], "Informe (IN) publicado por ColCERT el 20 de agosto de 2026.")
        self.assertEqual(entradas[2]["summary"], "Aviso publicado por ColCERT el 21 de agosto de 2026.")

    def test_enlaces_de_otros_dominios_no_son_avisos(self):
        html = """<html><body>
        <div class="recuadro"><a href="https://www.otro-sitio.gov.co/800/w3-article-1.html">Ajeno</a>
          <h6 class="fecha">1 de agosto de 2026</h6></div>
        <div class="recuadro"><a href="javascript:abrir('w3-article-2.html')">Guion</a>
          <h6 class="fecha">2 de agosto de 2026</h6></div>
        <div class="recuadro"><a href="https://colcert.gov.co/800/w3-article-3.html">Mismo dominio sin www</a>
          <h6 class="fecha">3 de agosto de 2026</h6></div>
        <div class="recuadro"><a href="https://www.colcert.gov.co/800/w3-article-4.html">Mismo dominio absoluto</a>
          <h6 class="fecha">4 de agosto de 2026</h6></div>
        <div class="recuadro"><a href="/800/w3-article-5.html">Relativo a la raíz</a>
          <h6 class="fecha">5 de agosto de 2026</h6></div>
        <div class="recuadro"><a href="w3-article-6.html">Relativo</a>
          <h6 class="fecha">6 de agosto de 2026</h6></div>
        </body></html>"""
        entradas, _ = collector.analizar_html_colcert(html, URL_COLCERT)
        self.assertEqual([e["title"] for e in entradas],
                         ["Mismo dominio sin www", "Mismo dominio absoluto", "Relativo a la raíz", "Relativo"])
        self.assertEqual(entradas[2]["link"], "https://www.colcert.gov.co/800/w3-article-5.html")
        # La fecha del recuadro ajeno no se cuela en el primero que sí cuenta
        self.assertEqual(entradas[0]["published"][:10], "2026-08-03")

    def test_cadena_completa_se_queda_con_la_pagina_con_mas_avisos(self):
        # Portada → canal (1 recuadro + refresh) → listado (3 recuadros): antes se paraba en el canal
        with mock.patch.object(collector.http, "fetch", side_effect=_fetch_colcert) as f:
            res = collector.descargar_html_colcert("https://www.colcert.gov.co/", timeout=5, retries=0)
        self.assertTrue(res.ok)
        self.assertEqual(f.call_count, 3)
        self.assertEqual(len(res.entries), 3)
        self.assertEqual(res.final_url, URL_COLCERT)
        self.assertNotIn("Aliados estratégicos", [e["title"] for e in res.entries])
        self.assertEqual(res.latency_ms, 36)                    # suma de los tres saltos (12 cada uno)

    def test_pagina_intermedia_con_mas_avisos_que_la_final_se_conserva(self):
        def servidor(url, **_kw):
            if url.endswith("/a.html"):
                return _fetch(url, HTML_LISTADO.replace(b"</head>",
                              b'<meta http-equiv="refresh" content="0;URL=b.html"></head>'))
            return _fetch(url, HTML_SALTO.replace(b'<meta http-equiv="refresh" content="0;URL=w3-propertyvalue-412601.html">', b""))

        with mock.patch.object(collector.http, "fetch", side_effect=servidor) as f:
            res = collector.descargar_html_colcert("https://www.colcert.gov.co/800/a.html", timeout=5, retries=0)
        self.assertEqual(f.call_count, 2)                       # se siguió el refresh igualmente
        self.assertTrue(res.ok)
        self.assertEqual(len(res.entries), 3)
        self.assertEqual(res.final_url, "https://www.colcert.gov.co/800/a.html")

    def test_salto_caido_conserva_la_pagina_anterior_con_avisos(self):
        def servidor(url, **_kw):
            if url.endswith("/a.html"):
                return _fetch(url, HTML_LISTADO.replace(b"</head>",
                              b'<meta http-equiv="refresh" content="0;URL=b.html"></head>'))
            return http.FetchResult(False, 503, None, "http_503", 7, url)

        with mock.patch.object(collector.http, "fetch", side_effect=servidor):
            res = collector.descargar_html_colcert("https://www.colcert.gov.co/800/a.html", timeout=5, retries=0)
        self.assertTrue(res.ok)
        self.assertEqual(len(res.entries), 3)
        # …pero si la única página con refresh no tenía avisos, el fallo del salto se propaga
        def servidor2(url, **_kw):
            if url.endswith("/a.html"):
                return _fetch(url, HTML_PORTADA)
            return http.FetchResult(False, 503, None, "http_503", 7, url)

        with mock.patch.object(collector.http, "fetch", side_effect=servidor2):
            res = collector.descargar_html_colcert("https://www.colcert.gov.co/a.html", timeout=5, retries=0)
        self.assertFalse(res.ok)
        self.assertEqual(res.error, "http_503")

    def test_bucle_de_refresh_con_avisos_devuelve_los_avisos(self):
        # a → b → a: bucle, pero «a» tiene avisos: se devuelven en vez de fallar
        def servidor(url, **_kw):
            if url.endswith("/a.html"):
                return _fetch(url, HTML_LISTADO.replace(b"</head>",
                              b'<meta http-equiv="refresh" content="0;URL=b.html"></head>'))
            return _fetch(url, b'<html><head><meta http-equiv="refresh" content="0;URL=a.html"></head></html>')

        with mock.patch.object(collector.http, "fetch", side_effect=servidor) as f:
            res = collector.descargar_html_colcert("https://www.colcert.gov.co/800/a.html", timeout=5, retries=0)
        self.assertEqual(f.call_count, 2)
        self.assertTrue(res.ok)
        self.assertEqual(len(res.entries), 3)


class TestRecolectorColcert(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "colombia.db")
        db.init_db(self.ruta)
        with db.session(self.ruta) as conn:
            ahora = db.utcnow()
            conn.execute(
                """INSERT INTO technologies(slug,name,vendor,category,criticality,systems_count,
                       exposure,enabled,created_at,updated_at)
                   VALUES('cisco-asa','Cisco ASA','Cisco','red','high',2,'internet',1,?,?)""",
                (ahora, ahora))
            tid = conn.execute("SELECT id FROM technologies WHERE slug='cisco-asa'").fetchone()[0]
            conn.execute("INSERT INTO tech_aliases(technology_id, alias, match_mode) VALUES(?,?,?)",
                         (tid, "Cisco Secure Firewall", "phrase"))
            self.source_id = sources.crear(
                conn, slug="colcert", name="ColCERT (Gobierno de Colombia)", url=URL_COLCERT,
                kind="html_colcert", category="government", priority="high", enabled=1, timeout_s=45)
            # Una API activa: no debe recolectarse como feed ni contarse como fallo
            sources.crear(conn, slug="cisa_kev", name="CISA KEV", url=sources.URL_CISA_KEV,
                          kind="kev_json", category="government", priority="critical", enabled=1)
        self.cfg = Cfg(translate_engine="none", collect_lookback_days=3650,
                       collect_require_technology=True, http_retries=0,
                       ollama_max_calls_per_run=0)

    def tearDown(self):
        self.dir.cleanup()

    def test_recolecta_y_guarda_solo_lo_correlacionado(self):
        ahora_fijo = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
        with mock.patch.object(collector.http, "fetch", side_effect=_fetch_colcert), \
             mock.patch.object(collector, "_ahora", return_value=ahora_fijo), \
             mock.patch.object(collector, "comprobar_apis", return_value={}) as apis, \
             db.session(self.ruta) as conn:
            stats = collector.recolectar(conn, cfg=self.cfg)
            filas = [dict(r) for r in conn.execute(
                "SELECT id, cve, title_en, summary_en, published_at, month FROM threats")]
            enlaces = [r[0] for r in conn.execute("SELECT url FROM threat_sources WHERE source_id=?",
                                                  (self.source_id,))]
            salud = [dict(r) for r in conn.execute(
                "SELECT ok, entries, accepted FROM source_health WHERE source_id=?", (self.source_id,))]
            tecnologias = conn.execute("SELECT COUNT(*) FROM threat_technologies").fetchone()[0]

        self.assertEqual(stats["fuentes"], 1)          # la API no se recolecta como feed
        self.assertEqual(stats["fuentes_ok"], 1)
        self.assertEqual(stats["entradas"], 3)
        self.assertEqual(stats["aceptadas"], 1)
        self.assertEqual(stats["descartadas_sin_tecnologia"], 2)
        self.assertTrue(apis.called)
        self.assertEqual(len(filas), 1)
        amenaza = filas[0]
        self.assertEqual(amenaza["cve"], "CVE-2026-20349")
        self.assertIn("Cisco Secure Firewall ASA y FTD", amenaza["title_en"])
        self.assertEqual(amenaza["summary_en"], "Alerta (AL) publicada por ColCERT el 19 de agosto de 2026.")
        self.assertEqual(amenaza["published_at"], "2026-08-19T13:00:00Z")
        self.assertEqual(amenaza["month"], "2026-08")
        self.assertEqual(enlaces, ["https://www.colcert.gov.co/800/w3-article-440346.html"])
        self.assertEqual(salud, [{"ok": 1, "entries": 3, "accepted": 1}])
        self.assertEqual(tecnologias, 1)

    def test_segunda_pasada_no_duplica(self):
        with mock.patch.object(collector.http, "fetch", side_effect=_fetch_colcert), \
             mock.patch.object(collector, "comprobar_apis", return_value={}), \
             db.session(self.ruta) as conn:
            collector.recolectar(conn, cfg=self.cfg)
            stats = collector.recolectar(conn, cfg=self.cfg)
            total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
            vistas = conn.execute("SELECT times_seen FROM threats").fetchone()[0]
        self.assertEqual(total, 1)
        self.assertEqual(vistas, 2)
        self.assertEqual(stats["reaparecidas"], 1)
        self.assertEqual(stats["nuevas"], 0)

    def test_fuente_caida_se_registra_sin_tumbar_la_recoleccion(self):
        caido = http.FetchResult(False, None, None, "timeout", 5000, None)
        with mock.patch.object(collector.http, "fetch", return_value=caido), \
             mock.patch.object(collector, "comprobar_apis", return_value={}), \
             db.session(self.ruta) as conn:
            stats = collector.recolectar(conn, cfg=self.cfg)
            salud = dict(conn.execute(
                "SELECT ok, error FROM source_health WHERE source_id=?", (self.source_id,)).fetchone())
        self.assertEqual(stats["fuentes_fallo"], 1)
        self.assertEqual(stats["fuentes_con_fallo"][0]["slug"], "colcert")
        self.assertEqual(salud, {"ok": 0, "error": "timeout"})

    def test_comprobar_apis_no_toca_las_fuentes_html(self):
        with mock.patch.object(sources, "probar", return_value={"ok": True, "entries": 1,
                                                                "latency_ms": 1, "status": 200,
                                                                "error": None}) as probar, \
             db.session(self.ruta) as conn:
            resultado = collector.comprobar_apis(conn, cfg=self.cfg)
        self.assertEqual(resultado["comprobadas"], 1)
        self.assertEqual(probar.call_count, 1)


class TestInterfazFuentes(unittest.TestCase):
    """La GUI muestra el tipo nuevo en español y permite editar la fuente sin
    perder el tipo (antes un tipo desconocido se reescribía como «rss»)."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "gui.db")
        db.init_db(cls.ruta)
        from webui import auth
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", "AdminSeguro#2026", rol="admin", actor="t")
            sources.seed(conn, solo_nuevas=True)
            cls.colcert_id = sources.obtener(conn, "colcert")["id"]
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "admin", "password": "AdminSeguro#2026"})
        return cli

    def test_detalle_muestra_tipo_en_espanol_y_conserva_el_tipo_al_editar(self):
        cli = self._cliente()
        pagina = cli.get(f"/fuentes/{self.colcert_id}").get_data(as_text=True)
        self.assertIn("Página HTML de avisos de ColCERT", pagina)
        self.assertIn('value="html_colcert" selected', pagina)
        csrf = re.search(r'name="csrf" value="([^"]+)"', pagina).group(1)
        r = cli.post(f"/fuentes/{self.colcert_id}/editar", data={
            "csrf": csrf, "name": "ColCERT (Gobierno de Colombia)", "url": URL_COLCERT,
            "kind": "html_colcert", "category": "government", "priority": "high",
            "timeout_s": "45", "enabled": "1", "notes": "Editada desde la prueba."})
        self.assertIn(r.status_code, (302, 303))
        with db.session(self.ruta) as conn:
            fila = sources.obtener(conn, "colcert")
        self.assertEqual(fila["kind"], "html_colcert")
        self.assertEqual(fila["notes"], "Editada desde la prueba.")


if __name__ == "__main__":
    unittest.main()
