"""Descripciones reales de las vulnerabilidades (threatintel.enrich, v7, 2026-09-06).

El 6 de septiembre de 2026, 11 de las 25 vulnerabilidades detalladas del correo diario
llevaban como descripción el texto literal «Información publicada.»: el canal de Microsoft
publica ese relleno y el enriquecimiento solo rellenaba las descripciones vacías, así que
nunca lo sustituía. Estas pruebas fijan el comportamiento que lo impide.

Sin red (``threatintel.http.fetch_json`` sustituido por un doble que cuenta las llamadas),
sin correo y con base temporal bajo ``data/``. Cubren: detección del relleno (casos
positivos y negativos, incluidos textos cortos legítimos que NO deben tocarse), sustitución
por NVD, por CVE.org y por el boletín de Microsoft leído de la copia local, uso del texto
en inglés que ya había («fuente»), anotación del origen y de la fecha, frase honesta cuando
ninguna fuente publica nada, respeto del ajuste ``descripcion_completar``, idempotencia
(dos pasadas no rehacen el trabajo ni consumen red), tope de consultas de red, orden por
relevancia y la garantía de que una descripción buena nunca se sobrescribe.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from threatintel import db, enrich
from threatintel.http import JsonResult
from threatintel.paths import BASE_DIR


class Cfg(dict):
    """Configuración mínima con ``.get`` y ``nvd_api_key``, como la de threatintel.config."""

    nvd_api_key = ""

    def get(self, clave, defecto=None):
        return super().get(clave, defecto)


def cfg_basica(**cambios) -> Cfg:
    base = Cfg({
        "descripcion_completar": True,
        "enrich_nvd_enabled": True,
        "translate_engine": "none",     # sin motor: el texto en inglés se deja como está
        "nvd_rate_limit_sleep_s": 0,    # las pruebas no esperan al límite de NVD
        "http_timeout_s": 5,
        "http_retries": 0,
        "ollama_max_calls_per_run": 0,
    })
    base.update(cambios)
    return base


def _json(data, *, ok=True, status=200):
    return JsonResult(ok=ok, status=status, data=data, error=None, latency_ms=1)


NO_ENCONTRADO = JsonResult(ok=False, status=404, data=None, error="404", latency_ms=1)


def respuesta_nvd(cve: str, descripcion: str) -> JsonResult:
    """Respuesta de la API 2.0 de NVD con una descripción en inglés."""
    return _json({"vulnerabilities": [{"cve": {
        "id": cve,
        "descriptions": [{"lang": "es", "value": "no debe usarse: idioma distinto"},
                         {"lang": "en", "value": descripcion}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
            "baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "version": "3.1", "baseSeverity": "HIGH"}}]},
        "references": [{"url": "https://ejemplo.invalido/aviso"}],
        "published": "2026-09-01T00:00:00.000",
    }}]})


def respuesta_cve_org(cve: str, descripcion: str) -> JsonResult:
    """Respuesta del registro CVE 5.x de CVE.org."""
    return _json({"cveMetadata": {"cveId": cve, "state": "PUBLISHED",
                                  "datePublished": "2026-09-01T00:00:00Z"},
                  "containers": {"cna": {
                      "title": "Aviso del fabricante",
                      "descriptions": [{"lang": "en", "value": descripcion}],
                      "references": [{"url": "https://ejemplo.invalido/cna"}]}}})


class RedFalsa:
    """Doble de ``http.fetch_json``: responde según la URL y cuenta las llamadas."""

    def __init__(self, *, nvd: JsonResult = NO_ENCONTRADO, cve_org: JsonResult = NO_ENCONTRADO):
        self.nvd = nvd
        self.cve_org = cve_org
        self.llamadas: list[str] = []

    def __call__(self, url, **kwargs):
        self.llamadas.append(url)
        if url.startswith(enrich.URL_NVD):
            return self.nvd
        if url.startswith("https://cveawg.mitre.org/"):
            return self.cve_org
        raise AssertionError(f"la prueba no debe salir a la red: {url}")


def documento_msrc(directorio: Path, nombre: str, cve: str, descripcion: str) -> None:
    """Escribe una copia local de boletín CVRF como la que deja threatintel.msrc."""
    documento = {"Vulnerability": [{
        "CVE": cve,
        "Title": {"Value": "Vulnerabilidad de ejemplo"},
        "Notes": [{"Title": "Description", "Type": 2, "Ordinal": "0", "Value": descripcion},
                  {"Title": "FAQ", "Type": 3, "Ordinal": "1", "Value": "otra nota"}],
    }]}
    (directorio / f"{nombre}.json").write_text(json.dumps(documento), encoding="utf-8")


# --------------------------------------------------------------------------
# 1. Deteccion del relleno
# --------------------------------------------------------------------------
class DeteccionRelleno(unittest.TestCase):
    """`es_descripcion_relleno` decide si un texto describe la vulnerabilidad."""

    RELLENO = (
        ("", "vacía"),
        ("   ", "solo espacios"),
        ("Información publicada.", "relleno del canal de Microsoft"),
        ("Information published.", "el mismo relleno en inglés"),
        ("<p>Information published.</p>", "el mismo relleno con etiquetas HTML"),
        ("No description available", "relleno de NVD"),
        ("Descripción no disponible.", "relleno de NVD traducido"),
        ("** RESERVED ** This candidate has been reserved by an organization or "
         "individual that will use it when announcing a new security problem.",
         "identificador reservado"),
        ("** REJECT ** DO NOT USE THIS CANDIDATE NUMBER.", "identificador retirado"),
        ("Reconocimiento Actualizado", "cambio de créditos del boletín"),
        ("Acknowledgement Updated", "cambio de créditos del boletín en inglés"),
        ("Reconocimiento añadido. Esto es sólo un cambio informativo.",
         "cambio de créditos del boletín"),
        ("CWE añadido. Cambio informativo solamente.", "cambio administrativo del boletín"),
        ("Valor CWE actualizado. Esto es sólo un cambio informativo.",
         "cambio administrativo del boletín"),
        ("N/A", "marcador de ausencia de dato"),
        ("Sin datos", "marcador de ausencia de dato"),
        ("CVE-2026-1234", "solo el identificador"),
        ("CVE-2026-1234, CVE-2026-1235", "solo identificadores"),
        ("https://security-tracker.debian.org/tracker/DSA-6155-1", "solo un enlace"),
        ("https:///tracker/", "solo un enlace roto"),
        ("Windows 11 25H2 - Reflujo de salto", "texto corto sin contenido técnico"),
    )

    VALIDAS = (
        "Use after free in Windows Kernel allows an authorized attacker to elevate "
        "privileges locally.",
        "Desbordamiento de búfer en curl.",                      # corta pero técnica
        "Denegación de servicio en el núcleo de Linux.",         # corta pero técnica
        "Buffer overflow in libxml2.",                           # corta pero técnica
        "Actualice a la versión 2.4.58 para corregirlo.",        # corta, con versión
        "Esta vulnerabilidad permite a un atacante remoto ejecutar código arbitrario "
        "en el servidor mediante una petición manipulada.",
        "Este CVE fue asignado por Chrome. Microsoft Edge (Chromium) ingesta Chromium, "
        "que aborda esta vulnerabilidad; consulte las notas de la versión.",
    )

    def test_textos_de_relleno(self):
        for texto, motivo in self.RELLENO:
            with self.subTest(texto=texto[:40]):
                self.assertTrue(enrich.es_descripcion_relleno(texto),
                                f"debería detectarse como relleno ({motivo})")
                self.assertIsInstance(enrich.motivo_relleno(texto), str)

    def test_descripciones_validas_no_se_tocan(self):
        for texto in self.VALIDAS:
            with self.subTest(texto=texto[:40]):
                self.assertFalse(enrich.es_descripcion_relleno(texto),
                                 "una descripción real nunca debe darse por relleno")
                self.assertIsNone(enrich.motivo_relleno(texto))

    def test_titulo_repetido_es_relleno(self):
        titulo = "Apache Gravitino 1.2.1 - Falsificación de petición del lado del servidor"
        self.assertTrue(enrich.es_descripcion_relleno(titulo, titulo=titulo))
        self.assertFalse(enrich.es_descripcion_relleno(titulo, titulo="Otro título distinto"))

    def test_identificador_del_propio_cve(self):
        self.assertTrue(enrich.es_descripcion_relleno("cve-2026-1234", cve="CVE-2026-1234"))

    def test_frase_honesta_no_es_relleno(self):
        """Si lo fuera, el repaso entraría en bucle rehaciéndola cada día."""
        frase = enrich.descripcion_honesta(cve="CVE-2026-1234")
        self.assertFalse(enrich.es_descripcion_relleno(frase))
        self.assertNotIn("Información publicada", frase)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2026-1234", frase)

    def test_frase_honesta_con_enlace_del_aviso(self):
        frase = enrich.descripcion_honesta(cve="CVE-2026-1234",
                                           enlace="https://ejemplo.invalido/aviso")
        self.assertIn("https://ejemplo.invalido/aviso", frase)
        self.assertIn("Sin descripción publicada", frase)


# --------------------------------------------------------------------------
# 2. Sustitucion de la descripcion
# --------------------------------------------------------------------------
# PENDIENTE PARA EL COORDINADOR (2026-09-06): en `threatintel/db.py` el diccionario
# `_COLUMNAS_NUEVAS` repite la clave "threats", asi que la entrada de la v7 pisa a la
# anterior y, ademas, `migrar_columnas` se ejecuta ANTES de crear el esquema: en una base
# NUEVA las columnas `descripcion_origen` y `descripcion_buscada_at` no llegan a crearse
# (si en la base real, que ya tenia la tabla). Mientras se corrige en `db.py` (anadirlas a
# la tabla `threats` del propio esquema), las pruebas las agregan aqui; cuando esten en el
# esquema, esta funcion no hara nada.
COLUMNAS_V7 = (("descripcion_origen", "TEXT"), ("descripcion_buscada_at", "TEXT"))


def asegurar_columnas_v7(ruta: str) -> None:
    with db.session(ruta) as conn:
        existentes = {r[1] for r in conn.execute("PRAGMA table_info(threats)")}
        for nombre, tipo in COLUMNAS_V7:
            if nombre not in existentes:
                conn.execute(f"ALTER TABLE threats ADD COLUMN {nombre} {tipo}")


class _BaseConBase(unittest.TestCase):
    """Base temporal con amenazas de prueba y una carpeta de boletines vacía."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "descripciones.db")
        db.init_db(self.ruta)
        asegurar_columnas_v7(self.ruta)
        self.cache_msrc = Path(self.dir.name) / "msrc"
        self.cache_msrc.mkdir()
        enrich.olvidar_indice_msrc()
        self.conn = db.connect(self.ruta)
        self.addCleanup(self.conn.close)
        self.addCleanup(self.dir.cleanup)
        self.addCleanup(enrich.olvidar_indice_msrc)

    def amenaza(self, fingerprint, cve, *, titulo="Vulnerabilidad en OpenSSL",
                resumen_en="Information published.", resumen_es="Información publicada.",
                severidad="High", relevancia=50.0, estado="nueva", enlace=None):
        ahora = db.utcnow()
        cur = self.conn.execute(
            """INSERT INTO threats(fingerprint, cve, title_en, title_es, summary_en,
                                   summary_es, severity, severity_source, first_seen_at,
                                   last_seen_at, month, relevance, estado)
               VALUES(?,?,?,?,?,?,?,'nvd',?,?,?,?,?)""",
            (fingerprint, cve, titulo, titulo, resumen_en, resumen_es, severidad,
             ahora, ahora, ahora[:7], relevancia, estado))
        threat_id = cur.lastrowid
        if enlace:
            self.conn.execute(
                "INSERT INTO sources(slug, name, url, kind, category, priority, enabled, "
                "timeout_s, created_at, updated_at) VALUES('prueba','Fuente de prueba',?,"
                "'rss','vendor','high',1,10,?,?) ON CONFLICT(slug) DO NOTHING",
                (enlace, ahora, ahora))
            source_id = self.conn.execute(
                "SELECT id FROM sources WHERE slug='prueba'").fetchone()["id"]
            self.conn.execute(
                "INSERT OR IGNORE INTO threat_sources(threat_id, source_id, url, seen_at) "
                "VALUES(?,?,?,?)", (threat_id, source_id, enlace, ahora))
        return threat_id

    def fila(self, threat_id) -> dict:
        return dict(self.conn.execute(
            "SELECT id, cve, title_en, title_es, summary_en, summary_es, severity, "
            "descripcion_origen, descripcion_buscada_at FROM threats WHERE id=?",
            (threat_id,)).fetchone())


class SustitucionPorFuente(_BaseConBase):
    """Orden a): el texto en inglés que ya envió la fuente, si vale, no se vuelve a pedir."""

    def test_usa_el_texto_en_ingles_que_ya_habia(self):
        bueno = ("Use after free in the Windows Kernel allows an authorized attacker to "
                 "elevate privileges locally.")
        tid = self.amenaza("fp-fuente", "CVE-2026-0001", resumen_en=bueno,
                           resumen_es="Información publicada.")
        red = RedFalsa()
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertTrue(resultado["cambiada"])
        self.assertEqual(resultado["origen"], "fuente")
        self.assertEqual(red.llamadas, [], "no debe consultarse la red si el texto ya está")
        fila = self.fila(tid)
        self.assertEqual(fila["summary_en"], bueno, "el texto original se conserva")
        self.assertIsNone(fila["summary_es"],
                          "sin motor de traducción el informe muestra el original en inglés")
        self.assertEqual(fila["descripcion_origen"], "fuente")
        self.assertTrue(fila["descripcion_buscada_at"])


class SustitucionPorNvd(_BaseConBase):
    """Orden b): NVD."""

    DESCRIPCION = ("A use-after-free in the HTTP/2 stack of the Linux kernel allows a "
                   "remote attacker to execute arbitrary code.")

    def test_sustituye_y_anota_origen_y_fecha(self):
        tid = self.amenaza("fp-nvd", "CVE-2026-0002")
        red = RedFalsa(nvd=respuesta_nvd("CVE-2026-0002", self.DESCRIPCION))
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertTrue(resultado["cambiada"])
        self.assertEqual(resultado["origen"], "nvd")
        fila = self.fila(tid)
        self.assertEqual(fila["summary_en"], self.DESCRIPCION)
        self.assertEqual(fila["descripcion_origen"], "nvd")
        self.assertTrue(fila["descripcion_buscada_at"])
        self.assertNotIn("Information published", fila["summary_en"])

    def test_reutiliza_la_respuesta_de_nvd_sin_pedirla_otra_vez(self):
        """El enriquecimiento ya consultó NVD: no debe repetirse la petición."""
        tid = self.amenaza("fp-nvd2", "CVE-2026-0003")
        red = RedFalsa()
        datos = {"encontrado": True, "descripcion": self.DESCRIPCION}
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), nvd=datos,
                cache_msrc=self.cache_msrc)
        self.assertEqual(resultado["origen"], "nvd")
        self.assertEqual(resultado["consultas"], 0)
        self.assertEqual(red.llamadas, [])

    def test_nvd_con_relleno_no_se_acepta(self):
        """NVD también publica «** RESERVED **»: no sirve como descripción."""
        tid = self.amenaza("fp-nvd3", "CVE-2026-0004")
        red = RedFalsa(nvd=respuesta_nvd("CVE-2026-0004", "** RESERVED ** ..."),
                       cve_org=respuesta_cve_org("CVE-2026-0004",
                                                 "SQL injection in the login form allows "
                                                 "an unauthenticated attacker to read the "
                                                 "whole database."))
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertEqual(resultado["origen"], "cve.org")


class SustitucionPorCveOrg(_BaseConBase):
    """Orden c): CVE.org, que ya se cachea en la tabla cve_detalle."""

    def test_sustituye_cuando_nvd_no_tiene_nada(self):
        descripcion = ("Improper input validation in the PDF parser allows a remote "
                       "attacker to cause a denial of service.")
        tid = self.amenaza("fp-cveorg", "CVE-2026-0005")
        red = RedFalsa(cve_org=respuesta_cve_org("CVE-2026-0005", descripcion))
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertEqual(resultado["origen"], "cve.org")
        self.assertEqual(self.fila(tid)["summary_en"], descripcion)
        self.assertEqual(self.fila(tid)["descripcion_origen"], "cve.org")
        guardado = self.conn.execute(
            "SELECT encontrado FROM cve_detalle WHERE cve='CVE-2026-0005'").fetchone()
        self.assertEqual(guardado["encontrado"], 1, "el detalle queda cacheado")


class SustitucionPorBoletinMicrosoft(_BaseConBase):
    """Orden d): la nota del boletín CVRF ya descargado, sin salir a la red."""

    def test_lee_la_nota_del_documento_cvrf(self):
        descripcion = ("<p>Buffer over-read in Windows Routing and Remote Access Service "
                       "allows an unauthorized attacker to disclose information over a "
                       "network.</p>")
        documento_msrc(self.cache_msrc, "2026-Sep", "CVE-2026-0006", descripcion)
        tid = self.amenaza("fp-msrc", "CVE-2026-0006")
        red = RedFalsa()
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertEqual(resultado["origen"], "msrc")
        fila = self.fila(tid)
        self.assertIn("Buffer over-read", fila["summary_en"])
        self.assertNotIn("<p>", fila["summary_en"], "el HTML del boletín se limpia")
        self.assertEqual(fila["descripcion_origen"], "msrc")

    def test_gana_el_boletin_mas_reciente(self):
        documento_msrc(self.cache_msrc, "2025-Apr", "CVE-2026-0007",
                       "Old description of the vulnerability in the Windows kernel.")
        documento_msrc(self.cache_msrc, "2026-Sep", "CVE-2026-0007",
                       "Revised description of the vulnerability in the Windows kernel.")
        self.assertIn("Revised", enrich.descripcion_msrc("CVE-2026-0007",
                                                         cache_dir=self.cache_msrc))

    def test_sin_boletin_devuelve_none(self):
        self.assertIsNone(enrich.descripcion_msrc("CVE-2026-9999",
                                                  cache_dir=self.cache_msrc))
        self.assertIsNone(enrich.descripcion_msrc("no es un cve",
                                                  cache_dir=self.cache_msrc))


class FraseHonesta(_BaseConBase):
    """Cuando ninguna fuente publica nada, se dice la verdad; nunca un relleno."""

    def test_escribe_la_frase_honesta_con_el_enlace_del_aviso(self):
        tid = self.amenaza("fp-nada", "CVE-2026-0008",
                           enlace="https://ejemplo.invalido/aviso-original")
        red = RedFalsa()
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertTrue(resultado["cambiada"])
        self.assertEqual(resultado["origen"], enrich.ORIGEN_SIN_DATO)
        fila = self.fila(tid)
        self.assertIn("Sin descripción publicada todavía", fila["summary_es"])
        self.assertIn("https://ejemplo.invalido/aviso-original", fila["summary_es"])
        self.assertNotIn("Información publicada", fila["summary_es"])
        self.assertEqual(fila["descripcion_origen"], enrich.ORIGEN_SIN_DATO)

    def test_amenaza_sin_cve_tampoco_queda_con_relleno(self):
        tid = self.amenaza("fp-sincve", None,
                           resumen_en="https://security-tracker.debian.org/tracker/DSA-6155-1",
                           resumen_es="https://security-tracker.debian.org/tracker/DSA-6155-1")
        red = RedFalsa()
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertEqual(resultado["origen"], enrich.ORIGEN_SIN_DATO)
        self.assertEqual(red.llamadas, [], "sin CVE no hay nada que consultar")
        self.assertIn("Sin descripción publicada", self.fila(tid)["summary_es"])

    def test_texto_corto_real_se_conserva_si_no_hay_nada_mejor(self):
        """Conservador: un texto pobre pero propio vale más que una frase genérica."""
        corto = "Windows 11 25H2 - Reflujo de salto"
        tid = self.amenaza("fp-corto", "CVE-2026-0009", resumen_en=corto, resumen_es=corto)
        red = RedFalsa()
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertFalse(resultado["cambiada"])
        fila = self.fila(tid)
        self.assertEqual(fila["summary_es"], corto)
        self.assertTrue(fila["descripcion_buscada_at"], "queda anotado que se buscó")

    def test_sin_red_no_se_da_por_perdida_una_amenaza_con_cve(self):
        tid = self.amenaza("fp-sinred", "CVE-2026-0010")
        resultado = enrich.completar_descripcion(
            self.conn, self.fila(tid), cfg=cfg_basica(), permitir_red=False,
            cache_msrc=self.cache_msrc)
        self.assertFalse(resultado["cambiada"])
        fila = self.fila(tid)
        self.assertEqual(fila["summary_es"], "Información publicada.")
        self.assertIsNone(fila["descripcion_buscada_at"],
                          "sin consultar la red no se cierra la búsqueda")


class DescripcionBuena(_BaseConBase):
    """Una descripción válida no se sobrescribe ni consume red."""

    BUENA = ("Heap-based buffer overflow in the image decoder allows a remote attacker "
             "to execute arbitrary code by supplying a crafted PNG file.")

    def test_no_se_toca(self):
        tid = self.amenaza("fp-buena", "CVE-2026-0011", resumen_en=self.BUENA,
                           resumen_es="Un desbordamiento de memoria dinámica en el "
                                      "decodificador de imágenes permite ejecutar código.")
        antes = self.fila(tid)
        red = RedFalsa(nvd=respuesta_nvd("CVE-2026-0011", "Otra descripción distinta"))
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertFalse(resultado["cambiada"])
        self.assertEqual(red.llamadas, [])
        self.assertEqual(self.fila(tid), antes, "ni el texto ni las marcas cambian")


class Traduccion(_BaseConBase):
    """La descripción nueva pasa por el flujo de traducción del proyecto, sin duplicarlo."""

    def test_se_delega_en_translate_traducir(self):
        tid = self.amenaza("fp-trad", "CVE-2026-0012", severidad="Critical")
        red = RedFalsa(nvd=respuesta_nvd(
            "CVE-2026-0012", "Remote code execution in the SMB service allows an "
                             "unauthenticated attacker to run arbitrary code."))
        traducida = ("La ejecución remota de código en el servicio SMB permite a un "
                     "atacante no autenticado ejecutar código arbitrario.")
        with mock.patch.object(enrich.http, "fetch_json", red), \
                mock.patch.object(enrich.translate, "traducir",
                                  return_value=(traducida, "argos")) as doble:
            enrich.completar_descripcion(self.conn, self.fila(tid), cfg=cfg_basica(),
                                         cache_msrc=self.cache_msrc)
        self.assertEqual(doble.call_count, 1, "una sola traducción, la del flujo normal")
        self.assertEqual(doble.call_args.kwargs["severidad"], "Critical")
        self.assertEqual(self.fila(tid)["summary_es"], traducida)

    def test_descripcion_ya_en_espanol_se_guarda_tal_cual(self):
        espanola = ("Una vulnerabilidad de desbordamiento de búfer en el analizador de "
                    "certificados permite a un atacante remoto ejecutar código.")
        tid = self.amenaza("fp-es", "CVE-2026-0013")
        red = RedFalsa(nvd=respuesta_nvd("CVE-2026-0013", espanola))
        with mock.patch.object(enrich.http, "fetch_json", red):
            enrich.completar_descripcion(self.conn, self.fila(tid), cfg=cfg_basica(),
                                         cache_msrc=self.cache_msrc)
        self.assertEqual(self.fila(tid)["summary_es"], espanola)


# --------------------------------------------------------------------------
# 3. Repaso retroactivo
# --------------------------------------------------------------------------
class Repaso(_BaseConBase):

    def test_respeta_el_ajuste_desactivado(self):
        tid = self.amenaza("fp-ajuste", "CVE-2026-0014")
        red = RedFalsa(nvd=respuesta_nvd("CVE-2026-0014", "Something bad happens here."))
        cfg = cfg_basica(descripcion_completar=False)
        with mock.patch.object(enrich.http, "fetch_json", red):
            estadisticas = enrich.repasar_descripciones(self.conn, cfg=cfg, limite=10,
                                                        cache_msrc=self.cache_msrc)
            individual = enrich.completar_descripcion(self.conn, self.fila(tid), cfg=cfg,
                                                      cache_msrc=self.cache_msrc)
        self.assertTrue(estadisticas["omitido"])
        self.assertEqual(estadisticas["revisadas"], 0)
        self.assertFalse(individual["cambiada"])
        self.assertEqual(red.llamadas, [])
        self.assertEqual(self.fila(tid)["summary_es"], "Información publicada.")

    def test_repasa_por_relevancia_y_marca_el_origen(self):
        baja = self.amenaza("fp-baja", "CVE-2026-0015", relevancia=10.0)
        alta = self.amenaza("fp-alta", "CVE-2026-0016", relevancia=95.0)
        red = RedFalsa(nvd=respuesta_nvd(
            "CVE-2026-0016", "Privilege escalation in the print spooler allows a local "
                             "attacker to gain SYSTEM rights."))
        with mock.patch.object(enrich.http, "fetch_json", red):
            estadisticas = enrich.repasar_descripciones(
                self.conn, cfg=cfg_basica(), limite=1, cache_msrc=self.cache_msrc)
        self.assertEqual(estadisticas["revisadas"], 1)
        self.assertEqual(estadisticas["resueltas"], 1)
        self.assertEqual(estadisticas["por_origen"], {"nvd": 1})
        self.assertEqual(self.fila(alta)["descripcion_origen"], "nvd",
                         "se empieza por la amenaza de más relevancia")
        self.assertIsNone(self.fila(baja)["descripcion_origen"])

    def test_idempotencia_sin_red_en_la_segunda_pasada(self):
        self.amenaza("fp-idem", "CVE-2026-0017")
        red = RedFalsa(nvd=respuesta_nvd(
            "CVE-2026-0017", "Out-of-bounds write in the font parser allows remote code "
                             "execution when opening a crafted document."))
        with mock.patch.object(enrich.http, "fetch_json", red):
            primera = enrich.repasar_descripciones(self.conn, cfg=cfg_basica(), limite=10,
                                                   cache_msrc=self.cache_msrc)
            llamadas_primera = list(red.llamadas)
            segunda = enrich.repasar_descripciones(self.conn, cfg=cfg_basica(), limite=10,
                                                   cache_msrc=self.cache_msrc)
        self.assertEqual(primera["resueltas"], 1)
        self.assertEqual(segunda["revisadas"], 0)
        self.assertEqual(segunda["resueltas"], 0)
        self.assertEqual(red.llamadas, llamadas_primera,
                         "la segunda pasada no consume ni una consulta de red")

    def test_tope_de_consultas_de_red(self):
        for indice in range(4):
            self.amenaza(f"fp-tope-{indice}", f"CVE-2026-01{indice}0",
                         relevancia=90.0 - indice)
        red = RedFalsa()      # NVD y CVE.org responden 404: dos consultas por amenaza
        with mock.patch.object(enrich.http, "fetch_json", red):
            estadisticas = enrich.repasar_descripciones(
                self.conn, cfg=cfg_basica(), limite=10, max_consultas=2,
                cache_msrc=self.cache_msrc)
        self.assertLessEqual(estadisticas["consultas"], 2)
        self.assertLessEqual(len(red.llamadas), 2)
        self.assertLess(estadisticas["revisadas"], 4)

    def test_no_repasa_las_amenazas_cerradas(self):
        cerrada = self.amenaza("fp-cerrada", "CVE-2026-0018", estado="descartada")
        red = RedFalsa(nvd=respuesta_nvd("CVE-2026-0018", "No debería consultarse."))
        with mock.patch.object(enrich.http, "fetch_json", red):
            estadisticas = enrich.repasar_descripciones(
                self.conn, cfg=cfg_basica(), limite=10, cache_msrc=self.cache_msrc)
        self.assertEqual(estadisticas["revisadas"], 0)
        self.assertEqual(red.llamadas, [])
        self.assertIsNone(self.fila(cerrada)["descripcion_origen"])

    def test_reintenta_la_frase_honesta_cuando_la_fuente_ya_publica(self):
        """Lo que hoy no existe puede publicarse mañana: la frase honesta se revisa."""
        tid = self.amenaza("fp-reintento", "CVE-2026-0019")
        red_vacia = RedFalsa()
        with mock.patch.object(enrich.http, "fetch_json", red_vacia):
            enrich.completar_descripcion(self.conn, self.fila(tid), cfg=cfg_basica(),
                                         cache_msrc=self.cache_msrc)
        self.assertEqual(self.fila(tid)["descripcion_origen"], enrich.ORIGEN_SIN_DATO)
        red = RedFalsa(nvd=respuesta_nvd(
            "CVE-2026-0019", "Improper authentication in the API allows a remote attacker "
                             "to bypass the login."))
        with mock.patch.object(enrich.http, "fetch_json", red):
            estadisticas = enrich.repasar_descripciones(
                self.conn, cfg=cfg_basica(), limite=10, dias_reintento=0,
                cache_msrc=self.cache_msrc)
        self.assertEqual(estadisticas["resueltas"], 1)
        fila = self.fila(tid)
        self.assertEqual(fila["descripcion_origen"], "nvd")
        self.assertIn("Improper authentication", fila["summary_en"])


# --------------------------------------------------------------------------
# 4. Correcciones de la revision del 6 de septiembre de 2026
# --------------------------------------------------------------------------
class PlantillaConTextoRealDetras(unittest.TestCase):
    """Una descripción REAL que empieza por una frase de plantilla no es relleno.

    Las plantillas están ancladas al principio porque varias fuentes añaden detrás la
    fecha de revisión, así que sin más comprobación cualquier texto que empezara por
    «Información publicada.», «Reserved…», «Duplicate of CVE-…» o «Revision
    information…» se habría dado por relleno y su contenido habría desaparecido de la
    vista, sustituido por la frase genérica. Caso real: la amenaza 2599 de la base de
    producción (CVE-2026-48566), cuyo texto avisa de que ya está corregido.
    """

    REALES = (
        ("Información publicada. Este CVE fue abordado por actualizaciones que fueron "
         "publicadas en mayo de 2026, pero el CVE fue omitido involuntariamente de las "
         "actualizaciones de seguridad de mayo de 2026. Los clientes que ya han "
         "instalado las actualizaciones de mayo 2026 no necesitan tomar ninguna acción "
         "adicional.", "caso real de la amenaza 2599"),
        ("Reserved memory ranges in the AMD SEV firmware allow a local attacker with "
         "ring0 access to read privileged data and elevate privileges on the affected "
         "host.", "descripción que empieza por «Reserved»"),
        ("Duplicate of CVE-2026-1111. Sin embargo, el fallo permite a un atacante "
         "remoto ejecutar código arbitrario en el servidor afectado mediante una "
         "petición HTTP manipulada de gran tamaño.", "duplicado con explicación propia"),
        ("Revision information for the affected builds is listed below; the flaw allows "
         "an unauthenticated remote attacker to execute arbitrary code in the SMB "
         "server component.", "revisión con explicación propia"),
    )

    # Palabrería fija que sí es relleno completo, aunque ocupe varias frases.
    RELLENO_LARGO = (
        "** RESERVED ** This candidate has been reserved by an organization or "
        "individual that will use it when announcing a new security problem. When the "
        "candidate has been publicized, the details for this candidate will be provided.",
        "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This "
        "candidate was withdrawn by its CNA. Notes: none.",
        "Información publicada. Revisado el 5 de septiembre de 2026.",
    )

    def test_no_se_dan_por_relleno(self):
        for texto, caso in self.REALES:
            with self.subTest(caso=caso):
                self.assertFalse(
                    enrich.es_descripcion_relleno(texto, titulo="Título distinto"),
                    "una descripción real nunca debe darse por relleno por su primera frase")

    def test_la_palabreria_completa_sigue_siendo_relleno(self):
        for texto in self.RELLENO_LARGO:
            with self.subTest(texto=texto[:40]):
                self.assertTrue(enrich.es_descripcion_relleno(texto),
                                "el aviso de identificador reservado o retirado no describe nada")


class NoSePierdeUnTextoReal(_BaseConBase):
    """Ningún texto real se sustituye por la frase genérica, ni siquiera sin red."""

    REAL = ("Información publicada. Este CVE fue abordado por actualizaciones que fueron "
            "publicadas en mayo de 2026, pero el CVE fue omitido involuntariamente de "
            "las actualizaciones de seguridad de mayo de 2026.")

    def test_ninguna_fuente_publica_nada_y_el_texto_se_conserva(self):
        tid = self.amenaza("fp-real", "CVE-2026-48566", resumen_en=self.REAL,
                           resumen_es=self.REAL, titulo="Vulnerabilidad en Windows")
        red = RedFalsa()      # NVD y CVE.org responden 404
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertFalse(resultado["cambiada"])
        self.assertEqual(red.llamadas, [], "una descripción válida no consulta la red")
        fila = self.fila(tid)
        self.assertEqual(fila["summary_es"], self.REAL)
        self.assertIsNone(fila["descripcion_origen"])
        self.assertNotIn("Sin descripción publicada", fila["summary_es"] or "")


class MotorDeTraduccion(_BaseConBase):
    """`threats.translation_engine` deja de mentir sobre el origen del texto.

    La ficha de la vulnerabilidad rotula el bloque «Traducción automática (motor) del
    texto original en inglés» siempre que el motor no sea «none», así que la frase
    honesta (que escribe el propio sistema) y la descripción recién traducida tienen que
    dejar el motor correcto.
    """

    def motor(self, threat_id) -> str:
        return self.conn.execute("SELECT translation_engine FROM threats WHERE id=?",
                                 (threat_id,)).fetchone()["translation_engine"]

    def test_se_guarda_el_motor_de_la_traduccion_nueva(self):
        tid = self.amenaza("fp-motor", "CVE-2026-0020")
        self.conn.execute("UPDATE threats SET translation_engine='argos' WHERE id=?", (tid,))
        red = RedFalsa(nvd=respuesta_nvd(
            "CVE-2026-0020", "Remote code execution in the SMB service allows an "
                             "unauthenticated attacker to run arbitrary code."))
        traducida = ("La ejecución remota de código en el servicio SMB permite a un "
                     "atacante no autenticado ejecutar código arbitrario.")
        with mock.patch.object(enrich.http, "fetch_json", red), \
                mock.patch.object(enrich.translate, "traducir",
                                  return_value=(traducida, "ollama")):
            enrich.completar_descripcion(self.conn, self.fila(tid), cfg=cfg_basica(),
                                         cache_msrc=self.cache_msrc)
        self.assertEqual(self.motor(tid), "ollama",
                         "el rótulo de la ficha debe nombrar el motor que tradujo este texto")

    def test_la_frase_honesta_no_se_presenta_como_traduccion(self):
        tid = self.amenaza("fp-motor-honesta", "CVE-2026-0021")
        self.conn.execute("UPDATE threats SET translation_engine='argos' WHERE id=?", (tid,))
        red = RedFalsa()
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertEqual(resultado["origen"], enrich.ORIGEN_SIN_DATO)
        self.assertEqual(self.motor(tid), "none",
                         "la frase la escribe el sistema, no es la traducción de nada")


class ConsultasContadas(_BaseConBase):
    """Solo se cuentan las peticiones que salen de verdad a Internet."""

    def test_el_detalle_cacheado_no_cuenta_como_consulta(self):
        descripcion = ("Improper input validation in the PDF parser allows a remote "
                       "attacker to cause a denial of service.")
        self.conn.execute(
            "INSERT INTO cve_detalle(cve, encontrado, json, consultado_at) VALUES(?,1,?,?)",
            ("CVE-2026-0022", json.dumps({"descripcion": descripcion}), db.utcnow()))
        tid = self.amenaza("fp-cache", "CVE-2026-0022")
        red = RedFalsa()
        with mock.patch.object(enrich.http, "fetch_json", red):
            hallazgo = enrich.buscar_descripcion(
                self.conn, self.fila(tid), cfg=cfg_basica(),
                nvd={"encontrado": False}, cache_msrc=self.cache_msrc)
        self.assertEqual(hallazgo["origen"], "cve.org")
        self.assertEqual(red.llamadas, [], "el detalle estaba en la caché")
        self.assertEqual(hallazgo["consultas"], 0,
                         "contar una consulta que no se hizo agota el tope y obliga a "
                         "esperar el límite de NVD sin motivo")


class TextoVisibleSeguro(_BaseConBase):
    """Siglas explicadas y sin caracteres invisibles en lo que se guarda."""

    def test_la_frase_honesta_explica_la_sigla(self):
        frase = enrich.descripcion_honesta(cve="CVE-2026-1234")
        self.assertIn("base de datos nacional de vulnerabilidades", frase)
        self.assertIn("(NVD)", frase)

    def test_se_quitan_los_caracteres_que_alteran_el_orden_de_lectura(self):
        peligroso = ("Desbordamiento de b\u00fafer en \u202egpj.eliftset\u202c que "
                     "permite a un atacante remoto ejecutar c\u00f3digo arbitrario.")
        self.assertNotIn("\u202e", enrich.limpiar_invisibles(peligroso))
        self.assertNotIn("\u202e", enrich.normalizar_descripcion(peligroso))
        tid = self.amenaza("fp-bidi", "CVE-2026-0023")
        red = RedFalsa(nvd=respuesta_nvd("CVE-2026-0023", peligroso))
        with mock.patch.object(enrich.http, "fetch_json", red):
            enrich.completar_descripcion(self.conn, self.fila(tid), cfg=cfg_basica(),
                                         cache_msrc=self.cache_msrc)
        guardado = self.fila(tid)["summary_en"]
        self.assertIn("Desbordamiento", guardado)
        for invisible in ("\u202e", "\u202c", "\u200b", "\ufeff"):
            self.assertNotIn(invisible, guardado)


class FilaSinIdentificador(_BaseConBase):
    """Una fila sin «id» no se puede escribir: antes se contaba como resuelta."""

    def test_no_escribe_ni_consulta_la_red(self):
        tid = self.amenaza("fp-sinid", "CVE-2026-0024")
        antes = self.fila(tid)
        red = RedFalsa(nvd=respuesta_nvd("CVE-2026-0024", "No debería consultarse nada."))
        with mock.patch.object(enrich.http, "fetch_json", red):
            resultado = enrich.completar_descripcion(
                self.conn, {"cve": "CVE-2026-0024", "summary_es": "Información publicada."},
                cfg=cfg_basica(), cache_msrc=self.cache_msrc)
        self.assertFalse(resultado["cambiada"])
        self.assertIsNone(resultado["origen"])
        self.assertIn("identificador", resultado["motivo"])
        self.assertEqual(red.llamadas, [])
        self.assertEqual(self.fila(tid), antes)


class Auditoria(_BaseConBase):
    """Cada descripción sustituida queda en el registro de auditoría."""

    def apuntes(self) -> list[tuple]:
        return [(r["action"], r["entity"], r["entity_id"], r["detail"])
                for r in self.conn.execute(
                    "SELECT action, entity, entity_id, detail FROM audit_log "
                    "ORDER BY id")]

    def test_apunte_por_amenaza_con_el_origen(self):
        tid = self.amenaza("fp-audit", "CVE-2026-0025")
        red = RedFalsa(nvd=respuesta_nvd(
            "CVE-2026-0025", "Out-of-bounds read in the TLS handshake allows a remote "
                             "attacker to disclose memory contents."))
        with mock.patch.object(enrich.http, "fetch_json", red):
            enrich.completar_descripcion(self.conn, self.fila(tid), cfg=cfg_basica(),
                                         cache_msrc=self.cache_msrc)
        apuntes = self.apuntes()
        self.assertEqual(len(apuntes), 1)
        accion, entidad, entidad_id, detalle = apuntes[0]
        self.assertEqual(accion, "descripcion.completada")
        self.assertEqual(entidad, "threats")
        self.assertEqual(entidad_id, str(tid))
        self.assertIn("NVD", detalle)

    def test_apunte_de_la_frase_honesta(self):
        tid = self.amenaza("fp-audit2", "CVE-2026-0026")
        red = RedFalsa()
        with mock.patch.object(enrich.http, "fetch_json", red):
            enrich.completar_descripcion(self.conn, self.fila(tid), cfg=cfg_basica(),
                                         cache_msrc=self.cache_msrc)
        acciones = [a[0] for a in self.apuntes()]
        self.assertEqual(acciones, ["descripcion.sin_dato"])


class RepasoEnElEnriquecimientoDiario(_BaseConBase):
    """El repaso retroactivo viaja con `enriquecer_pendientes`, que corre cada día.

    Sin este enganche el objetivo del encargo solo se cumpliría para las amenazas
    NUEVAS con identificador CVE: las que ya estaban guardadas con relleno tienen
    `enriched_at` y no vuelven a pasar por el enriquecimiento.
    """

    def historica(self, fingerprint, cve, **extra):
        tid = self.amenaza(fingerprint, cve, **extra)
        self.conn.execute("UPDATE threats SET enriched_at=? WHERE id=?",
                          (db.utcnow(), tid))
        return tid

    def cfg(self, **cambios):
        return cfg_basica(enrich_kev_enabled=False, enrich_epss_enabled=False,
                          enrich_max_per_run=10, **cambios)

    def test_repasa_el_historico_aunque_no_haya_amenazas_nuevas(self):
        tid = self.historica("fp-hist", "CVE-2026-0027")
        red = RedFalsa(nvd=respuesta_nvd(
            "CVE-2026-0027", "Improper authorization in the web console allows a remote "
                             "attacker to read other tenants' data."))
        with mock.patch.object(enrich.http, "fetch_json", red):
            estadisticas = enrich.enriquecer_pendientes(self.conn, cfg=self.cfg())
        self.assertEqual(estadisticas["candidatas"], 0, "no hay amenazas nuevas")
        self.assertEqual(estadisticas["descripciones_repasadas"], 1)
        self.assertEqual(estadisticas["descripciones_completadas"], 1)
        fila = self.fila(tid)
        self.assertEqual(fila["descripcion_origen"], "nvd")
        self.assertIn("Improper authorization", fila["summary_en"])

    def test_el_repaso_se_puede_desactivar_con_el_ajuste(self):
        tid = self.historica("fp-hist2", "CVE-2026-0028")
        red = RedFalsa(nvd=respuesta_nvd("CVE-2026-0028", "No debería consultarse."))
        with mock.patch.object(enrich.http, "fetch_json", red):
            estadisticas = enrich.enriquecer_pendientes(
                self.conn, cfg=self.cfg(descripcion_repaso_limite=0))
        self.assertEqual(estadisticas["descripciones_repasadas"], 0)
        self.assertEqual(red.llamadas, [])
        self.assertIsNone(self.fila(tid)["descripcion_origen"])

    def test_amenaza_nueva_e_historica_en_la_misma_ejecucion(self):
        nueva = self.amenaza("fp-nueva", "CVE-2026-0029")          # sin enriched_at
        vieja = self.historica("fp-vieja", "CVE-2026-0030")
        descripcion = ("Use of a hard-coded credential in the update service allows a "
                       "local attacker to elevate privileges.")
        red = RedFalsa(nvd=respuesta_nvd("CVE-2026-0029", descripcion))
        # NVD contesta la misma descripción a cualquier consulta: basta para comprobar
        # que las dos amenazas quedan resueltas y que el repaso corre después.
        with mock.patch.object(enrich.http, "fetch_json", red):
            estadisticas = enrich.enriquecer_pendientes(self.conn, cfg=self.cfg())
        self.assertEqual(estadisticas["candidatas"], 1)
        self.assertEqual(estadisticas["descripciones_repasadas"], 1)
        self.assertEqual(self.fila(nueva)["descripcion_origen"], "nvd")
        self.assertEqual(self.fila(vieja)["descripcion_origen"], "nvd")


if __name__ == "__main__":
    unittest.main()
