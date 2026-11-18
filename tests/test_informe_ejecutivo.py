"""Informe ejecutivo mensual de diez páginas (2026-09-15).

Petición literal del usuario:

    «necesito que a final de mes también se genere un informe ejecutivo sobre las amenazas
    del mes que no exceda las 10 páginas, donde debe ser muy conciso, concreto, directo y
    lo que normalmente le interesa a un gerente: temas de cifras, comparación entre meses
    o años y avances entre meses con detectadas y remediadas»

Lo que fijan estas pruebas:

* el documento se genera sin error y **no pasa de diez páginas** (se mide de verdad
  convirtiéndolo a PDF con LibreOffice cuando está instalado, y siempre se comprueba el
  guardián estructural que hace imposible que crezca: ningún apartado lleva una fila por
  vulnerabilidad);
* es **para un gerente**: ni un identificador de vulnerabilidad, ni un nombre de paquete,
  ni una versión, ni una orden que ejecutar;
* trae las **comparaciones** que se pidieron: mes contra mes anterior y contra el mismo mes
  del año pasado, en número, en porcentaje y en palabras («mejoró», «empeoró», «se
  mantiene»), y dice «no hay dato» cuando no hay año anterior en vez de inventarse un
  100 %;
* trae el **avance entre meses con detectadas y remediadas**, con el saldo de la deuda y el
  tiempo medio en corregir, y no pinta a cero los meses en los que no había serie;
* la selección es **fija**: ni la dirección web puede añadirle apartados, ampliarle el
  periodo ni cambiarle el alcance, que es lo que garantiza el tope de páginas;
* el **informe mensual completo sigue siendo idéntico** al de antes, párrafo a párrafo;
* la pantalla ``/informes/`` lo ofrece como una plantilla más, con sus permisos, su
  alcance por perfil y su auditoría.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_informe_ejecutivo
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from docx import Document

from threatintel import db, informe_seleccion as isel, report
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth                       # noqa: E402
from webui.vistas import informes            # noqa: E402

CLAVE = "ClaveSegura#2026"

#: Meses de la base de prueba. Septiembre de 2025 existe a propósito: es el «mismo mes del
#: año pasado» del mes que se informa, y sin él no se podría comprobar la comparación anual.
PLAN = {
    "2025-09": {"Critical": 1, "High": 2, "Medium": 1, "Low": 3},
    "2026-08": {"Critical": 3, "High": 2, "Medium": 1, "Low": 1},
    "2026-09": {"Critical": 2, "High": 4, "Medium": 2, "Low": 5},
}
MES = "2026-09"


class ConfiguracionFalsa:
    """La configuración mínima que necesita el informe, sin ficheros ni secretos."""
    settings: dict = {}
    report_to: list = []

    def get(self, clave, defecto=None):
        from threatintel.config import DEFAULT_SETTINGS
        if clave == "translate_engine":
            return "none"
        return DEFAULT_SETTINGS.get(clave, defecto)


def _sembrar(ruta: str) -> dict:
    """Base con tres meses de amenazas, dos activos y una cola de remediación con historia.

    La cola tiene detecciones y correcciones en DOS meses distintos para que la serie de
    «detectadas y remediadas» tenga de verdad dos filas que comparar: con un solo mes no se
    podría comprobar que el saldo de la deuda se calcula bien.
    """
    ids: dict = {"amenazas": {}}
    with db.session(ruta) as conn:
        auth.crear_usuario(conn, "admin@ejemplo.local", CLAVE, rol="admin",
                           nombre="Administradora", actor="t")
        auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                           nombre="Lectora", actor="t")
        auth.crear_usuario(conn, "operador@ejemplo.local", CLAVE, rol="ciberseguridad",
                           nombre="Operador SOC", actor="t")

        cur = conn.execute(
            """INSERT INTO technologies(slug, name, version_installed, criticality,
                                        systems_count, exposure, enabled, created_at,
                                        updated_at)
               VALUES('openssl','OpenSSL','3.0.1','high',12,'internet',1,?,?)""",
            (db.utcnow(), db.utcnow()))
        ids["tecnologia"] = cur.lastrowid

        for nombre, origen, proceso in (("srv-informes-01", "servidores", "Impuestos"),
                                        ("pc-informes-01", "equipos", "Pila")):
            cur = conn.execute(
                """INSERT INTO activos(origen, ocs_id, nombre, so_familia, so_nombre,
                        so_version, ip, entorno, proceso, presente, ultimo_inventario,
                        primera_vez_at, visto_at)
                   VALUES(?, (SELECT COALESCE(MAX(ocs_id),0)+1 FROM activos), ?, 'debian',
                          'Debian GNU/Linux', '12', '10.1.2.9', 'produccion', ?, 1, ?, ?, ?)""",
                (origen, nombre, proceso, db.utcnow(), db.utcnow(), db.utcnow()))
            ids[origen] = cur.lastrowid
            conn.execute("""INSERT INTO activo_software(activo_id, nombre, nombre_norm, version)
                            VALUES(?,'openssl','openssl','3.0.1')""", (ids[origen],))

        n = 0
        for mes, reparto in PLAN.items():
            for severidad, cuantas in reparto.items():
                for _ in range(cuantas):
                    n += 1
                    en_kev = 1 if severidad == "Critical" else 0
                    cur = conn.execute(
                        """INSERT INTO threats(fingerprint, cve, title_en, title_es,
                                summary_es, severity, severity_source, cvss_score, in_kev,
                                first_seen_at, last_seen_at, times_seen, month, relevance,
                                estado)
                           VALUES(?,?,?,?,?,?,'nvd',?,?,?,?,1,?,80.0,'nueva')""",
                        (f"fp-{n:04d}", f"CVE-2026-{n:04d}", f"Threat {n}",
                         f"Amenaza de prueba {n}", "Resumen en español de la amenaza.",
                         severidad, 9.1, en_kev,
                         f"{mes}-05T09:00:00Z", f"{mes}-05T09:00:00Z", mes))
                    tid = cur.lastrowid
                    ids["amenazas"].setdefault((mes, severidad), []).append(tid)
                    conn.execute(
                        """INSERT INTO threat_technologies(threat_id, technology_id,
                                matched_alias, confidence, version_verdict)
                           VALUES(?,?,'openssl',0.95,'affected')""",
                        (tid, ids["tecnologia"]))
                    conn.execute(
                        """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at,
                                afectados, no_afectados, sin_dato)
                           VALUES(?,?,1,0,0)""", (tid, db.utcnow()))
                    objetivos = [ids["servidores"]]
                    if mes == "2026-09":
                        objetivos.append(ids["equipos"])
                    for activo_id in objetivos:
                        conn.execute(
                            """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                                    version_instalada, version_corregida, veredicto, motor,
                                    evidencia, evaluado_at)
                               VALUES(?,?,?,'openssl','3.0.1','3.0.14','afectado','osv',
                                      'prueba',?)""",
                            (activo_id, tid, f"CVE-2026-{n:04d}", db.utcnow()))
                        # La cola de remediación: las de agosto se detectaron en agosto y
                        # la mitad se corrigió en agosto; las de septiembre siguen abiertas.
                        if mes == "2026-08":
                            corregida = (n % 2 == 0)
                            conn.execute(
                                """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete,
                                        version_vulnerable, version_corregida, motor, estado,
                                        detectado_at, comprobado_at, corregido_at)
                                   VALUES(?,?,?,'openssl','3.0.1','3.0.14','osv',?,
                                          '2026-08-03T09:00:00Z','2026-08-20T09:00:00Z',?)""",
                                (activo_id, tid, f"CVE-2026-{n:04d}",
                                 "corregida" if corregida else "abierta",
                                 "2026-08-13T09:00:00Z" if corregida else None))
                        elif mes == "2026-09":
                            conn.execute(
                                """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete,
                                        version_vulnerable, version_corregida, motor, estado,
                                        detectado_at, comprobado_at)
                                   VALUES(?,?,?,'openssl','3.0.1','3.0.14','osv','abierta',
                                          '2026-09-02T09:00:00Z','2026-09-10T09:00:00Z')""",
                                (activo_id, tid, f"CVE-2026-{n:04d}"))
    return ids


def _texto(doc) -> str:
    """Todo el texto del documento: párrafos y celdas de tabla."""
    partes = [p.text for p in doc.paragraphs]
    for tabla in doc.tables:
        for fila in tabla.rows:
            partes.extend(c.text for c in fila.cells)
    return "\n".join(partes)


def _titulos(doc) -> list[str]:
    return [p.text for p in doc.paragraphs if p.style.name == "Heading 1"]


def _huella(doc) -> list[str]:
    partes = [f"{p.style.name}|{p.text}" for p in doc.paragraphs]
    for tabla in doc.tables:
        for fila in tabla.rows:
            partes.append("TABLA|" + "¬".join(c.text for c in fila.cells))
    return partes


def _paginas_reales(datos: bytes) -> int:
    """Páginas del documento, convirtiéndolo a PDF con LibreOffice.

    Devuelve 0 si LibreOffice o pdfinfo no están instalados: la prueba que lo usa se salta
    sola en ese caso y queda el guardián estructural, que no depende de nada externo.
    """
    soffice, pdfinfo = shutil.which("soffice"), shutil.which("pdfinfo")
    if not soffice or not pdfinfo:
        return 0
    with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
        docx = Path(tmp) / "ejecutivo.docx"
        docx.write_bytes(datos)
        try:
            subprocess.run([soffice, "--headless", "--convert-to", "pdf",
                            "--outdir", tmp, str(docx)],
                           check=True, capture_output=True, timeout=180)
            salida = subprocess.run([pdfinfo, str(Path(tmp) / "ejecutivo.pdf")],
                                    check=True, capture_output=True, timeout=60)
        except (subprocess.SubprocessError, OSError):
            return 0
        encontrado = re.search(rb"^Pages:\s+(\d+)", salida.stdout, re.M)
        return int(encontrado.group(1)) if encontrado else 0


class BaseConDatos(unittest.TestCase):
    """Base temporal bajo data/, sembrada una vez para toda la clase."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.tmp.name) / "ejecutivo.db")
        db.init_db(cls.ruta)
        cls.ids = _sembrar(cls.ruta)
        cls.cfg = ConfiguracionFalsa()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.contexto = db.session(self.ruta)
        self.conn = self.contexto.__enter__()

    def tearDown(self):
        self.contexto.__exit__(None, None, None)


# ==========================================================================
# 1. Las piezas de cálculo
# ==========================================================================
class TestVariacion(unittest.TestCase):
    """La comparación, dicha en palabras. Es lo que pidió el usuario."""

    def test_bajar_es_mejorar_cuando_menos_es_mejor(self):
        v = report._variacion(80, 100)
        self.assertEqual(v["palabra"], "mejoró")
        self.assertEqual(v["absoluta"], -20)
        self.assertEqual(v["porcentaje"], 20.0)
        self.assertIn("20 menos", v["texto"])
        self.assertIn("20,0 %", v["texto"])

    def test_subir_es_empeorar_cuando_menos_es_mejor(self):
        v = report._variacion(150, 100)
        self.assertEqual(v["palabra"], "empeoró")
        self.assertEqual(v["absoluta"], 50)
        self.assertIn("50 más", v["texto"])

    def test_bajar_es_empeorar_cuando_mas_es_mejor(self):
        """Las vulnerabilidades remediadas son la magnitud al revés."""
        self.assertEqual(report._variacion(10, 30, menos_es_mejor=False)["palabra"],
                         "empeoró")
        self.assertEqual(report._variacion(40, 30, menos_es_mejor=False)["palabra"],
                         "mejoró")

    def test_igual_se_mantiene(self):
        v = report._variacion(7, 7)
        self.assertEqual(v["palabra"], "se mantiene")
        self.assertEqual(v["texto"], "igual que el periodo anterior")

    def test_sin_dato_anterior_no_se_inventa_un_porcentaje(self):
        v = report._variacion(12, None)
        self.assertFalse(v["comparable"])
        self.assertIsNone(v["porcentaje"])
        self.assertIn("no hay dato", v["texto"])

    def test_desde_cero_no_divide_por_cero(self):
        v = report._variacion(5, 0)
        self.assertTrue(v["comparable"])
        self.assertIsNone(v["porcentaje"])
        self.assertIn("el periodo anterior era cero", v["texto"])

    def test_numeros_en_formato_espanol(self):
        self.assertIn("4.583 más", report._variacion(15731, 11148)["texto"])


class TestMesDesplazado(unittest.TestCase):
    def test_mes_anterior_y_mismo_mes_del_ano_pasado(self):
        self.assertEqual(report._mes_desplazado("2026-09", -1), "2026-08")
        self.assertEqual(report._mes_desplazado("2026-09", -12), "2025-09")
        self.assertEqual(report._mes_desplazado("2026-01", -1), "2025-12")
        self.assertEqual(report._mes_desplazado("2026-12", 1), "2027-01")

    def test_un_mes_ilegible_no_rompe(self):
        self.assertEqual(report._mes_desplazado("", -1), "")
        self.assertEqual(report._mes_desplazado(None, -1), "")


class TestPlural(unittest.TestCase):
    """«794 vulnerabilidades en 1 activos» se lee como un error del sistema."""

    def test_singular_y_plural(self):
        self.assertEqual(report._plural(1, "activo"), "1 activo")
        self.assertEqual(report._plural(652, "activo"), "652 activos")
        self.assertEqual(report._plural(0, "activo"), "0 activos")
        self.assertEqual(report._plural(2, "vulnerabilidad", "vulnerabilidades"),
                         "2 vulnerabilidades")
        self.assertEqual(report._plural(1234, "activo"), "1.234 activos")


# ==========================================================================
# 2. Las cifras del informe
# ==========================================================================
class TestResumen(BaseConDatos):

    def setUp(self):
        super().setUp()
        self.datos = report.resumen_ejecutivo_mensual(self.conn, MES, cfg=self.cfg)

    def test_las_cifras_del_mes(self):
        d = self.datos
        self.assertEqual(d["month"], MES)
        self.assertEqual(d["periodo"], "septiembre de 2026")
        # Ocho amenazas reportables en septiembre (las cinco bajas no cuentan nunca).
        self.assertEqual(d["amenazas"]["total"], 8)
        # Una vulnerabilidad es un CVE en un activo: ocho amenazas en dos máquinas.
        self.assertEqual(d["vulnerabilidades"], 16)
        self.assertEqual(d["activos_afectados"], 2)
        self.assertEqual(d["parque"]["total"], 2)
        self.assertEqual(d["pct_parque"], 100.0)
        # Las críticas están en el catálogo KEV: dos amenazas por dos máquinas.
        self.assertEqual(d["vulnerabilidades_kev"], 4)

    def test_la_severidad_baja_no_cuenta_en_ninguna_cifra(self):
        self.assertEqual(self.datos["amenazas"]["bajas"], 0)
        for m in self.datos["magnitudes"]:
            self.assertNotIn("baja", m["nombre"].lower())

    def test_compara_con_el_mes_anterior(self):
        por_clave = {m["clave"]: m for m in self.datos["magnitudes"]}
        amenazas = por_clave["amenazas"]
        self.assertEqual(amenazas["actual"], 8)
        self.assertEqual(amenazas["anterior"], 6, "agosto: 3 críticas, 2 altas y 1 media")
        self.assertEqual(amenazas["variacion_mes"]["palabra"], "empeoró")
        self.assertEqual(amenazas["variacion_mes"]["absoluta"], 2)

    def test_compara_con_el_mismo_mes_del_ano_pasado(self):
        self.assertTrue(self.datos["hay_anio_anterior"])
        self.assertEqual(self.datos["mes_anio_anterior"], "2025-09")
        por_clave = {m["clave"]: m for m in self.datos["magnitudes"]}
        # Septiembre de 2025: 1 crítica, 2 altas y 1 media (las 3 bajas no cuentan).
        self.assertEqual(por_clave["amenazas"]["anio"], 4)
        self.assertEqual(por_clave["amenazas"]["variacion_anio"]["palabra"], "empeoró")
        self.assertEqual(por_clave["amenazas"]["variacion_anio"]["absoluta"], 4)

    def test_sin_mes_anterior_no_se_inventa_la_comparacion(self):
        datos = report.resumen_ejecutivo_mensual(self.conn, "2025-09", cfg=self.cfg)
        self.assertFalse(datos["hay_anio_anterior"])
        for m in datos["magnitudes"]:
            self.assertFalse(m["variacion_anio"]["comparable"])

    def test_avance_de_detectadas_y_remediadas(self):
        avance = {f["mes"]: f for f in self.datos["avance"]}
        self.assertIn("2026-08", avance)
        self.assertIn("2026-09", avance)
        # Agosto: seis amenazas en un activo; la mitad se corrigió el 13 de agosto.
        self.assertEqual(avance["2026-08"]["detectadas"], 6)
        self.assertEqual(avance["2026-08"]["remediadas"], 3)
        self.assertEqual(avance["2026-08"]["saldo"], 3)
        # Diez días entre el 3 y el 13 de agosto.
        self.assertEqual(avance["2026-08"]["dias_medios"], 10.0)
        # Septiembre: ocho amenazas en dos activos, ninguna cerrada todavía.
        self.assertEqual(avance["2026-09"]["detectadas"], 16)
        self.assertEqual(avance["2026-09"]["remediadas"], 0)
        self.assertIsNone(avance["2026-09"]["dias_medios"])

    def test_no_pinta_a_cero_los_meses_sin_serie(self):
        """Un cero se lee como «no apareció nada» y sería falso: no había cola todavía."""
        meses = [f["mes"] for f in self.datos["avance"]]
        self.assertEqual(meses, ["2026-08", "2026-09"])
        self.assertNotIn("2025-09", meses)

    def test_el_trabajo_pendiente_viene_de_la_cola_de_remediacion(self):
        pendiente = self.datos["pendiente"]
        self.assertGreater(pendiente["vulnerabilidades_unicas"], 0)
        self.assertGreaterEqual(pendiente["actualizaciones"], 1)
        self.assertGreaterEqual(pendiente["activos_con_abiertas"], 1)

    def test_dos_ejecuciones_seguidas_dan_lo_mismo(self):
        otra = report.resumen_ejecutivo_mensual(self.conn, MES, cfg=self.cfg)
        for clave in ("vulnerabilidades", "activos_afectados", "vulnerabilidades_kev",
                      "detectadas_mes", "remediadas_mes", "saldo_mes"):
            self.assertEqual(self.datos[clave], otra[clave], clave)

    def test_un_mes_anterior_a_la_cola_de_remediacion_lo_dice(self):
        """La cola se registra desde agosto: en julio no hay serie, y no es un cero."""
        datos = report.resumen_ejecutivo_mensual(self.conn, "2026-07", cfg=self.cfg)
        self.assertEqual(datos["avance"], [])
        self.assertEqual(datos["avance_desde"], "2026-08")
        self.assertTrue(datos["avance_posterior_al_mes"])

    def test_el_alcance_del_perfil_acota_las_cifras(self):
        """Un perfil de Redes solo informa de sus servidores, también aquí."""
        sel = isel.Seleccion.desde_parametros(
            {"plantilla": "ejecutivo", "mes": MES}, meses_disponibles=[MES],
            origen_perfil="servidores")
        self.assertEqual(sel.origen_perfil, "servidores")
        datos = report.resumen_ejecutivo_mensual(self.conn, MES, cfg=self.cfg,
                                                 seleccion=sel)
        self.assertEqual(datos["parque"]["total"], 1, "solo el servidor")
        self.assertEqual(datos["parque"]["equipos"], 0)
        self.assertEqual(datos["activos_afectados"], 1)
        self.assertIn("servidores", datos["alcance_es"])
        # Y las vulnerabilidades son las de ese servidor, no las de todo el parque.
        completo = report.resumen_ejecutivo_mensual(self.conn, MES, cfg=self.cfg)
        self.assertLess(datos["vulnerabilidades"], completo["vulnerabilidades"])

    def test_un_mes_sin_datos_no_rompe(self):
        datos = report.resumen_ejecutivo_mensual(self.conn, "2026-03", cfg=self.cfg)
        self.assertEqual(datos["amenazas"]["total"], 0)
        self.assertEqual(datos["vulnerabilidades"], 0)
        self.assertEqual(datos["activos_afectados"], 0)


# ==========================================================================
# 3. El documento
# ==========================================================================
class TestDocumento(BaseConDatos):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with db.session(cls.ruta) as conn:
            cls.datos_docx = report.generar_ejecutivo_en_memoria(conn, MES, cfg=cls.cfg)
        import io
        cls.doc = Document(io.BytesIO(cls.datos_docx))
        cls.texto = _texto(cls.doc)

    def test_los_cinco_apartados_numerados_seguidos(self):
        titulos = _titulos(self.doc)
        self.assertEqual(titulos, [
            "1. Las cifras del mes",
            "2. Comparación con el mes anterior y con el año pasado",
            "3. Avance mes a mes: detectadas y remediadas",
            "4. Dónde está el trabajo pendiente",
            "5. Qué conviene hacer el mes que viene"])

    def test_la_portada_dice_el_mes_y_el_alcance(self):
        self.assertIn("INFORME EJECUTIVO", self.texto)
        self.assertIn("MES: SEPTIEMBRE DE 2026", self.texto)
        self.assertIn("Alcance: toda la organización", self.texto)

    def test_no_lleva_ninguna_ficha_tecnica(self):
        """«nada de fichas técnicas, ni de identificadores de paquete, ni de órdenes»."""
        prohibidos = ("CVE-", "openssl", "OpenSSL", "3.0.1", "3.0.14", "apt-get",
                      "sudo ", "dpkg", "CVSS", "Ficha", "fingerprint")
        for palabra in prohibidos:
            self.assertNotIn(palabra, self.texto,
                             f"el informe ejecutivo no puede escribir «{palabra}»")

    def test_cada_cifra_lleva_su_unidad(self):
        for unidad in ("amenazas", "vulnerabilidades", "activos"):
            self.assertIn(unidad, self.texto)
        # Los decimales van con coma, como en el resto de la plataforma.
        self.assertRegex(self.texto, r"\d+,\d %")
        self.assertNotRegex(self.texto, r"\d+\.\d %",
                            "un porcentaje con punto decimal no es formato español")

    def test_trae_las_comparaciones_en_palabras(self):
        self.assertIn("septiembre de 2026", self.texto.lower())
        self.assertIn("agosto de 2026", self.texto.lower())
        self.assertIn("septiembre de 2025", self.texto.lower())
        self.assertTrue(any(p in self.texto for p in ("mejoró", "empeoró", "se mantiene")),
                        "la variación tiene que decirse en palabras")
        self.assertRegex(self.texto, r"\d+,\d %", "falta la variación en porcentaje")

    def test_trae_el_avance_de_detectadas_y_remediadas(self):
        self.assertIn("Detectadas", self.texto)
        self.assertIn("Remediadas", self.texto)
        self.assertIn("Días medios en corregir", self.texto)
        self.assertIn("la deuda sube en", self.texto)

    def test_la_recomendacion_son_cuatro_puntos_como_mucho(self):
        puntos = [p.text for p in self.doc.paragraphs
                  if re.match(r"^[1-9]\. [A-ZÁÉÍÓÚÑ]", p.text)]
        # Los títulos de apartado también empiezan por «N. »: se descuentan.
        puntos = [p for p in puntos if p not in _titulos(self.doc)]
        self.assertGreaterEqual(len(puntos), 1)
        self.assertLessEqual(len(puntos), 4,
                             "«tres o cuatro puntos como mucho»")
        for texto in puntos:
            self.assertIn("Qué cambia si se hace",
                          self.texto[self.texto.index(texto):self.texto.index(texto) + 900])

    def test_no_pasa_de_diez_paginas(self):
        paginas = _paginas_reales(self.datos_docx)
        if not paginas:
            self.skipTest("LibreOffice o pdfinfo no están instalados en este servidor")
        self.assertLessEqual(paginas, 10,
                             f"el informe ejecutivo ocupa {paginas} páginas")
        self.assertGreaterEqual(paginas, 1)

    def test_guardian_estructural_del_tope_de_paginas(self):
        """Ningún apartado crece con el número de vulnerabilidades.

        Es la garantía que no depende de tener LibreOffice instalado: si alguien añadiera
        una tabla con una fila por vulnerabilidad, estas cifras se dispararían y el
        documento dejaría de caber en diez páginas.
        """
        filas = sum(len(t.rows) for t in self.doc.tables)
        parrafos = [p for p in self.doc.paragraphs if p.text.strip()]
        self.assertLessEqual(filas, 45, f"{filas} filas de tabla: el documento crecerá")
        self.assertLessEqual(len(parrafos), 60,
                             f"{len(parrafos)} párrafos: el documento crecerá")
        # Un solo salto de página: el de la portada.
        saltos = self.doc.element.body.xml.count('w:type="page"')
        self.assertLessEqual(saltos, 2, "demasiados saltos de página")

    def test_el_pie_lo_distingue_del_informe_completo(self):
        pie = self.doc.sections[0].footer.paragraphs[0].text
        self.assertIn("Informe ejecutivo de ciberseguridad", pie)
        self.assertIn("septiembre de 2026", pie)

    def test_dos_generaciones_seguidas_producen_el_mismo_documento(self):
        import io
        with db.session(self.ruta) as conn:
            otra = report.generar_ejecutivo_en_memoria(conn, MES, cfg=self.cfg)
        self.assertEqual(_huella(Document(io.BytesIO(otra))), _huella(self.doc))

    def test_sin_serie_no_recomienda_mantener_un_ritmo_que_no_existe(self):
        """En julio no hay cola registrada: el documento no puede decir «se cerraron 0»."""
        import io
        with db.session(self.ruta) as conn:
            datos = report.generar_ejecutivo_en_memoria(conn, "2026-07", cfg=self.cfg)
        texto = _texto(Document(io.BytesIO(datos)))
        self.assertIn("no hay serie de vulnerabilidades detectadas y corregidas", texto)
        self.assertIn("agosto de 2026", texto)
        self.assertNotIn("Mantener el ritmo de cierre", texto)
        self.assertNotIn("se cerraron 0 vulnerabilidades frente a 0", texto)
        self.assertIn("Reducir la cola de", texto)

    def test_un_mes_sin_datos_genera_igualmente(self):
        import io
        with db.session(self.ruta) as conn:
            datos = report.generar_ejecutivo_en_memoria(conn, "2026-03", cfg=self.cfg)
        doc = Document(io.BytesIO(datos))
        self.assertEqual(len(_titulos(doc)), 5)
        self.assertIn("MES: MARZO DE 2026", _texto(doc))

    def test_el_informe_mensual_completo_sigue_siendo_identico(self):
        """La ejecución mensual programada no puede notar este cambio."""
        with db.session(self.ruta) as conn:
            antes = _huella(report.construir_documento(conn, MES, cfg=self.cfg))
            despues = _huella(report.construir_documento(
                conn, MES, cfg=self.cfg, secciones=isel.APARTADOS_MENSUAL))
        self.assertEqual(antes, despues)
        self.assertIn("Heading 1|1. Resumen ejecutivo", antes)
        self.assertIn("Heading 1|Anexo A. Relación del resto de hallazgos", antes)
        # Y no se le ha colado nada del ejecutivo.
        self.assertNotIn("Heading 1|1. Las cifras del mes", antes)


# ==========================================================================
# 4. La ejecución mensual programada
# ==========================================================================
class TestEjecucionMensual(BaseConDatos):
    """«Engánchalo a la ejecución mensual programada para que salga a final de mes
    junto al informe completo»."""

    def test_se_guarda_con_su_propio_nombre_al_lado_del_completo(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            destino = Path(tmp) / report.nombre_fichero_ejecutivo(MES)
            ruta = report.generar_ejecutivo(self.conn, MES, cfg=self.cfg, destino=destino)
            self.assertTrue(ruta.exists())
            self.assertEqual(ruta.name, "Informe_Ejecutivo_2026_09.docx")
            self.assertGreater(ruta.stat().st_size, 10_000)
            # Permisos: solo el propietario y su grupo, como el informe completo.
            self.assertEqual(ruta.stat().st_mode & 0o777, 0o640)
            doc = Document(str(ruta))
            self.assertEqual(len(_titulos(doc)), 5)

    def test_la_ejecucion_mensual_lo_genera_y_lo_adjunta(self):
        codigo = (BASE_DIR / "bin" / "ejecucion_mensual.py").read_text(encoding="utf-8")
        self.assertIn("report.generar_ejecutivo(conn, mes, cfg=cfg)", codigo)
        self.assertIn("adjuntos = [ruta] + ([ruta_ejecutivo] if ruta_ejecutivo else [])",
                      codigo)
        self.assertIn("attachments=adjuntos", codigo)
        # Y si el ejecutivo fallara, el informe completo se envía igual.
        self.assertIn("se envia solo el informe completo", codigo)

    def test_el_correo_mensual_anuncia_los_dos_documentos(self):
        from threatintel import notify
        resumen = report.construir_resumen(self.conn, MES, cfg=self.cfg)
        con_dos = notify.render_monthly_email(dict(
            resumen, nombre_archivo="Informe_Mensual_2026_09.docx", tamano_kb=62,
            ejecutivo_kb=40, url_interfaz="https://si.ejemplo.local/"))
        self.assertIn("Documentos adjuntos: 2", con_dos)
        self.assertIn("Informe ejecutivo", con_dos)
        self.assertIn("Diez páginas como máximo", con_dos)
        # Y sin el segundo documento el correo sigue siendo el de siempre.
        con_uno = notify.render_monthly_email(dict(
            resumen, nombre_archivo="Informe_Mensual_2026_09.docx", tamano_kb=62,
            url_interfaz="https://si.ejemplo.local/"))
        self.assertIn("Documento adjunto", con_uno)
        self.assertNotIn("Documentos adjuntos: 2", con_uno)
        self.assertNotIn("Informe ejecutivo", con_uno)


# ==========================================================================
# 5. La selección: estructura fija, pase lo que pase en la dirección web
# ==========================================================================
class TestSeleccionEjecutiva(unittest.TestCase):

    MESES = ["2026-09", "2026-08", "2025-09"]

    def _sel(self, params, **kw):
        return isel.Seleccion.desde_parametros(params, meses_disponibles=self.MESES, **kw)

    def test_la_plantilla_existe_y_es_de_un_mes(self):
        plantilla = isel.PLANTILLA_POR_CLAVE[isel.PLANTILLA_EJECUTIVA]
        self.assertEqual(plantilla.periodo, "mes")
        self.assertEqual(plantilla.alcance, "organizacion")
        self.assertEqual(plantilla.apartados, isel.APARTADOS_EJECUTIVO)
        self.assertNotIn("Low", plantilla.severidades)

    def test_los_apartados_son_fijos(self):
        sel = self._sel({"plantilla": "ejecutivo"})
        self.assertTrue(sel.es_ejecutivo())
        self.assertEqual(sel.apartados, isel.APARTADOS_EJECUTIVO)
        self.assertFalse(sel.es_mensual_clasico())

    def test_la_direccion_web_no_puede_anadirle_apartados(self):
        sel = self._sel({"plantilla": "ejecutivo", "apartados_enviados": "1",
                         "apartado": ["anexo", "prioritarias", "ej_cifras"]})
        self.assertEqual(sel.apartados, isel.APARTADOS_EJECUTIVO)
        self.assertNotIn("anexo", sel.apartados)
        self.assertNotIn("prioritarias", sel.apartados)

    def test_la_direccion_web_no_puede_ampliarle_el_periodo_ni_el_alcance(self):
        sel = self._sel({"plantilla": "ejecutivo", "periodo": "anio",
                         "alcance": "kev", "sev": ["Critical"]})
        self.assertEqual(sel.periodo, "mes")
        self.assertEqual(sel.alcance, "organizacion")
        self.assertEqual(sel.severidades, isel.SEVERIDADES)

    def test_los_apartados_del_ejecutivo_no_se_cuelan_en_otro_informe(self):
        sel = self._sel({"plantilla": "mensual", "apartados_enviados": "1",
                         "apartado": ["ej_cifras", "ej_avance"]})
        self.assertFalse(sel.es_ejecutivo())
        self.assertEqual(sel.apartados, isel.APARTADOS_MENSUAL)

    def test_ordenar_apartados_no_mezcla_los_dos_catalogos(self):
        mezcla = isel.ordenar_apartados(["portada", "anexo", "ej_cifras"])
        self.assertEqual(mezcla, ("ej_cifras",))
        self.assertEqual(isel.ordenar_apartados(["portada", "anexo"]),
                         ("portada", "anexo"))

    def test_la_numeracion_del_esquema_es_la_del_documento(self):
        sel = self._sel({"plantilla": "ejecutivo"})
        esquema = isel.esquema(sel)
        self.assertEqual([e["numero"] for e in esquema], [None, 1, 2, 3, 4, 5])
        self.assertEqual(esquema[0]["titulo"], "Portada del informe ejecutivo")

    def test_la_estimacion_promete_diez_paginas_o_menos(self):
        sel = self._sel({"plantilla": "ejecutivo"})
        estimacion = isel.estimacion(sel, {"amenazas": 25000}, actualizaciones=90000)
        self.assertLessEqual(estimacion["paginas"], 10,
                             "la estimación no puede pasar de diez páginas ni con la base llena")
        self.assertEqual(estimacion["fichas"], 0)
        self.assertEqual(estimacion["filas_anexo"], 0)

    def test_el_nombre_del_fichero_lo_identifica(self):
        sel = self._sel({"plantilla": "ejecutivo", "mes": "2026-09"})
        self.assertEqual(sel.nombre_fichero(), "informe_ejecutivo_2026-09.docx")
        self.assertEqual(report.nombre_fichero_ejecutivo("2026-09"),
                         "Informe_Ejecutivo_2026_09.docx")


# ==========================================================================
# 6. La pantalla y el permiso
# ==========================================================================
class TestPantalla(BaseConDatos):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)
        if "informes" not in cls.app.blueprints:
            cls.app.register_blueprint(informes.bp)

    def _cliente(self, correo: str):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": correo, "password": CLAVE})
        return cli

    def _csrf(self, cli) -> str:
        html = cli.get("/", follow_redirects=True).get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def test_la_plantilla_se_abre_por_su_enlace(self):
        cli = self._cliente("admin@ejemplo.local")
        r = cli.get("/informes/?plantilla=ejecutivo")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("Informe ejecutivo del mes", html)
        self.assertIn("En uso", html)
        self.assertIn("nunca pasa de diez páginas", html)
        # Su esquema, con los cinco apartados numerados.
        self.assertIn("1. Las cifras del mes", html)
        self.assertIn("5. Qué conviene hacer el mes que viene", html)

    def test_la_pantalla_cumple_la_politica_de_contenido(self):
        cli = self._cliente("admin@ejemplo.local")
        html = cli.get("/informes/?plantilla=ejecutivo").get_data(as_text=True)
        self.assertNotIn("<script>", html.lower().replace(" ", ""))
        self.assertNotRegex(html, r'<[a-zA-Z][^>]*\sstyle=')
        self.assertNotRegex(html, r'<[a-zA-Z][^>]*\son[a-z]+=')

    def test_se_genera_y_se_descarga(self):
        cli = self._cliente("admin@ejemplo.local")
        r = cli.post("/informes/generar", data={
            "csrf": self._csrf(cli), "plantilla": "ejecutivo",
            "periodo": "mes", "mes": "2026-09", "alcance": "organizacion",
            "apartados_enviados": "1",
            "apartado": list(isel.APARTADOS_EJECUTIVO),
            "sev": list(isel.SEVERIDADES)})
        self.assertEqual(r.status_code, 200)
        self.assertIn("wordprocessingml", r.headers.get("Content-Type", ""))
        self.assertIn("informe_ejecutivo_2026-09.docx",
                      r.headers.get("Content-Disposition", ""))
        import io
        doc = Document(io.BytesIO(r.get_data()))
        self.assertEqual(len(_titulos(doc)), 5)

    def test_la_generacion_queda_en_la_auditoria(self):
        # Generar informes es exclusivo de administración (auth.ROLES_INFORMES).
        cli = self._cliente("admin@ejemplo.local")
        cli.post("/informes/generar", data={
            "csrf": self._csrf(cli), "plantilla": "ejecutivo",
            "periodo": "mes", "mes": "2026-09", "alcance": "organizacion",
            "apartados_enviados": "1",
            "apartado": list(isel.APARTADOS_EJECUTIVO),
            "sev": list(isel.SEVERIDADES)})
        with db.session(self.ruta) as conn:
            fila = conn.execute(
                "SELECT username, action, entity_id, detail FROM audit_log "
                "WHERE action='informe.medida' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertIsNotNone(fila, "la generación no quedó auditada")
        self.assertEqual(fila["username"], "admin@ejemplo.local")
        self.assertEqual(fila["entity_id"], "ejecutivo")
        self.assertIn("informe ejecutivo de septiembre de 2026", fila["detail"])

    def test_un_perfil_sin_permiso_no_llega(self):
        cli = self._cliente("lectora@ejemplo.local")
        self.assertEqual(cli.get("/informes/?plantilla=ejecutivo").status_code, 403)
        r = cli.post("/informes/generar", data={"plantilla": "ejecutivo"})
        self.assertIn(r.status_code, (400, 403))

    def test_sin_token_no_se_genera(self):
        cli = self._cliente("admin@ejemplo.local")
        r = cli.post("/informes/generar", data={"plantilla": "ejecutivo",
                                                "mes": "2026-09"})
        self.assertNotEqual(r.status_code, 200)
        self.assertNotIn("wordprocessingml", r.headers.get("Content-Type", ""))


if __name__ == "__main__":
    unittest.main()
