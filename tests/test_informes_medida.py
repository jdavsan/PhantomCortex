"""Generador de informes a medida (/informes/, 2026-09-10).

El usuario pidió: «el apartado de /informes/ es para que se puedan crear informes con lo
que uno desee, es decir que uno pueda agregar lo que desea y no descargar los informes de
cada mes, entonces ajusta eso, la idea es poder crear informes personalizados y tener
plantillas de informes preconfiguradas».

Estas pruebas fijan lo que el generador promete:

* la selección se valida contra listas blancas: un periodo, un alcance o una severidad que
  no existan caen al valor de la plantilla, y **la severidad baja no entra nunca**, ni
  escribiéndola en la dirección web;
* los filtros de periodo, alcance y severidad se aplican de verdad: se comprueba el
  CONTENIDO del documento y de las consultas, no solo que la página responda 200;
* cada plantilla genera sin error y el documento lleva los apartados que promete y ninguno
  más, numerados seguidos;
* el informe mensual por omisión sigue siendo IDÉNTICO al de antes: se compara párrafo a
  párrafo y celda a celda con ``report.construir_documento`` sin argumentos nuevos;
* un perfil acotado a un tipo de máquina no puede generar fuera de su alcance (404);
* una selección que no devuelve nada avisa en vez de generar un documento vacío;
* la generación queda en la auditoría con la plantilla, el periodo, el alcance y los
  apartados, y la página cumple la CSP estricta y lleva recorrido guiado en orden.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_informes_medida
"""
from __future__ import annotations

import io
import re
import sys
import tempfile
import unittest
from datetime import date
from html import unescape
from pathlib import Path
from unittest import mock

from docx import Document

from threatintel import db, informe_seleccion as isel, report
from threatintel.paths import BASE_DIR, REPORTS_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402
from webui.vistas import informes  # noqa: E402

CLAVE = "ClaveSegura#2026"

#: Meses con datos en la base de prueba. La distribución está pensada para que cada filtro
#: se pueda comprobar con una cifra distinta: julio tiene bajas (que no deben contar
#: nunca), agosto tiene KEV y septiembre es el mes «en curso».
PLAN = {
    "2026-07": {"Critical": 2, "High": 1, "Medium": 3, "Low": 4},
    "2026-08": {"Critical": 3, "High": 2, "Medium": 1, "Low": 1},
    "2026-09": {"Critical": 1, "High": 1, "Medium": 2, "Low": 2},
}


class ConfiguracionFalsa:
    """La configuración mínima que necesitan el informe y las vistas, sin ficheros."""
    settings: dict = {}
    report_to: list = []

    def get(self, clave, defecto=None):
        from threatintel.config import DEFAULT_SETTINGS
        if clave == "translate_engine":
            return "none"
        return DEFAULT_SETTINGS.get(clave, defecto)


def _sembrar(ruta: str) -> dict:
    """Base de prueba con amenazas de tres meses, dos activos, una tecnología,
    aplicabilidad confirmada y una remediación pendiente con su versión corregida."""
    ids: dict = {"amenazas": {}}
    with db.session(ruta) as conn:
        auth.crear_usuario(conn, "admin@ejemplo.local", CLAVE, rol="admin",
                           nombre="Administradora", actor="t")
        auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                           nombre="Lectora", actor="t")
        auth.crear_usuario(conn, "operador@ejemplo.local", CLAVE, rol="ciberseguridad",
                           nombre="Operador SOC", actor="t")
        auth.crear_usuario(conn, "redes@ejemplo.local", CLAVE, rol="redes",
                           nombre="Jefe de Redes", actor="t")

        # Tecnología del inventario
        cur = conn.execute(
            """INSERT INTO technologies(slug, name, version_installed, criticality,
                                        systems_count, exposure, enabled, created_at,
                                        updated_at)
               VALUES('openssl','OpenSSL','3.0.1','high',12,'internet',1,?,?)""",
            (db.utcnow(), db.utcnow()))
        ids["tecnologia"] = cur.lastrowid

        # Activos: un servidor de «Impuestos» y un equipo de cómputo de «Pila»
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
                    en_kev = 1 if (mes == "2026-08" and severidad == "Critical") else 0
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
                    # Correlación con la tecnología y aplicabilidad confirmada en el
                    # servidor; el equipo de cómputo solo para las de agosto.
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
                    if mes == "2026-08":
                        objetivos.append(ids["equipos"])
                    for activo_id in objetivos:
                        conn.execute(
                            """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                                    version_instalada, version_corregida, veredicto, motor,
                                    evidencia, evaluado_at)
                               VALUES(?,?,?,'openssl','3.0.1','3.0.14','afectado','osv',
                                      'prueba',?)""",
                            (activo_id, tid, f"CVE-2026-{n:04d}", db.utcnow()))
                        conn.execute(
                            """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete,
                                    version_vulnerable, version_corregida, motor, estado,
                                    detectado_at, comprobado_at)
                               VALUES(?,?,?,'openssl','3.0.1','3.0.14','osv','abierta',?,?)""",
                            (activo_id, tid, f"CVE-2026-{n:04d}", db.utcnow(), db.utcnow()))
    return ids


def _app(ruta: str):
    from webui.app import crear_app
    app = crear_app(db_path=ruta, testing=True)
    if "informes" not in app.blueprints:
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


def _huella(doc) -> list[str]:
    """Párrafos (con su estilo) y filas de tabla del documento, para compararlos."""
    partes = [f"{p.style.name}|{p.text}" for p in doc.paragraphs]
    for tabla in doc.tables:
        for fila in tabla.rows:
            partes.append("TABLA|" + "¬".join(c.text for c in fila.cells))
    return partes


def _titulos(doc) -> list[str]:
    return [p.text for p in doc.paragraphs if p.style.name == "Heading 1"]


# ==========================================================================
# 1. La selección: validación y listas blancas
# ==========================================================================
class TestSeleccion(unittest.TestCase):
    """Funciones puras: aquí está el riesgo de que la dirección web mande de más."""

    MESES = ["2026-09", "2026-08", "2026-07"]

    def _sel(self, params, **kw):
        return isel.Seleccion.desde_parametros(params, meses_disponibles=self.MESES, **kw)

    def test_sin_parametros_es_el_informe_mensual_de_siempre(self):
        sel = self._sel({})
        self.assertEqual(sel.plantilla, "mensual")
        self.assertEqual(sel.periodo, "mes")
        self.assertEqual(sel.mes, "2026-09", "el mes más reciente con datos")
        self.assertEqual(sel.apartados, isel.APARTADOS_MENSUAL)
        self.assertEqual(sel.severidades, isel.SEVERIDADES)
        self.assertTrue(sel.es_mensual_clasico())

    def test_la_severidad_baja_no_entra_ni_escribiendola_en_la_direccion(self):
        sel = self._sel({"sev": ["Low"], "mes": "2026-08"})
        self.assertNotIn("Low", sel.severidades)
        self.assertEqual(sel.severidades, isel.SEVERIDADES,
                         "sin ninguna severidad válida se usan las tres que se reportan")
        sel2 = self._sel({"sev": ["Low", "Critical"]})
        self.assertEqual(sel2.severidades, ("Critical",))
        sql, params = sel2.where_severidad()
        self.assertNotIn("Low", params)
        self.assertNotIn("Low", isel.SEVERIDADES)

    def test_valores_desconocidos_caen_a_la_plantilla(self):
        sel = self._sel({"plantilla": "inventada", "periodo": "milenio",
                         "alcance": "galaxia", "apartado": ["ninguno"]})
        self.assertEqual(sel.plantilla, "mensual")
        self.assertEqual(sel.periodo, "mes")
        self.assertEqual(sel.alcance, "organizacion")
        self.assertEqual(sel.apartados, isel.APARTADOS_MENSUAL)

    def test_los_numeros_y_las_fechas_se_acotan(self):
        self.assertEqual(self._sel({"periodo": "dias", "dias": "0"}).dias, 1)
        self.assertEqual(self._sel({"periodo": "dias", "dias": "99999"}).dias, 366)
        self.assertEqual(self._sel({"periodo": "dias", "dias": "no"}).dias, 30)
        # Fechas al revés: se ordenan solas.
        sel = self._sel({"periodo": "intervalo", "desde": "2026-08-31", "hasta": "2026-08-01"})
        self.assertEqual((sel.desde, sel.hasta), ("2026-08-01", "2026-08-31"))
        # Una fecha imposible cae al último mes.
        sel2 = self._sel({"periodo": "intervalo", "desde": "2026-02-31", "hasta": "x"})
        self.assertRegex(sel2.desde, r"^\d{4}-\d{2}-\d{2}$")
        # Intervalo desmedido: se recorta al tope.
        sel3 = self._sel({"periodo": "intervalo", "desde": "1990-01-01", "hasta": "2026-01-01"})
        desde, hasta = sel3.rango()
        self.assertLessEqual((hasta - desde).days, isel.DIAS_MAXIMO)

    def test_el_periodo_se_escribe_en_espanol(self):
        self.assertEqual(self._sel({"mes": "2026-08"}).etiqueta_periodo(), "agosto de 2026")
        self.assertIn("últimos 15 días",
                      self._sel({"periodo": "dias", "dias": "15"}).etiqueta_periodo())
        self.assertIn("de agosto de 2026",
                      self._sel({"periodo": "intervalo", "desde": "2026-08-01",
                                 "hasta": "2026-08-10"}).etiqueta_periodo())
        self.assertIn("el año", self._sel({"periodo": "anio"}).etiqueta_periodo())

    def test_el_nombre_del_fichero_no_lleva_texto_de_la_persona(self):
        sel = self._sel({"plantilla": "direccion", "mes": "2026-08",
                         "titulo": "../../etc/passwd y otras cosas raras"})
        self.assertEqual(sel.nombre_fichero(), "informe_direccion_2026-08.docx")
        self.assertRegex(sel.nombre_fichero(), r"^informe_[a-z]+_[\d_-]+\.docx$")
        for malo in ("..", "/", "\\", "passwd"):
            self.assertNotIn(malo, sel.nombre_fichero())

    def test_los_textos_se_limpian_y_se_recortan(self):
        sel = self._sel({"titulo": "Informe\x00 con\tcontrol " + "x" * 200,
                         "nota": " nota  con    espacios "})
        self.assertNotIn("\x00", sel.titulo)
        self.assertNotIn("\t", sel.titulo)
        self.assertLessEqual(len(sel.titulo), 120)
        self.assertEqual(sel.nota, "nota con espacios")

    def test_la_seleccion_va_y_vuelve_por_la_direccion_web(self):
        """Es lo que sustituye a guardar plantillas en la base: el enlace ES la plantilla."""
        for params in ({"plantilla": "direccion", "mes": "2026-08", "sev": ["Critical"]},
                       {"plantilla": "proceso", "alcance": "proceso", "proceso": "Impuestos"},
                       {"plantilla": "kev", "periodo": "dias", "dias": "45"},
                       {"plantilla": "activo", "alcance": "activo", "activo": "7",
                        "titulo": "Informe del servidor", "destinatario": "Redes",
                        "nota": "Para la reunión del jueves"}):
            with self.subTest(params=params):
                sel = self._sel(params)
                vuelta = self._sel(sel.a_parametros())
                self.assertEqual(sel, vuelta)

    def test_los_apartados_se_ordenan_y_se_numeran_como_siempre(self):
        self.assertEqual(isel.ordenar_apartados(["conclusiones", "portada", "portada", "x"]),
                         ("portada", "conclusiones"))
        historicos = isel.numeros_de_apartado(isel.APARTADOS_MENSUAL)
        self.assertEqual(historicos, {"resumen_ejecutivo": 1, "panorama": 2, "tecnologias": 3,
                                      "activos": 4, "prioritarias": 5, "conclusiones": 6,
                                      "precision": 7, "metodologia": 8})
        # Un informe corto numera seguido, sin huecos.
        self.assertEqual(isel.numeros_de_apartado(("portada", "resumen_ejecutivo",
                                                   "conclusiones")),
                         {"resumen_ejecutivo": 1, "conclusiones": 2})

    def test_las_plantillas_estan_completas_y_son_coherentes(self):
        self.assertGreaterEqual(len(isel.PLANTILLAS), 6)
        for p in isel.PLANTILLAS:
            with self.subTest(plantilla=p.clave):
                self.assertTrue(p.nombre and p.descripcion and p.para_quien)
                self.assertIn(p.periodo, isel.CLASES_PERIODO)
                self.assertIn(p.alcance, isel.ALCANCES)
                self.assertEqual(isel.ordenar_apartados(p.apartados),
                                 tuple(p.apartados), "los apartados van en orden del documento")
                for clave in p.apartados:
                    self.assertIn(clave, isel.APARTADO_POR_CLAVE)
                self.assertNotIn("Low", p.severidades)
        self.assertEqual(isel.PLANTILLA_POR_CLAVE["mensual"].apartados, isel.APARTADOS_MENSUAL)

    def test_la_plantilla_de_proceso_y_de_activo_piden_el_dato_que_falta(self):
        sel = self._sel({"plantilla": "proceso"})
        completa, falta = sel.completa()
        self.assertFalse(completa)
        self.assertIn("proceso de negocio", falta)
        sel2 = self._sel({"plantilla": "activo"})
        self.assertFalse(sel2.completa()[0])
        self.assertIn("activo", sel2.completa()[1])

    def test_el_alcance_del_perfil_manda_sobre_la_direccion(self):
        sel = self._sel({"alcance": "tipo", "tipo": "equipos"}, origen_perfil="servidores")
        self.assertEqual(sel.tipo, "servidores", "un perfil de Redes no informa de equipos")
        sql, params = sel.where_alcance()
        self.assertIn("servidores", params)
        self.assertNotIn("equipos", params)
        # También cuando pide «toda la organización».
        sel2 = self._sel({"alcance": "organizacion"}, origen_perfil="equipos")
        self.assertIn("equipos", sel2.where_alcance()[1])
        self.assertFalse(sel2.es_mensual_clasico(),
                         "con alcance de perfil ya no es el informe mensual completo")

    def test_el_sql_va_siempre_parametrizado(self):
        sel = self._sel({"alcance": "proceso", "proceso": "Robert'); DROP TABLE threats;--",
                         "mes": "2026-08"})
        sql, params = sel.where()
        self.assertNotIn("DROP", sql)
        self.assertIn("Robert'); DROP TABLE threats;--", params)
        self.assertEqual(sql.count("?"), len(params))


# ==========================================================================
# 1b. Calendario fijo: trimestre, semestre y año completo (2026-11-17)
# ==========================================================================
class TestPeriodoCalendarioFijo(unittest.TestCase):
    """Petición del usuario: trimestral/semestral/anual con periodos de CALENDARIO fijo
    (Q1 ene-mar...), no «los últimos N meses». Todo relativo a ``isel.hoy()`` real, nunca
    a una fecha fija, para que la prueba no caduque (es la misma razón por la que otras
    pruebas del proyecto recalculan AHORA en vez de fijarlo)."""

    def _sel(self, params):
        return isel.Seleccion.desde_parametros(params, meses_disponibles=[])

    @staticmethod
    def _fin_de_mes(anio: int, mes: int) -> date:
        """Cálculo independiente del que usa el código, para no probar una función
        contra sí misma."""
        import calendar
        return date(anio, mes, calendar.monthrange(anio, mes)[1])

    def test_un_trimestre_totalmente_pasado_no_se_recorta(self):
        hoy = isel.hoy()
        # Dos trimestres atras del actual: siempre terminado por completo.
        anio, t = hoy.year, (hoy.month - 1) // 3 + 1
        anio, t = (anio - 1, t + 2) if t <= 2 else (anio, t - 2)
        sel = self._sel({"periodo": "trimestre", "trimestre": f"{anio}-T{t}"})
        desde, hasta = sel.rango()
        primer_mes = 3 * t - 2
        self.assertEqual(desde, date(anio, primer_mes, 1))
        self.assertEqual(hasta, self._fin_de_mes(anio, primer_mes + 2))
        self.assertLess(hasta, hoy, "un trimestre ya terminado no llega hasta hoy")

    def test_el_trimestre_en_curso_se_corta_hoy(self):
        hoy = isel.hoy()
        t_actual = (hoy.month - 1) // 3 + 1
        sel = self._sel({"periodo": "trimestre", "trimestre": f"{hoy.year}-T{t_actual}"})
        _, hasta = sel.rango()
        self.assertEqual(hasta, hoy)

    def test_un_semestre_totalmente_pasado_no_se_recorta(self):
        hoy = isel.hoy()
        s_actual = 1 if hoy.month <= 6 else 2
        anio, s = (hoy.year - 1, 2) if s_actual == 1 else (hoy.year, 1)
        sel = self._sel({"periodo": "semestre", "semestre": f"{anio}-S{s}"})
        desde, hasta = sel.rango()
        primer_mes = 6 * s - 5
        self.assertEqual(desde, date(anio, primer_mes, 1))
        self.assertEqual(hasta, self._fin_de_mes(anio, primer_mes + 5))

    def test_anio_sin_elegir_ninguno_sigue_siendo_el_actual_hasta_hoy(self):
        """Compatibilidad: un enlace guardado ANTES de que existiera «anio_valor» (sin
        ese parámetro) tiene que dar exactamente lo mismo que daba antes."""
        hoy = isel.hoy()
        sel = self._sel({"periodo": "anio"})
        desde, hasta = sel.rango()
        self.assertEqual(desde, date(hoy.year, 1, 1))
        self.assertEqual(hasta, hoy)
        self.assertEqual(sel.anio_valor, "")

    def test_anio_pasado_elegido_entra_completo(self):
        anio_pasado = isel.hoy().year - 1
        sel = self._sel({"periodo": "anio", "anio_valor": str(anio_pasado)})
        desde, hasta = sel.rango()
        self.assertEqual(desde, date(anio_pasado, 1, 1))
        self.assertEqual(hasta, date(anio_pasado, 12, 31))
        self.assertIn("completo", sel.etiqueta_periodo())

    def test_valores_mal_formados_se_descartan_en_vez_de_fallar(self):
        for params in (
                {"periodo": "trimestre", "trimestre": "no-es-nada"},
                {"periodo": "trimestre", "trimestre": "2026-T9"},
                {"periodo": "semestre", "semestre": "2026-S3"},
                {"periodo": "anio", "anio_valor": "no-es-un-año"},
                {"periodo": "anio", "anio_valor": "99999"}):
            with self.subTest(params=params):
                sel = self._sel(params)
                # No lanza excepción y da un rango valido (el de respaldo: el año actual).
                desde, hasta = sel.rango()
                self.assertLessEqual(desde, hasta)

    def test_a_parametros_reconstruye_el_trimestre_elegido(self):
        original = self._sel({"periodo": "trimestre", "trimestre": "2026-T2"})
        reconstruida = self._sel(original.a_parametros())
        self.assertEqual(reconstruida.periodo, "trimestre")
        self.assertEqual(reconstruida.trimestre, "2026-T2")
        self.assertEqual(reconstruida.rango(), original.rango())

    def test_a_parametros_reconstruye_el_semestre_elegido(self):
        original = self._sel({"periodo": "semestre", "semestre": "2025-S1"})
        reconstruida = self._sel(original.a_parametros())
        self.assertEqual(reconstruida.semestre, "2025-S1")

    def test_a_parametros_reconstruye_el_anio_elegido(self):
        original = self._sel({"periodo": "anio", "anio_valor": "2025"})
        reconstruida = self._sel(original.a_parametros())
        self.assertEqual(reconstruida.anio_valor, "2025")

    def test_las_etiquetas_usan_la_ordinal_correcta(self):
        self.assertEqual(isel.etiqueta_trimestre(2026, 1), "1.er trimestre de 2026 (enero-marzo)")
        self.assertEqual(isel.etiqueta_trimestre(2026, 3),
                         "3.er trimestre de 2026 (julio-septiembre)")
        self.assertEqual(isel.etiqueta_trimestre(2026, 2),
                         "2.º trimestre de 2026 (abril-junio)")
        self.assertEqual(isel.etiqueta_semestre(2026, 1), "1.er semestre de 2026 (enero-junio)")


# ==========================================================================
# 2. Las consultas: los filtros se aplican de verdad
# ==========================================================================
class BaseConDatos(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "informes_medida.db")
        db.init_db(cls.ruta)
        cls.ids = _sembrar(cls.ruta)
        cls.app = _app(cls.ruta)
        cls.cfg = ConfiguracionFalsa()

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _sel(self, params, **kw):
        return isel.Seleccion.desde_parametros(
            params, meses_disponibles=list(PLAN)[::-1], **kw)


class TestConsultasFiltradas(BaseConDatos):

    def test_el_filtro_de_mes_cuenta_solo_ese_mes_y_sin_bajas(self):
        with db.session(self.ruta) as conn:
            for mes, reparto in PLAN.items():
                sel = self._sel({"mes": mes})
                stats = isel.estadisticas(conn, sel)
                esperado = reparto["Critical"] + reparto["High"] + reparto["Medium"]
                with self.subTest(mes=mes):
                    self.assertEqual(stats["total"], esperado,
                                     "las bajas no cuentan en ninguna cifra")
                    self.assertEqual(stats["criticas"], reparto["Critical"])
                    self.assertEqual(stats["bajas"], 0)

    def test_el_filtro_de_severidad_recorta_el_total(self):
        with db.session(self.ruta) as conn:
            sel = self._sel({"mes": "2026-08", "sev": ["Critical"]})
            stats = isel.estadisticas(conn, sel)
            self.assertEqual(stats["total"], PLAN["2026-08"]["Critical"])
            self.assertEqual(stats["altas"], 0)
            amenazas = isel.amenazas(conn, sel)
            self.assertEqual({a["severity"] for a in amenazas}, {"Critical"})

    def test_el_intervalo_de_fechas_y_los_ultimos_dias_recortan_igual(self):
        with db.session(self.ruta) as conn:
            solo_agosto = self._sel({"periodo": "intervalo", "desde": "2026-08-01",
                                     "hasta": "2026-08-31"})
            esperado = sum(v for k, v in PLAN["2026-08"].items() if k != "Low")
            self.assertEqual(isel.estadisticas(conn, solo_agosto)["total"], esperado)
            # Un día antes del primero: no entra nada de agosto.
            vacio = self._sel({"periodo": "intervalo", "desde": "2026-08-01",
                               "hasta": "2026-08-04"})
            self.assertEqual(isel.estadisticas(conn, vacio)["total"], 0)
            # El día exacto sí entra (los dos extremos del intervalo cuentan).
            justo = self._sel({"periodo": "intervalo", "desde": "2026-08-05",
                               "hasta": "2026-08-05"})
            self.assertEqual(isel.estadisticas(conn, justo)["total"], esperado)

    def test_el_alcance_por_proceso_por_tipo_y_por_activo(self):
        with db.session(self.ruta) as conn:
            # El equipo de cómputo solo tiene aplicabilidad de agosto.
            equipos = self._sel({"periodo": "anio", "alcance": "tipo", "tipo": "equipos"})
            esperado_agosto = sum(v for k, v in PLAN["2026-08"].items() if k != "Low")
            self.assertEqual(isel.estadisticas(conn, equipos)["total"], esperado_agosto)
            # El servidor los tiene de los tres meses.
            servidores = self._sel({"periodo": "anio", "alcance": "tipo",
                                    "tipo": "servidores"})
            total_anio = sum(v for reparto in PLAN.values()
                             for k, v in reparto.items() if k != "Low")
            self.assertEqual(isel.estadisticas(conn, servidores)["total"], total_anio)
            # Por proceso: «Pila» es el equipo de cómputo, «Impuestos» el servidor.
            pila = self._sel({"periodo": "anio", "alcance": "proceso", "proceso": "Pila"})
            self.assertEqual(isel.estadisticas(conn, pila)["total"], esperado_agosto)
            # Por activo concreto.
            uno = self._sel({"periodo": "anio", "alcance": "activo",
                             "activo": str(self.ids["equipos"])})
            self.assertEqual(isel.estadisticas(conn, uno)["total"], esperado_agosto)
            # Un proceso que no existe no devuelve nada (y no revienta).
            ninguno = self._sel({"periodo": "anio", "alcance": "proceso",
                                 "proceso": "No existe"})
            self.assertEqual(isel.estadisticas(conn, ninguno)["total"], 0)

    def test_el_alcance_por_tecnologia_y_por_explotacion_activa(self):
        with db.session(self.ruta) as conn:
            tec = self._sel({"periodo": "anio", "alcance": "tecnologia",
                             "tecnologia": "openssl"})
            total_anio = sum(v for reparto in PLAN.values()
                             for k, v in reparto.items() if k != "Low")
            self.assertEqual(isel.estadisticas(conn, tec)["total"], total_anio)
            desconocida = self._sel({"periodo": "anio", "alcance": "tecnologia",
                                     "tecnologia": "no-existe"})
            self.assertEqual(isel.estadisticas(conn, desconocida)["total"], 0)
            kev = self._sel({"periodo": "anio", "alcance": "kev"})
            self.assertEqual(isel.estadisticas(conn, kev)["total"],
                             PLAN["2026-08"]["Critical"])
            self.assertEqual(isel.estadisticas(conn, kev)["en_kev"],
                             PLAN["2026-08"]["Critical"])

    def test_la_vista_previa_dice_amenazas_y_activos(self):
        with db.session(self.ruta) as conn:
            previa = isel.vista_previa(conn, self._sel({"mes": "2026-08"}))
            self.assertEqual(previa["amenazas"],
                             sum(v for k, v in PLAN["2026-08"].items() if k != "Low"))
            self.assertEqual(previa["activos_afectados"], 2)
            self.assertEqual(previa["activos_ambito"], 2)
            # Acotada a un tipo de máquina, el denominador también se acota.
            previa2 = isel.vista_previa(conn, self._sel({"mes": "2026-08", "alcance": "tipo",
                                                         "tipo": "servidores"}))
            self.assertEqual(previa2["activos_ambito"], 1)
            self.assertEqual(previa2["activos_afectados"], 1)
            # Un periodo sin datos: cero, y la pantalla lo usa para no generar.
            previa3 = isel.vista_previa(conn, self._sel({"periodo": "intervalo",
                                                         "desde": "2020-01-01",
                                                         "hasta": "2020-01-31"}))
            self.assertEqual(previa3["amenazas"], 0)

    def test_el_resumen_de_activos_respeta_el_alcance(self):
        with db.session(self.ruta) as conn:
            todo = isel.resumen_activos(conn, self._sel({"mes": "2026-08"}), cfg=self.cfg)
            self.assertEqual(todo["total"], 2)
            self.assertEqual(todo["servidores"], 1)
            self.assertEqual(todo["equipos"], 1)
            self.assertEqual(todo["activos_afectados"], 2)
            solo_servidores = isel.resumen_activos(
                conn, self._sel({"mes": "2026-08", "alcance": "tipo", "tipo": "servidores"}),
                cfg=self.cfg)
            self.assertEqual(solo_servidores["total"], 1)
            self.assertEqual(solo_servidores["equipos"], 0)
            self.assertEqual(solo_servidores["activos_afectados"], 1)

    def test_las_actualizaciones_pendientes_se_cuentan_por_alcance(self):
        with db.session(self.ruta) as conn:
            todas = isel.actualizaciones_pendientes(conn, self._sel({"periodo": "anio"}))
            self.assertEqual(todas, 2, "una actualización por activo (mismo paquete)")
            solo_uno = isel.actualizaciones_pendientes(
                conn, self._sel({"periodo": "anio", "alcance": "activo",
                                 "activo": str(self.ids["servidores"])}))
            self.assertEqual(solo_uno, 1)


# ==========================================================================
# 3. Los documentos: apartados prometidos y nada más
# ==========================================================================
class TestDocumentos(BaseConDatos):

    def _documento(self, sel):
        return report.construir_documento(
            self.conn, sel.mes_representativo(), cfg=self.cfg,
            secciones=sel.apartados, filtros=sel)

    def setUp(self):
        self.contexto = db.session(self.ruta)
        self.conn = self.contexto.__enter__()

    def tearDown(self):
        self.contexto.__exit__(None, None, None)

    def test_el_informe_mensual_por_omision_es_identico_al_de_antes(self):
        """La ejecución mensual programada no puede notar este cambio."""
        antes = _huella(report.construir_documento(self.conn, "2026-08", cfg=self.cfg))
        # Mismo documento pidiendo explícitamente los apartados del informe mensual.
        despues = _huella(report.construir_documento(
            self.conn, "2026-08", cfg=self.cfg, secciones=isel.APARTADOS_MENSUAL))
        self.assertEqual(antes, despues)
        self.assertEqual(
            [t for t in antes if t.startswith("Heading 1|")],
            ["Heading 1|Índice", "Heading 1|1. Resumen ejecutivo",
             "Heading 1|2. Panorama del periodo",
             "Heading 1|3. Exposición de la organización",
             "Heading 1|4. Activos de la organización",
             "Heading 1|5. Vulnerabilidades prioritarias",
             "Heading 1|Anexo A. Relación del resto de hallazgos",
             "Heading 1|6. Conclusiones y recomendaciones",
             "Heading 1|7. Precisión del filtro de alertas",
             "Heading 1|8. Nota metodológica"])

    def test_cada_plantilla_genera_y_trae_sus_apartados_y_ninguno_mas(self):
        titulos_esperados = {
            "portada": None, "indice": "Índice",
            "resumen_ejecutivo": "Resumen ejecutivo",
            "panorama": "Panorama del periodo",
            "tecnologias": "Exposición de la organización",
            "activos": "Activos de la organización",
            "prioritarias": "Vulnerabilidades prioritarias",
            "remediacion": "Cola de remediación",
            "anexo": "Anexo A.", "conclusiones": "Conclusiones y recomendaciones",
            "precision": "Precisión del filtro", "metodologia": "Nota metodológica",
        }
        for plantilla in isel.PLANTILLAS:
            if plantilla.clave == isel.PLANTILLA_EJECUTIVA:
                # El informe ejecutivo mensual (2026-09-15) no se compone con estos
                # apartados: es otro documento, con su propio generador y su estructura
                # fija. Lo cubre tests/test_informe_ejecutivo.py.
                continue
            params = {"plantilla": plantilla.clave, "mes": "2026-08"}
            if plantilla.alcance == "proceso":
                params["proceso"] = "Impuestos"
            if plantilla.alcance == "activo":
                params["activo"] = str(self.ids["servidores"])
            sel = self._sel(params)
            with self.subTest(plantilla=plantilla.clave):
                self.assertTrue(sel.completa()[0], sel.completa()[1])
                doc = self._documento(sel)
                titulos = _titulos(doc)
                # Están los que promete...
                for clave in sel.apartados:
                    esperado = titulos_esperados[clave]
                    if esperado is None:
                        continue
                    self.assertTrue(any(esperado in t for t in titulos),
                                    f"falta el apartado «{clave}» en {titulos}")
                # ...y ninguno de los que no promete.
                for clave, esperado in titulos_esperados.items():
                    if clave in sel.apartados or esperado is None:
                        continue
                    self.assertFalse(any(esperado in t for t in titulos),
                                     f"sobra el apartado «{clave}» en {titulos}")
                # Numeración seguida, sin huecos.
                numeros = [int(m.group(1)) for t in titulos
                           if (m := re.match(r"^(\d+)\.", t))]
                self.assertEqual(numeros, list(range(1, len(numeros) + 1)),
                                 f"la numeración salta: {titulos}")

    def test_el_resumen_para_direccion_no_lleva_fichas_ni_anexo(self):
        sel = self._sel({"plantilla": "direccion", "mes": "2026-08"})
        doc = self._documento(sel)
        texto = "\n".join(p.text for p in doc.paragraphs)
        self.assertNotIn("Anexo A", texto)
        self.assertNotIn("Vulnerabilidades prioritarias", texto)
        self.assertIn("Resumen ejecutivo", texto)
        self.assertIn("Conclusiones", texto)

    def test_el_informe_tecnico_de_remediacion_dice_a_que_version_actualizar(self):
        sel = self._sel({"plantilla": "remediacion", "mes": "2026-08"})
        doc = self._documento(sel)
        filas = [f for f in _huella(doc) if f.startswith("TABLA|")]
        cabeceras = [f for f in filas if "Actualizar a" in f]
        self.assertTrue(cabeceras, "la tabla de la cola no tiene su cabecera")
        self.assertTrue(any("3.0.14" in f for f in filas),
                        "no aparece la versión a la que hay que actualizar")
        self.assertTrue(any("srv-informes-01" in f for f in filas))
        texto = "\n".join(p.text for p in doc.paragraphs)
        self.assertIn("situación actual", texto,
                      "el apartado debe advertir que la cola no es la foto del periodo")

    def test_el_informe_de_explotacion_activa_solo_trae_las_del_catalogo_kev(self):
        """Solo las del catálogo KEV de CISA: se comprueba CVE a CVE."""
        sel = self._sel({"plantilla": "kev"})
        doc = self._documento(sel)
        contenido = "\n".join(_huella(doc))
        with db.session(self.ruta) as conn:
            en_kev = {f[0] for f in conn.execute(
                "SELECT cve FROM threats WHERE in_kev=1")}
            fuera = {f[0] for f in conn.execute(
                "SELECT cve FROM threats WHERE in_kev=0 AND month='2026-08'")}
        self.assertTrue(en_kev)
        for cve in en_kev:
            self.assertIn(cve, contenido, f"falta {cve}, que sí está en KEV")
        for cve in fuera:
            self.assertNotIn(cve, contenido, f"sobra {cve}, que no está en KEV")
        self.assertIn("explotación activa", contenido)

    def test_el_informe_de_un_activo_habla_solo_de_ese_activo(self):
        sel = self._sel({"plantilla": "activo", "periodo": "anio",
                         "activo": str(self.ids["equipos"])})
        doc = self._documento(sel)
        filas = "\n".join(_huella(doc))
        self.assertIn("pc-informes-01", filas)
        self.assertNotIn("srv-informes-01", filas)

    def test_la_severidad_baja_no_aparece_en_ninguna_cifra(self):
        for params in ({"plantilla": "mensual", "mes": "2026-07", "titulo": "Con filtros"},
                       {"plantilla": "direccion", "mes": "2026-07"}):
            sel = self._sel(params)
            with self.subTest(params=params):
                doc = self._documento(sel)
                for fila in _huella(doc):
                    if fila.startswith("TABLA|"):
                        celdas = fila[len("TABLA|"):].split("¬")
                        self.assertNotIn("Baja", celdas,
                                         f"la severidad baja no se reporta: {fila}")
                texto = "\n".join(p.text for p in doc.paragraphs)
                # Las cuatro bajas de julio no se cuentan en el total.
                esperado = sum(v for k, v in PLAN["2026-07"].items() if k != "Low")
                self.assertIn(str(esperado), texto)

    def test_el_titulo_el_destinatario_y_la_nota_salen_en_la_portada(self):
        sel = self._sel({"plantilla": "direccion", "mes": "2026-08",
                         "titulo": "Informe para la junta directiva",
                         "destinatario": "Junta directiva",
                         "nota": "Preparado para la reunión del 15 de septiembre."})
        doc = self._documento(sel)
        texto = "\n".join(p.text for p in doc.paragraphs)
        self.assertIn("INFORME PARA LA JUNTA DIRECTIVA", texto)
        self.assertIn("Destinatario: Junta directiva", texto)
        self.assertIn("Preparado para la reunión del 15 de septiembre.", texto)
        self.assertIn("PERIODO: AGOSTO DE 2026", texto)
        self.assertIn("Alcance: toda la organización", texto)

    def test_una_seleccion_con_un_solo_apartado_tambien_sale(self):
        sel = self._sel({"apartado": ["conclusiones"], "mes": "2026-08"})
        doc = self._documento(sel)
        self.assertEqual(_titulos(doc), ["1. Conclusiones y recomendaciones"])

    def test_un_periodo_sin_datos_genera_un_documento_que_lo_dice(self):
        """La vista no deja llegar aquí, pero el generador no puede caerse."""
        sel = self._sel({"periodo": "intervalo", "desde": "2020-01-01", "hasta": "2020-01-31"})
        doc = self._documento(sel)
        texto = "\n".join(p.text for p in doc.paragraphs)
        self.assertIn("no se registraron", texto.lower())


# ==========================================================================
# 4. La página: permisos, alcance, auditoría y CSP
# ==========================================================================
class TestPagina(BaseConDatos):

    def _cliente(self, usuario: str):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": CLAVE})
        return cli

    def _csrf(self, cli) -> str:
        html = cli.get("/", follow_redirects=True).get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def _auditoria(self, accion: str) -> list[dict]:
        with db.session(self.ruta) as conn:
            return [dict(f) for f in conn.execute(
                "SELECT * FROM audit_log WHERE action=? ORDER BY id", (accion,))]

    def test_el_generador_se_pinta_con_sus_plantillas_y_su_vista_previa(self):
        admin = self._cliente("admin@ejemplo.local")
        r = admin.get("/informes/")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        for texto in ("Plantillas preconfiguradas", "Informe mensual completo",
                      "Resumen para dirección", "Informe técnico de remediación",
                      "Informe por proceso",
                      "Vulnerabilidades con explotación activa", "Informe de un activo",
                      "Qué informe quiere", "Vista previa y descarga",
                      "Copiar el enlace de este informe", "Meses disponibles",
                      "Generar y descargar"):
            self.assertIn(texto, html, texto)
        # La severidad baja no se ofrece en ninguna casilla.
        self.assertNotIn('value="Low"', html)
        self.assertNotIn("Severidad bajas", html)

    def test_la_pagina_cumple_la_csp_estricta_y_el_recorrido_va_en_orden(self):
        admin = self._cliente("admin@ejemplo.local")
        r = admin.get("/informes/")
        html = r.get_data(as_text=True)
        self.assertEqual(_atributos_peligrosos(html), [])
        self.assertIn("default-src 'none'", r.headers.get("Content-Security-Policy", ""))
        pasos = [int(n) for n in re.findall(r'data-tour="(\d+)"', html)]
        self.assertGreaterEqual(len(pasos), 4)
        self.assertEqual(pasos, sorted(pasos), f"el recorrido salta hacia atrás: {pasos}")
        self.assertEqual(len(pasos), len(set(pasos)))
        self.assertEqual(min(pasos), 1)

    def test_cada_plantilla_se_puede_abrir_por_su_enlace(self):
        admin = self._cliente("admin@ejemplo.local")
        for p in isel.PLANTILLAS:
            with self.subTest(plantilla=p.clave):
                r = admin.get(f"/informes/?plantilla={p.clave}")
                self.assertEqual(r.status_code, 200)
                html = r.get_data(as_text=True)
                self.assertIn("En uso", html)
                if p.exige:
                    # 2026-09-10: la razón por la que todavía no se puede generar se
                    # escribe junto al botón, que queda deshabilitado, en lugar de
                    # sustituir la vista previa por un aviso.
                    self.assertIn("No se puede generar todavía", html)
                    self.assertIn("Generar y descargar en Word", html)
                    self.assertRegex(html, r"<button[^>]*disabled[^>]*>Generar y descargar en Word")

    def test_el_enlace_copiable_reconstruye_la_seleccion(self):
        admin = self._cliente("admin@ejemplo.local")
        r = admin.get("/informes/?plantilla=direccion&mes=2026-08&sev=Critical"
                      "&titulo=Para+la+junta")
        html = r.get_data(as_text=True)
        # El valor viaja escapado en el HTML («&amp;»): el navegador lo desescapa al
        # leer el atributo, y aquí se hace lo mismo para seguir el enlace de verdad.
        enlace = unescape(re.search(r'id="enlace-informe" value="([^"]+)"', html).group(1))
        self.assertIn("plantilla=direccion", enlace)
        self.assertIn("sev=Critical", enlace)
        self.assertIn("titulo=Para", enlace)
        # Y ese enlace, seguido, devuelve la misma pantalla.
        ruta = enlace.split("/informes/", 1)[1]
        r2 = admin.get("/informes/" + ruta)
        self.assertEqual(r2.status_code, 200)
        self.assertIn("Para la junta", r2.get_data(as_text=True))

    def test_genera_descarga_docx_y_lo_deja_en_la_auditoria(self):
        admin = self._cliente("admin@ejemplo.local")
        csrf = self._csrf(admin)
        antes = len(self._auditoria(informes.ACCION_AUDITORIA_MEDIDA))
        ficheros_antes = (sorted(p.name for p in REPORTS_DIR.glob("*.docx"))
                          if REPORTS_DIR.exists() else [])
        r = admin.post("/informes/generar", data={
            "csrf": csrf, "plantilla": "direccion", "periodo": "mes", "mes": "2026-08",
            "alcance": "organizacion", "sev": ["Critical", "High"],
            "apartado": ["portada", "resumen_ejecutivo", "panorama", "conclusiones"],
            "titulo": "Resumen para dirección", "destinatario": "Gerencia",
            "nota": "Nota de prueba"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.mimetype, informes.MIME_DOCX)
        self.assertIn('filename="informe_direccion_2026-08.docx"',
                      r.headers.get("Content-Disposition", ""))
        self.assertTrue(r.data.startswith(b"PK"), "un .docx es un ZIP: empieza por PK")
        doc = Document(io.BytesIO(r.data))
        titulos = [p.text for p in doc.paragraphs if p.style.name == "Heading 1"]
        self.assertEqual(titulos, ["1. Resumen ejecutivo", "2. Panorama del periodo",
                                   "3. Conclusiones y recomendaciones"])
        # No queda copia en el servidor.
        ficheros_despues = (sorted(p.name for p in REPORTS_DIR.glob("*.docx"))
                            if REPORTS_DIR.exists() else [])
        self.assertEqual(ficheros_antes, ficheros_despues)
        # Auditoría con plantilla, periodo, alcance, severidades y apartados.
        filas = self._auditoria(informes.ACCION_AUDITORIA_MEDIDA)
        self.assertEqual(len(filas), antes + 1)
        ultima = filas[-1]
        self.assertEqual(ultima["username"], "admin@ejemplo.local")
        self.assertEqual(ultima["entity"], "informes")
        self.assertEqual(ultima["entity_id"], "direccion")
        for trozo in ("agosto de 2026", "toda la organización", "críticas, altas",
                      "resumen_ejecutivo", "informe_direccion_2026-08.docx"):
            self.assertIn(trozo, ultima["detail"], trozo)

    def test_la_plantilla_mensual_se_audita_como_informe_del_mes(self):
        """Cuando la selección es el informe mensual de siempre se genera por el mismo
        camino y se anota en el mes, que es lo que lee la tabla de meses."""
        admin = self._cliente("admin@ejemplo.local")
        csrf = self._csrf(admin)
        antes = len(self._auditoria(informes.ACCION_AUDITORIA))
        datos = {"csrf": csrf, "plantilla": "mensual", "periodo": "mes", "mes": "2026-07",
                 "alcance": "organizacion", "sev": list(isel.SEVERIDADES),
                 "apartado": list(isel.APARTADOS_MENSUAL)}
        r = admin.post("/informes/generar", data=datos)
        self.assertEqual(r.status_code, 200)
        self.assertIn('filename="informe_mensual_2026-07.docx"',
                      r.headers.get("Content-Disposition", ""))
        filas = self._auditoria(informes.ACCION_AUDITORIA)
        self.assertEqual(len(filas), antes + 1)
        self.assertEqual(filas[-1]["entity_id"], "2026-07")
        # Y el documento es el mensual completo, con su numeración histórica.
        doc = Document(io.BytesIO(r.data))
        titulos = [p.text for p in doc.paragraphs if p.style.name == "Heading 1"]
        self.assertIn("8. Nota metodológica", titulos)
        self.assertIn("Anexo A. Relación del resto de hallazgos", titulos)

    def test_sin_csrf_no_se_genera_nada(self):
        admin = self._cliente("admin@ejemplo.local")
        antes = len(self._auditoria(informes.ACCION_AUDITORIA_MEDIDA))
        r = admin.post("/informes/generar", data={"plantilla": "direccion"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(len(self._auditoria(informes.ACCION_AUDITORIA_MEDIDA)), antes)

    def test_el_perfil_de_solo_lectura_no_entra_ni_con_csrf(self):
        lectora = self._cliente("lectora@ejemplo.local")
        antes = len(self._auditoria(informes.ACCION_AUDITORIA_MEDIDA))
        self.assertEqual(lectora.get("/informes/").status_code, 403)
        csrf = self._csrf(lectora)
        r = lectora.post("/informes/generar", data={"csrf": csrf, "plantilla": "direccion"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(len(self._auditoria(informes.ACCION_AUDITORIA_MEDIDA)), antes)

    def test_una_seleccion_vacia_avisa_y_no_genera(self):
        admin = self._cliente("admin@ejemplo.local")
        csrf = self._csrf(admin)
        antes = len(self._auditoria(informes.ACCION_AUDITORIA_MEDIDA))
        # Vista previa: la página ya lo dice y no ofrece el botón.
        html = admin.get("/informes/?periodo=intervalo&desde=2020-01-01&hasta=2020-01-31"
                         "&apartado=portada&apartado=panorama").get_data(as_text=True)
        self.assertIn("no devuelve nada", html)
        # 2026-09-10: el botón sigue ahí pero DESHABILITADO y con la razón escrita al
        # lado, en vez de desaparecer: así se sabe por qué no se puede generar sin
        # tener que pulsarlo (petición del usuario del 2026-09-10).
        self.assertRegex(html, r"<button[^>]*disabled[^>]*>Generar y descargar en Word")
        self.assertIn("No se puede generar todavía", html)
        # Y el POST tampoco genera.
        r = admin.post("/informes/generar", data={
            "csrf": csrf, "plantilla": "direccion", "periodo": "intervalo",
            "desde": "2020-01-01", "hasta": "2020-01-31", "alcance": "organizacion",
            "sev": ["Critical"], "apartado": ["portada", "panorama"]},
            follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn("no devuelve ninguna vulnerabilidad", r.get_data(as_text=True))
        self.assertEqual(len(self._auditoria(informes.ACCION_AUDITORIA_MEDIDA)), antes)

    def test_falta_el_proceso_o_el_activo_y_se_dice_en_vez_de_generar(self):
        admin = self._cliente("admin@ejemplo.local")
        csrf = self._csrf(admin)
        r = admin.post("/informes/generar", data={
            "csrf": csrf, "plantilla": "proceso", "alcance": "proceso", "proceso": "",
            "periodo": "mes", "mes": "2026-08", "sev": ["Critical"],
            "apartado": ["portada", "activos"]}, follow_redirects=True)
        self.assertIn("Elija el proceso de negocio", r.get_data(as_text=True))

    def test_un_proceso_inventado_se_avisa_en_la_pantalla(self):
        admin = self._cliente("admin@ejemplo.local")
        html = admin.get("/informes/?alcance=proceso&proceso=Inventado").get_data(as_text=True)
        self.assertIn("no tiene vulnerabilidades", html)

    def test_un_perfil_acotado_no_puede_generar_fuera_de_su_alcance(self):
        """El perfil de Redes solo informa de servidores; pedir equipos de cómputo o un
        equipo concreto responde 404, igual que en el resto de la plataforma."""
        with mock.patch.object(auth, "ROLES_INFORMES", ("admin", "ciberseguridad", "redes")):
            redes = self._cliente("redes@ejemplo.local")
            self.assertEqual(redes.get("/informes/").status_code, 200)
            # Pedir el otro tipo de máquina: 404.
            self.assertEqual(
                redes.get("/informes/?alcance=tipo&tipo=equipos").status_code, 404)
            # Pedir un equipo de cómputo concreto: 404.
            self.assertEqual(
                redes.get(f"/informes/?alcance=activo&activo={self.ids['equipos']}"
                          ).status_code, 404)
            # Su propio tipo: 200.
            self.assertEqual(
                redes.get(f"/informes/?alcance=activo&activo={self.ids['servidores']}"
                          ).status_code, 200)
            # Y al generar «toda la organización» el documento habla solo de servidores.
            csrf = self._csrf(redes)
            r = redes.post("/informes/generar", data={
                "csrf": csrf, "plantilla": "remediacion", "periodo": "anio",
                "alcance": "organizacion", "sev": list(isel.SEVERIDADES),
                "apartado": ["portada", "activos", "remediacion"]})
            self.assertEqual(r.status_code, 200)
            doc = Document(io.BytesIO(r.data))
            filas = "\n".join(_huella(doc))
            self.assertIn("srv-informes-01", filas)
            self.assertNotIn("pc-informes-01", filas)
            # El POST con el tipo ajeno tampoco pasa.
            self.assertEqual(redes.post("/informes/generar", data={
                "csrf": csrf, "plantilla": "direccion", "alcance": "tipo",
                "tipo": "equipos", "periodo": "mes", "mes": "2026-08",
                "sev": ["Critical"], "apartado": ["portada"]}).status_code, 404)

    def test_la_pagina_avisa_cuando_la_generacion_va_a_tardar(self):
        """«Nunca dejes que la petición muera sin explicación»: con una selección grande
        la pantalla dice cuánto tarda antes de que se pulse el botón.

        2026-09-15: el aviso decía «puede tardar entre quince y cuarenta segundos» y la
        línea de la estimación, tres renglones más arriba, «unos 7 segundos»: dos cifras
        para lo mismo. Ahora el aviso escribe la MISMA estimación que la línea de arriba,
        así que la prueba comprueba las dos cosas: que el aviso aparece solo por encima
        del umbral y que la duración que dice es literalmente la calculada, no otra.
        """
        admin = self._cliente("admin@ejemplo.local")
        sin_aviso = admin.get("/informes/?plantilla=mensual&mes=2026-08").get_data(as_text=True)
        self.assertNotIn("la generación tarda", sin_aviso,
                         "con seis amenazas no hace falta avisar")
        with mock.patch.object(informes, "UMBRAL_AVISO_LENTO", 1):
            html = admin.get("/informes/?plantilla=mensual&mes=2026-08").get_data(as_text=True)
        self.assertIn("la generación tarda", html)
        self.assertIn("No cierre la página", html)
        # Una sola duración en la pantalla: la del aviso es la de la estimación de arriba.
        duracion = re.search(r"la generación tarda ([^,]+), la misma estimación", html)
        self.assertIsNotNone(duracion, "el aviso ya no cita la estimación de arriba")
        self.assertIn(f"y {duracion.group(1)}", html,
                      "la línea «Estimación: …» dice otra duración distinta")


if __name__ == "__main__":
    unittest.main()
