#!/usr/bin/env python3
"""Revisión de claridad del 2026-09-15: las cifras que antes se contradecían.

Cada prueba fija UNO de los defectos que la revisión encontró en el Panel, en la
consulta de Amenazas, en la ficha de una amenaza y en el inventario tecnológico. El
criterio es siempre el mismo: dos números de la misma magnitud en la misma pantalla —o
en dos pantallas que se leen seguidas— tienen que coincidir, y lo que no se puede hacer
coincidir tiene que estar explicado con su cifra.

La base es temporal bajo ``data/`` (patrón de tests/test_pagina_panel.py y
tests/test_usuarios.py). Nunca se toca ``data/threat_intel.db`` ni se sale a la red.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_claridad_operacion
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import db, queries, remediacion  # noqa: E402
from threatintel.paths import BASE_DIR  # noqa: E402
from webui.vistas import amenazas as vista_amenazas  # noqa: E402
from webui.vistas import panel as vista_panel  # noqa: E402
from webui.vistas import tecnologias as vista_tecnologias  # noqa: E402

ADMIN, CLAVE_ADMIN = "claridad.admin@ejemplo.local", "ClaridadSegura#2026"
LECTOR, CLAVE_LECTOR = "claridad.lector@ejemplo.local", "LectorSeguro#2026"

MES = "2026-09"
MES_ANTERIOR = "2026-08"

# Punto de referencia temporal para pruebas: posterior a los datos sembrados (2026-09-20)
# para que las ventanas de -30 a -60 días capturen esos datos.
AHORA_PRUEBA = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sembrar(ruta: str) -> None:
    """Un parque pequeño pero con todos los casos que la revisión encontró.

    * amenazas de las cuatro severidades en dos meses, para que la baja se pueda contar
      mal si alguna consulta se olvida de excluirla;
    * una tecnología con versiones instaladas de varias series (el caso «Microsoft
      Windows 6.0.25.33020») y otra con una sola serie;
    * vulnerabilidades confirmadas en `aplicabilidad` y una remediación abierta cuya
      fila de evaluación NO existe (el caso de las 122 de producción);
    * una amenaza con la descripción mal traducida y otra bien traducida.
    """
    from webui import auth as _auth
    ahora = datetime.now(timezone.utc)
    ts = _iso(ahora)

    with db.session(ruta) as conn:
        _auth.crear_usuario(conn, ADMIN, CLAVE_ADMIN, rol="admin", nombre="Claridad", actor="test")
        _auth.crear_usuario(conn, LECTOR, CLAVE_LECTOR, rol="ciberseguridad", nombre="Lectora", actor="test")
        conn.execute("UPDATE users SET must_change=0, tour_estado='completado'")
        db.set_setting(conn, "ignore_low_severity", "1")

        # ---------------------------------------------------------- tecnologías
        versiones_windows = [
            {"version": "6.0.25.33020", "activos": 1},
            {"version": "8.0.23.35609", "activos": 2},
            {"version": "10.0.19045", "activos": 12},
            {"version": "10.0.26200", "activos": 30},
            {"version": "48.100.4037", "activos": 1},
        ]
        versiones_linux = [
            {"version": "5.4.0-100.113", "activos": 4},
            {"version": "5.4.0-120.136", "activos": 6},
        ]
        conn.execute(
            """INSERT INTO technologies(id,slug,name,vendor,category,version_installed,
                   criticality,systems_count,exposure,enabled,created_at,updated_at,
                   activos_ocs,versiones_ocs,ocs_actualizado_at)
               VALUES(1,'windows','Microsoft Windows','Microsoft','sistema-operativo',
                      '6.0.25.33020','high',46,'interna',1,?,?,46,?,?)""",
            (ts, ts, json.dumps(versiones_windows), ts))
        conn.execute(
            """INSERT INTO technologies(id,slug,name,vendor,category,version_installed,
                   criticality,systems_count,exposure,enabled,created_at,updated_at,
                   activos_ocs,versiones_ocs,ocs_actualizado_at)
               VALUES(2,'linux','Linux','Canonical','sistema-operativo',
                      '5.4.0','critical',10,'interna',1,?,?,10,?,?)""",
            (ts, ts, json.dumps(versiones_linux), ts))
        conn.execute(
            """INSERT INTO technologies(id,slug,name,vendor,category,version_installed,
                   criticality,systems_count,exposure,enabled,created_at,updated_at)
               VALUES(3,'postgresql','PostgreSQL','PostgreSQL','base-de-datos',
                      '15.4','medium',2,'interna',1,?,?)""", (ts, ts))

        # ---------------------------------------------------------- activos
        for activo_id, origen, nombre in ((1, "servidores", "SRV-PD-01"),
                                          (2, "servidores", "SRV-PD-02"),
                                          (3, "equipos", "PC-0001")):
            conn.execute(
                """INSERT INTO activos(id,origen,ocs_id,nombre,so_nombre,so_familia,
                       zona,presente,primera_vez_at,visto_at,ultimo_inventario,
                       entorno,proceso,n_software)
                   VALUES(?,?,?,?,'Ubuntu 22.04','ubuntu','interna',1,?,?,?,
                          'produccion','Contabilidad',20)""",
                (activo_id, origen, activo_id, nombre, ts, ts, ts))

        # ---------------------------------------------------------- amenazas
        # Mes en curso: 4 críticas, 6 altas, 8 medias y 3 BAJAS. Mes anterior: 2+3+4+1.
        plan = {MES: [("Critical", 4), ("High", 6), ("Medium", 8), ("Low", 3)],
                MES_ANTERIOR: [("Critical", 2), ("High", 3), ("Medium", 4), ("Low", 1)]}
        tid = 0
        for mes, tramos in plan.items():
            anio, numero = (int(x) for x in mes.split("-"))
            for severidad, cuantas in tramos:
                for k in range(cuantas):
                    tid += 1
                    fecha = _iso(datetime(anio, numero, 1 + (k % 20), 9, 0, tzinfo=timezone.utc))
                    # Procedencia: dos tercios con CVSS oficial, el resto estimada.
                    origen = "nvd" if k % 3 != 2 else "heuristic"
                    conn.execute(
                        """INSERT INTO threats(id,fingerprint,cve,title_en,title_es,
                               summary_en,summary_es,severity,severity_source,cvss_score,
                               in_kev,first_seen_at,last_seen_at,month,relevance,estado)
                           VALUES(?,?,?,?,?,?,?,?,?,?,0,?,?,?,?, 'nueva')""",
                        (tid, f"fp-{tid}", f"CVE-2026-{1000 + tid}",
                         f"Threat {tid}", f"Amenaza {tid}",
                         "A use-after-free in the kernel allows a local attacker to fix it.",
                         "Un fijar el uso después de la compra en el núcleo permite a un "
                         "atacante local fijar el flujo." if tid == 1 else
                         "Una vulnerabilidad del núcleo permite a un atacante local elevar "
                         "privilegios.",
                         severidad, origen, 9.8 if severidad == "Critical" else 5.0,
                         fecha, fecha, mes, 50 + (tid % 40)))
                    # Correlación con Microsoft Windows para TODAS, incluidas las bajas:
                    # así la ficha de la tecnología puede contarlas mal si se descuida.
                    conn.execute(
                        """INSERT OR IGNORE INTO threat_technologies(threat_id,technology_id,
                               matched_alias,confidence,version_verdict)
                           VALUES(?,1,'windows',1.0,'unknown')""", (tid,))
        # Una amenaza del mes en curso toca DOS tecnologías: el reparto por tecnología
        # del Panel no puede sumar el total del mes.
        for amenaza in (1, 3, 5):
            conn.execute(
                """INSERT OR IGNORE INTO threat_technologies(threat_id,technology_id,
                       matched_alias,confidence,version_verdict)
                   VALUES(?,2,'linux',1.0,'affected')""", (amenaza,))
        # Y otra no toca ninguna: se borra su correlación.
        conn.execute("DELETE FROM threat_technologies WHERE threat_id=2")

        # ------------------------------------------------- vulnerabilidades reales
        # Tres pares (activo, CVE) confirmados, de severidad crítica y alta.
        confirmadas = [(1, 1, "CVE-2026-1001", "linux-image"),
                       (2, 1, "CVE-2026-1001", "linux-image"),
                       (1, 5, "CVE-2026-1005", "openssl")]
        for activo_id, threat_id, cve, paquete in confirmadas:
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id,threat_id,cve,paquete,
                       version_instalada,version_corregida,veredicto,motor,evaluado_at)
                   VALUES(?,?,?,?,'1.0','2.0','afectado','osv',?)""",
                (activo_id, threat_id, cve, paquete, ts))
            conn.execute(
                """INSERT INTO remediaciones(activo_id,threat_id,cve,paquete,
                       version_vulnerable,version_corregida,motor,estado,
                       detectado_at,comprobado_at)
                   VALUES(?,?,?,?,'1.0','2.0','osv','abierta',?,?)""",
                (activo_id, threat_id, cve, paquete, ts, ts))
        # Una vulnerabilidad de severidad BAJA confirmada: no cuenta en ninguna cifra.
        conn.execute(
            """INSERT INTO aplicabilidad(activo_id,threat_id,cve,paquete,version_instalada,
                   version_corregida,veredicto,motor,evaluado_at)
               VALUES(3,19,'CVE-2026-1019','curl','1.0','2.0','afectado','osv',?)""", (ts,))
        conn.execute(
            """INSERT INTO remediaciones(activo_id,threat_id,cve,paquete,version_vulnerable,
                   version_corregida,motor,estado,detectado_at,comprobado_at)
               VALUES(3,19,'CVE-2026-1019','curl','1.0','2.0','osv','abierta',?,?)""", (ts, ts))
        # LA HUÉRFANA: remediación abierta sin fila de evaluación que la confirme hoy.
        # Es el caso de las 122 de producción (CVE-2026-13608 en 122 activos).
        conn.execute(
            """INSERT INTO remediaciones(activo_id,threat_id,cve,paquete,version_vulnerable,
                   version_corregida,motor,estado,detectado_at,comprobado_at)
               VALUES(2,6,'CVE-2026-1006','curl','1.0','2.0','osv','abierta',?,?)""", (ts, ts))

        # Resumen de la evaluacion por amenaza: sin el, la ficha dice «todavia no
        # evaluada» y no pinta ni el desglose por sistema ni la tabla de activos.
        for threat_id, afectados in ((1, 2), (5, 1)):
            conn.execute(
                """INSERT INTO aplicabilidad_amenaza(threat_id,evaluado_at,afectados,
                       no_afectados,sin_dato,afectados_expuestos,parche_disponible,detalle)
                   VALUES(?,?,?,0,0,?,1,?)""",
                (threat_id, ts, afectados, afectados,
                 json.dumps({"lineas": ["Evaluada contra OSV.dev"], "incompleta": False})))

        conn.execute(
            """INSERT INTO executions(kind,started_at,finished_at,status,sources_ok,
                   sources_failed,threats_new,threats_alerted)
               VALUES('daily',?,?,'success',4,0,12,3)""",
            (_iso(ahora - timedelta(hours=2)), _iso(ahora - timedelta(hours=1))))


class _Base(unittest.TestCase):
    """Base temporal bajo data/ y aplicación en modo prueba, una sola vez."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "claridad.db")
        db.init_db(cls.ruta)
        _sembrar(cls.ruta)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)
        cls.conn = db.connect(cls.ruta)
        cls.cli = cls._sesion(ADMIN, CLAVE_ADMIN)
        cls.panel = cls.cli.get("/").get_data(as_text=True)
        cls.amenazas = cls.cli.get("/amenazas/").get_data(as_text=True)
        cls.tecnologia = cls.cli.get("/tecnologias/1").get_data(as_text=True)
        cls.inventario = cls.cli.get("/tecnologias/").get_data(as_text=True)
        cls.ficha = cls.cli.get("/amenazas/1").get_data(as_text=True)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    @classmethod
    def _sesion(cls, usuario: str, clave: str):
        cli = cls.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": clave})
        return cli

    @staticmethod
    def _texto(html: str) -> str:
        sin = re.sub(r"(?s)<(script|style).*?</\1>", " ", html)
        sin = re.sub(r"(?s)<!--.*?-->", " ", sin)
        sin = re.sub(r"<[^>]+>", " ", sin)
        for entidad, letra in (("&nbsp;", " "), ("&amp;", "&"), ("&laquo;", "«"),
                               ("&raquo;", "»"), ("&#34;", '"'), ("&#39;", "'")):
            sin = sin.replace(entidad, letra)
        return re.sub(r"\s+", " ", sin).strip()


# ==========================================================================
# 1. La severidad baja no se cuenta ni se enseña en /amenazas/
# ==========================================================================
class TestSeveridadBajaFueraDeLaLista(_Base):

    def test_buscar_sin_severidades_deja_fuera_la_baja(self):
        abiertas = [e for e in queries.ESTADOS if e not in queries.ESTADOS_CERRADOS]
        _, con = queries.buscar(self.conn, limite=1, estados=abiertas, excluir_bajas=True)
        _, sin = queries.buscar(self.conn, limite=1, estados=abiertas)
        bajas = self.conn.execute(
            "SELECT COUNT(*) FROM threats WHERE severity='Low' AND estado NOT IN "
            "('descartada','falso_positivo')").fetchone()[0]
        self.assertEqual(bajas, 4, "el sembrado tiene que traer amenazas de severidad baja")
        self.assertEqual(sin - con, bajas)

    def test_la_cabecera_y_la_tarjeta_dicen_el_mismo_numero(self):
        """El defecto original: 7.514 en la cabecera y 7.293 en la tarjeta."""
        texto = self._texto(self.amenazas)
        cabecera = re.search(r"([\d.]+) amenazas coinciden con el filtro actual", texto)
        tarjeta = re.search(r"([\d.]+) Amenazas registradas", texto)
        self.assertIsNotNone(cabecera, "no se encontró el recuento de la cabecera")
        self.assertIsNotNone(tarjeta, "no se encontró la tarjeta de amenazas registradas")
        self.assertEqual(cabecera.group(1), tarjeta.group(1))

    def test_ninguna_pagina_de_la_lista_ensena_la_insignia_baja(self):
        texto = self._texto(self.cli.get("/amenazas/?pagina=99999").get_data(as_text=True))
        self.assertNotIn(" Baja ", texto)
        self.assertNotIn("Amenaza 19", texto, "una amenaza de severidad baja está en la lista")

    def test_los_filtros_arrastran_el_ajuste_aunque_no_se_elija_severidad(self):
        with self.app.test_request_context("/amenazas/"):
            from flask import g
            g.cfg = {"ignore_low_severity": True}
            self.assertTrue(vista_amenazas._filtros()["excluir_bajas"])
            g.cfg = {"ignore_low_severity": False}
            self.assertFalse(vista_amenazas._filtros()["excluir_bajas"])

    def test_la_exportacion_csv_tampoco_lleva_la_baja(self):
        csv = self.cli.get("/amenazas/exportar.csv").get_data(as_text=True)
        self.assertNotIn("Low", csv)
        self.assertIn("Critical", csv)


# ==========================================================================
# 2 y 3. El Panel da UN solo total del mes y UN solo porcentaje
# ==========================================================================
class TestUnSoloTotalDelMes(_Base):

    def test_la_procedencia_suma_el_total_de_estadisticas_mes(self):
        """El defecto original: 1.622 en la barra de procedencia y 1.532 en la tarjeta."""
        procedencia = vista_panel._procedencia_severidad(self.conn, MES, excluir_bajas=True)
        stats = queries.estadisticas_mes(self.conn, MES, excluir_bajas=True)
        self.assertEqual(sum(procedencia.values()), stats["total"])
        con_bajas = vista_panel._procedencia_severidad(self.conn, MES, excluir_bajas=False)
        self.assertEqual(sum(con_bajas.values()) - sum(procedencia.values()), 3,
                         "el sembrado tiene tres bajas en el mes en curso")

    def test_el_porcentaje_de_cvss_oficial_es_el_mismo_en_los_dos_sitios(self):
        """El defecto original: 80 % en el flujo y 77 % en la barra de procedencia."""
        procedencia = vista_panel._procedencia_severidad(self.conn, MES, excluir_bajas=True)
        stats = queries.estadisticas_mes(self.conn, MES, excluir_bajas=True)
        de_la_barra = round(procedencia["nvd"] * 100.0 / sum(procedencia.values()), 1)
        self.assertEqual(de_la_barra, stats["pct_con_cvss_real"])
        self.assertEqual(procedencia["nvd"], stats["sev_nvd"])

    def test_la_pagina_no_ensena_dos_totales_distintos(self):
        texto = self._texto(self.panel)
        stats = queries.estadisticas_mes(self.conn, MES, excluir_bajas=True)
        self.assertIn(f"CVSS oficial (NVD) {stats['sev_nvd']}", texto)
        self.assertIn("Amenazas del periodo", texto)


# ==========================================================================
# 2 bis. La ficha de una tecnología: la tabla cuadra con la gráfica
# ==========================================================================
class TestFichaDeTecnologiaCuadra(_Base):

    def test_la_evolucion_deja_fuera_la_baja(self):
        filas = vista_tecnologias._evolucion_tecnologia(self.conn, 1, excluir_bajas=True)
        por_mes = {f["month"]: f for f in filas}
        self.assertEqual(por_mes[MES]["bajas"], 0)
        self.assertEqual(por_mes[MES]["total"],
                         por_mes[MES]["criticas"] + por_mes[MES]["altas"] + por_mes[MES]["medias"])
        con_bajas = {f["month"]: f for f in
                     vista_tecnologias._evolucion_tecnologia(self.conn, 1, excluir_bajas=False)}
        self.assertEqual(con_bajas[MES]["total"] - por_mes[MES]["total"], 3)

    def test_la_barra_mide_lo_mismo_que_la_fila_de_la_tabla(self):
        """El defecto original: la barra decía 726 y la fila 734."""
        filas = vista_tecnologias._evolucion_tecnologia(self.conn, 1, excluir_bajas=True)
        series = vista_tecnologias._series_evolucion(filas, sin_bajas=True)["series"]
        for i, fila in enumerate(filas):
            alto_barra = sum(s["valores"][i] for s in series)
            self.assertEqual(alto_barra, fila["total"],
                             f"la barra de {fila['month']} no mide lo que dice su fila")

    def test_la_tabla_ya_no_tiene_columna_de_bajas(self):
        """Era la única tabla de la plataforma que nombraba la severidad que no se reporta."""
        tabla = re.search(r"(?s)<h2>Amenazas por mes</h2>.*?</table>", self.tecnologia)
        self.assertIsNotNone(tabla, "no se encontró la tabla de amenazas por mes")
        encabezados = re.findall(r"<th[^>]*>(.*?)</th>", tabla.group(0), re.S)
        self.assertNotIn("Bajas", [self._texto(e) for e in encabezados])
        self.assertIn("Medias", [self._texto(e) for e in encabezados])


# ==========================================================================
# 4. Amenazas y Remediación no se desmienten
# ==========================================================================
class TestConciliacionConRemediacion(_Base):

    def test_lo_pendiente_es_lo_confirmado_mas_lo_que_no_se_puede_confirmar(self):
        cifras = queries.resumen_amenazas(self.conn, incluir_bajas=False)
        huerfanas = queries.vulnerabilidades_pendientes_sin_confirmar(self.conn)
        pendientes = remediacion.resumen(self.conn, solo_cifras=True)["vulnerabilidades_unicas"]
        self.assertEqual(huerfanas, 1, "el sembrado tiene una remediación sin evaluación")
        self.assertEqual(cifras["vulnerabilidades"] + huerfanas, pendientes)

    def test_ninguna_confirmada_se_queda_fuera_de_la_cola(self):
        """La otra mitad de la comprobación: confirmado ⊆ pendiente."""
        confirmadas = {tuple(r) for r in self.conn.execute(
            """SELECT DISTINCT ap.activo_id, ap.cve FROM aplicabilidad ap
                 JOIN activos a ON a.id=ap.activo_id
                 LEFT JOIN threats t ON t.id=ap.threat_id
                WHERE ap.veredicto='afectado' AND a.presente=1
                  AND (t.id IS NULL OR t.estado NOT IN ('descartada','falso_positivo','mitigada'))
                  AND (t.severity IS NULL OR t.severity <> 'Low')""")}
        pendientes = {tuple(r) for r in self.conn.execute(
            """SELECT DISTINCT r.activo_id, r.cve FROM remediaciones r
                WHERE r.estado='abierta' AND r.cve IS NOT NULL AND r.cve <> ''
                  AND NOT EXISTS (SELECT 1 FROM threats tb WHERE tb.id=r.threat_id
                                   AND tb.severity='Low')""")}
        self.assertTrue(confirmadas <= pendientes)

    def test_la_pagina_de_amenazas_explica_la_diferencia_con_su_cifra(self):
        texto = self._texto(self.amenazas)
        cifras = queries.resumen_amenazas(self.conn, incluir_bajas=False)
        huerfanas = queries.vulnerabilidades_pendientes_sin_confirmar(self.conn)
        self.assertIn("Por qué Remediación enseña", texto)
        self.assertIn(f"{cifras['vulnerabilidades'] + huerfanas} vulnerabilidades pendientes", texto)

    def test_el_panel_tambien_lo_explica(self):
        self.assertIn("Por qué Remediación enseña más vulnerabilidades",
                      self._texto(self.panel))

    def test_el_recorte_por_tipo_de_maquina_se_respeta(self):
        total = queries.vulnerabilidades_pendientes_sin_confirmar(self.conn)
        servidores = queries.vulnerabilidades_pendientes_sin_confirmar(
            self.conn, origen="servidores")
        equipos = queries.vulnerabilidades_pendientes_sin_confirmar(self.conn, origen="equipos")
        self.assertEqual(servidores + equipos, total)


# ==========================================================================
# 5. El reparto por tecnología dice por qué no suma
# ==========================================================================
class TestRepartoPorTecnologia(_Base):

    def test_el_reparto_no_suma_el_mes_y_la_pagina_lo_dice(self):
        stats = queries.estadisticas_mes(self.conn, MES, excluir_bajas=True)
        top = queries.top_tecnologias(self.conn, MES, 8, excluir_bajas=True)
        suma = sum(int(t["amenazas"] or 0) for t in top)
        self.assertNotEqual(suma, stats["total"], "el sembrado tiene que descuadrar a propósito")
        texto = self._texto(self.panel)
        self.assertIn("no suman", texto)
        self.assertIn("cuenta en las dos barras", texto)
        self.assertIn("no está en ninguna barra", texto)


# ==========================================================================
# 6, 9 y 18. Rótulos que dicen lo que cuentan, concordancia y ceros
# ==========================================================================
class TestRotulosYConcordancia(_Base):

    def test_las_tarjetas_de_la_tecnologia_hablan_de_amenazas(self):
        texto = self._texto(self.tecnologia)
        self.assertIn("Amenazas que afectan a la versión instalada", texto)
        self.assertIn("Amenazas descartadas por la versión instalada", texto)
        self.assertNotIn("Versión afectada", texto)
        self.assertNotIn("Versión no afectada", texto)

    def test_el_plural_de_version_no_lleva_tilde(self):
        self.assertNotIn("versiónes", self._texto(self.tecnologia))
        self.assertIn("versiones distintas", self._texto(self.tecnologia))

    def test_una_sola_critica_se_escribe_en_singular(self):
        texto = self._texto(self.inventario)
        criticas = self.conn.execute(
            "SELECT COUNT(*) FROM technologies WHERE criticality='critical'").fetchone()[0]
        self.assertEqual(criticas, 1, "el sembrado tiene una sola tecnología crítica")
        self.assertIn("1 crítica ·", texto)
        self.assertNotIn("1 críticas", texto)

    def test_la_columna_confirmadas_distingue_el_cero_del_sin_dato(self):
        texto = self._texto(self.panel)
        self.assertIn("sin dato", texto)
        self.assertIn("«Sin dato» no es un cero", texto)


# ==========================================================================
# 7. Jerga fuera de la pantalla
# ==========================================================================
class TestSinJerga(_Base):

    def test_el_panel_no_nombra_productos_ni_ficheros(self):
        texto = self._texto(self.panel)
        for palabra in ("Ollama", "llama3", "Zabbix", "/salud.json"):
            self.assertNotIn(palabra, texto, f"el Panel sigue nombrando «{palabra}»")

    def test_la_ficha_rotula_la_huella_interna_como_lo_que_es(self):
        texto = self._texto(self.ficha)
        self.assertIn("Huella interna de la plataforma", texto)
        self.assertIn("Solo para soporte técnico", texto)

    def test_el_inventario_explica_el_identificador_interno_y_el_cpe(self):
        texto = self._texto(self.inventario)
        self.assertIn("identificador interno", texto.lower())
        self.assertIn("Identificador estándar del producto", texto)
        self.assertIn("Common Platform Enumeration", self.inventario)


# ==========================================================================
# 8. Traducción automática poco fiable
# ==========================================================================
class TestTraduccionPocoFiable(_Base):

    def test_detecta_los_terminos_mal_vertidos(self):
        malos = vista_amenazas.terminos_mal_traducidos(
            "Un fijar el uso después de la compra permite escalar privilegios.",
            "A use-after-free allows privilege escalation.")
        self.assertIn("use-after-free", malos)

    def test_no_marca_un_texto_correcto(self):
        self.assertEqual(
            vista_amenazas.terminos_mal_traducidos(
                "Una vulnerabilidad de tipo use-after-free permite ejecutar código.",
                "A use-after-free allows code execution."), [])

    def test_no_marca_cuando_el_original_no_hablaba_de_eso(self):
        """«fijar la fecha» es español correcto si el inglés no decía «fix»."""
        self.assertEqual(
            vista_amenazas.terminos_mal_traducidos(
                "Conviene fijar la fecha de la revisión.",
                "The review date should be scheduled."), [])

    def test_la_ficha_avisa_y_ensena_el_original(self):
        texto = self._texto(self.ficha)
        self.assertIn("La traducción automática no es fiable en este texto", texto)
        self.assertIn("use-after-free", texto)
        self.assertIn("Ver la traducción automática al español", texto)

    def test_una_ficha_bien_traducida_no_lleva_el_aviso(self):
        texto = self._texto(self.cli.get("/amenazas/3").get_data(as_text=True))
        self.assertNotIn("La traducción automática no es fiable", texto)


# ==========================================================================
# 10. Una sola lista de categorías
# ==========================================================================
class TestCategoriasCoherentes(_Base):

    def test_el_formulario_ofrece_las_categorias_reales(self):
        reales = {r[0] for r in self.conn.execute(
            "SELECT DISTINCT category FROM technologies WHERE category IS NOT NULL "
            "AND category <> ''")}
        ofrecidas = set(vista_tecnologias.categorias_del_inventario(self.conn))
        self.assertEqual(ofrecidas, reales)

    def test_la_tabla_de_cobertura_usa_la_misma_lista(self):
        cobertura = {f["categoria"] for f in
                     vista_tecnologias._cobertura_por_categoria(self.conn)}
        self.assertEqual(cobertura, set(vista_tecnologias.categorias_del_inventario(self.conn)))

    def test_una_base_sin_tecnologias_sigue_ofreciendo_la_lista_de_respaldo(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            ruta = str(Path(tmp) / "vacia.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                self.assertEqual(vista_tecnologias.categorias_del_inventario(conn),
                                 list(vista_tecnologias.CATEGORIAS))


# ==========================================================================
# 11 y 12. Fechas en español y comparaciones honestas
# ==========================================================================
class TestFechasYComparaciones(_Base):

    def test_la_fecha_del_informe_va_en_letra(self):
        texto = self._texto(self.panel)
        self.assertNotRegex(texto, r"previsto el \d{2}/\d{2}/\d{4}")
        self.assertRegex(texto, r"previsto el \d{1,2} de [a-záéíóú]+ de \d{4}")

    def test_la_variacion_compara_dos_ventanas_iguales_y_lo_escribe(self):
        variaciones = vista_panel._variaciones_30_dias(self.conn)
        for clave, v in variaciones.items():
            self.assertEqual(v["dias"], vista_panel.VENTANA_TENDENCIA_DIAS, clave)
        texto = self._texto(self.panel)
        self.assertRegex(texto, r"en los últimos 30 días frente a [\d.]+ en los 30 anteriores")

    def test_la_variacion_tampoco_cuenta_la_severidad_baja(self):
        con = vista_panel._variaciones_30_dias(self.conn, ahora=AHORA_PRUEBA, excluir_bajas=True)
        sin = vista_panel._variaciones_30_dias(self.conn, ahora=AHORA_PRUEBA, excluir_bajas=False)
        self.assertLess(con["total"]["actual"] + con["total"]["anterior"],
                        sin["total"]["actual"] + sin["total"]["anterior"])

    def test_la_tarjeta_dice_cuantos_dias_lleva_el_mes(self):
        hoy = datetime.now(timezone.utc).date()
        dias = vista_panel._dias_del_mes(f"{hoy.year:04d}-{hoy.month:02d}", hoy)
        self.assertEqual(dias["transcurridos"], hoy.day)
        self.assertGreaterEqual(dias["totales"], 28)
        self.assertEqual(vista_panel._dias_del_mes("2026-02", datetime(2026, 9, 15).date()),
                         {"transcurridos": 28, "totales": 28})
        self.assertEqual(vista_panel._dias_del_mes(None, hoy), {"transcurridos": 0, "totales": 0})


# ==========================================================================
# 13. Un solo aviso, con sujeto
# ==========================================================================
class TestAvisoSinRepetir(_Base):

    def test_el_motivo_de_la_credencial_no_se_repite(self):
        salud = {"motivos": ["Caduca en 5 días. Conviene renovarla.", "2 fuentes caídas"]}
        cred = {"estado": "por_caducar", "mensaje": "Caduca en 5 días. Conviene renovarla."}
        self.assertEqual(vista_panel.motivos_sin_repetir(salud, cred), ["2 fuentes caídas"])

    def test_sin_aviso_propio_el_motivo_se_conserva(self):
        salud = {"motivos": ["la última ejecución falló"]}
        self.assertEqual(vista_panel.motivos_sin_repetir(salud, {"estado": "ok"}),
                         ["la última ejecución falló"])
        self.assertEqual(vista_panel.motivos_sin_repetir(None, None), [])

    def test_el_aviso_propio_dice_que_pasa_si_no_se_renueva(self):
        """El sujeto y la consecuencia («qué caduca y qué pasa si no se renueva»).

        La base de pruebas no tiene credencial de correo configurada, así que el aviso no
        se pinta: se comprueba sobre la plantilla, que es donde vive el texto.
        """
        plantilla = (BASE_DIR / "webui" / "templates" / "panel.html").read_text(encoding="utf-8")
        bloque = re.search(r"(?s)cred\.estado == 'por_caducar'.*?\{% endif %\}", plantilla)
        self.assertIsNotNone(bloque)
        self.assertIn("buzón de correo con el que la plataforma envía los avisos", bloque.group(0))
        self.assertIn("dejarán de salir el correo de alerta diario", bloque.group(0))


# ==========================================================================
# 14. El recorrido guiado promete lo que esa persona puede ver
# ==========================================================================
class TestRecorridoPorPerfil(_Base):

    @staticmethod
    def _enlaces_del_menu(html: str) -> list[str]:
        nav = re.search(r"(?s)<nav class=\"nav\".*?</nav>", html)
        return re.findall(r"<span>([^<]+)</span>", nav.group(0)) if nav else []

    def test_cada_perfil_ve_su_numero_de_secciones(self):
        admin = self._enlaces_del_menu(self.panel)
        lector = self._enlaces_del_menu(
            self._sesion(LECTOR, CLAVE_LECTOR).get("/").get_data(as_text=True))
        self.assertEqual(len(admin), 17, "el perfil de administración ve 17 secciones")
        self.assertEqual(len(lector), 9, "el perfil de consulta ve 9 secciones")
        self.assertTrue(set(lector) < set(admin))

    def test_el_menu_no_ofrece_nada_que_el_perfil_no_pueda_abrir(self):
        """El recorrido cuenta los enlaces pintados, así que basta con que no sobren."""
        cli = self._sesion(LECTOR, CLAVE_LECTOR)
        nav = re.search(r"(?s)<nav class=\"nav\".*?</nav>",
                        cli.get("/").get_data(as_text=True))
        for destino in re.findall(r"<a href=\"([^\"]+)\"", nav.group(0)):
            self.assertEqual(cli.get(destino).status_code, 200, destino)


# ==========================================================================
# 15. Tarjetas de una línea, con el detalle plegado
# ==========================================================================
class TestTarjetasCortas(_Base):

    def test_las_tarjetas_de_amenazas_caben_en_una_linea(self):
        rejilla = re.search(r'(?s)<div class="rejilla c4">(.*?)</div>\s*</div>\s*</div>',
                            self.amenazas)
        self.assertIsNotNone(rejilla)
        for nota in re.findall(r'<div class="nota">(.*?)</div>', rejilla.group(1), re.S):
            self.assertLessEqual(len(self._texto(nota)), 110, nota)

    def test_el_detalle_esta_en_un_desplegable(self):
        self.assertIn("Qué cuenta exactamente cada cifra", self.amenazas)
        self.assertIn("Qué cuenta exactamente cada cifra", self.panel)
        self.assertIn("<details", self.amenazas)

    def test_el_bloque_de_activos_del_panel_no_es_un_parrafo_de_nueve_lineas(self):
        sub = re.search(r'(?s)id="estado-activos".*?<span class="sub">(.*?)</span>', self.panel)
        self.assertIsNotNone(sub)
        self.assertLessEqual(len(self._texto(sub.group(1))), 180)


# ==========================================================================
# 16. La ficha de la amenaza, sin ruido
# ==========================================================================
class TestFichaSinRuido(_Base):

    def test_los_bloques_largos_se_ven_de_inmediato_sin_desplegar(self):
        """Decisión invertida el 2026-11-16 (petición del usuario): antes estos dos
        bloques venían plegados en un <details> porque eran muy largos; ahora se ven
        de inmediato -paginados de a 10- porque «no todos ven la opción de desplegar
        lista de manera rápida». El resumen plegado ya no existe."""
        self.assertNotIn("Ver la lista de", self.ficha)
        self.assertNotIn("Ver la tabla por sistema operativo", self.ficha)
        # El cuadro de activos afectados (AJAX, paginado de a 10) está en la página,
        # listo para cargarse sin que nadie tenga que desplegar nada.
        self.assertIn('id="grid-cuerpo-activos"', self.ficha)
        self.assertIn('id="tabla-por-sistema"', self.ficha)
        # Ningún <details> de la ficha viene abierto salvo el del estado ya marcado.
        abiertos = re.findall(r"<details[^>]*\bopen\b", self.ficha)
        self.assertEqual(abiertos, [], "un desplegable de la ficha viene abierto")

    def test_la_orden_de_comprobacion_no_esta_en_la_columna_de_la_accion(self):
        self.assertIn("Cómo verificarlo en la máquina", self.ficha)

    def test_el_bloque_de_falso_positivo_esta_plegado(self):
        self.assertIn("Si marca «Falso positivo»", self._texto(self.ficha))

    def test_los_rangos_por_confirmacion_de_git_no_se_pintan(self):
        legibles, ocultos = vista_amenazas.versiones_legibles(
            ["4a1b3c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b", "de 6.1 a 6.6.12", "9f0c12a"])
        self.assertEqual(legibles, ["de 6.1 a 6.6.12"])
        self.assertEqual(ocultos, 2)

    def test_el_depurado_conserva_el_resto_del_detalle(self):
        detalle = {"encontrado": True, "afectados": [
            {"fabricante": "Linux", "producto": "kernel",
             "versiones": ["4a1b3c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b", "6.6.12"]}]}
        salida = vista_amenazas._detalle_cve_legible(detalle)
        self.assertEqual(salida["afectados"][0]["versiones"], ["6.6.12"])
        self.assertEqual(salida["versiones_ocultas"], 1)
        self.assertEqual(salida["encontrado"], True)


# ==========================================================================
# 17. Todas las etiquetas del eje, y en español
# ==========================================================================
class TestEtiquetasDelEje(_Base):

    def test_el_mes_lleva_la_preposicion(self):
        self.assertEqual(vista_tecnologias._mes_corto("2026-03"), "marzo de 2026")
        self.assertEqual(vista_tecnologias._mes_corto("2026-03", corto=True), "marzo\nde 2026")

    def test_se_pintan_todas_las_barras_con_su_nombre(self):
        from webui import graficos
        meses = [vista_tecnologias._mes_corto(f"2026-{m:02d}", corto=True) for m in range(1, 11)]
        series = [{"clave": "critico", "nombre": "Críticas", "valores": [5] * 10},
                  {"clave": "alto", "nombre": "Altas", "valores": [40] * 10}]
        sin = str(graficos.barras_apiladas(meses, series, alto=300))
        con = str(graficos.barras_apiladas(meses, series, alto=300, etiquetas_todas=True))
        etiquetas_con = [re.sub(r"<[^>]+>", " ", t).strip()
                         for t in re.findall(r'<text class="eje"[^>]*>(.*?)</text>', con, re.S)]
        rotuladas = [e for e in etiquetas_con if "de 2026" in e]
        self.assertEqual(len(rotuladas), 10)
        self.assertLess(len(re.findall(r'<text class="eje"', sin)),
                        len(re.findall(r'<text class="eje"', con)))
        self.assertIn("rotate(-45", con)
        self.assertNotIn("style=", con)

    def test_la_ficha_de_la_tecnologia_las_pinta_todas(self):
        grafico = re.search(r'(?s)<figure class="grafico-envoltorio grafico-barras-apiladas">'
                            r'(?!.*?</figure>.*?Amenazas por mes).*?</figure>', self.tecnologia)
        meses = self.conn.execute(
            "SELECT COUNT(DISTINCT t.month) FROM threat_technologies tt "
            "JOIN threats t ON t.id=tt.threat_id WHERE tt.technology_id=1 "
            "AND t.severity <> 'Low'").fetchone()[0]
        etiquetas = re.findall(r"de 20\d\d", self.tecnologia)
        self.assertGreaterEqual(len(etiquetas), meses)


# ==========================================================================
# 18. Versiones que no encajan con el patrón del producto
# ==========================================================================
class TestVersionesAtipicas(_Base):

    def test_marca_las_series_minoritarias(self):
        reparto = vista_tecnologias.marcar_versiones_atipicas([
            {"version": "10.0.26200", "activos": 30},
            {"version": "10.0.19045", "activos": 12},
            {"version": "48.100.4037", "activos": 1},
        ])
        atipicas = [v["version"] for v in reparto["versiones"] if v["atipica"]]
        self.assertEqual(atipicas, ["48.100.4037"])
        self.assertIn("No encaja con el patrón", reparto["versiones"][2]["motivo"])
        self.assertEqual(reparto["serie_dominante"], "10")

    def test_no_marca_nada_cuando_todas_son_de_la_misma_serie(self):
        reparto = vista_tecnologias.marcar_versiones_atipicas([
            {"version": "5.4.0-100.113", "activos": 4},
            {"version": "5.4.0-120.136", "activos": 6},
        ])
        self.assertEqual(reparto["atipicas"], 0)
        self.assertFalse(reparto["dispersa"])
        self.assertEqual(vista_tecnologias.version_declarada_atipica("5.4.0", reparto), "")

    def test_avisa_cuando_conviven_muchas_series(self):
        reparto = vista_tecnologias.marcar_versiones_atipicas([
            {"version": "1.0", "activos": 16},
            {"version": "2.8.9", "activos": 4},
            {"version": "3.0.0", "activos": 5},
        ])
        self.assertTrue(reparto["dispersa"])
        motivo = vista_tecnologias.version_declarada_atipica("1.0", reparto)
        self.assertIn("MÁS ANTIGUA", motivo)

    def test_una_lista_vacia_no_rompe_nada(self):
        reparto = vista_tecnologias.marcar_versiones_atipicas([])
        self.assertEqual(reparto["versiones"], [])
        self.assertEqual(reparto["activos"], 0)
        self.assertFalse(reparto["dispersa"])
        self.assertEqual(vista_tecnologias.version_declarada_atipica("1.0", reparto), "")
        self.assertEqual(vista_tecnologias.marcar_versiones_atipicas(None)["atipicas"], 0)

    def test_la_ficha_lo_dice_en_ambar_con_su_explicacion(self):
        texto = self._texto(self.tecnologia)
        self.assertIn("no encaja con el patrón", texto)
        self.assertIn("versión instalada más antigua", texto)


# ==========================================================================
# Casos límite: base vacía y dos ejecuciones seguidas
# ==========================================================================
class TestCasosLimite(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "vacia.db")
        db.init_db(self.ruta)
        self.conn = db.connect(self.ruta)

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    def test_sin_datos_las_cifras_valen_cero_y_no_hay_excepciones(self):
        self.assertEqual(queries.vulnerabilidades_pendientes_sin_confirmar(self.conn), 0)
        self.assertEqual(vista_panel._procedencia_severidad(self.conn, "2026-09"),
                         {"nvd": 0, "vector": 0, "kev": 0, "heuristic": 0, "otros": 0})
        self.assertEqual(vista_tecnologias._evolucion_tecnologia(self.conn, 1), [])

    def test_dos_llamadas_seguidas_dan_el_mismo_numero(self):
        primera = queries.vulnerabilidades_pendientes_sin_confirmar(self.conn)
        segunda = queries.vulnerabilidades_pendientes_sin_confirmar(self.conn)
        self.assertEqual(primera, segunda)

    def test_una_pagina_vacia_se_dibuja_sin_datos(self):
        from webui import graficos
        self.assertEqual(str(graficos.barras_apiladas([], [], etiquetas_todas=True)),
                         str(graficos.VACIO))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestAvisoDeSaludConAccion(unittest.TestCase):
    """El aviso de la portada dice qué pasa y qué hacer (2026-09-15).

    Queja del usuario: «necesito que además este mensaje que me arroja al ingresar "El
    sistema funciona con incidencias · 44 de 44 fuentes activas operativas" sea más claro
    para saber qué hacer, porque no sé qué debo hacer para que todas funcionen y tampoco es
    detallado».

    Tres defectos en una línea: ponía al lado de la palabra «incidencias» las 44 fuentes que
    SÍ funcionaban, no decía qué caducaba, y no decía qué hacer ni adónde ir.
    """

    def _salud(self, **credencial):
        import tempfile
        from pathlib import Path
        from threatintel import db, health
        from threatintel.paths import BASE_DIR
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as carpeta:
            ruta = str(Path(carpeta) / "salud.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                if credencial:
                    conn.execute(
                        "INSERT INTO credentials_meta(key, rotated_at, last_verify_ok, updated_at) "
                        "VALUES('smtp_password', ?, 1, ?)",
                        (credencial["rotated_at"], db.utcnow()))
            with db.connect(ruta) as conn:
                return health.resumen_sistema(conn, cfg={"smtp_rotation_days": 30})

    def test_si_el_cron_deja_de_llamar_al_script_se_avisa_por_la_hora_no_por_el_estado(self):
        """`resumen_sistema` antes solo miraba si la ÚLTIMA fila de executions decía
        'failed'; si el cron se perdía (se borró la tarea, el servidor se reinició) nunca
        se escribía una fila nueva y la última seguía diciendo 'success' aunque llevara
        semanas sin volver a correr. Ahora se compara también contra el reloj."""
        import tempfile
        from pathlib import Path
        from threatintel import db, health
        from threatintel.paths import BASE_DIR
        from datetime import datetime, timedelta, timezone

        hace_3_dias = (datetime.now(timezone.utc) - timedelta(days=3)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as carpeta:
            ruta = str(Path(carpeta) / "salud.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                conn.execute(
                    "INSERT INTO executions(kind, started_at, finished_at, status) "
                    "VALUES('daily', ?, ?, 'success')", (hace_3_dias, hace_3_dias))
            with db.connect(ruta) as conn:
                salud = health.resumen_sistema(conn, cfg={"smtp_rotation_days": 30})

        self.assertEqual(salud["estado_global"], "critico")
        claves = [i["clave"] for i in salud["incidencias"]]
        self.assertIn("ejecucion_ausente", claves)

    def test_una_ejecucion_reciente_y_correcta_no_genera_incidencia_de_ausencia(self):
        import tempfile
        from pathlib import Path
        from threatintel import db, health
        from threatintel.paths import BASE_DIR
        from datetime import datetime, timezone

        ahora = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as carpeta:
            ruta = str(Path(carpeta) / "salud.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                conn.execute(
                    "INSERT INTO executions(kind, started_at, finished_at, status) "
                    "VALUES('daily', ?, ?, 'success')", (ahora, ahora))
            with db.connect(ruta) as conn:
                salud = health.resumen_sistema(conn, cfg={"smtp_rotation_days": 30})

        claves = [i["clave"] for i in salud["incidencias"]]
        self.assertNotIn("ejecucion_ausente", claves)

    def test_cada_incidencia_lleva_sujeto_consecuencia_y_accion(self):
        from datetime import datetime, timedelta, timezone
        hace = (datetime.now(timezone.utc) - timedelta(days=27)).strftime("%Y-%m-%dT%H:%M:%SZ")
        salud = self._salud(rotated_at=hace)
        incidencias = salud["incidencias"]
        self.assertTrue(incidencias, "una contraseña a punto de caducar es una incidencia")
        for inc in incidencias:
            with self.subTest(clave=inc["clave"]):
                self.assertGreater(len(inc["titulo"]), 25, "el título dice de qué se trata")
                self.assertTrue(inc["consecuencia"], "dice qué pasa si nadie hace nada")
                self.assertTrue(inc["accion"], "dice qué hacer")
                self.assertNotIn("Caduca en", inc["titulo"][:10],
                                 "el título no puede empezar sin sujeto")

    def test_el_titulo_dice_que_es_lo_que_caduca(self):
        from datetime import datetime, timedelta, timezone
        hace = (datetime.now(timezone.utc) - timedelta(days=27)).strftime("%Y-%m-%dT%H:%M:%SZ")
        titulo = self._salud(rotated_at=hace)["incidencias"][0]["titulo"]
        self.assertIn("contraseña del buzón", titulo)
        self.assertIn("caduca en", titulo)

    def test_sin_incidencias_no_se_habla_de_incidencias(self):
        salud = self._salud()
        self.assertEqual(salud["incidencias"], [])
        self.assertEqual(salud["estado_global"], "ok")

    def test_la_plantilla_no_pone_las_fuentes_buenas_junto_a_la_palabra_incidencias(self):
        from threatintel.paths import BASE_DIR
        plantilla = (BASE_DIR / "webui" / "templates" / "panel.html").read_text(encoding="utf-8")
        self.assertIn("El sistema funciona, pero hay algo que atender", plantilla)
        # La frase antigua solo puede quedar dentro del comentario que explica el cambio.
        visible = "\n".join(l for l in plantilla.splitlines()
                            if "Antes decía" not in l and "fuentes activas operativas" not in l)
        self.assertNotIn("El sistema funciona con incidencias", visible)
        self.assertIn("Qué hacer:", plantilla)
        self.assertIn("Lo demás funciona:", plantilla)

    def test_los_enlaces_de_las_incidencias_existen_de_verdad(self):
        """Un enlace inventado tumba la portada entera con un error 500.

        Pasó el 2026-09-15: la incidencia apuntaba a «credenciales.lista», que no existe
        (la ruta se llama «credenciales.panel»), y el panel dejó de cargarse para todo el
        mundo. La suite no lo detectó porque ninguna prueba pintaba el aviso con una
        incidencia dentro.
        """
        import tempfile
        from pathlib import Path
        from threatintel.paths import BASE_DIR
        from webui.app import crear_app
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as carpeta:
            app = crear_app(db_path=str(Path(carpeta) / "rutas.db"), testing=True)
            puntos = {str(r.endpoint) for r in app.url_map.iter_rules()}
        import inspect
        import re as _re
        from threatintel import health
        fuente = inspect.getsource(health.resumen_sistema)
        # Los enlaces de las incidencias son el penúltimo argumento de cada llamada.
        enlaces = set(_re.findall(r'"((?:credenciales|fuentes|sincronizaciones|activos|amenazas)\.[a-z_]+)"',
                                  fuente))
        self.assertTrue(enlaces, "la salud debe ofrecer adónde ir")
        for enlace in sorted(enlaces):
            with self.subTest(enlace=enlace):
                self.assertIn(enlace, puntos, "ese destino no existe en la plataforma")
