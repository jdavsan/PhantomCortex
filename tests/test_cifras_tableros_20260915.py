#!/usr/bin/env python3
"""Auditoría de tableros del 2026-09-15: cada cifra que antes se contradecía.

La auditoría encontró trece pares de números que decían lo mismo con dos valores
distintos, casi siempre en la misma pantalla. Cada clase de esta suite fija UNO de esos
pares, con el mismo criterio del proyecto: dos cifras de la misma magnitud que se leen
juntas tienen que coincidir, y lo que no puede coincidir (un «top diez» que repite, la
suma de una columna que cuenta el mismo activo varias veces) tiene que estar escrito con
su número al lado.

Qué cubre, punto por punto de la auditoría:

1.  Panel · el paso «Correlación» toma la corrida que DE VERDAD recolectó.
2.  Ficha de tecnología · instalaciones, activos, versiones distintas y las que no
    declaran versión.
3.  Ficha de tecnología · tarjetas, dona y serie mensual con el mismo criterio.
4.  ``/tecnologias/`` · el pie no suma «Sistemas» ni «Amenazas».
5.  ``/tecnologias/`` · la columna «Amenazas» con el mismo criterio que la gráfica.
6.  ``queries.cve_recurrentes`` ya no nombra la severidad que no se reporta.
7.  ``/excepciones/`` · el selector dice lo mismo que la ficha del activo.
8.  Las leyendas de los «top N» declaran qué suman (``leyenda_nota``).
9.  ``/fuentes/`` · el catálogo cuenta las mismas amenazas que Amenazas.
10. Panel y ``/activos/software`` · el porcentaje de software clasificado, sin redondeo
    que mienta.
11. Panel · «amenazas con CVE», no «CVE».
12. Panel · rótulos de la leyenda de meses, de las dos corridas diarias y de las
    excluidas por el filtro.
13. Panel · «Confirmadas por versión de la tecnología».

La base es temporal bajo ``data/`` (patrón de tests/test_pagina_panel.py y
tests/test_claridad_operacion.py). Nunca se toca ``data/threat_intel.db`` ni se sale a
la red.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_cifras_tableros_20260915
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

from threatintel import db, ocs, queries  # noqa: E402
from threatintel.paths import BASE_DIR  # noqa: E402
from webui.graficos import fmt  # noqa: E402
from webui.vistas import fuentes as vista_fuentes  # noqa: E402
from webui.vistas import panel as vista_panel  # noqa: E402
from webui.vistas import tecnologias as vista_tec  # noqa: E402

ADMIN, CLAVE = "auditoria.tableros@ejemplo.local", "AuditoriaSegura#2026"
MES = "2026-09"
MES_ANTERIOR = "2026-08"

#: Tecnología con varias versiones instaladas y con una instalación que no declara
#: versión: es el caso de «Microsoft Windows» en producción (56 instalaciones en 50
#: activos y 29 sin versión declarada) reducido a cinco filas.
TEC_NAVEGADOR = 1
TEC_BASE_DATOS = 2


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sembrar(ruta: str) -> None:
    """Un parque pequeño con todos los casos de la auditoría.

    * amenazas de las cuatro severidades en dos meses, para que la que no se reporta se
      pueda contar mal si alguna consulta se olvida de excluirla;
    * un CVE recurrente de severidad alta, otro de la severidad que no se reporta y otro
      ya descartado por el equipo;
    * una tecnología con dos versiones instaladas, un activo con dos de ellas y una
      instalación sin versión declarada;
    * dos corridas diarias, la que recolecta y la que solo envía el correo;
    * vulnerabilidades confirmadas para el selector de excepciones, una de ellas de la
      severidad que no se reporta y otra de una amenaza descartada.
    """
    from webui import auth as _auth
    ahora = datetime.now(timezone.utc)
    ts = _iso(ahora)

    with db.session(ruta) as conn:
        _auth.crear_usuario(conn, ADMIN, CLAVE, rol="admin", nombre="Auditoría", actor="test")
        conn.execute("UPDATE users SET must_change=0, tour_estado='completado'")
        db.set_setting(conn, "ignore_low_severity", "1")

        # ------------------------------------------------------------- fuentes
        for sid, slug, nombre, categoria in ((1, "fuente-oficial", "Base oficial de vulnerabilidades", "database"),
                                             (2, "fuente-fabricante", "Avisos del fabricante", "vendor")):
            conn.execute(
                """INSERT INTO sources(id,slug,name,url,kind,category,priority,enabled,
                       timeout_s,created_at,updated_at)
                   VALUES(?,?,?,?,'rss',?,'high',1,30,?,?)""",
                (sid, slug, nombre, f"https://interno.invalid/{slug}", categoria, ts, ts))
            conn.execute(
                """INSERT INTO source_health(source_id,checked_at,ok,http_status,entries,
                       accepted,latency_ms,error) VALUES(?,?,1,200,5,3,120,NULL)""",
                (sid, ts))

        # ---------------------------------------------------------- tecnologías
        versiones_navegador = [{"version": "1.0", "activos": 1},
                               {"version": "2.0", "activos": 3}]
        conn.execute(
            """INSERT INTO technologies(id,slug,name,vendor,category,version_installed,
                   criticality,systems_count,exposure,enabled,created_at,updated_at,
                   activos_ocs,versiones_ocs,ocs_actualizado_at)
               VALUES(?,'navegador-corporativo','Navegador corporativo','Fabricante',
                      'navegador','1.0','high',3,'interna',1,?,?,3,?,?)""",
            (TEC_NAVEGADOR, ts, ts, json.dumps(versiones_navegador), ts))
        conn.execute(
            """INSERT INTO technologies(id,slug,name,vendor,category,version_installed,
                   criticality,systems_count,exposure,enabled,created_at,updated_at,
                   activos_ocs,versiones_ocs,ocs_actualizado_at)
               VALUES(?,'base-de-datos','Base de datos corporativa','Fabricante',
                      'base-de-datos','15.4','critical',2,'interna',1,?,?,2,?,?)""",
            (TEC_BASE_DATOS, ts, ts, json.dumps([{"version": "15.4", "activos": 2}]), ts))

        # --------------------------------------------------------------- activos
        for activo_id, origen, nombre in ((1, "servidores", "SRV-AUDITORIA-01"),
                                          (2, "servidores", "SRV-AUDITORIA-02"),
                                          (3, "equipos", "PC-AUDITORIA-01")):
            conn.execute(
                """INSERT INTO activos(id,origen,ocs_id,nombre,so_nombre,so_familia,zona,
                       presente,primera_vez_at,visto_at,ultimo_inventario,entorno,proceso,
                       n_software)
                   VALUES(?,?,?,?,'Ubuntu 22.04','ubuntu','interna',1,?,?,?,'produccion',
                          'Contabilidad',3)""",
                (activo_id, origen, activo_id, nombre, ts, ts, ts))

        # Software instalado: cinco instalaciones del navegador en tres activos; el
        # activo 1 tiene DOS versiones y el activo 2 una instalación sin versión.
        software = [(1, "navegador corporativo", "1.0", TEC_NAVEGADOR),
                    (1, "navegador corporativo complemento", "2.0", TEC_NAVEGADOR),
                    (2, "navegador corporativo", "2.0", TEC_NAVEGADOR),
                    (3, "navegador corporativo", "2.0", TEC_NAVEGADOR),
                    (2, "navegador corporativo servicio", "", TEC_NAVEGADOR),
                    (1, "base de datos corporativa", "15.4", TEC_BASE_DATOS),
                    (2, "base de datos corporativa", "15.4", TEC_BASE_DATOS),
                    (3, "programa sin clasificar", "1.0", None)]
        for activo_id, nombre, version, tec in software:
            conn.execute(
                """INSERT INTO activo_software(activo_id,nombre,nombre_norm,version,
                       fabricante,technology_id) VALUES(?,?,?,?,'Fabricante',?)""",
                (activo_id, nombre.title(), nombre, version, tec))

        # -------------------------------------------------------------- amenazas
        # (id, cve, severidad, mes, en_kev, estado, tecnología)
        amenazas = [
            (1, "CVE-2026-0001", "Critical", MES, 1, "nueva", TEC_NAVEGADOR),
            (2, "CVE-2026-0002", "High", MES, 0, "nueva", TEC_NAVEGADOR),
            (3, "CVE-2026-0003", "Medium", MES, 0, "nueva", TEC_NAVEGADOR),
            (4, "CVE-2026-0004", "Low", MES, 0, "nueva", TEC_NAVEGADOR),
            (5, "CVE-2026-0005", "High", MES, 0, "nueva", TEC_BASE_DATOS),
            (6, "CVE-2026-0006", "Low", MES, 0, "nueva", TEC_BASE_DATOS),
            (7, "CVE-2026-0007", "Critical", MES_ANTERIOR, 1, "nueva", TEC_NAVEGADOR),
            (8, "CVE-2026-0008", "Medium", MES_ANTERIOR, 0, "nueva", TEC_BASE_DATOS),
            # CVE recurrente de severidad alta: el que la tabla de Tendencias sí enseña.
            (9, "CVE-2026-0009", "High", MES_ANTERIOR, 0, "nueva", TEC_NAVEGADOR),
            (10, "CVE-2026-0009", "High", MES, 0, "nueva", TEC_NAVEGADOR),
            # CVE recurrente de la severidad que no se reporta: no puede salir.
            (11, "CVE-2026-0011", "Low", MES_ANTERIOR, 0, "nueva", None),
            (12, "CVE-2026-0011", "Low", MES, 0, "nueva", None),
            # CVE recurrente ya descartado por el equipo: tampoco.
            (13, "CVE-2026-0013", "High", MES_ANTERIOR, 0, "descartada", None),
            (14, "CVE-2026-0013", "High", MES, 0, "descartada", None),
            # Sin CVE: no cuenta en el bloque de enriquecimiento.
            (15, None, "Medium", MES, 0, "nueva", None),
        ]
        for tid, cve, severidad, mes, kev, estado, tec in amenazas:
            anio, numero = (int(x) for x in mes.split("-"))
            fecha = _iso(datetime(anio, numero, 5, 9, 0, tzinfo=timezone.utc))
            # Ninguna se ha alertado todavía: así el Panel las clasifica y se puede
            # comprobar el recuento de excluidas por el filtro.
            conn.execute(
                """INSERT INTO threats(id,fingerprint,cve,title_en,title_es,severity,
                       severity_source,cvss_score,in_kev,first_seen_at,last_seen_at,
                       times_seen,month,alerted_at,relevance,enriched_at,estado)
                   VALUES(?,?,?,?,?,?,'nvd',?,?,?,?,2,?,NULL,?,?,?)""",
                (tid, f"fp-{tid}", cve, f"Aviso {tid}", f"Aviso {tid} en español",
                 severidad, 9.1 if severidad == "Critical" else 5.0, kev, fecha, fecha,
                 mes, 40 + tid, fecha if cve else None, estado))
            if tec:
                conn.execute(
                    """INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,
                           confidence,version_verdict) VALUES(?,?,'alias',1.0,'unknown')""",
                    (tid, tec))
            # La fuente oficial cita todas; el fabricante, solo las del mes en curso.
            conn.execute(
                "INSERT INTO threat_sources(threat_id,source_id,url,seen_at) VALUES(?,1,?,?)",
                (tid, f"https://interno.invalid/aviso/{tid}", ts))
            if mes == MES:
                conn.execute(
                    "INSERT INTO threat_sources(threat_id,source_id,url,seen_at) VALUES(?,2,?,?)",
                    (tid, f"https://interno.invalid/fabricante/{tid}", ts))

        # Una amenaza con la versión confirmada como vulnerable: la columna
        # «Confirmadas por versión de la tecnología» del Panel.
        conn.execute("UPDATE threat_technologies SET version_verdict='affected' "
                     "WHERE threat_id=1 AND technology_id=?", (TEC_NAVEGADOR,))

        # ------------------------------------------------- vulnerabilidades del parque
        # El activo 1 tiene una confirmada que cuenta, una de la severidad que no se
        # reporta y una de una amenaza descartada: su ficha dice 1, y el selector de
        # excepciones tiene que decir 1 también.
        confirmadas = [(1, 1, "CVE-2026-0001", "navegador"),
                       (1, 4, "CVE-2026-0004", "navegador"),
                       (1, 14, "CVE-2026-0013", "navegador"),
                       (2, 5, "CVE-2026-0005", "base-de-datos"),
                       (2, 1, "CVE-2026-0001", "navegador")]
        for activo_id, threat_id, cve, paquete in confirmadas:
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id,threat_id,cve,paquete,
                       version_instalada,version_corregida,veredicto,motor,evaluado_at)
                   VALUES(?,?,?,?,'1.0','2.0','afectado','osv',?)""",
                (activo_id, threat_id, cve, paquete, ts))

        # ------------------------------------------------------------ ejecuciones
        # Las DOS corridas diarias: la de la mañana recolecta (7 amenazas nuevas) y la
        # de la tarde solo envía el correo (ninguna fuente, 4 alertadas).
        conn.execute(
            """INSERT INTO executions(kind,started_at,finished_at,status,sources_ok,
                   sources_failed,threats_new,threats_alerted)
               VALUES('daily',?,?,'success',2,0,7,0)""",
            (_iso(ahora - timedelta(hours=3)), _iso(ahora - timedelta(hours=2, minutes=40))))
        conn.execute(
            """INSERT INTO executions(kind,started_at,finished_at,status,sources_ok,
                   sources_failed,threats_new,threats_alerted)
               VALUES('daily',?,?,'success',0,0,0,4)""",
            (_iso(ahora - timedelta(hours=2)), _iso(ahora - timedelta(hours=1, minutes=55))))
        conn.execute(
            """INSERT INTO executions(kind,started_at,finished_at,status,sources_ok,
                   sources_failed,threats_new,threats_alerted)
               VALUES('monthly','2026-08-31T22:00:00Z','2026-08-31T22:03:00Z','success',0,0,0,0)""")


class _Base(unittest.TestCase):
    """Base temporal bajo data/ y aplicación en modo prueba, una sola vez."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "tableros.db")
        db.init_db(cls.ruta)
        _sembrar(cls.ruta)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)
        cls.conn = db.connect(cls.ruta)
        cls.cli = cls.app.test_client()
        cls.cli.post("/login", data={"usuario": ADMIN, "password": CLAVE})
        cls.panel = cls._pagina("/")
        cls.inventario = cls._pagina("/tecnologias/")
        cls.ficha_tec = cls._pagina(f"/tecnologias/{TEC_NAVEGADOR}")
        cls.fuentes = cls._pagina("/fuentes/")
        cls.excepciones = cls._pagina("/excepciones/")
        cls.software = cls._pagina("/activos/software")
        cls.activos = cls._pagina("/activos/")

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    @classmethod
    def _pagina(cls, url: str) -> str:
        resp = cls.cli.get(url)
        assert resp.status_code == 200, f"{url} respondió {resp.status_code}"
        return resp.get_data(as_text=True)

    @staticmethod
    def _texto(html: str) -> str:
        """El texto visible, sin etiquetas, comentarios ni espacios de sobra."""
        sin = re.sub(r"(?s)<(script|style).*?</\1>", " ", html)
        sin = re.sub(r"(?s)<!--.*?-->", " ", sin)
        sin = re.sub(r"<[^>]+>", " ", sin)
        for entidad, letra in (("&nbsp;", " "), ("&amp;", "&"), ("&laquo;", "«"),
                               ("&raquo;", "»"), ("&#34;", '"'), ("&#39;", "'")):
            sin = sin.replace(entidad, letra)
        return re.sub(r"\s+", " ", sin).strip()

    @staticmethod
    def _figura(html: str, tipo: str, indice: int = 0) -> str:
        figuras = re.findall(r'<figure class="grafico-envoltorio grafico-'
                             + re.escape(tipo) + r'">.*?</figure>', html, re.S)
        assert len(figuras) > indice, f"no hay figura {tipo} nº {indice}"
        return figuras[indice]

    @staticmethod
    def _leyenda(nombre: str, dentro: str) -> str:
        m = re.search(re.escape(nombre) + r" <b>([^<]+)</b>", dentro)
        return m.group(1) if m else ""


# ==========================================================================
# 1. El paso «Correlación» habla de la corrida que recolectó
# ==========================================================================
class TestCorrelacionTomaLaRecoleccion(_Base):

    def test_la_ultima_recoleccion_no_es_la_corrida_de_la_alerta(self):
        ultima = vista_panel._ultima_ejecucion(self.conn, "daily")
        recoleccion = vista_panel._ultima_recoleccion(self.conn)
        self.assertEqual(int(ultima["threats_new"] or 0), 0, "la más reciente es la alerta")
        self.assertEqual(int(ultima["sources_ok"] or 0), 0)
        self.assertEqual(int(recoleccion["threats_new"] or 0), 7)
        self.assertEqual(int(recoleccion["sources_ok"] or 0), 2)
        self.assertLess(recoleccion["started_at"], ultima["started_at"])

    def test_el_panel_escribe_las_amenazas_nuevas_de_esa_recoleccion(self):
        texto = self._texto(self.panel)
        self.assertIn("7 amenazas nuevas en la última recolección", texto)
        self.assertNotIn("0 amenazas nuevas en la última recolección", texto)

    def test_la_tabla_de_ejecuciones_dice_lo_mismo_que_el_paso(self):
        """El defecto original: el flujo decía 0 y la tabla de la misma página 261."""
        texto = self._texto(self.panel)
        self.assertIn("Recolección diaria Correcta 7", texto)
        self.assertIn("7 amenazas nuevas en la última recolección", texto)

    def test_sin_dato_de_fuentes_se_comporta_como_antes(self):
        """Una base cuyas corridas no traen ``sources_ok`` sigue dando la última."""
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE executions SET sources_ok=0 WHERE kind='daily'")
            fila = vista_panel._ultima_recoleccion(conn)
            conn.execute("UPDATE executions SET sources_ok=2 "
                         "WHERE kind='daily' AND threats_new=7")
        self.assertIsNotNone(fila)
        self.assertEqual(int(fila["threats_alerted"] or 0), 4, "devuelve la más reciente")


# ==========================================================================
# 2. La ficha de la tecnología: instalaciones, activos y versiones
# ==========================================================================
class TestInstalacionesDeLaTecnologia(_Base):

    def test_resumen_instalaciones_separa_activos_de_instalaciones(self):
        r = ocs.resumen_instalaciones(self.conn, TEC_NAVEGADOR)
        self.assertEqual(r["instalaciones"], 5)
        self.assertEqual(r["activos"], 3)
        self.assertEqual(r["con_version"], 4)
        self.assertEqual(r["sin_version"], 1)
        self.assertEqual(r["versiones"], 2)

    def test_la_cabecera_dice_activos_y_versiones_distintas(self):
        """El defecto original: «en 56 activos» con la tarjeta de al lado en 50."""
        texto = self._texto(self.ficha_tec)
        self.assertIn("en 3 activos, con 2 versiones distintas", texto)
        self.assertNotIn("en 4 activos", texto)

    def test_la_tarjeta_de_activos_y_la_cabecera_coinciden(self):
        texto = self._texto(self.ficha_tec)
        activos = self.conn.execute(
            "SELECT activos_ocs FROM technologies WHERE id=?", (TEC_NAVEGADOR,)).fetchone()[0]
        self.assertEqual(activos, 3)
        self.assertIn(f"en {activos} activos, con 2 versiones distintas", texto)
        self.assertIn("Activos con esta tecnología", texto)

    def test_la_columna_se_llama_instalaciones_y_no_activos(self):
        self.assertIn("Instalaciones (activo y versión)", self.ficha_tec)
        self.assertNotIn('<th class="num">Activos</th>', self.ficha_tec)

    def test_el_pie_declara_las_instalaciones_sin_version(self):
        """Las que desaparecían de la tabla sin que nada las mencionara."""
        texto = self._texto(self.ficha_tec)
        self.assertIn("4 instalaciones (activo y versión) en 3 activos", texto)
        self.assertIn("1 más sin versión declarada", texto)

    def test_los_porcentajes_del_reparto_usan_las_instalaciones(self):
        """1 de 4 es el 25 %, no el 33 % que salía con el denominador de activos."""
        tabla = re.search(r"Versiones instaladas según OCS Inventory.*?</table>",
                          self.ficha_tec, re.S).group(0)
        self.assertIn("1.0: 1 (25 %)", self._texto(tabla))
        self.assertIn("Otras versiones: 3 (75 %)", self._texto(tabla))

    def test_una_tecnologia_sin_software_no_rompe_la_ficha(self):
        vacia = ocs.resumen_instalaciones(self.conn, 999)
        self.assertEqual(vacia["instalaciones"], 0)
        self.assertEqual(vacia["versiones"], 0)


# ==========================================================================
# 3. La ficha de la tecnología cuenta las mismas amenazas en todas partes
# ==========================================================================
class TestFichaTecnologiaMismoCriterio(_Base):

    def test_las_tarjetas_la_dona_y_la_serie_dicen_lo_mismo(self):
        """El defecto original: 2.159 en las tarjetas y 2.142 en la gráfica."""
        con_bajas = self.conn.execute(
            "SELECT COUNT(*) FROM threat_technologies WHERE technology_id=?",
            (TEC_NAVEGADOR,)).fetchone()[0]
        sin_bajas = self.conn.execute(
            """SELECT COUNT(*) FROM threat_technologies tt JOIN threats t ON t.id=tt.threat_id
                WHERE tt.technology_id=? AND (t.severity IS NULL OR t.severity<>'Low')""",
            (TEC_NAVEGADOR,)).fetchone()[0]
        self.assertGreater(con_bajas, sin_bajas, "el sembrado tiene que descuadrar")
        evolucion = vista_tec._evolucion_tecnologia(self.conn, TEC_NAVEGADOR,
                                                   excluir_bajas=True)
        self.assertEqual(sum(e["total"] for e in evolucion), sin_bajas)
        dona = self._figura(self.ficha_tec, "dona", 0)
        suma_dona = sum(int(v.replace(".", "")) for _, v in
                        re.findall(r"</span>([^<]+?) <b>([^<]+)</b>", dona))
        self.assertEqual(suma_dona, sin_bajas)
        # Las tarjetas de arriba reparten esas mismas amenazas (afectadas, descartadas y
        # sin determinar) y la pregunta del panel las nombra con el mismo total.
        texto = self._texto(self.ficha_tec)
        self.assertIn(f"sus {fmt(sin_bajas)} amenazas afectan de verdad", texto)
        self.assertIn(f"de las {fmt(sin_bajas)} correlacionadas", texto)

    def test_la_tabla_de_amenazas_asociadas_no_nombra_la_severidad_que_no_se_reporta(self):
        tabla = re.search(r"<h2>Amenazas asociadas</h2>.*?</table>", self.ficha_tec, re.S)
        self.assertIsNotNone(tabla)
        self.assertNotIn(">Baja<", tabla.group(0))


# ==========================================================================
# 4 y 5. El inventario: el pie no suma y la columna usa el criterio de la gráfica
# ==========================================================================
class TestPieDelInventario(_Base):

    def test_el_pie_no_suma_sistemas_sino_activos_distintos(self):
        """El defecto original: «Sistemas 22.236» en un parque de 730 máquinas."""
        activos = self.conn.execute(
            """SELECT COUNT(*) FROM activos a WHERE a.presente=1
                 AND EXISTS (SELECT 1 FROM activo_software s
                              WHERE s.activo_id=a.id AND s.technology_id IS NOT NULL)"""
        ).fetchone()[0]
        suma_columna = self.conn.execute(
            "SELECT COALESCE(SUM(activos_ocs),0) FROM technologies").fetchone()[0]
        self.assertEqual(activos, 3)
        self.assertGreater(suma_columna, activos, "el sembrado tiene que repetir activos")
        # El último pie de la página es el de la tabla del inventario (el primero es el
        # de la tabla de cobertura por categoría).
        tfoot = re.findall(r"<tfoot>.*?</tfoot>", self.inventario, re.S)[-1]
        self.assertIn(f">{fmt(activos)}</a>", tfoot)
        self.assertNotIn(f">{fmt(suma_columna)}<", tfoot)
        self.assertIn("tienen instalada alguna de estas tecnologías", self._texto(self.inventario))

    def test_el_pie_dice_las_amenazas_distintas_y_la_suma_que_repite(self):
        """El defecto original: «Amenazas 8.363», más que el catálogo entero."""
        distintas = vista_tec._amenazas_distintas(self.conn, [TEC_NAVEGADOR, TEC_BASE_DATOS])
        suma = self.conn.execute(
            """SELECT COALESCE(SUM((SELECT COUNT(DISTINCT tt.threat_id)
                    FROM threat_technologies tt JOIN threats t2 ON t2.id=tt.threat_id
                   WHERE tt.technology_id=t.id
                     AND (t2.severity IS NULL OR t2.severity<>'Low'))),0)
                 FROM technologies t""").fetchone()[0]
        texto = self._texto(self.inventario)
        self.assertIn(f"{fmt(distintas)} amenazas distintas", texto)
        self.assertIn(f"la suma de la columna, {fmt(suma)}, repite", texto)

    def test_la_columna_amenazas_deja_fuera_la_severidad_que_no_se_reporta(self):
        """El defecto original: 2.159 en la tabla y 2.142 en la gráfica de al lado."""
        con_bajas = self.conn.execute(
            "SELECT COUNT(DISTINCT threat_id) FROM threat_technologies WHERE technology_id=?",
            (TEC_NAVEGADOR,)).fetchone()[0]
        sin_bajas = self.conn.execute(
            """SELECT COUNT(DISTINCT tt.threat_id) FROM threat_technologies tt
                 JOIN threats t ON t.id=tt.threat_id
                WHERE tt.technology_id=? AND (t.severity IS NULL OR t.severity<>'Low')""",
            (TEC_NAVEGADOR,)).fetchone()[0]
        self.assertEqual((con_bajas, sin_bajas), (7, 6))
        fila = re.search(r"<tr>(?:(?!</tr>).)*Navegador corporativo.*?</tr>",
                         self.inventario, re.S).group(0)
        self.assertIn(f'<td class="num">{fmt(sin_bajas)}</td>', fila)
        self.assertNotIn(f'<td class="num">{fmt(con_bajas)}</td>', fila)

    def test_el_grafico_y_la_tabla_cuentan_lo_mismo(self):
        top = vista_tec._top_tecnologias(self.conn, 10, excluir_bajas=True)
        por_nombre = {t["name"]: t for t in top}
        navegador = por_nombre["Navegador corporativo"]
        self.assertEqual(navegador["amenazas"],
                         navegador["criticas"] + navegador["altas"] + navegador["medias"],
                         "la barra apila exactamente las amenazas que dice la columna")
        con_bajas = vista_tec._top_tecnologias(self.conn, 10, excluir_bajas=False)
        self.assertGreater({t["name"]: t for t in con_bajas}["Navegador corporativo"]["amenazas"],
                           navegador["amenazas"])


# ==========================================================================
# 6. CVE recurrentes: sin la severidad que no se reporta ni las cerradas
# ==========================================================================
class TestCveRecurrentes(_Base):

    def test_por_omision_deja_fuera_la_severidad_que_no_se_reporta(self):
        todos = queries.cve_recurrentes(self.conn, 50, excluir_bajas=False)
        reportables = queries.cve_recurrentes(self.conn, 50)
        cves_todos = {r["cve"] for r in todos}
        cves = {r["cve"] for r in reportables}
        self.assertIn("CVE-2026-0009", cves, "el recurrente de severidad alta sí sale")
        self.assertIn("CVE-2026-0011", cves_todos)
        self.assertNotIn("CVE-2026-0011", cves, "la severidad que no se reporta, no")
        self.assertNotIn("CVE-2026-0013", cves, "una amenaza descartada, tampoco")
        self.assertEqual(len(todos) - len(reportables), 2)

    def test_ninguna_fila_escribe_el_nombre_de_esa_severidad(self):
        """Era la única fila de toda la plataforma que lo escribía."""
        self.assertFalse([r for r in queries.cve_recurrentes(self.conn, 50)
                          if r["severidad"] == "Low"])

    def test_quien_la_llama_no_tiene_que_cambiar_nada(self):
        """El valor por omisión es el criterio del resto de la plataforma."""
        import inspect
        firma = inspect.signature(queries.cve_recurrentes)
        self.assertIs(firma.parameters["excluir_bajas"].default, True)


# ==========================================================================
# 7. El selector de excepciones dice lo mismo que la ficha del activo
# ==========================================================================
class TestSelectorDeExcepciones(_Base):

    def _cifra_de_la_ficha(self, activo_id: int) -> int:
        return self.conn.execute(
            """SELECT COUNT(DISTINCT ap.cve) FROM aplicabilidad ap
                 LEFT JOIN threats t ON t.id=ap.threat_id
                WHERE ap.activo_id=? AND ap.veredicto='afectado'
                  AND (t.id IS NULL OR t.estado NOT IN ('descartada','falso_positivo','mitigada'))
                  AND (t.severity IS NULL OR t.severity<>'Low')""", (activo_id,)).fetchone()[0]

    def test_cada_activo_del_selector_dice_la_cifra_de_su_ficha(self):
        """El defecto original: 348 de 652 activos con dos números distintos."""
        from flask import g
        with self.app.test_request_context("/excepciones/"):
            from threatintel import config
            from webui.vistas import excepciones as vista_exc
            # Conexión propia: al cerrarse el contexto, la aplicación cierra ``g.db``.
            g.db = db.connect(self.ruta)
            g.cfg = config.load(g.db)
            seleccionados = vista_exc._activos_del_selector(None)
        self.assertTrue(seleccionados)
        for activo in seleccionados:
            self.assertEqual(activo["cves"], self._cifra_de_la_ficha(activo["id"]),
                             activo["nombre"])

    def test_el_activo_con_amenazas_descartadas_o_no_reportables_cuenta_solo_las_vivas(self):
        self.assertEqual(self._cifra_de_la_ficha(1), 1)
        texto = self._texto(self.excepciones)
        self.assertIn("SRV-AUDITORIA-01 · servidor · Contabilidad · 1 vulnerabilidad", texto)
        self.assertNotIn("SRV-AUDITORIA-01 · servidor · Contabilidad · 3 vulnerabilidades", texto)


# ==========================================================================
# 8. Las leyendas de los «top N» dicen qué suman
# ==========================================================================
class TestLeyendasConNota(_Base):

    def test_el_panel_explica_que_su_leyenda_suma_solo_las_barras(self):
        """El defecto original: «Críticas 156» en la leyenda y 118 en la tarjeta."""
        fig = self._figura(self.panel, "barras-horizontales", 0)
        self.assertIn('<p class="leyenda-nota pequeno tenue">', fig)
        self.assertIn("barras mostradas", fig)
        self.assertIn("cuenta en las dos", fig)

    def test_el_inventario_explica_que_su_leyenda_suma_solo_las_barras(self):
        fig = self._figura(self.inventario, "barras-horizontales", 0)
        self.assertIn("barras mostradas, no del inventario", fig)

    def test_las_fuentes_explican_la_suya_con_el_total_sin_repeticiones(self):
        fig = self._figura(self.fuentes, "barras-horizontales", 0)
        distintas = vista_fuentes._amenazas_distintas(self.conn)
        self.assertIn("barras mostradas, no del catálogo", fig)
        self.assertIn(f"{fmt(distintas)} amenazas distintas", fig)


# ==========================================================================
# 9. El catálogo de fuentes cuenta las mismas amenazas que Amenazas
# ==========================================================================
class TestFuentesMismoCriterio(_Base):

    def test_el_pie_del_catalogo_coincide_con_el_total_de_amenazas(self):
        """El defecto original: 7.514 aquí y 7.284 en Amenazas y Tendencias."""
        reportables = self.conn.execute(
            """SELECT COUNT(*) FROM threats
                WHERE (severity IS NULL OR severity<>'Low')
                  AND estado NOT IN ('descartada','falso_positivo')""").fetchone()[0]
        distintas = vista_fuentes._amenazas_distintas(self.conn)
        con_bajas = vista_fuentes._amenazas_distintas(self.conn, excluir_bajas=False)
        self.assertGreater(con_bajas, distintas, "el sembrado tiene que descuadrar")
        # Todas las amenazas del sembrado tienen procedencia registrada, así que el pie
        # del catálogo es exactamente el total de las que se reportan más las cerradas,
        # que no son cosa de esta página.
        cerradas = self.conn.execute(
            """SELECT COUNT(*) FROM threats WHERE estado IN ('descartada','falso_positivo')
                 AND (severity IS NULL OR severity<>'Low')""").fetchone()[0]
        self.assertEqual(distintas, reportables + cerradas)
        self.assertIn(f">{fmt(distintas)} distintas</td>", self.fuentes)

    def test_la_columna_por_fuente_usa_el_mismo_criterio(self):
        aportacion = vista_fuentes._aportacion_por_fuente(self.conn)
        con_bajas = vista_fuentes._aportacion_por_fuente(self.conn, excluir_bajas=False)
        self.assertLess(aportacion[1], con_bajas[1])
        for sid, n in aportacion.items():
            self.assertIn(f'<td class="num">{fmt(n)}</td>', self.fuentes, f"fuente {sid}")

    def test_el_grafico_de_las_que_mas_aportan_tambien(self):
        top = vista_fuentes._top_fuentes(self.conn, 10)
        aportacion = vista_fuentes._aportacion_por_fuente(self.conn)
        for fuente in top:
            self.assertEqual(fuente["amenazas"], aportacion[fuente["id"]], fuente["name"])


# ==========================================================================
# 10. El porcentaje de software clasificado, sin redondeo que mienta
# ==========================================================================
class TestPorcentajeDeSoftwareClasificado(_Base):

    def test_las_tres_pantallas_escriben_el_mismo_porcentaje(self):
        """El defecto original: «100,0 %» en el Panel y en Software, «99,99 %» en Activos."""
        resumen = ocs.resumen(self.conn, cfg=None)
        esperado = f"{fmt(resumen['pct_mapeado_valor'], resumen['pct_mapeado_decimales'])} %"
        self.assertEqual(resumen["instalaciones_sin_clasificar"], 1)
        self.assertNotEqual(esperado, "100 %")
        for nombre, html in (("panel", self.panel), ("software", self.software),
                             ("activos", self.activos)):
            self.assertIn(esperado, self._texto(html), nombre)

    def test_el_panel_dice_cuantas_instalaciones_quedan_sin_clasificar(self):
        self.assertIn("1 instalación sin clasificar", self._texto(self.panel))

    def test_solo_se_escribe_cien_por_cien_cuando_no_queda_ninguna(self):
        self.assertEqual(ocs.porcentaje_honesto(10, 10), (100.0, 0))
        self.assertEqual(ocs.porcentaje_honesto(9999, 10000), (99.99, 2))


# ==========================================================================
# 11. «Amenazas con CVE», no «CVE»
# ==========================================================================
class TestEnriquecimientoAmenazasConCve(_Base):

    def test_cuenta_amenazas_y_no_identificadores_distintos(self):
        enr = vista_panel._enriquecimiento(self.conn)
        con_cve = self.conn.execute(
            """SELECT COUNT(*) FROM threats WHERE cve IS NOT NULL
                 AND (severity IS NULL OR severity<>'Low')
                 AND estado NOT IN ('descartada','falso_positivo')""").fetchone()[0]
        distintos = self.conn.execute(
            "SELECT COUNT(DISTINCT cve) FROM threats WHERE cve IS NOT NULL").fetchone()[0]
        self.assertEqual(enr["con_cve"], con_cve)
        self.assertNotEqual(con_cve, distintos, "el sembrado repite un CVE en dos meses")
        self.assertIn(f"de {fmt(con_cve)} amenazas con CVE siguen sin consultar",
                      self._texto(self.panel))

    def test_sin_el_filtro_cuenta_todas_como_antes(self):
        todas = vista_panel._enriquecimiento(self.conn, excluir_bajas=False)
        reportables = vista_panel._enriquecimiento(self.conn)
        self.assertGreater(todas["con_cve"], reportables["con_cve"])

    def test_el_rotulo_ya_no_llama_cve_a_las_amenazas(self):
        texto = self._texto(self.panel)
        self.assertNotRegex(texto, r"\d+ CVE siguen sin consultar")


# ==========================================================================
# 12. Rótulos del Panel que confundían
# ==========================================================================
class TestRotulosDelPanel(_Base):

    def test_la_leyenda_de_la_evolucion_dice_cuantos_meses_suma(self):
        evolucion = queries.evolucion_mensual(self.conn, 6, excluir_bajas=True)
        texto = self._texto(self.panel)
        self.assertIn(f"suma de los {fmt(len(evolucion))} meses", texto)
        self.assertIn(f"{fmt(sum(e['total'] for e in evolucion))} amenazas en total", texto)

    def test_la_linea_del_catalogo_kev_no_parece_un_cuarto_grupo(self):
        fig = self._figura(self.panel, "barras-apiladas", 0)
        self.assertIn("Con explotación confirmada (ya contadas arriba)", fig)
        self.assertNotIn(">En KEV <b>", fig)
        self.assertIn("no se suma", self._texto(self.panel))

    def test_las_dos_corridas_diarias_se_llaman_distinto(self):
        """El defecto original: las dos se llamaban «Recolección diaria» y la de la
        alerta salía con «Fuentes 0», que se lee como un fallo."""
        texto = self._texto(self.panel)
        self.assertIn("Envío de la alerta diaria", texto)
        self.assertIn("Recolección diaria", texto)
        filas = vista_panel._etiquetar_ejecuciones(
            self.conn.execute("SELECT * FROM executions ORDER BY started_at DESC LIMIT 3"))
        self.assertEqual(filas[0]["tipo_es"], "Envío de la alerta diaria")
        self.assertFalse(filas[0]["consulta_fuentes"])
        self.assertEqual(filas[1]["tipo_es"], "Recolección diaria")
        self.assertTrue(filas[1]["consulta_fuentes"])
        self.assertIn("no consulta fuentes", self.panel)

    def test_una_fila_sin_dato_de_fuentes_se_sigue_llamando_recoleccion(self):
        filas = vista_panel._etiquetar_ejecuciones([{"kind": "daily", "status": "success"}])
        self.assertEqual(filas[0]["tipo_es"], "Recolección diaria")

    def test_las_excluidas_por_el_filtro_no_cuentan_la_severidad_que_no_se_reporta(self):
        """El defecto original: «1.409 excluidas» con 150 excluidas por severidad."""
        from threatintel import config
        cfg = config.load(self.conn)
        clasificacion = queries.clasificar_pendientes(self.conn, cfg=cfg, persistir=False)
        por_severidad = clasificacion["conteo"]["severidad_baja"]
        total = sum(clasificacion["conteo"].values())
        self.assertGreater(por_severidad, 0, "el sembrado tiene que traer alguna")
        texto = self._texto(self.panel)
        self.assertIn(f"{fmt(total - por_severidad)} excluidas por el filtro", texto)
        self.assertNotIn(f"{fmt(total)} excluidas por el filtro", texto)


# ==========================================================================
# 13. «Confirmadas por versión de la tecnología»
# ==========================================================================
class TestColumnaConfirmadas(_Base):

    def test_la_columna_dice_contra_que_se_confirma(self):
        self.assertIn("Confirmadas por versión de la tecnología", self.panel)
        texto = self._texto(self.panel)
        self.assertIn("No es lo mismo que las amenazas confirmadas en algún activo", texto)

    def test_el_pie_explica_la_diferencia_con_las_confirmadas_en_algun_activo(self):
        texto = self._texto(self.panel)
        self.assertIn("se comprueban máquina por máquina", texto)


# ==========================================================================
# Casos límite: base vacía y dos ejecuciones seguidas de la misma página
# ==========================================================================
class TestCasosLimite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "vacia.db")
        db.init_db(cls.ruta)
        from webui import auth as _auth
        with db.session(cls.ruta) as conn:
            _auth.crear_usuario(conn, ADMIN, CLAVE, rol="admin", actor="test")
            conn.execute("UPDATE users SET must_change=0, tour_estado='completado'")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)
        cls.conn = db.connect(cls.ruta)
        cls.cli = cls.app.test_client()
        cls.cli.post("/login", data={"usuario": ADMIN, "password": CLAVE})

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    def test_con_la_base_vacia_las_paginas_responden(self):
        for url in ("/", "/tecnologias/", "/fuentes/", "/excepciones/", "/activos/software"):
            with self.subTest(url=url):
                self.assertEqual(self.cli.get(url).status_code, 200)

    def test_consultas_sin_datos(self):
        self.assertIsNone(vista_panel._ultima_recoleccion(self.conn))
        self.assertEqual(queries.cve_recurrentes(self.conn, 10), [])
        self.assertEqual(vista_tec._amenazas_distintas(self.conn, []), 0)
        self.assertEqual(vista_tec._activos_con_estas_tecnologias(self.conn, [], todas=False), 0)
        self.assertEqual(vista_tec._activos_con_estas_tecnologias(self.conn, [], todas=True), 0)
        self.assertEqual(vista_fuentes._amenazas_distintas(self.conn), 0)
        self.assertEqual(ocs.resumen_instalaciones(self.conn, 1)["instalaciones"], 0)

    def test_dos_ejecuciones_seguidas_dan_el_mismo_html(self):
        """Ninguna de las cifras nuevas depende de un estado que se consuma."""
        for url in ("/tecnologias/", "/fuentes/"):
            with self.subTest(url=url):
                primera = self.cli.get(url).get_data(as_text=True)
                segunda = self.cli.get(url).get_data(as_text=True)
                quitar = lambda h: re.sub(r'data-csrf="[^"]*"', "", h)  # noqa: E731
                self.assertEqual(quitar(primera), quitar(segunda))


if __name__ == "__main__":
    unittest.main(verbosity=2)
