#!/usr/bin/env python3
"""El bloque «Estado de los activos (OCS Inventory)» del Panel y el del correo
dicen lo mismo (petición del usuario del 2026-09-06).

El correo de alerta abre con ese bloque y cuatro cifras; en la plataforma esas
cifras estaban repartidas y el bloque del Panel se llamaba «Activos de la
organización», así que el usuario no lo encontraba. Estas pruebas comprueban que:

* el Panel titula el bloque exactamente «Estado de los activos (OCS Inventory)»;
* muestra las mismas cuatro cifras, con la misma etiqueta y en el mismo orden que
  el correo (con vulnerabilidades confirmadas, en producción o contingencia, fuera
  de soporte, sin reportar) y con los mismos valores, calculados con la misma
  fuente (``ocs.resumen`` más ``expuestos_afectados``);
* cada cifra enlaza a la vista filtrada de ``/activos/`` que contiene justamente
  esos activos (se comprueba contra el CSV, que aplica el filtro en el servidor);
* la frase de totales coincide con la del correo;
* el paso del recorrido guiado sigue presente y con el nombre nuevo;
* la página cumple la CSP estricta (sin ``style=`` ni ``on*=``).

Sin red y sin correo real: ``notify.render_alert_email`` solo devuelve el HTML,
nunca envía. La base es temporal bajo ``data/``; nunca se toca
``data/threat_intel.db``.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_panel_activos
"""
from __future__ import annotations

import html as _html
import inspect
import re
import sys
import tempfile
import unittest
from typing import Optional
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatintel import config, db, notify, ocs  # noqa: E402
from threatintel.paths import BASE_DIR  # noqa: E402
from webui.vistas import panel as vista  # noqa: E402

USUARIO, CLAVE = "panel-activos", "PruebaSegura#2026"

TITULO = "Estado de los activos (OCS Inventory)"
#: Etiquetas y orden del RESUMEN SEMANAL (threatintel/emails/semanal.html). El bloque
#: salio del correo diario el 2026-09-07: son cifras de estado acumulado y aquel correo
#: habla de lo detectado hoy. «Sin reportar» ya no esta: es mantenimiento del inventario
#: y tiene su propio informe para Servicios Tecnologicos.
#: Las CINCO filas del bloque, en el mismo orden en el Panel y en el correo semanal.
#: La quinta es del 2026-09-10: los activos que no reportan estaban contados en las
#: cuatro primeras con un dato de hace más de 30 días y el bloque decía «las máquinas
#: que no reportan no están aquí», que era falso.
ETIQUETAS = ("Con al menos una vulnerabilidad confirmada", "En producción o contingencia",
             "Fuera de soporte y con vulnerabilidades",
             "Fuera de soporte, sin vulnerabilidades conocidas hoy",
             "Sin reportar: su dato es de hace más de 30 días")
#: Cierre del bloque en el Panel: acota el trozo a analizar.
FIN_BLOQUE = "Un activo cuenta como afectado"

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)
#: Una fila del bloque del semanal: titulo, equipos y vulnerabilidades.
#: La unidad de estas cuatro cifras pasó de «equipos» a «activos» el 2026-09-08:
#: mezclan servidores y equipos de cómputo, así que «equipos» a secas era ambiguo.
#: El grupo opcional de las vulnerabilidades NO puede cruzar a la fila siguiente: la
#: cuarta fila no tiene esa cifra (lleva «—») y, sin la anticipación negativa, se comía
#: la de la quinta y hacía desaparecer una fila entera del análisis (2026-09-10).
RE_SEMANAL = re.compile(
    r'background-color:#ffffff;">\s*<strong>([^<]+)</strong>.*?'
    r'font-size:18px;[^"]*">([\d.]+)</div>\s*<div[^>]*>activos</div>'
    r'(?:(?:(?!<strong>).)*?font-size:18px;[^"]*">([\d.]+)</div>\s*'
    r'<div[^>]*>vulnerabilidades</div>)?',
    re.S)
RE_PANEL = re.compile(
    r'<div class="valor fs-22-b"><a href="([^"]+)">([^<]+)</a>\s*'
    r'<span class="pequeno tenue">activos?</span></div>\s*'
    r'(?:<div class="pequeno">([\d.]+) <span class="tenue">vulnerabilidades</span></div>\s*)?'
    r'<div class="etiqueta">([^<]+)</div>')

#: Desde el 2026-09-10 (tarde) la cifra «En producción o contingencia» la calcula
#: ``ocs.resumen`` y NADIE la vuelve a escribir: ni el Panel, ni ``bin/ejecucion_diaria.py``,
#: ni ``bin/enviar_prueba.py``. Antes estaba copiada palabra por palabra en los tres, y
#: ninguna de las tres copias dejaba fuera la severidad baja ni el riesgo aceptado, así
#: que la misma pantalla mezclaba dos criterios. ``test_una_sola_fuente_de_la_cifra``
#: comprueba que la consulta no ha vuelto a aparecer en ningún sitio.
FRAGMENTO_CONSULTA_ANTIGUA = "a.entorno IN ('produccion','contingencia')"


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _numero(texto: str) -> int:
    """«1.234» (formato español) -> 1234."""
    return int(texto.strip().replace(".", "").replace(" ", ""))


def _sin_espacios(texto: str) -> str:
    return re.sub(r"\s+", " ", texto).strip()


def _sembrar(ruta: str) -> None:
    """Inventario pequeño pero con todos los casos límite de las cuatro cifras.

    Cinco activos presentes (tres servidores y dos equipos de cómputo) más uno que
    ya no está en OCS y una amenaza mitigada, que NO deben contarse:

    * srv-web-01: producción, afectado                -> con vulnerabilidades, expuesto
    * srv-db-01:  contingencia, afectado              -> con vulnerabilidades, expuesto
    * srv-des-01: desarrollo, afectado y sin soporte  -> con vulnerabilidades, fuera de soporte
    * pc-ana:     sin entorno, sin inventario 60 días -> fuera de soporte, sin reportar
    * pc-luis:    producción, afectado por una amenaza mitigada -> no cuenta
    * srv-viejo:  ausente de OCS (presente=0), afectado        -> no cuenta
    """
    ahora = datetime.now(timezone.utc)
    ts = _iso(ahora)
    viejo = _iso(ahora - timedelta(days=60))
    mes = ts[:7]
    with db.session(ruta) as conn:
        from webui import auth as _auth
        _auth.crear_usuario(conn, USUARIO, CLAVE, rol="admin", actor="test")

        conn.execute("""INSERT INTO technologies(id,slug,name,vendor,category,criticality,systems_count,
                        exposure,enabled,created_at,updated_at)
                        VALUES(1,'curl','curl','curl','biblioteca','high',0,'interna',1,?,?)""", (ts, ts))
        for tid, fp, cve, estado in ((1, "fp-abierta", "CVE-2026-0001", "nueva"),
                                     (2, "fp-mitigada", "CVE-2026-0002", "mitigada")):
            conn.execute("""INSERT INTO threats(id,fingerprint,cve,title_en,title_es,severity,severity_source,
                            first_seen_at,last_seen_at,month,relevance,estado)
                            VALUES(?,?,?,?,?, 'High','nvd',?,?,?,60.0,?)""",
                         (tid, fp, cve, f"Threat {tid}", f"Amenaza {tid}", ts, ts, mes, estado))

        activos = [
            (1, "servidores", "srv-web-01", "ubuntu", "produccion", ts, 1),
            (2, "servidores", "srv-db-01", "debian", "contingencia", ts, 1),
            (3, "servidores", "srv-des-01", "debian", "desarrollo", ts, 1),
            (4, "equipos", "pc-ana", "windows", None, viejo, 1),
            (5, "equipos", "pc-luis", "windows", "produccion", ts, 1),
            (6, "servidores", "srv-viejo", "debian", "produccion", ts, 0),
        ]
        for aid, origen, nombre, familia, entorno, inventario, presente in activos:
            conn.execute("""INSERT INTO activos(id,origen,ocs_id,device_id,nombre,so_nombre,so_version,
                            so_familia,entorno,ip,ultima_conexion,ultimo_inventario,n_software,presente,
                            primera_vez_at,visto_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (aid, origen, aid, f"DEV{aid}", nombre, f"Sistema {familia}", "1.0", familia,
                          entorno, f"10.1.1.{aid}", inventario, inventario, 2, presente, ts, ts))
        # software: dos instalaciones, una clasificada en el inventario de tecnologías
        conn.execute("INSERT INTO activo_software(activo_id,nombre,nombre_norm,version,technology_id) "
                     "VALUES(1,'curl','curl','7.81.0',1)")
        conn.execute("INSERT INTO activo_software(activo_id,nombre,nombre_norm,version,technology_id) "
                     "VALUES(1,'programa propio','programa propio','1.0',NULL)")
        # vulnerabilidades confirmadas (veredicto «afectado»)
        for aid, tid in ((1, 1), (2, 1), (3, 1), (5, 2), (6, 1)):
            conn.execute("""INSERT INTO aplicabilidad(activo_id,threat_id,cve,paquete,version_instalada,
                            version_corregida,veredicto,motor,evidencia,evaluado_at)
                            VALUES(?,?,?,'curl','7.81.0','7.82.0','afectado','osv','prueba',?)""",
                         (aid, tid, f"CVE-2026-{tid:04d}", ts))
        # hallazgos abiertos: dos sistemas fuera de soporte y uno resuelto (no cuenta)
        for aid in (3, 4):
            conn.execute("INSERT INTO hallazgos_activos(activo_id,tipo,clave,detalle,detectado_at) "
                         "VALUES(?,'fin_soporte','sistema','sin soporte desde 2024-01-01',?)", (aid, ts))
        conn.execute("INSERT INTO hallazgos_activos(activo_id,tipo,clave,detalle,detectado_at,resuelto_at) "
                     "VALUES(1,'fin_soporte','sistema','ya corregido',?,?)", (ts, ts))


def _resumen_del_correo(conn, cfg) -> dict:
    """``meta["resumen_activos"]`` tal como lo arma bin/ejecucion_diaria.py: hoy es
    ``ocs.resumen`` a secas, que ya trae ``expuestos_afectados``."""
    return ocs.resumen(conn, cfg=cfg)


def _cifras_correo(html_semanal: str) -> list[tuple[str, int, Optional[int]]]:
    """[(etiqueta, activos, vulnerabilidades)] del bloque del resumen semanal."""
    inicio = html_semanal.index(TITULO)
    trozo = html_semanal[inicio:]
    salida = []
    for etiqueta, equipos, vulns in RE_SEMANAL.findall(trozo):
        if etiqueta.strip() not in ETIQUETAS:
            continue
        salida.append((etiqueta.strip(), _numero(equipos),
                       _numero(vulns) if vulns else None))
    return salida


def _cifras_panel(html_panel: str) -> list[tuple[str, int, Optional[int], str]]:
    """[(etiqueta, activos, vulnerabilidades, enlace)] del bloque del Panel."""
    inicio = html_panel.index('id="estado-activos"')
    trozo = html_panel[inicio:html_panel.index(FIN_BLOQUE, inicio)]
    return [(etiqueta.strip(), _numero(valor),
             _numero(vulns) if vulns else None, _html.unescape(href))
            for href, valor, vulns, etiqueta in RE_PANEL.findall(trozo)]


class TestBloqueActivosDelPanel(unittest.TestCase):
    """Panel con inventario: mismas cifras que el correo y enlaces que las explican."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "panel_activos.db")
        db.init_db(cls.ruta)
        _sembrar(cls.ruta)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)
        cls.conn = db.connect(cls.ruta)
        # Misma configuración que usa la interfaz (g.cfg = config.load(g.db)).
        cls.cfg = config.load(cls.conn)
        cls.resumen = _resumen_del_correo(cls.conn, cls.cfg)
        cls.estado_activos = ocs.estado_activos(cls.conn, cfg=cls.cfg)
        # El bloque vive ahora en el resumen semanal, no en la alerta diaria.
        cls.correo = notify.entorno().get_template("semanal.html").render(
            desde=None, hasta=None, dias=7, seguimiento=[], seguimiento_total=0,
            informativo=[], omitidas=0, descartadas=[], descartadas_total=0,
            alertadas=[], alertadas_total=0, alertadas_omitidas=0, ids_incluidas=[],
            umbral_relevancia=50, min_confianza=0.6, horas_espera=24, maximo=40,
            url_interfaz="http://localhost:9090/amenazas/",
            url_activos="http://localhost:9090/activos/",
            estado_activos=cls.estado_activos, vacio=False)
        cls.alerta_diaria = notify.render_alert_email([], {
            "periodo": db.utcnow()[:7], "url_interfaz": "http://localhost:9090/amenazas/",
            "url_activos": "http://localhost:9090/activos/", "resumen_activos": cls.resumen})
        cls.cliente = cls.app.test_client()
        cls.cliente.post("/login", data={"usuario": USUARIO, "password": CLAVE})
        respuesta = cls.cliente.get("/")
        cls.estado = respuesta.status_code
        cls.html = respuesta.get_data(as_text=True)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    # ------------------------------------------------------------ el título
    def test_el_panel_titula_el_bloque_igual_que_el_correo(self):
        self.assertEqual(self.estado, 200)
        self.assertIn(f"<h2>{TITULO}</h2>", self.html)
        self.assertIn(TITULO, self.correo)
        # el nombre antiguo ya no aparece: el usuario buscaba el del correo
        self.assertNotIn("Los equipos reales", self.html)

    def test_el_bloque_ya_no_va_en_la_alerta_diaria(self):
        """Se movio al resumen semanal el 2026-09-07: la alerta diaria habla de HOY."""
        self.assertNotIn(TITULO, self.alerta_diaria)
        self.assertNotIn("Sin reportar", self.alerta_diaria,
                         "los activos que no reportan tienen su propio informe")

    def test_subtitulo_explica_que_es_ocs_inventory(self):
        for texto in ("OCS Inventory (Open Computers and Software Inventory)",
                      "inventario informático de la organización",
                      "resumen semanal"):
            self.assertIn(texto, self.html)

    def test_el_subtitulo_dice_que_cuenta_cada_cifra(self):
        """El usuario no podia saber si «772» eran activos o vulnerabilidades.

        El 2026-09-08 la unidad pasó de «equipos» a «activos (servidores y equipos de
        cómputo)»: «equipos» a secas es palabra prohibida por ambigua, y estas cuatro
        cifras mezclan los dos tipos de máquina, así que la unidad correcta es «activos».
        """
        for texto in ("activos", "vulnerabilidades",
                      "un CVE en un activo", "cuenta una sola vez",
                      "servidores y equipos de cómputo"):
            self.assertIn(texto, self.html)
        self.assertNotRegex(self.html, r"<span class=\"pequeno tenue\">equipos</span>")

    def test_recorrido_guiado_con_el_nombre_nuevo(self):
        self.assertRegex(self.html, r'<div class="panel" id="estado-activos" data-tour="11" '
                                    r'data-tour-titulo="Estado de los activos \(OCS Inventory\)" '
                                    r'data-tour-texto="[^"]{41,}"')
        pasos = re.findall(r'data-tour="(\d+)"[^>]*data-tour-titulo="([^"]+)"', self.html)
        self.assertGreaterEqual(len(pasos), 2)
        self.assertIn(TITULO, [titulo for _, titulo in pasos])

    # ---------------------------------------------------------- las cifras
    def test_cuatro_cifras_en_el_orden_del_correo(self):
        self.assertEqual([e for e, _, _ in _cifras_correo(self.correo)], list(ETIQUETAS))
        self.assertEqual([e for e, _, _, _ in _cifras_panel(self.html)], list(ETIQUETAS))

    def test_las_cifras_del_panel_son_las_del_correo(self):
        correo = _cifras_correo(self.correo)
        panel = [(etiqueta, equipos, vulns)
                 for etiqueta, equipos, vulns, _ in _cifras_panel(self.html)]
        self.assertEqual(panel, correo)

    def test_cada_cifra_dice_si_son_equipos_o_vulnerabilidades(self):
        """La ambigüedad que reportó el usuario: «400» sin decir de qué."""
        for html in (self.correo, self.html):
            trozo = html[html.index(TITULO):]
            self.assertIn("equipos", trozo)
            self.assertIn("vulnerabilidades", trozo)

    def test_los_valores_son_los_del_inventario_sembrado(self):
        """Semántica de cada cifra: equipos frente a vulnerabilidades individuales.

        Del inventario de prueba: srv-web-01, srv-db-01 y srv-des-01 tienen alguna
        vulnerabilidad confirmada; srv-web-01 y srv-db-01 están en producción o
        contingencia; srv-des-01 y pc-ana están fuera de soporte, y de esos dos solo
        srv-des-01 arrastra vulnerabilidades."""
        cifras = {e: (eq, vu) for e, eq, vu in _cifras_correo(self.correo)}
        self.assertEqual(cifras["Con al menos una vulnerabilidad confirmada"][0], 3)
        self.assertEqual(cifras["En producción o contingencia"][0], 2)
        self.assertEqual(cifras["Fuera de soporte y con vulnerabilidades"][0], 1)
        self.assertEqual(cifras["Fuera de soporte, sin vulnerabilidades conocidas hoy"][0], 1)
        # las vulnerabilidades son al menos tantas como los equipos afectados
        equipos, vulns = cifras["Con al menos una vulnerabilidad confirmada"]
        self.assertIsNotNone(vulns)
        self.assertGreaterEqual(vulns, equipos)

    def test_una_sola_fuente_de_la_cifra(self):
        """«En producción o contingencia» sale solo de ``ocs.resumen``.

        Ni el Panel ni los dos guiones del correo la vuelven a calcular: la consulta
        antigua no debe reaparecer en ninguno de los tres, porque cada copia era una
        oportunidad de que un criterio (la severidad baja, el riesgo aceptado) se aplicara
        en dos sitios y no en el tercero.
        """
        for ruta in (BASE_DIR / "bin" / "ejecucion_diaria.py",
                     BASE_DIR / "bin" / "enviar_prueba.py",
                     BASE_DIR / "webui" / "vistas" / "panel.py"):
            texto = ruta.read_text(encoding="utf-8")
            self.assertNotIn(FRAGMENTO_CONSULTA_ANTIGUA, texto,
                             f"{ruta.name} vuelve a calcular la cifra por su cuenta")
        self.assertIn("expuestos_afectados",
                      (BASE_DIR / "threatintel" / "ocs.py").read_text(encoding="utf-8"),
                      "la cifra la tiene que calcular ocs.resumen")
        self.assertEqual(vista._expuestos_afectados(self.conn, cfg=self.cfg),
                         self.resumen["expuestos_afectados"])

    def test_frase_de_totales_igual_que_en_el_correo(self):
        frase = "5 activos (3 servidores y 2 equipos de cómputo)"
        self.assertIn("5 activos", self.correo,
                      "el semanal nombra el total del parque")
        self.assertIn(frase, self.html)
        self.assertIn(FIN_BLOQUE, self.html)
        # porcentaje de software clasificado, en formato español (una instalación de dos)
        self.assertIn("50,0 % del software instalado está clasificado", self.html)

    # ---------------------------------------------------------- los enlaces
    def test_cada_cifra_enlaza_a_su_vista_de_activos(self):
        enlaces = {etiqueta: href for etiqueta, _, _, href in _cifras_panel(self.html)}
        self.assertEqual(enlaces["Con al menos una vulnerabilidad confirmada"],
                         "/activos/?vista=afectados")
        self.assertEqual(enlaces["En producción o contingencia"],
                         "/activos/?vista=afectados&entorno=produccion")
        # Las dos filas de fin de soporte llevan a la misma vista rápida: la lista no
        # separa «con vulnerabilidades» de «sin vulnerabilidades».
        self.assertEqual(enlaces["Fuera de soporte y con vulnerabilidades"],
                         "/activos/?vista=fuera_soporte")
        self.assertEqual(enlaces["Fuera de soporte, sin vulnerabilidades conocidas hoy"],
                         "/activos/?vista=fuera_soporte")
        self.assertNotIn("Sin reportar", enlaces,
                         "los activos que no reportan tienen su propio informe")
        for etiqueta, href in enlaces.items():
            with self.subTest(cifra=etiqueta):
                respuesta = self.cliente.get(href)
                self.assertEqual(respuesta.status_code, 200)
                pagina = respuesta.get_data(as_text=True)
                self.assertIn("Activos de la organización", pagina)
                vista_pedida = re.search(r"vista=(\w+)", href).group(1)
                # la vista rápida llega marcada como activa (el filtro se aplica en el navegador)
                self.assertRegex(pagina, r'data-vista="' + vista_pedida + r'" aria-pressed="true"')

    def test_el_enlace_de_cada_cifra_lista_exactamente_esos_activos(self):
        """El CSV aplica el mismo filtro en el servidor: cuenta filas y compara."""
        cifras = dict((etiqueta, valor) for etiqueta, valor, _, _ in _cifras_panel(self.html))
        self.assertEqual(self._filas_csv("vista=afectados"),
                         cifras["Con al menos una vulnerabilidad confirmada"])
        # Las dos filas de fin de soporte suman los equipos de esa vista rápida
        self.assertEqual(self._filas_csv("vista=fuera_soporte"),
                         cifras["Fuera de soporte y con vulnerabilidades"]
                         + cifras["Fuera de soporte, sin vulnerabilidades conocidas hoy"])
        # producción y contingencia se filtran por separado; juntas son la cifra del correo
        self.assertEqual(self._filas_csv("vista=afectados&entorno=produccion")
                         + self._filas_csv("vista=afectados&entorno=contingencia"),
                         cifras["En producción o contingencia"])

    def test_los_dos_entornos_expuestos_tienen_enlace(self):
        # Adaptado el 2026-09-15 (revisión de claridad): el detalle de cada cifra se
        # movió al desplegable «Qué cuenta exactamente cada cifra», que está dentro del
        # mismo bloque pero DESPUÉS de la frase que marcaba su final, así que el trozo se
        # toma hasta el cierre del desplegable.
        inicio = self.html.index('id="estado-activos"')
        fin = self.html.index("</details>", inicio) + len("</details>")
        trozo = self.html[inicio:fin]
        self.assertIn(FIN_BLOQUE, trozo)
        self.assertIn("La lista de activos filtra un entorno a la vez", trozo)
        for entorno, nombre in (("produccion", "producción"), ("contingencia", "contingencia")):
            enlace = f'<a href="/activos/?vista=afectados&amp;entorno={entorno}">{nombre}</a>'
            self.assertIn(enlace, trozo)
            respuesta = self.cliente.get(f"/activos/?vista=afectados&entorno={entorno}")
            self.assertEqual(respuesta.status_code, 200)
            self.assertIn(f'<option value="{entorno}" selected>', respuesta.get_data(as_text=True))

    def _filas_csv(self, consulta: str) -> int:
        respuesta = self.cliente.get(f"/activos/exportar.csv?{consulta}")
        self.assertEqual(respuesta.status_code, 200, consulta)
        lineas = respuesta.get_data(as_text=True).strip().splitlines()
        return max(len(lineas) - 1, 0)   # sin la fila de encabezados

    # ------------------------------------------------------------------ CSP
    def test_csp_estricta_en_el_panel(self):
        self.assertIsNone(RE_STYLE.search(self.html), "hay un atributo style=")
        self.assertIsNone(RE_ON.search(self.html), "hay un manejador on*=")
        self.assertNotRegex(self.html, r"<script(?![^>]*\bsrc=)[^>]*>")

    def test_el_bloque_no_depende_solo_del_color(self):
        """Cada cifra lleva su etiqueta escrita; el cero se pinta en gris (neutro)."""
        with self.app.test_request_context():
            cifras = vista._cifras_activos({
                "activos_presentes": 4, "activos_afectados": 0,
                "vulnerabilidades": 0, "expuestos_activos": 0,
                "expuestos_vulnerabilidades": 0,
                "fuera_soporte_con_vulnerabilidades": 7,
                "fuera_soporte_vulnerabilidades": 19,
                "fuera_soporte_sin_vulnerabilidades": 0,
                "dias_sin_reportar": 30, "sin_reportar_activos": 2,
                "sin_reportar_vulnerabilidades": 5, "sin_reportar_afectados": 2,
                "activos_afectados_con_dato": 0, "vulnerabilidades_con_dato": 0,
                "expuestos_activos_con_dato": 0,
                "expuestos_vulnerabilidades_con_dato": 0})
        self.assertEqual([c["color"] for c in cifras],
                         ["neutro", "neutro", "alto", "neutro", "medio"])
        self.assertEqual([c["etiqueta"] for c in cifras], list(ETIQUETAS))
        # la cuarta fila no lleva cifra de vulnerabilidades: no tendría sentido
        self.assertEqual([c["vulnerabilidades"] for c in cifras], [0, 0, 19, None, 5])
        self.assertEqual(vista._cifras_activos({"activos_presentes": 0}), [])
        self.assertEqual(vista._cifras_activos(None), [])


class TestPanelSinActivos(unittest.TestCase):
    """Sin inventario sincronizado el bloque explica qué hacer, sin cifras huérfanas."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "panel_vacio.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            from webui import auth as _auth
            _auth.crear_usuario(conn, USUARIO, CLAVE, rol="admin", actor="test")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)
        cliente = cls.app.test_client()
        cliente.post("/login", data={"usuario": USUARIO, "password": CLAVE})
        respuesta = cliente.get("/")
        cls.estado = respuesta.status_code
        cls.html = respuesta.get_data(as_text=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_estado_vacio_con_el_mismo_titulo(self):
        self.assertEqual(self.estado, 200)
        self.assertIn(f"<h2>{TITULO}</h2>", self.html)
        self.assertIn("Sin activos sincronizados.", self.html)
        self.assertNotIn("Con vulnerabilidades confirmadas", self.html)
        self.assertIsNone(RE_STYLE.search(self.html))
        self.assertIsNone(RE_ON.search(self.html))

    def test_el_correo_tampoco_pinta_el_bloque_sin_activos(self):
        correo = notify.render_alert_email([], {"periodo": db.utcnow()[:7], "resumen_activos": {}})
        self.assertNotIn(TITULO, correo)


if __name__ == "__main__":
    unittest.main(verbosity=2)
