"""Correcciones de la revisión visual del 2026-09-09 (capturas en tema claro y oscuro).

La revisión con capturas rechazó el trabajo de ese día. Cada prueba de aquí fija una de
las correcciones, con la medida que la justifica:

1. BLOQUEANTE · Remediación contaba la severidad Baja y el resto de la plataforma no, así
   que la página de Activos mostraba «746 con vulnerabilidades confirmadas» arriba y «748
   activos con pendientes» más abajo sin explicar la diferencia. Medido sobre la base real
   el 2026-09-09: 62.985 filas pendientes y 42.830 vulnerabilidades por activo con la
   Baja; 59.404 y 41.594 sin ella; 3.581 filas, 1.236 vulnerabilidades y 8 CVE distintos
   son de severidad Baja, y 1 activo tiene pendientes SOLO de severidad Baja. La Baja NO
   se saca de la cola (es decisión del usuario y no está tomada): se añade el filtro de
   severidad, con «todas» por omisión, y las dos pantallas explican la diferencia con su
   cifra.
2. Cuatro cifras distintas bajo la palabra «vulnerabilidades» en la misma pantalla: cada
   una lleva ahora su unidad escrita («filas de remediación», «CVE distintos»).
3. La gráfica semanal sumaba 66.326 detecciones cuando la página decía 62.985, porque
   contaba las 3.341 filas de activos retirados de OCS Inventory.
4. El nombre de la fila fusionada no decía la versión en 121 de las 124 fusiones del
   núcleo de producción; ahora la dicen las 124 (111 por el nombre de un paquete y 13 por
   la versión instalada).
5. La columna «Vulnerabilidades» no decía su unidad en pantalla y la sublínea de filas
   solo aparecía en las filas fusionadas.
6. Un solo texto para el desplegable de paquetes en las tres plantillas que lo muestran.
7. Objetivos táctiles de 44 px (CLAUDE.md y reglas del proyecto, que prevalecen sobre los
   24 px de la habilidad ui-ux-pro-max) y foco visible en el desplegable.
8. El plan de remediación llamaba «grupos de remediación» a lo que el resto de la
   plataforma llama actualizaciones, y decía «1 · Activos por corregir».
9. Idioma: «equipo» a secas por una máquina, «nº» y «Nº», fechas ISO en títulos
   emergentes y el recorrido guiado de la ficha del activo, que saltaba hacia atrás.

Sin red: base temporal bajo ``data/`` y datos insertados a mano (se reutilizan los
ayudantes de ``test_remediacion_agrupada``).
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db, remediacion
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "tests"))
from webui import auth  # noqa: E402
import test_remediacion_agrupada as base  # noqa: E402

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)
CLAVE = base.CLAVE

PLANTILLAS = BASE_DIR / "webui" / "templates"
ESTILO = (BASE_DIR / "webui" / "static" / "estilo.css").read_text(encoding="utf-8")

#: Plantillas que esta revisión tocó y en las que «equipo» a secas ya no puede volver.
#: Se admiten «equipos de cómputo» y «equipo de cómputo», que son el nombre completo del
#: tipo de máquina, y nada más.
PLANTILLAS_REVISADAS = ("remediaciones.html", "_remediaciones_activo.html",
                        "_remediaciones_resumen.html", "remediacion.html",
                        "activo_detalle.html", "activos.html", "_windows_parches.html")

#: El texto único del desplegable de paquetes, en las tres plantillas que lo pintan.
TEXTO_DESPLEGABLE = "paquetes del mismo origen: una sola orden los actualiza"


# ==========================================================================
# 1. La severidad baja no cuenta en nada (reescrito el 2026-09-10)
#
# Hasta el 2026-09-09 esta clase fijaba lo contrario: que Remediación, por ser la cola de
# trabajo, contaba también la severidad baja y lo explicaba con cifras en pantalla. La
# orden del usuario del 2026-09-10 cierra esa discusión —«las amenazas y vulnerabilidades
# de severidad baja no se deben tener en cuenta en absolutamente nada»—, así que lo que se
# fija aquí es lo nuevo: la baja no está en ninguna cifra, en ninguna lista, en ningún
# CSV, y la pantalla no la nombra. El caso reversible (ajuste desactivado) y el resto de
# los sitios están en tests/test_severidad_baja.py.
# ==========================================================================
class TestSeveridadBajaEnLaCola(unittest.TestCase):
    """La severidad baja no cuenta ni en Remediación, que era el último sitio donde sí.

    El equipo de cómputo «PC-solo-bajas» reproduce en pequeño el caso de producción: su
    única remediación pendiente es de severidad baja, así que NO puede contar como activo
    con pendientes. El servidor «srv-sin-evaluar-01» reproduce el otro motivo por el que
    Remediación y «Con vulnerabilidades confirmadas» pueden discrepar, que no tiene nada
    que ver con la severidad: su fila de aplicabilidad ya no está (evaluación incompleta) y
    la remediación no se cierra por eso.
    """

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "revision_bajas.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            # Un servidor con una vulnerabilidad crítica, una alta y una baja del mismo
            # paquete. Las dos primeras llevan su fila de aplicabilidad («aviso»), así que
            # este activo SÍ cuenta en «Con vulnerabilidades confirmadas».
            cls.srv = base._activo(conn, "srv-mixto-01", ip="10.0.0.21")
            base._software(conn, cls.srv, "openssl", "3.0.1")
            for cve, severidad, corregida, aviso in (
                    ("CVE-2026-7001", "High", "3.0.5", "DSA-7001"),
                    ("CVE-2026-7002", "Critical", "3.0.6", "DSA-7002"),
                    ("CVE-2026-7003", "Low", "3.0.4", None)):
                t = base._amenaza(conn, cve, severity=severidad)
                base._remediacion(conn, cls.srv, t, cve, "openssl", "3.0.1", corregida,
                                  aviso=aviso)
            # Un equipo de cómputo cuya ÚNICA pendiente es de severidad baja: no cuenta
            # como activo con pendientes en ninguna cifra.
            cls.solo_baja = base._activo(conn, "PC-solo-bajas", origen="equipos",
                                         proceso=None, ip="10.1.1.55")
            base._software(conn, cls.solo_baja, "curl", "7.80.0")
            t = base._amenaza(conn, "CVE-2026-7004", severity="Low")
            base._remediacion(conn, cls.solo_baja, t, "CVE-2026-7004", "curl", "7.80.0",
                              "7.81.0")
            # Y un servidor con una pendiente alta cuya fila de aplicabilidad ya no está
            # (evaluación incompleta): la remediación no se cierra por eso, así que
            # Remediación lo cuenta y «Con vulnerabilidades confirmadas» no. Es el único
            # motivo de discrepancia que queda tras la orden del 2026-09-10 (en
            # producción, 601 activos con pendientes frente a 597 confirmados).
            cls.sin_evaluar = base._activo(conn, "srv-sin-evaluar-01", ip="10.0.0.22")
            base._software(conn, cls.sin_evaluar, "nginx", "1.20.0")
            t = base._amenaza(conn, "CVE-2026-7005", severity="High")
            base._remediacion(conn, cls.sin_evaluar, t, "CVE-2026-7005", "nginx",
                              "1.20.0", "1.20.2")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        self.conn = db.connect(self.ruta)
        self.addCleanup(self.conn.close)

    def _cliente(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        return cli

    def _html(self, url):
        r = self._cliente().get(url)
        self.assertEqual(r.status_code, 200, url)
        html = r.get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html), f"style= en {url}")
        self.assertIsNone(RE_ON.search(html), f"on*= en {url}")
        return html

    # ---------------------------------------------------------------- el módulo
    def test_el_resumen_no_cuenta_la_severidad_baja(self):
        res = remediacion.resumen(self.conn, dias=30)
        # Cinco filas pendientes en la tabla, tres en las cifras: las dos bajas no cuentan.
        self.assertEqual(int(self.conn.execute(
            "SELECT COUNT(*) FROM remediaciones WHERE estado='abierta'").fetchone()[0]), 5)
        self.assertEqual(res["abiertas"], 3)
        self.assertEqual(res["vulnerabilidades_unicas"], 3)
        self.assertEqual(res["cve_distintos"], 3)
        # El equipo de cómputo cuya única pendiente es baja NO cuenta como activo con
        # pendientes: quedan el servidor mixto y el que espera una evaluación nueva.
        self.assertEqual(res["activos_con_abiertas"], 2)
        self.assertEqual(res["servidores_con_abiertas"], 2)
        self.assertEqual(res["equipos_con_abiertas"], 0)
        self.assertTrue(res["sin_bajas"])

    def test_el_resumen_ya_no_devuelve_cifras_de_severidad_baja(self):
        """Las claves que servían para explicar la diferencia desaparecen: no hay
        diferencia que explicar, y una clave a cero se leería como «no hay bajas»."""
        res = remediacion.resumen(self.conn, dias=30)
        for clave in ("abiertas_bajas", "abiertas_sin_bajas", "vulnerabilidades_bajas",
                      "vulnerabilidades_sin_bajas", "cve_distintos_bajos",
                      "activos_con_abiertas_sin_bajas", "activos_solo_bajas"):
            self.assertNotIn(clave, res, f"la clave «{clave}» ya no debe existir")

    def test_el_filtro_de_severidad_no_ofrece_la_baja(self):
        self.assertEqual(remediacion.SEVERIDADES_FILTRO,
                         ("todas", "critical", "high", "medium"))
        for texto in remediacion.SEVERIDAD_FILTRO_ES.values():
            self.assertNotIn("baja", texto.lower(), f"«{texto}» nombra la severidad baja")
        # «todas» son las tres que se reportan; un valor antiguo guardado en un enlace
        # («low», «sin_bajas») no filtra nada y NO devuelve las bajas a la lista.
        for valor in ("todas", "low", "sin_bajas", "loquesea", None):
            self.assertEqual(remediacion.contar(self.conn, estado="abierta",
                                                severidad=valor), 3, f"severidad={valor}")
        self.assertEqual(remediacion.contar(self.conn, estado="abierta",
                                            severidad="critical"), 1)
        self.assertEqual(remediacion.contar_actualizaciones(self.conn, estado="abierta"), 2)

    def test_la_lista_y_el_listado_agrupado_no_traen_ninguna_baja(self):
        filas = remediacion.listar(self.conn, estado="abierta", limite=100)
        self.assertEqual(len(filas), 3)
        self.assertNotIn("Low", [f.get("severity") for f in filas])
        grupos = remediacion.listar_actualizaciones(self.conn, estado="abierta", limite=50)
        self.assertEqual({g["activo_nombre"] for g in grupos},
                         {"srv-mixto-01", "srv-sin-evaluar-01"})
        openssl = next(g for g in grupos if g["paquete"] == "openssl")
        self.assertEqual(openssl["vulnerabilidades"], 2, "la baja no suma al grupo")
        self.assertEqual(openssl["version_objetivo"], "3.0.6",
                         "la más alta de las dos que se reportan")
        self.assertNotIn("CVE-2026-7003", [c["cve"] for c in openssl["cves"]])

    def test_la_pagina_ofrece_el_filtro_sin_la_baja_y_no_la_nombra(self):
        html = self._html("/remediaciones/")
        self.assertIn('<label for="severidad">Severidad</label>', html)
        self.assertIn('name="severidad"', html)
        # El valor de omisión sigue siendo «todas», que ahora son las tres que se reportan.
        seleccionada = re.search(r'<option value="(\w+)" selected>[^<]*</option>',
                                 html.split('name="severidad"')[1])
        self.assertIsNotNone(seleccionada, "ninguna opción de severidad viene marcada")
        self.assertEqual(seleccionada.group(1), "todas")
        # Y ninguna opción, ni ningún texto de la página, nombra la severidad baja.
        selector = html.split('name="severidad"')[1].split("</select>")[0]
        self.assertNotIn("baja", selector.lower())
        self.assertNotIn("severidad baja", html.lower())

    def test_el_panel_de_unidades_ya_no_habla_de_bajas(self):
        html = self._html("/remediaciones/")
        panel = html.split('id="unidades-remediacion"')[1].split("</table>")[0]
        for texto in ("Actualizaciones pendientes", "Vulnerabilidades pendientes",
                      "Filas de remediación pendientes", "CVE distintos",
                      "Activos con pendientes"):
            self.assertIn(texto, panel, f"falta la fila «{texto}»")
        self.assertNotIn("baja", panel.lower())
        # Las unidades siguen explicadas, que es la parte buena del panel.
        panel_plano = " ".join(panel.split())
        self.assertIn("Una por activo y CVE", panel_plano)
        self.assertIn("Una por activo, amenaza y paquete", panel_plano)

    def test_activos_explica_la_diferencia_que_queda_sin_hablar_de_bajas(self):
        html = self._html("/activos/")
        panel = " ".join(html.split('id="remediacion-resumen"')[1]
                         .split("</span>")[0].split())
        self.assertIn("Por qué las dos cifras de activos no coinciden exactamente", panel)
        self.assertIn("dice 1 y «Activos con pendientes», aquí abajo, dice 2", panel)
        self.assertIn("La diferencia son 1 activo", panel)
        self.assertIn("esperan una evaluación nueva", panel)
        self.assertNotIn("baja", panel.lower())
        # Y la tarjeta remite a esa explicación en vez de dejar el número solo.
        self.assertIn("ver la nota de este panel", html)

    def test_el_csv_no_exporta_ninguna_severidad_baja(self):
        cli = self._cliente()
        for severidad in ("todas", "low", "sin_bajas"):
            r = cli.get(f"/remediaciones/exportar.csv?estado=abierta&severidad={severidad}")
            self.assertEqual(r.status_code, 200)
            texto = r.get_data(as_text=True)
            lineas = [l for l in texto.splitlines() if l.strip()]
            self.assertEqual(len(lineas) - 1, 3, f"CSV con severidad={severidad}")
            self.assertNotIn("Low", texto)
            self.assertNotIn("CVE-2026-7003", texto)
            self.assertNotIn("CVE-2026-7004", texto)


# ==========================================================================
# 2. Cada cifra con su unidad escrita en pantalla
# ==========================================================================
class TestUnidadesEnPantalla(unittest.TestCase):
    """Cuatro cifras distintas compartían la palabra «vulnerabilidades»."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "revision_unidades.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            # Un servidor con el núcleo fusionado (dos paquetes, tres CVE cada uno) y un
            # paquete suelto con un solo CVE: la sublínea de filas debe salir en los dos.
            cls.srv = base._activo(conn, "srv-unidades-01", ip="10.0.0.31")
            for paquete in ("linux-image-6.8.0-60-generic", "linux-modules-6.8.0-60-generic"):
                base._software(conn, cls.srv, paquete, "6.8.0-60.62")
                for cve in ("CVE-2026-8001", "CVE-2026-8002", "CVE-2026-8003"):
                    t = conn.execute("SELECT id FROM threats WHERE cve=?", (cve,)).fetchone()
                    tid = t["id"] if t else base._amenaza(conn, cve)
                    base._remediacion(conn, cls.srv, tid, cve, paquete, "6.8.0-60.62",
                                      "6.8.0-60.63")
            base._software(conn, cls.srv, "nginx", "1.20.0")
            t = base._amenaza(conn, "CVE-2026-8010")
            base._remediacion(conn, cls.srv, t, "CVE-2026-8010", "nginx", "1.20.0", "1.20.2")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _html(self, url="/remediaciones/"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        r = cli.get(url)
        self.assertEqual(r.status_code, 200, url)
        html = r.get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html), f"style= en {url}")
        self.assertIsNone(RE_ON.search(html), f"on*= en {url}")
        return html

    def test_los_rotulos_dicen_la_unidad_de_su_cifra(self):
        html = self._html()
        # Cabecera de la columna, con la unidad y no solo en el título emergente.
        self.assertIn("Vulnerabilidades que resuelve", html)
        self.assertIn("Una por activo y CVE: la misma vulnerabilidad en varios paquetes "
                      "cuenta una vez", html)
        # «Por proceso de negocio»: desde el 2026-09-15 cuenta VULNERABILIDADES, no filas.
        # Contando filas, sus columnas sumaban 48.291 mientras la tarjeta de la misma
        # pantalla decía 32.823, y el usuario lo señaló: «este tablero tampoco es muy
        # claro». Ahora la suma de la primera columna ES la tarjeta.
        self.assertIn("Cuántas vulnerabilidades tiene pendientes cada proceso de negocio", html)
        self.assertIn(">Vulnerabilidades pendientes<", html)
        self.assertIn(">En producción o contingencia<", html)
        self.assertNotIn("Remediaciones expuestas", html)
        self.assertIn(">Vulnerabilidades corregidas<", html)
        # Las filas de remediación siguen a la vista como trazabilidad, bajo la cifra.
        self.assertIn("fila", html)
        # La tarjeta de CVE distintos ya no los llama «vulnerabilidades distintas».
        self.assertNotIn("vulnerabilidades distintas en total", html)
        self.assertIn("CVE distintos", html)

    def test_el_encabezado_de_la_vista_por_vulnerabilidad_dice_que_son_filas(self):
        html = self._html("/remediaciones/?vista=vulnerabilidad")
        cabecera = html.split('id="tabla-remediaciones"')[1].split("</h2>")[0]
        self.assertIn("Filas de trazabilidad, una por activo, amenaza y paquete", cabecera)
        # Y el rótulo del identificador ya no es una abreviatura.
        self.assertIn("Remediación número", html)

    def test_la_sublinea_de_filas_esta_siempre_presente(self):
        """También en la fila de un solo paquete: si solo salía en las fusionadas, la otra
        parecía incompleta."""
        html = self._html()
        # La fusión del núcleo: seis filas en dos paquetes para tres vulnerabilidades.
        self.assertIn("6 filas de remediación en 2 paquetes", html)
        # Y el paquete suelto: una fila en un paquete, con el singular bien escrito.
        self.assertIn("1 fila de remediación en 1 paquete", html)
        # La cifra de vulnerabilidades lleva su unidad al lado, en pantalla.
        self.assertIn("vulnerabilidades</span>", html)

    def test_la_ficha_del_activo_dice_las_mismas_unidades(self):
        html = self._html(f"/activos/{self.srv}")
        self.assertIn("Vulnerabilidades que resuelve", html)
        self.assertIn("6 filas de remediación en 2 paquetes", html)
        self.assertIn("1 fila de remediación en 1 paquete", html)

    def test_un_solo_texto_para_el_desplegable_de_paquetes(self):
        for nombre in ("remediaciones.html", "_remediaciones_activo.html",
                       "remediacion.html"):
            texto = (PLANTILLAS / nombre).read_text(encoding="utf-8")
            with self.subTest(plantilla=nombre):
                self.assertEqual(texto.count(TEXTO_DESPLEGABLE), 1,
                                 "el desplegable de paquetes lleva un único texto, el largo")
        # Y el texto corto que había en la ficha del activo ya no existe en ninguna.
        for nombre in PLANTILLAS_REVISADAS:
            texto = (PLANTILLAS / nombre).read_text(encoding="utf-8")
            with self.subTest(plantilla=nombre):
                self.assertNotIn("paquetes del mismo origen</summary>", texto)


# ==========================================================================
# 3. La gráfica semanal, sin activos retirados y con las semanas sin datos marcadas
# ==========================================================================
class TestSerieSemanal(unittest.TestCase):
    """Sumaba 66.326 detecciones donde la página decía 62.985: contaba las filas de
    activos que ya no figuran en OCS Inventory."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.addCleanup(self.dir.cleanup)
        self.ruta = str(Path(self.dir.name) / "revision_semanas.db")
        db.init_db(self.ruta)
        self.conn = db.connect(self.ruta)
        self.addCleanup(self.conn.close)
        self.srv = base._activo(self.conn, "srv-semanas-01", ip="10.0.0.41")
        self.amenaza = base._amenaza(self.conn, "CVE-2026-9001")

    def _fecha(self, expresion, *modificadores):
        marcas = "".join(", ?" for _ in modificadores)
        return self.conn.execute(f"SELECT date(?{marcas})",
                                 (expresion, *modificadores)).fetchone()[0]

    def test_los_activos_retirados_no_cuentan_en_la_grafica(self):
        # Mismo cálculo que ``remediacion._serie_semanal`` para el lunes de la semana en
        # curso (corregido el 2026-11-15: la fórmula vieja fallaba cuando «hoy» es lunes).
        lunes = self._fecha("now", "-6 days", "weekday 1")
        primer_lunes = self._fecha(lunes, "-28 days")
        # Dos detecciones reales y una de un activo retirado, la misma semana.
        for i, estado in enumerate(("abierta", "abierta", "activo_ausente")):
            base._remediacion(self.conn, self.srv, self.amenaza, f"CVE-2026-90{i:02d}",
                              f"paquete{i}", "1.0", "1.1", estado=estado,
                              detectado_at=f"{primer_lunes}T10:00:00Z")
        serie = remediacion.resumen(self.conn, dias=35)["semanas"]
        self.assertEqual([s["detectadas"] for s in serie], [2, 0, 0, 0, 0],
                         "la fila del activo retirado no puede contar como detección")
        # Y la suma de la serie coincide con lo que la página dice que hay pendiente.
        res = remediacion.resumen(self.conn, dias=35)
        self.assertEqual(sum(s["detectadas"] for s in res["semanas"]), res["abiertas"])
        self.assertEqual(res["activo_ausente"], 1)

    def test_cada_semana_dice_si_no_tuvo_datos_y_con_su_fecha_completa(self):
        lunes = self._fecha("now", "-6 days", "weekday 1")
        primer_lunes = self._fecha(lunes, "-28 days")
        base._remediacion(self.conn, self.srv, self.amenaza, "CVE-2026-9050", "nginx",
                          "1.0", "1.1", detectado_at=f"{primer_lunes}T10:00:00Z")
        serie = remediacion.resumen(self.conn, dias=35)["semanas"]
        self.assertEqual([s["sin_datos"] for s in serie], [False, True, True, True, True])
        # La etiqueta del eje lleva el día, el mes en palabras y el año, en dos líneas.
        for s in serie:
            with self.subTest(semana=s["inicio"]):
                self.assertRegex(s["etiqueta"],
                                 r"^\d{1,2} de [a-záéíóú]+\n\d{4}$")
                self.assertRegex(s["etiqueta_larga"],
                                 r"^\d{1,2} de [a-záéíóú]+ de \d{4}$")
        # Nunca el mes abreviado sin año, que es lo que se leía antes («10 ago»).
        self.assertEqual(remediacion._etiqueta_semana("2026-08-10"), "10 de agosto\n2026")
        self.assertEqual(remediacion._etiqueta_semana("2026-08-10", larga=True),
                         "10 de agosto de 2026")

    def test_la_leyenda_pinta_en_neutro_la_serie_que_vale_cero(self):
        """Un cero en verde se lee como si algo hubiera ido bien."""
        from webui.vistas import remediaciones as vista
        lunes = self._fecha("now", "-6 days", "weekday 1")
        base._remediacion(self.conn, self.srv, self.amenaza, "CVE-2026-9060", "nginx",
                          "1.0", "1.1", detectado_at=f"{lunes}T10:00:00Z")
        res = remediacion.resumen(self.conn, dias=35)
        svg = str(vista._grafico_semanal(res))
        self.assertIn("Vulnerabilidades detectadas", svg, "la leyenda dice la unidad")
        self.assertIn("Vulnerabilidades corregidas", svg)
        # Nada corregido en el periodo: su marcador va en gris, no en verde.
        self.assertIn("leyenda-punto serie-neutro", svg)
        self.assertNotIn("leyenda-punto serie-exito", svg)


# ==========================================================================
# 4. El nombre de la fila fusionada dice la versión
# ==========================================================================
class TestNombreDeLaFusionConVersion(unittest.TestCase):
    """121 de las 124 fusiones del núcleo de producción se llamaban «Núcleo Linux» a
    secas. Ahora la versión sale del nombre de un paquete o, si ninguno la lleva, de la
    versión que OCS Inventory ve instalada."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.addCleanup(self.dir.cleanup)
        self.ruta = str(Path(self.dir.name) / "revision_nombre.db")
        db.init_db(self.ruta)
        self.conn = db.connect(self.ruta)
        self.addCleanup(self.conn.close)

    def _grupo_de(self, paquetes, instaladas):
        """Un grupo real, por el mismo camino que la página (``pagina_actualizaciones``)."""
        srv = base._activo(self.conn, "srv-nucleo-01", ip="10.0.0.51")
        for paquete in paquetes:
            if instaladas.get(paquete):
                base._software(self.conn, srv, paquete, instaladas[paquete])
            for cve in ("CVE-2026-9101", "CVE-2026-9102"):
                fila = self.conn.execute("SELECT id FROM threats WHERE cve=?",
                                         (cve,)).fetchone()
                tid = fila["id"] if fila else base._amenaza(self.conn, cve)
                base._remediacion(self.conn, srv, tid, cve, paquete,
                                  instaladas.get(paquete) or "6.1.0-30", "6.1.148-1")
        grupos = remediacion.listar_actualizaciones(self.conn, estado="abierta",
                                                    activo_id=srv)
        self.assertEqual(len(grupos), 1, "los dos paquetes tienen que fusionarse")
        return grupos[0]

    def test_la_variante_con_version_gana_a_la_de_arquitectura(self):
        """El caso de 108 de las 121 filas: «linux-image-6.1.0-37-amd64» conviviendo con
        «linux-image-amd64», sin que ninguna variante sea prefijo de la otra."""
        g = self._grupo_de(("linux-image-6.1.0-37-amd64", "linux-image-amd64"),
                           {"linux-image-6.1.0-37-amd64": "6.1.0-37",
                            "linux-image-amd64": "6.1.0-37"})
        self.assertEqual(g["nombre"], "Núcleo Linux 6.1.0-37-amd64")
        self.assertEqual(g["variante_origen"], "paquete")
        self.assertTrue(g["es_fusion"])

    def test_sin_version_en_ningun_nombre_se_usa_la_instalada(self):
        """El caso de las 13 restantes: «linux-perf» con «linux-tools-common»."""
        g = self._grupo_de(("linux-perf", "linux-tools-common"),
                           {"linux-perf": "6.1.148-1", "linux-tools-common": "6.1.148-1"})
        self.assertEqual(g["nombre"], "Núcleo Linux 6.1.148-1")
        self.assertEqual(g["variante_origen"], "instalada")

    def test_ninguna_fusion_del_nucleo_se_queda_sin_version_si_se_conoce(self):
        """La medida que la revisión pidió: cuántas fusiones del núcleo quedan sin versión."""
        casos = (("linux-image-6.1.0-37-amd64", "linux-image-amd64"),
                 ("linux-image-6.12.90+deb13.1-amd64", "linux-image-amd64"),
                 ("linux-headers-6.8.0-60-generic", "linux-image-6.8.0-60-generic"),
                 ("linux-perf", "linux-tools-common"))
        sin_version = [c for c in casos
                       if not remediacion.nombre_actualizacion(
                           c, version_instalada="6.1.148-1")["variante"]]
        self.assertEqual(sin_version, [], "toda fusión del núcleo dice su versión")


# ==========================================================================
# 5. Recorrido guiado: el orden de los pasos es el orden de la página
# ==========================================================================
class TestOrdenDelRecorrido(unittest.TestCase):
    """``webui/static/app.js`` ordena los pasos por el número de ``data-tour``, así que el
    número tiene que crecer en el orden en que los paneles aparecen en la página. En la
    ficha del activo los pasos de remediación estaban numerados 11 y 12 y aparecían antes
    que el 7 y el 9: el recorrido saltaba hacia atrás."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "revision_tour.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            cls.srv = base._activo(conn, "srv-tour-01", ip="10.0.0.61")
            base._software(conn, cls.srv, "openssl", "3.0.1")
            t = base._amenaza(conn, "CVE-2026-9201")
            base._remediacion(conn, cls.srv, t, "CVE-2026-9201", "openssl", "3.0.1", "3.0.5")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _pasos(self, url):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        r = cli.get(url)
        self.assertEqual(r.status_code, 200, url)
        html = r.get_data(as_text=True)
        return [int(n) for n in re.findall(r'data-tour="(\d+)"', html)]

    def test_los_pasos_van_en_orden_creciente_en_la_pagina(self):
        for url in (f"/activos/{self.srv}", "/activos/", "/remediaciones/",
                    f"/activos/{self.srv}/remediacion"):
            pasos = self._pasos(url)
            with self.subTest(url=url):
                self.assertGreaterEqual(len(pasos), 2, "recorrido demasiado corto")
                self.assertEqual(pasos, sorted(pasos),
                                 f"el recorrido de {url} salta hacia atrás: {pasos}")
                self.assertEqual(len(pasos), len(set(pasos)), "números repetidos")
                self.assertEqual(pasos[0], 1, "el recorrido empieza en el paso 1")

    def test_la_ficha_del_activo_no_deja_huecos_con_sus_paneles_visibles(self):
        """Con el perfil de administración y un activo con remediaciones, los pasos que se
        pintan son consecutivos salvo los de los paneles que ese activo no tiene (el de
        Windows, que solo existe en máquinas con Windows)."""
        pasos = self._pasos(f"/activos/{self.srv}")
        faltan = [n for n in range(1, max(pasos) + 1) if n not in pasos]
        self.assertEqual(faltan, [6],
                         "solo puede faltar el paso del panel de Windows, que este activo "
                         f"no tiene; faltan {faltan}")


# ==========================================================================
# 6. Idioma, abreviaturas y fechas
# ==========================================================================
class TestIdiomaDeLasPlantillasRevisadas(unittest.TestCase):
    """«equipo» a secas nunca designa una máquina; ni «nº», ni «Nº», ni fechas ISO."""

    #: «equipo» seguido de algo que no sea «de cómputo» o «s de cómputo».
    RE_EQUIPO = re.compile(r"\bequipos?\b(?!\s+de\s+cómputo)", re.I)

    def test_ninguna_plantilla_revisada_llama_equipo_a_una_maquina(self):
        for nombre in PLANTILLAS_REVISADAS:
            texto = (PLANTILLAS / nombre).read_text(encoding="utf-8")
            # Solo el texto que se LEE: fuera los comentarios de Jinja (que explican la
            # propia regla) y fuera las expresiones y las etiquetas de control, donde
            # «equipos» es el nombre de un campo de la base («resumen.equipos») y no una
            # palabra que nadie ve.
            visible = re.sub(r"\{#.*?#\}", "", texto, flags=re.S)
            visible = re.sub(r"\{\{.*?\}\}", " ", visible, flags=re.S)
            visible = re.sub(r"\{%.*?%\}", " ", visible, flags=re.S)
            with self.subTest(plantilla=nombre):
                sobrantes = self.RE_EQUIPO.findall(visible)
                self.assertEqual(sobrantes, [],
                                 f"{nombre} usa «equipo» a secas: {sobrantes}")

    def test_ninguna_plantilla_revisada_abrevia_numero(self):
        for nombre in PLANTILLAS_REVISADAS:
            texto = (PLANTILLAS / nombre).read_text(encoding="utf-8")
            with self.subTest(plantilla=nombre):
                self.assertNotIn("nº", texto)
                self.assertNotIn("Nº", texto)
        # El rótulo que las sustituye dice qué es, para alguien nuevo.
        self.assertIn("Remediación número",
                      (PLANTILLAS / "remediaciones.html").read_text(encoding="utf-8"))

    #: Campos de fecha que, interpolados en un texto visible, tienen que pasar por un
    #: filtro de formato español («fecha_es» o «hace»): sin él salen en formato ISO.
    RE_CAMPO_FECHA = re.compile(r"\{\{([^}]*\b(?:eol|_at|fecha)\b[^}]*)\}\}")

    def test_las_fechas_de_los_titulos_emergentes_van_en_espanol(self):
        """Cinco títulos de la lista de activos decían «2025-10-14»."""
        for nombre in PLANTILLAS_REVISADAS:
            texto = (PLANTILLAS / nombre).read_text(encoding="utf-8")
            for titulo in re.findall(r'title="([^"]*)"', texto):
                for expresion in self.RE_CAMPO_FECHA.findall(titulo):
                    with self.subTest(plantilla=nombre, expresion=expresion.strip()):
                        self.assertRegex(
                            expresion, r"\|\s*(fecha_es|hace)\b",
                            "una fecha en un título emergente sin filtro de español sale "
                            "en formato ISO («2025-10-14»)")

    def test_el_plan_llama_actualizaciones_a_las_actualizaciones_y_explica_las_siglas(self):
        texto = (PLANTILLAS / "remediacion.html").read_text(encoding="utf-8")
        self.assertNotIn("Grupos de remediación", texto,
                         "el plan usaba una unidad que no existe en ninguna otra pantalla")
        self.assertIn("Actualizaciones por aplicar", texto)
        self.assertIn("Actualización por aplicar", texto, "singular para una sola")
        self.assertIn("Activo por corregir", texto, "el plural fijo decía «1 · Activos»")
        self.assertIn('<abbr title="Ubuntu Security Notice: aviso de seguridad de Ubuntu">USN</abbr>',
                      texto)


# ==========================================================================
# 7. Objetivos táctiles, foco y anchos: lo que fija la hoja de estilos
# ==========================================================================
class TestReglasDeEstilo(unittest.TestCase):
    """Las medidas que la revisión tomó sobre el DOM se sostienen en estas reglas."""

    def test_los_controles_llegan_a_44_pixeles(self):
        """CLAUDE.md y las reglas del proyecto exigen 44 px y prevalecen sobre los 24 px
        de la habilidad ui-ux-pro-max. Medido antes: summary 26,6 px, .btn.pequeno 30 px,
        .btn 34 px y los botones de icono 30 x 30 px."""
        for regla in ("summary { min-height: 44px;",
                      ".btn { min-height: 44px; }",
                      ".btn.pequeno { min-height: 44px;",
                      ".btn-icono, .btn.pequeno.btn-icono { width: 44px; height: 44px;",
                      ".chips-rapidos button.chip, .chips-rapidos a.chip { min-height: 44px; }"):
            with self.subTest(regla=regla):
                self.assertIn(regla, ESTILO)
        # Y no queda ninguna regla que baje el summary por debajo de 44 px.
        self.assertNotRegex(ESTILO, r"summary \{ min-height: (?!44px)\d+px")

    def test_el_summary_tiene_foco_visible_y_aspecto_accionable(self):
        self.assertIn("a:focus-visible, button:focus-visible, summary:focus-visible,",
                      ESTILO)
        self.assertIn("summary:hover, summary:focus-visible { color: var(--acento); "
                      "text-decoration: underline; }", ESTILO)

    def test_las_cabeceras_de_fila_del_cuerpo_no_son_cabeceras_de_columna(self):
        """La regla general de «th» las dejaba en mayúsculas, en una línea, con fondo y
        «position: sticky»: la celda «Equipos de cómputo…» medía 308,8 px sin poder
        partirse y sacaba la tabla del envoltorio."""
        bloque = ESTILO.split("tbody th {")[1].split("}")[0]
        for propiedad in ("text-transform: none", "white-space: normal",
                          "background: transparent", "position: static"):
            with self.subTest(propiedad=propiedad):
                self.assertIn(propiedad, bloque)

    def test_las_cabeceras_de_columna_pueden_ocupar_dos_lineas(self):
        """«Último inventario» perdía 17 px de texto y «Vulnerabilidades» 29 px."""
        self.assertIn(".tabla-activos thead th { white-space: normal; }", ESTILO)
        self.assertIn(".tabla-compacta thead th { white-space: normal; }", ESTILO)

    def test_los_anchos_de_la_tabla_de_activos_siguen_sumando_cien(self):
        anchos = [float(v) for v in re.findall(
            r"\.tabla-activos \.col-[a-z]+ \{ width: ([\d.]+)%", ESTILO)]
        # Cada columna puede declararse dos veces (la definición original y el ajuste del
        # 2026-09-09); vale la ÚLTIMA, que es la que aplica en cascada.
        ultimos: dict = {}
        for clave, valor in re.findall(
                r"\.tabla-activos \.(col-[a-z]+) \{ width: ([\d.]+)%", ESTILO):
            ultimos[clave] = float(valor)
        self.assertEqual(len(ultimos), 9, f"nueve columnas declaradas: {sorted(ultimos)}")
        self.assertAlmostEqual(sum(ultimos.values()), 100.0, places=3,
                               msg=f"los porcentajes no suman 100: {ultimos}")
        self.assertGreaterEqual(ultimos["col-vulns"], 12.0,
                                "la columna de vulnerabilidades necesita 137 px para su "
                                "cabecera y para la insignia «KEV 7»")
        self.assertTrue(anchos, "sin anchos declarados no hay reparto que comprobar")

    def test_el_ambar_del_tema_claro_se_distingue_del_naranja(self):
        """«Altas» y «Medias» se diferenciaban en 1,12:1 en tema claro."""
        claro = ESTILO[:ESTILO.index(':root[data-tema="claro"]')]
        alto = re.search(r"--alto: (#[0-9a-f]{6})", claro).group(1)
        medio = re.search(r"--medio: (#[0-9a-f]{6})", claro).group(1)
        fondo_panel = re.search(r"--fondo-panel: (#[0-9a-f]{6})", claro).group(1)
        fondo = re.search(r"--fondo: (#[0-9a-f]{6})", claro).group(1)

        def luminancia(h):
            def lineal(c):
                return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
            r, g, b = [lineal(int(h[i:i + 2], 16) / 255) for i in (1, 3, 5)]
            return 0.2126 * r + 0.7152 * g + 0.0722 * b

        def contraste(a, b):
            la, lb = luminancia(a), luminancia(b)
            return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)

        self.assertGreaterEqual(contraste(alto, medio), 1.5,
                                f"«Altas» ({alto}) y «Medias» ({medio}) siguen iguales")
        for nombre, superficie in (("panel", fondo_panel), ("fondo", fondo)):
            with self.subTest(sobre=nombre):
                self.assertGreaterEqual(contraste(medio, superficie), 4.5)
        # Y el separador entre tramos contiguos de la barra de progreso.
        self.assertIn(".progreso span + span { border-left: 1.5px solid var(--fondo-panel); }",
                      ESTILO)


if __name__ == "__main__":
    unittest.main()


class TestGraficaSemanalEnVulnerabilidades(unittest.TestCase):
    """La gráfica semanal cuenta vulnerabilidades, no filas de remediación (2026-09-15).

    Queja del usuario, literal: «ajusta el tablero de "Remediaciones detectadas y corregidas
    por semana" pues no es muy claro, no son vulnerabilidades o amenazas detectadas y
    remediadas?, porque confunde con lo que tiene y dice actualmente, no es claro».

    Medido sobre la base real antes del cambio: la gráfica decía 56.723 detectadas en
    treinta días mientras las tarjetas de la MISMA pantalla decían 32.823 vulnerabilidades
    pendientes y 48.291 filas de remediación. Tres cifras distintas a la vez, y la de la
    gráfica era la única que nadie había pedido.
    """

    def test_un_cve_en_dos_paquetes_del_mismo_activo_cuenta_una_vez(self):
        import tempfile
        from pathlib import Path
        from threatintel import db, remediacion
        from threatintel.paths import BASE_DIR
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as carpeta:
            ruta = str(Path(carpeta) / "semanal.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                conn.execute(
                    """INSERT INTO activos(ocs_id, nombre, origen, so_familia, presente,
                                           entorno, primera_vez_at, visto_at)
                       VALUES(1,'srv-semana','servidores','debian',1,'produccion',?,?)""",
                    (db.utcnow(), db.utcnow()))
                activo = conn.execute("SELECT id FROM activos").fetchone()[0]
                conn.execute(
                    """INSERT INTO threats(fingerprint, cve, title_en, severity, severity_source,
                                           first_seen_at, last_seen_at, month, relevance, estado)
                       VALUES('fp-sem','CVE-2026-7777','Aviso','High','nvd',?,?,?,70.0,'nueva')""",
                    (db.utcnow(), db.utcnow(), db.utcnow()[:7]))
                amenaza = conn.execute("SELECT id FROM threats").fetchone()[0]
                lunes = conn.execute("SELECT date('now','-6 days','weekday 1')").fetchone()[0]
                # El MISMO CVE en el MISMO servidor, en dos paquetes distintos.
                for paquete in ("openssl", "libssl3"):
                    conn.execute(
                        """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete,
                                version_vulnerable, version_corregida, motor, estado,
                                detectado_at, comprobado_at)
                           VALUES(?,?,'CVE-2026-7777',?,'1.0','1.1','osv','abierta',?,?)""",
                        (activo, amenaza, paquete, f"{lunes}T10:00:00Z", f"{lunes}T10:00:00Z"))
            with db.connect(ruta) as conn:
                serie = remediacion._serie_semanal(conn, 30)
                detectadas = sum(s["detectadas"] for s in serie)
                filas = conn.execute(
                    "SELECT COUNT(*) FROM remediaciones WHERE estado='abierta'").fetchone()[0]
        self.assertEqual(filas, 2, "hay dos filas de remediación, una por paquete")
        self.assertEqual(detectadas, 1,
                         "pero es UNA vulnerabilidad: un CVE en un activo, como la tarjeta")

    def test_el_titulo_y_el_texto_hablan_de_vulnerabilidades(self):
        from threatintel.paths import BASE_DIR
        plantilla = (BASE_DIR / "webui" / "templates" / "remediaciones.html").read_text(encoding="utf-8")
        self.assertIn("<h2>Vulnerabilidades detectadas y corregidas por semana</h2>", plantilla)
        self.assertNotIn("<h2>Remediaciones detectadas y corregidas por semana</h2>", plantilla)
        self.assertIn("Una vulnerabilidad es un CVE en", plantilla)
        self.assertIn("No es el total pendiente", plantilla)


class TestTablaPorProcesoEnVulnerabilidades(unittest.TestCase):
    """«Por proceso de negocio» cuenta vulnerabilidades, no filas (2026-09-15).

    Queja del usuario: «este tablero tampoco es muy claro». Contaba filas de remediación,
    una por activo, amenaza y paquete, así que sus columnas sumaban 48.291 mientras la
    tarjeta de arriba de la misma pantalla decía 32.823 vulnerabilidades pendientes. Ahora
    la suma de la primera columna es exactamente esa tarjeta.
    """

    def test_la_suma_por_proceso_es_la_tarjeta_de_vulnerabilidades(self):
        import tempfile
        from pathlib import Path
        from threatintel import db, remediacion
        from threatintel.paths import BASE_DIR
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as carpeta:
            ruta = str(Path(carpeta) / "proceso.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                for numero, (nombre, proceso) in enumerate((
                        ("srv-a", "Pila"), ("srv-b", "Pila"), ("srv-c", "Impuestos")), start=1):
                    conn.execute(
                        """INSERT INTO activos(ocs_id, nombre, origen, so_familia, presente,
                                               proceso, entorno, primera_vez_at, visto_at)
                           VALUES(?,?,'servidores','debian',1,?,'produccion',?,?)""",
                        (numero, nombre, proceso, db.utcnow(), db.utcnow()))
                conn.execute(
                    """INSERT INTO threats(fingerprint, cve, title_en, severity, severity_source,
                                           first_seen_at, last_seen_at, month, relevance, estado)
                       VALUES('fp-p','CVE-2026-5555','Aviso','High','nvd',?,?,?,70.0,'nueva')""",
                    (db.utcnow(), db.utcnow(), db.utcnow()[:7]))
                amenaza = conn.execute("SELECT id FROM threats").fetchone()[0]
                # El MISMO CVE en dos paquetes de cada activo: seis filas, tres vulnerabilidades.
                for activo in (1, 2, 3):
                    for paquete in ("openssl", "libssl3"):
                        conn.execute(
                            """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete,
                                    version_vulnerable, version_corregida, motor, estado,
                                    detectado_at, comprobado_at)
                               VALUES(?,?,'CVE-2026-5555',?,'1.0','1.1','osv','abierta',?,?)""",
                            (activo, amenaza, paquete, db.utcnow(), db.utcnow()))
            with db.connect(ruta) as conn:
                res = remediacion.resumen(conn, dias=30)
        por_proceso = {p["proceso"]: p for p in res["por_proceso"]}
        self.assertEqual(sum(p["abiertas"] for p in res["por_proceso"]), 6, "seis filas")
        self.assertEqual(sum(p["vulnerables"] for p in res["por_proceso"]),
                         res["vulnerabilidades_unicas"],
                         "la suma por proceso es la misma cifra que la tarjeta")
        self.assertEqual(res["vulnerabilidades_unicas"], 3, "tres vulnerabilidades, no seis")
        self.assertEqual(por_proceso["Pila"]["vulnerables"], 2)
        self.assertEqual(por_proceso["Pila"]["abiertas"], 4, "y sus cuatro filas siguen ahí")
