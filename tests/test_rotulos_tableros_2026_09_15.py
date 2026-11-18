"""Rótulos y cifras corregidos en la auditoría de tableros del 2026-09-15.

La auditoría encontró que varias cifras de las pantallas de Amenazas, Tendencias, Activos,
Correcciones pendientes, Alertas por proceso, Remediación y la ficha de amenaza estaban
bien calculadas pero mal nombradas: el rótulo no decía qué contaba la cifra, o decía algo
que la consulta no hacía. Dos eran de verdad incoherentes (la leyenda de «Tecnologías más
afectadas» frente a la tarjeta de la misma página, y el «porcentaje corregido» del avance
por tipo de máquina, que dividía un flujo de treinta días entre un stock de hoy).

Cada prueba de este fichero fija UN rótulo o UNA cifra de las corregidas, con el texto
exacto que debe leerse, para que una reescritura futura no lo deshaga sin darse cuenta.
Sin red (no se consulta ninguna fuente) y con base temporal bajo ``data/``.
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

from threatintel import db, parches
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402
from webui.vistas import activos as vista_activos  # noqa: E402

CLAVE = "ClaveSegura#2026"
ADMIN = "admin@ejemplo.local"

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)

#: Identificadores de las amenazas de prueba.
CVE_DOS_TEC = "CVE-2026-1001"     # menciona dos tecnologías: cuenta en las dos barras
CVE_CONFIRMADA = "CVE-2026-1002"  # versión de la tecnología vulnerable
CVE_SIN_TEC = "CVE-2026-1003"     # sin ninguna tecnología del inventario
CVE_MENCION = "CVE-2026-1005"     # una tecnología con prueba y otra solo mencionada
CVE_KEV = "CVE-2026-1006"         # explotación activa confirmada


def _texto(html: str) -> str:
    """El texto visible de un trozo de HTML, con los espacios normalizados."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


class BaseTableros(unittest.TestCase):
    """Un parque pequeño pero completo: dos versiones de sistema y activos sin sistema,
    servidores con y sin proceso de negocio, amenazas con y sin tecnología correlacionada,
    remediaciones abiertas y correcciones pendientes en el catálogo."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "tableros.db")
        db.init_db(cls.ruta)
        ahora = db.utcnow()
        cls.mes = ahora[:7]
        anio, numero = int(cls.mes[:4]), int(cls.mes[5:7])
        cls.mes_anterior = f"{anio - 1}-12" if numero == 1 else f"{anio}-{numero - 1:02d}"
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, ADMIN, CLAVE, rol="admin", nombre="Administradora", actor="t")
            # --- inventario tecnológico -------------------------------------------------
            for slug, nombre, version in (("windows", "Microsoft Windows", "6.0.25"),
                                          ("chrome", "Google Chrome", None),
                                          ("winrar", "WinRAR", None)):
                conn.execute(
                    """INSERT INTO technologies(slug, name, vendor, category, criticality, exposure,
                                                version_installed, systems_count, enabled, created_at, updated_at)
                       VALUES(?,?,'Fabricante','aplicacion','high','interna',?,3,1,?,?)""",
                    (slug, nombre, version, ahora, ahora))
            tec = {r["slug"]: r["id"] for r in conn.execute("SELECT id, slug FROM technologies")}
            # --- activos ----------------------------------------------------------------
            # Dos versiones reales de sistema y un equipo de cómputo cuyo agente nunca envió
            # el sistema («Sin datos de sistema», familia «desconocido»): ese es el caso que
            # entraba en el top de versiones sin ser una versión.
            maquinas = (
                (1, "srv-proceso-01", "servidores", "ubuntu", "Ubuntu 22.04", "22.04", "Tesorería"),
                (2, "srv-proceso-02", "servidores", "ubuntu", "Ubuntu 22.04", "22.04", "Tesorería"),
                (3, "srv-sin-proceso", "servidores", "debian", "Debian 13", "13", None),
                (4, "pc-sin-sistema", "equipos", "desconocido", "Sin datos de sistema", None, None),
            )
            for ocs_id, nombre, origen, familia, so_nombre, ciclo, proceso in maquinas:
                conn.execute(
                    """INSERT INTO activos(ocs_id, nombre, origen, so_familia, so_nombre, so_ciclo,
                                           ecosistema, ip, presente, entorno, proceso,
                                           ultimo_inventario, primera_vez_at, visto_at)
                       VALUES(?,?,?,?,?,?,'Ubuntu:22.04',?,1,'produccion',?,?,?,?)""",
                    (ocs_id, nombre, origen, familia, so_nombre, ciclo,
                     f"10.8.8.{ocs_id}", proceso, ahora, ahora, ahora))
            cls.activos = {r["nombre"]: r["id"] for r in conn.execute("SELECT id, nombre FROM activos")}
            for activo_id in cls.activos.values():
                conn.execute("""INSERT INTO activo_software(activo_id, nombre, nombre_norm, version)
                                VALUES(?,'openssl','openssl','1.0')""", (activo_id,))
            # --- amenazas ---------------------------------------------------------------
            amenazas = (
                ("fp-dos", CVE_DOS_TEC, "Critical", cls.mes, 0, 3),
                ("fp-confirmada", CVE_CONFIRMADA, "High", cls.mes, 0, 1),
                ("fp-sin-tec", CVE_SIN_TEC, "Medium", cls.mes, 0, 1),
                ("fp-mencion", CVE_MENCION, "High", cls.mes, 0, 1),
                ("fp-kev", CVE_KEV, "Critical", cls.mes, 1, 1),
                # El mismo identificador en el mes anterior: así es un CVE recurrente y la
                # tabla «CVE recurrentes» tiene filas que enseñar.
                ("fp-dos-anterior", CVE_DOS_TEC, "Critical", cls.mes_anterior, 0, 4),
            )
            for fingerprint, cve, severidad, mes, en_kev, veces in amenazas:
                conn.execute(
                    """INSERT INTO threats(fingerprint, cve, title_en, title_es, summary_en, severity,
                           severity_source, cvss_score, in_kev, first_seen_at, last_seen_at,
                           times_seen, month, relevance, estado)
                       VALUES(?,?,?,?,'Resumen de prueba','""" + severidad + """','nvd',7.5,?,?,?,?,?,60.0,'nueva')""",
                    (fingerprint, cve, f"Aviso {cve}", f"Aviso {cve}", en_kev,
                     ahora, ahora, veces, mes))
            cls.amenazas = {r["fingerprint"]: r["id"] for r in
                            conn.execute("SELECT id, fingerprint FROM threats")}
            # Correlación con el inventario. La confianza decide si la tecnología se lista
            # en la ficha o si es solo una mención sin prueba de exposición.
            correlaciones = (
                ("fp-dos", "windows", 1.0, "unknown"),
                ("fp-dos", "chrome", 1.0, "unknown"),
                ("fp-confirmada", "windows", 1.0, "affected"),
                ("fp-mencion", "chrome", 1.0, "unknown"),
                ("fp-mencion", "winrar", 0.3, "unknown"),
            )
            for fingerprint, slug, confianza, veredicto in correlaciones:
                conn.execute(
                    """INSERT INTO threat_technologies(threat_id, technology_id, matched_alias,
                                                       confidence, version_verdict)
                       VALUES(?,?,?,?,?)""",
                    (cls.amenazas[fingerprint], tec[slug], slug, confianza, veredicto))
            # --- aplicabilidad y remediaciones -----------------------------------------
            # srv-proceso-01, srv-sin-proceso y pc-sin-sistema tienen vulnerabilidades
            # confirmadas; solo srv-proceso-01 tiene una de explotación activa (KEV).
            # La última no tiene versión que instalar: es la que Remediación cuenta como
            # «actualización sin versión que instalar» y la que hace que el catálogo de
            # correcciones pendientes tenga activos implicados.
            afectados = (
                ("srv-proceso-01", "fp-confirmada", CVE_CONFIRMADA, "openssl", "1.2"),
                ("srv-proceso-01", "fp-kev", CVE_KEV, "openssl", "1.2"),
                ("srv-sin-proceso", "fp-confirmada", CVE_CONFIRMADA, "openssl", "1.2"),
                ("pc-sin-sistema", "fp-confirmada", CVE_CONFIRMADA, "openssl", "1.2"),
                ("srv-proceso-02", "fp-sin-tec", CVE_SIN_TEC, "openssl", None),
            )
            for nombre, fingerprint, cve, paquete, corregida in afectados:
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada,
                                                 version_corregida, veredicto, motor, evaluado_at)
                       VALUES(?,?,?,?,'1.0',?,'afectado','osv',?)""",
                    (cls.activos[nombre], cls.amenazas[fingerprint], cve, paquete, corregida, ahora))
                conn.execute(
                    """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete, version_vulnerable,
                                                 version_corregida, motor, estado, detectado_at, comprobado_at)
                       VALUES(?,?,?,?,'1.0',?,'osv','abierta',?,?)""",
                    (cls.activos[nombre], cls.amenazas[fingerprint], cve, paquete, corregida, ahora, ahora))
            for fingerprint, n in (("fp-confirmada", 3), ("fp-kev", 1)):
                conn.execute(
                    """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados, no_afectados,
                                                         sin_dato, afectados_expuestos, parche_disponible, detalle)
                       VALUES(?,?,?,0,0,?,1,'{}')""", (cls.amenazas[fingerprint], ahora, n, n))
            # --- catálogo de correcciones pendientes ------------------------------------
            # Cuatro filas para DOS identificadores distintos: es justo lo que la cifra «en
            # seguimiento» no decía (una fila por identificador, paquete y versión).
            catalogo = (
                (CVE_SIN_TEC, "openssl", "Ubuntu:22.04"),
                (CVE_SIN_TEC, "openssl", "Debian:13"),
                (CVE_SIN_TEC, "libssl", "Ubuntu:22.04"),
                (CVE_MENCION, "openssl", "Ubuntu:22.04"),
            )
            for cve, paquete, ecosistema in catalogo:
                conn.execute(
                    """INSERT INTO parches_pendientes(cve, paquete, ecosistema, threat_id, motivo,
                                                      n_activos, n_activos_expuestos, detectado_at)
                       VALUES(?,?,?,?,'aviso_sin_version',1,1,?)""",
                    (cve, paquete, ecosistema,
                     cls.amenazas["fp-sin-tec" if cve == CVE_SIN_TEC else "fp-mencion"], ahora))
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": ADMIN, "password": CLAVE})
        return cli

    def _html(self, url: str) -> str:
        r = self._cliente().get(url)
        self.assertEqual(r.status_code, 200, url)
        html = r.get_data(as_text=True)
        # CSP estricta: ninguna de las correcciones introduce estilo ni código en línea.
        self.assertIsNone(RE_STYLE.search(html), f"style= en {url}")
        self.assertIsNone(RE_ON.search(html), f"on*= en {url}")
        return html


class TestTendencias(BaseTableros):
    """Puntos 1, 2 y 3 de la auditoría: la leyenda de «Tecnologías más afectadas», la
    columna «Confirmadas» y la columna «Apariciones»."""

    def _panel_tecnologias(self) -> str:
        html = self._html("/amenazas/tendencias")
        return html.split("Tecnologías más afectadas", 2)[2].split("CVE recurrentes")[0]

    def test_la_leyenda_de_tecnologias_avisa_de_que_suma_con_repeticion(self):
        """Punto 1. La leyenda suma las barras dibujadas y las suma con repetición (una
        amenaza que menciona dos tecnologías cuenta en las dos), así que NO coincide con la
        tarjeta «Amenazas del periodo» de la misma página. Antes nadie lo decía: sobre la
        base real la leyenda ponía Críticas 168, Altas 938 y Medias 699 y la tarjeta 118,
        834 y 571."""
        panel = self._panel_tecnologias()
        nota = re.search(r'<p class="leyenda-nota[^"]*">(.*?)</p>', panel, re.S)
        self.assertIsNotNone(nota, "la leyenda de la gráfica de tecnologías no lleva nota")
        texto = _texto(nota.group(1))
        self.assertIn("con repetición", texto)
        self.assertIn("una amenaza que menciona dos tecnologías cuenta en las dos", texto)
        self.assertIn("No es el total del periodo", texto)
        # Y debajo de la gráfica, la explicación completa que el Panel ya tenía.
        parrafos = [_texto(p) for p in re.findall(r'<p class="pequeno suave mt-12">(.*?)</p>', panel, re.S)]
        explicacion = next((p for p in parrafos if "no suman" in p), "")
        self.assertTrue(explicacion, f"falta la explicación bajo la gráfica: {parrafos}")
        for frase in ("no suman", "tecnologías con más", "no todas",
                      "no está en ninguna barra"):
            self.assertIn(frase, explicacion)

    def test_la_leyenda_y_la_tarjeta_discrepan_y_por_eso_se_explica(self):
        """La discrepancia es real con estos datos: la leyenda suma más críticas y más
        altas que la tarjeta, porque CVE-2026-1001 menciona dos tecnologías. La prueba fija
        que el modelo NO cambió (la consulta es correcta): lo que se añadió es el aviso."""
        html = self._html("/amenazas/tendencias")
        panel = html.split("Tecnologías más afectadas", 2)[2].split("CVE recurrentes")[0]
        leyenda = _texto(panel.split('class="leyenda"')[1].split("</ul>")[0])
        self.assertIn("Críticas 2 amenazas", leyenda)   # 1 de Windows + 1 de Chrome
        self.assertIn("Altas 3 amenazas", leyenda)      # 1 + 1 + 1 (WinRAR)
        tarjetas = _texto(html.split('class="rejilla c4 mb-18"')[1].split("</div></div>")[0])
        self.assertIn("1", tarjetas)  # la tarjeta cuenta 1 crítica, sin repetir
        self.assertIn("Amenazas críticas", tarjetas)

    def test_la_columna_confirmadas_dice_que_es_por_version_de_la_tecnologia(self):
        """Punto 2. «Confirmadas» a secas chocaba con «Amenazas confirmadas en algún
        activo» de la página de Amenazas: Microsoft Windows salía con 0 aquí y con 1.545
        allí sobre la base real."""
        panel = self._panel_tecnologias()
        cabecera = panel.split("<table", 1)[1].split("</thead>")[0]
        titulos = [_texto(c) for c in re.findall(r"<th[^>]*>(.*?)</th>", cabecera, re.S)]
        self.assertIn("Confirmadas por versión de la tecnología", titulos)
        self.assertNotIn("Confirmadas", titulos, "la columna ambigua sigue ahí")
        pie = _texto(panel.split('class="panel-pie"')[1].split("</div>")[0])
        self.assertIn("No es lo mismo que «Amenazas confirmadas en algún activo»", pie)
        self.assertIn("versión instalada en cada uno de los activos reales", pie)
        # El pie enlaza a la página donde vive la otra cifra.
        enlaces = panel.split('class="panel-pie"')[1].split("</div>")[0]
        self.assertIn('href="/amenazas/', enlaces)

    def test_la_columna_apariciones_dice_que_cuenta_citas_en_avisos(self):
        """Punto 3. «Apariciones» no son activos ni periodos: son las veces que los avisos
        recolectados citaron el identificador, y hasta hoy solo lo decía el título
        emergente. En las dos páginas que la enseñan."""
        for url, marca in (("/amenazas/", "CVE presentes en varios periodos"),
                           ("/amenazas/tendencias", "CVE recurrentes")):
            with self.subTest(url=url):
                html = self._html(url)
                self.assertIn(marca, html, "la tabla de CVE recurrentes no se pintó")
                cabecera = html.split(marca, 1)[1].split("</thead>")[0]
                titulos = [_texto(c) for c in re.findall(r"<th[^>]*>(.*?)</th>", cabecera, re.S)]
                self.assertIn("Veces citado en avisos", titulos)
                self.assertNotIn("Apariciones", titulos)


class TestPaginaActivos(BaseTableros):
    """Puntos 4, 5 y 6: la unidad del recuento KEV, la nota de «Activos con pendientes» y
    la barra «Sin datos de sistema» dentro de un top de versiones."""

    def test_los_activos_con_explotacion_activa_llevan_su_unidad(self):
        """Punto 4. «176 con explotación activa (KEV)» no decía de qué eran 176: son
        ACTIVOS, no vulnerabilidades (la página de Amenazas cuenta 343 vulnerabilidades KEV
        sobre los mismos datos)."""
        html = self._html("/activos/")
        tarjeta = html.split("Con vulnerabilidades confirmadas", 1)[1].split("</div></div>")[0]
        self.assertIn("de ellos con explotación activa (KEV)", _texto(tarjeta))
        self.assertNotIn("1 con explotación activa (KEV)", _texto(tarjeta))

    def test_la_nota_de_activos_con_pendientes_dice_el_criterio_real(self):
        """Punto 5. Decía «de cualquier severidad» y es falso: la consulta deja fuera la
        severidad baja y las remediaciones cubiertas por una excepción vigente."""
        html = self._html("/activos/")
        panel = html.split('id="remediacion-resumen"', 1)[1].split("Buscar activos")[0]
        tarjeta = _texto(panel.split("Activos con pendientes", 1)[1][:400])
        self.assertIn("de severidad crítica, alta o media", tarjeta)
        self.assertIn("el riesgo aceptado con excepción vigente no cuenta", tarjeta)
        self.assertNotIn("de cualquier severidad", panel)

    def test_sin_datos_de_sistema_sale_del_top_de_versiones_y_se_dice_aparte(self):
        """Punto 6. «Sin datos de sistema» no es una versión: competía con Debian 12 y
        Windows 11 Pro dentro de un top de versiones y además robaba un puesto, así que el
        pie prometía doce versiones cuando solo dibujaba once."""
        html = self._html("/activos/")
        panel = html.split("Versiones de sistema con más activos", 1)[1].split("panel-pie")[0]
        etiquetas = re.findall(r'<text class="eje"[^>]*>(?:<title>.*?</title>)?(.*?)</text>',
                               panel, re.S)
        self.assertIn("Ubuntu 22.04", etiquetas)
        self.assertIn("Debian 13", etiquetas)
        self.assertNotIn("Sin datos de sistema", etiquetas,
                         "lo que no es una versión no puede ser una barra del top de versiones")
        # Y se dice aparte, con su cifra, su unidad y su enlace.
        aparte = [p for p in re.findall(r'<p class="pequeno suave mt-12">(.*?)</p>', panel, re.S)
                  if "sin datos de sistema" in _texto(p)]
        self.assertEqual(len(aparte), 1, "falta la línea de los activos sin datos de sistema")
        texto = _texto(aparte[0])
        self.assertIn("1 activo sin datos de sistema", texto)
        self.assertIn("sin competir con las versiones porque no lo son", texto)
        self.assertIn('href="/activos/?familia=desconocido"', aparte[0])

    def test_el_recuento_de_versiones_no_cuenta_lo_que_no_es_una_version(self):
        """Las tres funciones que alimentan la gráfica, por separado: la barra, el recuento
        de las que quedan fuera y los activos sin sistema."""
        sistemas = [
            {"so_nombre": "Ubuntu 22.04", "so_familia": "ubuntu", "n": 10, "soporte": {}},
            {"so_nombre": "Sin datos de sistema", "so_familia": "desconocido", "n": 4, "soporte": None},
            {"so_nombre": "Debian 13", "so_familia": "debian", "n": 2, "soporte": {}},
        ]
        with self.app.test_request_context("/activos/"):
            items = vista_activos._items_sistemas(sistemas, limite=2)
        self.assertEqual([it["etiqueta"] for it in items], ["Ubuntu 22.04", "Debian 13"])
        self.assertEqual(vista_activos._versiones_fuera_grafica(sistemas, limite=1),
                         {"versiones": 1, "activos": 2})
        self.assertEqual(vista_activos._activos_sin_datos_de_sistema(sistemas), 4)
        self.assertEqual(vista_activos._activos_sin_datos_de_sistema([]), 0)


class TestCorreccionesPendientes(BaseTableros):
    """Punto 7: «191 en seguimiento» eran filas del catálogo, no vulnerabilidades, y
    convivían con las «1.748 actualizaciones sin versión» de Remediación sin explicación."""

    def test_el_resumen_dice_cuantos_identificadores_y_paquetes_hay_detras(self):
        with db.session(self.ruta) as conn:
            resumen = parches.resumen(conn)
        self.assertEqual(resumen["en_seguimiento"], 4, "cuatro filas de catálogo")
        self.assertEqual(resumen["cve_distintos"], 2, "para dos identificadores distintos")
        self.assertEqual(resumen["paquetes"], 2)
        self.assertEqual(resumen["ecosistemas"], 2)

    def test_la_tarjeta_lleva_la_unidad_y_explica_que_es_cada_fila(self):
        html = self._html("/parches-pendientes/")
        tarjeta = _texto(html.split("Correcciones en seguimiento", 1)[1].split("</div></div>")[0])
        self.assertIn("una por identificador", tarjeta)
        self.assertIn("paquete y versión del sistema operativo", tarjeta)
        self.assertIn("2 identificadores distintos en 2 paquetes", tarjeta)
        # El rótulo sin unidad («En seguimiento» a secas) ya no está entre los indicadores;
        # sigue siendo el nombre de la lista del filtro, que sí es una lista y no una cifra.
        indicadores = html.split('class="rejilla c4 mb-18"', 1)[1].split("Por qué no se conoce")[0]
        self.assertNotIn(">En seguimiento<", indicadores, "el rótulo sin unidad sigue ahí")

    def test_se_concilia_con_remediacion_diciendo_que_son_unidades_distintas(self):
        html = self._html("/parches-pendientes/")
        pie = _texto(html.split('class="panel-pie"', 1)[1].split("</div>")[0])
        self.assertIn("Por qué Remediación enseña otra cifra", pie)
        self.assertIn("correcciones del catálogo", pie)
        self.assertIn("una tarea por activo y origen de paquete", pie)
        # La cifra viva de Remediación: una actualización sin versión que instalar.
        self.assertIn("cuenta 1 actualización sin versión que instalar", pie)
        self.assertIn("ninguna de las dos está mal", pie)


class TestAlertasPorProceso(BaseTableros):
    """Punto 8: las tarjetas suman los procesos, así que solo hablan de los servidores con
    proceso asignado; el alcance tiene que estar en la propia cifra."""

    def test_las_cifras_dicen_que_solo_cubren_los_servidores_con_proceso(self):
        html = self._html("/alertas-proceso/")
        bloque = html.split('class="rejilla c4 mb-18"', 1)[1].split("Destino y activación")[0]
        texto = _texto(bloque)
        self.assertIn("Servidores con proceso asignado", texto)
        self.assertIn("de los 3 servidores presentes en OCS Inventory", texto)
        self.assertIn("1 sin proceso asignado no recibe ningún correo por proceso", texto)
        self.assertIn("Servidores con proceso y con vulnerabilidades", texto)
        # Con proceso hay 2 servidores afectados; en todo el parque hay 3 de 3: el que
        # falta es el que no tiene proceso, y esta página no lo cubre.
        self.assertIn("En todo el parque son 3 de 3 servidores", texto)
        self.assertIn("la diferencia está en los servidores sin proceso", texto)
        self.assertNotIn("Con vulnerabilidades servidores con la versión vulnerable", texto)

    def test_el_parque_se_cuenta_igual_que_en_el_resto_de_la_plataforma(self):
        """El recuento del parque usa el mismo criterio de severidad y de estado que
        ``alertas_proceso.procesos_disponibles``: si no, las dos cifras de la misma tarjeta
        se contradirían."""
        from webui.vistas import alertas_proceso as vista
        with db.session(self.ruta) as conn:
            parque = vista._parque_de_servidores(conn)
        self.assertEqual(parque, {"total": 3, "con_proceso": 2, "con_vulnerabilidades": 3})

    def test_una_amenaza_cerrada_a_mano_no_cuenta_en_el_parque(self):
        from webui.vistas import alertas_proceso as vista
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE threats SET estado='descartada' WHERE fingerprint='fp-confirmada'")
        try:
            with db.session(self.ruta) as conn:
                parque = vista._parque_de_servidores(conn)
            # Quedan el servidor con la amenaza KEV y el de la amenaza sin tecnología,
            # las dos abiertas; el tercero solo tenía la que se acaba de descartar.
            self.assertEqual(parque["con_vulnerabilidades"], 2)
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE threats SET estado='nueva' WHERE fingerprint='fp-confirmada'")


class TestFichaDeAmenaza(BaseTableros):
    """Punto 9: la cabecera contaba tecnologías que la tabla no listaba, porque las que
    están por debajo del umbral de confianza van a una nota aparte."""

    def test_la_cabecera_cuenta_lo_que_la_tabla_lista(self):
        html = self._html(f"/amenazas/{self.amenazas['fp-mencion']}")
        panel = html.split("Tecnologías afectadas", 1)[1].split("desglose por sistema")[0]
        sub = _texto(panel.split('class="sub"', 1)[1].split("</span>")[0])
        self.assertIn("Se lista 1 tecnología con prueba suficiente", sub)
        self.assertIn("0 con versión afectada y 1 sin determinar", sub)
        # Y la tabla tiene exactamente esa fila.
        cuerpo = panel.split("<tbody>", 1)[1].split("</tbody>")[0]
        self.assertEqual(len(re.findall(r"<tr>", cuerpo)), 1)
        self.assertIn("Google Chrome", cuerpo)
        self.assertNotIn("WinRAR", cuerpo)

    def test_las_menciones_sin_prueba_tienen_su_propio_recuento(self):
        html = self._html(f"/amenazas/{self.amenazas['fp-mencion']}")
        panel = html.split("Tecnologías afectadas", 1)[1].split("desglose por sistema")[0]
        sub = _texto(panel.split('class="sub"', 1)[1].split("</span>")[0])
        self.assertIn("1 mención sin prueba de exposición", sub)
        self.assertIn("no se lista en la tabla", sub)
        nota = _texto([p for p in re.findall(r'<div class="panel-pie">(.*?)</div>', panel, re.S)
                       if "sin prueba de exposición" in p][-1])
        self.assertIn("1 mención sin prueba de exposición", nota)
        self.assertIn("WinRAR", nota)

    def test_una_amenaza_con_dos_tecnologias_listadas_las_cuenta_las_dos(self):
        """El caso contrario: las dos correlaciones tienen prueba suficiente, luego las dos
        se listan y la cabecera dice dos."""
        html = self._html(f"/amenazas/{self.amenazas['fp-dos']}")
        panel = html.split("Tecnologías afectadas", 1)[1].split("desglose por sistema")[0]
        sub = _texto(panel.split('class="sub"', 1)[1].split("</span>")[0])
        self.assertIn("Se listan 2 tecnologías con prueba suficiente", sub)
        self.assertNotIn("mención sin prueba", sub)
        cuerpo = panel.split("<tbody>", 1)[1].split("</tbody>")[0]
        self.assertEqual(len(re.findall(r"<tr>", cuerpo)), 2)


class TestAvancePorTipoDeMaquina(BaseTableros):
    """Punto 10: «0,6 % corregido: 140 de 22.731» sumaba 140 filas corregidas en treinta
    días (un flujo) y 22.591 pendientes hoy (un stock) en un denominador inexistente."""

    def _bloque(self) -> str:
        html = self._html("/remediaciones/")
        self.assertIn('id="avance-por-tipo"', html)
        return html.split('id="avance-por-tipo"', 1)[1].split("Por proceso de negocio")[0]

    def test_sin_cola_anterior_no_se_inventa_ningun_porcentaje(self):
        """Todas las remediaciones de prueba se detectaron hoy: no hay nada pendiente de
        antes del periodo, así que no hay avance que medir y se dan las dos cifras por
        separado, cada una con su unidad y su referencia de tiempo."""
        bloque = self._bloque()
        self.assertIn("Avance del periodo", bloque)
        self.assertNotIn("Porcentaje corregido", bloque)
        texto = _texto(bloque)
        self.assertIn("Sin porcentaje: no hay cola anterior con la que medirlo", texto)
        self.assertIn("(movimiento)", texto)
        self.assertIn("(foto de hoy)", texto)
        self.assertIn("No se dividen entre sí", texto)
        self.assertNotIn("corregido:", texto)

    def test_con_cola_anterior_el_porcentaje_es_de_la_misma_cohorte(self):
        """Se envejecen las remediaciones de los servidores y se cierra una dentro del
        periodo: el avance es 1 de 4 de ESA cola, no 1 entre 1 más lo pendiente de hoy."""
        with db.session(self.ruta) as conn:
            conn.execute("""UPDATE remediaciones SET detectado_at=
                            strftime('%Y-%m-%dT%H:%M:%SZ','now','-60 days')
                             WHERE activo_id IN (SELECT id FROM activos WHERE origen='servidores')""")
            conn.execute("""UPDATE remediaciones SET estado='corregida', corregido_at=?, version_final='1.2'
                             WHERE id=(SELECT MIN(id) FROM remediaciones
                                        WHERE activo_id IN (SELECT id FROM activos WHERE origen='servidores'))""",
                         (db.utcnow(),))
        try:
            bloque = self._bloque()
            servidores = _texto(bloque.split("Equipos de cómputo")[0])
            self.assertIn("25,0 %", servidores)
            self.assertIn("1 de 4 filas de remediación que ya estaban pendientes el", servidores)
            equipos = _texto(bloque.split("Equipos de cómputo", 1)[1])
            self.assertIn("Sin porcentaje: no hay cola anterior con la que medirlo", equipos)
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE remediaciones SET estado='abierta', corregido_at=NULL, version_final=NULL")
                conn.execute("UPDATE remediaciones SET detectado_at=?", (db.utcnow(),))

    def test_la_cola_anterior_se_calcula_por_tipo_de_maquina(self):
        from webui.vistas import remediaciones as vista
        with self.app.test_request_context("/remediaciones/"):
            from flask import g
            g.db = db.connect(self.ruta)
            try:
                cola = vista._cola_al_empezar(30)
            finally:
                g.db.close()
        self.assertIn("servidores", cola)
        self.assertIn("equipos", cola)
        self.assertEqual(cola["servidores"], {"cohorte": 0, "corregidas": 0})
        self.assertTrue(str(cola["desde"]).startswith(str(date.today().year)))


class TestConcordanciaFichaDelActivo(BaseTableros):
    """Punto 11 (menor): «1 actualización que cubren N vulnerabilidades»."""

    def test_una_sola_actualizacion_dice_que_cubre_en_singular(self):
        html = self._html(f"/activos/{self.activos['srv-sin-proceso']}")
        texto = _texto(html)
        self.assertIn("1 actualización que cubre ", texto)
        self.assertNotIn("1 actualización que cubren", texto)

    def test_varias_actualizaciones_siguen_en_plural(self):
        plantilla = (BASE_DIR / "webui" / "templates" / "_remediaciones_activo.html").read_text(encoding="utf-8")
        self.assertIn("{{ 'cubre' if act.total == 1 else 'cubren' }}", plantilla)


if __name__ == "__main__":
    unittest.main()
