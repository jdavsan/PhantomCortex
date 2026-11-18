"""La severidad baja no cuenta en nada (orden del usuario del 2026-09-10).

Literal del usuario: «las amenazas y vulnerabilidades de severidad baja no se deben tener
en cuenta en absolutamente nada, así que no cuentan, recuerde que solo es lo de severidad
crítica, alta y media».

Hasta el 2026-09-09 la regla estaba aplicada en Amenazas, el Panel, Tendencias, la página
de Activos, el resumen semanal y el informe mensual, pero NO en la cola de trabajo
(Remediación), ni en «Correcciones pendientes», ni en los parches de Windows, ni en el
inventario de componentes, ni en el plan de remediación. Estas pruebas fijan las dos
mitades de la regla:

* con el ajuste ``ignore_low_severity`` activo (lo normal) una vulnerabilidad de severidad
  baja no está en ninguna cifra, ninguna lista, ninguna gráfica, ningún documento ni
  ninguna exportación, y un activo cuyas ÚNICAS pendientes son bajas no cuenta como activo
  con pendientes;
* con el ajuste DESACTIVADO vuelve a aparecer en todo, sin migración ninguna, porque nada
  se borra de la base y la sincronización sigue abriendo la remediación (decisión escrita
  en ``threatintel.remediacion.sincronizar``).

Y la distinción que hay que conservar: las funciones de EVALUACIÓN siguen evaluando y
guardando la severidad baja (es un hecho comprobado contra OCS Inventory, y la severidad de
un CVE cambia con el tiempo). Lo que no hace es contarse ni mostrarse.

Sin red: todo se inserta a mano en una base temporal bajo ``data/``.
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import aplicabilidad, db, msrc, parches, remediacion, sbom
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from tests import test_remediacion_agrupada as base  # noqa: E402
from webui import auth  # noqa: E402

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)

CLAVE = "ClaveSegura#2026"

#: La palabra que ninguna pantalla puede volver a escribir mientras el ajuste esté activo.
PALABRA_PROHIBIDA = "severidad baja"


def _sin_bajas(conn, activo: bool = True) -> None:
    """Deja el ajuste ``ignore_low_severity`` en el estado pedido."""
    db.set_setting(conn, "ignore_low_severity", bool(activo))


class BaseSeveridadBaja(unittest.TestCase):
    """Parque mínimo con las cuatro severidades y los casos límite del encargo.

    * ``srv_mixto``: un servidor con una crítica, una alta, una media y una baja del mismo
      paquete (openssl). La baja pide la versión MÁS ALTA a propósito: si contara, sería
      ella la que fijara la versión objetivo del grupo y la orden del plan.
    * ``pc_solo_baja``: un equipo de cómputo cuya ÚNICA pendiente es de severidad baja. No
      puede contar como activo con pendientes.
    * ``pc_windows``: un equipo con dos vulnerabilidades del motor de parches de Microsoft,
      una alta y una baja.
    """

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "severidad_baja.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                              nombre="Jefa Administradora", actor="t")
            cls.srv_mixto = base._activo(conn, "srv-mixto-01", ip="10.0.0.31")
            base._software(conn, cls.srv_mixto, "openssl", "3.0.1")
            cls.amenazas = {}
            # La baja pide 3.0.9, más alta que la crítica (3.0.6): si contara, la versión
            # objetivo del grupo y la orden del plan saldrían de una vulnerabilidad que no
            # se reporta.
            for cve, severidad, corregida in (
                    ("CVE-2026-8001", "Critical", "3.0.6"),
                    ("CVE-2026-8002", "High", "3.0.5"),
                    ("CVE-2026-8003", "Medium", "3.0.4"),
                    ("CVE-2026-8004", "Low", "3.0.9")):
                t = base._amenaza(conn, cve, severity=severidad)
                cls.amenazas[cve] = t
                base._remediacion(conn, cls.srv_mixto, t, cve, "openssl", "3.0.1",
                                  corregida, aviso=f"DSA-{cve[-4:]}")
            # Equipo de cómputo con una sola pendiente, de severidad baja.
            cls.pc_solo_baja = base._activo(conn, "PC-solo-baja", origen="equipos",
                                            proceso="Mantenimiento", ip="10.1.1.61")
            base._software(conn, cls.pc_solo_baja, "curl", "7.80.0")
            t = base._amenaza(conn, "CVE-2026-8005", severity="Low")
            cls.amenazas["CVE-2026-8005"] = t
            base._remediacion(conn, cls.pc_solo_baja, t, "CVE-2026-8005", "curl",
                              "7.80.0", "7.81.0", aviso="DSA-8005")
            # Equipo Windows con el motor de parches de Microsoft: una alta y una baja.
            cls.pc_windows = base._activo(conn, "PC-windows-01", familia="windows",
                                          origen="equipos", proceso="Mantenimiento",
                                          ip="10.1.1.62")
            # Nombre y rama de compilación reales: el motor de Microsoft empareja el
            # activo con su producto por la rama de la compilación y por si es servidor o
            # puesto (``msrc.elegir_producto``), así que sin estos dos datos el equipo se
            # queda sin producto y no habría nada que contar.
            conn.execute("UPDATE activos SET so_nombre=?, so_version=?, windows_build=?, "
                         "windows_kb=?, windows_kb_publicado=?, arquitectura=? WHERE id=?",
                         ("Windows 11 Version 24H2", "10.0.26100", "10.0.26100.1000",
                          "KB5000001", "2026-08-11T07:00:00Z", "x86 64 bit",
                          cls.pc_windows))
            conn.execute(
                """INSERT INTO msrc_correcciones(cve, producto_id, producto, kb,
                        build_corregida, documento, publicado_at)
                   VALUES('CVE-2026-8101','11-24H2-x64',
                          'Windows 11 Version 24H2 for x64-based Systems','KB5000002',
                          '10.0.26100.2000','2026-Sep','2026-09-01T07:00:00Z')""")
            for cve, severidad in (("CVE-2026-8101", "High"), ("CVE-2026-8102", "Low")):
                t = base._amenaza(conn, cve, severity=severidad)
                cls.amenazas[cve] = t
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor,
                            evidencia, evaluado_at)
                       VALUES(?,?,?,'windows','10.0.26100.1000','10.0.26100.2000',
                              'afectado','msrc','prueba',?)""",
                    (cls.pc_windows, t, cve, db.utcnow()))
            # «Correcciones pendientes»: dos filas en seguimiento, una alta y una baja.
            for cve, severidad in (("CVE-2026-8201", "High"), ("CVE-2026-8202", "Low")):
                t = base._amenaza(conn, cve, severity=severidad)
                cls.amenazas[cve] = t
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor,
                            evidencia, evaluado_at)
                       VALUES(?,?,?,'nginx','1.20.0',NULL,'afectado','osv','prueba',?)""",
                    (cls.srv_mixto, t, cve, db.utcnow()))
                conn.execute(
                    """INSERT INTO parches_pendientes(cve, paquete, ecosistema, threat_id,
                            motivo, n_activos, n_activos_expuestos, detectado_at)
                       VALUES(?, 'nginx', 'debian', ?, 'sin_parche_publicado', 1, 1, ?)""",
                    (cve, t, db.utcnow()))
            # Inventario de componentes (SBOM): un componente con una alta y una baja.
            for cve, severidad in (("CVE-2026-8301", "High"), ("CVE-2026-8302", "Low")):
                t = base._amenaza(conn, cve, severity=severidad)
                cls.amenazas[cve] = t
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor,
                            evidencia, evaluado_at)
                       VALUES(?,?,?,'lodash','4.17.20','4.17.21','afectado','sbom',
                              'prueba',?)""",
                    (cls.srv_mixto, t, cve, db.utcnow()))
            conn.execute(
                """INSERT INTO activo_componentes(activo_id, nombre, version, ecosistema,
                        fichero, importado_at)
                   VALUES(?, 'lodash', '4.17.20', 'npm', 'sbom.json', ?)""",
                (cls.srv_mixto, db.utcnow()))
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        self.conn = db.connect(self.ruta)
        self.addCleanup(self.conn.close)
        # Cada prueba empieza con el ajuste en su valor normal (activo).
        _sin_bajas(self.conn, True)
        self.addCleanup(lambda: _sin_bajas(db.connect(self.ruta), True))

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


# ==========================================================================
# 1. Remediación: la cola de trabajo
# ==========================================================================
class TestRemediacionSinBajas(BaseSeveridadBaja):

    def test_la_tabla_conserva_las_bajas_pero_las_cifras_no_las_cuentan(self):
        """Nada se borra de la base: las cinco filas siguen ahí (regla 4 del encargo)."""
        self.assertEqual(int(self.conn.execute(
            "SELECT COUNT(*) FROM remediaciones WHERE estado='abierta'").fetchone()[0]), 5)
        res = remediacion.resumen(self.conn, dias=30)
        self.assertEqual(res["abiertas"], 3, "tres filas: crítica, alta y media")
        self.assertEqual(res["vulnerabilidades_unicas"], 3)
        self.assertEqual(res["cve_distintos"], 3)
        self.assertEqual(res["actualizaciones"], 1, "un solo paquete que actualizar")
        self.assertTrue(res["sin_bajas"])

    def test_un_activo_con_solo_bajas_no_cuenta_como_activo_con_pendientes(self):
        res = remediacion.resumen(self.conn, dias=30)
        self.assertEqual(res["activos_con_abiertas"], 1, "solo el servidor mixto")
        self.assertEqual(res["servidores_con_abiertas"], 1)
        self.assertEqual(res["equipos_con_abiertas"], 0,
                         "el equipo cuya única pendiente es baja no cuenta")
        nombres = {g["activo_nombre"]
                   for g in remediacion.listar_actualizaciones(self.conn, limite=50)}
        self.assertNotIn("PC-solo-baja", nombres)

    def test_la_version_objetivo_no_sale_de_una_vulnerabilidad_baja(self):
        """La baja pedía 3.0.9, más alta que la crítica: si contara, la orden mandaría
        instalar una versión por algo que no se reporta."""
        grupo = remediacion.listar_actualizaciones(self.conn, limite=50)[0]
        self.assertEqual(grupo["version_objetivo"], "3.0.6")
        self.assertEqual(grupo["vulnerabilidades"], 3)
        self.assertNotIn("CVE-2026-8004", [c["cve"] for c in grupo["cves"]])
        self.assertNotIn("3.0.9", [v["version"] for v in grupo["versiones"]])

    def test_el_reparto_por_proceso_no_cuenta_las_bajas(self):
        res = remediacion.resumen(self.conn, dias=30)
        por_proceso = {p["proceso"]: p for p in res["por_proceso"]}
        self.assertEqual(sorted(por_proceso), ["Pila"],
                         "el proceso cuyas únicas pendientes son bajas no aparece")
        self.assertEqual(por_proceso["Pila"]["abiertas"], 3)
        self.assertEqual(por_proceso["Pila"]["activos_con_abiertas"], 1)
        self.assertNotIn("Mantenimiento", remediacion.procesos(self.conn))

    def test_el_avance_por_tipo_de_maquina_no_cuenta_las_bajas(self):
        servidores = remediacion.resumen(self.conn, dias=30, origen="servidores",
                                         solo_cifras=True)
        equipos = remediacion.resumen(self.conn, dias=30, origen="equipos",
                                      solo_cifras=True)
        self.assertEqual((servidores["abiertas"], servidores["vulnerabilidades_unicas"],
                          servidores["activos_con_abiertas"]), (3, 3, 1))
        self.assertEqual((equipos["abiertas"], equipos["vulnerabilidades_unicas"],
                          equipos["activos_con_abiertas"]), (0, 0, 0),
                         "el único equipo con pendientes solo tiene una baja")
        # Y las dos partes suman el total, sin dejar filas sueltas por el camino.
        total = remediacion.resumen(self.conn, dias=30, solo_cifras=True)
        self.assertEqual(servidores["abiertas"] + equipos["abiertas"], total["abiertas"])

    def test_la_grafica_semanal_no_cuenta_las_bajas(self):
        semanas = remediacion.resumen(self.conn, dias=30)["semanas"]
        self.assertTrue(semanas, "la gráfica tiene datos")
        self.assertEqual(sum(s["detectadas"] for s in semanas), 3,
                         "las dos bajas no están en ninguna barra")
        self.assertEqual(sum(s["corregidas"] for s in semanas), 0)

    def test_el_historial_del_activo_y_su_total_no_traen_la_baja(self):
        self.assertEqual(remediacion.contar_historial_activo(self.conn, self.srv_mixto), 3)
        historial = remediacion.historial_activo(self.conn, self.srv_mixto, limite=100)
        self.assertEqual(len(historial), 3)
        self.assertNotIn("CVE-2026-8004", [h["cve"] for h in historial])
        # El equipo cuya única pendiente es baja no tiene historial que mostrar.
        self.assertEqual(remediacion.contar_historial_activo(self.conn, self.pc_solo_baja), 0)
        self.assertEqual(remediacion.historial_activo(self.conn, self.pc_solo_baja), [])

    def test_la_pagina_y_el_csv_no_traen_ninguna_baja(self):
        html = self._html("/remediaciones/")
        self.assertNotIn("CVE-2026-8004", html)
        self.assertNotIn("CVE-2026-8005", html)
        self.assertNotIn(PALABRA_PROHIBIDA, html.lower())
        r = self._cliente().get("/remediaciones/exportar.csv?estado=abierta")
        self.assertEqual(r.status_code, 200)
        csv = r.get_data(as_text=True)
        self.assertEqual(len([l for l in csv.splitlines() if l.strip()]) - 1, 3)
        self.assertNotIn("Low", csv)
        self.assertNotIn("CVE-2026-8004", csv)

    def test_la_accion_de_grupo_no_toca_las_filas_de_severidad_baja(self):
        """Si la baja no se ve, la acción de grupo tampoco puede actuar sobre ella: el
        mensaje diría un número de vulnerabilidades que no está en ninguna pantalla."""
        una = self.conn.execute(
            "SELECT id FROM remediaciones WHERE cve='CVE-2026-8001'").fetchone()[0]
        grupo = remediacion._remediaciones_del_grupo(self.conn, una)
        self.assertEqual(grupo["cves"], 3)
        self.assertEqual(len(grupo["ids"]), 3)
        baja = self.conn.execute(
            "SELECT id FROM remediaciones WHERE cve='CVE-2026-8004'").fetchone()[0]
        self.assertNotIn(int(baja), grupo["ids"])


# ==========================================================================
# 2. El plan de remediación y su descarga en texto
# ==========================================================================
class TestPlanSinBajas(BaseSeveridadBaja):

    def test_el_plan_de_un_activo_no_incluye_la_baja(self):
        plan = aplicabilidad.plan_remediacion(self.conn, activo_id=self.srv_mixto)
        self.assertNotIn("CVE-2026-8004", plan["cves"])
        self.assertEqual(plan["total_activos"], 1)
        versiones = {g["corregida"] for g in plan["grupos"]}
        self.assertNotIn("3.0.9", versiones, "la versión que pedía la baja no manda")

    def test_la_descarga_en_texto_trae_lo_mismo_que_la_pagina(self):
        plan = aplicabilidad.plan_remediacion(self.conn, activo_id=self.srv_mixto)
        texto = aplicabilidad.plan_remediacion_texto(plan, titulo="Plan de prueba")
        self.assertNotIn("CVE-2026-8004", texto)
        self.assertNotIn("3.0.9", texto)
        self.assertNotIn(PALABRA_PROHIBIDA, texto.lower())
        # Los bloques del fichero son los grupos de la página: ni uno más.
        self.assertIn(f"Actualizaciones por aplicar: {len(plan['grupos'])}", texto)

    def test_el_plan_de_una_amenaza_baja_no_lista_activos(self):
        vacio = aplicabilidad.plan_remediacion(
            self.conn, threat_id=self.amenazas["CVE-2026-8004"])
        self.assertEqual(vacio["grupos"], [])
        self.assertEqual(vacio["total_activos"], 0)
        lleno = aplicabilidad.plan_remediacion(
            self.conn, threat_id=self.amenazas["CVE-2026-8001"])
        self.assertEqual(lleno["total_activos"], 1)

    def test_las_cifras_del_activo_no_cuentan_la_baja(self):
        conteo = aplicabilidad.conteo_activo(self.conn, self.srv_mixto)
        self.assertEqual(conteo["afectado"], 5,
                         "de openssl la crítica, la alta y la media; de nginx y del "
                         "componente, solo la alta de cada uno")
        cves = [v["cve"] for v in aplicabilidad.vulnerabilidades_activo(
            self.conn, self.srv_mixto, limite=100)]
        self.assertNotIn("CVE-2026-8004", cves)
        self.assertNotIn("CVE-2026-8302", cves)
        # El total que pagina la lista de veredictos cuenta lo mismo que la lista.
        total = aplicabilidad.contar_veredictos_activo(self.conn, self.srv_mixto)
        self.assertEqual(len(aplicabilidad.veredictos_de_activo(
            self.conn, self.srv_mixto, limite=1000)), total)

    def test_la_ultima_version_a_instalar_no_sale_de_una_baja(self):
        mapa = aplicabilidad.versiones_pedidas_por_paquete(
            self.conn, [(self.srv_mixto, "openssl")])
        info = mapa[(self.srv_mixto, "openssl")]
        self.assertEqual(info["version_objetivo"], "3.0.6")
        self.assertEqual(info["versiones_pedidas"], 3)
        self.assertEqual(info["vulnerabilidades"], 3)


# ==========================================================================
# 3. Correcciones pendientes, parches de Windows e inventario de componentes
# ==========================================================================
class TestOtrasPantallasSinBajas(BaseSeveridadBaja):

    def test_correcciones_pendientes_no_cuenta_la_baja(self):
        res = parches.resumen(self.conn)
        self.assertEqual(res["en_seguimiento"], 1, "solo la alta")
        self.assertEqual(res["por_motivo"]["sin_parche_publicado"], 1)
        self.assertEqual(parches.contar(self.conn, estado="seguimiento"), 1)
        filas = parches.listar(self.conn, estado="seguimiento", limite=100)
        self.assertEqual([f["cve"] for f in filas], ["CVE-2026-8201"])
        sin_correccion = parches.sin_correccion(self.conn)
        self.assertEqual(sin_correccion["total"], 1)
        self.assertNotIn("CVE-2026-8202",
                         [f["cve"] for g in sin_correccion["grupos"] for f in g["muestra"]])

    def test_el_correo_diario_no_anuncia_una_correccion_de_severidad_baja(self):
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE parches_pendientes SET encontrado_at=?, "
                         "version_corregida='1.20.2' WHERE avisado_at IS NULL",
                         (db.utcnow(),))
        try:
            novedades = parches.novedades(self.conn)
            self.assertEqual([n["cve"] for n in novedades], ["CVE-2026-8201"])
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE parches_pendientes SET encontrado_at=NULL, "
                             "version_corregida=NULL")

    def test_la_pagina_de_correcciones_pendientes_no_nombra_la_baja(self):
        html = self._html("/parches-pendientes/")
        self.assertIn("CVE-2026-8201", html)
        self.assertNotIn("CVE-2026-8202", html)
        self.assertNotIn(PALABRA_PROHIBIDA, html.lower())

    def test_los_parches_de_windows_no_cuentan_la_baja(self):
        activo = dict(self.conn.execute("SELECT * FROM activos WHERE id=?",
                                        (self.pc_windows,)).fetchone())
        res = msrc.resumen_activo(self.conn, activo)
        self.assertTrue(res["aplica"])
        self.assertEqual(res["n_afectados"], 1, "solo la alta")
        self.assertEqual(res["n_corregidos"], 0)
        self.assertEqual(res["n_sin_dato"], 0)

    def test_el_inventario_de_componentes_no_cuenta_la_baja(self):
        res = sbom.resumen_activo(self.conn, self.srv_mixto)
        self.assertEqual(res["vulnerabilidades"], 1, "solo la alta del componente")

    def test_la_ficha_del_activo_no_nombra_la_baja(self):
        html = self._html(f"/activos/{self.srv_mixto}")
        self.assertNotIn("CVE-2026-8004", html)
        self.assertNotIn(PALABRA_PROHIBIDA, html.lower())


# ==========================================================================
# 4. Con el ajuste desactivado, todo vuelve a aparecer sin migración
# ==========================================================================
class TestConElAjusteDesactivado(BaseSeveridadBaja):
    """Regla 4 del encargo: las bajas que ya están en la base no se borran; si el ajuste se
    desactivara, reaparecen sin migración ninguna."""

    def setUp(self):
        super().setUp()
        _sin_bajas(self.conn, False)

    def test_remediacion_vuelve_a_contarlas_todas(self):
        res = remediacion.resumen(self.conn, dias=30)
        self.assertEqual(res["abiertas"], 5)
        self.assertEqual(res["vulnerabilidades_unicas"], 5)
        self.assertEqual(res["cve_distintos"], 5)
        self.assertEqual(res["activos_con_abiertas"], 2)
        self.assertEqual(res["equipos_con_abiertas"], 1)
        self.assertFalse(res["sin_bajas"])
        self.assertEqual(sum(s["detectadas"] for s in res["semanas"]), 5)
        self.assertEqual(remediacion.contar(self.conn, estado="abierta"), 5)
        self.assertEqual(remediacion.contar_historial_activo(self.conn, self.pc_solo_baja), 1)

    def test_el_grupo_vuelve_a_pedir_la_version_mas_alta_de_todas(self):
        grupos = remediacion.listar_actualizaciones(self.conn, limite=50)
        openssl = next(g for g in grupos if g["paquete"] == "openssl")
        self.assertEqual(openssl["vulnerabilidades"], 4)
        self.assertEqual(openssl["version_objetivo"], "3.0.9")
        self.assertIn("PC-solo-baja", {g["activo_nombre"] for g in grupos})

    def test_el_plan_y_las_otras_pantallas_vuelven_a_incluirla(self):
        plan = aplicabilidad.plan_remediacion(self.conn, activo_id=self.srv_mixto)
        self.assertIn("CVE-2026-8004", plan["cves"])
        texto = aplicabilidad.plan_remediacion_texto(plan, titulo="Plan de prueba")
        self.assertIn("CVE-2026-8004", texto)
        self.assertEqual(parches.resumen(self.conn)["en_seguimiento"], 2)
        self.assertEqual(parches.contar(self.conn, estado="seguimiento"), 2)
        activo = dict(self.conn.execute("SELECT * FROM activos WHERE id=?",
                                        (self.pc_windows,)).fetchone())
        self.assertEqual(msrc.resumen_activo(self.conn, activo)["n_afectados"], 2)
        self.assertEqual(sbom.resumen_activo(self.conn, self.srv_mixto)["vulnerabilidades"], 2)
        self.assertEqual(aplicabilidad.conteo_activo(self.conn, self.srv_mixto)["afectado"], 8,
                         "las cuatro de openssl, las dos de nginx y las dos del componente")
        self.assertIn("CVE-2026-8004",
                      [v["cve"] for v in aplicabilidad.vulnerabilidades_activo(
                          self.conn, self.srv_mixto, limite=100)])

    def test_la_pagina_de_remediacion_vuelve_a_listarla(self):
        html = self._html("/remediaciones/?vista=vulnerabilidad")
        self.assertIn("CVE-2026-8004", html)
        r = self._cliente().get("/remediaciones/exportar.csv?estado=abierta")
        self.assertEqual(len([l for l in r.get_data(as_text=True).splitlines()
                              if l.strip()]) - 1, 5)


# ==========================================================================
# 5. Evaluar no es contar: la evaluación sigue viendo la severidad baja
# ==========================================================================
class TestEvaluarNoEsContar(BaseSeveridadBaja):

    def test_los_veredictos_de_severidad_baja_siguen_guardados(self):
        """La evaluación es un hecho comprobado contra OCS Inventory y no se pierde: la
        severidad de un CVE cambia (un fallo bajo sube a alto cuando llega la puntuación
        oficial o entra en el catálogo KEV), y ese día tiene que aparecer con su
        antigüedad verdadera."""
        filas = self.conn.execute(
            "SELECT COUNT(*) FROM aplicabilidad WHERE cve IN ('CVE-2026-8004','CVE-2026-8005')"
        ).fetchone()[0]
        self.assertEqual(filas, 2, "los veredictos de las bajas siguen en la base")
        abiertas = self.conn.execute(
            "SELECT COUNT(*) FROM remediaciones WHERE cve IN "
            "('CVE-2026-8004','CVE-2026-8005') AND estado='abierta'").fetchone()[0]
        self.assertEqual(abiertas, 2, "la sincronización no dejó de abrirlas")

    def test_al_subir_de_severidad_aparece_con_su_fecha_de_deteccion(self):
        """Es la razón de que ``sincronizar`` siga abriendo las bajas: el día que el CVE
        sube de severidad, la remediación ya existe con su antigüedad real."""
        antes = remediacion.resumen(self.conn, dias=30)["abiertas"]
        detectado = self.conn.execute(
            "SELECT detectado_at FROM remediaciones WHERE cve='CVE-2026-8004'").fetchone()[0]
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE threats SET severity='Critical' WHERE cve='CVE-2026-8004'")
        try:
            res = remediacion.resumen(self.conn, dias=30)
            self.assertEqual(res["abiertas"], antes + 1)
            fila = next(f for f in remediacion.listar(self.conn, estado="abierta", limite=100)
                        if f["cve"] == "CVE-2026-8004")
            self.assertEqual(fila["detectado_at"], detectado,
                             "conserva la fecha de detección original")
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE threats SET severity='Low' WHERE cve='CVE-2026-8004'")


if __name__ == "__main__":
    unittest.main()
