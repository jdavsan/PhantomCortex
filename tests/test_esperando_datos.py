"""Trabajo que nadie puede hacer: «esperando datos del inventario» (2026-09-10, esquema v14).

Defecto medido sobre la base real el 2026-09-10: **2.480 remediaciones abiertas sin
ninguna vulnerabilidad confirmada detrás** (2.477 dejando fuera la severidad baja, que no
cuenta en nada). Todas del motor de parches de Microsoft (``msrc``, paquete ``windows``) y
de **cuatro equipos de cómputo** —``PC-705``, ``PC-712``, ``PC-763`` y
``PC-833``, identificadores 705, 712, 763 y 833— con Windows 11 (``so_version``
10.0.26200) y ``windows_build`` nulo: OCS Inventory no informa de ninguna actualización
acumulativa reconocida, así que el motor no puede calcular la compilación instalada y la
evaluación de hoy responde ``sin_dato`` a las 2.480. No es un fallo de lectura de la
familia: de los 37 activos con esa versión, 33 sí informan su compilación.

Decisión tomada con el usuario, y que estas pruebas fijan como contrato:

* **No se cierran.** Nadie ha comprobado que estén corregidas; cerrarlas sería mentir.
* **No cuentan como trabajo pendiente.** Nadie puede hacerlas: salen de la cola, de las
  cifras, de la vista agrupada y de la gráfica.
* **Se distinguen los dos casos** en ``remediacion.sincronizar``: si la evaluación de hoy
  dice que ya NO afecta, se cierra con su evidencia y su motivo; si dice «sin dato», pasa
  a ``esperando_datos``.
* **Es reversible sin intervención**: en cuanto la evaluación vuelve a confirmar, la
  remediación regresa a la cola **con su fecha de detección original**.
* **Se ataca la causa**: los activos aparecen en la página de Activos con el hallazgo
  «Sin datos de actualizaciones de Windows», para que Servicios Tecnológicos revise su
  agente. El rótulo se llamaba «Sin datos suficientes de Windows» hasta el 2026-09-15:
  se renombró en la revisión de claridad porque esa cifra (activos con el agente
  incompleto) y la de Remediación («vulnerabilidades esperando datos del inventario»)
  cuentan cosas distintas y se leían como dos versiones del mismo número.

Base temporal bajo ``data/``, sin red y sin correo.
"""
from __future__ import annotations

import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatintel import db, ocs, remediacion
from threatintel.paths import BASE_DIR
from webui import auth

CLAVE = "AdminSeguro#2026"
RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


AHORA = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
T0 = _iso(AHORA - timedelta(days=40))     # detección original
T1 = _iso(AHORA - timedelta(days=20))
T2 = _iso(AHORA)
T3 = _iso(AHORA + timedelta(days=1))


class CfgFalso(dict):
    def get(self, clave, defecto=None):
        return super().get(clave, defecto)


class BaseEspera(unittest.TestCase):
    """Un equipo de cómputo con Windows 11 y la compilación desconocida (el caso de
    producción), otro con la compilación conocida y un servidor Ubuntu de control."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "espera.db")
        db.init_db(self.ruta)
        self.conn = db.connect(self.ruta)
        c = self.conn
        auth.crear_usuario(c, "admin", CLAVE, rol="admin", actor="t")
        # 1: equipo con Windows 11 sin compilación reconocida (PC-705 en producción)
        # 2: equipo con Windows 11 y compilación conocida (los 33 que sí informan)
        # 3: servidor Ubuntu de control
        for (aid, origen, nombre, familia, so_nombre, version, build, kb) in (
                (1, "equipos", "PC-SIN-COMPILACION", "windows", "Windows 11 Pro",
                 "10.0.26200", None, None),
                (2, "equipos", "PC-CON-COMPILACION", "windows", "Windows 11 Pro",
                 "10.0.26200", "10.0.26200.1200", "KB5065426"),
                (3, "servidores", "SRV-UBUNTU", "ubuntu", "Ubuntu 22.04",
                 "22.04", None, None)):
            c.execute(
                """INSERT INTO activos(id, origen, ocs_id, nombre, so_familia, so_nombre,
                                       so_version, windows_build, windows_kb, entorno,
                                       proceso, presente, primera_vez_at, visto_at,
                                       ultimo_inventario, n_software)
                   VALUES(?,?,?,?,?,?,?,?,?,'produccion','Contabilidad',1,?,?,?,3)""",
                (aid, origen, aid * 10, nombre, familia, so_nombre, version, build, kb,
                 T0, T2, T2))
        for idx, (cve, severidad) in enumerate(
                (("CVE-2026-30001", "Critical"), ("CVE-2026-30002", "High"),
                 ("CVE-2026-30003", "Low"), ("CVE-2026-30004", "High")), start=1):
            c.execute(
                """INSERT INTO threats(id, fingerprint, cve, title_en, title_es, severity,
                                       first_seen_at, last_seen_at, month, estado, in_kev)
                   VALUES(?,?,?,?,?,?,?,?,?,'nueva',0)""",
                (idx, f"fp-{idx}", cve, f"Fallo {idx}", f"Fallo {idx}", severidad,
                 T0, T0, T0[:7]))
        c.execute("INSERT INTO activo_software(activo_id, nombre, nombre_norm, version) "
                  "VALUES(3,'curl','curl','7.81.0')")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    # ------------------------------------------------------------------ ayudas
    def _veredicto(self, activo_id, threat_id, cve, paquete, veredicto, *,
                   instalada=None, corregida=None, motor="msrc", evaluado_at=T0,
                   evidencia="El equipo no tiene ninguna actualización acumulativa reconocida"):
        self.conn.execute(
            """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada,
                                         version_corregida, veredicto, motor, evidencia, evaluado_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(activo_id, cve, paquete) DO UPDATE SET
                   veredicto=excluded.veredicto, version_instalada=excluded.version_instalada,
                   version_corregida=excluded.version_corregida, evidencia=excluded.evidencia,
                   evaluado_at=excluded.evaluado_at""",
            (activo_id, threat_id, cve, paquete, instalada, corregida, veredicto, motor,
             evidencia, evaluado_at))

    def _fila(self, activo_id, cve, paquete="windows"):
        r = self.conn.execute(
            "SELECT * FROM remediaciones WHERE activo_id=? AND cve=? AND paquete=?",
            (activo_id, cve, paquete)).fetchone()
        return dict(r) if r else None

    def _abrir_las_tres(self):
        """Tres remediaciones de Windows en el equipo 1 (dos que se reportan y una baja)
        y una en el equipo 2, todas confirmadas."""
        for tid, cve in ((1, "CVE-2026-30001"), (2, "CVE-2026-30002"), (3, "CVE-2026-30003")):
            self._veredicto(1, tid, cve, "windows", "afectado",
                            instalada="10.0.26200.1000", corregida="10.0.26200.1200")
        self._veredicto(2, 1, "CVE-2026-30001", "windows", "afectado",
                        instalada="10.0.26200.1000", corregida="10.0.26200.1200")
        remediacion.sincronizar(self.conn, ahora=T1)
        self.conn.commit()

    def _todas_sin_dato(self):
        """La evaluación de hoy no puede decidir en el equipo 1 (compilación desconocida)."""
        for tid, cve in ((1, "CVE-2026-30001"), (2, "CVE-2026-30002"), (3, "CVE-2026-30003")):
            self._veredicto(1, tid, cve, "windows", "sin_dato", evaluado_at=T2)
        self.conn.commit()

    def _cliente(self):
        from webui.app import crear_app
        app = crear_app(db_path=self.ruta, testing=True)
        cli = app.test_client()
        respuesta = cli.post("/login", data={"usuario": "admin", "password": CLAVE})
        self.assertIn(respuesta.status_code, (302, 303))
        return cli


# ==========================================================================
class TestSincronizarDistingueLosDosCasos(BaseEspera):

    def test_sin_dato_no_cierra_y_sale_de_la_cola(self):
        self._abrir_las_tres()
        antes = remediacion.resumen(self.conn, dias=30)
        deteccion = self._fila(1, "CVE-2026-30001")["detectado_at"]
        self._todas_sin_dato()
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.commit()
        self.assertEqual(r["cerradas"], 0, "no se cierra ninguna: nadie lo ha comprobado")
        self.assertEqual(r["esperando_datos_nuevas"], 3)
        self.assertEqual(r["esperando_datos"], 3)
        for cve in ("CVE-2026-30001", "CVE-2026-30002", "CVE-2026-30003"):
            fila = self._fila(1, cve)
            self.assertEqual(fila["estado"], "esperando_datos")
            self.assertIsNone(fila["corregido_at"], "no se cierra")
            self.assertIsNone(fila["version_final"])
            self.assertIn("no pudo decidir si sigue afectado", fila["cerrado_motivo"])
            self.assertIn("El equipo no tiene ninguna actualización acumulativa reconocida",
                          fila["cerrado_motivo"], "el motivo lleva la evidencia")
        self.assertEqual(self._fila(1, "CVE-2026-30001")["detectado_at"], deteccion,
                         "la fecha de detección original no se toca")
        despues = remediacion.resumen(self.conn, dias=30)
        # Dos de las tres se reportan (la tercera es de severidad baja y ya no contaba).
        self.assertEqual(antes["abiertas"] - despues["abiertas"], 2)
        self.assertEqual(despues["esperando_datos"], 2)
        self.assertEqual(despues["esperando_datos_activos"], 1)
        self.assertEqual(despues["esperando_datos_vulnerabilidades"], 2)
        self.assertEqual(despues["activos_con_abiertas"], 1, "solo queda el equipo 2")

    def test_no_afectado_si_se_cierra_con_su_evidencia(self):
        """El otro caso: la evaluación de hoy dice que YA NO afecta. Eso sí se cierra."""
        self._abrir_las_tres()
        self.conn.execute("UPDATE activos SET windows_build='10.0.26200.1200' WHERE id=1")
        self._veredicto(1, 1, "CVE-2026-30001", "windows", "no_afectado",
                        instalada="10.0.26200.1200", evaluado_at=T2)
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.commit()
        self.assertEqual(r["cerradas"], 1)
        fila = self._fila(1, "CVE-2026-30001")
        self.assertEqual(fila["estado"], "corregida")
        self.assertEqual(fila["version_final"], "10.0.26200.1200")
        self.assertIn("boletines de Microsoft", fila["cerrado_motivo"])

    def test_una_que_esperaba_se_cierra_si_la_evaluacion_dice_que_ya_no_afecta(self):
        """El agente vuelve a informar y la máquina resulta estar al día: se cierra con
        su evidencia, sin pasar por la cola."""
        self._abrir_las_tres()
        self._todas_sin_dato()
        remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.execute("UPDATE activos SET windows_build='10.0.26200.1200', "
                          "windows_kb='KB5065426' WHERE id=1")
        self._veredicto(1, 1, "CVE-2026-30001", "windows", "no_afectado",
                        instalada="10.0.26200.1200", evaluado_at=T3)
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.conn.commit()
        self.assertEqual(r["cerradas"], 1)
        fila = self._fila(1, "CVE-2026-30001")
        self.assertEqual(fila["estado"], "corregida")
        self.assertIn("KB5065426", fila["cerrado_motivo"], "la evidencia nombra la acumulativa")

    def test_vuelve_a_la_cola_con_su_fecha_de_deteccion_original(self):
        self._abrir_las_tres()
        deteccion = self._fila(1, "CVE-2026-30001")["detectado_at"]
        self._todas_sin_dato()
        remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.commit()
        self.assertEqual(remediacion.resumen(self.conn)["esperando_datos"], 2)
        # El agente vuelve a informar y sigue afectada.
        self.conn.execute("UPDATE activos SET windows_build='10.0.26200.1000' WHERE id=1")
        self._veredicto(1, 1, "CVE-2026-30001", "windows", "afectado",
                        instalada="10.0.26200.1000", corregida="10.0.26200.1200",
                        evaluado_at=T3)
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.conn.commit()
        self.assertEqual(r["reabiertas"], 1)
        fila = self._fila(1, "CVE-2026-30001")
        self.assertEqual(fila["estado"], "abierta")
        self.assertEqual(fila["detectado_at"], deteccion,
                         "no es una detección nueva: nada se corrigió mientras esperaba")
        self.assertIn("Vuelve a la cola", fila["cerrado_motivo"])

    def test_dos_ejecuciones_seguidas_no_cambian_nada(self):
        self._abrir_las_tres()
        self._todas_sin_dato()
        remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.commit()
        antes = [dict(r) for r in self.conn.execute(
            "SELECT * FROM remediaciones ORDER BY id")]
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.commit()
        self.assertEqual(r["esperando_datos_nuevas"], 0)
        self.assertEqual(r["cerradas"], 0)
        self.assertEqual([dict(x) for x in self.conn.execute(
            "SELECT * FROM remediaciones ORDER BY id")], antes)

    def test_si_el_activo_desaparece_de_ocs_deja_de_esperar(self):
        self._abrir_las_tres()
        self._todas_sin_dato()
        remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.execute("UPDATE activos SET presente=0 WHERE id=1")
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.conn.commit()
        self.assertEqual(r["activo_ausente"], 3)
        self.assertEqual(r["esperando_datos"], 0)
        self.assertEqual(self._fila(1, "CVE-2026-30001")["estado"], "activo_ausente")

    def test_una_fila_afectada_gana_a_una_sin_dato_del_mismo_paquete(self):
        """Si el mismo (activo, CVE, paquete) tiene a la vez «afectado» y «sin dato» —dos
        motores— la vulnerabilidad está confirmada y la remediación NO sale de la cola."""
        self._abrir_las_tres()
        # El motor msrc pasa a «sin dato», pero otro motor la confirma con otro paquete
        # del mismo CVE: la fila de 'windows' es la que decide, así que se comprueba con
        # la MISMA clave (activo, CVE, paquete) y dos veredictos no caben. Se usa un
        # segundo CVE evaluado por dos motores distintos sobre el mismo paquete.
        self._veredicto(1, 4, "CVE-2026-30004", "windows", "afectado",
                        instalada="10.0.26200.1000", corregida="10.0.26200.1200",
                        evaluado_at=T2)
        remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.commit()
        self.assertEqual(self._fila(1, "CVE-2026-30004")["estado"], "abierta")

    def test_el_servidor_de_control_no_se_toca(self):
        self._veredicto(3, 2, "CVE-2026-30002", "curl", "afectado", motor="osv",
                        instalada="7.81.0", corregida="7.82.0")
        remediacion.sincronizar(self.conn, ahora=T1)
        self._abrir_las_tres()
        self._todas_sin_dato()
        remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.commit()
        self.assertEqual(self._fila(3, "CVE-2026-30002", "curl")["estado"], "abierta")


# ==========================================================================
class TestListaYCausa(BaseEspera):

    def test_la_lista_agrupa_por_activo_y_dice_que_hay_que_hacer(self):
        self._abrir_las_tres()
        self._todas_sin_dato()
        remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.commit()
        espera = remediacion.esperando_datos(self.conn)
        self.assertEqual(espera["total_activos"], 1)
        self.assertEqual(espera["total_filas"], 2, "la severidad baja no cuenta en nada")
        self.assertEqual(espera["total_vulnerabilidades"], 2)
        fila = espera["filas"][0]
        self.assertEqual(fila["activo_nombre"], "PC-SIN-COMPILACION")
        self.assertEqual(fila["origen_es"], "Equipo de cómputo")
        self.assertEqual(fila["filas"], 2)
        self.assertTrue(fila["solo_windows"])
        self.assertGreaterEqual(fila["dias"], 20, "cuenta desde la detección original")
        self.assertIn("acumulativa", fila["motivo"])

    def test_la_lista_se_acota_al_tipo_de_maquina(self):
        self._abrir_las_tres()
        self._todas_sin_dato()
        remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.commit()
        self.assertEqual(remediacion.esperando_datos(
            self.conn, origen="equipos")["total_activos"], 1)
        self.assertEqual(remediacion.esperando_datos(
            self.conn, origen="servidores")["total_activos"], 0)

    def test_sin_ninguna_la_lista_esta_vacia_y_no_falla(self):
        espera = remediacion.esperando_datos(self.conn)
        self.assertEqual(espera["filas"], [])
        self.assertEqual(espera["total_filas"], 0)
        self.assertFalse(espera["recortado"])

    def test_el_hallazgo_senala_el_activo_para_arreglar_la_causa(self):
        self._todas_sin_dato()
        resultado = ocs.detectar_hallazgos(self.conn, cfg=CfgFalso({"ocs_stale_days": 30}))
        self.conn.commit()
        self.assertEqual(resultado["sin_datos_windows"]["abiertos"], 1)
        fila = self.conn.execute(
            "SELECT activo_id, detalle FROM hallazgos_activos "
            "WHERE tipo='sin_datos_windows' AND resuelto_at IS NULL").fetchone()
        self.assertEqual(fila["activo_id"], 1)
        self.assertIn("no informa de ninguna actualización acumulativa", fila["detalle"])
        self.assertIn("Windows 11 Pro 10.0.26200", fila["detalle"])
        self.assertIn("sin_datos_windows", ocs.TIPO_HALLAZGO_ES)
        self.assertIn("agente de OCS Inventory", ocs.TIPO_HALLAZGO_EXPLICACION["sin_datos_windows"])

    def test_el_hallazgo_se_cierra_solo_cuando_vuelven_los_datos(self):
        self._todas_sin_dato()
        cfg = CfgFalso({"ocs_stale_days": 30})
        ocs.detectar_hallazgos(self.conn, cfg=cfg)
        self.conn.execute("UPDATE activos SET windows_build='10.0.26200.1200' WHERE id=1")
        resultado = ocs.detectar_hallazgos(self.conn, cfg=cfg)
        self.conn.commit()
        self.assertEqual(resultado["sin_datos_windows"]["cerrados"], 1)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM hallazgos_activos WHERE tipo='sin_datos_windows' "
            "AND resuelto_at IS NULL").fetchone()[0], 0)

    def test_un_windows_sin_boletines_no_se_marca(self):
        """Una máquina cuya versión de Windows no tiene boletines (Windows 7) tampoco
        tiene compilación, pero eso no es un fallo del agente: es un sistema fuera de
        soporte, que ya tiene su propio hallazgo."""
        self.conn.execute("UPDATE activos SET so_nombre='Windows 7 Professional', "
                          "so_version='6.1.7601' WHERE id=2")
        resultado = ocs.detectar_hallazgos(self.conn, cfg=CfgFalso({"ocs_stale_days": 30}))
        self.conn.commit()
        self.assertEqual(resultado["sin_datos_windows"]["abiertos"], 0,
                         "sin filas del motor msrc no hay hallazgo")


# ==========================================================================
class TestInterfaz(BaseEspera):

    def test_la_pagina_de_remediacion_ensena_el_panel(self):
        self._abrir_las_tres()
        self._todas_sin_dato()
        remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.commit()
        cli = self._cliente()
        respuesta = cli.get("/remediaciones/")
        self.assertEqual(respuesta.status_code, 200)
        html = respuesta.get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html), "style= en la página")
        self.assertIsNone(RE_ON.search(html), "on*= en la página")
        self.assertIn("Esperando datos del inventario", html)
        self.assertIn("PC-SIN-COMPILACION", html)
        self.assertIn("Revisar el agente de OCS Inventory", html)
        self.assertIn("Remediaciones esperando datos del inventario", html)
        # Recorrido guiado: el panel nuevo tiene su paso y la numeración no se repite.
        pasos = re.findall(r'data-tour="(\d+)"', html)
        self.assertEqual(len(pasos), len(set(pasos)), f"pasos repetidos: {pasos}")
        self.assertIn("4", pasos)

    def test_sin_ninguna_el_panel_no_se_pinta(self):
        self._abrir_las_tres()
        cli = self._cliente()
        html = cli.get("/remediaciones/").get_data(as_text=True)
        self.assertNotIn("Esperando datos del inventario</h2>", html,
                         "un panel vacío permanente sería ruido")
        self.assertIn("Remediaciones esperando datos del inventario", html,
                      "pero la tabla «Qué cuenta cada cifra» lo dice siempre, con su cero")

    def test_no_estan_en_la_cola_pero_se_pueden_filtrar(self):
        self._abrir_las_tres()
        self._todas_sin_dato()
        remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.commit()
        cli = self._cliente()
        cola = cli.get("/remediaciones/?vista=vulnerabilidad").get_data(as_text=True)
        self.assertNotIn("CVE-2026-30002", cola, "no está en la cola de trabajo")
        filtrada = cli.get(
            "/remediaciones/?vista=vulnerabilidad&estado=esperando_datos").get_data(as_text=True)
        self.assertIn("CVE-2026-30002", filtrada)
        self.assertIn("Esperando datos del inventario", filtrada)

    def test_la_pagina_de_activos_ensena_el_hallazgo_y_su_atajo(self):
        self._todas_sin_dato()
        ocs.detectar_hallazgos(self.conn, cfg=CfgFalso({"ocs_stale_days": 30}))
        self.conn.commit()
        cli = self._cliente()
        lista = cli.get("/activos/").get_data(as_text=True)
        self.assertEqual(cli.get("/activos/").status_code, 200)
        # 2026-09-15: el rótulo del hallazgo pasó de «Sin datos suficientes de Windows» a
        # «Sin datos de actualizaciones de Windows» (revisión de claridad). Se comprueba
        # lo mismo que antes —que el hallazgo se ve en la lista y en la ficha— con la
        # redacción nueva, y además que la antigua ya no queda en ningún sitio, para que
        # no convivan dos nombres del mismo hallazgo.
        self.assertIn("Sin datos de actualizaciones de Windows", lista)
        self.assertNotIn("Sin datos suficientes de Windows", lista)
        atajo = cli.get("/activos/?vista=sin_datos_windows").get_data(as_text=True)
        self.assertIn("PC-SIN-COMPILACION", atajo)
        self.assertNotIn("PC-CON-COMPILACION", atajo)
        ficha = cli.get("/activos/1").get_data(as_text=True)
        self.assertIn("Sin datos de actualizaciones de Windows", ficha)
        self.assertNotIn("Sin datos suficientes de Windows", ficha)
        self.assertIsNone(RE_STYLE.search(ficha))
        self.assertIsNone(RE_ON.search(ficha))


if __name__ == "__main__":
    unittest.main()
