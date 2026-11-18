"""Dos defectos medidos el 2026-09-10, con sus pruebas propias.

**1. Activos que no reportan y cuyas cifras se dan por buenas.** Medido sobre la base
real: **74 activos presentes de 717** tienen su último inventario de hace más de 30 días
(el ajuste ``ocs_stale_days``), y **30 de ellos** figuran con vulnerabilidades
confirmadas: **4.023 vulnerabilidades** calculadas sobre datos viejos. Ni afirmarlas ni
negarlas es honesto.

Decisión, con su porqué: **no se borran de las cifras, se SEPARAN y se declaran**. Cada
sitio que publica una cifra de riesgo (``ocs.resumen``, ``ocs.estado_activos``,
``queries.resumen_amenazas``, el bloque del Panel, la página de Activos, la de Amenazas y
el resumen semanal) devuelve además la MISMA magnitud calculada solo sobre los activos que
reportan al día (``*_con_dato``) y cuántos quedan fuera (``sin_reportar_*``), y la
interfaz enseña las dos con enlace a su lista. Quitarlos en silencio del numerador
dejándolos en el denominador equivaldría a afirmar que están limpios; quitarlos de los dos
sin decirlo escondería 4.023 hallazgos reales del último estado conocido. Lo que no puede
pasar —y esto es lo que estas pruebas vigilan— es que una cifra los cuente y otra no sin
decirlo: las tres funciones tienen que dar exactamente el mismo reparto.

**2. Lo que no tiene corrección se queda en la cola sin vigilancia.** Las vulnerabilidades
confirmadas sin versión que las corrija (4.384 filas de ``aplicabilidad`` en 140 grupos de
CVE, paquete y sistema) no son trabajo accionable: nadie puede aplicar una versión que no
existe. Aquí se comprueba que salen del recuento accionable, que su cola de espera dice
los días esperando y el activo más expuesto, y que el día que aparece la corrección el
aviso sale en el correo diario, no se pierde y dice en cuántos activos se puede aplicar.

Base temporal bajo ``data/``, sin red y sin enviar un solo correo.
"""
from __future__ import annotations

import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatintel import db, notify, ocs, parches, queries, remediacion
from threatintel.paths import BASE_DIR
from webui import auth

CLAVE = "AdminSeguro#2026"
RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


#: Relativo al instante real de ejecución, no una fecha histórica fija: la vista web
#: de «sin reportar» (webui/vistas/activos.py) calcula su umbral contra
#: datetime.now(timezone.utc), así que una fecha fija se aleja del umbral con el paso
#: del tiempo real y rompe las aserciones sobre la petición HTTP (no sobre las llamadas
#: directas a ocs.*, que sí aceptan `ahora=` inyectado).
AHORA = datetime.now(timezone.utc).replace(hour=12, minute=0, second=0, microsecond=0)
RECIENTE = _iso(AHORA - timedelta(days=1))
VIEJO = _iso(AHORA - timedelta(days=90))
T0 = _iso(AHORA - timedelta(days=45))


class CfgFalso(dict):
    def get(self, clave, defecto=None):
        return super().get(clave, defecto)


class Base(unittest.TestCase):
    """Cuatro activos presentes: dos que reportan al día (uno afectado) y dos que no
    reportan desde hace noventa días (uno afectado)."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "inventario.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", CLAVE, rol="admin", actor="t")
            for (aid, origen, nombre, entorno, inventario) in (
                    (1, "servidores", "SRV-AL-DIA", "produccion", RECIENTE),
                    (2, "servidores", "SRV-LIMPIO", "desarrollo", RECIENTE),
                    (3, "servidores", "SRV-MUDO", "produccion", VIEJO),
                    (4, "equipos", "PC-MUDO", "pruebas", VIEJO)):
                conn.execute(
                    """INSERT INTO activos(id, origen, ocs_id, nombre, so_familia, so_nombre,
                                           so_version, ecosistema, entorno, proceso, presente,
                                           primera_vez_at, visto_at, ultimo_inventario, n_software)
                       VALUES(?,?,?,?,'ubuntu','Ubuntu 22.04','22.04','Ubuntu:22.04',?,'Contabilidad',
                              1,?,?,?,2)""",
                    (aid, origen, aid * 10, nombre, entorno, T0, RECIENTE, inventario))
            for idx, (cve, severidad) in enumerate(
                    (("CVE-2026-40001", "Critical"), ("CVE-2026-40002", "High")), start=1):
                conn.execute(
                    """INSERT INTO threats(id, fingerprint, cve, title_en, title_es, severity,
                                           first_seen_at, last_seen_at, month, estado, in_kev)
                       VALUES(?,?,?,?,?,?,?,?,?,'nueva',0)""",
                    (idx, f"fp-{idx}", cve, f"Fallo {idx}", f"Fallo {idx}", severidad,
                     T0, T0, T0[:7]))
            # SRV-AL-DIA y SRV-MUDO afectados por el CVE-2026-40001 (openssl, con versión
            # corregida) y SRV-MUDO además por el CVE-2026-40002 (curl, SIN corrección).
            for (activo, tid, cve, paquete, corregida) in (
                    (1, 1, "CVE-2026-40001", "openssl", "3.0.14"),
                    (3, 1, "CVE-2026-40001", "openssl", "3.0.14"),
                    (3, 2, "CVE-2026-40002", "curl", None),
                    (1, 2, "CVE-2026-40002", "curl", None)):
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                                                 version_instalada, version_corregida, veredicto,
                                                 motor, evidencia, evaluado_at)
                       VALUES(?,?,?,?,'1.0',?,'afectado','osv','prueba',?)""",
                    (activo, tid, cve, paquete, corregida, T0))
                conn.execute(
                    """INSERT OR IGNORE INTO activo_software(activo_id, nombre, nombre_norm, version)
                       VALUES(?,?,?,'1.0')""", (activo, paquete, paquete))
            remediacion.sincronizar(conn)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cfg(self):
        return CfgFalso({"ignore_low_severity": True, "ocs_stale_days": 30})

    def _cliente(self):
        cli = self.app.test_client()
        respuesta = cli.post("/login", data={"usuario": "admin", "password": CLAVE})
        self.assertIn(respuesta.status_code, (302, 303))
        return cli

    def _html(self, cli, ruta):
        respuesta = cli.get(ruta)
        self.assertEqual(respuesta.status_code, 200, ruta)
        html = respuesta.get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html), f"style= en {ruta}")
        self.assertIsNone(RE_ON.search(html), f"on*= en {ruta}")
        return html


# ==========================================================================
class TestInventarioViejoSeSepara(Base):

    def test_ocs_resumen_da_las_dos_cifras(self):
        with db.session(self.ruta) as conn:
            r = ocs.resumen(conn, cfg=self._cfg(), ahora=AHORA)
        self.assertEqual(r["total"], 4)
        self.assertEqual(r["sin_reportar"], 2, "SRV-MUDO y PC-MUDO")
        self.assertEqual(r["presentes_con_dato"], 2)
        self.assertEqual(r["con_vulnerabilidades"], 2, "SRV-AL-DIA y SRV-MUDO")
        self.assertEqual(r["con_vulnerabilidades_con_dato"], 1, "solo SRV-AL-DIA")
        self.assertEqual(r["sin_reportar_afectados"], 1, "solo SRV-MUDO")
        self.assertEqual(r["dias_sin_reportar"], 30)
        # La suma cuadra siempre: nadie se queda fuera de las dos cifras.
        self.assertEqual(r["con_vulnerabilidades"],
                         r["con_vulnerabilidades_con_dato"] + r["sin_reportar_afectados"])

    def test_estado_activos_da_el_mismo_reparto(self):
        with db.session(self.ruta) as conn:
            e = ocs.estado_activos(conn, cfg=self._cfg(), ahora=AHORA)
        self.assertEqual(e["activos_afectados"], 2)
        self.assertEqual(e["activos_afectados_con_dato"], 1)
        self.assertEqual(e["sin_reportar_afectados"], 1)
        self.assertEqual(e["sin_reportar_activos"], 2)
        self.assertEqual(e["sin_reportar_servidores"], 1)
        self.assertEqual(e["sin_reportar_equipos"], 1)
        self.assertEqual(e["activos_presentes_con_dato"], 2)
        # Vulnerabilidades: SRV-AL-DIA tiene dos y SRV-MUDO dos.
        self.assertEqual(e["vulnerabilidades"], 4)
        self.assertEqual(e["vulnerabilidades_con_dato"], 2)
        self.assertEqual(e["sin_reportar_vulnerabilidades"], 2)
        self.assertEqual(e["vulnerabilidades"],
                         e["vulnerabilidades_con_dato"] + e["sin_reportar_vulnerabilidades"])
        # Expuestos: SRV-AL-DIA y SRV-MUDO están en producción; solo uno reporta.
        self.assertEqual(e["expuestos_activos"], 2)
        self.assertEqual(e["expuestos_activos_con_dato"], 1)

    def test_amenazas_dice_exactamente_lo_mismo_que_activos(self):
        """La regla del encargo: no puede pasar que una cifra los cuente y otra no.

        Sin ``ahora=``, a propósito: ``queries.resumen_amenazas`` calcula su propio
        umbral de «sin reportar» con el reloj real de SQLite (``_umbral_sin_reportar``,
        que no acepta una fecha de referencia) precisamente para que la página de
        Amenazas y la de Activos usen el mismo plazo sin pasárselo entre ellas. Fijar
        ``ahora=AHORA`` solo en ``ocs.*`` aquí desincroniza las dos partes del reparto
        «sin reportar» frente al reloj real que sigue usando ``queries`` y esta prueba
        empieza a fallar (comprobado: 2026-11-15, con 66 días de diferencia entre
        ``AHORA`` y el reloj real, el reparto deja de coincidir). La prueba sigue
        comparando ambas funciones con el MISMO instante, el real, que es justo lo que
        quiere comprobar.
        """
        with db.session(self.ruta) as conn:
            a = queries.resumen_amenazas(conn)
            e = ocs.estado_activos(conn, cfg=self._cfg())
            r = ocs.resumen(conn, cfg=self._cfg())
        for clave in ("sin_reportar_afectados", "sin_reportar_vulnerabilidades",
                      "vulnerabilidades_con_dato", "activos_afectados_con_dato"):
            self.assertEqual(a[clave], e[clave], f"Amenazas y estado_activos: {clave}")
        self.assertEqual(a["sin_reportar_activos"], e["sin_reportar_activos"])
        self.assertEqual(a["presentes_con_dato"], e["activos_presentes_con_dato"])
        self.assertEqual(a["activos_afectados_con_dato"], r["con_vulnerabilidades_con_dato"])
        self.assertEqual(a["sin_reportar_afectados"], r["sin_reportar_afectados"])
        self.assertEqual(a["dias_sin_reportar"], 30)

    def test_el_plazo_sale_del_ajuste_y_al_ampliarlo_dejan_de_ser_viejos(self):
        with db.session(self.ruta) as conn:
            db.set_setting(conn, "ocs_stale_days", 365)
            a = queries.resumen_amenazas(conn)
            e = ocs.estado_activos(conn, cfg=CfgFalso({"ocs_stale_days": 365}))
            db.set_setting(conn, "ocs_stale_days", 30)
        self.assertEqual(a["sin_reportar_activos"], 0, "con 365 días ninguno es viejo")
        self.assertEqual(a["vulnerabilidades_con_dato"], a["vulnerabilidades"])
        self.assertEqual(e["sin_reportar_activos"], 0)
        self.assertEqual(e["vulnerabilidades_con_dato"], e["vulnerabilidades"])

    def test_un_activo_que_nunca_reporto_cuenta_como_viejo(self):
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE activos SET ultimo_inventario=NULL WHERE id=2")
            e = ocs.estado_activos(conn, cfg=self._cfg(), ahora=AHORA)
            conn.execute("UPDATE activos SET ultimo_inventario=? WHERE id=2", (RECIENTE,))
        self.assertEqual(e["sin_reportar_activos"], 3,
                         "«nunca ha reportado» es el caso peor, no una excepción")

    # ------------------------------------------------------------- interfaz
    def test_el_panel_ensena_la_quinta_cifra_y_el_reparto(self):
        cli = self._cliente()
        html = self._html(cli, "/")
        self.assertIn("Sin reportar: su dato es de hace más de 30 días", html)
        self.assertIn("cuyo dato es de hace más de 30 días", html)
        self.assertIn("mantenimiento del inventario", html)
        self.assertIn("/activos/?vista=sin_reportar", html)

    def test_la_pagina_de_activos_lo_dice_en_la_tarjeta(self):
        cli = self._cliente()
        html = self._html(cli, "/activos/")
        self.assertIn("con el inventario al día", html)
        self.assertIn("Sin reportar al inventario", html)
        self.assertIn("tarea de Redes", html)
        # y la lista de esos activos existe y trae los dos
        lista = self._html(cli, "/activos/?vista=sin_reportar")
        self.assertIn("SRV-MUDO", lista)
        self.assertIn("PC-MUDO", lista)
        self.assertNotIn("SRV-AL-DIA", lista)

    def test_la_pagina_de_amenazas_lo_dice_en_las_cifras(self):
        cli = self._cliente()
        html = self._html(cli, "/amenazas/")
        self.assertIn("días sin reportar", html)
        self.assertIn("con el inventario al día", html)

    def test_el_resumen_semanal_lleva_la_quinta_fila(self):
        with db.session(self.ruta) as conn:
            estado = ocs.estado_activos(conn, cfg=self._cfg(), ahora=AHORA)
            resumen = ocs.resumen(conn, cfg=self._cfg(), ahora=AHORA)
        self.assertTrue(resumen["sin_reportar"])
        html = notify.entorno().get_template("semanal.html").render(
            desde=None, hasta=None, dias=7, seguimiento=[], seguimiento_total=0,
            informativo=[], omitidas=0, descartadas=[], descartadas_total=0,
            alertadas=[], alertadas_total=0, alertadas_omitidas=0, ids_incluidas=[],
            umbral_relevancia=50, min_confianza=0.6, horas_espera=24, maximo=40,
            url_interfaz="http://localhost:9090/amenazas/",
            url_activos="http://localhost:9090/activos/",
            estado_activos=estado, vacio=False)
        self.assertIn("Sin reportar: su dato es de hace más de 30 días", html)
        self.assertIn("mantenimiento del inventario", html)
        self.assertIn("no se pueden ni afirmar ni negar hoy", html)


# ==========================================================================
class TestSinCorreccion(Base):

    def _grupo(self, conn, cve="CVE-2026-40002", paquete="curl", motivo="sin_parche_publicado",
               dias=45):
        conn.execute(
            """INSERT OR REPLACE INTO parches_pendientes(cve, paquete, ecosistema, threat_id,
                                                         motivo, n_activos, n_activos_expuestos,
                                                         detectado_at)
               VALUES(?,?,'Ubuntu:22.04',2,?,2,2,?)""",
            (cve, paquete, motivo, _iso(AHORA - timedelta(days=dias))))

    def test_la_cola_de_espera_dice_los_dias_y_el_activo_mas_expuesto(self):
        with db.session(self.ruta) as conn:
            self._grupo(conn)
            filas = parches.listar(conn)
        self.assertEqual(len(filas), 1)
        fila = filas[0]
        self.assertGreaterEqual(fila["dias_en_espera"], 44)
        expuesto = fila["activo_mas_expuesto"]
        self.assertIsNotNone(expuesto)
        self.assertEqual(expuesto["nombre"], "SRV-AL-DIA",
                         "de los dos afectados en producción, el primero por nombre")
        self.assertEqual(expuesto["entorno_es"], "Producción")
        self.assertTrue(expuesto["expuesto"])
        self.assertEqual(expuesto["origen_es"], "Servidor")

    def test_el_mas_expuesto_es_el_de_produccion_aunque_haya_mas_de_pruebas(self):
        with db.session(self.ruta) as conn:
            # Un equipo de cómputo de pruebas con la misma vulnerabilidad
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                                             version_instalada, veredicto, motor, evidencia, evaluado_at)
                   VALUES(4,2,'CVE-2026-40002','curl','1.0','afectado','osv','prueba',?)""", (T0,))
            self._grupo(conn)
            fila = parches.listar(conn)[0]
            self.assertEqual(fila["activo_mas_expuesto"]["entorno"], "produccion")
            conn.execute("DELETE FROM aplicabilidad WHERE activo_id=4")

    def test_sin_correccion_agrupa_por_motivo_con_su_activo_mas_expuesto(self):
        with db.session(self.ruta) as conn:
            self._grupo(conn)
            resumen = parches.sin_correccion(conn)
        self.assertEqual(resumen["total"], 1)
        grupo = resumen["grupos"][0]
        self.assertEqual(grupo["motivo"], "sin_parche_publicado")
        self.assertGreaterEqual(grupo["dias_mas_antigua"], 44)
        self.assertEqual(grupo["muestra"][0]["activo_mas_expuesto"]["nombre"], "SRV-AL-DIA")

    def test_lo_que_no_tiene_version_no_es_trabajo_accionable(self):
        """``remediacion.resumen`` separa las actualizaciones que ya tienen una versión
        a la que subir de las que esperan a que se publique la corrección."""
        with db.session(self.ruta) as conn:
            r = remediacion.resumen(conn, dias=30)
        self.assertEqual(r["actualizaciones"],
                         r["actualizaciones_con_version"] + r["actualizaciones_sin_version"])
        self.assertGreaterEqual(r["actualizaciones_sin_version"], 1,
                                "el curl de los dos servidores no tiene versión que instalar")

    def test_la_pagina_lo_dice_y_enlaza_a_la_cola_de_espera(self):
        cli = self._cliente()
        html = self._html(cli, "/remediaciones/")
        self.assertIn("trabajo accionable", html)
        self.assertIn("esperan a que se publique la corrección", " ".join(html.split()))
        self.assertIn("/parches-pendientes/", html)

    def test_la_pagina_de_correcciones_pendientes_ensena_la_cola(self):
        with db.session(self.ruta) as conn:
            self._grupo(conn)
        cli = self._cliente()
        html = self._html(cli, "/parches-pendientes/")
        self.assertIn("Activo más expuesto", html)
        self.assertIn("Días esperando", html)
        self.assertIn("SRV-AL-DIA", html)
        self.assertIn("trabajo que todavía no se puede hacer", html)


# ==========================================================================
class TestAvisoDeLaCorreccion(Base):

    def _encontrada(self, conn, cve="CVE-2026-40002", paquete="curl", n_activos=2,
                    expuestos=2):
        conn.execute(
            """INSERT OR REPLACE INTO parches_pendientes(cve, paquete, ecosistema, threat_id,
                                                         motivo, n_activos, n_activos_expuestos,
                                                         detectado_at, encontrado_at,
                                                         version_corregida, aviso)
               VALUES(?,?,'Ubuntu:22.04',2,'sin_parche_publicado',?,?,?,?, '8.5.0-1', 'USN-7000-1')""",
            (cve, paquete, n_activos, expuestos, _iso(AHORA - timedelta(days=45)),
             _iso(AHORA)))

    def test_novedades_devuelve_la_correccion_con_sus_activos(self):
        with db.session(self.ruta) as conn:
            conn.execute("DELETE FROM parches_pendientes")
            self._encontrada(conn)
            filas = parches.novedades(conn)
        self.assertEqual(len(filas), 1)
        self.assertEqual(filas[0]["version_corregida"], "8.5.0-1")
        self.assertEqual(filas[0]["n_activos"], 2)
        self.assertGreaterEqual(filas[0]["dias_en_espera"], 44)

    def test_el_correo_diario_dice_que_se_puede_aplicar_y_en_cuantos_activos(self):
        with db.session(self.ruta) as conn:
            conn.execute("DELETE FROM parches_pendientes")
            self._encontrada(conn)
            filas = parches.novedades(conn)
        html = notify.render_alert_email([], {"parches_nuevos": filas,
                                              "url_interfaz": "https://ejemplo.invalid/amenazas/"})
        self.assertIn("Ya se puede aplicar", html)
        plano = " ".join(html.split())
        self.assertIn("1 corrección publicada · se puede aplicar en 2 activos", plano)
        self.assertIn("esto sí se puede hacer hoy", plano)
        self.assertIn("De esos activos, 2 están en producción o contingencia", plano)
        self.assertIn("8.5.0-1", plano)

    def test_el_aviso_va_antes_del_detalle_para_que_no_se_pierda(self):
        """Iba al final del correo, detrás de todo el detalle: en un correo de veinte
        amenazas quedaba fuera de la primera pantalla."""
        with db.session(self.ruta) as conn:
            conn.execute("DELETE FROM parches_pendientes")
            self._encontrada(conn)
            filas = parches.novedades(conn)
        html = notify.render_alert_email([], {"parches_nuevos": filas})
        self.assertLess(html.index("Ya se puede aplicar"),
                        html.index("Cómo leer esta alerta"),
                        "el aviso tiene que ir antes de la nota metodológica")

    def test_sin_correcciones_la_seccion_no_se_pinta(self):
        html = notify.render_alert_email([], {"parches_nuevos": []})
        self.assertNotIn("Ya se puede aplicar", html)

    def test_la_ejecucion_diaria_lo_anuncia_tambien_sin_amenazas_nuevas(self):
        """El día que no hay amenazas nuevas es justo cuando hay tiempo de aplicar las
        correcciones: el aviso NO se puede perder. Se comprueba sobre el código del
        guion, que es donde estaba el defecto."""
        texto = (BASE_DIR / "bin" / "ejecucion_diaria.py").read_text(encoding="utf-8")
        # 1. las correcciones se leen ANTES de decidir si se envía el correo
        self.assertLess(texto.index("parches_nuevos = parches.novedades(conn, marcar=False)"),
                        texto.index('if not cfg.get("alert_enabled", True):'))
        # 2. con «no enviar si está vacío» se envía igualmente si hay correcciones
        self.assertIn('not cfg.get("alert_send_when_empty", True) and not parches_nuevos', texto)
        # 3. el correo «sin novedades» las lleva
        sin_novedades = texto[texto.index("elif not pendientes:"):texto.index("elif args.sin_alerta:")]
        self.assertIn('"parches_nuevos": parches_nuevos', sin_novedades)
        # 4. y solo se sellan si el envío salió bien
        self.assertIn("_sellar_correcciones()", sin_novedades)
        self.assertIn("if parches_nuevos and not args.dry_run:", texto)

    def test_una_correccion_se_anuncia_una_sola_vez(self):
        with db.session(self.ruta) as conn:
            conn.execute("DELETE FROM parches_pendientes")
            self._encontrada(conn)
            self.assertEqual(len(parches.novedades(conn, marcar=True)), 1)
            self.assertEqual(parches.novedades(conn), [], "ya se anunció")


if __name__ == "__main__":
    unittest.main()
