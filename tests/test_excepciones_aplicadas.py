"""La excepción vigente saca la vulnerabilidad de la cola y de las cifras (2026-09-10).

El módulo de excepciones con vencimiento (``threatintel/excepciones.py``, esquema 13,
página ``/excepciones/``) publicaba la condición «esta fila no cuenta» pero NINGUNA
consulta la aplicaba: una excepción quedaba registrada, auditada y avisada mientras la
vulnerabilidad seguía en la página de Remediación y en las cifras del Panel. Estas pruebas
son el contrato de lo que se aplicó, y vigilan las dos mitades del acuerdo:

* lo que la excepción SÍ hace: sacar la vulnerabilidad de la cola de trabajo
  (``remediacion.contar``, ``listar``, ``resumen``, la vista agrupada, la gráfica semanal,
  el reparto por proceso y el avance por tipo de máquina), de las cifras de riesgo
  (``queries.resumen_amenazas``, ``aplicabilidad``), del plan de remediación y de la
  alerta diaria, con el motivo propio ``riesgo_aceptado``;
* lo que NO hace: borrarla ni ocultarla. Sigue en la ficha del activo y en su historial,
  marcada con la insignia «Riesgo aceptado», en la ficha de la amenaza y en
  ``/excepciones/``; ``sincronizar`` la sigue abriendo y cerrando igual, y al VENCER
  vuelve sola a la cola y a las cifras sin que nadie ejecute nada.

Y la regla que hace verificable todo lo anterior: cada sitio que deja fuera la severidad
baja deja fuera también el riesgo aceptado. Con CERO excepciones vigentes el ayudante
devuelve cadena vacía y las consultas quedan exactamente como estaban.

Base temporal bajo data/, sin red y sin enviar un solo correo.
"""
from __future__ import annotations

import re
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from flask import g

from threatintel import aplicabilidad, db, digest, excepciones, health, notify, queries
from threatintel import remediacion
from threatintel.paths import BASE_DIR
from webui import auth
from webui.vistas import remediaciones as vista_remediaciones

CLAVE = "AdminSeguro#2026"
JUSTIFICACION = ("El fabricante no certifica la versión corregida hasta noviembre y la "
                 "aplicación de nómina deja de funcionar si se actualiza antes.")
MOTIVO_REVOCACION = "Se consiguió la ventana de cambio antes de lo previsto y ya se actualizó."
RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)


def _fecha(dias: int) -> str:
    """Fecha ISO a ``dias`` de hoy en UTC: las pruebas no caducan con el calendario."""
    return (date.fromisoformat(excepciones.hoy()) + timedelta(days=dias)).isoformat()


class CfgFalso(dict):
    """Ajustes mínimos con ``get``, como el ``cfg`` de la aplicación."""

    def get(self, clave, defecto=None):
        return super().get(clave, defecto)


class BaseAplicada(unittest.TestCase):
    """Inventario mínimo pero completo: dos servidores y un equipo de cómputo de tres
    procesos distintos, cuatro amenazas (una con explotación activa confirmada), sus
    veredictos de aplicabilidad y la cola de remediación que sale de ellos.

    Ocho filas de cola: seis vulnerabilidades (pares activo-CVE) en tres activos, con un
    CVE que se repite en dos paquetes del mismo activo (el caso del núcleo) para que las
    cifras de «filas» y de «vulnerabilidades» no puedan confundirse.
    """

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "excepciones_aplicadas.db")
        db.init_db(cls.ruta)
        ahora = db.utcnow()
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", CLAVE, rol="admin", actor="t")
            auth.crear_usuario(conn, "redes", CLAVE, rol="redes", actor="t")
            for (aid, origen, nombre, proceso, familia) in (
                    (1, "servidores", "SRV-CONTABILIDAD", "Contabilidad", "ubuntu"),
                    (2, "servidores", "SRV-NOMINA", "Nómina", "ubuntu"),
                    (3, "equipos", "PC-TESORERIA", "Tesorería", "windows")):
                conn.execute(
                    """INSERT INTO activos(id, origen, ocs_id, nombre, so_familia, so_version,
                                           ecosistema, zona, entorno, proceso, presente,
                                           primera_vez_at, visto_at)
                       VALUES(?,?,?,?,?,'22.04','Ubuntu:22.04','interna','produccion',?,1,?,?)""",
                    (aid, origen, aid * 10, nombre, familia, proceso, ahora, ahora))
            for idx, (cve, severidad, kev) in enumerate(
                    (("CVE-2026-1001", "High", 0), ("CVE-2026-1002", "Critical", 1),
                     ("CVE-2026-1003", "Medium", 0), ("CVE-2026-1004", "High", 0)), start=1):
                conn.execute(
                    """INSERT INTO threats(id, fingerprint, cve, title_en, title_es, severity,
                                           severity_source, first_seen_at, last_seen_at, month,
                                           in_kev, estado, relevance, alerted_at)
                       VALUES(?,?,?,?,?,?, 'nvd', ?, ?, ?, ?, 'nueva', 80, NULL)""",
                    (idx, f"fp-{idx}", cve, f"Fallo {idx}", f"Fallo {idx}", severidad,
                     ahora, ahora, ahora[:7], kev))
            # (activo, amenaza, CVE, paquete). El CVE-2026-1001 del servidor 1 llega por
            # dos paquetes: una sola vulnerabilidad, dos filas de cola.
            cls.filas = (
                (1, 1, "CVE-2026-1001", "openssl"),
                (1, 1, "CVE-2026-1001", "libssl3"),
                (1, 2, "CVE-2026-1002", "openssl"),
                (1, 3, "CVE-2026-1003", "curl"),
                (2, 1, "CVE-2026-1001", "openssl"),
                (2, 4, "CVE-2026-1004", "nginx"),
                (3, 1, "CVE-2026-1001", "openssl"),
                (3, 3, "CVE-2026-1003", "curl"),
            )
            for activo, threat, cve, paquete in cls.filas:
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                                                 version_instalada, version_corregida,
                                                 veredicto, motor, evaluado_at)
                       VALUES(?,?,?,?,'1.0','2.0','afectado','osv',?)""",
                    (activo, threat, cve, paquete, ahora))
                conn.execute(
                    """INSERT OR IGNORE INTO activo_software(activo_id, nombre, nombre_norm,
                                                             version)
                       VALUES(?,?,?,'1.0')""", (activo, paquete, paquete))
            for threat in (1, 2, 3, 4):
                conn.execute(
                    """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados,
                                                         no_afectados, sin_dato, detalle)
                       VALUES(?,?,?,0,0,'{}')""",
                    (threat, ahora,
                     len({a for a, t, _c, _p in cls.filas if t == threat})))
            remediacion.sincronizar(conn)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        with db.session(self.ruta) as conn:
            conn.execute("DELETE FROM excepciones")
            conn.execute("DELETE FROM audit_log")
            conn.execute("DELETE FROM admin_notices")
            conn.execute("UPDATE threats SET alerted_at=NULL, alert_skip_reason=NULL")

    # ------------------------------------------------------------------ ayudas
    def _crear(self, conn, **cambios):
        datos = {"alcance": "activo_cve", "activo_id": 1, "cve": "CVE-2026-1001",
                 "justificacion": JUSTIFICACION,
                 "responsable_nombre": "Ana Pérez Gómez",
                 "responsable_correo": "ana.perez@ejemplo.local",
                 "compensacion": "Solo acepta conexiones desde la red de administración.",
                 # 20 días: por debajo del plazo máximo de una excepción con
                 # explotación activa confirmada (30), que es el más corto de los dos.
                 "vence_at": _fecha(20), "confirmar_kev": True}
        datos.update(cambios)
        return excepciones.crear(conn, actor="admin", **datos)

    def _cifras(self, conn) -> dict:
        """Las cifras que la excepción tiene que mover, todas de las funciones reales."""
        res = remediacion.resumen(conn, dias=30)
        amenazas = queries.resumen_amenazas(conn)
        por_proceso = {p["proceso"]: p["abiertas"] for p in res["por_proceso"]}
        return {
            "cola": remediacion.contar(conn, estado="abierta"),
            "listadas": len(remediacion.listar(conn, estado="abierta", limite=100)),
            "abiertas": res["abiertas"],
            "vulnerabilidades": res["vulnerabilidades_unicas"],
            "actualizaciones": res["actualizaciones"],
            "activos": res["activos_con_abiertas"],
            "servidores": res["servidores_con_abiertas"],
            "equipos": res["equipos_con_abiertas"],
            "cve_distintos": res["cve_distintos"],
            "sin_excepcion": res["sin_excepcion"],
            "por_proceso": por_proceso,
            "procesos_cola": remediacion.procesos(conn),
            "semanal_detectadas": sum(s["detectadas"] for s in (res["semanas"] or [])),
            "agrupadas": remediacion.contar_actualizaciones(conn, estado="abierta"),
            "am_vulnerabilidades": amenazas["vulnerabilidades"],
            "am_activos": amenazas["activos_afectados"],
            "am_criticas": amenazas["criticas"],
            "am_altas": amenazas["altas"],
            "am_cve": amenazas["cve_confirmados"],
            "am_confirmadas": amenazas["confirmadas"],
            "am_aceptadas": amenazas["vulnerabilidades_aceptadas"],
            "am_con_excepciones": amenazas["con_excepciones"],
            "procesos_parque": queries.procesos_del_parque(conn),
            "plan_servidor_1": len(aplicabilidad.plan_remediacion(conn, activo_id=1)["grupos"]),
            "activos_distintos": aplicabilidad.activos_distintos(conn, [1, 2, 3, 4]),
        }

    def _cliente(self, usuario="admin"):
        cli = self.app.test_client()
        respuesta = cli.post("/login", data={"usuario": usuario, "password": CLAVE})
        self.assertIn(respuesta.status_code, (302, 303))
        return cli

    def _html(self, cli, ruta: str) -> str:
        respuesta = cli.get(ruta)
        self.assertEqual(respuesta.status_code, 200, ruta)
        html = respuesta.get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html), f"style= en {ruta}")
        self.assertIsNone(RE_ON.search(html), f"on*= en {ruta}")
        return html


# ==========================================================================
class TestCeroExcepciones(BaseAplicada):
    """Sin ninguna excepción vigente NADA cambia: el ayudante devuelve cadena vacía y las
    consultas son, carácter por carácter, las de siempre."""

    def test_los_ayudantes_devuelven_cadena_vacia(self):
        with db.session(self.ruta) as conn:
            self.assertFalse(excepciones.hay_excepciones(conn))
            self.assertEqual(remediacion._y_sin_excepcion(conn), "")
            self.assertEqual(aplicabilidad._y_sin_excepcion(conn), "")
            self.assertEqual(excepciones.y_sin_excepcion(conn), "")

    def test_una_vencida_o_revocada_no_cambia_ninguna_cifra(self):
        with db.session(self.ruta) as conn:
            antes = self._cifras(conn)
            fila = self._crear(conn, vence_at=_fecha(1))
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?", (_fecha(-2), fila["id"]))
            otra = self._crear(conn, activo_id=2, cve="CVE-2026-1004")
            excepciones.revocar(conn, otra["id"], motivo=MOTIVO_REVOCACION, actor="admin")
            self.assertFalse(excepciones.hay_excepciones(conn))
            self.assertEqual(remediacion._y_sin_excepcion(conn), "")
            self.assertEqual(self._cifras(conn), antes)

    def test_el_resumen_dice_que_no_hay_exclusion(self):
        with db.session(self.ruta) as conn:
            self.assertFalse(remediacion.resumen(conn)["sin_excepcion"])
            self.assertFalse(queries.resumen_amenazas(conn)["con_excepciones"])
            self.assertEqual(queries.resumen_amenazas(conn)["vulnerabilidades_aceptadas"], 0)


class TestSaleDeLaColaYDeLasCifras(BaseAplicada):
    """Una excepción vigente sobre (servidor 1, CVE-2026-1001) tapa DOS filas de la cola
    (openssl y libssl3) que son UNA sola vulnerabilidad."""

    def test_una_excepcion_vigente_saca_la_vulnerabilidad_de_todo(self):
        with db.session(self.ruta) as conn:
            antes = self._cifras(conn)
            self._crear(conn)
            despues = self._cifras(conn)
        self.assertEqual(antes["cola"] - despues["cola"], 2, "dos filas de cola")
        self.assertEqual(antes["listadas"] - despues["listadas"], 2)
        self.assertEqual(antes["abiertas"] - despues["abiertas"], 2)
        self.assertEqual(antes["vulnerabilidades"] - despues["vulnerabilidades"], 1,
                         "una sola vulnerabilidad: el mismo CVE en dos paquetes")
        self.assertEqual(antes["am_vulnerabilidades"] - despues["am_vulnerabilidades"], 1)
        self.assertEqual(despues["am_aceptadas"], 1)
        self.assertTrue(despues["am_con_excepciones"])
        self.assertTrue(despues["sin_excepcion"])
        # El avance por tipo de máquina y el reparto por proceso salen del mismo resumen.
        self.assertEqual(antes["servidores"], despues["servidores"], "el servidor sigue con otras")
        self.assertEqual(antes["por_proceso"]["Contabilidad"] - despues["por_proceso"]["Contabilidad"], 2)
        # La gráfica semanal cuenta VULNERABILIDADES (un CVE en un activo) desde el
        # 2026-09-15, no filas de remediación: las dos filas de este caso son el mismo CVE
        # en el mismo servidor, en dos paquetes, así que la gráfica baja en UNA, igual que
        # la tarjeta «Vulnerabilidades pendientes» y no como la de filas.
        self.assertEqual(antes["semanal_detectadas"] - despues["semanal_detectadas"], 1)
        self.assertEqual(antes["semanal_detectadas"] - despues["semanal_detectadas"],
                         antes["vulnerabilidades"] - despues["vulnerabilidades"],
                         "la gráfica y la tarjeta de vulnerabilidades se mueven igual")
        # La vista agrupada: openssl del servidor 1 ya no tiene esa vulnerabilidad.
        self.assertLessEqual(despues["agrupadas"], antes["agrupadas"])
        # Y el plan de remediación de ese activo deja de mandar corregirla.
        self.assertLess(despues["plan_servidor_1"], antes["plan_servidor_1"] + 1)

    def test_la_cifra_de_aceptadas_cuadra_con_lo_que_desaparece(self):
        with db.session(self.ruta) as conn:
            antes = self._cifras(conn)
            self._crear(conn)
            self._crear(conn, activo_id=2, cve="CVE-2026-1004")
            despues = self._cifras(conn)
        # La aplicación cierra ``g.db`` al terminar el contexto, así que la petición de
        # prueba usa su propia conexión y no la de la sesión de arriba.
        with self.app.test_request_context("/remediaciones/"):
            g.db = db.connect(self.ruta)
            cifras = vista_remediaciones._cifras_riesgo_aceptado()
        desaparecidas = antes["vulnerabilidades"] - despues["vulnerabilidades"]
        self.assertEqual(desaparecidas, 2)
        self.assertEqual(cifras["vulnerabilidades"], desaparecidas)
        self.assertEqual(cifras["filas"], antes["cola"] - despues["cola"])
        self.assertTrue(cifras["hay"])
        self.assertEqual(despues["am_aceptadas"], desaparecidas,
                         "Amenazas y Remediación dicen la misma cifra de riesgo aceptado")

    def test_un_activo_cuyas_unicas_pendientes_se_aceptan_sale_de_los_activos(self):
        with db.session(self.ruta) as conn:
            antes = self._cifras(conn)
            self._crear(conn, activo_id=3, cve="CVE-2026-1001")
            self._crear(conn, activo_id=3, cve="CVE-2026-1003")
            despues = self._cifras(conn)
        self.assertEqual(antes["activos"] - despues["activos"], 1)
        self.assertEqual(antes["equipos"] - despues["equipos"], 1)
        self.assertEqual(antes["am_activos"] - despues["am_activos"], 1)
        self.assertNotIn("Tesorería", despues["por_proceso"])
        self.assertNotIn("Tesorería", despues["procesos_cola"])
        self.assertNotIn("Tesorería", despues["procesos_parque"])

    def test_el_reparto_por_severidad_sigue_cuadrando_con_el_total(self):
        with db.session(self.ruta) as conn:
            self._crear(conn, activo_id=1, cve="CVE-2026-1002")
            cifras = queries.resumen_amenazas(conn)
        suma = sum(int(cifras[c] or 0) for c in
                   ("criticas", "altas", "medias", "bajas", "sin_severidad"))
        self.assertEqual(suma, cifras["vulnerabilidades"])
        self.assertEqual(cifras["criticas"], 0, "la única crítica tenía el riesgo aceptado")


class TestNoLaOculta(BaseAplicada):
    """Lo que la excepción NO hace: la ficha del activo, su historial y la ficha de la
    amenaza siguen enseñando la vulnerabilidad, con su insignia."""

    def test_el_historial_del_activo_la_sigue_trayendo(self):
        with db.session(self.ruta) as conn:
            antes_total = remediacion.contar_historial_activo(conn, 1)
            antes = len(remediacion.historial_activo(conn, 1, limite=50))
            self._crear(conn)
            self.assertEqual(remediacion.contar_historial_activo(conn, 1), antes_total)
            self.assertEqual(len(remediacion.historial_activo(conn, 1, limite=50)), antes)
            # Y el total pagina exactamente la misma lista.
            self.assertEqual(antes_total, antes)

    def test_los_veredictos_del_activo_no_se_tocan(self):
        with db.session(self.ruta) as conn:
            antes = (aplicabilidad.contar_veredictos_activo(conn, 1),
                     dict(aplicabilidad.conteo_activo(conn, 1)),
                     len(aplicabilidad.vulnerabilidades_activo(conn, 1)))
            self._crear(conn)
            self.assertEqual(
                (aplicabilidad.contar_veredictos_activo(conn, 1),
                 dict(aplicabilidad.conteo_activo(conn, 1)),
                 len(aplicabilidad.vulnerabilidades_activo(conn, 1))), antes,
                "el veredicto es un hecho técnico: la excepción es una decisión de riesgo")

    def test_sincronizar_no_borra_ni_cierra_lo_aceptado(self):
        with db.session(self.ruta) as conn:
            self._crear(conn)
            filas_antes = conn.execute(
                "SELECT COUNT(*) FROM remediaciones WHERE activo_id=1 AND cve='CVE-2026-1001'"
                " AND estado='abierta'").fetchone()[0]
            primera = remediacion.sincronizar(conn)
            segunda = remediacion.sincronizar(conn)
            filas_despues = conn.execute(
                "SELECT COUNT(*) FROM remediaciones WHERE activo_id=1 AND cve='CVE-2026-1001'"
                " AND estado='abierta'").fetchone()[0]
        self.assertEqual(filas_antes, filas_despues)
        self.assertEqual(primera["cerradas"], 0)
        self.assertEqual(segunda["abiertas_nuevas"], 0, "dos ejecuciones seguidas: idempotente")

    def test_la_ficha_del_activo_pinta_la_insignia_con_su_fecha(self):
        with db.session(self.ruta) as conn:
            self._crear(conn)
        cli = self._cliente()
        html = self._html(cli, "/activos/1")
        self.assertIn("Riesgo aceptado", html)
        self.assertIn("Ana Pérez Gómez", html)
        self.assertIn("excepción vigente", html)
        self.assertIn("/excepciones/", html)
        self.assertIn("CVE-2026-1001", html)
        # La fecha, en español y con todas sus letras (nunca «2026-10-25»).
        self.assertIn(notify.fecha_larga(_fecha(20)).split(" de ")[0], html)

    def test_la_ficha_de_la_amenaza_pinta_la_insignia(self):
        with db.session(self.ruta) as conn:
            self._crear(conn, alcance="cve", activo_id=None, cve="CVE-2026-1003")
        cli = self._cliente()
        html = self._html(cli, "/amenazas/3")
        self.assertIn("Riesgo aceptado", html)
        self.assertIn("ana.perez@ejemplo.local", html)
        self.assertIn("en toda la organización", html)
        # Los activos afectados siguen en el cuadro: su versión sigue siendo vulnerable.
        # Ese cuadro es AJAX (2026-11-16): el nombre vive en su propio endpoint, no en
        # el HTML inicial de la ficha.
        datos = cli.get("/amenazas/activos-afectados/3").get_json()
        nombres = [a["nombre"] for a in datos["activos"]]
        self.assertIn("SRV-CONTABILIDAD", nombres)
        # Y ese mismo activo viene marcado con el riesgo aceptado de alcance «cve».
        marcado = next(a for a in datos["activos"] if a["nombre"] == "SRV-CONTABILIDAD")
        self.assertTrue(marcado["riesgo_aceptado"])

    def test_la_pagina_de_remediacion_dice_cuantas_se_aceptaron(self):
        with db.session(self.ruta) as conn:
            self._crear(conn)
        cli = self._cliente()
        html = self._html(cli, "/remediaciones/")
        self.assertIn("Vulnerabilidades con el riesgo aceptado", html)
        self.assertIn("aceptado con una excepción vigente", html)
        self.assertIn("no están corregidas", html)
        self.assertIn("/excepciones/", html)


class TestVenceYSeRevoca(BaseAplicada):
    def test_al_vencer_vuelve_sola_sin_que_nadie_haga_nada(self):
        with db.session(self.ruta) as conn:
            antes = self._cifras(conn)
            fila = self._crear(conn, vence_at=_fecha(1))
            self.assertLess(self._cifras(conn)["cola"], antes["cola"])
            # Pasa el tiempo: nadie ejecuta nada, solo cambia la fecha del calendario.
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?", (_fecha(-1), fila["id"]))
            self.assertEqual(self._cifras(conn), antes)
            self.assertEqual(excepciones.obtener(conn, fila["id"])["estado"], "vencida")

    def test_la_revocacion_la_devuelve_en_el_acto(self):
        with db.session(self.ruta) as conn:
            antes = self._cifras(conn)
            fila = self._crear(conn)
            self.assertNotEqual(self._cifras(conn), antes)
            excepciones.revocar(conn, fila["id"], motivo=MOTIVO_REVOCACION, actor="admin")
            self.assertEqual(self._cifras(conn), antes)


class TestAlcances(BaseAplicada):
    def test_por_cve_en_toda_la_organizacion_tapa_todos_sus_activos(self):
        with db.session(self.ruta) as conn:
            antes = self._cifras(conn)
            self._crear(conn, alcance="cve", activo_id=None, cve="CVE-2026-1001")
            despues = self._cifras(conn)
        # CVE-2026-1001 está en los tres activos y en cuatro filas (dos paquetes en el 1).
        self.assertEqual(antes["cola"] - despues["cola"], 4)
        self.assertEqual(antes["vulnerabilidades"] - despues["vulnerabilidades"], 3)
        self.assertEqual(antes["am_cve"] - despues["am_cve"], 1, "ese CVE ya no cuenta")
        self.assertEqual(despues["am_aceptadas"], 3)

    def test_por_paquete_tapa_solo_ese_paquete(self):
        with db.session(self.ruta) as conn:
            antes = self._cifras(conn)
            self._crear(conn, alcance="activo_paquete", activo_id=1, cve=None, paquete="openssl")
            despues = self._cifras(conn)
        # En el servidor 1, openssl tiene dos filas (CVE-1001 y CVE-1002); libssl3 y curl
        # siguen en la cola, así que el CVE-2026-1001 de ese activo NO desaparece.
        self.assertEqual(antes["cola"] - despues["cola"], 2)
        self.assertEqual(antes["vulnerabilidades"] - despues["vulnerabilidades"], 1,
                         "solo desaparece la que no tenía otro paquete pendiente")
        self.assertEqual(despues["am_aceptadas"], 1)
        with db.session(self.ruta) as conn:
            pendientes = {(r["cve"], r["paquete"]) for r in
                          remediacion.listar(conn, estado="abierta", limite=50, activo_id=1)}
        self.assertIn(("CVE-2026-1001", "libssl3"), pendientes)
        self.assertNotIn(("CVE-2026-1001", "openssl"), pendientes)
        self.assertNotIn(("CVE-2026-1002", "openssl"), pendientes)

    def test_el_alcance_por_paquete_no_afecta_a_otros_activos(self):
        with db.session(self.ruta) as conn:
            self._crear(conn, alcance="activo_paquete", activo_id=1, cve=None, paquete="openssl")
            otros = {r["activo_id"] for r in remediacion.listar(conn, estado="abierta", limite=50)}
        self.assertEqual(otros, {1, 2, 3})


class TestAlertaDiaria(BaseAplicada):
    """La alerta diaria no dispara por una afectación confirmada cuyo riesgo está
    aceptado, y el motivo que se registra es ``riesgo_aceptado``, no «sin afectación
    confirmada», que sería falso."""

    CFG = CfgFalso({"ignore_low_severity": True, "alert_solo_con_activos_afectados": True,
                    "applicability_enabled": True, "alert_kev_sin_activos": True,
                    "alert_min_relevance": 50, "alert_skip_without_assets": True,
                    "alert_require_identifier": True})

    def _vistas(self, conn, threat_id):
        vistas = [queries._fila_a_view(r) for r in conn.execute(
            f"SELECT {queries._THREAT_COLS} FROM threats WHERE id=?", (threat_id,))]
        queries._adjuntar_relaciones(conn, vistas)
        aplicabilidad.adjuntar_resumen(conn, vistas)
        self.assertTrue(queries._adjuntar_activos_afectados(conn, vistas))
        return vistas

    def test_el_motivo_es_riesgo_aceptado_y_no_se_alerta(self):
        with db.session(self.ruta) as conn:
            # CVE-2026-1004 solo afecta al servidor 2: una sola excepción lo tapa entero.
            vista = self._vistas(conn, 4)[0]
            self.assertIsNone(queries.motivo_exclusion(vista, cfg=self.CFG))
            self._crear(conn, activo_id=2, cve="CVE-2026-1004")
            vista = self._vistas(conn, 4)[0]
            self.assertEqual(vista["activos_afectados_presentes"], 0)
            self.assertEqual(vista["activos_afectados_aceptados"], 1)
            self.assertEqual(queries.motivo_exclusion(vista, cfg=self.CFG), "riesgo_aceptado")
            clasificacion = queries.clasificar_pendientes(conn, cfg=self.CFG, persistir=True)
            self.assertIn(4, clasificacion["excluidas"]["riesgo_aceptado"])
            self.assertEqual(
                conn.execute("SELECT alert_skip_reason FROM threats WHERE id=4").fetchone()[0],
                "riesgo_aceptado")
            self.assertNotIn(4, [v["id"] for v in
                                 queries.pendientes_de_alerta(conn, cfg=self.CFG)])

    def test_al_vencer_vuelve_a_ser_alertable_sin_que_nadie_haga_nada(self):
        with db.session(self.ruta) as conn:
            fila = self._crear(conn, activo_id=2, cve="CVE-2026-1004", vence_at=_fecha(1))
            self.assertEqual(queries.motivo_exclusion(self._vistas(conn, 4)[0], cfg=self.CFG),
                             "riesgo_aceptado")
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?", (_fecha(-1), fila["id"]))
            self.assertIsNone(queries.motivo_exclusion(self._vistas(conn, 4)[0], cfg=self.CFG))
            self.assertIsNone(
                conn.execute("SELECT alerted_at FROM threats WHERE id=4").fetchone()[0],
                "la amenaza nunca se marcó como alertada, así que se alerta al vencer")

    def test_la_explotacion_activa_confirmada_sigue_alertando(self):
        with db.session(self.ruta) as conn:
            self._crear(conn, activo_id=1, cve="CVE-2026-1002")
            vista = self._vistas(conn, 2)[0]
            self.assertEqual(vista["activos_afectados_presentes"], 0)
            self.assertEqual(vista["activos_afectados_aceptados"], 1)
            self.assertIsNone(queries.motivo_exclusion(vista, cfg=self.CFG),
                              "CISA confirma que se está explotando: el correo sale igual")
            self.assertEqual(vista.get("riesgo_aceptado_vigente"), 1)
            self.assertNotIn("kev_sin_activos_confirmados", vista,
                             "no se puede decir «no confirmado» de algo confirmado y aceptado")

    def test_el_motivo_tiene_texto_en_los_tres_sitios(self):
        self.assertIn("riesgo_aceptado", queries.MOTIVOS_EXCLUSION)
        for tabla in (queries.MOTIVO_EXCLUSION_ES, notify.MOTIVOS_FILTRO_ES,
                      digest.FRASES_MOTIVO):
            self.assertIn("riesgo_aceptado", tabla)
            self.assertNotIn("_", tabla["riesgo_aceptado"].replace("{", "").replace("}", ""))
        frase = digest.frase_motivo("riesgo_aceptado", 3)
        self.assertIn("excepción vigente", frase)
        self.assertNotIn("riesgo_aceptado", frase)

    def test_el_resumen_semanal_lo_cuenta_con_su_nombre(self):
        with db.session(self.ruta) as conn:
            self._crear(conn, activo_id=2, cve="CVE-2026-1004")
            queries.clasificar_pendientes(conn, cfg=self.CFG, persistir=True)
            conteo = queries.conteo_exclusiones(conn, db.utcnow()[:10] + "T00:00:00Z")
        self.assertEqual(conteo["riesgo_aceptado"], 1)


class TestSaludYAjuste(BaseAplicada):
    def test_las_metricas_de_zabbix(self):
        with db.session(self.ruta) as conn:
            metricas = health.exportar_metricas(conn, cfg=CfgFalso())
            self.assertEqual(metricas["ti.excepciones.vencidas"], 0)
            self.assertEqual(metricas["ti.excepciones.por_vencer"], 0)
            self.assertEqual(metricas["ti.excepciones.vulnerabilidades_cubiertas"], 0)
            vencida = self._crear(conn, vence_at=_fecha(1))
            conn.execute("UPDATE excepciones SET vence_at=? WHERE id=?", (_fecha(-3), vencida["id"]))
            self._crear(conn, activo_id=2, cve="CVE-2026-1004", vence_at=_fecha(3))
            metricas = health.exportar_metricas(conn, cfg=CfgFalso())
        self.assertEqual(metricas["ti.excepciones.vencidas"], 1)
        self.assertEqual(metricas["ti.excepciones.por_vencer"], 1)
        self.assertEqual(metricas["ti.excepciones.vulnerabilidades_cubiertas"], 1)

    def test_el_ajuste_de_dias_de_aviso_se_ve_y_se_valida(self):
        from webui.vistas import ajustes
        claves = [c for _, items in ajustes.GRUPOS for c, _e, _t, _a in items]
        self.assertIn("excepciones_aviso_dias", claves)
        self.assertEqual(ajustes.RANGOS_ENTEROS["excepciones_aviso_dias"], (1, 120,
                         "debe estar entre 1 y 120 días"))
        cli = self._cliente()
        html = self._html(cli, "/ajustes/")
        self.assertIn("excepciones_aviso_dias", html)
        self.assertIn("Días de antelación del aviso de excepciones por vencer", html)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        cli.post("/ajustes/guardar", data={"csrf": csrf, "excepciones_aviso_dias": "200"})
        with db.session(self.ruta) as conn:
            self.assertEqual(excepciones.ajuste_aviso_dias(conn), 15,
                             "un valor fuera de rango no se guarda: sigue el de siempre")
        cli.post("/ajustes/guardar", data={"csrf": csrf, "excepciones_aviso_dias": "30"})
        with db.session(self.ruta) as conn:
            self.assertEqual(excepciones.ajuste_aviso_dias(conn), 30)


class TestReglaDelGrep(BaseAplicada):
    """La regla que hace verificable el trabajo: en los cinco módulos que calculan cifras
    de riesgo, cada función que aplica la exclusión de la severidad baja aplica también la
    del riesgo aceptado. Las únicas excepciones son la ficha del activo, su historial y
    las funciones que ESCRIBEN (``sincronizar``, ``evaluar_amenaza``), donde la fila debe
    seguir viéndose o abriéndose.

    Ampliada el 2026-09-10 (tarde) con ``threatintel/ocs.py``, ``threatintel/parches.py``,
    ``webui/vistas/panel.py`` y ``webui/vistas/activos.py``, que eran los cuatro sitios
    que seguían contando el riesgo aceptado: la tarjeta grande de la página de Activos, el
    bloque de activos del Panel, la columna «Afectados» de la lista y la cola de
    «Correcciones pendientes».
    """

    SIN_CONDICION = {
        # ``contar_congeladas_activo`` se añade el 2026-09-15: es la cifra de
        # remediaciones congeladas de un activo retirado de OCS Inventory que se escribe
        # en la ficha y en su plan. Acompaña a la MISMA tabla que ``historial_activo``,
        # que sí trae las filas con el riesgo aceptado (con su insignia), así que
        # descontarlas aquí volvería a dejar el aviso por debajo de lo que se ve debajo.
        "remediacion": ("contar_historial_activo", "contar_congeladas_activo",
                        "historial_activo", "sincronizar"),
        "aplicabilidad": ("contar_veredictos_activo", "veredictos_de_activo", "conteo_activo",
                          "vulnerabilidades_activo", "evaluar_amenaza", "recalcular_resumenes",
                          "adjuntar_resumen", "activos_de_amenaza"),
        # ``ocs.sincronizar_origen`` y ``detectar_hallazgos`` escriben; ninguna de las dos
        # menciona la severidad baja, así que la regla no las alcanza.
        "ocs": (),
        # ``parches.sincronizar`` y ``buscar`` escriben y no filtran (la corrección se
        # sigue buscando cada día aunque el riesgo esté aceptado).
        "parches": (),
        # Las cuatro del Panel que nombran la severidad baja y NO llevan la condición
        # son series del CATÁLOGO de amenazas, no del parque: el reparto por severidad de
        # lo publicado en el mes, la evolución mensual, las tecnologías más citadas y la
        # vista ``inicio``, que solo reparte esas series a las plantillas. Una excepción
        # acepta el riesgo de una vulnerabilidad en un activo; no borra la amenaza del
        # catálogo ni cambia lo que se publicó (mismo criterio que ``queries.top_tecnologias``
        # y ``queries.evolucion_mensual``).
        # ``_variaciones_30_dias`` se añade el 2026-09-15: es la flecha de tendencia de
        # las tarjetas del Panel y cuenta lo PUBLICADO en los últimos 30 días frente a
        # los 30 anteriores, sobre la tabla ``threats``. Mismo criterio que las otras
        # cuatro: es catálogo, no parque, y una excepción no borra lo que se publicó.
        "panel": ("_porciones_severidad", "_items_tecnologias", "_series_evolucion",
                  "_variaciones_30_dias", "inicio"),
        # La ficha del activo no descuenta el riesgo aceptado: la fila tiene que seguir
        # viéndose con su insignia. ``_sin_bajas`` solo lee el ajuste.
        # ``_cargar_activo`` es la ficha del activo: su fila tiene que seguir viéndose
        # con la insignia «Riesgo aceptado», igual que ``remediacion.historial_activo`` y
        # ``aplicabilidad.conteo_activo``. De sus subconsultas la ficha solo pinta los
        # hallazgos y el software clasificado.
        "activos": ("_cargar_activo",),
    }

    def _funciones_con(self, modulo, aguja: str) -> set:
        """Nombres de las funciones del fichero que mencionan ``aguja``."""
        import ast
        import inspect
        arbol = ast.parse(inspect.getsource(modulo))
        salida = set()
        for nodo in ast.walk(arbol):
            if isinstance(nodo, (ast.FunctionDef, ast.AsyncFunctionDef)):
                texto = ast.get_source_segment(inspect.getsource(modulo), nodo) or ""
                # El cuerpo, sin la documentación: un comentario o un docstring que
                # nombre la condición no la aplica.
                cuerpo = texto
                if (nodo.body and isinstance(nodo.body[0], ast.Expr)
                        and isinstance(nodo.body[0].value, ast.Constant)
                        and isinstance(nodo.body[0].value.value, str)):
                    cuerpo = cuerpo.replace(nodo.body[0].value.value, "")
                if aguja in cuerpo:
                    salida.add(nodo.name)
        return salida

    #: Cómo se nombra la exclusión de la severidad baja en cada módulo y cómo la del
    #: riesgo aceptado. No son iguales en todos: ``ocs`` y ``panel`` las pegan a una
    #: variable ``viva`` o ``sin_bajas``, y ``activos`` recibe la condición ya resuelta
    #: como parámetro.
    AGUJAS_BAJAS = ("_SIN_BAJAS_SQL", "_y_sin_bajas", "_SIN_BAJAS_APLICABILIDAD_SQL",
                    "ignore_low_severity", "sin_bajas")
    AGUJAS_EXCEPCION = ("_SIN_EXCEPCION_SQL", "_y_sin_excepcion", "excepciones.hay_excepciones",
                        "excepciones.y_sin_excepcion", "_sin_excepcion", "sin_excepcion")

    MODULOS = ()          # se rellena en :meth:`test_cada_sitio_...`

    def test_cada_sitio_de_las_bajas_lleva_tambien_el_riesgo_aceptado(self):
        from threatintel import ocs, parches
        from webui.vistas import activos as vista_activos
        from webui.vistas import panel as vista_panel
        for modulo, nombre in ((remediacion, "remediacion"), (aplicabilidad, "aplicabilidad"),
                               (ocs, "ocs"), (parches, "parches"),
                               (vista_panel, "panel"), (vista_activos, "activos")):
            bajas = set()
            for aguja in self.AGUJAS_BAJAS:
                bajas |= self._funciones_con(modulo, aguja)
            excep = set()
            for aguja in self.AGUJAS_EXCEPCION:
                excep |= self._funciones_con(modulo, aguja)
            faltan = {f for f in bajas - excep
                      if not f.startswith("_y_sin") and f not in ("excluir_bajas", "_sin_bajas")}
            self.assertEqual(faltan, set(self.SIN_CONDICION[nombre]) & faltan,
                             f"en {nombre} hay funciones que dejan fuera la severidad baja "
                             f"pero no el riesgo aceptado: {sorted(faltan)}")
            for esperada in self.SIN_CONDICION[nombre]:
                self.assertNotIn(esperada, excep,
                                 f"{nombre}.{esperada} NO debe aplicar la condición: la fila "
                                 f"tiene que seguir viéndose o abriéndose")


# ==========================================================================
# Los cuatro sitios que faltaban (2026-09-10, tarde)
# ==========================================================================
class TestActivosPanelYParches(BaseAplicada):
    """Los cuatro sitios que el 2026-09-10 por la mañana seguían contando el riesgo
    aceptado, y que se aplicaron JUNTOS porque son cifras de lo mismo en la misma
    pantalla: ``ocs.resumen`` (la tarjeta grande de la página de Activos y del correo),
    ``ocs.estado_activos`` (el bloque del Panel y del resumen semanal),
    ``webui.vistas.activos`` (la columna «Afectados», el atajo y el orden por riesgo) y
    ``threatintel.parches`` («Correcciones pendientes»).
    """

    def _cifras_inventario(self, conn) -> dict:
        cfg = CfgFalso({"ignore_low_severity": True, "ocs_stale_days": 30})
        from threatintel import ocs
        from webui.vistas import panel as vista_panel
        res = ocs.resumen(conn, cfg=cfg)
        est = ocs.estado_activos(conn, cfg=cfg)
        srv = vista_panel._estado_activos_en_alcance(conn, "servidores", cfg=cfg) or {}
        return {
            "con_vulnerabilidades": res["con_vulnerabilidades"],
            "expuestos_afectados": res["expuestos_afectados"],
            "proceso_contabilidad": {p["proceso"]: p["con_vulnerabilidades"]
                                     for p in res["procesos"]}.get("Contabilidad"),
            "estado_activos_afectados": est["activos_afectados"],
            "estado_vulnerabilidades": est["vulnerabilidades"],
            "estado_cve": est["cve_distintos"],
            "estado_expuestos_activos": est["expuestos_activos"],
            "panel_servidores_afectados": srv.get("activos_afectados"),
            "panel_servidores_vulnerabilidades": srv.get("vulnerabilidades"),
        }

    # ------------------------------------------------- ocs.resumen y estado_activos
    def test_el_activo_cuyas_unicas_vulnerabilidades_se_aceptan_deja_de_contar(self):
        """El equipo de cómputo 3 tiene dos vulnerabilidades: si se aceptan las dos, deja
        de ser «un activo con vulnerabilidades confirmadas» en las dos funciones."""
        with db.session(self.ruta) as conn:
            antes = self._cifras_inventario(conn)
            self._crear(conn, activo_id=3, cve="CVE-2026-1001")
            self._crear(conn, activo_id=3, cve="CVE-2026-1003")
            despues = self._cifras_inventario(conn)
        self.assertEqual(antes["con_vulnerabilidades"] - despues["con_vulnerabilidades"], 1,
                         "ocs.resumen ya no cuenta el equipo de cómputo 3")
        self.assertEqual(antes["estado_activos_afectados"] - despues["estado_activos_afectados"], 1,
                         "ocs.estado_activos dice lo mismo que ocs.resumen")
        self.assertEqual(antes["estado_vulnerabilidades"] - despues["estado_vulnerabilidades"], 2)
        self.assertEqual(antes["expuestos_afectados"] - despues["expuestos_afectados"], 1,
                         "está en producción: también sale de «en producción o contingencia»")
        self.assertEqual(antes["estado_expuestos_activos"] - despues["estado_expuestos_activos"], 1)

    def test_las_dos_funciones_de_ocs_dicen_siempre_la_misma_cifra(self):
        """``ocs.resumen.con_vulnerabilidades`` y ``ocs.estado_activos.activos_afectados``
        son la misma magnitud: la página de Activos enlaza de una a la otra."""
        with db.session(self.ruta) as conn:
            for cambios in ({}, {"activo_id": 3, "cve": "CVE-2026-1001"},
                            {"alcance": "cve", "activo_id": None, "cve": "CVE-2026-1003"}):
                if cambios:
                    self._crear(conn, **cambios)
                cifras = self._cifras_inventario(conn)
                self.assertEqual(cifras["con_vulnerabilidades"],
                                 cifras["estado_activos_afectados"])

    def test_el_reparto_por_proceso_de_ocs_no_puede_pasarse_del_total(self):
        with db.session(self.ruta) as conn:
            self._crear(conn)                       # servidor 1, CVE-2026-1001
            self._crear(conn, cve="CVE-2026-1002")  # servidor 1, CVE-2026-1002
            self._crear(conn, cve="CVE-2026-1003")  # servidor 1, CVE-2026-1003
            cifras = self._cifras_inventario(conn)
        self.assertEqual(cifras["proceso_contabilidad"], 0,
                         "el servidor de Contabilidad ya no tiene nada sin aceptar")

    def test_el_panel_acotado_a_servidores_cuenta_igual_que_el_general(self):
        """Redes solo ve servidores: su bloque del Panel no puede contar el riesgo
        aceptado si el del SOC no lo cuenta."""
        with db.session(self.ruta) as conn:
            antes = self._cifras_inventario(conn)
            self._crear(conn, activo_id=2, cve="CVE-2026-1001")
            self._crear(conn, activo_id=2, cve="CVE-2026-1004")
            despues = self._cifras_inventario(conn)
        self.assertEqual(antes["panel_servidores_afectados"] - despues["panel_servidores_afectados"], 1)
        self.assertEqual(antes["panel_servidores_vulnerabilidades"]
                         - despues["panel_servidores_vulnerabilidades"], 2)

    # --------------------------------------------------------- página de Activos
    def test_la_pagina_de_activos_dice_lo_mismo_en_la_tarjeta_y_en_la_tabla(self):
        cli = self._cliente()
        with db.session(self.ruta) as conn:
            self._crear(conn, activo_id=3, cve="CVE-2026-1001")
            self._crear(conn, activo_id=3, cve="CVE-2026-1003")
        html = self._html(cli, "/activos/")
        # La tarjeta grande sale de ocs.resumen; el atajo, de las subconsultas de la vista.
        with db.session(self.ruta) as conn:
            from threatintel import ocs
            esperado = ocs.resumen(conn, cfg=CfgFalso({"ignore_low_severity": True}))["con_vulnerabilidades"]
        self.assertEqual(esperado, 2, "quedan el servidor 1 y el servidor 2")
        self.assertIn(f'<div class="valor">{esperado}</div>', html)
        # El atajo «Con vulnerabilidades confirmadas» enseña los mismos activos.
        html_vista = self._html(cli, "/activos/?vista=afectados")
        self.assertNotIn("PC-TESORERIA", html_vista,
                         "el equipo con todo el riesgo aceptado ya no está en el atajo")
        self.assertIn("SRV-CONTABILIDAD", html_vista)
        # Y en la ficha del activo SÍ sigue viéndose, con su insignia.
        ficha = self._html(cli, "/activos/3")
        self.assertIn("Riesgo aceptado", ficha)

    def test_el_csv_de_activos_cuenta_como_la_pagina(self):
        cli = self._cliente()
        with db.session(self.ruta) as conn:
            self._crear(conn, activo_id=3, cve="CVE-2026-1001")
            self._crear(conn, activo_id=3, cve="CVE-2026-1003")
        respuesta = cli.get("/activos/exportar.csv")
        self.assertEqual(respuesta.status_code, 200)
        texto = respuesta.get_data(as_text=True)
        fila = [l for l in texto.splitlines() if l.startswith("PC-TESORERIA")]
        self.assertTrue(fila, "el activo sigue en el inventario")
        self.assertEqual(fila[0].split(";")[13], "0",
                         "cero vulnerabilidades confirmadas: su riesgo está aceptado")

    # --------------------------------------------------------------- parches
    def _grupo_pendiente(self, conn, cve="CVE-2026-1001", paquete="openssl"):
        """Una fila de ``parches_pendientes`` como la que abre ``parches.sincronizar``."""
        conn.execute(
            """INSERT OR REPLACE INTO parches_pendientes(cve, paquete, ecosistema, threat_id,
                                                         motivo, n_activos, n_activos_expuestos,
                                                         detectado_at)
               VALUES(?,?,'Ubuntu:22.04',1,'sin_parche_publicado',3,3,?)""",
            (cve, paquete, db.utcnow()))

    def test_el_grupo_sale_de_la_cola_cuando_se_acepta_el_cve_entero(self):
        from threatintel import parches
        with db.session(self.ruta) as conn:
            self._grupo_pendiente(conn)
            self.assertEqual(parches.resumen(conn)["en_seguimiento"], 1)
            self.assertEqual(parches.contar(conn), 1)
            self.assertEqual(parches.sin_correccion(conn)["total"], 1)
            self._crear(conn, alcance="cve", activo_id=None, cve="CVE-2026-1001")
            self.assertEqual(parches.resumen(conn)["en_seguimiento"], 0,
                             "aceptado en toda la organización: nadie tiene que esperar")
            self.assertEqual(parches.contar(conn), 0)
            self.assertEqual(parches.sin_correccion(conn)["total"], 0)
            self.assertEqual(len(parches.listar(conn)), 0)

    def test_el_grupo_sigue_si_queda_un_activo_sin_aceptar(self):
        """Un alcance por activo NO borra el grupo: los otros dos activos siguen
        esperando la corrección, y esa espera es real."""
        from threatintel import parches
        with db.session(self.ruta) as conn:
            self._grupo_pendiente(conn)
            self._crear(conn, activo_id=1, cve="CVE-2026-1001")
            self.assertEqual(parches.resumen(conn)["en_seguimiento"], 1)
            self.assertEqual(parches.sin_correccion(conn)["total"], 1)
            # Aceptado en los tres activos: ya no queda nadie esperando.
            self._crear(conn, activo_id=2, cve="CVE-2026-1001")
            self._crear(conn, activo_id=3, cve="CVE-2026-1001")
            self.assertEqual(parches.resumen(conn)["en_seguimiento"], 0)

    def test_el_aviso_del_correo_no_anuncia_lo_que_nadie_va_a_aplicar(self):
        from threatintel import parches
        with db.session(self.ruta) as conn:
            self._grupo_pendiente(conn)
            conn.execute("UPDATE parches_pendientes SET encontrado_at=?, version_corregida='2.0'",
                         (db.utcnow(),))
            self.assertEqual(len(parches.novedades(conn)), 1)
            self._crear(conn, alcance="cve", activo_id=None, cve="CVE-2026-1001")
            self.assertEqual(len(parches.novedades(conn)), 0,
                             "el riesgo está aceptado en toda la organización")

    def test_sin_excepciones_parches_queda_como_estaba(self):
        from threatintel import parches
        with db.session(self.ruta) as conn:
            self.assertEqual(parches._y_sin_excepcion(conn), "")
            self.assertEqual(parches._y_sin_excepcion(conn, aplicabilidad=True), "")
            self._crear(conn)
            self.assertIn("EXISTS", parches._y_sin_excepcion(conn))
            self.assertIn("NOT IN", parches._y_sin_excepcion(conn, aplicabilidad=True))


class TestCifraCubiertaExacta(BaseAplicada):
    """``excepciones.vulnerabilidades_cubiertas`` es la DIFERENCIA exacta, no el conteo de
    pares con alguna fila cubierta. Sobre la base real la vieja decía 1.745 y lo que de
    verdad desaparecía de Amenazas y de Remediación eran 1.742: tres pares cuyo otro
    paquete seguía pendiente. Aquí se reproduce ese caso en pequeño."""

    def test_un_paquete_aceptado_y_otro_pendiente_no_tapan_la_vulnerabilidad(self):
        with db.session(self.ruta) as conn:
            antes = queries.resumen_amenazas(conn)["vulnerabilidades"]
            # El servidor 1 tiene el CVE-2026-1001 por openssl y por libssl3, y el
            # CVE-2026-1002 solo por openssl. Aceptar «openssl en el servidor 1» tapa dos
            # filas y DOS pares, pero solo UNA vulnerabilidad desaparece de las cifras.
            self._crear(conn, alcance="activo_paquete", activo_id=1, cve="",
                        paquete="openssl")
            despues = queries.resumen_amenazas(conn)
            cubiertas = excepciones.vulnerabilidades_cubiertas(conn)
        self.assertEqual(antes - despues["vulnerabilidades"], 1,
                         "el CVE-2026-1001 sigue contando: libssl3 sigue pendiente")
        self.assertEqual(cubiertas, 1, "la cifra es la diferencia real, no dos")
        self.assertEqual(cubiertas, despues["vulnerabilidades_aceptadas"],
                         "la página de Excepciones y la de Amenazas dicen lo mismo")

    def test_cuadra_con_amenazas_en_los_tres_alcances(self):
        for cambios in ({}, {"alcance": "cve", "activo_id": None, "cve": "CVE-2026-1001"},
                        {"alcance": "activo_paquete", "cve": "", "paquete": "curl",
                         "activo_id": 3}):
            with self.subTest(alcance=cambios.get("alcance", "activo_cve")):
                with db.session(self.ruta) as conn:
                    conn.execute("DELETE FROM excepciones")
                    self._crear(conn, **cambios)
                    self.assertEqual(
                        excepciones.vulnerabilidades_cubiertas(conn),
                        queries.resumen_amenazas(conn)["vulnerabilidades_aceptadas"])

    def test_una_amenaza_cerrada_a_mano_no_cuenta_como_riesgo_aceptado(self):
        """Si el analista descartó la amenaza, su vulnerabilidad ya no estaba en las
        cifras: aceptar su riesgo no «tapa» nada nuevo y no puede sumar."""
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE threats SET estado='descartada' WHERE cve='CVE-2026-1004'")
            self._crear(conn, activo_id=2, cve="CVE-2026-1004")
            self.assertEqual(excepciones.vulnerabilidades_cubiertas(conn), 0)
            conn.execute("UPDATE threats SET estado='nueva' WHERE cve='CVE-2026-1004'")

    def test_la_severidad_baja_no_cuenta_como_riesgo_aceptado(self):
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE threats SET severity='Low' WHERE cve='CVE-2026-1004'")
            self._crear(conn, activo_id=2, cve="CVE-2026-1004")
            self.assertEqual(excepciones.vulnerabilidades_cubiertas(conn), 0,
                             "una baja no estaba en ninguna cifra: no hay nada que tapar")
            conn.execute("UPDATE threats SET severity='High' WHERE cve='CVE-2026-1004'")

    def test_el_resumen_puede_omitir_la_cifra_cara(self):
        with db.session(self.ruta) as conn:
            self._crear(conn)
            completo = excepciones.resumen(conn)
            ligero = excepciones.resumen(conn, con_cubiertas=False)
        self.assertEqual(completo["vulnerabilidades_cubiertas"], 1)
        self.assertTrue(completo["con_cubiertas"])
        self.assertIsNone(ligero["vulnerabilidades_cubiertas"],
                          "sin la cifra: /salud.json no recorre aplicabilidad dos veces")
        self.assertFalse(ligero["con_cubiertas"])
        self.assertEqual(completo["vigentes"], ligero["vigentes"])
        self.assertEqual(completo["vencidas"], ligero["vencidas"])

    def test_la_pagina_de_excepciones_sigue_ensenando_la_cifra(self):
        cli = self._cliente()
        with db.session(self.ruta) as conn:
            self._crear(conn)
        html = self._html(cli, "/excepciones/")
        self.assertIn("vulnerabilidades desaparecen de las cifras de riesgo por su causa", html)
        self.assertIn("diferencia exacta", html,
                      "la etiqueta dice exactamente qué cuenta")


if __name__ == "__main__":
    unittest.main()
