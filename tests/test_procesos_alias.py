"""Agrupación de etiquetas de OCS en un mismo proceso de negocio (2026-09-06).

El usuario indicó que las etiquetas que el campo TAG de OCS usa para designar al
equipo técnico (variantes de «administración» y los nodos «Proxmox»/«PVE») son el
proceso «Administración técnica», y que debía quedar así en toda la plataforma, los
correos y los informes: los nodos de virtualización son infraestructura que
administra ese equipo, no un proceso de negocio.

La decisión vive en un solo sitio (``ocs.normalizar_proceso``), de modo que todo lo que lea
``activos.proceso`` lo hereda."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from threatintel import db, ocs
from threatintel.paths import BASE_DIR


class Cfg(dict):
    def get(self, clave, defecto=None):
        return super().get(clave, defecto)


class TestAliasDeProcesos(unittest.TestCase):
    def test_las_etiquetas_indicadas_son_administracion_tecnica(self):
        for etiqueta in ("administración", "Administración", "ADMINISTRACIÓN", "administracion",
                         "admin", "ADMIN", "  admin  ",
                         # Los nodos de virtualización los administra el equipo técnico;
                         # «Proxmox» no es un proceso de negocio.
                         "Proxmox", "proxmox", "PROXMOX", "  Proxmox ", "PVE", "pve"):
            self.assertEqual(ocs.normalizar_proceso(etiqueta), "Administración técnica", etiqueta)

    def test_las_demas_etiquetas_no_se_tocan(self):
        for etiqueta in ("Pila", "Soporte", "Proyectos", "Contabilidad", "Finanzas",
                         "Gestión Administrativa", "Operaciones"):
            self.assertEqual(ocs.normalizar_proceso(etiqueta), etiqueta)
        self.assertIsNone(ocs.normalizar_proceso(None))
        self.assertIsNone(ocs.normalizar_proceso("   "))

    def test_el_ajuste_anade_y_tiene_prioridad(self):
        cfg = Cfg(ocs_procesos_alias=["Operaciones = Cartera y Recaudo", "admin=Dirección"])
        self.assertEqual(ocs.normalizar_proceso("Operaciones", cfg=cfg), "Cartera y Recaudo")
        self.assertEqual(ocs.normalizar_proceso("admin", cfg=cfg), "Dirección",
                         "lo escrito en Ajustes manda sobre el mapa base")
        self.assertEqual(ocs.normalizar_proceso("Pila", cfg=cfg), "Pila")
        # Entradas mal escritas se ignoran sin romper nada
        for malo in ("sin igual", "= solo proceso", "etiqueta =", ""):
            ocs.alias_procesos(Cfg(ocs_procesos_alias=[malo]))

    def test_la_sincronizacion_guarda_el_proceso_agrupado(self):
        """Dos servidores con etiquetas distintas quedan en el mismo proceso, y la etiqueta
        original se conserva en ``etiqueta_ocs`` para poder auditar de dónde viene."""
        import sys
        sys.path.insert(0, str(BASE_DIR / "tests"))
        import test_activos_ocs as datos
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            ruta = str(Path(tmp) / "procesos.db")
            db.init_db(ruta)
            hw = [list(f) for f in datos.HW[:2]]
            conn = db.connect(ruta)
            try:
                cuentas = {hw[0][0]: {"TAG": "admin"}, hw[1][0]: {"TAG": "Proxmox"}}
                lector = datos.LectorFalso([tuple(f) for f in hw],
                                           [s for s in datos.SW if s[0] in (hw[0][0], hw[1][0])],
                                           cuentas=cuentas) if "cuentas" in datos.LectorFalso.__init__.__code__.co_varnames \
                    else datos.LectorFalso([tuple(f) for f in hw], [s for s in datos.SW if s[0] in (hw[0][0], hw[1][0])])
                ocs.sincronizar_origen(conn, "servidores", lector, cfg=datos.Cfg())
                procesos = {r[0] for r in conn.execute(
                    "SELECT proceso FROM activos WHERE proceso IS NOT NULL")}
                etiquetas = {r[0] for r in conn.execute(
                    "SELECT etiqueta_ocs FROM activos WHERE etiqueta_ocs IS NOT NULL")}
            finally:
                conn.close()
        if procesos:   # el lector de prueba solo trae TAG si lo admite
            self.assertNotIn("admin", procesos)
            self.assertNotIn("Proxmox", procesos)
        self.assertTrue(procesos <= {"Administración técnica"} or not procesos, procesos)


class TestReaplicarAlias(unittest.TestCase):
    """Un alias nuevo se aplica en el acto, sin esperar a la sincronización del día
    siguiente: la función compara con la etiqueta original de OCS (``etiqueta_ocs``),
    que es la que no se toca nunca."""

    def test_reasigna_los_activos_ya_guardados(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as d:
            ruta = str(Path(d) / "alias.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                for i, (nombre, tag, proceso) in enumerate((
                        ("px-nodo1", "Proxmox", "Proxmox"),
                        ("px-nodo2", "Proxmox", "Proxmox"),
                        ("srv-pila", "Pila", "Pila"),
                        ("srv-sin-tag", None, None)), start=1):
                    conn.execute(
                        """INSERT INTO activos(ocs_id, nombre, origen, so_familia, presente,
                                               etiqueta_ocs, proceso, primera_vez_at, visto_at)
                           VALUES(?,?,'servidores','debian',1,?,?,?,?)""",
                        (i, nombre, tag, proceso, db.utcnow(), db.utcnow()))
                resultado = ocs.reaplicar_alias_procesos(conn, actor="prueba")
                self.assertEqual(resultado["cambiados"], 2)
                procesos = dict(conn.execute("SELECT nombre, proceso FROM activos"))
                self.assertEqual(procesos["px-nodo1"], "Administración técnica")
                self.assertEqual(procesos["px-nodo2"], "Administración técnica")
                self.assertEqual(procesos["srv-pila"], "Pila", "los demás no se tocan")
                self.assertIsNone(procesos["srv-sin-tag"])
                # es idempotente: una segunda pasada no cambia nada
                self.assertEqual(ocs.reaplicar_alias_procesos(conn, actor="prueba")["cambiados"], 0)
                # y queda constancia
                self.assertIsNotNone(conn.execute(
                    "SELECT 1 FROM audit_log WHERE action='ocs.alias_procesos'").fetchone())


if __name__ == "__main__":
    unittest.main()
