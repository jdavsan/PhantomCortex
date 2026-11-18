"""Seguimiento de remediación con cierre automático (esquema v6, 2026-09-05).

Sin red: los activos, amenazas, software y veredictos de aplicabilidad se insertan a mano
en una base temporal. Comprueba el ciclo completo de ``threatintel.remediacion.sincronizar``
(abrir, comprobar, cerrar por versión corregida, cerrar por desinstalación o cambio de versión,
no cerrar cuando la fila desaparece con la misma versión instalada, parche de Windows del motor
msrc que solo se cierra con una fila «no_afectado» de Microsoft, activo ausente, reabrir, idempotencia), las consultas de las vistas (historial, resumen, listado) y la
página /remediaciones/ (sesión, filtros, CSV, recorrido guiado, CSP sin style= ni on*=)."""
from __future__ import annotations

import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatintel import db, remediacion
from threatintel.paths import BASE_DIR

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


AHORA = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
T0 = _iso(AHORA - timedelta(days=10))      # evaluación que detectó la vulnerabilidad
T1 = _iso(AHORA - timedelta(days=3))       # sincronización siguiente
T2 = _iso(AHORA)                           # sincronización de hoy
T3 = _iso(AHORA + timedelta(days=2))


def _activo(conn, nombre, *, ip="10.0.0.1", entorno="produccion", proceso="Pila", presente=1, origen="servidores"):
    cur = conn.execute(
        """INSERT INTO activos(origen, ocs_id, nombre, so_familia, so_nombre, ip, entorno, proceso, presente,
                               primera_vez_at, visto_at)
           VALUES(?, (SELECT COALESCE(MAX(ocs_id), 0) + 1 FROM activos), ?, 'ubuntu', 'Ubuntu 22.04', ?, ?, ?, ?, ?, ?)""",
        (origen, nombre, ip, entorno, proceso, presente, T0, T0))
    return cur.lastrowid


def _amenaza(conn, cve, *, severity="High", in_kev=0, estado="nueva", titulo=None):
    cur = conn.execute(
        """INSERT INTO threats(fingerprint, cve, title_en, title_es, severity, first_seen_at, last_seen_at, month,
                               estado, in_kev)
           VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (f"fp-{cve}", cve, f"{cve} english title", titulo, severity, T0, T0, T0[:7], estado, in_kev))
    return cur.lastrowid


def _software(conn, activo_id, paquete, version):
    conn.execute("INSERT OR REPLACE INTO activo_software(activo_id, nombre, nombre_norm, version) VALUES(?,?,?,?)",
                 (activo_id, paquete, paquete, version))


def _veredicto(conn, activo_id, threat_id, cve, paquete, instalada, corregida, veredicto, evaluado_at=T0, motor="osv"):
    conn.execute(
        """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada, version_corregida,
                                     veredicto, motor, evidencia, aviso, evaluado_at)
           VALUES(?,?,?,?,?,?,?,?,'prueba','USN-1',?)
           ON CONFLICT(activo_id, cve, paquete) DO UPDATE SET version_instalada=excluded.version_instalada,
               veredicto=excluded.veredicto, evaluado_at=excluded.evaluado_at""",
        (activo_id, threat_id, cve, paquete, instalada, corregida, veredicto, motor, evaluado_at))


def _fila(conn, activo_id, cve, paquete):
    r = conn.execute("SELECT * FROM remediaciones WHERE activo_id=? AND cve=? AND paquete=?",
                     (activo_id, cve, paquete)).fetchone()
    return dict(r) if r else None


class TestSincronizar(unittest.TestCase):
    """Ciclo de vida de una remediación con base temporal nueva por prueba."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "remediacion.db")
        db.init_db(self.ruta)
        self.conn = db.connect(self.ruta)
        c = self.conn
        self.web = _activo(c, "srv-web-01", ip="10.0.0.11", proceso="Pila")
        self.db_ = _activo(c, "srv-db-01", ip="10.0.0.12", entorno="desarrollo", proceso="Helpvoz")
        self.t_curl = _amenaza(c, "CVE-2024-11053", severity="High", titulo="Fuga de credenciales en curl")
        self.t_ssl = _amenaza(c, "CVE-2026-0001", severity="Critical", in_kev=1, estado="descartada")
        _software(c, self.web, "curl", "7.81.0-1ubuntu1.15")
        _software(c, self.web, "openssl", "3.0.2-0ubuntu1.10")
        _software(c, self.db_, "curl", "7.81.0-1ubuntu1.15")
        _veredicto(c, self.web, self.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.15", "7.81.0-1ubuntu1.20", "afectado")
        _veredicto(c, self.web, self.t_ssl, "CVE-2026-0001", "openssl", "3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.18", "afectado")
        _veredicto(c, self.db_, self.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.15", "7.81.0-1ubuntu1.20", "afectado")
        # Un «no afectado» desde el principio nunca abre remediación
        _veredicto(c, self.db_, self.t_ssl, "CVE-2026-0001", "openssl", "3.0.2-0ubuntu1.18", "3.0.2-0ubuntu1.18", "no_afectado")

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    def test_abrir(self):
        r = remediacion.sincronizar(self.conn, ahora=T1)
        self.assertEqual(r["abiertas_nuevas"], 3)
        self.assertEqual(r["abiertas"], 3)
        self.assertEqual((r["cerradas"], r["activo_ausente"], r["comprobadas"], r["reabiertas"]), (0, 0, 0, 0))
        f = _fila(self.conn, self.web, "CVE-2024-11053", "curl")
        self.assertEqual(f["estado"], "abierta")
        self.assertEqual(f["detectado_at"], T0, "detectado_at es la fecha de la evaluación, no la de hoy")
        self.assertEqual(f["comprobado_at"], T1)
        self.assertEqual((f["version_vulnerable"], f["version_corregida"], f["motor"], f["threat_id"]),
                         ("7.81.0-1ubuntu1.15", "7.81.0-1ubuntu1.20", "osv", self.t_curl))
        self.assertIsNone(f["corregido_at"])
        # La amenaza descartada a mano abre igualmente: el estado de la amenaza es otra dimensión
        self.assertEqual(_fila(self.conn, self.web, "CVE-2026-0001", "openssl")["estado"], "abierta")
        self.assertIsNone(_fila(self.conn, self.db_, "CVE-2026-0001", "openssl"))
        # Auditoría de la escritura
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='remediacion.sincronizar'").fetchone()[0], 1)

    def test_comprobar_e_idempotencia(self):
        remediacion.sincronizar(self.conn, ahora=T1)
        antes = [dict(r) for r in self.conn.execute("SELECT * FROM remediaciones ORDER BY id")]
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual((r["abiertas_nuevas"], r["cerradas"], r["activo_ausente"], r["reabiertas"]), (0, 0, 0, 0))
        self.assertEqual(r["comprobadas"], 3)
        despues = [dict(r) for r in self.conn.execute("SELECT * FROM remediaciones ORDER BY id")]
        for a, d in zip(antes, despues):
            self.assertEqual(d.pop("comprobado_at"), T2)
            a.pop("comprobado_at")
            self.assertEqual(a, d, "solo cambia comprobado_at")
        # Sin cambios no se añade auditoría
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='remediacion.sincronizar'").fetchone()[0], 1)

    def test_cerrar_por_version_corregida(self):
        remediacion.sincronizar(self.conn, ahora=T1)
        # La reevaluación ve la versión corregida
        _veredicto(self.conn, self.web, self.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.20",
                   "7.81.0-1ubuntu1.20", "no_afectado", evaluado_at=T2)
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["cerradas"], 1)
        self.assertEqual(r["abiertas"], 2)
        self.assertEqual(r["comprobadas"], 2)
        f = _fila(self.conn, self.web, "CVE-2024-11053", "curl")
        self.assertEqual(f["estado"], "corregida")
        self.assertEqual(f["corregido_at"], T2)
        self.assertEqual(f["version_final"], "7.81.0-1ubuntu1.20")
        self.assertEqual(f["cerrado_motivo"], "La sincronización vio la versión 7.81.0-1ubuntu1.20, que ya incluye la corrección")
        self.assertEqual(f["detectado_at"], T0)
        # La del otro activo sigue pendiente
        self.assertEqual(_fila(self.conn, self.db_, "CVE-2024-11053", "curl")["estado"], "abierta")

    def test_cerrar_por_paquete_desinstalado(self):
        remediacion.sincronizar(self.conn, ahora=T1)
        # La reevaluación borra la fila (el paquete ya no está) y OCS ya no lo lista
        self.conn.execute("DELETE FROM aplicabilidad WHERE activo_id=? AND paquete='openssl'", (self.web,))
        self.conn.execute("DELETE FROM activo_software WHERE activo_id=? AND nombre_norm='openssl'", (self.web,))
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["cerradas"], 1)
        f = _fila(self.conn, self.web, "CVE-2026-0001", "openssl")
        self.assertEqual(f["estado"], "corregida")
        self.assertEqual(f["cerrado_motivo"], remediacion.MOTIVO_DESINSTALADO)
        self.assertEqual(f["corregido_at"], T2)
        self.assertIsNone(f["version_final"])
        self.assertTrue(remediacion.historial_activo(self.conn, self.web)[-1]["desinstalado"])

    def test_cerrar_sin_fila_pero_paquete_con_otra_version(self):
        remediacion.sincronizar(self.conn, ahora=T1)
        # La fila desapareció y OCS ve otra versión del paquete: cambio confirmado, se cierra
        self.conn.execute("DELETE FROM aplicabilidad WHERE activo_id=? AND paquete='openssl'", (self.web,))
        _software(self.conn, self.web, "openssl", "3.0.2-0ubuntu1.18")
        self.conn.execute("DELETE FROM activo_software WHERE activo_id=? AND version='3.0.2-0ubuntu1.10'", (self.web,))
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["cerradas"], 1)
        self.assertEqual(r["sin_evaluar"], 0)
        f = _fila(self.conn, self.web, "CVE-2026-0001", "openssl")
        self.assertEqual(f["estado"], "corregida")
        self.assertEqual(f["corregido_at"], T2)
        self.assertEqual(f["version_final"], "3.0.2-0ubuntu1.18")
        self.assertIn("3.0.2-0ubuntu1.18", f["cerrado_motivo"])
        self.assertIn("3.0.2-0ubuntu1.10", f["cerrado_motivo"], "el motivo cita la versión vulnerable y la nueva")
        self.assertNotEqual(f["cerrado_motivo"], remediacion.MOTIVO_DESINSTALADO)
        self.assertFalse(remediacion.historial_activo(self.conn, self.web)[-1]["desinstalado"])

    def test_sin_fila_con_misma_version_no_cierra(self):
        """Hallazgo del revisor: las filas de aplicabilidad también desaparecen por una evaluación
        incompleta (OSV.dev sin respuesta o cupo agotado), por la purga de retención de la amenaza
        o por un cambio en el mapa de nombres. Si OCS sigue viendo la misma versión vulnerable no
        hay corrección que afirmar: la remediación se queda pendiente con su fecha original."""
        remediacion.sincronizar(self.conn, ahora=T1)
        self.conn.execute("DELETE FROM aplicabilidad WHERE activo_id=? AND cve='CVE-2024-11053'", (self.web,))
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual((r["cerradas"], r["reabiertas"], r["abiertas_nuevas"]), (0, 0, 0))
        self.assertEqual(r["sin_evaluar"], 1)
        self.assertEqual(r["abiertas"], 3)
        f = _fila(self.conn, self.web, "CVE-2024-11053", "curl")
        self.assertEqual(f["estado"], "abierta")
        self.assertEqual(f["detectado_at"], T0)
        self.assertEqual(f["comprobado_at"], T1, "sin fila no se puede afirmar que siga vulnerable")
        self.assertIsNone(f["corregido_at"])
        self.assertIsNone(f["version_final"])
        res = remediacion.resumen(self.conn, dias=30)
        self.assertEqual((res["corregidas_periodo"], res["tiempo_medio_dias"]), (0, None))
        # Sin cambios reales tampoco hay auditoría nueva
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='remediacion.sincronizar'").fetchone()[0], 1)
        # Lo mismo tras una evaluación incompleta real: evaluar_amenaza con OSV.dev caído borra las
        # filas anteriores de la amenaza y no escribe ninguna nueva.
        from threatintel import aplicabilidad

        class OSVCaido:
            def registro(self, *a, **k):
                raise aplicabilidad.ErrorOSV("cupo de consultas a OSV.dev agotado")

            def consultar(self, *a, **k):
                raise aplicabilidad.ErrorOSV("cupo de consultas a OSV.dev agotado")

            def __getattr__(self, nombre):
                def _f(*a, **k):
                    raise aplicabilidad.ErrorOSV("cupo de consultas a OSV.dev agotado")
                return _f

        amenaza = dict(self.conn.execute("SELECT * FROM threats WHERE id=?", (self.t_curl,)).fetchone())
        _veredicto(self.conn, self.web, self.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.15",
                   "7.81.0-1ubuntu1.20", "afectado", evaluado_at=T0)
        self.conn.execute("UPDATE activos SET ecosistema='Ubuntu:22.04' WHERE presente=1")
        res_eval = aplicabilidad.evaluar_amenaza(self.conn, amenaza, osv=OSVCaido(), vuxml=None, ahora=T3)
        self.assertTrue(res_eval["incompleta"])
        self.assertTrue(any("OSV.dev" in e for e in res_eval["errores"]))
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM aplicabilidad WHERE threat_id=?", (self.t_curl,)).fetchone()[0], 0)
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual(r["cerradas"], 0)
        self.assertEqual(_fila(self.conn, self.web, "CVE-2024-11053", "curl")["estado"], "abierta")
        self.assertEqual(_fila(self.conn, self.db_, "CVE-2024-11053", "curl")["estado"], "abierta")
        # Cuando OSV vuelve a responder y la fila reaparece «afectado», solo se comprueba: ni se
        # reabre ni cuenta como detección nueva.
        _veredicto(self.conn, self.web, self.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.15",
                   "7.81.0-1ubuntu1.20", "afectado", evaluado_at=T3)
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual((r["cerradas"], r["reabiertas"], r["abiertas_nuevas"]), (0, 0, 0))
        f = _fila(self.conn, self.web, "CVE-2024-11053", "curl")
        self.assertEqual((f["estado"], f["detectado_at"], f["comprobado_at"]), ("abierta", T0, T3))
        # Amenaza purgada por retención (borrado en cascada de aplicabilidad): sigue pendiente
        self.conn.execute("DELETE FROM threats WHERE id=?", (self.t_ssl,))
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual(r["cerradas"], 0)
        f = _fila(self.conn, self.web, "CVE-2026-0001", "openssl")
        self.assertEqual((f["estado"], f["detectado_at"]), ("abierta", T0))
        huerfana = [h for h in remediacion.historial_activo(self.conn, self.web) if h["cve"] == "CVE-2026-0001"][0]
        self.assertEqual(huerfana["titulo"], "CVE-2026-0001", "sin amenaza el título es el CVE")
        self.assertEqual(huerfana["estado_es"], "Pendiente")

    def test_sistema_base_freebsd(self):
        """El «paquete» freebsd de VuXML es el sistema base: no está en activo_software y no se
        desinstala. Sin fila de aplicabilidad solo se cierra si cambió la versión del sistema."""
        bsd = _activo(self.conn, "srv-bsd-01", ip="10.0.0.13", proceso="Pila")
        self.conn.execute("UPDATE activos SET so_familia='freebsd', so_nombre='FreeBSD 14.4', so_version='14.4-RELEASE-p6' WHERE id=?", (bsd,))
        t_bsd = _amenaza(self.conn, "CVE-2026-0002", severity="High")
        _veredicto(self.conn, bsd, t_bsd, "CVE-2026-0002", "freebsd", "14.4_6", "14.4_7", "afectado", motor="vuxml")
        r = remediacion.sincronizar(self.conn, ahora=T1)
        self.assertEqual(r["abiertas_nuevas"], 4)
        self.conn.execute("DELETE FROM aplicabilidad WHERE activo_id=?", (bsd,))
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["cerradas"], 0, "el sistema base no se «desinstala»")
        self.assertEqual(r["sin_evaluar"], 1)
        f = _fila(self.conn, bsd, "CVE-2026-0002", "freebsd")
        self.assertEqual((f["estado"], f["detectado_at"], f["comprobado_at"]), ("abierta", T0, T1))
        # El sistema se actualizó al parche 7: OCS lo confirma y se cierra con la versión nueva
        self.conn.execute("UPDATE activos SET so_version='14.4-RELEASE-p7' WHERE id=?", (bsd,))
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual(r["cerradas"], 1)
        f = _fila(self.conn, bsd, "CVE-2026-0002", "freebsd")
        self.assertEqual((f["estado"], f["corregido_at"], f["version_final"]), ("corregida", T3, "14.4_7"))
        self.assertIn("14.4_6", f["cerrado_motivo"])
        self.assertIn("14.4_7", f["cerrado_motivo"])
        self.assertNotEqual(f["cerrado_motivo"], remediacion.MOTIVO_DESINSTALADO)

    def _windows(self, nombre="pc-contab-01", build="10.0.26100.3000", kb="KB5050009"):
        """Equipo Windows evaluado por el motor de parches (threatintel.msrc): la compilación
        efectiva y la acumulativa instalada viven en activos.windows_build / windows_kb."""
        win = _activo(self.conn, nombre, ip="10.1.1.50", proceso="Contabilidad", origen="equipos")
        self.conn.execute("UPDATE activos SET so_familia='windows', so_nombre='Microsoft Windows 11 Pro', "
                          "so_version='10.0.26100', windows_build=?, windows_kb=? WHERE id=?", (build, kb, win))
        return win

    def test_msrc_abre_y_no_cierra_sin_fila(self):
        """Parche de Windows (motor msrc, paquete 'windows'): no es un paquete de activo_software,
        así que la regla «paquete desinstalado» del paso 4 mentiría. Si la fila desaparece (ventana
        de boletines, producto MSRC perdido, borrado del motor principal) sigue pendiente."""
        win = self._windows()
        t_win = _amenaza(self.conn, "CVE-2026-21001", severity="Critical", in_kev=1)
        _veredicto(self.conn, win, t_win, "CVE-2026-21001", "windows", "10.0.26100.3000", "10.0.26100.3194",
                   "afectado", motor="msrc")
        r = remediacion.sincronizar(self.conn, ahora=T1)
        self.assertEqual(r["abiertas_nuevas"], 4)
        f = _fila(self.conn, win, "CVE-2026-21001", "windows")
        self.assertEqual((f["estado"], f["motor"], f["version_vulnerable"], f["version_corregida"], f["detectado_at"]),
                         ("abierta", "msrc", "10.0.26100.3000", "10.0.26100.3194", T0))
        # La fila msrc desaparece y 'windows' no está en activo_software: NO es una desinstalación
        self.conn.execute("DELETE FROM aplicabilidad WHERE activo_id=? AND paquete='windows'", (win,))
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual((r["cerradas"], r["reabiertas"], r["abiertas_nuevas"]), (0, 0, 0))
        self.assertEqual(r["sin_evaluar"], 1, "subestado «sin evaluar»")
        f = _fila(self.conn, win, "CVE-2026-21001", "windows")
        self.assertEqual((f["estado"], f["detectado_at"], f["comprobado_at"]), ("abierta", T0, T1),
                         "sin fila no se toca comprobado_at")
        self.assertIsNone(f["corregido_at"])
        self.assertNotEqual(f["cerrado_motivo"], remediacion.MOTIVO_DESINSTALADO)
        self.assertFalse(any(h["desinstalado"] for h in remediacion.historial_activo(self.conn, win)))
        self.assertTrue(remediacion.historial_activo(self.conn, win)[0]["msrc"])
        # Dos ejecuciones seguidas sin fila: idempotente (ni cambia nada ni audita)
        antes = [dict(x) for x in self.conn.execute("SELECT * FROM remediaciones ORDER BY id")]
        auditorias = self.conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='remediacion.sincronizar'").fetchone()[0]
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual((r["cerradas"], r["reabiertas"], r["abiertas_nuevas"], r["sin_evaluar"]), (0, 0, 0, 1))
        self.assertEqual(_fila(self.conn, win, "CVE-2026-21001", "windows"), antes[-1])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='remediacion.sincronizar'").fetchone()[0], auditorias)
        # El equipo pierde su compilación (sin producto MSRC): sigue pendiente igualmente
        self.conn.execute("UPDATE activos SET windows_build=NULL, windows_kb=NULL WHERE id=?", (win,))
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual(r["cerradas"], 0)
        self.assertEqual(_fila(self.conn, win, "CVE-2026-21001", "windows")["estado"], "abierta")
        # Vuelve la fila «afectado» (msrc la regeneró): solo se comprueba, sin reabrir ni duplicar
        self.conn.execute("UPDATE activos SET windows_build='10.0.26100.3000', windows_kb='KB5050009' WHERE id=?", (win,))
        _veredicto(self.conn, win, t_win, "CVE-2026-21001", "windows", "10.0.26100.3000", "10.0.26100.3194",
                   "afectado", evaluado_at=T3, motor="msrc")
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual((r["cerradas"], r["reabiertas"], r["abiertas_nuevas"], r["sin_evaluar"]), (0, 0, 0, 0))
        f = _fila(self.conn, win, "CVE-2026-21001", "windows")
        self.assertEqual((f["estado"], f["detectado_at"], f["comprobado_at"]), ("abierta", T0, T3))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM remediaciones WHERE activo_id=?", (win,)).fetchone()[0], 1)

    def test_msrc_cierra_con_motivo_de_microsoft(self):
        """La única forma de cerrar un parche de Windows: la fila msrc del mismo activo y CVE pasa a
        «no_afectado» con compilación conocida. El motivo cita los boletines de Microsoft, la
        compilación instalada y la KB que lleva el equipo."""
        win = self._windows()
        t_win = _amenaza(self.conn, "CVE-2026-21001", severity="Critical")
        _veredicto(self.conn, win, t_win, "CVE-2026-21001", "windows", "10.0.26100.3000", "10.0.26100.3194",
                   "afectado", motor="msrc")
        remediacion.sincronizar(self.conn, ahora=T1)
        # Fila no_afectado pero el activo sin compilación: no se afirma nada
        _veredicto(self.conn, win, t_win, "CVE-2026-21001", "windows", "10.0.26100.3194", "10.0.26100.3194",
                   "no_afectado", evaluado_at=T2, motor="msrc")
        self.conn.execute("UPDATE activos SET windows_build=NULL, windows_kb=NULL WHERE id=?", (win,))
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["cerradas"], 0)
        f = _fila(self.conn, win, "CVE-2026-21001", "windows")
        self.assertEqual((f["estado"], f["comprobado_at"]), ("abierta", T1))
        # Fila no_afectado sin compilación comparada: tampoco
        self.conn.execute("UPDATE activos SET windows_build='10.0.26100.3194', windows_kb='KB5051987' WHERE id=?", (win,))
        self.conn.execute("UPDATE aplicabilidad SET version_instalada=NULL WHERE activo_id=? AND paquete='windows'", (win,))
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["cerradas"], 0)
        self.assertEqual(_fila(self.conn, win, "CVE-2026-21001", "windows")["estado"], "abierta")
        # El equipo instaló la acumulativa: OCS ve la KB, msrc escribe no_afectado con la compilación
        _veredicto(self.conn, win, t_win, "CVE-2026-21001", "windows", "10.0.26100.3194", "10.0.26100.3194",
                   "no_afectado", evaluado_at=T2, motor="msrc")
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["cerradas"], 1)
        f = _fila(self.conn, win, "CVE-2026-21001", "windows")
        self.assertEqual((f["estado"], f["corregido_at"], f["version_final"], f["detectado_at"]),
                         ("corregida", T2, "10.0.26100.3194", T0))
        self.assertEqual(f["cerrado_motivo"], "Los boletines de Microsoft ya no señalan este CVE en la compilación "
                                              "instalada 10.0.26100.3194 (KB5051987)")
        self.assertEqual(f["cerrado_motivo"], remediacion.MOTIVO_MSRC.format(version="10.0.26100.3194", kb="KB5051987"))
        hist = [h for h in remediacion.historial_activo(self.conn, win) if h["cve"] == "CVE-2026-21001"][0]
        self.assertFalse(hist["desinstalado"])
        self.assertTrue(hist["msrc"])
        self.assertEqual(hist["dias"], 10)
        # Las de otros motores conservan su motivo de siempre
        _veredicto(self.conn, self.web, self.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.20",
                   "7.81.0-1ubuntu1.20", "no_afectado", evaluado_at=T2)
        remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(_fila(self.conn, self.web, "CVE-2024-11053", "curl")["cerrado_motivo"],
                         remediacion.MOTIVO_CORREGIDA.format(version="7.81.0-1ubuntu1.20"))
        # Idempotencia: otra ejecución no cambia nada; y si la fila msrc desaparece después
        # (corrección fuera de la ventana de boletines) la corregida se queda como está.
        antes = _fila(self.conn, win, "CVE-2026-21001", "windows")
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual((r["cerradas"], r["reabiertas"], r["abiertas_nuevas"]), (0, 0, 0))
        self.assertEqual(_fila(self.conn, win, "CVE-2026-21001", "windows"), antes)
        self.conn.execute("DELETE FROM aplicabilidad WHERE activo_id=? AND paquete='windows'", (win,))
        remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual(_fila(self.conn, win, "CVE-2026-21001", "windows"), antes)
        # Regresión: la fila vuelve a «afectado» (compilación anterior) y se reabre como las demás
        _veredicto(self.conn, win, t_win, "CVE-2026-21001", "windows", "10.0.26100.3000", "10.0.26100.3194",
                   "afectado", evaluado_at=T3, motor="msrc")
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual(r["reabiertas"], 1)
        f = _fila(self.conn, win, "CVE-2026-21001", "windows")
        self.assertEqual((f["estado"], f["motor"], f["detectado_at"]), ("abierta", "msrc", T3))
        self.assertIn("Antes: Los boletines de Microsoft ya no señalan", f["cerrado_motivo"])

    def test_motor_nulo_no_se_confunde_con_parche_de_windows(self):
        """La columna ``remediaciones.motor`` admite nulos (fila heredada o creada a mano). La
        seña del parche de Windows debe seguir siendo falsa con motor nulo: si la expresión se
        evaluara con la lógica de tres valores de SQL, ni su negación sería cierta y la
        remediación no se cerraría jamás ni por el paso 3 ni por el paso 4."""
        remediacion.sincronizar(self.conn, ahora=T1)
        self.conn.execute("UPDATE remediaciones SET motor=NULL")
        # Paso 4: el paquete ya no está instalado y la fila de evaluación desapareció
        self.conn.execute("DELETE FROM activo_software WHERE activo_id=? AND nombre_norm='curl'", (self.web,))
        self.conn.execute("DELETE FROM aplicabilidad WHERE activo_id=? AND paquete='curl'", (self.web,))
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["cerradas"], 1)
        f = _fila(self.conn, self.web, "CVE-2024-11053", "curl")
        self.assertEqual((f["estado"], f["cerrado_motivo"]), ("corregida", remediacion.MOTIVO_DESINSTALADO))
        # Paso 3: la evaluación ve la versión corregida y el motivo es el de siempre, no el de Microsoft
        _veredicto(self.conn, self.web, self.t_ssl, "CVE-2026-0001", "openssl", "3.0.2-0ubuntu1.18",
                   "3.0.2-0ubuntu1.18", "no_afectado", evaluado_at=T2)
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["cerradas"], 1)
        f = _fila(self.conn, self.web, "CVE-2026-0001", "openssl")
        self.assertEqual(f["cerrado_motivo"], remediacion.MOTIVO_CORREGIDA.format(version="3.0.2-0ubuntu1.18"))
        # Con paquete 'windows' y motor nulo sí es un parche de Windows: nunca «desinstalado»
        win = self._windows()
        t_win = _amenaza(self.conn, "CVE-2026-21002", severity="High")
        _veredicto(self.conn, win, t_win, "CVE-2026-21002", "windows", "10.0.26100.3000", "10.0.26100.3194",
                   "afectado", evaluado_at=T2, motor="msrc")
        remediacion.sincronizar(self.conn, ahora=T2)
        self.conn.execute("UPDATE remediaciones SET motor=NULL WHERE activo_id=?", (win,))
        self.conn.execute("DELETE FROM aplicabilidad WHERE activo_id=? AND paquete='windows'", (win,))
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual((r["cerradas"], r["sin_evaluar"]), (0, 1))
        self.assertEqual(_fila(self.conn, win, "CVE-2026-21002", "windows")["estado"], "abierta")

    def test_sin_dato_no_cierra_pero_sale_de_la_cola(self):
        """Desde el 2026-09-10 (esquema v14) un veredicto «sin dato» no deja la
        remediación en la cola: pasa a «esperando datos del inventario». No se cierra
        (nadie ha comprobado que esté corregida) y no cuenta como trabajo pendiente
        (nadie puede hacerla), y su fecha de detección se conserva intacta."""
        remediacion.sincronizar(self.conn, ahora=T1)
        antes = _fila(self.conn, self.web, "CVE-2024-11053", "curl")
        _veredicto(self.conn, self.web, self.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.15",
                   None, "sin_dato", evaluado_at=T2)
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["cerradas"], 0, "no se cierra nada")
        self.assertEqual(r["esperando_datos_nuevas"], 1)
        f = _fila(self.conn, self.web, "CVE-2024-11053", "curl")
        self.assertEqual(f["estado"], "esperando_datos")
        self.assertIsNone(f["corregido_at"])
        self.assertEqual(f["detectado_at"], antes["detectado_at"],
                         "la fecha de detección original no se toca")
        self.assertIn("no pudo decidir si sigue afectado", f["cerrado_motivo"])

    def test_activo_ausente(self):
        remediacion.sincronizar(self.conn, ahora=T1)
        self.conn.execute("UPDATE activos SET presente=0 WHERE id=?", (self.db_,))
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["activo_ausente"], 1)
        self.assertEqual(r["abiertas"], 2)
        f = _fila(self.conn, self.db_, "CVE-2024-11053", "curl")
        self.assertEqual(f["estado"], "activo_ausente")
        self.assertIsNone(f["corregido_at"])
        self.assertEqual(f["comprobado_at"], T2)
        self.assertEqual(f["cerrado_motivo"], remediacion.MOTIVO_AUSENTE)
        # Un activo ausente nuevo no abre remediaciones
        nuevo = _activo(self.conn, "srv-viejo", presente=0)
        _veredicto(self.conn, nuevo, self.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.15", "7.81.0-1ubuntu1.20", "afectado")
        r = remediacion.sincronizar(self.conn, ahora=T2)
        self.assertEqual(r["abiertas_nuevas"], 0)
        # Al reaparecer, la remediación se reabre
        self.conn.execute("UPDATE activos SET presente=1 WHERE id=?", (self.db_,))
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual(r["reabiertas"], 1)
        f = _fila(self.conn, self.db_, "CVE-2024-11053", "curl")
        self.assertEqual(f["estado"], "abierta")
        self.assertIn("Reabierta el 7 de septiembre de 2026", f["cerrado_motivo"])
        self.assertIn("volvió a figurar en OCS Inventory", f["cerrado_motivo"])
        self.assertIn(remediacion.MOTIVO_AUSENTE, f["cerrado_motivo"])
        self.assertEqual(f["detectado_at"], T0, "nada se corrigió: se conserva la fecha de detección original")
        self.assertEqual(f["comprobado_at"], T3)
        self.assertIsNone(f["corregido_at"])

    def test_reabrir_por_regresion(self):
        remediacion.sincronizar(self.conn, ahora=T1)
        _veredicto(self.conn, self.web, self.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.20",
                   "7.81.0-1ubuntu1.20", "no_afectado", evaluado_at=T1)
        remediacion.sincronizar(self.conn, ahora=T1)
        self.assertEqual(_fila(self.conn, self.web, "CVE-2024-11053", "curl")["estado"], "corregida")
        # Alguien reinstaló la versión vieja
        _veredicto(self.conn, self.web, self.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.15",
                   "7.81.0-1ubuntu1.20", "afectado", evaluado_at=T2)
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual(r["reabiertas"], 1)
        self.assertEqual(r["abiertas_nuevas"], 0)
        f = _fila(self.conn, self.web, "CVE-2024-11053", "curl")
        self.assertEqual(f["estado"], "abierta")
        self.assertEqual(f["detectado_at"], T2, "detectado_at nuevo")
        self.assertIsNone(f["corregido_at"])
        self.assertIsNone(f["version_final"])
        self.assertEqual(f["version_vulnerable"], "7.81.0-1ubuntu1.15")
        self.assertTrue(f["cerrado_motivo"].startswith("Reabierta el 7 de septiembre de 2026: la versión volvió a ser vulnerable"))
        self.assertIn("Antes: La sincronización vio la versión 7.81.0-1ubuntu1.20", f["cerrado_motivo"])
        # Y en la siguiente sin cambios, idempotente
        r = remediacion.sincronizar(self.conn, ahora=T3)
        self.assertEqual((r["abiertas_nuevas"], r["cerradas"], r["reabiertas"]), (0, 0, 0))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM remediaciones").fetchone()[0], 3)

    def test_historial_resumen_y_listado(self):
        remediacion.sincronizar(self.conn, ahora=T1)
        _veredicto(self.conn, self.web, self.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.20",
                   "7.81.0-1ubuntu1.20", "no_afectado", evaluado_at=T2)
        remediacion.sincronizar(self.conn, ahora=T2)

        hist = remediacion.historial_activo(self.conn, self.web)
        self.assertEqual([h["estado"] for h in hist], ["abierta", "corregida"], "abiertas primero")
        abierta, corregida = hist
        self.assertEqual(abierta["titulo"], "CVE-2026-0001 english title")
        self.assertEqual((abierta["severity"], abierta["in_kev"], abierta["estado_amenaza"]), ("Critical", True, "descartada"))
        self.assertEqual(abierta["estado_amenaza_es"], "Descartada")
        self.assertEqual(abierta["estado_es"], "Pendiente")
        self.assertEqual(corregida["titulo"], "Fuga de credenciales en curl")
        self.assertEqual(corregida["dias"], 10)
        # Pendiente: días desde la detección hasta hoy (no hasta la última comprobación)
        esperados = round((datetime.now(timezone.utc) - datetime.fromisoformat(T0.replace("Z", "+00:00"))).total_seconds() / 86400)
        self.assertEqual(abierta["dias"], esperados)
        self.assertGreater(abierta["dias"], 0)

        res = remediacion.resumen(self.conn, dias=30, ahora=AHORA)
        self.assertEqual(res["abiertas"], 2)
        self.assertEqual(res["activos_con_abiertas"], 2)
        self.assertEqual(res["corregidas_periodo"], 1)
        self.assertEqual(res["tiempo_medio_dias"], 10.0)
        procesos = {p["proceso"]: p for p in res["por_proceso"]}
        self.assertEqual(procesos["Pila"]["abiertas"], 1)
        self.assertEqual(procesos["Pila"]["abiertas_expuestas"], 1)
        self.assertEqual(procesos["Pila"]["corregidas_periodo"], 1)
        self.assertEqual(procesos["Helpvoz"]["abiertas"], 1)
        self.assertEqual(procesos["Helpvoz"]["abiertas_expuestas"], 0, "desarrollo no es entorno expuesto")
        self.assertEqual(res["dias"], 30)
        self.assertTrue(res["semanas"] and any(s["corregidas"] for s in res["semanas"]))
        # Con periodo corto la corrección de hoy cuenta pero la media sigue siendo 10 días
        res1 = remediacion.resumen(self.conn, dias=1, ahora=AHORA)
        self.assertEqual(res1["corregidas_periodo"], 1)
        self.assertEqual(res1["tiempo_medio_dias"], 10.0)
        self.assertEqual(remediacion.resumen(self.conn, dias=0, ahora=AHORA)["dias"], 30, "sin periodo válido se usa el de 30 días")

        filas = remediacion.listar(self.conn, estado="abierta")
        self.assertEqual({f["activo_nombre"] for f in filas}, {"srv-web-01", "srv-db-01"})
        self.assertEqual(filas[0]["cve"], "CVE-2026-0001", "KEV y crítica primero")
        self.assertEqual(filas[0]["entorno_es"], "Producción")
        self.assertEqual(filas[1]["entorno_es"], "Desarrollo")
        self.assertEqual(len(remediacion.listar(self.conn, estado="corregida")), 1)
        self.assertEqual(len(remediacion.listar(self.conn)), 3)
        self.assertEqual(len(remediacion.listar(self.conn, estado="todas")), 3)
        self.assertEqual([f["activo_nombre"] for f in remediacion.listar(self.conn, proceso="Helpvoz")], ["srv-db-01"])
        self.assertEqual(len(remediacion.listar(self.conn, q="10.0.0.11")), 2)
        self.assertEqual(len(remediacion.listar(self.conn, q="cve-2026")), 1)
        self.assertEqual(len(remediacion.listar(self.conn, q="srv-db")), 1)
        self.assertEqual(len(remediacion.listar(self.conn, q="%' OR 1=1 --")), 0, "LIKE parametrizado")
        # Los comodines de LIKE se buscan como texto literal
        self.assertEqual(len(remediacion.listar(self.conn, q="%")), 0)
        self.assertEqual(len(remediacion.listar(self.conn, q="_")), 0)
        self.assertEqual(len(remediacion.listar(self.conn, q="srv_web")), 0, "«_» no sustituye al guion")
        self.assertEqual(len(remediacion.listar(self.conn, q="\\")), 0)
        self.assertEqual(len(remediacion.listar(self.conn, q="srv-web")), 2)
        self.assertEqual(len(remediacion.listar(self.conn, limite=1)), 1)
        # contar() aplica los mismos filtros sin límite
        self.assertEqual(remediacion.contar(self.conn), 3)
        self.assertEqual(remediacion.contar(self.conn, estado="abierta"), 2)
        self.assertEqual(remediacion.contar(self.conn, estado="corregida", q="10.0.0.11"), 1)
        self.assertEqual(remediacion.contar(self.conn, proceso="Helpvoz"), 1)
        self.assertEqual(remediacion.contar(self.conn, q="%"), 0)
        self.assertEqual(remediacion.procesos(self.conn), ["Helpvoz", "Pila"])
        # Un activo sin proceso se agrupa por su TIPO, no en un «Sin proceso» que
        # mezclaba equipos de computo con servidores (2026-09-07): 249 equipos y 34
        # servidores caían en el mismo grupo y no se sabía de qué se hablaba.
        self.conn.execute("UPDATE activos SET proceso=NULL WHERE id=?", (self.db_,))
        grupos = {p["proceso"] for p in remediacion.resumen(self.conn)["por_proceso"]}
        self.assertIn(remediacion.GRUPO_SERVIDORES_SIN_PROCESO, grupos)
        self.assertNotIn("Sin proceso", grupos)
        self.assertEqual(
            [f["activo_nombre"] for f in remediacion.listar(
                self.conn, proceso=remediacion.GRUPO_SERVIDORES_SIN_PROCESO)],
            ["srv-db-01"])
        # el nombre antiguo sigue filtrando, para no romper enlaces guardados
        self.assertEqual([f["activo_nombre"] for f in remediacion.listar(
            self.conn, proceso="Sin proceso")], ["srv-db-01"])
        # y un equipo de usuario sin proceso cae en el grupo de Mantenimiento
        self.conn.execute("UPDATE activos SET proceso=NULL, origen='equipos' WHERE id=?", (self.db_,))
        grupos = {p["proceso"] for p in remediacion.resumen(self.conn)["por_proceso"]}
        self.assertIn(remediacion.GRUPO_EQUIPOS_SIN_PROCESO, grupos)
        self.assertIn("Mantenimiento", remediacion.GRUPO_EQUIPOS_SIN_PROCESO)
        self.conn.execute("UPDATE activos SET origen='servidores' WHERE id=?", (self.db_,))


class TestPaginaRemediacion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "remediacion_web.db")
        db.init_db(cls.ruta)
        from webui import auth
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", "AdminSeguro#2026", rol="admin", actor="t")
            auth.crear_usuario(conn, "lector", "LectorSeguro#2026", rol="ciberseguridad", actor="t")
            cls.web = _activo(conn, "srv-web-01", ip="10.0.0.11", proceso="Pila")
            cls.db_ = _activo(conn, "srv-db-01", ip="10.0.0.12", entorno="desarrollo", proceso="Helpvoz")
            cls.t_curl = _amenaza(conn, "CVE-2024-11053", severity="High", titulo="Fuga de credenciales en curl")
            cls.t_ssl = _amenaza(conn, "CVE-2026-0001", severity="Critical", in_kev=1)
            _software(conn, cls.web, "curl", "7.81.0-1ubuntu1.15")
            _software(conn, cls.web, "openssl", "3.0.2-0ubuntu1.10")
            _software(conn, cls.db_, "curl", "7.81.0-1ubuntu1.15")
            _veredicto(conn, cls.web, cls.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.15", "7.81.0-1ubuntu1.20", "afectado")
            _veredicto(conn, cls.web, cls.t_ssl, "CVE-2026-0001", "openssl", "3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.18", "afectado")
            _veredicto(conn, cls.db_, cls.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.15", "7.81.0-1ubuntu1.20", "afectado")
            remediacion.sincronizar(conn, ahora=T1)
            _veredicto(conn, cls.web, cls.t_curl, "CVE-2024-11053", "curl", "7.81.0-1ubuntu1.20",
                       "7.81.0-1ubuntu1.20", "no_afectado", evaluado_at=db.utcnow())
            remediacion.sincronizar(conn)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, usuario="admin", clave="AdminSeguro#2026"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": clave})
        return cli

    def _ok(self, cli, url):
        r = cli.get(url)
        html = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 200, url)
        if "text/html" in r.content_type:
            self.assertIsNone(RE_STYLE.search(html), f"style= en {url}")
            self.assertIsNone(RE_ON.search(html), f"on*= en {url}")
        return html

    def test_pagina_pendientes(self):
        """Requisito cambiado el 2026-09-08: la vista de omisión ya no es el listado por
        CVE sino el agrupado por actualización, así que la cabecera dice «Actualizaciones
        pendientes» en lugar de «Remediaciones pendientes». El usuario lo pidió porque el
        listado por CVE repetía la misma actualización de kernel una vez por aviso: «si hay
        una vulnerabilidad de kernel que se repite que se cuente como una». El resto de la
        cobertura de esta prueba (activos, CVE, filtros, recorrido guiado, CSP) sigue igual;
        se añade que el tablero diga las DOS magnitudes sin confundirlas y que exista el
        selector de vista."""
        cli = self._cliente("lector", "LectorSeguro#2026")
        html = self._ok(cli, "/remediaciones/")
        # «Vulnerabilidades pendientes» desde el 2026-09-09: la cifra principal es una por
        # activo y CVE (antes decia «Vulnerabilidades que cubren» sobre filas de remediacion).
        for texto in ("Seguimiento de remediación", "Actualizaciones pendientes",
                      "Vulnerabilidades pendientes", "Corregidas en 30 días",
                      "Días de media hasta corregir",
                      "Activos con pendientes", "Por proceso de negocio",
                      "srv-web-01", "srv-db-01", "CVE-2026-0001", "Exportar CSV", 'data-filtro-vivo="tabla-remediaciones"',
                      'id="tabla-remediaciones"', "Producción", "Desarrollo", "Pila", "Helpvoz",
                      'class="insignia critical">Pendiente<', 'class="insignia kev"'):
            self.assertIn(texto, html)
        # Las dos magnitudes con su nombre, nunca «equipos» a secas para las máquinas
        self.assertIn("servidor", html)
        self.assertIn("equipo", html)
        self.assertNotIn("equipos con al menos", html)
        # Selector de vista, con etiqueta visible y las dos opciones
        self.assertIn('<label for="vista">', html)
        self.assertIn("Por actualización", html)
        self.assertIn("Por vulnerabilidad", html)
        zona = html.split('id="tabla-remediaciones"')[1]
        self.assertNotIn('class="insignia ok">Corregida<', zona, "por defecto solo pendientes")
        self.assertIn(f"/activos/{self.web}", html)
        self.assertIn(f"/amenazas/{self.t_ssl}", html)
        # Recorrido guiado: al menos tres pasos con textos largos y en la etiqueta de apertura
        pasos = re.findall(r'data-tour="(\d+)"[^>]*data-tour-titulo="([^"]+)"[^>]*data-tour-texto="([^"]+)"', html)
        self.assertGreaterEqual(len(pasos), 3)
        for _, titulo, texto in pasos:
            self.assertGreater(len(texto), 40, titulo)
        self.assertNotRegex(html, r'<div class="panel-(cabecera|cuerpo)[^"]*" data-tour=')
        # Etiquetas visibles en los filtros
        for etiqueta in ('<label for="q">', '<label for="estado">', '<label for="proceso">'):
            self.assertIn(etiqueta, html)

    def test_la_vista_por_vulnerabilidad_sigue_disponible(self):
        """La vista por CVE no se quita: para investigar un CVE concreto sigue haciendo
        falta (2026-09-08). Con «vista=vulnerabilidad» vuelve el listado de siempre."""
        cli = self._cliente("lector", "LectorSeguro#2026")
        html = self._ok(cli, "/remediaciones/?vista=vulnerabilidad")
        self.assertIn("Vulnerabilidades pendientes", html)
        zona = html.split('id="tabla-remediaciones"')[1]
        self.assertIn("CVE-2026-0001", zona)
        self.assertIn("openssl", zona)
        # una vista desconocida no rompe: vuelve a la agrupada
        html = self._ok(cli, "/remediaciones/?vista=<script>")
        self.assertIn("Actualizaciones pendientes", html)

    def test_filtros(self):
        cli = self._cliente()
        html = self._ok(cli, "/remediaciones/?estado=corregida")
        zona = html.split('id="tabla-remediaciones"')[1]
        self.assertIn('class="insignia ok">Corregida<', zona)
        self.assertIn("que ya incluye la corrección", zona)
        self.assertIn("7.81.0-1ubuntu1.20", zona)
        self.assertNotIn("CVE-2026-0001", zona)
        self.assertIn("Actualizaciones ya corregidas", html)   # cabecera agrupada (2026-09-08)
        html = self._ok(cli, "/remediaciones/?estado=todas&proceso=Helpvoz")
        zona = html.split('id="tabla-remediaciones"')[1]
        self.assertIn("srv-db-01", zona)
        self.assertNotIn("srv-web-01", zona)
        self.assertIn("Quitar filtros", html)
        html = self._ok(cli, "/remediaciones/?q=CVE-2026-0001")
        zona = html.split('id="tabla-remediaciones"')[1]
        self.assertIn("srv-web-01", zona)
        self.assertNotIn("srv-db-01", zona)
        html = self._ok(cli, "/remediaciones/?q=nada-que-coincida&estado=activo_ausente")
        self.assertIn("Ninguna remediación coincide con los filtros.", html)
        # Estado desconocido no rompe: vuelve a pendientes
        html = self._ok(cli, "/remediaciones/?estado=<script>")
        self.assertIn("Actualizaciones pendientes", html)
        self.assertNotIn("<script>", html.split("</nav>")[-1] if "</nav>" in html else html)
        # Un comodín de LIKE no devuelve la lista completa
        html = self._ok(cli, "/remediaciones/?estado=todas&q=%25")
        self.assertIn("Ninguna remediación coincide con los filtros.", html)

    def test_aviso_de_recorte(self):
        """Cuando hay más filas que el límite de pantalla, la página lo dice y remite al CSV.

        Requisito cambiado el 2026-09-08: la vista de omisión agrupa por actualización, así
        que la cabecera ya no dice «3 filas.» a secas (una cifra que no decía de qué) sino
        las dos magnitudes: cuántas actualizaciones y de cuántas filas de remediación
        salen. Las filas de la página se cuentan por su identificador de remediación, que
        es uno por actualización, y no por la insignia de estado: la trazabilidad
        desplegable también lleva insignias y contarlas mezclaba dos cosas."""
        from unittest import mock
        from webui.vistas import remediaciones as vista
        cli = self._cliente()
        html = self._ok(cli, "/remediaciones/?estado=todas")
        self.assertNotIn("Se muestran las", html)
        self.assertIn("3 actualizaciones", html)
        self.assertIn("3 filas de remediación", html)
        with mock.patch.object(vista, "LIMITE_PAGINA", 2):
            html = self._ok(cli, "/remediaciones/?estado=todas")
        zona = html.split('id="tabla-remediaciones"')[1]
        self.assertIn("se muestran las 2 primeras", zona)
        self.assertIn("Se muestran las 2 primeras de 3 actualizaciones", zona)
        self.assertIn("exporte el CSV, que lleva hasta 20.000 filas", zona)
        self.assertIn('class="aviso info"', zona)
        self.assertEqual(zona.count('id="rem-'), 2, "dos actualizaciones en la página")
        # La vista por vulnerabilidad conserva el aviso hablando de remediaciones
        with mock.patch.object(vista, "LIMITE_PAGINA", 2):
            porcve = self._ok(cli, "/remediaciones/?estado=todas&vista=vulnerabilidad")
        self.assertIn("Se muestran las 2 primeras de 3 remediaciones",
                      porcve.split('id="tabla-remediaciones"')[1])
        # El CSV no se recorta con el límite de pantalla
        with mock.patch.object(vista, "LIMITE_PAGINA", 2):
            r = cli.get("/remediaciones/exportar.csv?estado=todas")
        self.assertEqual(len(r.get_data(as_text=True).strip().splitlines()), 4)

    def test_csv(self):
        cli = self._cliente()
        r = cli.get("/remediaciones/exportar.csv?estado=todas")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/csv", r.content_type)
        self.assertIn("attachment", r.headers["Content-Disposition"])
        texto = r.get_data(as_text=True)
        self.assertTrue(texto.startswith("﻿"), "BOM para Excel")
        lineas = texto.strip().splitlines()
        self.assertEqual(lineas[0].lstrip("﻿").split(";")[:6], ["estado", "activo", "ip", "entorno", "proceso", "cve"])
        self.assertEqual(len(lineas), 4)
        self.assertTrue(any(l.startswith("Corregida;srv-web-01;10.0.0.11;Producción;Pila;CVE-2024-11053") for l in lineas))
        self.assertIn("que ya incluye la corrección", texto)
        # Conserva los filtros
        r = cli.get("/remediaciones/exportar.csv?estado=abierta&proceso=Helpvoz")
        self.assertEqual(len(r.get_data(as_text=True).strip().splitlines()), 2)
        # Sin sesión no hay CSV
        r = self.app.test_client().get("/remediaciones/exportar.csv")
        self.assertIn(r.status_code, (302, 401, 403))

    def test_parciales_en_activos(self):
        cli = self._cliente()
        html = self._ok(cli, f"/activos/{self.web}")
        self.assertIn('id="remediaciones-activo"', html)
        # El panel lleva su paso del recorrido guiado. No se fija el NÚMERO: los pasos se
        # renumeran cuando la ficha gana o pierde paneles, y atar la prueba a un número
        # concreto solo obliga a tocarla sin que nada esté mal (2026-09-15).
        import re as _re
        panel = html[html.index('id="remediaciones-activo"'):]
        self.assertRegex(panel[:2000], r'data-tour="\d+"[^>]*data-tour-titulo="[^"]+"',
                         "el panel de remediación del activo debe tener su paso del recorrido")
        self.assertIn("1 pendiente<", html)
        self.assertIn("1 corregida<", html)
        self.assertIn("se cierran solas", html)
        self.assertIn("Ver en la página de remediación", html)
        html = self._ok(cli, "/activos/")
        self.assertIn('id="remediacion-resumen"', html)
        self.assertIn('data-tour="9"', html)
        self.assertIn("Ver remediación", html)
        self.assertIn("Corregidas en 30 días", html)


if __name__ == "__main__":
    unittest.main()
