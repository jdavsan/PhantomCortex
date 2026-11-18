"""Seguimiento diario de las correcciones que todavía no existen (v7, 2026-09-06).

El usuario pidió que, cuando la evaluación confirma una vulnerabilidad en un equipo y no se
conoce la versión que la corrige, se diga por qué (el aviso no la publica, el fabricante no ha
sacado el parche, la distribución no lo ha empaquetado), que se busque cada día y que, cuando
aparezca, el correo lo anuncie en una sección propia.

Sin red: OSV.dev se simula con un ``fetch`` falso o con un cliente doble. Base temporal bajo
``data/`` e interfaz con ``crear_app(db_path=..., testing=True)``.
"""
from __future__ import annotations

import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any, Optional

from threatintel import db, notify, parches
from threatintel.paths import BASE_DIR

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)
RE_SCRIPT = re.compile(r"<script(?![^>]*\ssrc=)", re.I)


def _asegurar_columna_motivo(conn: sqlite3.Connection) -> bool:
    """La v7 añade ``aplicabilidad.sin_parche_motivo``, pero en una base recién creada
    ``db.init_db`` no la pone: ``migrar_columnas`` se ejecuta antes de crear el esquema y se
    salta las tablas que todavía no existen, y la sentencia CREATE TABLE no la incluye. Hasta
    que el coordinador lo corrija en ``threatintel/db.py`` (fichero compartido), la prueba la
    añade a mano. Devuelve True si hubo que añadirla."""
    if any(r[1] == "sin_parche_motivo" for r in conn.execute("PRAGMA table_info(aplicabilidad)")):
        return False
    conn.execute("ALTER TABLE aplicabilidad ADD COLUMN sin_parche_motivo TEXT")
    return True


class Cfg(dict):
    """Ajustes mínimos (la aplicación real usa ``cfg.get``)."""

    def get(self, clave, defecto=None):
        return super().get(clave, defecto)


class ClienteOSVFalso:
    """Doble de ``aplicabilidad.ClienteOSV``: devuelve registros de un diccionario y cuenta
    las consultas, sin tocar la red ni la caché."""

    def __init__(self, registros: dict[str, Any], *, max_peticiones: int = 100):
        self.registros = registros
        self.max = max_peticiones
        self.peticiones = 0
        self.consultados: list[str] = []

    @property
    def agotado(self) -> bool:
        return self.peticiones >= self.max

    def registro(self, id_osv: str):
        self.consultados.append(id_osv)
        self.peticiones += 1
        return self.registros.get(id_osv)


def registro_osv(cve: str, *, ecosistema: str, paquete: str, corregida: Optional[str] = None,
                 urgencia: Optional[str] = None, otros: Optional[list[tuple[str, str]]] = None,
                 binarios: Optional[dict[str, Optional[str]]] = None) -> dict:
    """Registro de OSV.dev con la forma justa que lee ``threatintel.aplicabilidad``."""
    def entrada(eco, paq, fijada, urg, bins):
        eventos = [{"introduced": "0"}] + ([{"fixed": fijada}] if fijada else [])
        especifico: dict[str, Any] = {}
        if urg:
            especifico["urgency"] = urg
        if bins:
            especifico["binaries"] = [{"binary_name": n, "binary_version": v} for n, v in bins.items()]
        return {"package": {"name": paq, "ecosystem": eco}, "ranges": [{"type": "ECOSYSTEM", "events": eventos}],
                "ecosystem_specific": especifico}

    afectadas = [entrada(ecosistema, paquete, corregida, urgencia, binarios)]
    for eco_otro, version_otra in (otros or []):
        afectadas.append(entrada(eco_otro, paquete, version_otra, urgencia, None))
    return {"id": f"DEBIAN-{cve}", "details": "prueba", "affected": afectadas,
            "references": [{"url": "https://security-tracker.debian.org/tracker/" + cve}]}


class BasePrueba(unittest.TestCase):
    """Base temporal con dos servidores en producción, uno en desarrollo y varias amenazas."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "parches.db")
        db.init_db(self.ruta)
        self.conn = db.connect(self.ruta)
        _asegurar_columna_motivo(self.conn)
        self.ahora = db.utcnow()
        self._sembrar()

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    # ------------------------------------------------------------------ datos
    def _activo(self, nombre: str, *, ecosistema: Optional[str], familia: str, entorno: str,
                presente: int = 1) -> int:
        cur = self.conn.execute(
            """INSERT INTO activos(origen, ocs_id, nombre, so_familia, ecosistema, entorno, zona,
                   presente, primera_vez_at, visto_at)
               VALUES('servidores', (SELECT COALESCE(MAX(ocs_id),0)+1 FROM activos), ?, ?, ?, ?,
                      'interna', ?, ?, ?)""",
            (nombre, familia, ecosistema, entorno, presente, self.ahora, self.ahora))
        return int(cur.lastrowid)

    def _amenaza(self, cve: str, *, titulo_es: str, resumen: str = "", severidad: str = "High") -> int:
        cur = self.conn.execute(
            """INSERT INTO threats(fingerprint, cve, title_en, title_es, summary_en, severity,
                   severity_source, first_seen_at, last_seen_at, month, relevance, estado)
               VALUES(?,?,?,?,?,?,'nvd',?,?,?,60.0,'nueva')""",
            (f"fp-{cve}", cve, titulo_es, titulo_es, resumen, severidad, self.ahora, self.ahora,
             self.ahora[:7]))
        return int(cur.lastrowid)

    def _veredicto(self, activo_id: int, threat_id: Optional[int], cve: str, paquete: str, *,
                   instalada: str = "1.0", corregida: Optional[str] = None,
                   veredicto: str = "afectado", motor: str = "osv", evidencia: str = "",
                   evaluado_at: Optional[str] = None) -> None:
        self.conn.execute(
            """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada,
                   version_corregida, veredicto, motor, evidencia, evaluado_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (activo_id, threat_id, cve, paquete, instalada, corregida, veredicto, motor,
             evidencia or f"{paquete} {instalada}: todavía no hay corrección publicada para el "
                          f"paquete {paquete}", evaluado_at or self.ahora))

    def _sembrar(self):
        self.srv1 = self._activo("srv-app-01", ecosistema="Debian:13", familia="debian", entorno="produccion")
        self.srv2 = self._activo("srv-app-02", ecosistema="Debian:13", familia="debian", entorno="contingencia")
        self.srv3 = self._activo("srv-lab-01", ecosistema="Debian:13", familia="debian", entorno="desarrollo")
        self.ubu = self._activo("srv-ubu-01", ecosistema="Ubuntu:22.04", familia="ubuntu", entorno="produccion")
        # 1) el registro lista el paquete sin versión corregida
        self.t_sin_version = self._amenaza("CVE-2026-1001", titulo_es="Fallo en clamav")
        for activo in (self.srv1, self.srv2, self.srv3):
            self._veredicto(activo, self.t_sin_version, "CVE-2026-1001", "clamav")
        # 2) el aviso dice que no hay parche
        self.t_sin_parche = self._amenaza(
            "CVE-2026-1002", titulo_es="Fallo en el servidor de correo",
            resumen="The vendor has confirmed the issue; no patch is currently available.")
        self._veredicto(self.srv1, self.t_sin_parche, "CVE-2026-1002", "postfix")
        # 3) corregido en otra versión de la distribución
        self.t_distro = self._amenaza("CVE-2026-1003", titulo_es="Fallo en systemd")
        self._veredicto(self.srv1, self.t_distro, "CVE-2026-1003", "systemd")
        # 4) comparación de versión: el aviso solo enumera versiones afectadas
        self.t_version = self._amenaza(
            "CVE-2026-1004", titulo_es="Fallo en gitlab-runner",
            resumen="Affected versions prior to 19.2.2, prior to 19.1.4 and prior to 19.0.6.")
        self._veredicto(self.ubu, self.t_version, "CVE-2026-1004", "gitlab-runner", motor="version",
                        evidencia="gitlab-runner 18.9.0: anuncio: < 19.2.2, < 19.1.4 | instalado: 18.9.0")
        self.conn.commit()

    def _registros(self) -> dict[str, Any]:
        return {
            "DEBIAN-CVE-2026-1001": registro_osv("CVE-2026-1001", ecosistema="Debian:13",
                                                 paquete="clamav", urgencia="not yet assigned"),
            "DEBIAN-CVE-2026-1002": registro_osv("CVE-2026-1002", ecosistema="Debian:13",
                                                 paquete="postfix"),
            "DEBIAN-CVE-2026-1003": registro_osv("CVE-2026-1003", ecosistema="Debian:13",
                                                 paquete="systemd",
                                                 otros=[("Debian:14", "261.2-1")]),
        }

    def _cachear(self, registros: Optional[dict] = None):
        """Deja los registros en ``osv_cache``, que es de donde ``sincronizar`` deduce el motivo."""
        import json
        for id_osv, registro in (registros or self._registros()).items():
            self.conn.execute(
                "INSERT OR REPLACE INTO osv_cache(id, encontrado, json, consultado_at) VALUES(?,1,?,?)",
                (id_osv, json.dumps(registro), self.ahora))
        self.conn.commit()


class TestSincronizar(BasePrueba):
    def test_abre_actualiza_y_cierra_el_seguimiento(self):
        r = parches.sincronizar(self.conn)
        self.assertEqual(r["nuevas"], 4)
        self.assertEqual(r["en_seguimiento"], 4)
        fila = self.conn.execute(
            "SELECT * FROM parches_pendientes WHERE cve='CVE-2026-1001'").fetchone()
        self.assertEqual(fila["paquete"], "clamav")
        self.assertEqual(fila["ecosistema"], "Debian:13")
        self.assertEqual(fila["n_activos"], 3)
        self.assertEqual(fila["n_activos_expuestos"], 2)   # producción y contingencia
        self.assertIsNone(fila["encontrado_at"])

        # un activo más y otro entorno: los recuentos se actualizan sin duplicar filas
        srv4 = self._activo("srv-app-03", ecosistema="Debian:13", familia="debian", entorno="produccion")
        self._veredicto(srv4, self.t_sin_version, "CVE-2026-1001", "clamav")
        r2 = parches.sincronizar(self.conn)
        self.assertEqual(r2["nuevas"], 0)
        self.assertEqual(r2["actualizadas"], 4)
        fila = self.conn.execute(
            "SELECT * FROM parches_pendientes WHERE cve='CVE-2026-1001'").fetchone()
        self.assertEqual(fila["n_activos"], 4)
        self.assertEqual(fila["n_activos_expuestos"], 3)

        # la evaluación diaria ya conoce la versión: la fila se cierra anunciando la corrección
        self.conn.execute("UPDATE aplicabilidad SET version_corregida='1.4.6+dfsg-1', aviso='DSA-9999-1' "
                          "WHERE cve='CVE-2026-1001'")
        r3 = parches.sincronizar(self.conn)
        self.assertEqual(r3["encontradas"], 1)
        self.assertEqual(r3["borradas"], 0)
        self.assertEqual(r3["en_seguimiento"], 3)
        fila = self.conn.execute(
            "SELECT * FROM parches_pendientes WHERE cve='CVE-2026-1001'").fetchone()
        self.assertEqual(fila["version_corregida"], "1.4.6+dfsg-1")
        self.assertEqual(fila["aviso"], "DSA-9999-1")
        self.assertIsNotNone(fila["encontrado_at"])

        # el paquete desaparece del inventario: no hay nada que anunciar, la fila se borra
        self.conn.execute("DELETE FROM aplicabilidad WHERE cve='CVE-2026-1002'")
        r4 = parches.sincronizar(self.conn)
        self.assertEqual(r4["borradas"], 1)
        self.assertIsNone(self.conn.execute(
            "SELECT 1 FROM parches_pendientes WHERE cve='CVE-2026-1002'").fetchone())

    def test_los_cuatro_motivos_y_el_texto_en_espanol(self):
        self._cachear()
        parches.sincronizar(self.conn)
        motivos = {f["cve"]: f["motivo"] for f in self.conn.execute(
            "SELECT cve, motivo FROM parches_pendientes")}
        self.assertEqual(motivos["CVE-2026-1001"], "aviso_sin_version")
        self.assertEqual(motivos["CVE-2026-1002"], "sin_parche_publicado")
        self.assertEqual(motivos["CVE-2026-1003"], "distro_sin_empaquetar")
        self.assertEqual(motivos["CVE-2026-1004"], "aviso_sin_version")
        detalles = {f["cve"]: f["motivo_detalle"] for f in self.conn.execute(
            "SELECT cve, motivo_detalle FROM parches_pendientes")}
        self.assertIn("Debian 14", detalles["CVE-2026-1003"])
        self.assertIn("261.2-1", detalles["CVE-2026-1003"])
        self.assertIn("no patch is currently available", detalles["CVE-2026-1002"])
        for detalle in detalles.values():
            self.assertNotIn("None", detalle)
        # los cuatro motivos tienen texto en español, con tildes y sin abreviaturas
        for clave, texto in parches.MOTIVO_ES.items():
            self.assertGreater(len(texto), 20, clave)
            self.assertEqual(texto, texto.strip())

    def test_motivo_desconocido_cuando_no_hay_nada_que_leer(self):
        self.conn.execute("DELETE FROM aplicabilidad")
        activo = self._activo("srv-otro", ecosistema=None, familia="otro", entorno="produccion")
        self._veredicto(activo, None, "CVE-2026-2000", "programa-raro", motor="manual",
                        evidencia="afectado según consulta manual")
        parches.sincronizar(self.conn)
        fila = self.conn.execute("SELECT * FROM parches_pendientes").fetchone()
        self.assertEqual(fila["motivo"], "desconocido")
        self.assertEqual(fila["ecosistema"], "otro")
        self.assertIn("cada día", fila["motivo_detalle"])

    def test_escribe_el_motivo_en_aplicabilidad(self):
        self._cachear()
        parches.sincronizar(self.conn)
        filas = {(f["cve"], f["sin_parche_motivo"]) for f in self.conn.execute(
            "SELECT cve, sin_parche_motivo FROM aplicabilidad")}
        self.assertIn(("CVE-2026-1001", "aviso_sin_version"), filas)
        self.assertIn(("CVE-2026-1003", "distro_sin_empaquetar"), filas)
        # cuando aparece la versión, el motivo se borra
        self.conn.execute("UPDATE aplicabilidad SET version_corregida='1.4.6' WHERE cve='CVE-2026-1001'")
        parches.sincronizar(self.conn)
        self.assertEqual(0, self.conn.execute(
            "SELECT COUNT(*) FROM aplicabilidad WHERE cve='CVE-2026-1001' AND sin_parche_motivo IS NOT NULL"
        ).fetchone()[0])

    def test_no_sigue_activos_retirados_ni_veredictos_no_afectados(self):
        self.conn.execute("DELETE FROM aplicabilidad")
        retirado = self._activo("srv-viejo", ecosistema="Debian:13", familia="debian",
                                entorno="produccion", presente=0)
        self._veredicto(retirado, self.t_sin_version, "CVE-2026-1001", "clamav")
        self._veredicto(self.srv1, self.t_sin_version, "CVE-2026-3000", "curl", veredicto="no_afectado")
        r = parches.sincronizar(self.conn)
        self.assertEqual(r["en_seguimiento"], 0)

    def test_idempotente(self):
        self._cachear()
        parches.sincronizar(self.conn)
        antes = [tuple(f) for f in self.conn.execute(
            "SELECT cve, paquete, ecosistema, motivo, n_activos, detectado_at FROM parches_pendientes ORDER BY cve")]
        parches.sincronizar(self.conn)
        parches.sincronizar(self.conn)
        despues = [tuple(f) for f in self.conn.execute(
            "SELECT cve, paquete, ecosistema, motivo, n_activos, detectado_at FROM parches_pendientes ORDER BY cve")]
        self.assertEqual(antes, despues)
        self.assertEqual(4, self.conn.execute("SELECT COUNT(*) FROM parches_pendientes").fetchone()[0])


class TestEsquemaIncompleto(unittest.TestCase):
    """Una base sin la columna ``sin_parche_motivo`` no puede tumbar la ejecución diaria."""

    def test_sin_la_columna_el_seguimiento_sigue_funcionando(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as carpeta:
            ruta = str(Path(carpeta) / "sin_columna.db")
            db.init_db(ruta)
            conn = db.connect(ruta)
            try:
                # Desde el 2026-09-06 el esquema crea siempre la columna; se retira a mano
                # para comprobar que el seguimiento aguanta una base antigua sin migrar.
                _asegurar_columna_motivo(conn)
                conn.execute("ALTER TABLE aplicabilidad DROP COLUMN sin_parche_motivo")
                ahora = db.utcnow()
                conn.execute("""INSERT INTO activos(origen, ocs_id, nombre, so_familia, ecosistema,
                                    entorno, zona, presente, primera_vez_at, visto_at)
                                VALUES('servidores', 1, 'srv', 'debian', 'Debian:13', 'produccion',
                                       'interna', 1, ?, ?)""", (ahora, ahora))
                conn.execute("""INSERT INTO aplicabilidad(activo_id, cve, paquete, version_instalada,
                                    veredicto, motor, evidencia, evaluado_at)
                                VALUES(1, 'CVE-2026-9000', 'clamav', '1.0', 'afectado', 'osv', 'x', ?)""",
                             (ahora,))
                r = parches.sincronizar(conn)
                self.assertEqual(r["en_seguimiento"], 1)
                self.assertTrue(r["sin_columna_motivo"])
                self.assertEqual(parches.buscar(conn, osv=ClienteOSVFalso({}), limite=5)["consultadas"], 1)
            finally:
                conn.close()


class TestBuscar(BasePrueba):
    def _registros_con_correccion(self) -> dict[str, Any]:
        registros = self._registros()
        registros["DEBIAN-CVE-2026-1001"] = registro_osv(
            "CVE-2026-1001", ecosistema="Debian:13", paquete="clamav", corregida="1.4.6+dfsg-1")
        return registros

    def test_encuentra_la_version_y_la_escribe_en_las_dos_tablas(self):
        self._cachear()
        parches.sincronizar(self.conn)
        cliente = ClienteOSVFalso(self._registros_con_correccion())
        r = parches.buscar(self.conn, osv=cliente, limite=10)
        self.assertFalse(r["omitido"])
        self.assertEqual(r["encontradas"], 1)
        self.assertGreaterEqual(r["consultadas"], 4)
        fila = self.conn.execute("SELECT * FROM parches_pendientes WHERE cve='CVE-2026-1001'").fetchone()
        self.assertEqual(fila["version_corregida"], "1.4.6+dfsg-1")
        self.assertIsNotNone(fila["encontrado_at"])
        self.assertIsNotNone(fila["buscado_at"])
        self.assertEqual(fila["intentos"], 1)
        self.assertIn("Corrección encontrada", fila["motivo_detalle"])
        # las filas de aplicabilidad quedan con la versión y sin motivo
        for f in self.conn.execute("SELECT version_corregida, sin_parche_motivo FROM aplicabilidad "
                                   "WHERE cve='CVE-2026-1001'"):
            self.assertEqual(f["version_corregida"], "1.4.6+dfsg-1")
            self.assertIsNone(f["sin_parche_motivo"])
        # las que siguen sin corrección solo suman un intento
        otra = self.conn.execute("SELECT * FROM parches_pendientes WHERE cve='CVE-2026-1003'").fetchone()
        self.assertIsNone(otra["version_corregida"])
        self.assertEqual(otra["intentos"], 1)

    def test_no_repite_la_consulta_el_mismo_dia(self):
        self._cachear()
        parches.sincronizar(self.conn)
        cliente = ClienteOSVFalso(self._registros())
        primera = parches.buscar(self.conn, osv=cliente, limite=10)
        self.assertEqual(primera["consultadas"], 4)
        cliente2 = ClienteOSVFalso(self._registros())
        segunda = parches.buscar(self.conn, osv=cliente2, limite=10)
        self.assertEqual(segunda["consultadas"], 0)
        self.assertEqual(cliente2.peticiones, 0)
        self.assertIn("no hay filas pendientes", segunda.get("motivo", ""))
        # al día siguiente vuelve a tocarles
        self.conn.execute("UPDATE parches_pendientes SET buscado_at='2020-01-01T00:00:00Z'")
        cliente3 = ClienteOSVFalso(self._registros())
        tercera = parches.buscar(self.conn, osv=cliente3, limite=10)
        self.assertEqual(tercera["consultadas"], 4)
        self.assertEqual(2, self.conn.execute(
            "SELECT MIN(intentos) FROM parches_pendientes").fetchone()[0])

    def test_respeta_el_limite_y_el_orden_por_activos_expuestos(self):
        self._cachear()
        parches.sincronizar(self.conn)
        cliente = ClienteOSVFalso(self._registros())
        r = parches.buscar(self.conn, osv=cliente, limite=1)
        self.assertEqual(r["consultadas"], 1)
        buscada = self.conn.execute(
            "SELECT cve FROM parches_pendientes WHERE buscado_at IS NOT NULL").fetchall()
        self.assertEqual([f["cve"] for f in buscada], ["CVE-2026-1001"])   # 2 activos expuestos

    def test_respeta_los_ajustes(self):
        parches.sincronizar(self.conn)
        cliente = ClienteOSVFalso(self._registros())
        apagado = parches.buscar(self.conn, cfg=Cfg(parches_buscar_diario=False), osv=cliente)
        self.assertTrue(apagado["omitido"])
        self.assertIn("desactivado", apagado["motivo"])
        self.assertEqual(cliente.peticiones, 0)
        cero = parches.buscar(self.conn, cfg=Cfg(parches_buscar_diario=True, parches_max_consultas=0),
                              osv=cliente)
        self.assertTrue(cero["omitido"])
        self.assertIn("cero", cero["motivo"])
        dos = parches.buscar(self.conn, cfg=Cfg(parches_buscar_diario=True, parches_max_consultas=2),
                             osv=cliente)
        self.assertEqual(dos["consultadas"], 2)

    def test_deduce_la_version_del_aviso_cuando_hay_una_sola_cota(self):
        """El paquete no lo cubre el registro de la distribución y el aviso dice «anterior a X»."""
        self.conn.execute("DELETE FROM aplicabilidad")
        threat = self._amenaza("CVE-2026-1005", titulo_es="Fallo en Google Chrome",
                               resumen="Google Chrome prior to 152.0.7632.45 allows remote code execution.")
        self._veredicto(self.ubu, threat, "CVE-2026-1005", "google chrome", motor="version",
                        evidencia="google chrome 151.0: la versión instalada está en el rango afectado")
        parches.sincronizar(self.conn)
        cliente = ClienteOSVFalso({})
        r = parches.buscar(self.conn, osv=cliente, limite=5)
        self.assertEqual(r["encontradas"], 1)
        fila = self.conn.execute("SELECT * FROM parches_pendientes").fetchone()
        self.assertEqual(fila["version_corregida"], "152.0.7632.45")
        self.assertIn("restricciones de versión", fila["motivo_detalle"])

    def test_varias_ramas_en_el_aviso_no_se_dan_por_buenas(self):
        """«< 19.2.2, < 19.1.4, < 19.0.6»: no se puede saber cuál corresponde a cada equipo."""
        self._cachear()
        parches.sincronizar(self.conn)
        parches.buscar(self.conn, osv=ClienteOSVFalso(self._registros()), limite=10)
        fila = self.conn.execute("SELECT * FROM parches_pendientes WHERE cve='CVE-2026-1004'").fetchone()
        self.assertIsNone(fila["version_corregida"])
        self.assertEqual(fila["intentos"], 1)

    def test_un_fallo_de_la_fuente_no_tumba_la_ejecucion(self):
        class ClienteRoto(ClienteOSVFalso):
            def registro(self, id_osv):
                if id_osv.endswith("CVE-2026-1001"):
                    raise RuntimeError("OSV.dev no respondió")
                return super().registro(id_osv)

        self._cachear()
        parches.sincronizar(self.conn)
        r = parches.buscar(self.conn, osv=ClienteRoto(self._registros()), limite=10)
        self.assertEqual(len(r["errores"]), 1)
        self.assertIn("CVE-2026-1001", r["errores"][0])
        self.assertGreaterEqual(r["consultadas"], 3)
        fallida = self.conn.execute(
            "SELECT * FROM parches_pendientes WHERE cve='CVE-2026-1001'").fetchone()
        self.assertEqual(fallida["intentos"], 1)          # el intento se anota igualmente
        self.assertIsNotNone(fallida["buscado_at"])


class TestNovedadesYResumen(BasePrueba):
    def _con_correccion(self):
        self._cachear()
        parches.sincronizar(self.conn)
        registros = self._registros()
        registros["DEBIAN-CVE-2026-1001"] = registro_osv(
            "CVE-2026-1001", ecosistema="Debian:13", paquete="clamav", corregida="1.4.6+dfsg-1")
        parches.buscar(self.conn, osv=ClienteOSVFalso(registros), limite=10)

    def test_novedades_con_y_sin_marcar(self):
        self._con_correccion()
        filas = parches.novedades(self.conn)
        self.assertEqual(len(filas), 1)
        fila = filas[0]
        for clave in ("cve", "titulo", "severidad", "paquete", "ecosistema", "sistema",
                      "version_corregida", "aviso", "dias_en_espera", "n_activos",
                      "n_activos_expuestos"):
            self.assertIn(clave, fila)
        self.assertEqual(fila["titulo"], "Fallo en clamav")
        self.assertEqual(fila["sistema"], "Debian 13")
        self.assertEqual(fila["version_corregida"], "1.4.6+dfsg-1")
        self.assertEqual(fila["n_activos"], 3)
        self.assertEqual(fila["n_activos_expuestos"], 2)
        self.assertGreaterEqual(fila["dias_en_espera"], 0)
        # sin marcar, siguen apareciendo; al marcar, ya no
        self.assertEqual(len(parches.novedades(self.conn)), 1)
        self.assertEqual(len(parches.novedades(self.conn, marcar=True)), 1)
        self.assertEqual(parches.novedades(self.conn), [])
        self.assertIsNotNone(self.conn.execute(
            "SELECT avisado_at FROM parches_pendientes WHERE cve='CVE-2026-1001'").fetchone()[0])

    def test_resumen_y_listados(self):
        self._con_correccion()
        res = parches.resumen(self.conn)
        self.assertEqual(res["en_seguimiento"], 3)
        self.assertEqual(res["encontradas_hoy"], 1)
        self.assertEqual(res["encontradas_semana"], 1)
        self.assertEqual(set(res["por_motivo"]), set(parches.MOTIVO_ES))
        self.assertEqual(res["activos_afectados"], 2)      # srv-app-01 y srv-ubu-01
        self.assertIsNotNone(res["mas_antigua_dias"])
        seguimiento = parches.listar(self.conn, estado="seguimiento")
        self.assertEqual(len(seguimiento), 3)
        self.assertTrue(all(f["version_corregida"] is None for f in seguimiento))
        self.assertTrue(all(f["motivo_es"] in parches.MOTIVO_ES.values() for f in seguimiento))
        encontradas = parches.listar(self.conn, estado="encontradas")
        self.assertEqual([f["cve"] for f in encontradas], ["CVE-2026-1001"])
        self.assertEqual(parches.listar(self.conn, estado="inventado"),
                         parches.listar(self.conn, estado="seguimiento"))
        self.assertEqual([f["cve"] for f in parches.listar(self.conn, q="systemd")], ["CVE-2026-1003"])
        self.assertEqual(parches.listar(self.conn, q="no-existe-nada"), [])
        self.assertEqual(parches.contar(self.conn, estado="seguimiento"), 3)

    def test_ecosistema_en_espanol(self):
        self.assertEqual(parches.ecosistema_es("Debian:13"), "Debian 13")
        self.assertEqual(parches.ecosistema_es("Ubuntu:22.04"), "Ubuntu 22.04")
        self.assertEqual(parches.ecosistema_es("freebsd"), "FreeBSD")
        self.assertEqual(parches.ecosistema_es(""), "Sin sistema declarado")


class TestSeccionDelCorreo(BasePrueba):
    def _novedad(self) -> dict:
        return {"cve": "CVE-2026-1001", "titulo": "Fallo en clamav", "severidad": "Critical",
                "paquete": "clamav", "sistema": "Debian 13", "version_corregida": "1.4.6+dfsg-1",
                "aviso": "DSA-9999-1", "dias_en_espera": 12, "n_activos": 146,
                "n_activos_expuestos": 109, "in_kev": False}

    def test_sin_novedades_no_se_pinta_nada(self):
        plantilla = notify.entorno().get_template("_parches_nuevos.html")
        self.assertEqual(plantilla.render().strip(), "")
        self.assertEqual(plantilla.render(parches_nuevos=[]).strip(), "")
        self.assertEqual(plantilla.render(meta={"parches_nuevos": []}).strip(), "")

    def test_con_novedades_se_pinta_la_tabla(self):
        plantilla = notify.entorno().get_template("_parches_nuevos.html")
        for contexto in ({"parches_nuevos": [self._novedad()]},
                         {"meta": {"parches_nuevos": [self._novedad()]}}):
            html = plantilla.render(**contexto)
            # El título dice desde el 2026-09-10 que esto SÍ se puede hacer hoy: era
            # «Correcciones que ya están disponibles», que no distinguía el aviso del
            # resto del correo, y la sección se leía como una más.
            for texto in ("Ya se puede aplicar: correcciones publicadas",
                          "llevaban tiempo confirmadas",
                          "La corrección ya se ha publicado", "Fallo en clamav", "clamav",
                          "Debian 13", "1.4.6+dfsg-1", "DSA-9999-1", "12", "146",
                          "Versión que corrige", "Días en espera", "Activos afectados",
                          "109 en producción o contingencia"):
                self.assertIn(texto, html)
            # Y dice en cuántos activos se puede aplicar (2026-09-10): antes solo decía
            # cuántas correcciones había, que no sirve para programar la ventana.
            plano = " ".join(html.split())
            self.assertIn("1 corrección publicada · se puede aplicar en 146 activos", plano)
            self.assertIn("esto sí se puede hacer hoy", plano)
            self.assertIn("#1f4e78", notify.entorno().get_template("alerta.html").render(
                amenazas=[], total=0, sin_novedades=True, criticas=[], altas=[], medias=[],
                bajas=[], en_kev=[], afectadas=[], expuestas=[], con_activos=[], total_activos=0,
                top_tecnologias=[], meta={}, filtro={}, excluidas_total=0, motivos_es={},
                umbral_relevancia=50, resumen_activos={}))

    def test_la_linea_de_inclusion_del_coordinador_funciona(self):
        """En alerta.html basta con {% include "_parches_nuevos.html" %}: la sección lee
        ``meta.parches_nuevos``, que es lo que pasa bin/ejecucion_diaria.py."""
        plantilla = notify.entorno().from_string('{% include "_parches_nuevos.html" %}')
        self.assertEqual(plantilla.render(meta={"periodo": "2026-09"}).strip(), "")
        html = plantilla.render(meta={"parches_nuevos": [self._novedad()]})
        self.assertIn("Ya se puede aplicar: correcciones publicadas", html)
        self.assertIn("1.4.6+dfsg-1", html)

    def test_el_correo_escapa_el_html_de_los_datos(self):
        novedad = self._novedad()
        novedad["titulo"] = "<script>alert(1)</script>"
        html = notify.entorno().get_template("_parches_nuevos.html").render(parches_nuevos=[novedad])
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)


class TestPagina(BasePrueba):
    def setUp(self):
        super().setUp()
        self._cachear()
        parches.sincronizar(self.conn)
        registros = self._registros()
        registros["DEBIAN-CVE-2026-1001"] = registro_osv(
            "CVE-2026-1001", ecosistema="Debian:13", paquete="clamav", corregida="1.4.6+dfsg-1")
        parches.buscar(self.conn, osv=ClienteOSVFalso(registros), limite=10)
        from webui import auth
        auth.crear_usuario(self.conn, "admin", "AdminSeguro#2026", rol="admin", actor="t")
        auth.crear_usuario(self.conn, "lector", "LectorSeguro#2026", rol="ciberseguridad", actor="t")
        self.conn.commit()
        from webui.app import crear_app
        self.app = crear_app(db_path=self.ruta, testing=True)

    def _cliente(self, usuario="lector", clave="LectorSeguro#2026"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": clave})
        return cli

    def _ok(self, cli, url) -> str:
        r = cli.get(url)
        self.assertEqual(r.status_code, 200, url)
        html = r.get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html), f"style= en {url}")
        self.assertIsNone(RE_ON.search(html), f"on*= en {url}")
        self.assertIsNone(RE_SCRIPT.search(html), f"script en línea en {url}")
        self.assertNotIn("http://cdn", html)
        self.assertNotIn("googleapis", html)
        return html

    def test_exige_sesion(self):
        r = self.app.test_client().get("/parches-pendientes/")
        self.assertIn(r.status_code, (301, 302, 401, 403))

    def test_pagina_en_seguimiento(self):
        html = self._ok(self._cliente(), "/parches-pendientes/")
        # 2026-09-15 (revisión de claridad): dos rótulos se reescribieron porque no
        # decían QUÉ contaban. «Activos afectados» significaba tres cosas distintas en la
        # plataforma (652 en el Panel, 580 en Informes y 185 aquí) y ahora lleva su
        # alcance; «Encontradas en siete días» no decía que lo encontrado son
        # CORRECCIONES publicadas, no vulnerabilidades nuevas. Se comprueban los rótulos
        # nuevos, con la misma exigencia: que cada indicador de la página esté presente.
        for texto in ("Correcciones pendientes", "En seguimiento",
                      "Activos afectados por vulnerabilidades sin corrección publicada",
                      "Días de la más antigua",
                      # Una sola corrección publicada en el juego de prueba: singular.
                      "Corrección publicada en la última semana",
                      "Por qué no se conoce la versión que corrige", "Fallo en systemd",
                      "Debian 13", "Última búsqueda", "Intentos",
                      parches.MOTIVO_ES["distro_sin_empaquetar"]):
            self.assertIn(texto, html)
        self.assertNotIn("Correcciones publicadas en la última semana", html,
                         "con una sola corrección el rótulo va en singular")
        self.assertNotIn("Fallo en clamav", html)          # ya tiene corrección: no está aquí
        self.assertIn('data-filtro-vivo="tabla-parches"', html)
        self.assertIn('id="tabla-parches"', html)

    def test_pestana_de_ya_disponibles_y_buscador(self):
        cli = self._cliente()
        html = self._ok(cli, "/parches-pendientes/?estado=encontradas")
        self.assertIn("Ya disponibles", html)
        self.assertIn("Fallo en clamav", html)
        self.assertIn("1.4.6+dfsg-1", html)
        self.assertIn("Días de espera", html)
        self.assertNotIn("Fallo en systemd", html.split('id="tabla-parches"')[1])
        html = self._ok(cli, "/parches-pendientes/?q=systemd")
        self.assertIn("Fallo en systemd", html)
        self.assertNotIn("gitlab-runner", html.split('id="tabla-parches"')[1])
        html = self._ok(cli, "/parches-pendientes/?q=nada-de-nada")
        self.assertIn("Ninguna fila coincide", html)
        # un estado inventado no rompe la página: se cae al seguimiento
        self._ok(cli, "/parches-pendientes/?estado=<script>")

    def test_la_espera_media_se_ve_con_decimales_en_espanol(self):
        """El filtro «numero» solo sabe de enteros y truncaba «2,5 días» a «2».

        2026-09-15: la nota pasó de «2,5 días de espera media» a «estuvieron esperando
        2,5 días de media», porque el sujeto de la frase («las correcciones que salieron
        de la lista») no estaba escrito en ningún sitio. La prueba sigue comprobando lo
        mismo: que el decimal se escribe con coma y no truncado a «2».
        """
        self.conn.execute("""UPDATE parches_pendientes
                                SET detectado_at=datetime(encontrado_at, '-60 hours')
                              WHERE encontrado_at IS NOT NULL""")
        self.conn.commit()
        html = self._ok(self._cliente(), "/parches-pendientes/")
        self.assertIn("estuvieron esperando 2,5 días de media", html)
        self.assertNotIn("esperando 2 días de media", html)

    def test_recorrido_guiado_y_espanol(self):
        html = self._ok(self._cliente(), "/parches-pendientes/")
        pasos = re.findall(r'data-tour="(\d+)"[^>]*data-tour-titulo="([^"]+)"[^>]*data-tour-texto="([^"]+)"',
                           html)
        self.assertGreaterEqual(len(pasos), 3)
        self.assertEqual(min(int(n) for n, _, _ in pasos), 1)
        for _, titulo, texto in pasos:
            self.assertGreater(len(texto), 60, titulo)
        # español con tildes y sin abreviaturas en lo que se ve
        for abreviatura in (">Config<", ">Vuln.<", ">Rel.<", ">Ver.<", "N/A"):
            self.assertNotIn(abreviatura, html)

class TestNoInventaVersiones(BasePrueba):
    """Hallazgo de la revisión: la versión que dice el aviso original es la del proyecto
    («2.41»), no la del paquete de la distribución («2.40-2+deb13u1», que puede llevar la
    corrección incorporada por Debian). Darla por buena escribía en el inventario una versión
    inexistente, el plan de remediación ordenaba instalarla y, como la evaluación diaria vuelve
    a poner ``version_corregida`` a NULL, la misma corrección falsa se anunciaba todos los días.
    """

    def _grupo_de_distribucion(self) -> int:
        """Paquete de Debian evaluado con el motor de la distribución y un aviso con una sola
        cota «anterior a 2.41»; OSV.dev no tiene registro (404, todavía sin triar)."""
        self.conn.execute("DELETE FROM aplicabilidad")
        threat = self._amenaza(
            "CVE-2026-2222", titulo_es="Fallo en binutils",
            resumen="El problema afecta a las versiones anteriores a 2.41 de binutils.")
        self._veredicto(self.srv1, threat, "CVE-2026-2222", "binutils",
                        instalada="2.40-2+deb13u1", motor="osv")
        self.conn.commit()
        return threat

    def test_un_paquete_de_la_distribucion_no_toma_la_version_del_aviso(self):
        self._grupo_de_distribucion()
        parches.sincronizar(self.conn)
        r = parches.buscar(self.conn, osv=ClienteOSVFalso({}), limite=5)
        self.assertEqual(r["encontradas"], 0)
        self.assertEqual(r["sin_novedad"], 1)
        fila = self.conn.execute("SELECT * FROM parches_pendientes").fetchone()
        self.assertIsNone(fila["version_corregida"])
        self.assertIsNone(fila["encontrado_at"])
        self.assertEqual(fila["intentos"], 1)
        self.assertIn(fila["motivo"], parches.MOTIVOS)
        # el inventario sigue sin versión y con el motivo puesto
        aplic = self.conn.execute("SELECT * FROM aplicabilidad WHERE cve='CVE-2026-2222'").fetchone()
        self.assertIsNone(aplic["version_corregida"])
        self.assertIsNotNone(aplic["sin_parche_motivo"])
        self.assertEqual(parches.novedades(self.conn), [])

    def test_la_misma_correccion_falsa_no_se_anuncia_cada_dia(self):
        """La secuencia real de la ejecución diaria, cuatro días seguidos."""
        self._grupo_de_distribucion()
        anunciadas = 0
        for dia in range(4):
            # la evaluación diaria reescribe version_corregida a NULL en su UPSERT
            self.conn.execute("UPDATE aplicabilidad SET version_corregida=NULL")
            parches.sincronizar(self.conn)
            self.conn.execute("UPDATE parches_pendientes SET buscado_at=NULL")   # día nuevo
            parches.buscar(self.conn, osv=ClienteOSVFalso({}), limite=5)
            anunciadas += len(parches.novedades(self.conn, marcar=True))
        self.assertEqual(anunciadas, 0, "no hay corrección real que anunciar")

    def test_el_software_ajeno_a_la_distribucion_si_deduce_la_version(self):
        """Con el motor de comparación de versiones la versión del aviso sí es comparable."""
        self.conn.execute("DELETE FROM aplicabilidad")
        threat = self._amenaza("CVE-2026-2223", titulo_es="Fallo en Google Chrome",
                               resumen="Google Chrome prior to 152.0.7632.45 allows remote code execution.")
        self._veredicto(self.ubu, threat, "CVE-2026-2223", "google chrome", instalada="151.0",
                        motor="version")
        parches.sincronizar(self.conn)
        r = parches.buscar(self.conn, osv=ClienteOSVFalso({}), limite=5)
        self.assertEqual(r["encontradas"], 1)
        self.assertEqual(self.conn.execute(
            "SELECT version_corregida FROM parches_pendientes").fetchone()[0], "152.0.7632.45")

    def test_una_correccion_real_se_anuncia_una_sola_vez(self):
        """El registro de la distribución sí publica la versión: se anuncia el primer día y no
        se repite los siguientes, aunque la evaluación diaria reabra la fila cada mañana."""
        self._cachear()
        parches.sincronizar(self.conn)
        registros = self._registros()
        registros["DEBIAN-CVE-2026-1001"] = registro_osv(
            "CVE-2026-1001", ecosistema="Debian:13", paquete="clamav", corregida="1.4.6+dfsg-1")
        anuncios: list[str] = []
        for dia in range(4):
            self.conn.execute("UPDATE aplicabilidad SET version_corregida=NULL")
            parches.sincronizar(self.conn)
            self.conn.execute("UPDATE parches_pendientes SET buscado_at=NULL")
            parches.buscar(self.conn, osv=ClienteOSVFalso(registros), limite=10)
            anuncios += [f["cve"] for f in parches.novedades(self.conn, marcar=True)]
        self.assertEqual(anuncios, ["CVE-2026-1001"])
        fila = self.conn.execute(
            "SELECT * FROM parches_pendientes WHERE cve='CVE-2026-1001'").fetchone()
        self.assertEqual(fila["version_corregida"], "1.4.6+dfsg-1")
        self.assertIsNotNone(fila["avisado_at"])
        self.assertIn("no se vuelve a anunciar", fila["motivo_detalle"])
        # si más adelante aparece una versión distinta, esa sí se anuncia
        registros["DEBIAN-CVE-2026-1001"] = registro_osv(
            "CVE-2026-1001", ecosistema="Debian:13", paquete="clamav", corregida="1.4.7+dfsg-1")
        self.conn.execute("UPDATE aplicabilidad SET version_corregida=NULL")
        parches.sincronizar(self.conn)
        self.conn.execute("UPDATE parches_pendientes SET buscado_at=NULL")
        parches.buscar(self.conn, osv=ClienteOSVFalso(registros), limite=10)
        nuevas = parches.novedades(self.conn, marcar=True)
        self.assertEqual([f["version_corregida"] for f in nuevas], ["1.4.7+dfsg-1"])


class TestAmenazasCerradas(BasePrueba):
    """Lo que el analista cierra (descartada, falso positivo o mitigada) no se sigue buscando
    ni se anuncia, igual que en el panel y en el correo diario."""

    def _cerrar(self, threat_id: int, estado: str) -> None:
        self.conn.execute("UPDATE threats SET estado=? WHERE id=?", (estado, threat_id))
        self.conn.commit()

    def test_no_entran_en_el_seguimiento_ni_en_los_indicadores(self):
        for threat, estado in ((self.t_sin_parche, "falso_positivo"),
                               (self.t_distro, "descartada"),
                               (self.t_version, "mitigada")):
            self._cerrar(threat, estado)
        r = parches.sincronizar(self.conn)
        self.assertEqual(r["en_seguimiento"], 1)
        self.assertEqual([f["cve"] for f in self.conn.execute(
            "SELECT cve FROM parches_pendientes")], ["CVE-2026-1001"])
        res = parches.resumen(self.conn)
        self.assertEqual(res["en_seguimiento"], 1)
        self.assertEqual(res["activos_afectados"], 3)      # solo los de clamav
        self.assertEqual(res["activos_expuestos"], 2)
        self.assertEqual(len(parches.listar(self.conn)), 1)
        self.assertEqual(parches.contar(self.conn), 1)

    def test_una_amenaza_que_se_cierra_sale_del_seguimiento(self):
        parches.sincronizar(self.conn)
        self.assertEqual(4, self.conn.execute("SELECT COUNT(*) FROM parches_pendientes").fetchone()[0])
        self._cerrar(self.t_distro, "falso_positivo")
        r = parches.sincronizar(self.conn)
        self.assertEqual(r["borradas"], 1)
        self.assertIsNone(self.conn.execute(
            "SELECT 1 FROM parches_pendientes WHERE cve='CVE-2026-1003'").fetchone())
        # y su motivo desaparece del inventario
        self.assertEqual(0, self.conn.execute(
            "SELECT COUNT(*) FROM aplicabilidad WHERE cve='CVE-2026-1003' "
            "AND sin_parche_motivo IS NOT NULL").fetchone()[0])

    def test_no_se_consulta_a_la_fuente_por_una_amenaza_cerrada(self):
        parches.sincronizar(self.conn)
        self._cerrar(self.t_sin_version, "descartada")
        cliente = ClienteOSVFalso(self._registros())
        parches.buscar(self.conn, osv=cliente, limite=10)
        self.assertNotIn("DEBIAN-CVE-2026-1001", cliente.consultados)

    def test_una_correccion_de_amenaza_cerrada_no_se_anuncia(self):
        parches.sincronizar(self.conn)
        self.conn.execute("""UPDATE parches_pendientes
                                SET version_corregida='1.4.6+dfsg-1', encontrado_at=?
                              WHERE cve='CVE-2026-1001'""", (self.ahora,))
        self._cerrar(self.t_sin_version, "mitigada")
        self.assertEqual(parches.novedades(self.conn), [])


class TestTopeDelCorreo(BasePrueba):
    """Sin tope, una publicación que resolviera cientos de filas dejaría el correo por encima
    de los 102 KB que recortan Gmail y Outlook, escondiendo el resto de la alerta."""

    def _novedades(self, cuantas: int) -> list[dict]:
        return [{"cve": f"CVE-2026-{3000 + i}", "titulo": f"Fallo número {i} en un paquete",
                 "severidad": "High", "paquete": f"paquete-{i}", "sistema": "Debian 13",
                 "version_corregida": "1.2.3-1+deb13u1", "aviso": "DSA-9999-1",
                 "dias_en_espera": 3, "n_activos": 40, "n_activos_expuestos": 5,
                 "in_kev": False} for i in range(cuantas)]

    def test_recorta_la_tabla_y_dice_cuantas_faltan(self):
        plantilla = notify.entorno().get_template("_parches_nuevos.html")
        html = plantilla.render(parches_nuevos=self._novedades(parches.TOPE_CORREO + 5))
        self.assertEqual(html.count("1.2.3-1+deb13u1"), parches.TOPE_CORREO)
        self.assertIn("Hay 5 correcciones más", html)
        self.assertIn("en la lista «Ya disponibles»", html)
        self.assertIn(str(parches.TOPE_CORREO + 5), html)   # el total sigue diciéndose entero
        self.assertLess(len(html), 35000)
        # 300 correcciones tampoco desbordan el correo (Gmail recorta a unos 102 KB)
        muchas = plantilla.render(parches_nuevos=self._novedades(300))
        self.assertLess(len(muchas), 35000)
        self.assertIn(f"Hay {300 - parches.TOPE_CORREO} correcciones más", muchas)

    def test_una_sola_de_sobra_se_dice_en_singular(self):
        plantilla = notify.entorno().get_template("_parches_nuevos.html")
        html = plantilla.render(parches_nuevos=self._novedades(parches.TOPE_CORREO + 1))
        self.assertIn("Hay una corrección más", html)

    def test_sin_recorte_no_se_pinta_la_nota(self):
        plantilla = notify.entorno().get_template("_parches_nuevos.html")
        html = plantilla.render(parches_nuevos=self._novedades(3))
        self.assertNotIn("correcciones más", html)
        self.assertNotIn("corrección más", html)
        self.assertEqual(html.count("1.2.3-1+deb13u1"), 3)


class TestSelladoDespuesDelEnvio(BasePrueba):
    """``avisado_at`` debe poder sellarse DESPUÉS de que el correo salga: si se sella antes y el
    envío falla, la corrección no se anunciaría nunca."""

    def _con_correccion(self):
        self._cachear()
        parches.sincronizar(self.conn)
        registros = self._registros()
        registros["DEBIAN-CVE-2026-1001"] = registro_osv(
            "CVE-2026-1001", ecosistema="Debian:13", paquete="clamav", corregida="1.4.6+dfsg-1")
        parches.buscar(self.conn, osv=ClienteOSVFalso(registros), limite=10)

    def test_marcar_avisadas_sella_solo_lo_indicado(self):
        self._con_correccion()
        nov = parches.novedades(self.conn)                 # sin marcar: el correo aún no ha salido
        self.assertEqual(len(nov), 1)
        self.assertEqual(len(parches.novedades(self.conn)), 1)   # el envío falló: sigue pendiente
        self.assertEqual(parches.marcar_avisadas(self.conn, [f["id"] for f in nov]), 1)
        self.assertEqual(parches.novedades(self.conn), [])
        # sellar dos veces no cuenta dos veces, y una lista vacía no toca nada
        self.assertEqual(parches.marcar_avisadas(self.conn, [f["id"] for f in nov]), 0)
        self.assertEqual(parches.marcar_avisadas(self.conn, []), 0)
        self.assertEqual(parches.marcar_avisadas(self.conn, [None]), 0)


class TestResumenYRendimiento(BasePrueba):
    def test_espera_media_en_formato_espanol(self):
        self.assertEqual(parches._decimal_es(2.5), "2,5")
        self.assertEqual(parches._decimal_es(0.4), "0,4")
        self.assertEqual(parches._decimal_es(1234.5), "1.234,5")
        self.assertIsNone(parches._decimal_es(None))
        self._cachear()
        parches.sincronizar(self.conn)
        self.conn.execute("""UPDATE parches_pendientes
                                SET version_corregida='1.4.6+dfsg-1', encontrado_at=datetime('now'),
                                    detectado_at=datetime('now', '-60 hours')
                              WHERE cve='CVE-2026-1001'""")
        res = parches.resumen(self.conn)
        self.assertEqual(res["espera_media_es"], "2,5")
        self.assertEqual(res["espera_media_dias"], 2.5)

    def test_contar_no_recorre_las_filas(self):
        self._cachear()
        parches.sincronizar(self.conn)
        self.assertEqual(parches.contar(self.conn, estado="seguimiento"), 4)
        self.assertEqual(parches.contar(self.conn, estado="encontradas"), 0)
        self.assertEqual(parches.contar(self.conn, q="systemd"), 1)
        self.assertEqual(parches.contar(self.conn, q="%"), 0)          # el ESCAPE del LIKE
        self.assertEqual(parches.contar(self.conn, estado="inventado"),
                         parches.contar(self.conn, estado="seguimiento"))
        self.assertEqual(parches.contar(self.conn),
                         len(parches.listar(self.conn, limite=1000)))

    def test_el_cupo_de_consultas_se_agota_sin_romper_nada(self):
        self._cachear()
        parches.sincronizar(self.conn)
        cliente = ClienteOSVFalso(self._registros(), max_peticiones=2)
        r = parches.buscar(self.conn, osv=cliente, limite=10)
        self.assertTrue(r["cupo_agotado"])
        self.assertLessEqual(r["consultadas"], 2)
        self.assertEqual(r["errores"], [])
        # las filas que no se llegaron a revisar siguen pendientes para el día siguiente
        self.assertGreater(self.conn.execute(
            "SELECT COUNT(*) FROM parches_pendientes WHERE buscado_at IS NULL").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
