"""Hoja de cálculo de la alerta: un libro con una pestaña por vulnerabilidad (v7, 2026-09-06).

El usuario pidió que el correo se quedara con las tres vulnerabilidades más críticas y que
todas, con el mismo detalle, viajaran en un Excel con una hoja por vulnerabilidad, «para poder
hacer una gestión interna mucho más rápida».

Sin red y sin correo: base temporal bajo ``data/`` con ``db.init_db`` y libros escritos en el
mismo directorio temporal, que se borra al terminar.
"""
from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
import warnings
import zipfile
from datetime import date, datetime
from pathlib import Path
from typing import Any, Optional

from openpyxl import load_workbook

from threatintel import db, libro_alerta, queries
from threatintel.paths import BASE_DIR


class Cfg(dict):
    """Ajustes mínimos (la aplicación real usa ``cfg.get``)."""

    def get(self, clave, defecto=None):
        return super().get(clave, defecto)


def _asegurar_columna_motivo(conn: sqlite3.Connection) -> None:
    """``db.init_db`` no deja ``aplicabilidad.sin_parche_motivo`` en una base recién creada:
    la migración de columnas se ejecuta antes de crear el esquema y la sentencia CREATE TABLE
    no la incluye (``threatintel/db.py``, fichero compartido). Hasta que se corrija allí, la
    prueba la añade a mano, igual que ``tests/test_parches.py``."""
    if not any(r[1] == "sin_parche_motivo"
               for r in conn.execute("PRAGMA table_info(aplicabilidad)")):
        conn.execute("ALTER TABLE aplicabilidad ADD COLUMN sin_parche_motivo TEXT")


def _amenaza(conn: sqlite3.Connection, *, cve: Optional[str], titulo: str,
             severidad: str = "Critical", cvss: Optional[float] = 9.8,
             epss: Optional[float] = 0.42, relevancia: float = 90.0,
             en_kev: bool = True, fingerprint: Optional[str] = None) -> int:
    cur = conn.execute(
        """INSERT INTO threats (fingerprint, cve, title_en, title_es, summary_en, summary_es,
                                severity, severity_source, cvss_score, cvss_vector, epss_score,
                                in_kev, kev_due_date, published_at, first_seen_at, last_seen_at,
                                impact_es, remediation_es, month, alerted_at, relevance, estado)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (fingerprint or f"huella-{titulo}", cve, titulo, titulo,
         "English summary", "Descripción en español de la vulnerabilidad.",
         severidad, "nvd", cvss, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", epss,
         1 if en_kev else 0, "2026-09-20", "2026-09-01T08:00:00Z",
         "2026-09-05T08:00:00Z", "2026-09-06T08:00:00Z",
         "Permite ejecutar código de forma remota.", "Actualizar el paquete a la versión que corrige.",
         "2026-09", "2026-09-06T08:10:00Z", relevancia, "nueva"))
    return int(cur.lastrowid)


def _tecnologia(conn: sqlite3.Connection, threat_id: int, nombre: str, *,
                version: Optional[str] = "1.0", confianza: float = 1.0,
                veredicto: str = "affected") -> None:
    cur = conn.execute(
        """INSERT INTO technologies (name, slug, version_installed, criticality,
                                     systems_count, exposure, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (nombre, nombre.lower(), version, "critical", 3, "internet",
         "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"))
    conn.execute(
        """INSERT INTO threat_technologies (threat_id, technology_id, matched_alias,
                                            confidence, version_verdict)
           VALUES (?,?,?,?,?)""",
        (threat_id, int(cur.lastrowid), nombre, confianza, veredicto))


def _fuente(conn: sqlite3.Connection, threat_id: int, nombre: str, url: str) -> None:
    fila = conn.execute("SELECT id FROM sources WHERE slug=?", (nombre.lower(),)).fetchone()
    if fila is None:
        cur = conn.execute(
            """INSERT INTO sources (slug, name, url, kind, priority, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (nombre.lower(), nombre, url, "rss", "high",
             "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"))
        fuente_id = int(cur.lastrowid)
    else:
        fuente_id = int(fila[0])
    conn.execute("INSERT INTO threat_sources (threat_id, source_id, url, seen_at) VALUES (?,?,?,?)",
                 (threat_id, fuente_id, url, "2026-09-06T08:00:00Z"))


def _activo(conn: sqlite3.Connection, nombre: str, *, ocs_id: int, origen: str = "servidores",
            entorno: str = "produccion", proceso: str = "Contabilidad") -> int:
    cur = conn.execute(
        """INSERT INTO activos (origen, ocs_id, nombre, so_nombre, so_version, so_familia,
                                ecosistema, ip, zona, entorno, proceso, presente,
                                primera_vez_at, visto_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?)""",
        (origen, ocs_id, nombre, "Ubuntu", "22.04", "ubuntu", "Ubuntu:22.04",
         f"10.1.2.{ocs_id}", "interna", entorno, proceso,
         "2026-09-01T00:00:00Z", "2026-09-06T00:00:00Z"))
    return int(cur.lastrowid)


def _veredicto(conn: sqlite3.Connection, activo_id: int, threat_id: int, cve: str, *,
               paquete: str = "curl", instalada: str = "7.81.0-1ubuntu1.15",
               corregida: Optional[str] = "7.81.0-1ubuntu1.20",
               motivo: Optional[str] = None, aviso: Optional[str] = "USN-1234-1") -> None:
    conn.execute(
        """INSERT INTO aplicabilidad (activo_id, threat_id, cve, paquete, version_instalada,
                                      version_corregida, veredicto, motor, evidencia, aviso,
                                      sin_parche_motivo, evaluado_at)
           VALUES (?,?,?,?,?,?,'afectado','osv',?,?,?,?)""",
        (activo_id, threat_id, cve, paquete, instalada, corregida,
         "OSV.dev: versión anterior a la corregida", aviso, motivo, "2026-09-06T07:00:00Z"))


def _resumen_aplicabilidad(conn: sqlite3.Connection, threat_id: int, *, afectados: int,
                           expuestos: int, no_afectados: int = 2, sin_dato: int = 1) -> None:
    conn.execute(
        """INSERT INTO aplicabilidad_amenaza (threat_id, evaluado_at, afectados, no_afectados,
                                              sin_dato, afectados_expuestos, parche_disponible, detalle)
           VALUES (?,?,?,?,?,?,1,'{}')""",
        (threat_id, "2026-09-06T07:00:00Z", afectados, no_afectados, sin_dato, expuestos))


class BaseLibro(unittest.TestCase):
    """Base temporal con tres vulnerabilidades alertadas y sus activos."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "libro.db")
        db.init_db(self.ruta)
        self.destino = Path(self.dir.name) / "alerta.xlsx"
        self.cfg = Cfg(alert_excel_max_activos=500, alert_min_relevance=50,
                       alert_min_match_confidence=0.6)
        with db.connect(self.ruta) as conn:
            _asegurar_columna_motivo(conn)
            self.ids: list[int] = []
            for indice, (cve, titulo) in enumerate((
                    ("CVE-2026-1001", "Ejecución remota de código en curl"),
                    ("CVE-2026-1002", "Elevación de privilegios en el núcleo"),
                    ("CVE-2026-1003", "Fuga de información en OpenSSL")), start=1):
                tid = _amenaza(conn, cve=cve, titulo=titulo, relevancia=95.0 - indice)
                self.ids.append(tid)
                _tecnologia(conn, tid, f"Tecnología {indice}")
                _fuente(conn, tid, "NVD", f"https://nvd.nist.gov/vuln/detail/{cve}")
                activo = _activo(conn, f"srv-app-{indice:02d}", ocs_id=indice)
                _veredicto(conn, activo, tid, cve)
                _resumen_aplicabilidad(conn, tid, afectados=1, expuestos=1)
            conn.commit()

    def tearDown(self) -> None:
        self.dir.cleanup()

    def _vistas(self, ids: Optional[list[int]] = None) -> list[dict]:
        with db.connect(self.ruta) as conn:
            return [queries.obtener_amenaza(conn, i) for i in (ids or self.ids)]

    def _generar(self, *, vistas: Optional[list[dict]] = None, cfg: Any = None,
                 meta: Optional[dict] = None) -> Path:
        with db.connect(self.ruta) as conn:
            ruta = libro_alerta.generar(conn, vistas if vistas is not None else self._vistas(),
                                        destino=self.destino, cfg=cfg or self.cfg,
                                        meta=meta or {"url_base": "http://soc.ejemplo.local"})
        self.assertIsNotNone(ruta)
        return ruta


class TestEstructuraDelLibro(BaseLibro):
    def test_una_pestana_por_vulnerabilidad_mas_resumen(self):
        ruta = self._generar()
        libro = load_workbook(ruta)
        try:
            self.assertEqual(libro.sheetnames[0], "Resumen")
            self.assertEqual(libro.sheetnames[1:],
                             ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"])
            resumen = libro["Resumen"]
            self.assertEqual(resumen["A1"].value, "Prioridad")
            self.assertEqual(resumen.freeze_panes, "A2")
            self.assertTrue(resumen.auto_filter.ref)
            self.assertTrue(resumen["A1"].font.bold)
            # una fila por vulnerabilidad, en orden de prioridad
            self.assertEqual([resumen.cell(row=f, column=1).value for f in (2, 3, 4)], [1, 2, 3])
            self.assertEqual([resumen.cell(row=f, column=2).value for f in (2, 3, 4)],
                             ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"])
            self.assertEqual(resumen.cell(row=2, column=14).hyperlink.target,
                             "http://soc.ejemplo.local/amenazas/%d" % self.ids[0])
        finally:
            libro.close()

    def test_contenido_de_la_pestana_de_una_vulnerabilidad(self):
        ruta = self._generar()
        libro = load_workbook(ruta)
        try:
            hoja = libro["CVE-2026-1001"]
            texto = "\n".join(str(c.value) for fila in hoja.iter_rows() for c in fila
                              if c.value is not None)
            for esperado in ("Identificación", "Por qué está en la alerta", "Qué es y qué hacer",
                             "Descripción", "Impacto", "Remediación",
                             "Tecnologías afectadas del inventario", "Fuentes y referencias",
                             "Activos afectados (OCS Inventory)", "srv-app-01", "Producción",
                             "Contabilidad", "curl", "7.81.0-1ubuntu1.20", "USN-1234-1",
                             "Relevancia para la organización", "Explotación activa (CISA KEV)"):
                self.assertIn(esperado, texto, esperado)
            self.assertTrue(hoja.auto_filter.ref, "la tabla de activos lleva autofiltro")
        finally:
            libro.close()

    def test_libro_vacio_devuelve_none(self):
        with db.connect(self.ruta) as conn:
            self.assertIsNone(libro_alerta.generar(conn, [], destino=self.destino, cfg=self.cfg))
            self.assertIsNone(libro_alerta.generar(conn, None, destino=self.destino, cfg=self.cfg))
        self.assertFalse(self.destino.exists())

    def test_ruta_por_defecto_bajo_data_informes(self):
        """El directorio y el nombre por defecto, SIN escribir en el directorio real.

        ``data/informes/alerta_AAAA-MM-DD.xlsx`` es el libro que archiva la ejecución diaria y
        nadie más lo conserva: si la prueba escribiera ahí, cada pase de la suite posterior al
        cron borraría el libro del día (regla 5 del proyecto). Se sustituye la constante
        ``libro_alerta.DIRECTORIO`` por un directorio de la propia prueba."""
        self.assertEqual(libro_alerta.DIRECTORIO.name, "informes",
                         "el sitio de producción sigue siendo data/informes")
        propio = Path(self.dir.name) / "informes"
        original = libro_alerta.DIRECTORIO
        libro_alerta.DIRECTORIO = propio
        try:
            with db.connect(self.ruta) as conn:
                ruta = libro_alerta.generar(conn, self._vistas()[:1], cfg=self.cfg,
                                            meta={"url_base": "http://soc"})
        finally:
            libro_alerta.DIRECTORIO = original
        self.assertEqual(ruta.parent, propio)
        self.assertEqual(ruta.name, f"alerta_{date.today().isoformat()}.xlsx")
        # el libro lleva el mapa de activos vulnerables: directorio y fichero cerrados
        self.assertEqual(oct(propio.stat().st_mode)[-3:], "700")
        self.assertEqual(oct(ruta.stat().st_mode)[-3:], "600")

    def test_no_cambia_los_permisos_del_directorio_que_le_indican(self):
        """Con ``destino`` explícito no se toca el directorio ajeno: no le corresponde a este
        módulo cerrar un directorio que no es suyo."""
        salida = Path(self.dir.name) / "salida"
        salida.mkdir()
        salida.chmod(0o755)
        destino = salida / "libro.xlsx"
        with db.connect(self.ruta) as conn:
            libro_alerta.generar(conn, self._vistas()[:1], destino=destino, cfg=self.cfg,
                                 meta={"url_base": "http://soc"})
        self.assertTrue(destino.exists())
        self.assertEqual(oct(salida.stat().st_mode)[-3:], "755")


class TestNombresDePestana(BaseLibro):
    def test_saneados_y_unicos(self):
        with db.connect(self.ruta) as conn:
            repetida = _amenaza(conn, cve="CVE-2026-1001", titulo="El mismo CVE en otro aviso",
                                fingerprint="huella-repetida")
            rara = _amenaza(conn, cve="AVISO/2026:9?9*9[9]MUY-LARGO-DE-VERDAD-SI",
                            titulo="Identificador con caracteres prohibidos",
                            fingerprint="huella-rara")
            conn.commit()
        ruta = self._generar(vistas=self._vistas(self.ids + [repetida, rara]))
        libro = load_workbook(ruta)
        try:
            nombres = libro.sheetnames
            self.assertEqual(len(nombres), len(set(nombres)), "no puede haber pestañas repetidas")
            self.assertIn("CVE-2026-1001", nombres)
            self.assertIn("CVE-2026-1001 (2)", nombres)
            for nombre in nombres:
                self.assertLessEqual(len(nombre), 31, nombre)
                for prohibido in ":\\/?*[]":
                    self.assertNotIn(prohibido, nombre, nombre)
        finally:
            libro.close()

    def test_no_choca_con_las_pestanas_fijas_ni_por_mayusculas(self):
        """Excel y openpyxl comparan los nombres SIN distinguir mayúsculas: si aquí se dieran
        por distintos, openpyxl renombraría en silencio y saldrían nombres engañosos
        («CVE-2026-20011», que parece otro CVE) o de 32 caracteres."""
        usados: set[str] = set()
        nombres = [libro_alerta.nombre_pestana(x, usados) for x in (
            "Resumen", "correcciones pendientes", "CVE-2026-2001", "cve-2026-2001",
            "A" * 31, "a" * 40, "")]
        self.assertEqual(len({n.casefold() for n in nombres}), len(nombres), nombres)
        for nombre in nombres:
            self.assertTrue(nombre.strip(), "ninguna pestaña se queda sin nombre")
            self.assertLessEqual(len(nombre), 31, nombre)
            self.assertNotIn(nombre.casefold(),
                             (libro_alerta.HOJA_RESUMEN.casefold(),
                              libro_alerta.HOJA_CORRECCIONES.casefold()), nombre)

    def test_el_libro_no_renombra_ninguna_pestana(self):
        vistas = [{"id": indice, "cve": identificador, "title_es": f"Amenaza {indice}",
                   "severity": "High", "relevance": 60, "cvss_score": 7.5, "epss_score": 0.1,
                   "technologies": [], "sources": [], "activos": {"afectados": []}}
                  for indice, identificador in enumerate(
                      ("Resumen", "Correcciones Pendientes", "CVE-2026-2001",
                       "cve-2026-2001", "B" * 31, "b" * 40), start=1)]
        with warnings.catch_warnings(record=True) as avisos:
            warnings.simplefilter("always")
            ruta = libro_alerta.generar(
                None, vistas, destino=self.destino, cfg=self.cfg,
                meta={"url_base": "http://soc",
                      "parches_nuevos": [{"cve": "CVE-2026-0900", "titulo": "Ya corregida"}]})
        self.assertEqual([str(a.message) for a in avisos
                          if "31 characters" in str(a.message)], [])
        libro = load_workbook(ruta)
        try:
            nombres = libro.sheetnames
            self.assertEqual(nombres[0], libro_alerta.HOJA_RESUMEN)
            self.assertIn(libro_alerta.HOJA_CORRECCIONES, nombres)
            self.assertEqual(len({n.casefold() for n in nombres}), len(nombres), nombres)
            for nombre in nombres:
                self.assertLessEqual(len(nombre), 31, nombre)
        finally:
            libro.close()

    def test_sin_cve_usa_el_aviso(self):
        with db.connect(self.ruta) as conn:
            sin_cve = _amenaza(conn, cve=None, titulo="Aviso sin CVE", fingerprint="huella-sin-cve")
            activo = _activo(conn, "srv-sin-cve", ocs_id=90)
            _veredicto(conn, activo, sin_cve, "USN-9999-1", aviso="USN-9999-1")
            _resumen_aplicabilidad(conn, sin_cve, afectados=1, expuestos=1)
            conn.commit()
        ruta = self._generar(vistas=self._vistas([sin_cve]))
        libro = load_workbook(ruta)
        try:
            self.assertIn("USN-9999-1", libro.sheetnames)
        finally:
            libro.close()


class TestActivosYLimite(BaseLibro):
    def test_limite_con_fila_de_aviso(self):
        with db.connect(self.ruta) as conn:
            tid = self.ids[0]
            for n in range(10, 17):
                activo = _activo(conn, f"srv-extra-{n}", ocs_id=n)
                _veredicto(conn, activo, tid, "CVE-2026-1001")
            conn.execute("UPDATE aplicabilidad_amenaza SET afectados=8, afectados_expuestos=8 "
                         "WHERE threat_id=?", (tid,))
            conn.commit()
        ruta = self._generar(cfg=Cfg(alert_excel_max_activos=3))
        libro = load_workbook(ruta)
        try:
            hoja = libro["CVE-2026-1001"]
            nombres = [c.value for fila in hoja.iter_rows(min_col=1, max_col=1) for c in fila
                       if isinstance(c.value, str) and c.value.startswith("srv-")]
            self.assertEqual(len(nombres), 3, "el tope de activos por pestaña se respeta")
            texto = "\n".join(str(c.value) for fila in hoja.iter_rows() for c in fila
                              if c.value is not None)
            self.assertIn("Se listan los primeros 3 activos de 8", texto)
            self.assertIn("se consultan en la plataforma", texto)
        finally:
            libro.close()

    def test_motivo_cuando_no_hay_version_que_corrige(self):
        with db.connect(self.ruta) as conn:
            tid = self.ids[1]
            activo = _activo(conn, "srv-sin-parche", ocs_id=50)
            _veredicto(conn, activo, tid, "CVE-2026-1002", paquete="nginx",
                       corregida=None, motivo="sin_parche_publicado", aviso=None)
            conn.execute("UPDATE aplicabilidad_amenaza SET afectados=2, afectados_expuestos=2 "
                         "WHERE threat_id=?", (tid,))
            conn.commit()
        ruta = self._generar()
        libro = load_workbook(ruta)
        try:
            hoja = libro["CVE-2026-1002"]
            texto = "\n".join(str(c.value) for fila in hoja.iter_rows() for c in fila
                              if c.value is not None)
            self.assertIn("sin corrección publicada", texto)
            # la raya que se pintaba antes no queda en ninguna celda
            self.assertNotIn("—", [c.value for fila in hoja.iter_rows() for c in fila])
        finally:
            libro.close()

    def test_sin_activos_afectados_lo_dice(self):
        with db.connect(self.ruta) as conn:
            limpia = _amenaza(conn, cve="CVE-2026-2000", titulo="Sin activos afectados",
                              fingerprint="huella-limpia")
            _resumen_aplicabilidad(conn, limpia, afectados=0, expuestos=0)
            conn.commit()
        ruta = self._generar(vistas=self._vistas([limpia]))
        libro = load_workbook(ruta)
        try:
            texto = "\n".join(str(c.value) for fila in libro["CVE-2026-2000"].iter_rows()
                              for c in fila if c.value is not None)
            self.assertIn("Ningún activo presente tiene instalada la versión vulnerable", texto)
        finally:
            libro.close()


class TestTiposDeDato(BaseLibro):
    def test_numeros_y_fechas_no_van_como_texto(self):
        ruta = self._generar()
        libro = load_workbook(ruta)
        try:
            resumen = libro["Resumen"]
            self.assertIsInstance(resumen.cell(row=2, column=1).value, int)      # prioridad
            self.assertIsInstance(resumen.cell(row=2, column=5).value, float)    # CVSS
            self.assertEqual(resumen.cell(row=2, column=5).number_format, "0.0")
            self.assertIsInstance(resumen.cell(row=2, column=7).value, float)    # EPSS
            self.assertEqual(resumen.cell(row=2, column=7).number_format, "0.0%")
            self.assertIsInstance(resumen.cell(row=2, column=8).value, int)      # relevancia
            self.assertIsInstance(resumen.cell(row=2, column=10).value, int)     # activos
            # Revisión de claridad del 2026-09-15: la hoja de resumen y la ficha de cada
            # vulnerabilidad dicen la explotación activa con EL MISMO texto.
            self.assertEqual(resumen.cell(row=2, column=9).value, "Sí, confirmada por CISA")
            hoja = libro["CVE-2026-1001"]
            fechas = [c for fila in hoja.iter_rows() for c in fila
                      if isinstance(c.value, datetime)]
            self.assertTrue(fechas, "las fechas se escriben como fecha de Excel")
            for celda in fechas:
                self.assertEqual(celda.number_format, "DD/MM/YYYY")
                self.assertIsNone(celda.value.tzinfo)
            self.assertNotIn("=", str(hoja["A1"].value), "sin fórmulas")
        finally:
            libro.close()

    def test_epss_ausente_deja_la_celda_vacia(self):
        with db.connect(self.ruta) as conn:
            sin_epss = _amenaza(conn, cve="CVE-2026-3000", titulo="Sin EPSS ni CVSS",
                                cvss=None, epss=None, en_kev=False, fingerprint="huella-sin-epss")
            _resumen_aplicabilidad(conn, sin_epss, afectados=0, expuestos=0)
            conn.commit()
        ruta = self._generar(vistas=self._vistas([sin_epss]))
        libro = load_workbook(ruta)
        try:
            resumen = libro["Resumen"]
            self.assertIsNone(resumen.cell(row=2, column=5).value)
            self.assertIsNone(resumen.cell(row=2, column=7).value)
            self.assertEqual(resumen.cell(row=2, column=9).value, "No consta")
            texto = "\n".join(str(c.value) for fila in libro["CVE-2026-3000"].iter_rows()
                              for c in fila if c.value is not None)
            self.assertIn("no disponible", texto)
        finally:
            libro.close()


class TestCorrecciones(BaseLibro):
    correccion = {"cve": "CVE-2026-0900", "titulo": "Fallo en sudo sin parche hasta hoy",
                  "severidad": "High", "paquete": "sudo", "sistema": "Ubuntu 22.04",
                  "version_corregida": "1.9.9-1ubuntu2.4", "aviso": "USN-7000-1",
                  "dias_en_espera": 12, "n_activos": 5, "n_activos_expuestos": 3,
                  "motivo_es": "La distribución todavía no había empaquetado la corrección"}

    def test_pestana_con_las_correcciones_dadas(self):
        ruta = self._generar(meta={"url_base": "http://soc", "parches_nuevos": [self.correccion]})
        libro = load_workbook(ruta)
        try:
            self.assertIn("Correcciones pendientes", libro.sheetnames)
            hoja = libro["Correcciones pendientes"]
            self.assertEqual(hoja["A3"].value, "Vulnerabilidad")
            self.assertEqual(hoja["B4"].value, "CVE-2026-0900")
            self.assertEqual(hoja["H4"].value, 12)
            self.assertEqual(hoja["C4"].value, "Alta")
            self.assertEqual(hoja.freeze_panes, "A4")
        finally:
            libro.close()

    def test_sin_correcciones_no_se_escribe_la_pestana(self):
        ruta = self._generar()
        libro = load_workbook(ruta)
        try:
            self.assertNotIn("Correcciones pendientes", libro.sheetnames)
        finally:
            libro.close()


class TestSinConexion(BaseLibro):
    def test_usa_los_activos_de_la_vista(self):
        vista = self._vistas([self.ids[0]])[0]
        vista["activos"] = {"evaluada": True, "n_afectados": 1, "n_no_afectados": 0,
                            "n_sin_dato": 0, "mas": 0,
                            "afectados": [{"id": 1, "nombre": "srv-de-la-vista",
                                           "ip": "10.9.9.9", "origen": "equipos",
                                           "so_nombre": "Windows", "paquetes": ["chrome"],
                                           "version_instalada": "120", "version_corregida": None,
                                           "aviso": None, "sin_parche_motivo": None}]}
        ruta = libro_alerta.generar(None, [vista], destino=self.destino, cfg=self.cfg,
                                    meta={"url_base": "http://soc"})
        self.assertIsNotNone(ruta)
        libro = load_workbook(ruta)
        try:
            texto = "\n".join(str(c.value) for fila in libro["CVE-2026-1001"].iter_rows()
                              for c in fila if c.value is not None)
            self.assertIn("srv-de-la-vista", texto)
            self.assertIn("Equipo de cómputo", texto)
            self.assertIn("pendiente de publicar", texto)
        finally:
            libro.close()


class TestSeguridadDelLibro(BaseLibro):
    """Nada que venga de una fuente externa puede acabar siendo una fórmula (CWE-1236).

    El libro lo abren los analistas del SOC: un título de RSS como «=cmd|\' /c calc\'!A0» es la
    carga DDE clásica, y «=WEBSERVICE(...)» exfiltra datos. Hallazgo del revisor del
    2026-09-06."""

    CARGA = "=cmd|' /c calc'!A0"

    def _libro_con_cargas(self) -> Path:
        with db.connect(self.ruta) as conn:
            tid = _amenaza(conn, cve="=1+1", titulo=self.CARGA, fingerprint="huella-formula")
            conn.execute("""UPDATE threats SET summary_es=?, impact_es=?, remediation_es=?
                             WHERE id=?""",
                         ('=HYPERLINK("http://malo","pulse aquí")', "+1+1",
                          "@SUM(A1:A9)", tid))
            activo = _activo(conn, "=1+2", ocs_id=77)
            _veredicto(conn, activo, tid, "=1+1", paquete='=WEBSERVICE("http://malo")',
                       instalada="-1", corregida="-2", aviso="@USN")
            _resumen_aplicabilidad(conn, tid, afectados=1, expuestos=1)
            conn.commit()
        return self._generar(vistas=self._vistas([tid]))

    def test_ningun_texto_externo_se_escribe_como_formula(self):
        ruta = self._libro_con_cargas()
        libro = load_workbook(ruta)
        try:
            formulas, sin_marcar = [], []
            for hoja in libro.worksheets:
                for fila in hoja.iter_rows():
                    for celda in fila:
                        if celda.data_type == "f":
                            formulas.append((hoja.title, celda.coordinate, celda.value))
                        elif (isinstance(celda.value, str)
                                and celda.value[:1] in ("=", "+", "-", "@")
                                and not celda.quotePrefix):
                            sin_marcar.append((hoja.title, celda.coordinate, celda.value))
            self.assertEqual(formulas, [], "ninguna celda puede ser una fórmula")
            self.assertEqual(sin_marcar, [], "el texto peligroso va con prefijo de texto")
            texto = "\n".join(str(c.value) for hoja in libro.worksheets
                               for fila in hoja.iter_rows() for c in fila if c.value is not None)
            self.assertIn(self.CARGA, texto, "el texto se ve tal cual: no se ejecuta")
        finally:
            libro.close()

    def test_el_xml_del_libro_no_tiene_ni_una_etiqueta_de_formula(self):
        """Comprobación independiente de openpyxl: el .xlsx es un zip de XML."""
        ruta = self._libro_con_cargas()
        with zipfile.ZipFile(ruta) as zip_libro:
            hojas = [n for n in zip_libro.namelist() if n.startswith("xl/worksheets/")]
            self.assertTrue(hojas)
            for nombre in hojas:
                self.assertNotIn(b"<f>", zip_libro.read(nombre), nombre)


class TestTextoVisible(BaseLibro):
    """Español correcto y números en formato español en el texto que lee el analista."""

    def test_concordancia_de_singular_y_plural_y_miles(self):
        with db.connect(self.ruta) as conn:
            conn.execute("""UPDATE aplicabilidad_amenaza
                               SET afectados=1, afectados_expuestos=1, no_afectados=1234,
                                   sin_dato=1
                             WHERE threat_id=?""", (self.ids[0],))
            conn.execute("""UPDATE aplicabilidad_amenaza
                               SET no_afectados=1, sin_dato=2500 WHERE threat_id=?""",
                         (self.ids[1],))
            conn.commit()
        ruta = self._generar()
        libro = load_workbook(ruta)
        try:
            def texto_de(pestana: str) -> str:
                return "\n".join(str(c.value) for fila in libro[pestana].iter_rows()
                                  for c in fila if c.value is not None)

            primera = texto_de("CVE-2026-1001")
            self.assertIn("1 activo con la versión vulnerable instalada", primera)
            self.assertIn("1.234 ya están corregidos.", primera)
            self.assertIn("1 sin dato suficiente para decidir.", primera)
            self.assertNotIn("ya está corregido", primera)
            segunda = texto_de("CVE-2026-1002")
            self.assertIn("1 ya está corregido.", segunda)
            self.assertIn("2.500 sin datos suficientes para decidir.", segunda)
        finally:
            libro.close()

    def test_numeros_del_aviso_del_tope_en_formato_espanol(self):
        with db.connect(self.ruta) as conn:
            tid = self.ids[0]
            conn.execute("""UPDATE aplicabilidad_amenaza
                               SET afectados=1500, afectados_expuestos=1200 WHERE threat_id=?""",
                         (tid,))
            conn.commit()
        ruta = self._generar(cfg=Cfg(alert_excel_max_activos=1))
        libro = load_workbook(ruta)
        try:
            texto = "\n".join(str(c.value) for fila in libro["CVE-2026-1001"].iter_rows()
                               for c in fila if c.value is not None)
            self.assertIn("Se lista el primer activo de 1.500.", texto)
            self.assertIn("Los 1.499 restantes se consultan en la plataforma", texto)
            self.assertIn("1.500 activos con la versión vulnerable instalada", texto)
        finally:
            libro.close()


class TestRendimiento(BaseLibro):
    def test_muchas_vulnerabilidades_y_activos_en_segundos(self):
        """El caso que pidió el usuario (50 vulnerabilidades) no puede tardar minutos."""
        with db.connect(self.ruta) as conn:
            activos = [_activo(conn, f"srv-carga-{n:03d}", ocs_id=1000 + n) for n in range(60)]
            ids = []
            for n in range(15):
                tid = _amenaza(conn, cve=f"CVE-2026-5{n:03d}", titulo=f"Carga {n}",
                               fingerprint=f"huella-carga-{n}")
                ids.append(tid)
                for activo in activos:
                    _veredicto(conn, activo, tid, f"CVE-2026-5{n:03d}")
                _resumen_aplicabilidad(conn, tid, afectados=len(activos), expuestos=len(activos))
            conn.commit()
        vistas = self._vistas(ids)
        inicio = time.monotonic()
        ruta = self._generar(vistas=vistas, cfg=Cfg(alert_excel_max_activos=500))
        tardanza = time.monotonic() - inicio
        self.assertLess(tardanza, 60.0, f"tardó {tardanza:.1f} s")
        libro = load_workbook(ruta)
        try:
            self.assertEqual(len(libro.sheetnames), len(ids) + 1)
        finally:
            libro.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
