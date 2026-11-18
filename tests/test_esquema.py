"""Integridad del esquema de la base de datos (2026-09-06).

Dos veces se ha perdido una migración por repetir una clave en ``_COLUMNAS_NUEVAS``: Python
conserva solo la última y las columnas de la primera entrada nunca se añaden. Estas pruebas lo
impiden y comprueban que toda columna declarada en la migración existe también en una base
creada desde cero (las sentencias de creación y la migración deben decir lo mismo)."""
from __future__ import annotations

import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR

FUENTE = (BASE_DIR / "threatintel" / "db.py").read_text(encoding="utf-8")


class TestEsquema(unittest.TestCase):
    def test_ninguna_tabla_declarada_dos_veces_en_la_migracion(self):
        """Una clave repetida en el diccionario hace desaparecer la entrada anterior sin avisar."""
        declaradas = re.findall(r'^    "([a-z_]+)": \[', FUENTE, re.M)
        repetidas = sorted({t for t in declaradas if declaradas.count(t) > 1})
        self.assertEqual(repetidas, [], f"tablas declaradas más de una vez en _COLUMNAS_NUEVAS: {repetidas}")
        self.assertEqual(sorted(declaradas), sorted(db._COLUMNAS_NUEVAS),
                         "lo que declara el fichero y lo que ve Python deben coincidir")

    def test_una_base_nueva_tiene_todas_las_columnas_de_la_migracion(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            ruta = str(Path(tmp) / "esquema.db")
            db.init_db(ruta)
            conn = db.connect(ruta)
            try:
                for tabla, columnas in db._COLUMNAS_NUEVAS.items():
                    reales = {r[1] for r in conn.execute(f"PRAGMA table_info({tabla})")}
                    self.assertTrue(reales, f"la tabla {tabla} no existe en una base nueva")
                    faltan = [n for n, _ in columnas if n not in reales]
                    self.assertEqual(faltan, [], f"{tabla}: faltan en la sentencia de creación {faltan}")
            finally:
                conn.close()

    def test_la_migracion_es_idempotente(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            ruta = str(Path(tmp) / "dos_veces.db")
            db.init_db(ruta)
            db.init_db(ruta)      # no debe fallar ni duplicar nada
            conn = db.connect(ruta)
            try:
                version = conn.execute("SELECT value FROM schema_meta WHERE key='version'").fetchone()[0]
                self.assertEqual(int(version), db.SCHEMA_VERSION)
                tablas = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                for esperada in ("threats", "activos", "aplicabilidad", "remediaciones",
                                 "parches_pendientes", "alertas_proceso", "msrc_correcciones",
                                 "excepciones"):
                    self.assertIn(esperada, tablas)
            finally:
                conn.close()

    #: Columnas que tiene la tabla `excepciones` en la versión 15 del esquema.
    COLUMNAS_EXCEPCIONES = {
        "id", "alcance", "activo_id", "cve", "paquete", "justificacion",
        "responsable_nombre", "responsable_correo", "compensacion",
        "registrado_por", "registrado_at", "vence_at", "vence_at_inicial",
        "permanente", "revisada_at", "revisada_por", "revisada_nota", "revisiones",
        "revision_avisada_at", "estado", "kev", "prorrogas", "prorrogada_at",
        "prorrogada_por", "prorroga_motivo", "revocada_at", "revocada_por",
        "revocada_motivo", "avisado_at"}

    def test_la_tabla_de_excepciones_se_crea_con_sus_indices(self):
        """v13 (2026-09-10): aceptación de riesgo con vencimiento.
        v15 (2026-09-10): excepciones permanentes, sin fecha de vencimiento.

        La tabla no toca ``_COLUMNAS_NUEVAS``: su definición vive en una constante
        (``db._DDL_EXCEPCIONES``) que usan tanto el esquema como la reconstrucción de la
        migración, así que las dos dicen lo mismo por construcción. Lo que hay que
        vigilar es que esté con todas sus columnas y con sus cinco índices, incluido el
        único parcial que impide dos excepciones no revocadas sobre lo mismo."""
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            ruta = str(Path(tmp) / "excepciones.db")
            db.init_db(ruta)
            db.init_db(ruta)                  # idempotente también para la tabla nueva
            conn = db.connect(ruta)
            try:
                columnas = {r[1] for r in conn.execute("PRAGMA table_info(excepciones)")}
                self.assertEqual(columnas, self.COLUMNAS_EXCEPCIONES)
                indices = {r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' "
                    "AND tbl_name='excepciones'")}
                for indice in ("idx_exc_unica", "idx_exc_activo", "idx_exc_cve",
                               "idx_exc_vence", "idx_exc_permanente"):
                    self.assertIn(indice, indices)
                # «vencida» NO es un valor guardado: se calcula comparando la fecha
                # (threatintel/excepciones.py, SQL_VIGENTE). Si alguien lo añadiera al
                # esquema habría dos verdades sobre lo mismo.
                creacion = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE name='excepciones'").fetchone()[0]
                self.assertIn("vigente|revocada", creacion)
                # Y «permanente» y «vence_at» no se pueden contradecir: o hay fecha, o es
                # permanente. Sin el CHECK, un fallo de código dejaría una permanente con
                # fecha (avisada como «por vencer») o una temporal sin fecha (que no
                # vencería nunca, en silencio).
                self.assertIn("CHECK", creacion)
                for combinacion in ((1, "2026-12-31"), (0, None)):
                    with self.subTest(permanente=combinacion[0]):
                        with self.assertRaises(sqlite3.IntegrityError):
                            conn.execute(
                                """INSERT INTO excepciones(alcance, justificacion,
                                       responsable_nombre, responsable_correo,
                                       registrado_por, registrado_at, permanente, vence_at)
                                   VALUES('cve','x','y','z','a','b',?,?)""", combinacion)
                self.assertGreaterEqual(db.SCHEMA_VERSION, 15)
            finally:
                conn.close()

    def test_la_migracion_v15_conserva_las_filas_de_una_base_v14(self):
        """v14 -> v15 (2026-09-10): ``vence_at`` deja de ser NOT NULL.

        SQLite no sabe quitar un NOT NULL con ALTER TABLE, así que ``init_db`` reconstruye
        la tabla. Lo que hay que garantizar es que no se pierde ni una fila, que los datos
        llegan intactos, que los índices vuelven, que la tabla reconstruida es IDÉNTICA a
        la que se crea desde cero y que ejecutarlo dos veces no hace nada la segunda.
        """
        # La definición literal de la tabla en la v14, tal como estaba en producción
        # antes de esta tarea: `vence_at` y `vence_at_inicial` obligatorias, sin las
        # columnas de lo permanente y sin el CHECK.
        v14 = """
        CREATE TABLE excepciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alcance TEXT NOT NULL,
            activo_id INTEGER REFERENCES activos(id) ON DELETE CASCADE,
            cve TEXT, paquete TEXT,
            justificacion TEXT NOT NULL,
            responsable_nombre TEXT NOT NULL, responsable_correo TEXT NOT NULL,
            compensacion TEXT, registrado_por TEXT NOT NULL, registrado_at TEXT NOT NULL,
            vence_at TEXT NOT NULL, vence_at_inicial TEXT NOT NULL,
            estado TEXT NOT NULL DEFAULT 'vigente', kev INTEGER NOT NULL DEFAULT 0,
            prorrogas INTEGER NOT NULL DEFAULT 0, prorrogada_at TEXT, prorrogada_por TEXT,
            prorroga_motivo TEXT, revocada_at TEXT, revocada_por TEXT, revocada_motivo TEXT,
            avisado_at TEXT);
        CREATE UNIQUE INDEX idx_exc_unica ON excepciones(
            alcance, COALESCE(activo_id, -1), COALESCE(cve, ''), COALESCE(paquete, ''))
            WHERE estado <> 'revocada';
        CREATE INDEX idx_exc_activo ON excepciones(activo_id, estado);
        CREATE INDEX idx_exc_cve    ON excepciones(cve, estado);
        CREATE INDEX idx_exc_vence  ON excepciones(vence_at, estado);
        """
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            ruta = str(Path(tmp) / "v14.db")
            vieja = sqlite3.connect(ruta)
            vieja.executescript(v14)
            vieja.execute(
                """INSERT INTO excepciones(alcance, activo_id, cve, justificacion,
                       responsable_nombre, responsable_correo, registrado_por,
                       registrado_at, vence_at, vence_at_inicial, estado, kev, prorrogas)
                   VALUES('cve', NULL, 'CVE-2026-1001', 'justificación de la primera',
                          'Ana Pérez Gómez', 'ana.perez@ejemplo.local', 'admin',
                          '2026-09-01T10:00:00Z', '2026-12-01', '2026-11-01', 'vigente', 1, 2)""")
            vieja.execute(
                """INSERT INTO excepciones(alcance, activo_id, cve, justificacion,
                       responsable_nombre, responsable_correo, registrado_por,
                       registrado_at, vence_at, vence_at_inicial, estado)
                   VALUES('cve', NULL, 'CVE-2026-1002', 'justificación de la segunda',
                          'Ana Pérez Gómez', 'ana.perez@ejemplo.local', 'soc',
                          '2026-09-02T10:00:00Z', '2026-10-01', '2026-10-01', 'revocada')""")
            vieja.commit()
            vieja.close()

            db.init_db(ruta)
            conn = db.connect(ruta)
            try:
                self.assertEqual(
                    int(conn.execute("SELECT COUNT(*) FROM excepciones").fetchone()[0]), 2,
                    "la migración no puede perder ninguna fila")
                fila = conn.execute(
                    "SELECT * FROM excepciones WHERE cve='CVE-2026-1001'").fetchone()
                self.assertEqual(fila["vence_at"], "2026-12-01")
                self.assertEqual(fila["vence_at_inicial"], "2026-11-01")
                self.assertEqual(fila["kev"], 1)
                self.assertEqual(fila["prorrogas"], 2)
                self.assertEqual(fila["registrado_por"], "admin")
                self.assertEqual(fila["permanente"], 0,
                                 "lo que ya existía sigue teniendo fecha: nada se vuelve "
                                 "permanente por migrar")
                self.assertEqual(fila["revisiones"], 0)
                self.assertIsNone(fila["revisada_at"])
                self.assertEqual(conn.execute(
                    "SELECT estado FROM excepciones WHERE cve='CVE-2026-1002'"
                ).fetchone()[0], "revocada")
                columnas = {r[1] for r in conn.execute("PRAGMA table_info(excepciones)")}
                self.assertEqual(columnas, self.COLUMNAS_EXCEPCIONES)
                indices = {r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' "
                    "AND tbl_name='excepciones'")}
                for indice in ("idx_exc_unica", "idx_exc_activo", "idx_exc_cve",
                               "idx_exc_vence", "idx_exc_permanente"):
                    self.assertIn(indice, indices)
                self.assertEqual(
                    [], conn.execute("PRAGMA foreign_key_check(excepciones)").fetchall())
                # Ya no queda la tabla de trabajo de la migración.
                tablas = {r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                self.assertNotIn("excepciones_v15", tablas)
                # Y una permanente ya cabe en la tabla migrada.
                conn.execute(
                    """INSERT INTO excepciones(alcance, cve, justificacion,
                           responsable_nombre, responsable_correo, registrado_por,
                           registrado_at, permanente)
                       VALUES('cve', 'CVE-2026-1003', 'justificación', 'Ana Pérez Gómez',
                              'ana.perez@ejemplo.local', 'admin', '2026-09-10T10:00:00Z', 1)""")
                self.assertIsNone(conn.execute(
                    "SELECT vence_at FROM excepciones WHERE cve='CVE-2026-1003'").fetchone()[0])
            finally:
                conn.close()
            # Segunda pasada: no vuelve a reconstruir nada.
            conn = db.connect(ruta)
            try:
                self.assertFalse(db.reconstruir_excepciones(conn))
            finally:
                conn.close()
            db.init_db(ruta)
            conn = db.connect(ruta)
            try:
                self.assertEqual(
                    int(conn.execute("SELECT COUNT(*) FROM excepciones").fetchone()[0]), 3)
            finally:
                conn.close()

    def test_el_estado_esperando_datos_esta_en_el_esquema(self):
        """v14 (2026-09-10): «esperando datos del inventario».

        No hay columna nueva —el motivo va en ``cerrado_motivo``, como en
        «activo_ausente»—, pero sí un valor nuevo de ``remediaciones.estado``. Lo que hay
        que vigilar es que el comentario del esquema lo nombre (es donde se lee qué
        valores admite la columna) y que el módulo y el esquema no se separen: si alguien
        añade un estado en el código y no aquí, la siguiente persona que lea el esquema
        creerá que hay tres.
        """
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            ruta = str(Path(tmp) / "estados.db")
            db.init_db(ruta)
            conn = db.connect(ruta)
            try:
                creacion = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE name='remediaciones'").fetchone()[0]
                from threatintel import remediacion
                for estado in remediacion.ESTADOS:
                    self.assertIn(estado, creacion,
                                  f"el esquema no nombra el estado «{estado}»")
                self.assertIn("esperando_datos", remediacion.ESTADO_ES)
                self.assertIn("esperando_datos", remediacion.ESTADO_CLAVE)
                self.assertGreaterEqual(db.SCHEMA_VERSION, 14)
                # Y se puede guardar y leer: la columna no tiene CHECK, pero la prueba
                # deja constancia de que el valor es válido de verdad.
                conn.execute("INSERT INTO activos(id, origen, ocs_id, nombre, presente, "
                             "primera_vez_at, visto_at) VALUES(1,'equipos',1,'PC',1,?,?)",
                             (db.utcnow(), db.utcnow()))
                conn.execute("INSERT INTO remediaciones(activo_id, cve, paquete, estado, "
                             "detectado_at, comprobado_at) "
                             "VALUES(1,'CVE-2026-0001','windows','esperando_datos',?,?)",
                             (db.utcnow(), db.utcnow()))
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM remediaciones WHERE estado='esperando_datos'"
                ).fetchone()[0], 1)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
