"""Nivel de parche de Windows con los boletines de Microsoft (threatintel.msrc, 2026-09-05).

Sin red: un documento CVRF reducido e inventado, activos Windows con KB en su software y
una base temporal. Comprueba el parseo y el filtrado de productos, el mapeo compilación →
producto, la compilación efectiva, los tres veredictos, la idempotencia, el respeto a las
filas de otros motores, el ajuste ``msrc_enabled``, ``resumen_activo`` con y sin dato y que la
plantilla parcial se pinta en la ficha del activo sin ``style=`` ni ``on*=``. Tras la revisión:
servidor con servidor y puesto con puesto (Windows 7 no se asigna a Windows Server 2008 R2), edición
de 32 bits según la arquitectura de OCS, limpieza de las filas del activo que pierde su producto y
marca ``MARCA_PENDIENTE`` en las amenazas recientes que el motor principal aún no ha evaluado."""
from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from threatintel import aplicabilidad as ap
from threatintel import db, msrc
from threatintel.http import JsonResult
from threatintel.paths import BASE_DIR

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)


class Cfg(dict):
    """Config mínima (usa .get) como la de threatintel.config."""


P_25H2 = "20438"
P_25H2_ARM = "20437"
P_SRV2022 = "11923"
P_SRV2022_CORE = "11924"
P_OFFICE = "999"
P_SRV2008 = "10051"
P_W10_32 = "11568"
P_W10_64 = "11569"

PRODUCTOS = [
    {"ProductID": P_25H2, "Value": "Windows 11 Version 25H2 for x64-based Systems"},
    {"ProductID": P_25H2_ARM, "Value": "Windows 11 Version 25H2 for ARM64-based Systems"},
    {"ProductID": P_SRV2022, "Value": "Windows Server 2022"},
    {"ProductID": P_SRV2022_CORE, "Value": "Windows Server 2022 (Server Core installation)"},
    {"ProductID": P_OFFICE, "Value": "Microsoft Office 2019"},
    # comparte la compilación 6.1.7601 con Windows 7, que ya no aparece en los boletines
    {"ProductID": P_SRV2008, "Value": "Windows Server 2008 R2 for x64-based Systems Service Pack 1"},
    {"ProductID": P_W10_32, "Value": "Windows 10 Version 22H2 for 32-bit Systems"},
    {"ProductID": P_W10_64, "Value": "Windows 10 Version 22H2 for x64-based Systems"},
]


def _rem(build, kb, *pids, tipo=2):
    return {"Type": tipo, "FixedBuild": build, "Description": {"Value": kb}, "ProductID": list(pids),
            "URL": f"https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB{kb}", "Date": "0001-01-01T00:00:00"}


def _vuln(cve, *rems):
    return {"CVE": cve, "Title": {"Value": f"Título de {cve}"}, "Remediations": list(rems), "Threats": []}


DOC_JUL = {
    "DocumentTitle": {"Value": "July 2026 Security Updates"},
    "DocumentTracking": {"Identification": {"ID": {"Value": "2026-Jul"}}, "InitialReleaseDate": "2026-07-14T07:00:00",
                         "CurrentReleaseDate": "2026-08-01T01:00:00"},
    "ProductTree": {"FullProductName": PRODUCTOS},
    "Vulnerability": [
        _vuln("CVE-2026-0005", _rem("10.0.26200.8000", "5110000", P_25H2, P_25H2_ARM),
              _rem("10.0.20348.5300", "5110001", P_SRV2022, P_SRV2022_CORE)),
    ],
}

DOC_AUG = {
    "DocumentTitle": {"Value": "August 2026 Security Updates"},
    "DocumentTracking": {"Identification": {"ID": {"Value": "2026-Aug"}}, "InitialReleaseDate": "2026-08-11T07:00:00",
                         "CurrentReleaseDate": "2026-09-04T01:03:40"},
    "ProductTree": {"FullProductName": PRODUCTOS},
    "Vulnerability": [
        # dos compilaciones para el mismo producto: la más baja ya lo corrige
        _vuln("CVE-2026-0001", _rem("10.0.26200.9106", "5120994", P_25H2, P_25H2_ARM),
              _rem("10.0.26200.9168", "5121003", P_25H2, P_25H2_ARM),
              _rem("10.0.20348.5440", "5120229", P_SRV2022, P_SRV2022_CORE),
              _rem("16.0.1", "5002700", P_OFFICE), _rem(None, None, P_25H2, tipo=3)),
        # ruido real del boletín: la KB compartida de 24H2 y 25H2 aparece también con la compilación
        # de la otra rama; no debe cambiar ni la corrección ni el catálogo del producto
        _vuln("CVE-2026-0002", _rem("10.0.26200.9168", "5121003", P_25H2, P_25H2_ARM),
              _rem("10.0.26100.9168", "5121003", P_25H2, P_25H2_ARM)),
        _vuln("CVE-2026-0003", _rem("10.0.20348.5499", "5120242", P_SRV2022, P_SRV2022_CORE),
              _rem("6.1.7601.27000", "5060000", P_SRV2008),
              _rem("10.0.19045.6500", "5060001", P_W10_32, P_W10_64),
              _rem(None, None, P_SRV2022, tipo=3)),
        _vuln("CVE-2026-0004", _rem("16.0.2", "5002701", P_OFFICE)),            # solo Office: fuera
        _vuln("CVE-2026-0006", _rem("10.0.26200.9106", "5120994", P_25H2)),      # su amenaza está descartada
    ],
}

LISTA = {"value": [
    {"ID": "1999-Sep", "InitialReleaseDate": "1999-09-02T00:00:00Z", "CurrentReleaseDate": "2025-10-01T23:10:48Z",
     "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/1999-Sep"},
    {"ID": "2026-Aug", "InitialReleaseDate": "2026-08-11T07:00:00Z", "CurrentReleaseDate": "2026-09-04T01:03:40Z",
     "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Aug"},
    {"ID": "2026-Jul", "InitialReleaseDate": "2026-07-14T07:00:00Z", "CurrentReleaseDate": "2026-08-01T01:00:00Z",
     "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jul"},
    {"ID": "2020-Jan", "InitialReleaseDate": "2020-01-14T08:00:00Z", "CurrentReleaseDate": "2020-02-01T00:00:00Z",
     "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2020-Jan"},
]}

DOCUMENTOS = {"2026-Aug": DOC_AUG, "2026-Jul": DOC_JUL}


class FetchFalso:
    """Simula http.fetch_json: cuenta llamadas y puede fallar un documento."""

    def __init__(self, fallar=()):
        self.llamadas: list[str] = []
        self.fallar = set(fallar)

    def __call__(self, url, **kw):
        self.llamadas.append(url)
        if url == msrc.URL_LISTA:
            return JsonResult(True, 200, json.loads(json.dumps(LISTA)), None, 5)
        ident = url.rsplit("/", 1)[-1]
        if ident in self.fallar:
            return JsonResult(False, 503, None, "http_503", 5)
        if ident in DOCUMENTOS:
            return JsonResult(True, 200, json.loads(json.dumps(DOCUMENTOS[ident])), None, 5)
        return JsonResult(False, 404, None, "http_404", 5)


ACTIVOS = [
    # (nombre, so_nombre, so_version, familia, software)
    ("pc-uno", "Windows 11 Pro", "10.0.26200", "windows",
     ["Security Update KB5120994", "Update KB5003791", "Security Update for Microsoft Office 2010 (KB2589375) 32-Bit Edition"]),
    ("pc-dos", "Windows 11 Pro", "10.0.26200", "windows", ["Google Chrome", "Update for Microsoft Office 2010 (KB2589339)"]),
    ("pc-tres", "Windows 11 Pro", "10.0.26200", "windows", ["Update KB5110000"]),
    ("pc-cuatro", "Windows 11 Pro", "10.0.26200", "windows", ["Update for x64-based Windows Systems (KB5121003)"]),
    ("srv-uno", "Windows Server 2022 Standard", "10.0.20348", "windows", ["Security Update KB5120229"]),
    ("pc-viejo", "Windows 7 Professional", "6.1.7601", "windows", ["Security Update KB4474419"]),
    ("pc-32", "Windows 10 Pro", "10.0.19045", "windows", ["Security Update KB5060001"]),
    ("srv-linux", "Ubuntu 24.04.2 LTS", "24.04", "ubuntu", ["curl"]),
]

AMENAZAS = [("CVE-2026-0001", "nueva"), ("CVE-2026-0002", "nueva"), ("CVE-2026-0003", "nueva"),
            ("CVE-2026-0004", "nueva"), ("CVE-2026-0005", "nueva"), ("CVE-2026-0006", "descartada")]


def _sembrar(ruta: str) -> dict:
    """Base temporal con activos, software y amenazas. Devuelve ids por nombre y CVE."""
    ids: dict = {"activo": {}, "amenaza": {}}
    with db.session(ruta) as conn:
        ahora = db.utcnow()
        for i, (nombre, so_nombre, so_version, familia, software) in enumerate(ACTIVOS, start=1):
            conn.execute(
                """INSERT INTO activos(origen, ocs_id, nombre, so_nombre, so_version, so_familia, ecosistema, entorno,
                       arquitectura, presente, primera_vez_at, visto_at, n_software)
                   VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?)""",
                ("equipos" if nombre.startswith("pc") else "servidores", i, nombre, so_nombre, so_version, familia,
                 "Ubuntu:24.04" if familia == "ubuntu" else None,
                 "produccion" if nombre.startswith("srv") else "soporte",
                 "x86 32 bit" if nombre in ("pc-32", "pc-viejo") else "x86 64 bit", ahora, ahora, len(software)))
            aid = conn.execute("SELECT id FROM activos WHERE nombre=?", (nombre,)).fetchone()[0]
            ids["activo"][nombre] = aid
            for s in software:
                conn.execute("INSERT INTO activo_software(activo_id, nombre, nombre_norm, version, fabricante) VALUES(?,?,?,?,?)",
                             (aid, s, s.lower(), "", "Microsoft Corporation"))
        for cve, estado in AMENAZAS:
            conn.execute(
                """INSERT INTO threats(fingerprint, cve, title_en, summary_en, severity, severity_source, first_seen_at,
                       last_seen_at, month, relevance, estado)
                   VALUES(?,?,?,?,'High','nvd',?,?,?,60.0,?)""",
                (f"fp-{cve}", cve, f"Windows flaw {cve}", "Windows elevation of privilege", ahora, ahora, ahora[:7], estado))
            ids["amenaza"][cve] = conn.execute("SELECT id FROM threats WHERE cve=?", (cve,)).fetchone()[0]
        # fila de otro motor para el mismo activo y CVE (paquete distinto): no debe tocarse
        conn.execute(
            """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada, version_corregida, veredicto,
                   motor, evidencia, aviso, evaluado_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (ids["activo"]["pc-uno"], ids["amenaza"]["CVE-2026-0001"], "CVE-2026-0001", "google chrome", "150.0", "152.0",
             "afectado", "version", "Google Chrome 150.0: anterior a 152.0", None, "2026-09-01T00:00:00.000000Z"))
    return ids


class TestParseo(unittest.TestCase):
    def test_productos_windows_y_correcciones(self):
        productos = msrc.productos_windows(DOC_AUG)
        self.assertEqual(set(productos), {P_25H2, P_25H2_ARM, P_SRV2022, P_SRV2022_CORE, P_SRV2008, P_W10_32, P_W10_64})
        self.assertNotIn(P_OFFICE, productos)
        filas = msrc.correcciones_de(DOC_AUG, documento_id="2026-Aug", publicado_at="2026-08-11T07:00:00Z")
        cves = {f["cve"] for f in filas if not msrc.es_fila_catalogo(f["cve"])}
        self.assertEqual(cves, {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0006"})
        por = {(f["cve"], f["producto_id"]): f for f in filas}
        # con dos compilaciones para el mismo producto se guarda la más baja (ya corrige) y su KB
        f = por[("CVE-2026-0001", P_25H2)]
        self.assertEqual((f["kb"], f["build_corregida"], f["documento"]), ("5120994", "10.0.26200.9106", "2026-Aug"))
        self.assertEqual(por[("CVE-2026-0003", P_SRV2022_CORE)]["build_corregida"], "10.0.20348.5499")
        self.assertNotIn(("CVE-2026-0004", P_OFFICE), por)
        # catálogo KB -> compilación: la reedición KB5121003 aparece aunque no sea la primera corrección de nada
        self.assertEqual(por[("KB5121003", P_25H2)]["build_corregida"], "10.0.26200.9168")
        self.assertEqual(por[("KB5120242", P_SRV2022)]["build_corregida"], "10.0.20348.5499")
        self.assertEqual(por[("CVE-2026-0002", P_25H2)]["build_corregida"], "10.0.26200.9168")   # no la de 24H2
        self.assertFalse(any(f["build_corregida"].startswith("10.0.26100.") for f in filas))
        self.assertTrue(msrc.es_fila_catalogo("KB5121003"))
        self.assertFalse(msrc.es_fila_catalogo("CVE-2026-0001"))

    def test_kbs_builds_y_ventana(self):
        self.assertEqual(msrc.extraer_kbs(["Security Update KB5123304", "Update for x64-based Windows Systems (KB5001716)",
                                           "Google Chrome", "KB12"]), {"5123304", "5001716"})
        self.assertEqual(msrc.comparar_builds("10.0.26200.9168", "10.0.26200.9106"), 1)
        self.assertEqual(msrc.comparar_builds("10.0.26200.900", "10.0.26200.9106"), -1)   # numérico, no alfabético
        self.assertEqual(msrc.comparar_builds("10.0.26200.9106", "10.0.26200.9106"), 0)
        self.assertIsNone(msrc.comparar_builds("abc", "10.0.1.1"))
        from datetime import datetime, timezone
        self.assertEqual(msrc._ventana(datetime(2026, 9, 5, tzinfo=timezone.utc), 3), "2026-07-01T00:00:00Z")
        self.assertEqual(msrc._ventana(datetime(2026, 1, 5, tzinfo=timezone.utc), 18), "2024-08-01T00:00:00Z")
        docs = msrc._documentos_en_ventana(LISTA["value"], ahora=datetime(2026, 9, 5, tzinfo=timezone.utc), meses=3)
        self.assertEqual([d["documento"] for d in docs], ["2026-Jul", "2026-Aug"])

    def test_eleccion_de_producto(self):
        candidatos = [(P_25H2, "Windows 11 Version 25H2 for x64-based Systems"),
                      (P_25H2_ARM, "Windows 11 Version 25H2 for ARM64-based Systems")]
        self.assertEqual(msrc.elegir_producto({"so_nombre": "Windows 11 Pro"}, candidatos)[0], P_25H2)
        self.assertEqual(msrc.elegir_producto({"so_nombre": "Windows 11 Pro", "arquitectura": "ARM64"}, candidatos)[0], P_25H2_ARM)
        servidores = [(P_SRV2022_CORE, "Windows Server 2022 (Server Core installation)"), (P_SRV2022, "Windows Server 2022"),
                      ("12390", "Windows 11 Version 24H2 for x64-based Systems")]
        self.assertEqual(msrc.elegir_producto({"so_nombre": "Windows Server 2022 Standard"}, servidores)[0], P_SRV2022)
        self.assertEqual(msrc.elegir_producto({"so_nombre": "Windows 11 Pro"}, servidores)[0], "12390")
        self.assertIsNone(msrc.elegir_producto({"so_nombre": "Windows 7"}, []))
        # servidor con servidor y puesto con puesto, nunca cruzados: Windows 7 (6.1.7601) no es Server 2008 R2
        solo_servidor = [(P_SRV2008, "Windows Server 2008 R2 for x64-based Systems Service Pack 1")]
        self.assertIsNone(msrc.elegir_producto({"so_nombre": "Windows 7 Professional", "arquitectura": "x86 32 bit"}, solo_servidor))
        self.assertEqual(msrc.elegir_producto({"so_nombre": "Windows Server 2008 R2 Standard"}, solo_servidor)[0], P_SRV2008)
        self.assertIsNone(msrc.elegir_producto({"so_nombre": "Windows Server 2025 Standard"}, candidatos))
        # sin nombre del sistema no se sabe si es servidor: se admite cualquiera
        self.assertEqual(msrc.elegir_producto({"so_nombre": ""}, solo_servidor)[0], P_SRV2008)
        # la arquitectura de OCS elige la edición: «x86 32 bit» -> 32-bit; «x86 64 bit» -> x64; ARM -> ARM64
        w10 = [(P_W10_64, "Windows 10 Version 22H2 for x64-based Systems"), (P_W10_32, "Windows 10 Version 22H2 for 32-bit Systems")]
        self.assertEqual(msrc.elegir_producto({"so_nombre": "Windows 10 Pro", "arquitectura": "x86 32 bit"}, w10)[0], P_W10_32)
        self.assertEqual(msrc.elegir_producto({"so_nombre": "Windows 10 Pro", "arquitectura": "x86 64 bit"}, w10)[0], P_W10_64)
        self.assertEqual(msrc.elegir_producto({"so_nombre": "Windows 10 Pro"}, w10)[0], P_W10_64)
        self.assertEqual(msrc.arquitectura_preferida({"arquitectura": "x86 32 bit"}), "32-bit")
        self.assertEqual(msrc.arquitectura_preferida({"arquitectura": "x86_64"}), "x64")
        self.assertEqual(msrc.arquitectura_preferida({"arquitectura": "ARM64"}), "arm64")
        self.assertEqual(msrc.arquitectura_preferida({}), "x64")
        # sin edición de su arquitectura vale la x64 (mismas KB y compilaciones)
        self.assertEqual(msrc.elegir_producto({"so_nombre": "Windows 11 Pro", "arquitectura": "x86 32 bit"}, candidatos)[0], P_25H2)
        # la rama del activo debe ser la mayoritaria del producto: una compilación suelta de otra rama es ruido
        ramas = {"12390": ("Windows 11 Version 24H2 for x64-based Systems", {"10.0.26100": 40, "10.0.26200": 1}),
                 P_25H2: ("Windows 11 Version 25H2 for x64-based Systems", {"10.0.26200": 38, "10.0.26100": 2}),
                 "12436": ("Windows Server 2025", {"10.0.26100": 30})}
        self.assertEqual([p for p, _ in msrc.candidatos_por_rama(ramas, "10.0.26200")], [P_25H2])
        self.assertEqual(sorted(p for p, _ in msrc.candidatos_por_rama(ramas, "10.0.26100")), ["12390", "12436"])
        self.assertEqual(msrc.candidatos_por_rama(ramas, "10.0.19045"), [])
        self.assertEqual(msrc.candidatos_por_rama(ramas, None), [])
        # sin mayoría clara vale cualquiera que tenga la rama
        self.assertEqual([p for p, _ in msrc.candidatos_por_rama({"1": ("A", {"10.0.1": 1, "10.0.2": 1})}, "10.0.2")], ["1"])

    def test_compilacion_efectiva(self):
        mapa = {"5120994": ("10.0.26200.9106", "2026-08-11T07:00:00Z"), "5121003": ("10.0.26200.9168", "2026-08-11T07:00:00Z"),
                "5110000": ("10.0.26200.8000", "2026-07-14T07:00:00Z")}
        self.assertEqual(msrc.compilacion_efectiva({"5110000", "5120994", "9999999"}, mapa),
                         ("10.0.26200.9106", "KB5120994", "2026-08-11T07:00:00Z"))
        self.assertEqual(msrc.compilacion_efectiva({"5003791"}, mapa), (None, None, None))


class TestMotorMSRC(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "msrc.db")
        db.init_db(self.ruta)
        self.ids = _sembrar(self.ruta)
        self.cache = Path(self.dir.name) / "cache_msrc"
        self.parche = mock.patch.object(msrc, "CACHE_DIR", self.cache)
        self.parche.start()
        self.cfg = Cfg(msrc_enabled=True, msrc_meses=3, msrc_cache_hours=24)

    def tearDown(self):
        self.parche.stop()
        self.dir.cleanup()

    def _actualizar(self, conn, fetch=None, **kw):
        fetch = fetch or FetchFalso()
        from datetime import datetime, timezone
        with mock.patch.object(msrc, "_ahora", return_value=datetime(2026, 9, 5, 10, 0, tzinfo=timezone.utc)):
            res = msrc.actualizar(conn, cfg=self.cfg, fetch=fetch, **kw)
        return res, fetch

    def test_actualizar_descarga_cache_errores_y_ventana(self):
        conn = db.connect(self.ruta)
        try:
            # un boletín viejo ya guardado debe salir de la ventana de 3 meses
            conn.execute("INSERT INTO msrc_documentos(documento, publicado_at, revisado_at, descargado_at) VALUES('2020-Jan','2020-01-14T08:00:00Z','2020-02-01T00:00:00Z','2020-02-02T00:00:00Z')")
            conn.execute("INSERT INTO msrc_correcciones(cve, producto_id, producto, kb, build_corregida, documento, publicado_at) "
                         "VALUES('CVE-2020-0001','11923','Windows Server 2022','4000000','10.0.20348.1','2020-Jan','2020-01-14T08:00:00Z')")
            res, fetch = self._actualizar(conn)
            self.assertFalse(res["omitido"])
            self.assertEqual(res["descargados"], ["2026-Jul", "2026-Aug"])
            self.assertEqual(res["errores"], [])
            self.assertEqual(res["eliminados"], ["2020-Jan"])
            self.assertEqual(sorted(u.rsplit("/", 1)[-1] for u in fetch.llamadas), ["2026-Aug", "2026-Jul", "updates"])
            docs = {r["documento"]: dict(r) for r in conn.execute("SELECT * FROM msrc_documentos")}
            self.assertEqual(set(docs), {"2026-Jul", "2026-Aug"})
            self.assertEqual(docs["2026-Aug"]["n_cve"], 5)
            self.assertEqual(docs["2026-Aug"]["n_windows"], 4)
            self.assertEqual(docs["2026-Aug"]["revisado_at"], "2026-09-04T01:03:40Z")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM msrc_correcciones WHERE documento='2020-Jan'").fetchone()[0], 0)
            self.assertTrue((self.cache / "2026-Aug.json").is_file())
            n = conn.execute("SELECT COUNT(*) FROM msrc_correcciones").fetchone()[0]
            self.assertEqual(res["correcciones"], n)
            self.assertGreater(n, 0)
            # segunda pasada: nada que descargar (misma revisión y descargado hace poco)
            res2, fetch2 = self._actualizar(conn)
            self.assertEqual(res2["descargados"], [])
            self.assertEqual(res2["en_cache"], 2)
            self.assertEqual(len(fetch2.llamadas), 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM msrc_correcciones").fetchone()[0], n)   # idempotente
            # forzar: vuelve a descargar los dos
            res3, _ = self._actualizar(conn, forzar=True)
            self.assertEqual(res3["descargados"], ["2026-Jul", "2026-Aug"])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM msrc_correcciones").fetchone()[0], n)
            # error en un documento: se anota, el otro sigue; con copia local se reutiliza
            conn.execute("DELETE FROM msrc_documentos")
            conn.execute("DELETE FROM msrc_correcciones")
            (self.cache / "2026-Jul.json").unlink()
            res4, _ = self._actualizar(conn, fetch=FetchFalso(fallar={"2026-Jul"}))
            self.assertEqual(res4["descargados"], [])          # agosto viene de la copia local
            self.assertEqual(res4["en_cache"], 1)
            self.assertEqual(len(res4["errores"]), 1)
            self.assertIn("2026-Jul", res4["errores"][0])
            docs = {r["documento"]: dict(r) for r in conn.execute("SELECT * FROM msrc_documentos")}
            self.assertIsNotNone(docs["2026-Jul"]["error"])
            self.assertIsNone(docs["2026-Aug"]["error"])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM msrc_correcciones WHERE documento='2026-Jul'").fetchone()[0], 0)
            # lista inaccesible: error y nada roto
            res5 = msrc.actualizar(conn, cfg=self.cfg, fetch=lambda url, **k: JsonResult(False, 500, None, "conexion", 1))
            self.assertEqual(len(res5["errores"]), 1)
            self.assertIn("lista de boletines", res5["errores"][0])
        finally:
            conn.close()

    def test_desactivado(self):
        conn = db.connect(self.ruta)
        try:
            cfg = Cfg(msrc_enabled=False)
            fetch = FetchFalso()
            r = msrc.actualizar(conn, cfg=cfg, fetch=fetch)
            self.assertTrue(r["omitido"])
            self.assertEqual(fetch.llamadas, [])
            e = msrc.evaluar_activos(conn, cfg=cfg)
            self.assertTrue(e["omitido"])
            self.assertIn("motivo", e)
            # sin boletines descargados tampoco hay nada que evaluar, y se dice
            e2 = msrc.evaluar_activos(conn, cfg=self.cfg)
            self.assertTrue(e2["omitido"])
            self.assertIn("boletines", e2["motivo"])
        finally:
            conn.close()

    def test_evaluar_activos_veredictos_idempotencia_y_resumenes(self):
        conn = db.connect(self.ruta)
        try:
            self._actualizar(conn)
            conn.execute("UPDATE threats SET first_seen_at='2025-01-01T00:00:00Z' WHERE cve='CVE-2026-0005'")
            conn.commit()
            ev = msrc.evaluar_activos(conn, cfg=self.cfg, ahora="2026-09-05T10:00:00.000001Z")
            self.assertFalse(ev["omitido"])
            self.assertEqual(ev["activos"], 7)             # los siete Windows; el Ubuntu no
            self.assertEqual(ev["con_kb"], 5)              # pc-uno, pc-tres, pc-cuatro, srv-uno, pc-32
            self.assertEqual(ev["sin_kb"], 1)              # pc-dos
            self.assertEqual(ev["sin_producto"], 1)        # Windows 7: su rama solo tiene Windows Server 2008 R2
            indice = msrc._cargar_indice(conn)
            self.assertEqual(indice.candidatos("6.1.7601"), [(P_SRV2008, "Windows Server 2008 R2 for x64-based Systems Service Pack 1")])
            self.assertIsNone(indice.producto_de(act_viejo := {"so_nombre": "Windows 7 Professional", "so_version": "6.1.7601", "arquitectura": "x86 32 bit"}))
            self.assertEqual(indice.producto_de({**act_viejo, "so_nombre": "Windows Server 2008 R2 Standard"}), P_SRV2008)
            self.assertEqual(indice.producto_de({"so_nombre": "Windows 10 Pro", "so_version": "10.0.19045", "arquitectura": "x86 32 bit"}), P_W10_32)
            act = {r["nombre"]: dict(r) for r in conn.execute("SELECT * FROM activos")}
            self.assertEqual(act["pc-uno"]["windows_build"], "10.0.26200.9106")
            self.assertEqual(act["pc-uno"]["windows_kb"], "KB5120994")
            self.assertEqual(act["pc-uno"]["windows_kb_publicado"], "2026-08-11T07:00:00Z")
            self.assertEqual(act["pc-tres"]["windows_build"], "10.0.26200.8000")
            self.assertEqual(act["pc-cuatro"]["windows_build"], "10.0.26200.9168")   # KB reedición, vía catálogo
            self.assertEqual(act["srv-uno"]["windows_build"], "10.0.20348.5440")
            self.assertIsNone(act["pc-dos"]["windows_build"])
            self.assertIsNotNone(act["pc-dos"]["windows_evaluado_at"])
            self.assertIsNone(act["pc-viejo"]["windows_build"])
            self.assertIsNotNone(act["pc-viejo"]["windows_evaluado_at"])
            self.assertEqual(act["pc-32"]["windows_build"], "10.0.19045.6500")
            self.assertIsNone(act["srv-linux"]["windows_evaluado_at"])

            def filas(nombre):
                return {r["cve"]: dict(r) for r in conn.execute(
                    "SELECT * FROM aplicabilidad WHERE motor='msrc' AND activo_id=?", (self.ids["activo"][nombre],))}
            uno = filas("pc-uno")
            self.assertEqual(uno["CVE-2026-0001"]["veredicto"], "no_afectado")
            self.assertIn("Corregido por la actualización KB5120994", uno["CVE-2026-0001"]["evidencia"])
            self.assertEqual(uno["CVE-2026-0002"]["veredicto"], "afectado")
            self.assertIn("Falta la actualización acumulativa KB5121003 publicada el 11 de agosto de 2026", uno["CVE-2026-0002"]["evidencia"])
            self.assertIn("compilación instalada 10.0.26200.9106, corregida en 10.0.26200.9168", uno["CVE-2026-0002"]["evidencia"])
            self.assertEqual(uno["CVE-2026-0002"]["aviso"], "KB5121003")
            self.assertEqual(uno["CVE-2026-0002"]["paquete"], "windows")
            self.assertEqual(uno["CVE-2026-0002"]["version_instalada"], "10.0.26200.9106")
            self.assertEqual(uno["CVE-2026-0002"]["version_corregida"], "10.0.26200.9168")
            self.assertEqual(uno["CVE-2026-0005"]["veredicto"], "no_afectado")
            self.assertNotIn("CVE-2026-0003", uno)          # solo Windows Server
            self.assertNotIn("CVE-2026-0004", uno)          # solo Office
            self.assertNotIn("CVE-2026-0006", uno)          # amenaza descartada
            dos = filas("pc-dos")
            self.assertEqual({f["veredicto"] for f in dos.values()}, {"sin_dato"})
            self.assertIn("no tiene ninguna actualización acumulativa reconocida", dos["CVE-2026-0001"]["evidencia"])
            tres = filas("pc-tres")
            self.assertEqual((tres["CVE-2026-0001"]["veredicto"], tres["CVE-2026-0005"]["veredicto"]), ("afectado", "no_afectado"))
            cuatro = filas("pc-cuatro")
            self.assertEqual({f["veredicto"] for f in cuatro.values()}, {"no_afectado"})
            srv = filas("srv-uno")
            self.assertEqual((srv["CVE-2026-0001"]["veredicto"], srv["CVE-2026-0003"]["veredicto"], srv["CVE-2026-0005"]["veredicto"]),
                             ("no_afectado", "afectado", "no_afectado"))
            self.assertEqual(filas("pc-viejo"), {})
            self.assertEqual(filas("srv-linux"), {})
            self.assertEqual({c: f["veredicto"] for c, f in filas("pc-32").items()}, {"CVE-2026-0003": "no_afectado"})
            # la fila del otro motor (paquete distinto) sigue intacta
            otra = conn.execute("SELECT * FROM aplicabilidad WHERE motor='version' AND activo_id=?", (self.ids["activo"]["pc-uno"],)).fetchone()
            self.assertEqual((otra["paquete"], otra["veredicto"], otra["evaluado_at"]), ("google chrome", "afectado", "2026-09-01T00:00:00.000000Z"))
            # resumen por amenaza: coherente con aplicabilidad (un activo cuenta una vez; afectado manda)
            aa = {r["threat_id"]: dict(r) for r in conn.execute("SELECT * FROM aplicabilidad_amenaza")}
            t1 = aa[self.ids["amenaza"]["CVE-2026-0001"]]
            # pc-uno afectado por Chrome, pc-tres afectado por KB, pc-cuatro y srv-uno no afectados, pc-dos sin dato
            self.assertEqual((t1["afectados"], t1["no_afectados"], t1["sin_dato"]), (2, 2, 1))
            self.assertEqual(t1["parche_disponible"], 1)
            detalle = json.loads(t1["detalle"])
            self.assertTrue(any(ln.startswith("Boletín de seguridad de Microsoft") for ln in detalle["lineas"]))
            t3 = aa[self.ids["amenaza"]["CVE-2026-0003"]]
            self.assertEqual((t3["afectados"], t3["no_afectados"], t3["afectados_expuestos"]), (1, 1, 1))   # srv-uno en producción; pc-32 corregido
            # la fila nueva de una amenaza reciente lleva la marca que hace que el motor principal la evalúe
            # en su próxima pasada; la de una amenaza antigua (fuera de la ventana de recogida) lleva la fecha real
            self.assertEqual(t1["evaluado_at"], msrc.MARCA_PENDIENTE)
            self.assertEqual(aa[self.ids["amenaza"]["CVE-2026-0005"]]["evaluado_at"], "2026-09-05T10:00:00.000001Z")
            self.assertNotIn(self.ids["amenaza"]["CVE-2026-0004"], aa)
            self.assertNotIn(self.ids["amenaza"]["CVE-2026-0006"], aa)
            self.assertEqual(ev["afectados"], 4)   # pc-uno 0002, pc-tres 0001 y 0002, srv-uno 0003
            self.assertEqual(ap.MOTOR_ES["msrc"], "Boletín de seguridad de Microsoft (MSRC)")
            # idempotencia: segunda ejecución, mismas filas y recuentos
            total = conn.execute("SELECT COUNT(*) FROM aplicabilidad").fetchone()[0]
            ev2 = msrc.evaluar_activos(conn, cfg=self.cfg, ahora="2026-09-05T11:00:00.000001Z")
            self.assertEqual(ev2["filas"], ev["filas"])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM aplicabilidad").fetchone()[0], total)
            aa2 = {r["threat_id"]: dict(r) for r in conn.execute("SELECT * FROM aplicabilidad_amenaza")}
            self.assertEqual({k: (v["afectados"], v["no_afectados"], v["sin_dato"], v["evaluado_at"]) for k, v in aa2.items()},
                             {k: (v["afectados"], v["no_afectados"], v["sin_dato"], v["evaluado_at"]) for k, v in aa.items()})
            # el equipo instala la KB de agosto: el veredicto cambia y la fila antigua no se duplica
            conn.execute("INSERT INTO activo_software(activo_id, nombre, nombre_norm, version) VALUES(?, 'Security Update KB5121003', 'security update kb5121003', '')",
                         (self.ids["activo"]["pc-tres"],))
            msrc.evaluar_activos(conn, cfg=self.cfg, solo_activo=self.ids["activo"]["pc-tres"], ahora="2026-09-05T12:00:00.000001Z")
            tres = filas("pc-tres")
            self.assertEqual({f["veredicto"] for f in tres.values()}, {"no_afectado"})
            self.assertEqual(conn.execute("SELECT windows_build FROM activos WHERE nombre='pc-tres'").fetchone()[0], "10.0.26200.9168")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM aplicabilidad").fetchone()[0], total)
            t1 = conn.execute("SELECT * FROM aplicabilidad_amenaza WHERE threat_id=?", (self.ids["amenaza"]["CVE-2026-0001"],)).fetchone()
            self.assertEqual((t1["afectados"], t1["no_afectados"], t1["sin_dato"]), (1, 3, 1))
        finally:
            conn.close()

    def test_activo_que_pierde_su_producto_limpia_sus_filas(self):
        conn = db.connect(self.ruta)
        try:
            self._actualizar(conn)
            msrc.evaluar_activos(conn, cfg=self.cfg, ahora="2026-09-05T10:00:00.000001Z")
            uno = self.ids["activo"]["pc-uno"]
            t2 = self.ids["amenaza"]["CVE-2026-0002"]
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM aplicabilidad WHERE motor='msrc' AND activo_id=?", (uno,)).fetchone()[0], 3)
            antes = conn.execute("SELECT afectados, no_afectados, sin_dato FROM aplicabilidad_amenaza WHERE threat_id=?", (t2,)).fetchone()
            self.assertEqual(tuple(antes), (2, 1, 1))       # pc-uno y pc-tres afectados, pc-cuatro corregido, pc-dos sin dato
            # OCS deja de informar de la versión: ya no hay producto MSRC y los veredictos antiguos no valen
            conn.execute("UPDATE activos SET so_version='' WHERE id=?", (uno,))
            conn.commit()
            ev = msrc.evaluar_activos(conn, cfg=self.cfg, solo_activo=uno, ahora="2026-09-05T11:00:00.000001Z")
            self.assertEqual((ev["sin_producto"], ev["filas"]), (1, 0))
            a = conn.execute("SELECT windows_build, windows_kb, windows_evaluado_at FROM activos WHERE id=?", (uno,)).fetchone()
            self.assertEqual((a["windows_build"], a["windows_kb"], a["windows_evaluado_at"]), (None, None, "2026-09-05T11:00:00.000001Z"))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM aplicabilidad WHERE motor='msrc' AND activo_id=?", (uno,)).fetchone()[0], 0)
            # la fila del otro motor sigue y los recuentos por amenaza se han recalculado
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM aplicabilidad WHERE motor='version' AND activo_id=?", (uno,)).fetchone()[0], 1)
            despues = conn.execute("SELECT afectados, no_afectados, sin_dato FROM aplicabilidad_amenaza WHERE threat_id=?", (t2,)).fetchone()
            self.assertEqual(tuple(despues), (1, 1, 1))
            r = msrc.resumen_activo(conn, dict(conn.execute("SELECT * FROM activos WHERE id=?", (uno,)).fetchone()))
            self.assertIsNone(r["producto"])
            self.assertEqual((r["n_afectados"], r["n_corregidos"], r["n_sin_dato"]), (0, 0, 0))
            # los demás equipos no se han tocado
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM aplicabilidad WHERE motor='msrc' AND activo_id=?",
                                          (self.ids["activo"]["pc-tres"],)).fetchone()[0], 3)
        finally:
            conn.close()

    def test_resumen_activo_y_global(self):
        conn = db.connect(self.ruta)
        try:
            act = {r["nombre"]: dict(r) for r in conn.execute("SELECT * FROM activos")}
            # sin boletines descargados
            r = msrc.resumen_activo(conn, act["pc-uno"])
            self.assertTrue(r["aplica"])
            self.assertFalse(r["hay_boletines"])
            self.assertIn("Todavía no se han descargado", r["explicacion"])
            self.assertEqual(msrc.resumen_activo(conn, act["srv-linux"]), {"aplica": False})
            self._actualizar(conn)
            msrc.evaluar_activos(conn, cfg=self.cfg)
            act = {r["nombre"]: dict(r) for r in conn.execute("SELECT * FROM activos")}
            uno = msrc.resumen_activo(conn, act["pc-uno"])
            self.assertEqual(uno["producto"], "Windows 11 Version 25H2 for x64-based Systems")
            self.assertEqual((uno["build"], uno["kb"], uno["ultima_build"], uno["ultima_kb"]),
                             ("10.0.26200.9106", "KB5120994", "10.0.26200.9168", "KB5121003"))
            self.assertFalse(uno["al_dia"])
            self.assertEqual(uno["meses_atraso"], 0)
            self.assertIn("ese mismo mes otra posterior", uno["explicacion"])
            self.assertEqual((uno["n_afectados"], uno["n_corregidos"], uno["n_sin_dato"]), (1, 2, 0))
            tres = msrc.resumen_activo(conn, act["pc-tres"])
            self.assertEqual(tres["meses_atraso"], 1)
            self.assertIn("actualización de julio de 2026 (KB5110000)", tres["explicacion"])
            self.assertIn("otra en agosto de 2026 (KB5121003): le falta 1 mes de parches", tres["explicacion"])
            cuatro = msrc.resumen_activo(conn, act["pc-cuatro"])
            self.assertTrue(cuatro["al_dia"])
            self.assertEqual(cuatro["meses_atraso"], 0)
            self.assertIn("está al día", cuatro["explicacion"])
            dos = msrc.resumen_activo(conn, act["pc-dos"])
            self.assertIsNone(dos["build"])
            self.assertIsNone(dos["meses_atraso"])
            self.assertIsNone(dos["al_dia"])
            self.assertIn("OCS no informa de ninguna actualización acumulativa reconocida", dos["explicacion"])
            self.assertEqual(dos["n_sin_dato"], 3)
            self.assertEqual(dos["kbs_instaladas"], 1)     # la KB de Office no cuenta para Windows
            viejo = msrc.resumen_activo(conn, act["pc-viejo"])
            self.assertIsNone(viejo["producto"])
            self.assertIn("no publica correcciones para la compilación 6.1.7601", viejo["explicacion"])
            viejo_html = msrc.resumen_activo(conn, act["pc-viejo"])
            self.assertNotIn("Server 2008", viejo_html["explicacion"])      # no se le asigna el producto de servidor
            treinta = msrc.resumen_activo(conn, act["pc-32"])
            self.assertEqual(treinta["producto"], "Windows 10 Version 22H2 for 32-bit Systems")
            self.assertTrue(treinta["al_dia"])
            g = msrc.resumen(conn)
            self.assertEqual(g, {"activos_windows": 7, "al_dia": 2, "atrasados": 3, "sin_dato": 2,
                                 "documentos": 2, "ultimo_boletin": "2026-Aug"})
        finally:
            conn.close()

    def test_plantilla_en_la_ficha_del_activo(self):
        conn = db.connect(self.ruta)
        try:
            self._actualizar(conn)
            msrc.evaluar_activos(conn, cfg=self.cfg)
        finally:
            conn.close()
        from webui import auth
        from webui.app import crear_app
        with db.session(self.ruta) as conn:
            auth.crear_usuario(conn, "admin", "AdminSeguro#2026", rol="admin", actor="t")
        app = crear_app(db_path=self.ruta, testing=True)
        cli = app.test_client()
        cli.post("/login", data={"usuario": "admin", "password": "AdminSeguro#2026"})
        r = cli.get(f"/activos/{self.ids['activo']['pc-uno']}")
        html = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(RE_STYLE.search(html))
        self.assertIsNone(RE_ON.search(html))
        for texto in ("Actualizaciones de Windows", "10.0.26200.9106", "KB5120994", "KB5121003", "Compilación instalada",
                      "Última publicada por Microsoft", "Atraso de parches", "ese mismo mes otra posterior",
                      # Paso 6 del recorrido desde el 2026-09-09: la ficha del activo se
                      # renumeró para que el orden del recorrido coincida con el orden
                      # visual de la página (este panel va entre «Veredictos» y «Amenazas
                      # evaluadas»). Antes era el 10 y el recorrido saltaba hacia atrás.
                      'data-tour="6"', "Boletín de seguridad de Microsoft (MSRC)"):
            self.assertIn(texto, html)
        parcial = (BASE_DIR / "webui" / "templates" / "_windows_parches.html").read_text(encoding="utf-8")
        self.assertRegex(parcial, r'<div class="panel"[^>]*data-tour="6"[^>]*data-tour-titulo="[^"]+"[^>]*data-tour-texto="[^"]{41,}"')
        self.assertNotRegex(parcial, r'<div class="panel-(cabecera|cuerpo)[^"]*" data-tour=')
        # atraso de un mes: insignia media; sin dato: insignia neutra; al día: insignia ok
        html3 = cli.get(f"/activos/{self.ids['activo']['pc-tres']}").get_data(as_text=True)
        self.assertIn('<span class="insignia medium">1 mes</span>', html3)
        html2 = cli.get(f"/activos/{self.ids['activo']['pc-dos']}").get_data(as_text=True)
        self.assertIn('<span class="insignia neutra">Sin dato</span>', html2)
        self.assertIn("OCS no informa de ninguna actualización acumulativa reconocida", html2)
        html4 = cli.get(f"/activos/{self.ids['activo']['pc-cuatro']}").get_data(as_text=True)
        self.assertIn('<span class="insignia ok">Al día</span>', html4)
        # un activo que no es Windows no lleva el panel
        html_linux = cli.get(f"/activos/{self.ids['activo']['srv-linux']}").get_data(as_text=True)
        self.assertNotIn("Actualizaciones de Windows", html_linux)


if __name__ == "__main__":
    unittest.main()
