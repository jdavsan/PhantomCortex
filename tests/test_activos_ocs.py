"""Activos reales (OCS Inventory) y aplicabilidad por activo (2026-09-04).

Sin red ni MariaDB: el lector de OCS se simula con listas y las respuestas de
OSV.dev, VuXML y endoflife.date con funciones ``fetch`` falsas. Base temporal
bajo data/.

Cubre: comparación de versiones dpkg y pkg, normalización del sistema operativo,
sincronización (altas, cambios, desaparecidos, hash), mapa de nombres,
inventario alimentado por OCS, hallazgos de política, registros OSV (Ubuntu con
binarios y Debian con fuente), índice VuXML (puertos y sistema base), fin de
soporte, evaluación de una amenaza, consulta manual «¿le aplica este CVE?» y el
efecto en la relevancia.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from threatintel import aplicabilidad as ap
from threatintel import db, ocs, scoring
from threatintel import versiones_distro as vd
from threatintel.http import FetchResult, JsonResult
from threatintel.paths import BASE_DIR

AHORA = datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


class LectorFalso:
    def __init__(self, hardware, software):
        self._hw = hardware
        self._sw = software

    def hardware(self):
        return list(self._hw)

    def software(self):
        return iter(sorted(self._sw, key=lambda f: f[0]))


HW = [
    {"ID": 1, "DEVICEID": "SRV1", "NAME": "srv-web-01", "OSNAME": "Ubuntu 22.04", "OSVERSION": "22.04",
     "OSCOMMENTS": "Ubuntu 22.04.5 LTS", "IPADDR": "10.1.1.10", "LASTCOME": AHORA, "LASTDATE": AHORA,
     "USERID": None, "ARCH": "x86_64", "WORKGROUP": "ejemplo.local", "DESCRIPTION": "web"},
    {"ID": 2, "DEVICEID": "SRV2", "NAME": "srv-db-01", "OSNAME": "Debian GNU/Linux 12", "OSVERSION": "12",
     "OSCOMMENTS": None, "IPADDR": "10.0.5.20", "LASTCOME": AHORA, "LASTDATE": AHORA - timedelta(days=45),
     "USERID": None, "ARCH": None, "WORKGROUP": None, "DESCRIPTION": None},
    {"ID": 3, "DEVICEID": "SRV3", "NAME": "srv-bsd-01", "OSNAME": "FreeBSD amd64", "OSVERSION": "14.4-RELEASE-p6",
     "OSCOMMENTS": "GENERIC", "IPADDR": "10.1.1.30", "LASTCOME": AHORA, "LASTDATE": AHORA,
     "USERID": None, "ARCH": None, "WORKGROUP": None, "DESCRIPTION": None},
    {"ID": 4, "DEVICEID": "PC4", "NAME": "pc-ana", "OSNAME": "Microsoft Windows 7 Professional",
     "OSVERSION": "6.1.7601", "OSCOMMENTS": None, "IPADDR": "10.1.0.40", "LASTCOME": AHORA, "LASTDATE": AHORA,
     "USERID": "ana", "ARCH": "x86 64 bit", "WORKGROUP": None, "DESCRIPTION": None},
]
SW = [
    (1, "curl", "7.81.0-1ubuntu1.10", "https://curl.se/"),
    (1, "libcurl4:amd64", "7.81.0-1ubuntu1.10", "https://curl.se/"),
    (1, "apache2", "2.4.52-1ubuntu4.10", "Unavailable"),
    (1, "google-chrome-stable", "150.0.7000.1-1", None),
    (2, "curl", "7.88.1-10+deb12u12", None),
    (2, "libcurl4", "7.88.1-10+deb12u5", None),
    (2, "postgresql-15", "15.10-0+deb12u1", None),
    (3, "curl", "8.11.1_1", "Unavailable"),
    (3, "nginx-full", "1.30.4_7,3", "Unavailable"),
    (4, "Google Chrome", "150.0.7000.1", "Google LLC"),
    (4, "TightVNC", "2.8.81", "GlavSoft"),
    (4, "Java 7 Update 80", "7.0.800", "Oracle"),
]

REGISTRO_UBUNTU = {
    "id": "UBUNTU-CVE-2024-11053", "upstream": ["CVE-2024-11053"], "related": ["USN-7162-1"],
    "affected": [
        {"package": {"name": "curl", "ecosystem": "Ubuntu:22.04:LTS"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "7.81.0-1ubuntu1.20"}]}],
         "ecosystem_specific": {"binaries": [
             {"binary_name": "curl", "binary_version": "7.81.0-1ubuntu1.20"},
             {"binary_name": "libcurl4", "binary_version": "7.81.0-1ubuntu1.20"}]}},
        {"package": {"name": "curl", "ecosystem": "Ubuntu:Pro:18.04:LTS"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "7.58.0-2ubuntu3.24+esm10"}]}],
         "ecosystem_specific": {"binaries": [{"binary_name": "curl", "binary_version": "x"}]}},
    ],
    "references": [{"url": "https://ubuntu.com/security/notices/USN-7162-1"}],
}
REGISTRO_DEBIAN = {
    "id": "DEBIAN-CVE-2024-11053", "upstream": ["CVE-2024-11053"],
    "affected": [
        {"package": {"name": "curl", "ecosystem": "Debian:12"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "7.88.1-10+deb12u10"}]}],
         "ecosystem_specific": {"urgency": "not yet assigned"}},
        {"package": {"name": "curl", "ecosystem": "Debian:13"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "8.11.1-1"}]}]},
    ],
}
VUXML = """<?xml version="1.0"?><vuxml>
  <vuln vid="aaa"><topic>curl -- netrc leak</topic>
    <affects><package><name>curl</name><range><lt>8.11.1_2</lt></range></package></affects>
    <references><cvename>CVE-2024-11053</cvename></references></vuln>
  <vuln vid="bbb"><topic>FreeBSD -- kernel race</topic>
    <affects><package><name>FreeBSD-kernel</name><range><ge>14.4</ge><lt>14.4_9</lt></range>
      <range><ge>15.0</ge><lt>15.0_13</lt></range></package></affects>
    <references><cvename>CVE-2026-58094</cvename><freebsdsa>SA-26:63.posixshm</freebsdsa></references></vuln>
  <vuln vid="ccc"><topic>nginx -- njs overflow</topic>
    <affects><package><name>njs</name><range><lt>1.0.1</lt></range></package>
      <package><name>nginx-full</name><range><lt>1.30.4_7,3</lt></range></package></affects>
    <references><cvename>CVE-2026-78689</cvename></references></vuln>
  <vuln vid="ddd"><cancelled/><topic>cancelada</topic><references><cvename>CVE-2026-1</cvename></references></vuln>
</vuxml>"""
EOL = {
    "ubuntu": [{"cycle": "22.04", "codename": "Jammy", "eol": "2027-06-01", "latest": "22.04.5", "lts": True,
                "extendedSupport": "2032-04-09"}],
    "debian": [{"cycle": "12", "codename": "Bookworm", "eol": "2026-07-11", "latest": "12.15", "lts": False,
                "extendedSupport": "2028-06-30"},
               {"cycle": "11", "codename": "Bullseye", "eol": "2024-08-14", "extendedSupport": "2026-08-31"}],
    "freebsd": [{"cycle": "14.4", "releaseLabel": "releng/14.4", "eol": "2026-12-31", "lts": False}],
    "windows": [{"cycle": "7-sp1", "releaseLabel": "7 SP1", "eol": "2020-01-14", "latest": "6.1.7601"},
                {"cycle": "11-25h2-w", "releaseLabel": "11 25H2 (W)", "eol": "2027-10-12", "latest": "10.0.26200"}],
    "windows-server": [{"cycle": "2022", "eol": "2031-10-14", "latest": "10.0.20348"}],
}


def fetch_json_falso(url, **kw):
    if "osv.dev" in url:
        if url.endswith("UBUNTU-CVE-2024-11053"):
            return JsonResult(True, 200, REGISTRO_UBUNTU, None, 10)
        if url.endswith("DEBIAN-CVE-2024-11053"):
            return JsonResult(True, 200, REGISTRO_DEBIAN, None, 10)
        return JsonResult(False, 404, None, "http_404", 10)
    if "endoflife.date" in url:
        producto = url.rsplit("/", 1)[-1].replace(".json", "")
        return JsonResult(True, 200, EOL.get(producto, []), None, 10)
    return JsonResult(False, 500, None, "conexion", 10)


def fetch_falso(url, **kw):
    return FetchResult(True, 200, VUXML.encode("utf-8"), None, 10, url, content_type="text/xml")


class Cfg(dict):
    def get(self, k, d=None):
        return super().get(k, d)


class TestVersionesDistro(unittest.TestCase):
    def test_dpkg(self):
        self.assertLess(vd.comparar_dpkg("8.5.0-2ubuntu10.13", "8.5.0-2ubuntu10.16"), 0)
        self.assertGreater(vd.comparar_dpkg("1:9.6p1-3ubuntu13.19", "1:9.6p1-3ubuntu13.9"), 0)
        self.assertGreater(vd.comparar_dpkg("7.88.1-10+deb12u10", "7.88.1-10+deb12u5"), 0)
        self.assertLess(vd.comparar_dpkg("1.0~rc1", "1.0"), 0)
        self.assertEqual(vd.comparar_dpkg("1.0", "1.0"), 0)
        self.assertLess(vd.comparar_dpkg("2.2.1-0ubuntu1~24.04.3", "2.2.1-0ubuntu1"), 0)
        self.assertGreater(vd.comparar_dpkg("1:1.0", "2.0"), 0)        # la época manda
        self.assertEqual(vd.version_upstream("1:9.6p1-3ubuntu13.19"), "9.6p1")

    def test_pkg_freebsd(self):
        self.assertLess(vd.comparar_pkg("14.4_6", "14.4_9"), 0)
        self.assertLess(vd.comparar_pkg("15.0", "15.0_13"), 0)
        self.assertGreater(vd.comparar_pkg("15.1_3", "15.0_13"), 0)
        self.assertLess(vd.comparar_pkg("8.11.1_1", "8.12.0"), 0)
        self.assertGreater(vd.comparar_pkg("9.9.p2_1,1", "9.8.p1,1"), 0)
        self.assertLess(vd.comparar_pkg("1.30.4_7,3", "1.30.4_8,3"), 0)
        self.assertEqual(vd.version_base_freebsd("14.4-RELEASE-p6"), "14.4_6")
        self.assertEqual(vd.version_base_freebsd("15.0-RELEASE"), "15.0")
        self.assertIsNone(vd.version_base_freebsd("garbage"))
        self.assertTrue(vd.en_rango_pkg("14.4_6", {"ge": "14.4", "lt": "14.4_9"}))
        self.assertFalse(vd.en_rango_pkg("14.4_9", {"ge": "14.4", "lt": "14.4_9"}))
        self.assertFalse(vd.en_rango_pkg("14.4_9", {}))


class TestNormalizacionOCS(unittest.TestCase):
    def test_sistemas_operativos(self):
        u = ocs.normalizar_so("Ubuntu 24.04", "24.04", "Ubuntu 24.04.3 LTS")
        self.assertEqual((u["familia"], u["ciclo"], u["ecosistema"], u["version"]),
                         ("ubuntu", "24.04", "Ubuntu:24.04", "24.04.3 LTS"))
        d = ocs.normalizar_so("Debian GNU/Linux 13.5", "13.5", None)
        self.assertEqual((d["familia"], d["ciclo"], d["ecosistema"]), ("debian", "13", "Debian:13"))
        pve = ocs.normalizar_so("Debian GNU/Linux 10.4", "5.4.34-1-pve", None)
        self.assertEqual((pve["ciclo"], pve["version"]), ("10", "10.4"))
        f = ocs.normalizar_so("FreeBSD amd64", "14.4-RELEASE-p6", "GENERIC")
        self.assertEqual((f["familia"], f["ciclo"], f["ecosistema"]), ("freebsd", "14.4", None))
        w = ocs.normalizar_so("Microsoft Windows 11 Pro", "10.0.26200", None)
        self.assertEqual((w["familia"], w["ciclo"], w["edicion"], w["nombre_es"]),
                         ("windows", "11-25h2", "w", "Windows 11 Pro"))
        s = ocs.normalizar_so("Microsoft Windows Server 2022 Standard", "10.0.20348", None)
        self.assertEqual((s["ciclo"], s["edicion"]), ("2022", "server"))
        self.assertEqual(ocs.normalizar_so(None, None, None)["familia"], "desconocido")

    def test_nombres_y_fuentes(self):
        self.assertEqual(ocs.normalizar_nombre("libcurl4t64:amd64"), "libcurl4t64")
        self.assertEqual(ocs.normalizar_nombre("Google  Chrome "), "google chrome")
        self.assertEqual(ocs.paquete_fuente("libcurl4t64")[0], "curl")
        self.assertIn("linux", ocs.paquete_fuente("linux-image-6.8.0-138-generic"))
        self.assertIn("php8.2", ocs.paquete_fuente("php8.2-cli"))
        self.assertEqual(ocs.paquete_fuente("apache2", reglas={"apache2": "apache2"})[0], "apache2")

    def test_zona_por_cidr(self):
        self.assertEqual(ocs._zona_de("10.1.1.21/10.0.0.21", [], ["10.0.0.0/24"]), "dmz")
        self.assertEqual(ocs._zona_de("10.1.1.21", ["10.1.1.0/24"], []), "internet")
        self.assertEqual(ocs._zona_de("sin ip", ["10.1.1.0/24"], []), "interna")


class TestSincronizacionYMotor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "activos.db")
        db.init_db(cls.ruta)
        cls.cfg = Cfg(ocs_dmz_networks=["10.0.5.0/24"], ocs_stale_days=30, alert_min_match_confidence=0.6,
                      applicability_max_osv_per_run=50, osv_cache_hours=168, vuxml_cache_hours=24,
                      eol_cache_hours=168, collect_lookback_days=45, applicability_reevaluate_days=7,
                      applicability_max_threats_per_run=50, ocs_risk_software=["tightvnc", "java 7"],
                      ocs_edr_pattern="sophos", ocs_update_inventory=True)
        with db.session(cls.ruta) as conn:
            ahora = db.utcnow()
            for slug, name, cat in (("chrome", "Google Chrome", "navegador"), ("apache-httpd", "Apache HTTP Server", "servidor-web"),
                                    ("openssl", "OpenSSL", "criptografia"), ("freebsd", "FreeBSD", "sistema-operativo"),
                                    ("postgresql", "PostgreSQL", "base-de-datos")):
                conn.execute("""INSERT INTO technologies(slug,name,vendor,category,criticality,systems_count,exposure,enabled,
                                created_at,updated_at) VALUES(?,?,'x',?,'high',0,'interna',1,?,?)""",
                             (slug, name, cat, ahora, ahora))
            cls.tid_chrome = conn.execute("SELECT id FROM technologies WHERE slug='chrome'").fetchone()[0]
            conn.execute("""INSERT INTO threats(fingerprint,cve,title_en,summary_en,severity,severity_source,first_seen_at,
                            last_seen_at,month,relevance,estado) VALUES('fp-curl','CVE-2024-11053','curl netrc leak',
                            'curl before 8.11.1 leaks credentials','High','nvd',?,?,?,20.0,'nueva')""",
                         (ahora, ahora, ahora[:7]))
            conn.execute("""INSERT INTO threats(fingerprint,cve,title_en,summary_en,severity,severity_source,first_seen_at,
                            last_seen_at,month,relevance,estado) VALUES('fp-chrome','CVE-2026-9999','Google Chrome type confusion',
                            'Google Chrome prior to 152.0.7632.45 allows remote code execution','Critical','nvd',?,?,?,55.0,'nueva')""",
                         (ahora, ahora, ahora[:7]))
            conn.execute("""INSERT INTO threats(fingerprint,cve,title_en,summary_en,severity,severity_source,first_seen_at,
                            last_seen_at,month,relevance,estado) VALUES('fp-bsd','CVE-2026-58094','FreeBSD kernel race',
                            'FreeBSD 14.4 kernel race condition','High','nvd',?,?,?,40.0,'nueva')""",
                         (ahora, ahora, ahora[:7]))
            cls.id_curl = conn.execute("SELECT id FROM threats WHERE fingerprint='fp-curl'").fetchone()[0]
            cls.id_chrome = conn.execute("SELECT id FROM threats WHERE fingerprint='fp-chrome'").fetchone()[0]
            cls.id_bsd = conn.execute("SELECT id FROM threats WHERE fingerprint='fp-bsd'").fetchone()[0]
            conn.execute("INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,confidence,version_verdict) "
                         "VALUES(?,?,'google chrome',1.0,'unknown')", (cls.id_chrome, cls.tid_chrome))

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_01_sincronizacion_completa(self):
        conn = db.connect(self.ruta)
        try:
            r = ocs.sincronizar_origen(conn, "servidores", LectorFalso(HW[:3], [s for s in SW if s[0] <= 3]), cfg=self.cfg)
            self.assertIsNone(r["error"])
            self.assertEqual((r["activos"], r["nuevos"], r["software"]), (3, 3, 9))
            r2 = ocs.sincronizar_origen(conn, "equipos", LectorFalso(HW[3:], [s for s in SW if s[0] == 4]), cfg=self.cfg)
            self.assertEqual((r2["activos"], r2["nuevos"]), (1, 1))
            filas = {r["nombre"]: dict(r) for r in conn.execute("SELECT * FROM activos")}
            self.assertEqual(filas["srv-web-01"]["ecosistema"], "Ubuntu:22.04")
            self.assertEqual(filas["srv-db-01"]["zona"], "dmz")
            self.assertEqual(filas["srv-bsd-01"]["so_ciclo"], "14.4")
            self.assertEqual(filas["pc-ana"]["so_ciclo"], "7-sp1")
            self.assertEqual(conn.execute("SELECT nombre_norm FROM activo_software WHERE nombre='libcurl4:amd64'").fetchone()[0],
                             "libcurl4")
            self.assertIsNone(conn.execute("SELECT fabricante FROM activo_software WHERE nombre='apache2'").fetchone()[0])
            # Segunda pasada sin cambios: nada se reescribe; un cambio de versión sí
            r3 = ocs.sincronizar_origen(conn, "servidores", LectorFalso(HW[:3], [s for s in SW if s[0] <= 3]), cfg=self.cfg)
            self.assertEqual((r3["nuevos"], r3["cambiados"], r3["sin_cambios"]), (0, 0, 3))
            sw_mod = [(1, "curl", "7.81.0-1ubuntu1.20", None)] + [s for s in SW if s[0] in (2, 3)]
            r4 = ocs.sincronizar_origen(conn, "servidores", LectorFalso(HW[:2], sw_mod), cfg=self.cfg)
            self.assertEqual((r4["cambiados"], r4["desaparecidos"]), (1, 1))
            self.assertEqual(conn.execute("SELECT presente FROM activos WHERE nombre='srv-bsd-01'").fetchone()[0], 0)
            # Se restaura el estado completo para las demás pruebas
            ocs.sincronizar_origen(conn, "servidores", LectorFalso(HW[:3], [s for s in SW if s[0] <= 3]), cfg=self.cfg)
            self.assertEqual(conn.execute("SELECT presente FROM activos WHERE nombre='srv-bsd-01'").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM sync_ocs WHERE status='success'").fetchone()[0], 5)
        finally:
            conn.close()

    def test_02_mapa_inventario_y_hallazgos(self):
        conn = db.connect(self.ruta)
        try:
            creadas = ocs.sembrar_mapa(conn)
            self.assertGreater(creadas, 5)
            self.assertEqual(ocs.sembrar_mapa(conn), 0)          # idempotente
            r = ocs.aplicar_mapa(conn, respaldo=False)
            self.assertGreaterEqual(r["nombres_mapeados"], 3)
            tec = {row["nombre_norm"]: row["technology_id"] for row in conn.execute(
                "SELECT DISTINCT nombre_norm, technology_id FROM activo_software WHERE technology_id IS NOT NULL")}
            self.assertEqual(tec["google chrome"], self.tid_chrome)
            self.assertEqual(tec["google-chrome-stable"], self.tid_chrome)
            self.assertIn("apache2", tec)
            self.assertIn("postgresql-15", tec)
            propuestas = ocs.proponer_mapa(conn, limite=20)
            nombres = {p["nombre_norm"] for p in propuestas}
            self.assertIn("curl", nombres)
            # Clasificación de respaldo: nada queda sin tecnología; los paquetes de Debian/Ubuntu y
            # FreeBSD van a su tecnología de respaldo y los programas de Windows a una propia
            r2 = ocs.aplicar_mapa(conn)
            self.assertEqual(r2["instalaciones_mapeadas"], r2["instalaciones"])
            slug_de = {row["nombre_norm"]: row["slug"] for row in conn.execute(
                "SELECT DISTINCT s.nombre_norm, t.slug FROM activo_software s JOIN technologies t ON t.id=s.technology_id")}
            self.assertEqual(slug_de["curl"], "paquetes-debian-ubuntu")   # curl esta en Ubuntu, Debian y FreeBSD: gana la mayoria
            self.assertEqual(slug_de["nginx-full"], "puertos-freebsd")
            self.assertEqual(slug_de["tightvnc"], "tightvnc")             # programa de Windows -> tecnologia propia
            self.assertTrue(conn.execute("SELECT 1 FROM tecnologia_ocs WHERE origen='automatico' AND patron='tightvnc'").fetchone())
            # una regla manual manda sobre la automática
            ocs.retirar_automaticas(conn, "tightvnc", "exacto")
            conn.execute("INSERT INTO tecnologia_ocs(patron, modo, technology_id, origen, created_at) VALUES('tightvnc','exacto',?,'manual',?)",
                         (self.tid_chrome, db.utcnow()))
            ocs.aplicar_mapa(conn)
            self.assertEqual(conn.execute("SELECT technology_id FROM activo_software WHERE nombre_norm='tightvnc'").fetchone()[0], self.tid_chrome)
            conn.execute("DELETE FROM tecnologia_ocs WHERE patron='tightvnc' AND origen='manual'")
            ocs.aplicar_mapa(conn)
            ocs.actualizar_inventario_desde_ocs(conn, cfg=self.cfg)
            chrome = conn.execute("SELECT systems_count, version_installed, activos_ocs, versiones_ocs FROM technologies WHERE id=?",
                                  (self.tid_chrome,)).fetchone()
            self.assertEqual((chrome["systems_count"], chrome["activos_ocs"]), (2, 2))
            self.assertEqual(chrome["version_installed"], "150.0.7000.1")
            self.assertEqual(len(json.loads(chrome["versiones_ocs"])), 2)
            h = ocs.detectar_hallazgos(conn, cfg=self.cfg)
            self.assertEqual(h["sin_reportar"]["abiertos"], 1)          # srv-db-01 lleva 45 días
            self.assertEqual(h["software_riesgo"]["abiertos"], 2)       # TightVNC y Java 7 en pc-ana
            self.assertEqual(h["sin_edr"]["abiertos"], 1)               # pc-ana sin Sophos
            h2 = ocs.detectar_hallazgos(conn, cfg=self.cfg)
            self.assertEqual((h2["software_riesgo"]["nuevos"], h2["software_riesgo"]["cerrados"]), (0, 0))
            res = ocs.resumen(conn, cfg=self.cfg)
            self.assertEqual((res["total"], res["servidores"], res["equipos"], res["sin_reportar"]), (4, 3, 1, 1))
            self.assertGreater(res["pct_mapeado"], 0)
        finally:
            conn.close()

    def test_03_osv_afectaciones_y_dpkg(self):
        afect = ap.afectaciones(REGISTRO_UBUNTU, "Ubuntu:22.04")
        self.assertEqual(len(afect), 1)
        self.assertEqual(afect[0]["binarios"]["libcurl4"], "7.81.0-1ubuntu1.20")
        self.assertEqual(ap.afectaciones(REGISTRO_UBUNTU, "Ubuntu:24.04"), [])
        self.assertEqual(ap.ecosistemas_afectados(REGISTRO_DEBIAN), ["Debian:12", "Debian:13"])
        self.assertEqual(ap.avisos_de(REGISTRO_UBUNTU), ["USN-7162-1"])
        r = ap.evaluar_dpkg(afect, "libcurl4", "7.81.0-1ubuntu1.10", ["curl", "libcurl4"])
        self.assertEqual((r["veredicto"], r["version_corregida"]), (ap.AFECTADO, "7.81.0-1ubuntu1.20"))
        r = ap.evaluar_dpkg(afect, "curl", "7.81.0-1ubuntu1.20", ["curl"])
        self.assertEqual(r["veredicto"], ap.NO_AFECTADO)
        self.assertIsNone(ap.evaluar_dpkg(afect, "libcurl3-gnutls", "1", ["curl"]))   # Ubuntu lista binarios: no está
        deb = ap.afectaciones(REGISTRO_DEBIAN, "Debian:12")
        r = ap.evaluar_dpkg(deb, "libcurl4", "7.88.1-10+deb12u5", ocs.paquete_fuente("libcurl4"))
        self.assertEqual(r["veredicto"], ap.AFECTADO)
        r = ap.evaluar_dpkg(deb, "curl", "7.88.1-10+deb12u12", ["curl"])
        self.assertEqual(r["veredicto"], ap.NO_AFECTADO)
        sin_fix = [{"fuente": "curl", "corregidas": [], "binarios": {}}]
        self.assertIsNone(ap.evaluar_dpkg(sin_fix, "curl", "1", ["curl"])["version_corregida"])
        self.assertEqual(ap.evaluar_dpkg(sin_fix, "curl", "1", ["curl"])["veredicto"], ap.AFECTADO)

    def test_04_vuxml(self):
        idx = ap.IndiceVuXML(VUXML)
        self.assertEqual(len(idx), 3)                     # la cancelada no cuenta
        self.assertEqual(idx.paquetes_de("CVE-2026-78689"), {"njs", "nginx-full"})
        r = idx.evaluar("CVE-2024-11053", "curl", "8.11.1_1")
        self.assertEqual(r["veredicto"], ap.AFECTADO)
        self.assertEqual(idx.evaluar("CVE-2024-11053", "curl", "8.11.1_2")["veredicto"], ap.NO_AFECTADO)
        base = idx.evaluar("CVE-2026-58094", "freebsd-kernel", "14.4_6")
        self.assertEqual((base["veredicto"], base["aviso"]), (ap.AFECTADO, "FreeBSD-SA-26:63.posixshm"))
        self.assertEqual(idx.evaluar("CVE-2026-58094", "freebsd-kernel", "14.4_9")["veredicto"], ap.NO_AFECTADO)
        self.assertEqual(idx.evaluar("CVE-2026-58094", "freebsd-kernel", "14.3_2")["veredicto"], ap.NO_AFECTADO)
        self.assertEqual(idx.evaluar("CVE-2026-78689", "nginx-full", "1.30.4_7,3")["veredicto"], ap.NO_AFECTADO)
        self.assertIsNone(idx.evaluar("CVE-2026-78689", "curl", "1"))

    def test_05_fin_de_soporte(self):
        conn = db.connect(self.ruta)
        try:
            r = ap.actualizar_fin_soporte(conn, cfg=self.cfg, forzar=True, fetch=fetch_json_falso)
            self.assertEqual(set(r["actualizados"]), set(ap.PRODUCTOS_EOL))
            tabla = ap.tabla_fin_soporte(conn)
            hoy = date(2026, 9, 4)
            win7 = ap.estado_soporte(tabla, {"so_familia": "windows", "so_ciclo": "7-sp1",
                                             "so_nombre": "Windows 7 Professional"}, hoy=hoy)
            self.assertTrue(win7["fuera"])
            deb12 = ap.estado_soporte(tabla, {"so_familia": "debian", "so_ciclo": "12", "so_nombre": "Debian 12"}, hoy=hoy)
            self.assertFalse(deb12["fuera"])                      # Debian LTS gratis hasta 2028-06-30
            self.assertEqual(deb12["eol"], "2028-06-30")
            deb11 = ap.estado_soporte(tabla, {"so_familia": "debian", "so_ciclo": "11", "so_nombre": "Debian 11"}, hoy=hoy)
            self.assertTrue(deb11["fuera"])                       # su LTS acabó el 2026-08-31
            u22 = ap.estado_soporte(tabla, {"so_familia": "ubuntu", "so_ciclo": "22.04", "so_nombre": "Ubuntu 22.04"}, hoy=hoy)
            self.assertEqual(u22["eol"], "2027-06-01")            # el extendido de Ubuntu (Pro) no cuenta
            w11 = ap.estado_soporte(tabla, {"so_familia": "windows", "so_ciclo": "11-25h2",
                                            "so_nombre": "Windows 11 Pro"}, hoy=hoy)
            self.assertEqual((w11["ciclo"], w11["fuera"]), ("11-25h2-w", False))
            self.assertIsNone(ap.estado_soporte(tabla, {"so_familia": "centos", "so_ciclo": "7"}, hoy=hoy))
            h = ap.hallazgos_fin_soporte(conn, hoy=hoy)
            self.assertEqual(h["abiertos"], 1)                    # pc-ana (Windows 7); Debian 12 sigue en LTS
        finally:
            conn.close()

    def test_06_evaluar_amenaza_y_relevancia(self):
        conn = db.connect(self.ruta)
        try:
            osv = ap.ClienteOSV(conn, cfg=self.cfg, fetch=fetch_json_falso)
            vuxml = ap.IndiceVuXML(VUXML)
            amenaza = dict(conn.execute("SELECT * FROM threats WHERE id=?", (self.id_curl,)).fetchone())
            r = ap.evaluar_amenaza(conn, amenaza, cfg=self.cfg, osv=osv, vuxml=vuxml)
            # Ubuntu: curl y libcurl4 afectados en srv-web-01; Debian: libcurl4 afectado, curl corregido;
            # FreeBSD: curl 8.11.1_1 afectado
            self.assertEqual(r["afectados"], 3)
            self.assertEqual(r["errores"], [])
            self.assertEqual(osv.peticiones, 2)
            filas = {(f["activo_id"], f["paquete"]): dict(f) for f in conn.execute(
                "SELECT * FROM aplicabilidad WHERE threat_id=?", (self.id_curl,))}
            web = conn.execute("SELECT id FROM activos WHERE nombre='srv-web-01'").fetchone()[0]
            dbs = conn.execute("SELECT id FROM activos WHERE nombre='srv-db-01'").fetchone()[0]
            self.assertEqual(filas[(web, "libcurl4")]["veredicto"], ap.AFECTADO)
            self.assertEqual(filas[(web, "libcurl4")]["aviso"], "USN-7162-1")
            self.assertIn("Ubuntu 22.04", filas[(web, "curl")]["evidencia"])
            self.assertEqual(filas[(dbs, "curl")]["veredicto"], ap.NO_AFECTADO)
            self.assertEqual(filas[(dbs, "libcurl4")]["veredicto"], ap.AFECTADO)
            self.assertTrue(any(l.startswith("Ubuntu 22.04:") for l in r["detalle"]))
            # Segunda evaluación: todo desde la caché
            r2 = ap.evaluar_amenaza(conn, amenaza, cfg=self.cfg, osv=osv, vuxml=vuxml)
            self.assertEqual((osv.peticiones, r2["afectados"]), (2, 3))
            resumen = ap.activos_de_amenaza(conn, self.id_curl, limite=2)
            self.assertEqual((resumen["n_afectados"], len(resumen["afectados"]), resumen["mas"]), (3, 2, 1))
            # Amenaza de Chrome: comparación de versión con el texto del aviso (sin OSV)
            chrome = dict(conn.execute("SELECT * FROM threats WHERE id=?", (self.id_chrome,)).fetchone())
            rc = ap.evaluar_amenaza(conn, chrome, cfg=self.cfg, osv=osv, vuxml=vuxml)
            self.assertEqual(rc["afectados"], 2)                 # srv-web-01 (deb de Chrome) y pc-ana
            motores = {f[0] for f in conn.execute("SELECT DISTINCT motor FROM aplicabilidad WHERE threat_id=?", (self.id_chrome,))}
            self.assertEqual(motores, {"version"})
            # Con dos tecnologías (WordPress y PHP) el aviso no atribuye versiones: nada de motor 'version'
            tid_pg = conn.execute("SELECT id FROM technologies WHERE slug='postgresql'").fetchone()[0]
            conn.execute("INSERT INTO threat_technologies(threat_id,technology_id,matched_alias,confidence,version_verdict) "
                         "VALUES(?,?,'postgresql',0.9,'unknown')", (self.id_chrome, tid_pg))
            rc2 = ap.evaluar_amenaza(conn, chrome, cfg=self.cfg, osv=osv, vuxml=vuxml)
            self.assertEqual(rc2["afectados"], 0)
            self.assertTrue(any("nombra varias tecnologías" in l for l in rc2["detalle"]))
            conn.execute("DELETE FROM threat_technologies WHERE threat_id=? AND technology_id=?", (self.id_chrome, tid_pg))
            ap.evaluar_amenaza(conn, chrome, cfg=self.cfg, osv=osv, vuxml=vuxml)
            # Sistema base FreeBSD
            bsd = dict(conn.execute("SELECT * FROM threats WHERE id=?", (self.id_bsd,)).fetchone())
            rb = ap.evaluar_amenaza(conn, bsd, cfg=self.cfg, osv=osv, vuxml=vuxml)
            self.assertEqual(rb["afectados"], 1)
            fila = conn.execute("SELECT paquete, version_instalada, aviso FROM aplicabilidad WHERE threat_id=? AND veredicto='afectado'",
                                (self.id_bsd,)).fetchone()
            self.assertEqual((fila["paquete"], fila["version_instalada"]), ("freebsd-kernel", "14.4_6"))
            # Relevancia: sube con activos afectados
            from threatintel import enrich
            antes = conn.execute("SELECT relevance FROM threats WHERE id=?", (self.id_curl,)).fetchone()[0]
            enrich.recalcular_relevancia(conn, self.cfg, threat_ids=[self.id_curl])
            despues = conn.execute("SELECT relevance FROM threats WHERE id=?", (self.id_curl,)).fetchone()[0]
            self.assertGreater(despues, antes)
            self.assertGreater(scoring.relevancia(severity="High", cvss_score=8.0, activos={"afectados": 3}),
                               scoring.relevancia(severity="High", cvss_score=8.0))
            self.assertLess(scoring.relevancia(severity="High", cvss_score=8.0,
                                               activos={"afectados": 0, "no_afectados": 5, "sin_dato": 0}),
                            scoring.relevancia(severity="High", cvss_score=8.0))
            # evaluar_pendientes: las tres amenazas ya están evaluadas y frescas -> ninguna candidata
            stats = ap.evaluar_pendientes(conn, cfg=self.cfg, osv=osv, vuxml=vuxml)
            self.assertEqual(stats["candidatas"], 0)
            conn.execute("UPDATE aplicabilidad_amenaza SET evaluado_at=? WHERE threat_id=?",
                         (_iso(AHORA - timedelta(days=10)), self.id_curl))
            stats = ap.evaluar_pendientes(conn, cfg=self.cfg, osv=osv, vuxml=vuxml)
            self.assertEqual((stats["candidatas"], stats["evaluadas"], stats["con_afectados"]), (1, 1, 1))
        finally:
            conn.close()

    def test_07_cupo_osv_y_registro_inexistente(self):
        conn = db.connect(self.ruta)
        try:
            osv = ap.ClienteOSV(conn, cfg=self.cfg, max_peticiones=1, fetch=fetch_json_falso)
            self.assertIsNone(osv.registro("UBUNTU-CVE-2099-1"))           # 404 -> None y cacheado
            self.assertIsNone(osv.registro("UBUNTU-CVE-2099-1"))           # desde caché, sin petición
            self.assertEqual(osv.peticiones, 1)
            with self.assertRaises(ap.ErrorOSV):
                osv.registro("DEBIAN-CVE-2099-2")                          # cupo agotado y sin caché
            self.assertIsNotNone(osv.registro("UBUNTU-CVE-2024-11053"))    # caché aunque el cupo esté agotado
        finally:
            conn.close()

    def test_08_responder_cve(self):
        conn = db.connect(self.ruta)
        try:
            osv = ap.ClienteOSV(conn, cfg=self.cfg, fetch=fetch_json_falso)
            vuxml = ap.IndiceVuXML(VUXML)
            web = conn.execute("SELECT id FROM activos WHERE nombre='srv-web-01'").fetchone()[0]
            r = ap.responder_cve(conn, web, "cve-2024-11053", cfg=self.cfg, osv=osv, vuxml=vuxml)
            self.assertEqual(r["veredicto"], ap.AFECTADO)
            self.assertEqual({f["paquete"] for f in r["filas"]}, {"curl", "libcurl4"})
            self.assertEqual(r["amenaza"]["id"], self.id_curl)
            # CVE sin registro en OSV para Ubuntu y sin amenaza: sin dato
            r2 = ap.responder_cve(conn, web, "CVE-2099-0001", cfg=self.cfg, osv=osv, vuxml=vuxml)
            self.assertEqual(r2["veredicto"], ap.SIN_DATO)
            self.assertIsNone(r2["amenaza"])
            # FreeBSD: sistema base
            bsd = conn.execute("SELECT id FROM activos WHERE nombre='srv-bsd-01'").fetchone()[0]
            r3 = ap.responder_cve(conn, bsd, "CVE-2026-58094", cfg=self.cfg, osv=osv, vuxml=vuxml)
            self.assertEqual(r3["veredicto"], ap.AFECTADO)
            self.assertEqual(r3["filas"][0]["paquete"], "freebsd-kernel")
            # Debian 12 con un CVE que OSV solo registra para Debian 13: no la lista -> no afectado
            registro_solo_13 = {"id": "DEBIAN-CVE-2026-7777", "affected": [
                {"package": {"name": "curl", "ecosystem": "Debian:13"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "8.14.1-1"}]}]}]}

            def fetch_13(url, **kw):
                if url.endswith("DEBIAN-CVE-2026-7777"):
                    return JsonResult(True, 200, registro_solo_13, None, 5)
                return JsonResult(False, 404, None, "http_404", 5)
            dbs = conn.execute("SELECT id FROM activos WHERE nombre='srv-db-01'").fetchone()[0]
            r4 = ap.responder_cve(conn, dbs, "CVE-2026-7777", cfg=self.cfg,
                                  osv=ap.ClienteOSV(conn, cfg=self.cfg, fetch=fetch_13), vuxml=vuxml)
            self.assertEqual(r4["veredicto"], ap.NO_AFECTADO)
            self.assertTrue(any("no la lista" in l for l in r4["lineas"]))
            self.assertEqual(ap.responder_cve(conn, web, "no-es-cve", cfg=self.cfg, osv=osv)["veredicto"], ap.SIN_DATO)
            conteo = ap.conteo_activo(conn, web)
            self.assertGreaterEqual(conteo["afectado"], 1)
        finally:
            conn.close()

    def test_09_cargar_vuxml_con_cache(self):
        import threatintel.aplicabilidad as modulo
        cache = modulo.CACHE_VUXML
        original = modulo.CACHE_VUXML
        modulo.CACHE_VUXML = Path(self.dir.name) / "vuxml.xml"
        modulo._INDICE_VUXML = None
        try:
            idx = ap.cargar_vuxml(cfg=self.cfg, forzar=True, fetch=fetch_falso)
            self.assertEqual(len(idx), 3)
            self.assertTrue(modulo.CACHE_VUXML.exists())

            def fetch_roto(url, **kw):
                return FetchResult(False, None, None, "conexion", 5, url)
            idx2 = ap.cargar_vuxml(cfg=self.cfg, forzar=True, fetch=fetch_roto)   # usa la caché
            self.assertEqual(len(idx2), 3)
        finally:
            modulo.CACHE_VUXML = original
            modulo._INDICE_VUXML = None
            del cache


if __name__ == "__main__":
    unittest.main()
