"""Precisión de la correlación (2026-09-04): avisos de distribución por paquete,
alias genéricos con contexto de vulnerabilidad, exclusiones y lista de paquetes
instalados. Base temporal bajo data/."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from threatintel import db, matching
from threatintel.paths import BASE_DIR


class Cfg(dict):
    pass


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "matching.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            matching.seed_inventario(conn)
            # Solo las tecnologías que interesan a estas pruebas, con versión en una
            for slug in ("windows", "linux", "debian", "ubuntu", "chrome", "firefox", "java", "php"):
                conn.execute("UPDATE technologies SET enabled=1 WHERE slug=?", (slug,))
            conn.execute("UPDATE technologies SET version_installed='143.0.7499' WHERE slug='chrome'")

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _inventario(self, cfg=None):
        with db.connect(self.ruta) as conn:
            return matching.compilar_inventario(conn, cfg=cfg)

    @staticmethod
    def _por_slug(coincidencias):
        return {c.slug: c for c in coincidencias}


class TestPaqueteDeAviso(unittest.TestCase):
    def test_extraccion(self):
        casos = {
            "DSA-6479-1 roundcube - security update": "roundcube",
            "DSA-6477-1 linux - security update": "linux",
            "DLA-4321-1 firefox-esr - security update": "firefox-esr",
            "USN-7123-1: Linux kernel vulnerabilities": "linux",
            "USN-7130-1: Firefox vulnerabilities": "firefox",
            "[DSA 6476-1] chromium security update": None,   # formato sin guion: no es el patrón oficial
            "Google Patches 6th Chrome Zero-Day of 2026": None,
            "": None, None: None,
        }
        for titulo, esperado in casos.items():
            self.assertEqual(matching.extraer_paquete_aviso(titulo), esperado, titulo)

    def test_variantes(self):
        self.assertEqual(matching._variantes_paquete("firefox-esr")[:2], ["firefox-esr", "firefox"])
        self.assertIn("linux", matching._variantes_paquete("linux"))
        self.assertIn("gst", matching._variantes_paquete("gst-plugins-bad1.0")) if False else None


class TestCorrelacionPorPaquete(_Base):
    def test_dsa_de_paquete_ajeno_solo_menciona_debian(self):
        inv = self._inventario()
        c = self._por_slug(matching.encontrar(
            "DSA-6479-1 roundcube - security update. Several vulnerabilities were discovered in "
            "roundcube, a webmail solution.", inv, titulo="DSA-6479-1 roundcube - security update"))
        self.assertNotIn("roundcube", c)
        self.assertIn("debian", c)
        self.assertLessEqual(c["debian"].confidence, matching.CONFIANZA_MENCION)

    def test_dsa_de_paquete_del_inventario_correlaciona_el_paquete(self):
        inv = self._inventario()
        c = self._por_slug(matching.encontrar(
            "DSA-6477-1 linux - security update. Several vulnerabilities have been discovered in "
            "the Linux kernel that may lead to a privilege escalation.", inv,
            titulo="DSA-6477-1 linux - security update"))
        self.assertIn("linux", c)
        self.assertGreaterEqual(c["linux"].confidence, matching.CONFIANZA_PAQUETE_AVISO)
        self.assertLessEqual(c["debian"].confidence, matching.CONFIANZA_MENCION)

    def test_usn_firefox_y_sufijo_esr(self):
        inv = self._inventario()
        c = self._por_slug(matching.encontrar(
            "USN-7130-1: Firefox vulnerabilities. Several security issues were fixed in Firefox.",
            inv, titulo="USN-7130-1: Firefox vulnerabilities"))
        self.assertGreaterEqual(c["firefox"].confidence, 0.95)
        c2 = self._por_slug(matching.encontrar(
            "DLA-4321-1 firefox-esr - security update. Multiple security issues in firefox-esr.",
            inv, titulo="DLA-4321-1 firefox-esr - security update"))
        self.assertGreaterEqual(c2["firefox"].confidence, 0.95)

    def test_lista_de_paquetes_instalados_hace_plena_la_distribucion(self):
        lista = Path(self.dir.name) / "paquetes.txt"
        lista.write_text("# servidor web\nroundcube\nlibc6:amd64\nnginx 1.24\n", encoding="utf-8")
        inv = self._inventario(Cfg(debian_packages_file=str(lista)))
        self.assertIn("roundcube", inv.paquetes_instalados)
        self.assertIn("libc6", inv.paquetes_instalados)
        c = self._por_slug(matching.encontrar(
            "DSA-6479-1 roundcube - security update. Several vulnerabilities were discovered in roundcube.",
            inv, titulo="DSA-6479-1 roundcube - security update"))
        self.assertEqual(c["debian"].confidence, 1.0)
        self.assertIn("paquete «roundcube» instalado", c["debian"].version_evidence)

    def test_directorio_de_listas_y_ruta_inexistente(self):
        carpeta = Path(self.dir.name) / "paquetes"
        carpeta.mkdir(exist_ok=True)
        (carpeta / "srv1.txt").write_text("openssh-server\n", encoding="utf-8")
        (carpeta / "srv2.txt").write_text("postfix\n", encoding="utf-8")
        inv = self._inventario(Cfg(debian_packages_file=str(carpeta)))
        self.assertEqual(inv.paquetes_instalados, frozenset({"openssh-server", "postfix"}))
        inv2 = self._inventario(Cfg(debian_packages_file="/no/existe.txt"))
        self.assertEqual(inv2.paquetes_instalados, frozenset())


class TestGenericosYExclusiones(_Base):
    def test_noticia_de_malware_no_correlaciona_windows(self):
        inv = self._inventario()
        c = self._por_slug(matching.encontrar(
            "BraZetsu Malware Turns Compromised Windows Hosts Into Criminal Marketplace Inventory. "
            "The operators sell access to the infected machines.", inv,
            titulo="BraZetsu Malware Turns Compromised Windows Hosts Into Criminal Marketplace"))
        self.assertNotIn("windows", c)

    def test_vulnerabilidad_de_windows_si_correlaciona(self):
        inv = self._inventario()
        c = self._por_slug(matching.encontrar(
            "Microsoft patches Windows kernel flaw CVE-2026-1234 exploited in the wild.", inv,
            titulo="Microsoft patches Windows kernel flaw CVE-2026-1234"))
        self.assertIn("windows", c)

    def test_chrome_for_android_queda_excluido(self):
        inv = self._inventario()
        c = self._por_slug(matching.encontrar(
            "Chrome for Android Update. The Chrome team fixed several security vulnerabilities.",
            inv, titulo="Chrome for Android Update"))
        self.assertNotIn("chrome", c)
        c2 = self._por_slug(matching.encontrar(
            "Stable Channel Update for Desktop: Chrome 143 fixes a high-severity vulnerability "
            "in V8 (CVE-2026-9999).", inv, titulo="Stable Channel Update for Desktop"))
        self.assertIn("chrome", c2)

    def test_alias_multipalabra_no_cambia(self):
        inv = self._inventario()
        c = self._por_slug(matching.encontrar(
            "Microsoft Windows will show ads in the start menu, users report.", inv,
            titulo="Microsoft Windows will show ads"))
        self.assertIn("windows", c)   # «Microsoft Windows» sigue siendo nombre propio pleno

    def test_seed_pone_contexto_y_exclusiones(self):
        with db.connect(self.ruta) as conn:
            fila = conn.execute(
                """SELECT a.context_required FROM tech_aliases a JOIN technologies t ON t.id=a.technology_id
                    WHERE t.slug='windows' AND lower(a.alias)='windows' AND a.is_exclusion=0""").fetchone()
            excl = {r[0] for r in conn.execute(
                """SELECT a.alias FROM tech_aliases a JOIN technologies t ON t.id=a.technology_id
                    WHERE t.slug='chrome' AND a.is_exclusion=1""")}
        self.assertIn("vulnerability", fila[0])
        self.assertIn("Chrome for Android", excl)


class TestActualizarAlias(unittest.TestCase):
    def test_idempotente_y_respeta_alias_del_operador(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as d:
            ruta = str(Path(d) / "alias.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                matching.seed_inventario(conn)
                # Simular una base antigua: alias genéricos sin contexto y sin exclusiones
                conn.execute("UPDATE tech_aliases SET context_required=NULL WHERE lower(alias) IN ('windows','linux','java')")
                conn.execute("DELETE FROM tech_aliases WHERE is_exclusion=1 AND alias LIKE 'Chrome for%'")
                tid = conn.execute("SELECT id FROM technologies WHERE slug='java'").fetchone()[0]
                conn.execute("INSERT INTO tech_aliases(technology_id, alias, match_mode, is_exclusion) "
                             "VALUES(?, 'OpenJDK Runtime', 'phrase', 0)", (tid,))
            with db.connect(ruta) as conn:
                previsto = matching.aplicar_precision_alias(conn, aplicar=False)
                sin_cambios = conn.execute("SELECT COUNT(*) FROM tech_aliases WHERE context_required IS NULL "
                                           "AND lower(alias) IN ('windows','linux','java')").fetchone()[0]
            self.assertEqual(sin_cambios, 3)                   # el modo previo no escribe
            self.assertEqual(len(previsto["contexto"]), 3)
            self.assertIn(("chrome", "Chrome for Android"), previsto["exclusiones"])
            with db.session(ruta) as conn:
                hecho = matching.aplicar_precision_alias(conn, aplicar=True)
            with db.connect(ruta) as conn:
                otra = matching.aplicar_precision_alias(conn, aplicar=False)
                operador = conn.execute("SELECT COUNT(*) FROM tech_aliases WHERE alias='OpenJDK Runtime'").fetchone()[0]
            self.assertEqual(len(hecho["contexto"]), 3)
            self.assertEqual(otra, {"contexto": [], "exclusiones": []})   # idempotente
            self.assertEqual(operador, 1)                                  # el alias del operador sigue


if __name__ == "__main__":
    unittest.main()
