"""Reglas de la habilidad ui-ux-pro-max aplicadas a la interfaz (2026-09-04):
tipografía alojada en local (CSP sin recursos externos), movimiento reducido,
objetivos táctiles mínimos, sin textos de 10 px y punto de ruptura estrecho."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

from threatintel.paths import BASE_DIR

CSS = (BASE_DIR / "webui" / "static" / "estilo.css").read_text(encoding="utf-8")
FUENTES = BASE_DIR / "webui" / "static" / "fonts"


class TestReglasDeInterfaz(unittest.TestCase):
    def test_fuentes_locales_declaradas_y_presentes(self):
        for fichero in ("fira-sans-400-latin.woff2", "fira-sans-500-latin.woff2",
                        "fira-sans-600-latin.woff2", "fira-code-400-latin.woff2"):
            self.assertTrue((FUENTES / fichero).exists(), fichero)
            self.assertGreater((FUENTES / fichero).stat().st_size, 5000, fichero)
            self.assertIn(f'url("fonts/{fichero}")', CSS)
        self.assertIn('--fuente: "Fira Sans"', CSS)
        self.assertIn('--mono: "Fira Code"', CSS)
        self.assertNotIn("fonts.googleapis.com", CSS)      # nada externo: la CSP lo bloquearía
        self.assertTrue((FUENTES / "LICENCIA.txt").exists())

    def test_movimiento_reducido_y_objetivos_minimos(self):
        self.assertIn("prefers-reduced-motion: reduce", CSS)
        self.assertRegex(CSS, r"\.btn \{[^}]*min-height: 34px")
        self.assertRegex(CSS, r"\.btn\.pequeno \{[^}]*min-height: 30px")
        self.assertIn("@media (max-width: 480px)", CSS)

    def test_sin_texto_de_diez_pixeles(self):
        self.assertEqual(len(re.findall(r"font-size:\s*10px", CSS)), 0)
        self.assertEqual(len(re.findall(r"font-size:\s*9px", CSS)), 0)

    def test_csp_permite_fuentes_propias_y_nada_externo(self):
        # Con una base TEMPORAL, nunca la de produccion: `crear_app` sin `db_path` llama a
        # `db.init_db()` sobre `data/threat_intel.db`, y esta prueba llego a MIGRAR la base
        # real al ejecutar la suite (detectado el 2026-09-10 con el esquema v13). Ninguna
        # prueba debe tocar produccion, aunque el cambio sea aditivo.
        import tempfile
        from pathlib import Path
        from webui.app import crear_app
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as carpeta:
            app = crear_app(db_path=str(Path(carpeta) / "interfaz.db"), testing=True)
            self._comprobar_csp(app)

    def _comprobar_csp(self, app):
        cli = app.test_client()
        csp = cli.get("/login").headers.get("Content-Security-Policy", "")
        self.assertIn("font-src 'self'", csp)
        self.assertNotIn("unsafe", csp)
        self.assertNotIn("googleapis", csp)
        fuente = cli.get("/static/fonts/fira-sans-400-latin.woff2")
        self.assertEqual(fuente.status_code, 200)


if __name__ == "__main__":
    unittest.main()
