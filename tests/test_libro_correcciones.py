"""Libro aparte con las correcciones que ya están disponibles (2026-09-06).

El usuario lo pidió además del libro de vulnerabilidades: «se debe tener en cuenta también otro
archivo de Excel donde se mencione "Correcciones que ya están disponibles" con las que
aparecieron desde el envío anterior: paquete, versión que corrige, aviso, cuántos días
estuvieron en espera y cuántos equipos afectan, para tener un mejor control y visual»."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openpyxl import load_workbook

from threatintel import libro_alerta
from threatintel.paths import BASE_DIR

CORRECCIONES = [
    {"cve": "CVE-2026-15534", "titulo": "Lectura fuera de límites en Perl",
     "severidad": "Medium", "paquete": "libperl5.36", "sistema": "Debian 12",
     "version_corregida": "5.36.0-7+deb12u3", "aviso": "DLA-4801-1", "dias_en_espera": 12,
     "n_activos": 120, "n_activos_expuestos": 41,
     "motivo_es": "El aviso de seguridad no indicaba en qué versión se corregía"},
    {"cve": "CVE-2025-15661", "titulo": "Desbordamiento en libssh2",
     "severidad": "High", "paquete": "libssh2-1", "sistema": "Debian 13",
     "version_corregida": "1.11.1-1+deb13u1", "aviso": "DSA-5901-1", "dias_en_espera": 3,
     "n_activos": 293, "n_activos_expuestos": 210,
     "motivo_es": "La distribución todavía no había empaquetado la corrección"},
]


class TestLibroDeCorrecciones(unittest.TestCase):
    def test_sin_correcciones_no_se_genera_nada(self):
        """Un día sin novedades no adjunta un libro vacío al correo."""
        self.assertIsNone(libro_alerta.generar_correcciones(None, []))
        self.assertIsNone(libro_alerta.generar_correcciones(None, None, meta={"parches_nuevos": []}))

    def test_contenido_y_totales(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            ruta = Path(tmp) / "correcciones.xlsx"
            devuelta = libro_alerta.generar_correcciones(None, CORRECCIONES, destino=ruta)
            self.assertEqual(devuelta, ruta)
            hoja = load_workbook(ruta).active
            self.assertEqual(hoja.title, "Correcciones disponibles")
            self.assertIn("Correcciones que ya están disponibles", hoja.cell(row=1, column=1).value)
            self.assertIn("2", str(hoja.cell(row=2, column=1).value))   # el total en el subtítulo
            cabeceras = [hoja.cell(row=4, column=c).value for c in range(1, 12)]
            for esperada in ("Paquete", "Versión que corrige", "Aviso", "Días en espera",
                             "Activos afectados", "Por qué no existía la corrección"):
                self.assertIn(esperada, cabeceras)
            # Primera fila de datos
            fila = {cabeceras[c - 1]: hoja.cell(row=5, column=c).value for c in range(1, 12)}
            self.assertEqual(fila["Paquete"], "libperl5.36")
            self.assertEqual(fila["Versión que corrige"], "5.36.0-7+deb12u3")
            self.assertEqual(fila["Aviso"], "DLA-4801-1")
            self.assertEqual(fila["Días en espera"], 12)
            self.assertEqual(fila["Activos afectados"], 120)
            self.assertEqual(fila["Severidad"], "Media", "la severidad se escribe en español")
            # Fila de totales
            self.assertEqual(hoja.cell(row=7, column=1).value, "Total")
            self.assertEqual(hoja.cell(row=7, column=9).value, 413)
            self.assertEqual(hoja.cell(row=7, column=10).value, 251)
            self.assertEqual(hoja.freeze_panes, "A5")
            self.assertTrue(hoja.auto_filter.ref)

    def test_el_texto_de_una_fuente_nunca_se_evalua_como_formula(self):
        """Un título que empiece por «=» se guarda íntegro pero marcado como texto, para que
        ninguna hoja de cálculo lo ejecute al abrir el libro (el dato se conserva tal cual)."""
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            ruta = Path(tmp) / "raro.xlsx"
            libro_alerta.generar_correcciones(None, [dict(
                CORRECCIONES[0], titulo="=HYPERLINK(\"http://malo\",\"pulse\")", cve="+CVE-1", aviso="@aviso")],
                destino=ruta)
            hoja = load_workbook(ruta).active
            for columna in (1, 2, 7):
                celda = hoja.cell(row=5, column=columna)
                self.assertEqual(celda.data_type, "s", f"columna {columna} debe ser texto")
                self.assertTrue(celda.quotePrefix, f"columna {columna} sin prefijo de comilla")
                self.assertTrue(str(celda.value))   # el contenido no se pierde

    def test_los_datos_pueden_venir_incompletos(self):
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as tmp:
            ruta = Path(tmp) / "parcial.xlsx"
            self.assertIsNotNone(libro_alerta.generar_correcciones(
                None, [{"cve": "CVE-2026-1"}], destino=ruta))
            hoja = load_workbook(ruta).active
            self.assertEqual(hoja.cell(row=5, column=8).value, 0)


if __name__ == "__main__":
    unittest.main()
