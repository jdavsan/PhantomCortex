"""Fuentes de tipo 'dataset' (OSV.dev, Debian Security Tracker, VuXML, CVE.org,
endoflife.date): se registran en el catálogo, se sondean con una lectura parcial
y no generan amenazas. Sin red: los sondeos usan destinos prohibidos o
respuestas simuladas."""
from __future__ import annotations

import unittest
from unittest import mock

from threatintel import http, sources


class TestTipoDataset(unittest.TestCase):
    def test_kind_registrado_y_url_de_sondeo(self):
        self.assertIn("dataset", sources.KINDS)
        self.assertEqual(sources.url_de_sondeo("https://api.osv.dev/v1/query"),
                         "https://api.osv.dev/v1/vulns/CVE-2024-3094")
        self.assertEqual(sources.url_de_sondeo("https://cveawg.mitre.org/api/cve/{cve}"),
                         "https://cveawg.mitre.org/api/cve/CVE-2024-3094")
        self.assertEqual(sources.url_de_sondeo("https://endoflife.date/api/{producto}.json"),
                         "https://endoflife.date/api/ubuntu.json")
        self.assertEqual(sources.url_de_sondeo("https://vuxml.freebsd.org/freebsd/vuln.xml"),
                         "https://vuxml.freebsd.org/freebsd/vuln.xml")

    def test_sondeo_rechaza_destinos_internos_sin_excepcion(self):
        res = sources.probar_url("http://127.0.0.1/datos.json", kind="dataset", timeout_s=3)
        self.assertFalse(res["ok"])
        self.assertEqual(res["entries"], 0)
        self.assertEqual(res["error"], "destino_prohibido")

    def test_sondeo_parcial_da_por_buena_una_respuesta_grande(self):
        grande = http.FetchResult(True, 200, b'{"389-ds-base": {"CVE-2012-0833": {}}}' + b" " * 100,
                                  None, 120, "https://security-tracker.debian.org/tracker/data/json",
                                  content_type="application/json")
        with mock.patch.object(http, "fetch_parcial", return_value=grande):
            res = sources.probar_url("https://security-tracker.debian.org/tracker/data/json",
                                     kind="dataset", timeout_s=5)
        self.assertTrue(res["ok"])
        self.assertEqual(res["entries"], 1)
        self.assertIn("application/json", res["muestra"][0])
        self.assertIn("389-ds-base", res["muestra"][0])

    def test_leer_acotado_parcial_devuelve_los_primeros_bytes(self):
        class Resp:
            headers = {"Content-Length": "5000000"}
            def iter_content(self, chunk_size):
                for _ in range(10):
                    yield b"x" * 1000
            def close(self):
                pass
        contenido, excedido = http._leer_acotado(Resp(), 2500, parcial=True)
        self.assertTrue(excedido)
        self.assertEqual(len(contenido), 2500)
        contenido2, excedido2 = http._leer_acotado(Resp(), 2500)
        self.assertTrue(excedido2)
        self.assertEqual(contenido2, b"")   # sin parcial, el tope se respeta como antes


if __name__ == "__main__":
    unittest.main()
