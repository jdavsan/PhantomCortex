"""Traducción fiel de nombres de paquete y producto (2026-09-04).

`proteger`/`restaurar` son puros y se prueban siempre; la traducción real con
Argos se omite si el motor no está instalado."""
from __future__ import annotations

import unittest

from threatintel import translate


class Cfg(dict):
    pass


class TestProteccionDePaquetes(unittest.TestCase):
    def _protegidos(self, texto):
        _, mapa = translate.proteger(texto)
        return set(mapa.values())

    def test_identificador_con_paquete(self):
        self.assertIn("DSA-6476-1 chromium", self._protegidos("DSA-6476-1 chromium - security update"))
        self.assertIn("DLA-4321-1 firefox-esr", self._protegidos("DLA-4321-1 firefox-esr - security update"))
        self.assertIn("USN-7123-1: Linux", self._protegidos("USN-7123-1: Linux kernel vulnerabilities"))
        self.assertIn("RHSA-2026:1234 kernel", self._protegidos("RHSA-2026:1234 kernel security update"))
        # la palabra que sigue no es un paquete: se protege solo el identificador
        protegidos = self._protegidos("DSA-6480-1 security update for several packages")
        self.assertIn("DSA-6480-1", protegidos)
        self.assertFalse(any("security" in p for p in protegidos))

    def test_nombres_con_guion_o_digito(self):
        protegidos = self._protegidos(
            "Several vulnerabilities were discovered in webkit2gtk, libdbi-perl and gst-plugins-bad1.0.")
        for nombre in ("webkit2gtk", "libdbi-perl", "gst-plugins-bad1.0"):
            self.assertIn(nombre, protegidos, nombre)

    def test_palabra_entre_comillas(self):
        self.assertIn("roundcube", self._protegidos("The 'roundcube' package was updated."))
        self.assertIn("wire", self._protegidos('The "wire" messenger fixed a flaw.'))
        # una frase entre comillas no se protege
        self.assertNotIn("a long quoted sentence", self._protegidos('He said "a long quoted sentence" today.'))

    def test_lo_anterior_sigue_protegido_y_se_restaura(self):
        texto = "Patch Tuesday fixes CVE-2026-1234 in Google Chrome 143.0.7499 (CVSS 9.8)"
        protegido, mapa = translate.proteger(texto)
        self.assertNotIn("CVE-2026-1234", protegido)
        self.assertNotIn("143.0.7499", protegido)
        self.assertEqual(translate.restaurar(protegido, mapa), texto)


class TestPlantillasDeAviso(unittest.TestCase):
    def test_titulos_con_forma_fija(self):
        casos = {
            "DSA-6476-1 chromium - security update": "DSA-6476-1 chromium - actualización de seguridad",
            "DLA-4321-1 firefox-esr - security update": "DLA-4321-1 firefox-esr - actualización de seguridad",
            "USN-8724-1: rabbitmq-c vulnerabilities": "USN-8724-1: vulnerabilidades en rabbitmq-c",
            "USN-8720-1: GnuPG vulnerability": "USN-8720-1: vulnerabilidad en GnuPG",
            "USN-7123-1: Linux kernel vulnerabilities": "USN-7123-1: vulnerabilidades en Linux kernel",
            "USN-8700-2: OpenSSL regression": "USN-8700-2: regresión en OpenSSL",
            "Google Patches 6th Chrome Zero-Day of 2026": None,
        }
        for texto, esperado in casos.items():
            self.assertEqual(translate.traducir_aviso_plantilla(texto), esperado, texto)

    def test_traducir_usa_la_plantilla_sin_motor(self):
        salida, motor = translate.traducir("USN-8724-1: rabbitmq-c vulnerabilities",
                                           cfg=Cfg(translate_engine="argos"), conn=None)
        self.assertEqual((salida, motor), ("USN-8724-1: vulnerabilidades en rabbitmq-c", "plantilla"))


class TestArgosConPaquetes(unittest.TestCase):
    def setUp(self):
        if not translate.argos_disponible():
            self.skipTest("ArgosTranslate no disponible")
        self.cfg = Cfg(translate_engine="argos")

    def _traducir(self, texto):
        return translate.traducir(texto, cfg=self.cfg, conn=None, permitir_ollama=False)[0]

    def test_paquete_intacto(self):
        casos = {
            "DSA-6476-1 chromium - security update": ("chromium", "cromo"),
            "DSA-6472-1 bubblewrap - security update": ("bubblewrap", "burbujas"),
            "DSA-6471-1 wire - security update": ("wire", "Cable"),
            "DSA-6473-1 libdbi-perl - security update": ("libdbi-perl", None),
        }
        for texto, (debe, no_debe) in casos.items():
            traduccion = self._traducir(texto)
            self.assertIn(debe, traduccion, texto)
            if no_debe:
                self.assertNotIn(no_debe, traduccion, texto)
            self.assertIn("seguridad", traduccion.lower(), texto)   # el resto sí se traduce
            self.assertNotIn("ZPZ", traduccion)


if __name__ == "__main__":
    unittest.main()
