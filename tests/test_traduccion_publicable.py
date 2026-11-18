"""Lo que no está en español no se publica como si lo estuviera (2026-09-15).

La auditoría de claridad del 15 de septiembre de 2026 encontró que lo PRIMERO que se lee en
el correo diario, la tabla «Prioridad de actuación», traía titulares como «Linux Kernel TLS
Protocolo Out-Of-Bounds Información de divulgaci…», «Subsistema de uso después de la libre
escal…» o «Windows Error reportando Elevación de Privilege Vulnerability». Son tres defectos
distintos: inglés íntegro, traducción literal de un término técnico («use-after-free» →
«uso después de la compra») y mezcla a medio traducir.

Regla: más vale el título original en inglés, marcado como tal, que un español falso. Quien
lo lee sabe entonces que tiene que abrir la ficha, en vez de intentar entender una frase que
no significa nada.
"""

from __future__ import annotations

import unittest

from threatintel import translate


class TestQueSePublicaComoEspanol(unittest.TestCase):

    NO_PUBLICABLES = (
        "Linux Kernel TLS Protocol Out-Of-Bounds Information Disclosure Vulnerability",
        "Windows Error reportando Elevación de Privilege Vulnerability",
        "Windows Proveedores Credenciales Elevación de Vulnerabilidad Privilege",
        "ksmbd: ipc: fijar el uso después de la compra en ipc msg send request",
        "Subsistema de uso después de la libre escalada de privilegios",
        "reemplazar hdr2 len con codificado duro",
        "Fuera de los límites escriba en ANGLE",
    )
    PUBLICABLES = (
        "Vulnerabilidades en el kernel de Linux que permiten la escalada de privilegios",
        "USN-8748-1: vulnerabilidades en el núcleo de Linux para NVIDIA",
        "Ejecución remota de código en el servidor de nombres de dominio",
        "Actualización de seguridad para PHP en Ubuntu 22.04",
        "Vulnerabilidad crítica en Microsoft Windows Media Foundation",
        "Escalada de privilegios en el subsistema de red del núcleo",
    )

    def test_no_se_publica_lo_que_sigue_en_ingles_o_no_significa_nada(self):
        for texto in self.NO_PUBLICABLES:
            with self.subTest(texto=texto):
                self.assertFalse(translate._sirve_como_traduccion(texto),
                                 "esto no se puede enviar como si fuera español")

    def test_una_traduccion_correcta_si_se_publica(self):
        for texto in self.PUBLICABLES:
            with self.subTest(texto=texto):
                self.assertTrue(translate._sirve_como_traduccion(texto),
                                "una traducción buena no puede quedar marcada como mala")

    def test_un_nombre_de_producto_suelto_no_descarta_la_traduccion(self):
        """«kernel», «service» o «code» aparecen en español técnico correcto."""
        self.assertTrue(translate._sirve_como_traduccion(
            "Actualización del kernel de Linux en Debian 13"))
        self.assertTrue(translate._sirve_como_traduccion(
            "Denegación de servicio en el kernel de Linux"))

    def test_dos_palabras_inglesas_seguidas_descartan(self):
        self.assertTrue(translate._hay_ingles_seguido("Elevation of Privilege en Windows"))
        self.assertFalse(translate._hay_ingles_seguido("Vulnerabilidad en el kernel de Linux"))

    def test_los_identificadores_de_aviso_no_se_traducen(self):
        """Un identificador partido en palabras deja de ser citable."""
        for identificador in ("RHSA-2026:1234", "SUSE-SU-2026:4032-1", "ZDI-26-701",
                              "LSN-0121-1", "KB5083769", "ADV260001", "MS17-010",
                              "FreeBSD-SA-26:01.openssl"):
            with self.subTest(identificador=identificador):
                protegido, mapa = translate.proteger(f"Aviso {identificador} para Linux")
                self.assertNotIn(identificador, protegido,
                                 "debería haberse sustituido por un marcador")
                self.assertIn(identificador, translate.restaurar(protegido, mapa))

    def test_la_marca_dice_que_no_esta_traducido(self):
        self.assertEqual(translate.MARCA_SIN_TRADUCIR, " (sin traducir)")
