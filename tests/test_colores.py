"""Pruebas de temas y colores personalizados.

Verifica la carga de paletas, validación de colores, y aplicación de temas.
"""
import json
import unittest
from unittest.mock import patch

from webui import colores


class TestPaletas(unittest.TestCase):
    """Prueba de carga y gestión de paletas."""

    def test_cargar_paletas_estructura(self):
        """Verifica que las paletas tengan la estructura esperada."""
        paletas = colores.cargar_paletas()
        self.assertIn("paletas", paletas)
        self.assertIsInstance(paletas["paletas"], dict)
        # Debe haber al menos las cuatro paletas documentadas
        for nombre in ["viva", "corporativa", "oscura", "pastel"]:
            self.assertIn(nombre, paletas["paletas"])

    def test_paleta_viva_completa(self):
        """Verifica que la paleta viva tenga temas claro y oscuro."""
        paletas = colores.cargar_paletas()
        viva = paletas["paletas"]["viva"]
        self.assertIn("claro", viva)
        self.assertIn("oscuro", viva)
        self.assertIn("nombre", viva)
        self.assertIn("descripcion", viva)

    def test_obtener_paleta_existente(self):
        """Obtiene una paleta y tema válidos."""
        paleta = colores.obtener_paleta("viva", "claro")
        self.assertIsNotNone(paleta)
        self.assertIsInstance(paleta, dict)
        # Debe tener variables CSS
        self.assertTrue(any(k.startswith("--") for k in paleta.keys()))

    def test_obtener_paleta_inexistente(self):
        """Devuelve None para paleta que no existe."""
        paleta = colores.obtener_paleta("inexistente", "claro")
        self.assertIsNone(paleta)

    def test_obtener_paleta_tema_invalido(self):
        """Devuelve None si el tema no existe."""
        paleta = colores.obtener_paleta("viva", "invalido")
        self.assertIsNone(paleta)

    def test_listar_paletas_no_vacia(self):
        """La lista de paletas tiene al menos una."""
        lista = colores.listar_paletas()
        self.assertGreater(len(lista), 0)
        # Cada paleta tiene clave, nombre y descripción
        for p in lista:
            self.assertIn("clave", p)
            self.assertIn("nombre", p)
            self.assertIn("descripcion", p)


class TestValidacionColores(unittest.TestCase):
    """Prueba validación de colores hexadecimales."""

    def test_color_hexadecimal_valido_6_digitos(self):
        """Acepta colores en formato #RRGGBB."""
        self.assertTrue(colores.validar_color("#ff0000"))
        self.assertTrue(colores.validar_color("#00ff00"))
        self.assertTrue(colores.validar_color("#0000ff"))
        self.assertTrue(colores.validar_color("#123456"))

    def test_color_hexadecimal_valido_8_digitos(self):
        """Acepta colores con canal alfa #RRGGBBAA."""
        self.assertTrue(colores.validar_color("#ff0000ff"))
        self.assertTrue(colores.validar_color("#00ff0080"))

    def test_color_sin_hash(self):
        """Rechaza colores sin #."""
        self.assertFalse(colores.validar_color("ff0000"))
        self.assertFalse(colores.validar_color("123456"))

    def test_color_longitud_invalida(self):
        """Rechaza colores con longitud incorrecta."""
        self.assertFalse(colores.validar_color("#ff00"))  # Muy corto
        self.assertFalse(colores.validar_color("#ff00ff00ff"))  # Muy largo

    def test_color_no_hexadecimal(self):
        """Rechaza caracteres no hexadecimales."""
        self.assertFalse(colores.validar_color("#gggggg"))
        self.assertFalse(colores.validar_color("#zzzzzz"))
        self.assertFalse(colores.validar_color("#12345g"))

    def test_color_vacio(self):
        """Rechaza color vacío o None."""
        self.assertFalse(colores.validar_color(""))
        self.assertFalse(colores.validar_color(None))
        self.assertFalse(colores.validar_color("   "))

    def test_color_no_string(self):
        """Rechaza valores que no son strings."""
        self.assertFalse(colores.validar_color(123))
        self.assertFalse(colores.validar_color([]))
        self.assertFalse(colores.validar_color({}))

    def test_color_espacios_alrededor(self):
        """Acepta colores con espacios alrededor (tras trim)."""
        # La validación hace strip interno
        self.assertTrue(colores.validar_color("  #ff0000  "))


class TestConversionJSON(unittest.TestCase):
    """Prueba conversión de paletas a JSON para almacenamiento."""

    def test_convertir_paleta_valida_a_json(self):
        """Convierte una paleta válida a JSON."""
        json_str = colores.convertir_tema_paleta_json("viva", "claro")
        self.assertIsNotNone(json_str)
        self.assertGreater(len(json_str), 0)
        # Debe ser JSON válido
        datos = json.loads(json_str)
        self.assertIsInstance(datos, dict)
        # Debe tener variables CSS
        self.assertTrue(any(k.startswith("--") for k in datos.keys()))

    def test_convertir_paleta_invalida_a_json(self):
        """Devuelve JSON vacío para paleta inválida."""
        json_str = colores.convertir_tema_paleta_json("inexistente", "claro")
        self.assertEqual(json_str, "{}")

    def test_convertir_con_personalizaciones_validas(self):
        """Sobrescribe colores con personalizaciones válidas."""
        personalizaciones = {
            "--critico": "#ff5555",
            "--exito": "#55ff55"
        }
        json_str = colores.convertir_tema_paleta_json("viva", "claro",
                                                       personalizaciones)
        datos = json.loads(json_str)
        self.assertEqual(datos["--critico"], "#ff5555")
        self.assertEqual(datos["--exito"], "#55ff55")

    def test_convertir_ignora_personalizaciones_invalidas(self):
        """Ignora personalizaciones con color inválido."""
        personalizaciones = {
            "--critico": "#invalidcolor",  # Inválido
            "--exito": "#55ff55"  # Válido
        }
        json_str = colores.convertir_tema_paleta_json("viva", "claro",
                                                       personalizaciones)
        datos = json.loads(json_str)
        # La inválida no se sobrescribe
        self.assertNotEqual(datos.get("--critico"), "#invalidcolor")
        # La válida sí se sobrescribe
        self.assertEqual(datos["--exito"], "#55ff55")

    def test_convertir_ignora_variables_sin_prefijo(self):
        """Ignora personalizaciones que no empiezan con --."""
        personalizaciones = {
            "micolor": "#ff0000",  # Sin --
            "--exito": "#55ff55"  # Válido
        }
        json_str = colores.convertir_tema_paleta_json("viva", "claro",
                                                       personalizaciones)
        datos = json.loads(json_str)
        self.assertNotIn("micolor", datos)
        self.assertEqual(datos["--exito"], "#55ff55")


# NOTA: Los tests de endpoints requieren que el blueprint esté registrado en
# webui/app.py (fichero compartido que no podemos modificar como agente).
# Los endpoints se documentan en el informe final. Las pruebas aquí verifican
# la lógica de negocio (carga de paletas, validación, conversión a JSON).


if __name__ == "__main__":
    unittest.main()
