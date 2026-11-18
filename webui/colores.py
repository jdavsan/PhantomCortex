"""Gestión de temas y paletas personalizadas de color.

Paletas preconfiguradas y aplicación dinámica de colores personalizados
por usuario. Los colores se almacenan como JSON en las preferencias de sesión
del cliente, sin modificar la base de datos (almacenamiento local del navegador).

La aplicación dinámica se hace en JavaScript (app.js) inyectando variables CSS.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


def cargar_paletas() -> dict:
    """Carga el archivo de paletas preconfiguradas.

    Devuelve un diccionario con estructura:
    {
        "paletas": {
            "viva": {"nombre": str, "descripcion": str, "claro": {...}, "oscuro": {...}},
            ...
        }
    }
    """
    ruta = Path(__file__).parent / "paletas.json"
    if not ruta.exists():
        return {"paletas": {}}
    with open(ruta, "r", encoding="utf-8") as f:
        return json.load(f)


def obtener_paleta(nombre: str, tema: str = "claro") -> Optional[dict[str, str]]:
    """Obtiene una paleta preconfigurada y un tema específico.

    Args:
        nombre: Clave de la paleta (ej. "viva", "corporativa")
        tema: "claro" u "oscuro"

    Returns:
        Diccionario de tokens CSS {--variable: color} o None si no existe.
    """
    paletas = cargar_paletas()
    if nombre not in paletas.get("paletas", {}):
        return None
    paleta = paletas["paletas"][nombre]
    return paleta.get(tema)


def listar_paletas() -> list[dict]:
    """Lista todas las paletas disponibles.

    Devuelve una lista de dicts con nombre, clave y descripción.
    """
    paletas = cargar_paletas()
    resultado = []
    for clave, datos in paletas.get("paletas", {}).items():
        resultado.append({
            "clave": clave,
            "nombre": datos.get("nombre", clave),
            "descripcion": datos.get("descripcion", ""),
        })
    return resultado


def validar_color(color: str) -> bool:
    """Valida que un valor sea un color hexadecimal válido.

    Acepta #RRGGBB o #RRGGBBAA.
    """
    if not color or not isinstance(color, str):
        return False
    color = color.strip()
    if not color.startswith("#"):
        return False
    resto = color[1:]
    if len(resto) not in (6, 8):  # RGB o RGBA
        return False
    try:
        int(resto, 16)
        return True
    except ValueError:
        return False


def convertir_tema_paleta_json(paleta_clave: str, tema: str,
                                colores_personalizados: Optional[dict] = None) -> str:
    """Convierte una paleta a JSON para almacenamiento en cliente.

    Args:
        paleta_clave: Clave de la paleta preconfigurada
        tema: "claro" u "oscuro"
        colores_personalizados: Dict opcional de colores sobrescritos {--variable: valor}

    Returns:
        JSON con la paleta y sobrescrituras (vacío si paleta inválida).
    """
    paleta = obtener_paleta(paleta_clave, tema)
    if not paleta:
        return "{}"

    resultado = dict(paleta)  # Copia de la paleta base
    if colores_personalizados:
        # Sobrescribe solo los colores válidos
        for var, color in colores_personalizados.items():
            if var.startswith("--") and validar_color(color):
                resultado[var] = color

    return json.dumps(resultado)
