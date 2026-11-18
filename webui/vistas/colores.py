"""Endpoints para gestión de temas y colores personalizados.

Permite al usuario seleccionar paletas preconfiguradas y personalizar colores individuales.
Las preferencias se almacenan en localStorage (cliente) sin modificar la base de datos.
"""
from __future__ import annotations

import json

from flask import Blueprint, current_app, g, jsonify, request

from webui import auth, colores

bp = Blueprint("colores", __name__, url_prefix="/colores")


@bp.route("/paletas")
@auth.requiere_login
def listar_paletas():
    """Devuelve la lista de paletas preconfiguradas disponibles."""
    return jsonify({
        "paletas": colores.listar_paletas()
    })


@bp.route("/paleta/<clave>")
@auth.requiere_login
def obtener_paleta(clave: str):
    """Devuelve una paleta completa (claro y oscuro).

    Args:
        clave: Clave de la paleta (ej. "viva")
    """
    paletas_data = colores.cargar_paletas()
    if clave not in paletas_data.get("paletas", {}):
        return jsonify({"error": "Paleta no encontrada"}), 404

    paleta = paletas_data["paletas"][clave]
    return jsonify({
        "clave": clave,
        "nombre": paleta.get("nombre"),
        "descripcion": paleta.get("descripcion"),
        "claro": paleta.get("claro", {}),
        "oscuro": paleta.get("oscuro", {})
    })


@bp.route("/aplicar", methods=["POST"])
@auth.requiere_login
@auth.requiere_csrf
def aplicar_paleta():
    """Aplica una paleta y sobrescrituras de color personalizadas.

    Esperado en JSON:
    {
        "paleta": "viva",
        "tema": "claro",
        "personalizaciones": {
            "--critico": "#ff0000",  (opcional)
            ...
        }
    }

    Devuelve la configuración a aplicar en el navegador.
    """
    datos = request.get_json() or {}
    paleta_clave = datos.get("paleta", "viva").strip()
    tema = datos.get("tema", "claro").strip()
    personalizaciones = datos.get("personalizaciones") or {}

    # Validar
    if tema not in ("claro", "oscuro"):
        return jsonify({"error": "Tema debe ser 'claro' u 'oscuro'"}), 400

    # Obtener la paleta base
    paleta_base = colores.obtener_paleta(paleta_clave, tema)
    if not paleta_base:
        return jsonify({"error": f"Paleta '{paleta_clave}' no encontrada"}), 404

    # Validar personalizaciones
    for var, valor in personalizaciones.items():
        if not var.startswith("--"):
            return jsonify({"error": f"Variable CSS debe empezar con '--': {var}"}), 400
        if not colores.validar_color(valor):
            return jsonify({"error": f"Color inválido para {var}: {valor}"}), 400

    # Mezclar paleta base + personalizaciones
    resultado = dict(paleta_base)
    resultado.update(personalizaciones)

    return jsonify({
        "paleta": paleta_clave,
        "tema": tema,
        "colores": resultado
    })


@bp.route("/previsualizar/<clave>/<tema>")
@auth.requiere_login
def previsualizar(clave: str, tema: str):
    """Devuelve una paleta para previsualizar sin aplicarla.

    Se usa en la interfaz de Ajustes antes de guardar.
    """
    if tema not in ("claro", "oscuro"):
        return jsonify({"error": "Tema debe ser 'claro' u 'oscuro'"}), 400

    paleta = colores.obtener_paleta(clave, tema)
    if not paleta:
        return jsonify({"error": f"Paleta '{clave}' no encontrada"}), 404

    return jsonify({
        "clave": clave,
        "tema": tema,
        "colores": paleta
    })
