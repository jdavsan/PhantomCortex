#!/usr/bin/env python3
"""Demostración de las paletas de colores disponibles.

Ejecutar: sudo -n -u si .venv/bin/python bin/demostrar_colores.py
"""
from pathlib import Path
import sys
import json

# Añadir webui al path
sys.path.insert(0, str(Path(__file__).parent.parent))

from webui import colores


def mostrar_paleta(nombre: str):
    """Muestra detalles de una paleta."""
    print(f"\n{'='*70}")
    print(f"PALETA: {nombre.upper()}")
    print(f"{'='*70}")

    paletas = colores.cargar_paletas()
    if nombre not in paletas.get("paletas", {}):
        print(f"ERROR: Paleta '{nombre}' no encontrada")
        return

    p = paletas["paletas"][nombre]
    print(f"Nombre: {p.get('nombre')}")
    print(f"Descripción: {p.get('descripcion')}")

    for tema in ["claro", "oscuro"]:
        print(f"\n--- Tema {tema.upper()} ---")
        colores_tema = p.get(tema, {})
        if not colores_tema:
            print("  (vacío)")
            continue

        # Agrupar por categoría
        categorias = {}
        for var, color in colores_tema.items():
            if var.startswith("--cat-"):
                cat = "categórico"
            elif var.startswith("--fondo"):
                cat = "fondo"
            elif var.startswith("--texto"):
                cat = "texto"
            elif var.startswith("--"):
                cat = "semántico"
            else:
                cat = "otro"

            if cat not in categorias:
                categorias[cat] = []
            categorias[cat].append((var, color))

        for cat in ["fondo", "texto", "semántico", "categórico", "otro"]:
            if cat in categorias:
                print(f"  {cat.capitalize()}:")
                for var, color in sorted(categorias[cat]):
                    print(f"    {var:20} = {color}")


def listar_paletas():
    """Lista todas las paletas disponibles."""
    print("\n" + "="*70)
    print("PALETAS DE COLORES DISPONIBLES")
    print("="*70 + "\n")

    lista = colores.listar_paletas()
    for i, p in enumerate(lista, 1):
        print(f"{i}. {p['nombre']}")
        print(f"   Clave: {p['clave']}")
        print(f"   Descripción: {p['descripcion']}")
        print()


def validar_ejemplo():
    """Demuestra la validación de colores."""
    print("\n" + "="*70)
    print("VALIDACIÓN DE COLORES")
    print("="*70 + "\n")

    ejemplos = [
        "#ff0000",       # Válido
        "#00ff00ff",     # Válido (con alfa)
        "ff0000",        # Inválido (sin #)
        "#gggggg",       # Inválido (no hex)
        "#fff",          # Inválido (muy corto)
        "",              # Inválido (vacío)
    ]

    for ejemplo in ejemplos:
        válido = colores.validar_color(ejemplo)
        estado = "✓" if válido else "✗"
        print(f"{estado} {ejemplo:15} {'válido' if válido else 'inválido'}")


def personalizar_ejemplo():
    """Demuestra la personalización de colores."""
    print("\n" + "="*70)
    print("PERSONALIZACIÓN DE COLORES")
    print("="*70 + "\n")

    print("Tomando paleta 'corporativa' tema 'claro' y sobrescribiendo:")
    print("  --critico = #ff0000")
    print("  --exito = #00ff00")
    print()

    personalizaciones = {
        "--critico": "#ff0000",
        "--exito": "#00ff00"
    }

    json_str = colores.convertir_tema_paleta_json("corporativa", "claro", personalizaciones)
    datos = json.loads(json_str)

    print("Resultado (primeros 10 valores):")
    for var, color in sorted(datos.items())[:10]:
        print(f"  {var:20} = {color}")

    print(f"\nTotal de tokens: {len(datos)}")
    print(f"Verificación: --critico = {datos.get('--critico')} (sobrescrito)")
    print(f"Verificación: --exito = {datos.get('--exito')} (sobrescrito)")


if __name__ == "__main__":
    listar_paletas()

    # Mostrar detalles de la primera paleta
    lista = colores.listar_paletas()
    if lista:
        mostrar_paleta(lista[0]["clave"])

    validar_ejemplo()
    personalizar_ejemplo()

    print("\n" + "="*70)
    print("Demostración completada")
    print("="*70 + "\n")
