#!/usr/bin/env python3
"""OBSOLETO. Este script pertenece al sistema anterior a la reescritura de
septiembre de 2026 y NO debe ejecutarse.

Escribe en los ficheros JSON que ya no son la fuente de verdad, usa el
identificador md5(titulo+fecha) que duplicaba amenazas y re-alertaba el mismo
aviso varios dias seguidos, y estampa una puntuacion CVSS inventada.

Ejecutarlo enviaria una alerta DUPLICADA con datos peores que los del sistema
actual.

Se conserva solo como referencia. El equivalente actual esta en:
    bin/ejecucion_diaria.py    (recoleccion y alerta)
    bin/ejecucion_mensual.py   (informe y envio)

El original sin modificar esta en obsoleto/ y en el snapshot de respaldo de la instalación.
"""
import sys

print(__doc__)
print("\n  Ejecucion abortada a proposito.")
print("  Use:  .venv/bin/python bin/ejecucion_diaria.py --help\n")
sys.exit(1)
