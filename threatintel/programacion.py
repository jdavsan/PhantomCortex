"""Horario real del programador de tareas, registrado por quien puede leerlo.

La pagina «Consultas a OCS Inventory» tiene que decir a que hora se ejecuta la consulta.
La hora la fija el cron del usuario del servicio, y esa es la unica fuente de verdad: no
se escribe en el codigo ni en un ajuste que alguien pueda dejar desfasado.

El problema es que la interfaz web NO puede leerlo. Su unidad de systemd tiene
``NoNewPrivileges=true`` y ``RestrictSUIDSGID=true``, asi que la orden ``crontab`` no
puede tomar el grupo ``crontab`` con el que lee el directorio del spool, que no es
transitable para el usuario. Eso es endurecimiento correcto y no se toca por una etiqueta.

La solucion es que lo registre quien SI puede: los propios trabajos programados, que
corren en un shell normal. Cada ejecucion diaria llama a :func:`registrar` y guarda en
``settings`` el horario que acaba de leer. La interfaz lee ese valor y dice cuando se
tomo, de modo que si alguien cambia el cron, la pagina lo refleja al dia siguiente y
mientras tanto no miente sobre la fecha del dato.
"""
from __future__ import annotations

import subprocess
from typing import Any, Optional

from . import db
from .logging_setup import get_logger

log = get_logger("programacion")

#: Clave de ``settings`` donde vive el horario leido del cron.
CLAVE = "horario_programado"

#: Ordenes de la plataforma cuyo horario interesa, con lo que hace cada una.
ORDENES: tuple[tuple[str, str], ...] = (
    ("ejecucion_diaria.py --sin-alerta", "Consulta a OCS, recolección y enriquecimiento"),
    ("ejecucion_diaria.py --solo-alerta", "Clasificación y envío de la alerta"),
    ("ejecucion_diaria.py", "Ejecución diaria completa"),
    ("sincronizar_ocs.py", "Consulta a OCS a demanda (fuera de la diaria)"),
    ("enriquecer.py", "Enriquecimiento por lotes"),
    ("ejecucion_mensual.py", "Informe mensual"),
    ("resumen_semanal.py", "Resumen semanal"),
)


def leer_crontab(texto: Optional[str] = None) -> list[dict[str, str]]:
    """Horas de las ordenes de la plataforma en el crontab.

    ``texto`` permite pasar un crontab ya leido (las pruebas lo usan). Sin el, se
    pregunta con ``crontab -l``. Del resultado se extraen UNICAMENTE las lineas de las
    ordenes de la plataforma: el resto del programador no sale de aqui.
    """
    if texto is None:
        try:
            salida = subprocess.run(["crontab", "-l"], capture_output=True, text=True,
                                    timeout=5, stdin=subprocess.DEVNULL, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("no se pudo leer el crontab", extra={"error": str(exc)})
            return []
        if salida.returncode != 0:
            log.warning("crontab -l devolvio un codigo distinto de cero",
                        extra={"codigo": salida.returncode})
            return []
        texto = salida.stdout

    encontradas: list[dict[str, str]] = []
    for linea in texto.split("\n"):
        limpia = linea.strip()
        if not limpia or limpia.startswith("#"):
            continue
        campos = limpia.split()
        if len(campos) < 5:
            continue
        minuto, hora = campos[0], campos[1]
        if not minuto.isdigit() or not hora.isdigit():
            continue          # */5, rangos y listas no son un horario que se pueda mostrar asi
        # La orden mas especifica gana: «--sin-alerta» antes que «ejecucion_diaria.py».
        for orden, que_hace in ORDENES:
            if orden in limpia:
                encontradas.append({"hora": f"{int(hora):02d}:{int(minuto):02d}",
                                    "que_hace": que_hace, "orden": orden})
                break
    encontradas.sort(key=lambda x: x["hora"])
    return encontradas


def registrar(conn, *, texto: Optional[str] = None) -> list[dict[str, str]]:
    """Guarda en ``settings`` el horario leido del cron. Devuelve lo guardado.

    Si no se pudo leer nada NO se borra lo que hubiera: es mejor un horario de ayer,
    con su fecha a la vista, que ninguno.
    """
    horario = leer_crontab(texto)
    if horario:
        db.set_setting(conn, CLAVE, horario)
        log.info("horario del programador registrado", extra={"ordenes": len(horario)})
    return horario


def guardado(conn) -> dict[str, Any]:
    """``{"horario": [...], "leido_at": "..."}`` con lo ultimo que se registro."""
    fila = conn.execute("SELECT value, updated_at FROM settings WHERE key=?", (CLAVE,)).fetchone()
    if not fila:
        return {"horario": [], "leido_at": None}
    import json
    try:
        horario = json.loads(fila["value"] if hasattr(fila, "keys") else fila[0]) or []
    except (TypeError, ValueError):
        horario = []
    leido = fila["updated_at"] if hasattr(fila, "keys") else fila[1]
    return {"horario": horario if isinstance(horario, list) else [], "leido_at": leido}
