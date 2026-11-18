---
name: pruebas
description: "Ejecuta la suite de pruebas del proyecto Inteligencia de Amenazas como el usuario si y resume solo lo que falla; también un módulo o una prueba concreta. Úsalo antes de dar cualquier cambio por hecho y para diagnosticar una suite en rojo."
---

# Pruebas del proyecto

La suite vive en `tests/test_*.py` (unittest, sin red, bases temporales bajo `data/`). Se
ejecuta siempre como el usuario `si` con el entorno virtual del proyecto.

## Suite completa (obligatoria antes de dar algo por hecho)

```bash
bash .claude/skills/pruebas/scripts/suite.sh
```

Imprime el resumen (`Ran N tests … OK` o `FAILED`) y, si hay fallos, cada `FAIL`/`ERROR` con su
aserción. Equivale a:

```bash
cd /opt/inteligencia_amenazas && sudo -n -u si .venv/bin/python -m unittest discover -s tests -p "test_*.py"
```

## Un módulo o una prueba

```bash
bash .claude/skills/pruebas/scripts/suite.sh tests.test_pagina_activos
bash .claude/skills/pruebas/scripts/suite.sh tests.test_segundo_factor.TestFlujo.test_login
```

## Reglas
- Nunca «arreglar» una suite roja debilitando o borrando pruebas: se corrige el código o se
  adapta la prueba explicando en su docstring el cambio intencional.
- Las pruebas nuevas siguen las convenciones de `tests/test_pagina_activos.py`: base temporal
  (`tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))`, `db.init_db(ruta)`), aplicación
  con `crear_app(db_path=ruta, testing=True)`, sin red (mocks de `threatintel.http`), sin
  correo real (`Mailer(dry_run=True)` o doble).
- Varias suites pueden ejecutarse a la vez (cada una usa su base temporal); tardan unos 40 s.
- Si la suite falla por un fichero recién editado por otro agente, repite una vez antes de
  investigar: puede ser una edición a medias.
