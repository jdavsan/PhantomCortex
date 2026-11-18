#!/usr/bin/env bash
# Ejecuta la suite del proyecto (o un módulo/prueba) como el usuario si y resume los fallos.
# Uso: suite.sh                      → suite completa
#      suite.sh tests.test_x [...]   → módulos o pruebas concretas
set -uo pipefail
cd /opt/inteligencia_amenazas || exit 2
SALIDA="$(mktemp /tmp/suite_XXXXXX.txt)"
if [ $# -eq 0 ]; then
  sudo -n -u si .venv/bin/python -m unittest discover -s tests -p "test_*.py" >"$SALIDA" 2>&1
else
  sudo -n -u si .venv/bin/python -m unittest "$@" >"$SALIDA" 2>&1
fi
CODIGO=$?
grep -E "^(Ran |OK|FAILED)" "$SALIDA"
if [ $CODIGO -ne 0 ]; then
  echo "---- fallos ----"
  grep -E "^(FAIL|ERROR):" "$SALIDA"
  echo "---- detalle (primeras 80 líneas de aserciones y errores) ----"
  grep -E "AssertionError|Error:|Traceback|File \"" "$SALIDA" | head -80
fi
rm -f "$SALIDA"
exit $CODIGO
