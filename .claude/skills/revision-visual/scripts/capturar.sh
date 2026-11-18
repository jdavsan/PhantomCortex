#!/usr/bin/env bash
# Captura páginas de la consola en tema claro y oscuro con un usuario temporal de solo lectura.
#
# Uso:  capturar.sh [ruta ...]     (sin argumentos: páginas principales)
# Variables: BASE (http://127.0.0.1:9090), ANCHO (1440), ALTO (2600), ROL (viewer|admin),
#            DEST (data/revision/capturas/<fecha>)
#
# Método: se crea el usuario temporal (contraseña aleatoria), se descarga cada página con
# curl y la cookie de sesión, se reescriben las rutas /static/ a file:// para que Chrome cargue
# el CSS y el JS locales, y para el tema oscuro se añade data-tema="oscuro" al <html>.
# El usuario temporal se elimina siempre al terminar (trampa EXIT).
set -uo pipefail

PROYECTO=/opt/inteligencia_amenazas
cd "$PROYECTO" || exit 2
BASE="${BASE:-http://127.0.0.1:9090}"
ANCHO="${ANCHO:-1440}"
ALTO="${ALTO:-2600}"
MARCA="$(date +%Y%m%d-%H%M%S)"
DEST="${DEST:-$PROYECTO/data/revision/capturas/$MARCA}"
STATIC="file://$PROYECTO/webui/static/"
USUARIO="revision@ejemplo.local"
ROL="${ROL:-viewer}"
JAR="$(mktemp /tmp/capturas_cookies_XXXXXX)"

limpiar() {
  rm -f "$JAR"
  sudo -n -u si "$PROYECTO/.venv/bin/python" "$PROYECTO/.claude/skills/revision-visual/scripts/usuario_temporal.py" borrar >/dev/null 2>&1 || true
}
trap limpiar EXIT

mkdir -p "$DEST" && chown -R si:si "$PROYECTO/data/revision"
CLAVE="$(sudo -n -u si "$PROYECTO/.venv/bin/python" "$PROYECTO/.claude/skills/revision-visual/scripts/usuario_temporal.py" crear "$ROL")" || { echo "ERROR: no se pudo crear el usuario temporal" >&2; exit 1; }

if [ $# -eq 0 ]; then
  RUTAS=(/ /amenazas/ /amenazas/tendencias /activos/ /activos/software /tecnologias/ /fuentes/ /remediaciones/)
else
  RUTAS=("$@")
fi

curl -s -c "$JAR" -o /dev/null "$BASE/login"
curl -s -b "$JAR" -c "$JAR" -o /dev/null -d "usuario=$USUARIO" --data-urlencode "password=$CLAVE" "$BASE/login"
if ! curl -s -b "$JAR" -o /dev/null -w "%{http_code}" "$BASE/" | grep -q 200; then
  echo "ERROR: no se pudo iniciar sesión como $USUARIO (¿segundo factor obligatorio para lectores? ¿servicio caído?)" >&2; exit 1
fi

captura() {  # $1 = fichero html, $2 = png
  timeout 90 google-chrome --headless=new --no-sandbox --disable-gpu --hide-scrollbars \
    --window-size="${ANCHO},${ALTO}" --screenshot="$2" "file://$1" >/dev/null 2>&1 || true
}

for ruta in "${RUTAS[@]}"; do
  nombre=$(echo "$ruta" | sed 's#^/##; s#/$##; s#/#_#g; s#[?&=]#_#g'); [ -z "$nombre" ] && nombre="panel"
  html="$DEST/$nombre.html"
  codigo=$(curl -s -b "$JAR" -o "$html.tmp" -w "%{http_code}" "$BASE$ruta")
  if [ "$codigo" != "200" ]; then echo "  $ruta -> HTTP $codigo (sin captura)"; rm -f "$html.tmp"; continue; fi
  sed "s#\"/static/#\"$STATIC#g" "$html.tmp" > "$html"; rm -f "$html.tmp"
  sed 's#<html lang="es">#<html lang="es" data-tema="oscuro">#' "$html" > "$DEST/$nombre-oscuro.html"
  captura "$html" "$DEST/$nombre-claro.png"
  captura "$DEST/$nombre-oscuro.html" "$DEST/$nombre-oscuro.png"
  rm -f "$DEST/$nombre-oscuro.html"
  inl=$(grep -cE '\sstyle="|\son[a-z]+="' "$html" || true)
  col=$(grep -oE '(fill|stroke)="#[0-9a-fA-F]{3,8}"|(fill|stroke)="rgb' "$html" | grep -v 'favicon' | wc -l || true)
  ext=$(grep -oE '(src|href)="https?://' "$html" | wc -l || true)
  svg=$(grep -c '<svg class="grafico' "$html" || true)
  printf "  %-30s HTTP 200  gráficos=%-3s en-línea=%s colores-literales=%s externos=%s  -> %s-{claro,oscuro}.png\n" "$ruta" "$svg" "$inl" "$col" "$ext" "$nombre"
done
chown -R si:si "$DEST"
echo "Capturas en $DEST"
