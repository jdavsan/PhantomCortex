#!/bin/bash
# Activa la redireccion de la IP al nombre canonico SOLO cuando el DNS ya resuelve el nombre
# a este servidor; si se activara antes, nadie podria entrar por la IP ni por el nombre.
# Uso: omniguard-activar-redireccion [--forzar]
set -euo pipefail
NOMBRE=plataforma.ejemplo.local
IP=10.10.11.10
SITIO=/etc/nginx/sites-available/omniguard
PREPARADO=/etc/nginx/sites-available/omniguard.redireccion-al-nombre
if grep -q "return 301 https://$NOMBRE" "$SITIO" 2>/dev/null; then
  echo "la redireccion al nombre ya esta activa"; systemctl disable --now omniguard-redireccion.timer >/dev/null 2>&1 || true; exit 0
fi
if [[ "${1:-}" != "--forzar" ]]; then
  RESUELTO=$(getent ahostsv4 "$NOMBRE" 2>/dev/null | awk '{print $1}' | head -1 || true)
  if [[ "$RESUELTO" != "$IP" ]]; then
    echo "$(date '+%F %T') el DNS todavia no resuelve $NOMBRE a $IP (resuelve: '${RESUELTO:-nada}'); se espera"; exit 0
  fi
fi
cp "$SITIO" "$SITIO.anterior-$(date +%F-%H%M)"
cp "$PREPARADO" "$SITIO"
nginx -t && systemctl reload nginx
echo "$(date '+%F %T') redireccion al nombre ACTIVADA"
systemctl disable --now omniguard-redireccion.timer >/dev/null 2>&1 || true
