#!/bin/bash
# Asegura que la plataforma arranca sola tras un reinicio o un apagado accidental y que se
# levanta de nuevo si el proceso muere (2026-09-08, peticion del usuario).
#
#   sudo deploy/servicio/asegurar_arranque.sh            instala/habilita y comprueba
#   sudo deploy/servicio/asegurar_arranque.sh --probar   ademas mata el proceso y comprueba
#                                                        que systemd lo levanta solo
#
# Que garantiza:
#   * threat-intel-webui.service habilitado (WantedBy=multi-user.target), Restart=always con
#     5 segundos de espera, sin limite de reintentos (StartLimitIntervalSec=0), y esperando a
#     la red (Wants/After=network-online.target).
#   * nginx habilitado, para que el 443 este disponible desde el arranque.
set -euo pipefail
AQUI=$(cd "$(dirname "$0")" && pwd)
UNIDAD=/etc/systemd/system/threat-intel-webui.service
if [[ $EUID -ne 0 ]]; then echo "Ejecutelo con sudo."; exit 1; fi
if ! cmp -s "$AQUI/threat-intel-webui.service" "$UNIDAD"; then
  cp "$AQUI/threat-intel-webui.service" "$UNIDAD"; systemctl daemon-reload
  echo "unidad de systemd actualizada desde deploy/servicio/"
fi
systemctl enable threat-intel-webui nginx >/dev/null 2>&1
systemctl start threat-intel-webui nginx
echo "habilitados: web=$(systemctl is-enabled threat-intel-webui) nginx=$(systemctl is-enabled nginx)"
echo "activos:     web=$(systemctl is-active threat-intel-webui)  nginx=$(systemctl is-active nginx)"
if [[ "${1:-}" == "--probar" ]]; then
  PID=$(systemctl show -p MainPID --value threat-intel-webui)
  echo "matando el proceso $PID para comprobar que se levanta solo..."
  kill -9 "$PID"
  for i in $(seq 1 15); do
    sleep 1
    if [[ "$(systemctl is-active threat-intel-webui)" == "active" ]] && curl -sk -o /dev/null -m 3 https://127.0.0.1/login -H "Host: plataforma.ejemplo.local"; then
      echo "recuperado en $i segundo(s): la plataforma responde de nuevo"; exit 0
    fi
  done
  echo "NO se recupero en 15 segundos"; systemctl status threat-intel-webui --no-pager | tail -5; exit 2
fi
