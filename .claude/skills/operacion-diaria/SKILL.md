---
name: operacion-diaria
description: "Procedimientos de operación del sistema Inteligencia de Amenazas: comprobar servicio, cron y última ejecución; ejecutar la recolección diaria o la sincronización con OCS de forma segura (dry-run primero); enviar alertas pendientes con confirmación; leer logs. Úsalo ante preguntas de «¿se ejecutó?», «¿por qué no llegó el correo?» o para relanzar algo."
---

# Operación diaria

Todo se ejecuta como `si` con el entorno virtual: `sudo -n -u si .venv/bin/python bin/<script>.py`.
Antes de cualquier acción que escriba o envíe, confirmar con el usuario salvo que él la haya
pedido en ese momento. Nunca correos a destinatarios externos (el SMTP interno los rechaza).

## Comprobaciones rápidas (solo lectura)

```bash
systemctl status threat-intel-webui --no-pager | head -5
curl -s -o /dev/null -w "login HTTP %{http_code}\n" http://127.0.0.1:9090/login
sudo -n -u si crontab -l
tail -n 100 logs/threatintel.jsonl | grep -i '"level": "ERROR"\|error' | tail -20
sudo -n -u si .venv/bin/python - <<'EOF'
import sqlite3
c = sqlite3.connect("file:data/threat_intel.db?mode=ro", uri=True); c.row_factory = sqlite3.Row
print("últimas ejecuciones:", [dict(r) for r in c.execute("SELECT kind, status, started_at, finished_at FROM executions ORDER BY id DESC LIMIT 3")])
print("sincronización OCS:", [dict(r) for r in c.execute("SELECT origen, status, finished_at, activos FROM sync_ocs ORDER BY id DESC LIMIT 2")])
EOF
```

Pendientes de alertar (mismo criterio que la ejecución diaria): usar `queries.clasificar_pendientes(conn, cfg=cfg, persistir=False)` con la configuración cargada (`config.load()` o como lo hace `bin/ejecucion_diaria.py`).

## Ejecución diaria

```bash
sudo -n -u si .venv/bin/python bin/ejecucion_diaria.py --dry-run      # sin escribir ni enviar: ver qué haría
sudo -n -u si .venv/bin/python bin/ejecucion_diaria.py --sin-alerta   # todo salvo el correo
sudo -n -u si .venv/bin/python bin/ejecucion_diaria.py                # completa (envía la alerta y las de proceso)
```

Pasos: 0 sincronización con OCS, fin de soporte, parches de Windows (MSRC), remediación;
1 recolección; 2 enriquecimiento (NVD, KEV, EPSS) y aplicabilidad; 3-4 salud de fuentes;
5 alerta (general y por proceso); 6 registro. Si tarda, lanzarla desacoplada:
`setsid nohup sudo -n -u si .venv/bin/python bin/ejecucion_diaria.py > data/revision/diaria_<fecha>.log 2>&1 &`.
Nunca dos ejecuciones a la vez.

## Sincronización con OCS (sin correo)

```bash
sudo -n -u si .venv/bin/python bin/sincronizar_ocs.py --sin-aplicabilidad     # solo inventario y hallazgos
sudo -n -u si .venv/bin/python bin/sincronizar_ocs.py --max-amenazas 200      # con evaluación acotada
sudo -n -u si .venv/bin/python bin/sincronizar_ocs.py --solo-aplicabilidad --reevaluar --max-osv 0   # reevaluar sin red a OSV
```

## Después de un cambio de código
1. Suite en verde (habilidad `pruebas`).
2. `systemctl restart threat-intel-webui && sleep 2 && systemctl is-active threat-intel-webui`.
3. Migraciones de esquema: `sudo -n -u si .venv/bin/python -c "from threatintel import db; db.init_db()"`
   (idempotente) y comprobar `PRAGMA table_info`.
4. Si hay ejecuciones o sincronizaciones «colgadas» en `executions`/`sync_ocs` (estado `running`
   sin proceso vivo), cerrarlas a mano con fecha y motivo antes de relanzar.

## Copias de seguridad antes de cambios grandes

```bash
sudo -n -u si .venv/bin/python -c "import sqlite3; s=sqlite3.connect('data/threat_intel.db'); d=sqlite3.connect('backups/threat_intel_pre_<tema>_<fecha>.db'); s.backup(d)"
tar czf backups/snapshot_pre_<tema>_<fecha>.tar.gz --exclude='.venv' --exclude='venv' --exclude='data' --exclude='backups' --exclude='logs' --exclude='__pycache__' .
chown si:si backups/*
```
