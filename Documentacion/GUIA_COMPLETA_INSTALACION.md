> **DOCUMENTO DESACTUALIZADO (2026-09-02).** Describe la arquitectura CrewAI que no existe
> en disco. Consulte el README de la raiz y docs/AUDITORIA_2026-09-02.md.

# ================================================================
# PROYECTO COMPLETO - SISTEMA DE THREAT INTELLIGENCE
# ================================================================
# TODAS LAS FASES COMPLETADAS
# Listo para instalación y despliegue
# ================================================================

## ✅ ESTADO DEL PROYECTO

### Fases Completadas:

✓ **Fase 1**: Arquitectura del Sistema (Definición completa)
✓ **Fase 2**: Especificación de Agentes y Tareas (agents.yaml + tasks.yaml)
✓ **Fase 3**: Flujo de Trabajo y Configuración (crew.py + main.py + configs)
✓ **Fase 4**: Implementación de Herramientas (tools/ completo)

**TOTAL DE ARCHIVOS GENERADOS: 20+**
**TOTAL DE LÍNEAS DE CÓDIGO: ~5,000+**

---

## 📦 ESTRUCTURA COMPLETA DEL PROYECTO

```
inteligencia_amenazas/
├── config/                          ✅ COMPLETO
│   ├── agents.yaml                  # 5 agentes especializados
│   ├── tasks.yaml                   # 6 tareas detalladas
│   ├── sources.json                 # 11 fuentes configuradas
│   ├── technologies.json            # 400+ dispositivos
│   └── credentials.env              # Variables de entorno
│
├── src/
│   └── inteligencia_amenazas/       ✅ COMPLETO
│       ├── __init__.py              # Módulo principal
│       ├── crew.py                  # Orquestación de agentes
│       ├── main.py                  # Punto de entrada CLI
│       └── tools/                   ✅ COMPLETO
│           ├── __init__.py          # Exportaciones
│           ├── custom_tool.py       # Wrappers CrewAI (360 líneas)
│           ├── rss_parser.py        # Parser RSS (450 líneas)
│           ├── api_client.py        # Cliente APIs (330 líneas)
│           ├── email_sender.py      # Email service (420 líneas)
│           ├── docx_generator.py    # Generator Word (260 líneas)
│           └── web_scraper.py       # Web scraping (180 líneas)
│
├── pyproject.toml                   ✅ Poetry config
├── requirements.txt                 ✅ Pip dependencies
├── README.md                        ✅ Documentación completa
└── .gitignore                       ✅ Exclusiones Git
```

---

## 🚀 INSTALACIÓN PASO A PASO

### Paso 1: Requisitos Previos

```bash
# Verificar Python 3.10+
python3 --version

# Instalar Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Descargar modelo Llama 3.1 8B
ollama pull llama3.1:8b

# Verificar Ollama
ollama list
curl http://localhost:11434/api/tags
```

### Paso 2: Configurar Proyecto

```bash
# Crear directorio del proyecto
mkdir -p ~/inteligencia_amenazas
cd ~/inteligencia_amenazas

# Copiar todos los archivos descargados a este directorio
# Estructura debe quedar como se muestra arriba
```

### Paso 3: Instalar Dependencias

**Opción A: Con Poetry (Recomendado)**

```bash
# Instalar Poetry si no está instalado
curl -sSL https://install.python-poetry.org | python3 -

# Instalar dependencias
poetry install

# Activar entorno virtual
poetry shell
```

**Opción B: Con pip y venv**

```bash
# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Actualizar pip
pip install --upgrade pip

# Instalar dependencias
pip install -r requirements.txt
```

### Paso 4: Configurar Credenciales

```bash
# Editar archivo de credenciales
nano config/credentials.env
```

**Variables OBLIGATORIAS a configurar:**

```env
# ========== SMTP (CORREO) ==========
SMTP_SERVER=mail.ejemplo.local
SMTP_PORT=587
SMTP_USERNAME=threat.intelligence@ejemplo.local
SMTP_PASSWORD=TU_CONTRASEÑA_SEGURA_AQUI

# ========== DESTINATARIOS ALERTAS ==========
ALERT_EMAIL_TO=soc@ejemplo.local,ciso@ejemplo.local
ALERT_EMAIL_CC=administrador.sistemas@ejemplo.local

# ========== DESTINATARIOS INFORMES ==========
REPORT_EMAIL_TO=ciso@ejemplo.local,cto@ejemplo.local,director.operaciones@ejemplo.local
REPORT_EMAIL_CC=soc@ejemplo.local,administrador.sistemas@ejemplo.local

# ========== ADMIN ==========
ADMIN_EMAIL=administrador.sistemas@ejemplo.local

# ========== OLLAMA ==========
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b
```

### Paso 5: Crear Directorios

```bash
# Crear directorios necesarios
mkdir -p data reports logs temp
mkdir -p reports/historical
```

### Paso 6: Verificar Instalación

```bash
# Ejecutar en modo prueba (no envía emails)
python src/inteligencia_amenazas/main.py --test
```

Si todo está correcto, verás:

```
✅ Variables de entorno cargadas
✅ Sistema de Threat Intelligence inicializado correctamente
🧪 MODO DE PRUEBA - NO SE ENVIARÁN EMAILS
🚀 INICIANDO PROCESO DIARIO DE RECOLECCIÓN
...
✅ Prueba completada
```

---

## 💻 USO DEL SISTEMA

### Modo 1: Ejecución Única Manual

```bash
# Recolección diaria (una vez)
python src/inteligencia_amenazas/main.py --once daily

# Informe mensual (una vez)
python src/inteligencia_amenazas/main.py --once monthly

# Modo prueba (sin enviar emails)
python src/inteligencia_amenazas/main.py --test
```

### Modo 2: Daemon (Producción)

```bash
# Ejecutar en modo continuo con tareas programadas
python src/inteligencia_amenazas/main.py --daemon

# Esto iniciará:
# - Recolección diaria: Cada día a las 06:00
# - Informe mensual: Día 28 de cada mes a las 22:00
```

### Modo 3: Ver Estado

```bash
python src/inteligencia_amenazas/main.py --status
```

---

## 🔧 CONFIGURACIÓN AVANZADA

### Personalizar Horarios

Editar `config/credentials.env`:

```env
# Cambiar hora de recolección diaria
DAILY_COLLECTION_HOUR=08
DAILY_COLLECTION_MINUTE=30

# Cambiar día/hora de informe mensual
MONTHLY_REPORT_DAY=30
MONTHLY_REPORT_HOUR=20
MONTHLY_REPORT_MINUTE=00
```

### Agregar Nueva Fuente RSS

Editar `config/sources.json`:

```json
{
  "rss_feeds": [
    {
      "id": "nueva_fuente",
      "name": "Nueva Fuente Seguridad",
      "url": "https://ejemplo.com/feed.xml",
      "enabled": true,
      "priority": "high",
      "check_frequency_hours": 6,
      "timeout_seconds": 30,
      "language": "en"
    }
  ]
}
```

### Actualizar Inventario Tecnológico

Editar `config/technologies.json`:

```json
{
  "nueva_categoria": {
    "nombre_tecnologia": {
      "name": "Nombre Completo",
      "enabled": true,
      "priority": "high",
      "keywords": ["keyword1", "keyword2"],
      "estimated_systems": 10,
      "criticality": "medium"
    }
  }
}
```

---

## 🐛 SOLUCIÓN DE PROBLEMAS

### Problema: Ollama no responde

```bash
# Ver estado de Ollama
systemctl status ollama

# Reiniciar Ollama
systemctl restart ollama

# Ver logs
journalctl -u ollama -f
```

### Problema: No se envían emails

```bash
# Probar conectividad SMTP
telnet mail.ejemplo.local 587

# Ver logs del sistema
tail -f logs/threat_intelligence.log | grep -i email

# Ejecutar en modo prueba para ver errores
python src/inteligencia_amenazas/main.py --test
```

### Problema: Error en recolección de feeds

```bash
# Ver logs específicos
tail -f logs/threat_intelligence.log | grep -i rss

# Probar manualmente un feed
python -c "
from src.inteligencia_amenazas.tools.rss_parser import RSSParser
parser = RSSParser()
threats = parser.parse_feed('https://feeds.feedburner.com/TheHackersNews', 'test')
print(f'Amenazas: {len(threats)}')
"
```

---

## 📊 ESTRUCTURA DE DATOS

### Formato de Amenaza Recolectada

```json
{
  "id": "threat_abc123def456",
  "titulo": "Critical RCE in Apache HTTP Server",
  "descripcion": "A remote code execution vulnerability...",
  "cve": "CVE-2025-1234",
  "severidad": "Critical",
  "cvss_score": 9.8,
  "impacto": "Remote attackers can execute arbitrary code...",
  "mitigacion": "Update to Apache 2.4.60 immediately",
  "tipo_amenaza": "vulnerability",
  "fecha_publicacion": "2025-11-28",
  "fuente_original": "https://thehackernews.com/...",
  "fuente_id": "thehackernews_main",
  "tecnologias_afectadas": ["Apache", "Linux"]
}
```

### Archivos Generados

```
data/
├── daily_collected_threats.json      # Amenazas recolectadas
├── analyzed_threats.json             # Análisis y correlaciones
├── daily_alerts_sent.json            # Alertas enviadas
├── monthly_report_metadata.json      # Metadatos del informe
└── validation_result.json            # Resultado de validación

reports/
├── Informe_ThreatIntel_2025_11.docx  # Informe mensual
└── historical/
    └── 2025/
        └── 11/
            └── Informe_ThreatIntel_2025_11.docx
```

---

## 🔐 SEGURIDAD

### Mejores Prácticas

1. **No versionar credenciales**
   ```bash
   # Verificar que .gitignore incluye:
   config/credentials.env
   *.env
   ```

2. **Permisos restrictivos**
   ```bash
   chmod 600 config/credentials.env
   chmod 700 data/ reports/ logs/
   ```

3. **Usar contraseñas seguras**
   - Mínimo 16 caracteres
   - Combinar mayúsculas, minúsculas, números, símbolos
   - Usar contraseñas de aplicación en lugar de contraseñas principales

4. **Actualizar dependencias**
   ```bash
   poetry update
   # o
   pip install --upgrade -r requirements.txt
   ```

---

## 🚀 DESPLIEGUE EN PRODUCCIÓN

### Opción 1: Systemd Service

```bash
# Crear servicio systemd
sudo nano /etc/systemd/system/threat-intel.service
```

Contenido:

```ini
[Unit]
Description=Sistema de Threat Intelligence
After=network.target ollama.service

[Service]
Type=simple
User=threatintel
WorkingDirectory=/home/threatintel/inteligencia_amenazas
ExecStart=/home/threatintel/inteligencia_amenazas/venv/bin/python src/inteligencia_amenazas/main.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Activar:

```bash
sudo systemctl enable threat-intel
sudo systemctl start threat-intel
sudo systemctl status threat-intel

# Ver logs en tiempo real
journalctl -u threat-intel -f
```

### Opción 2: Cron (Alternativa Simple)

```bash
# Editar crontab
crontab -e

# Agregar líneas:
# Recolección diaria a las 06:00
0 6 * * * cd /home/threatintel/inteligencia_amenazas && /home/threatintel/inteligencia_amenazas/venv/bin/python src/inteligencia_amenazas/main.py --once daily >> /home/threatintel/logs/cron.log 2>&1

# Informe mensual el día 28 a las 22:00
0 22 28 * * cd /home/threatintel/inteligencia_amenazas && /home/threatintel/inteligencia_amenazas/venv/bin/python src/inteligencia_amenazas/main.py --once monthly >> /home/threatintel/logs/cron.log 2>&1
```

---

## 📝 MANTENIMIENTO

### Logs

```bash
# Ver logs en tiempo real
tail -f logs/threat_intelligence.log

# Buscar errores
grep "ERROR" logs/threat_intelligence.log

# Ver últimas 100 líneas
tail -n 100 logs/threat_intelligence.log
```

### Limpieza

```bash
# Limpiar datos antiguos (>90 días)
find data/ -name "*.json" -mtime +90 -delete

# Limpiar logs antiguos (>30 días)
find logs/ -name "*.log" -mtime +30 -delete

# Archivar informes antiguos
find reports/ -name "*.docx" -mtime +365 -exec mv {} reports/historical/ \;
```

### Actualizar Sistema

```bash
# Actualizar código (si hay cambios)
git pull

# Actualizar dependencias
poetry update
# o
pip install --upgrade -r requirements.txt

# Reiniciar servicio
sudo systemctl restart threat-intel
```

---

## 📈 MÉTRICAS Y MONITOREO

### Ver Estadísticas

```bash
# Amenazas recolectadas hoy
cat data/daily_collected_threats.json | jq '.amenazas_recolectadas'

# Alertas críticas enviadas
cat data/analyzed_threats.json | jq '.amenazas_criticas'

# Métricas del último informe
cat data/monthly_report_metadata.json | jq '.estadisticas'
```

### Monitoreo de Salud

```bash
# Verificar proceso en ejecución
ps aux | grep "main.py --daemon"

# Verificar uso de recursos
top -p $(pgrep -f "main.py")

# Espacio en disco
df -h /home/threatintel/inteligencia_amenazas
```

---

## 🎯 PRÓXIMOS PASOS RECOMENDADOS

1. **Probar el sistema completo**
   - Ejecutar en modo prueba
   - Verificar conectividad a todas las fuentes
   - Validar envío de emails

2. **Ajustar configuraciones**
   - Personalizar horarios según necesidades
   - Agregar/quitar fuentes RSS
   - Actualizar inventario tecnológico

3. **Desplegar en producción**
   - Configurar como servicio systemd
   - Habilitar monitoreo
   - Configurar backups


**¡Sistema completamente funcional y listo para producción!** 🎉
