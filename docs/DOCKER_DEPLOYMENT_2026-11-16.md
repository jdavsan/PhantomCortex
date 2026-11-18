# Despliegue con Docker - Inteligencia de Amenazas

Guía para desplegar el sistema de Inteligencia de Amenazas en contenedores Docker.

## Contenidos

1. [Requisitos](#requisitos)
2. [Despliegue con Docker](#despliegue-con-docker)
3. [Despliegue en Máquina Directa](#despliegue-en-máquina-directa)
4. [Configuración](#configuración)
5. [Operación](#operación)
6. [Solución de Problemas](#solución-de-problemas)

## Requisitos

### Para Docker
- Docker 20.10+
- Docker Compose 2.0+
- 2 GB RAM mínimo
- 5 GB espacio en disco

### Para Máquina Directa
- Python 3.13+
- pip
- SQLite 3.0+
- 1 GB RAM mínimo
- 5 GB espacio en disco

## Despliegue con Docker

### Inicio Rápido

```bash
# 1. Clonar o descargar el repositorio
cd inteligencia_amenazas

# 2. Crear archivo de configuración (si no existe)
cp config/credentials.env.example config/credentials.env
# Editar config/credentials.env con tus credenciales

# 3. Iniciar contenedor
docker-compose up -d

# 4. Verificar que el servicio está corriendo
docker-compose logs -f web
```

La aplicación estará disponible en `http://localhost:9090`

### Construcción Manual de la Imagen

Si prefieres construir manualmente:

```bash
# Construir imagen
docker build -t inteligencia-amenazas:latest .

# Ejecutar contenedor
docker run -d \
  --name inteligencia-amenazas \
  -p 9090:9090 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/config:/app/config \
  -e LOG_LEVEL=INFO \
  inteligencia-amenazas:latest
```

### Variables de Entorno

```bash
# Nivel de logs (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO

# Modo Flask
FLASK_ENV=production
```

### Volúmenes

| Volumen | Descripción | Obligatorio |
|---------|-------------|------------|
| `/app/data` | Base de datos SQLite | Sí |
| `/app/logs` | Archivos de log | Sí |
| `/app/config` | Configuración y credenciales | Sí |

### Red

El contenedor crea una red interna `amenazas-network` para facilitar la comunicación entre servicios (si usas múltiples contenedores).

## Despliegue en Máquina Directa

### Instalación

```bash
# 1. Requisitos del sistema (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y python3.13 python3.13-venv python3-pip sqlite3

# 2. Crear entorno virtual
python3.13 -m venv .venv
source .venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Instalar modelos de traducción (opcional, ~120 MB)
python -c "import argostranslate.package as p; \
    p.update_package_index(); \
    [p.install_from_path(q.download()) for q in p.get_available_packages() \
     if q.from_code=='en' and q.to_code=='es']"

# 5. Crear directorios necesarios
mkdir -p data logs config/mapeos

# 6. Preparar configuración
cp config/credentials.env.example config/credentials.env
# Editar config/credentials.env con tus credenciales
```

### Inicio de la Aplicación

```bash
# Activar entorno virtual
source .venv/bin/activate

# Iniciar servidor web
python -m webui.app

# Iniciar ejecuciones programadas (en otra terminal)
python -m threatintel.scheduler
```

### Ejecuciones Programadas (Cron)

```bash
# Agregar a crontab del usuario (crontab -e)

# Recolección diaria (8:00 AM)
0 8 * * * cd /opt/inteligencia_amenazas && .venv/bin/python bin/ejecucion_diaria.py

# Informe mensual (primer día del mes, 10:00 AM)
0 10 1 * * cd /opt/inteligencia_amenazas && .venv/bin/python send_monthly_report.py

# Resumen semanal (todos los lunes, 9:00 AM)
0 9 * * 1 cd /opt/inteligencia_amenazas && .venv/bin/python bin/resumen_semanal.py
```

## Configuración

### Archivo de Credenciales

Ubicación: `config/credentials.env`

```env
# Base de datos
DB_PATH=data/threat_intel.db

# Correo SMTP (si usas SMTP)
SMTP_HOST=smtp.ejemplo.local
SMTP_PORT=587
SMTP_USER=alertas@ejemplo.local
SMTP_PASSWORD=contraseña_segura
SMTP_FROM=alertas@ejemplo.local
SMTP_USE_TLS=1

# Gmail OAuth (si usas Gmail)
# Requiere configuración previa en Google Cloud Console
GMAIL_CLIENT_ID=tu_client_id
GMAIL_CLIENT_SECRET=tu_client_secret
GMAIL_REFRESH_TOKEN=tu_refresh_token

# Destinatarios de correos
ALERT_EMAIL_TO=seguridad@ejemplo.local
REPORT_EMAIL_TO=directivo@ejemplo.local
ADMIN_EMAIL=admin@ejemplo.local

# OCS Inventory
OCS_SERVIDORES_HOST=ocs.ejemplo.local
OCS_SERVIDORES_PORT=3306
OCS_SERVIDORES_USER=ocs_user
OCS_SERVIDORES_PASSWORD=ocs_password
OCS_SERVIDORES_DB=ocsweb

OCS_EQUIPOS_HOST=ocs.ejemplo.local
OCS_EQUIPOS_PORT=3306
OCS_EQUIPOS_USER=ocs_user
OCS_EQUIPOS_PASSWORD=ocs_password
OCS_EQUIPOS_DB=ocsweb
```

### Inventarios Múltiples

Ubicación: `config/inventarios.yml`

```yaml
fuentes:
  # OCS Inventory (servidores)
  - nombre: servidores
    tipo: ocs_mysql
    prefijo_credenciales: OCS_SERVIDORES

  # OCS Inventory (equipos de cómputo)
  - nombre: equipos
    tipo: ocs_mysql
    prefijo_credenciales: OCS_EQUIPOS

  # CSV genérico (GLPI, CMDB, etc.)
  - nombre: glpi_activos
    tipo: csv
    ruta: data/importados/glpi_activos.csv
    mapeo: config/mapeos/glpi.yml
```

Véase `config/inventarios.yml.example` para documentación completa.

## Operación

### Acceso a la Aplicación

- **URL**: http://localhost:9090 (o tu dominio)
- **Usuario de demostración**: demo@ejemplo.local
- **Contraseña**: Admin123

### Logs en Docker

```bash
# Ver logs en tiempo real
docker-compose logs -f web

# Ver últimas 100 líneas
docker-compose logs --tail 100 web

# Ver logs de contenedor específico
docker logs inteligencia-amenazas-web
```

### Logs en Máquina Directa

Ubicación: `logs/webui.jsonl`

```bash
# Ver logs en tiempo real
tail -f logs/webui.jsonl

# Ver logs formateados (requiere jq)
tail -f logs/webui.jsonl | jq '.'
```

### Parar Contenedor

```bash
# Docker Compose
docker-compose down

# Docker manual
docker stop inteligencia-amenazas
docker rm inteligencia-amenazas
```

### Actualización

#### Con Docker

```bash
# Descargar actualizaciones
git pull origin main

# Reconstruir imagen
docker-compose build

# Reiniciar servicio
docker-compose up -d
```

#### En Máquina Directa

```bash
# Parar servicios
source .venv/bin/activate
# Ctrl+C para parar el servidor

# Actualizar código
git pull origin main

# Instalar nuevas dependencias (si es necesario)
pip install -r requirements.txt

# Reiniciar
python -m webui.app
```

## Solución de Problemas

### Contenedor no inicia

```bash
# Verificar logs
docker-compose logs web

# Problemas comunes:
# - Puerto 9090 ya está en uso: cambiar en docker-compose.yml
# - Permisos de directorios: sudo chown -R 1000:1000 data logs config
# - Base de datos corrupta: borrar data/threat_intel.db y reiniciar
```

### Conexión rechazada a OCS Inventory

```bash
# Verificar credenciales en config/credentials.env
# Verificar conectividad a servidor OCS
docker-compose exec web ping ocs.ejemplo.local

# Probar conexión directa
docker-compose exec web python bin/probar_ocs.py
```

### Alertas no se envían

1. Verificar configuración de correo en Ajustes
2. Verificar credenciales SMTP o Gmail
3. Revisar logs: `docker-compose logs web | grep -i mail`
4. Probar conexión SMTP: `docker-compose exec web telnet smtp.ejemplo.local 587`

### Base de datos llena

```bash
# Limpiar datos antiguos (conserva 400 días por defecto)
source .venv/bin/activate
python -c "from threatintel.jobs import limpiar_datos_antiguos; limpiar_datos_antiguos()"
```

### Rendimiento lento

1. Agregar índices de base de datos (ya incluidos en distribución)
2. Aumentar memoria del contenedor:
   ```yaml
   services:
     web:
       deploy:
         resources:
           limits:
             memory: 4G
   ```
3. Revisar cantidad de amenazas: usar filtros en la interfaz

## Monitoreo

### Health Check

Ambos métodos (Docker y máquina directa) incluyen un health check:

```bash
# Docker
docker ps

# Máquina directa
curl http://localhost:9090/

# Resultado esperado: 200 OK
```

### Métricas de Sistema

```bash
# Docker - uso de recursos
docker stats inteligencia-amenazas-web

# Máquina directa
top
```

## Seguridad

### HTTPS

La aplicación soporta HTTPS. Configurar en `config/credentials.env`:

```env
webui_https=1
tls_certificado_ruta=/ruta/al/certificado.pem
```

### Red

Para mayor seguridad:
1. No exponer puerto 9090 directamente a Internet
2. Usar nginx o Apache como proxy inverso
3. Implementar autenticación adicional (LDAP, OAuth)

## Respaldo y Recuperación

```bash
# Respaldar datos
docker-compose exec web tar czf backup-$(date +%Y%m%d).tar.gz data/

# O en máquina directa
tar czf backup-$(date +%Y%m%d).tar.gz data/

# Restaurar
tar xzf backup-20261116.tar.gz
```

## Contacto y Soporte

Para problemas o sugerencias, contacta al equipo de Seguridad de la Información.
