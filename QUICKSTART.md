# 🚀 INICIO RÁPIDO - THREAT INTELLIGENCE SYSTEM

## ⚡ Instalación en 5 Minutos

### 1️⃣ Descomprimir el archivo

```bash
# Descomprimir
tar -xzf inteligencia_amenazas_completo.tar.gz

# Entrar al directorio
cd inteligencia_amenazas_completo
```

### 2️⃣ Ejecutar instalación automática

```bash
# Hacer ejecutable el instalador
chmod +x INSTALL.sh

# Ejecutar instalación
./INSTALL.sh
```

El script instalará automáticamente:
- ✅ Ollama
- ✅ Modelo Llama 3.1 8B
- ✅ Todas las dependencias Python
- ✅ Configuración de directorios
- ✅ Validación del sistema

### 3️⃣ Configurar credenciales

```bash
# Editar archivo de credenciales
nano config/credentials.env
```

**IMPORTANTE**: Completar las siguientes variables:

```env
# SMTP (Correo)
SMTP_SERVER=mail.ejemplo.local
SMTP_PORT=587
SMTP_USERNAME=threat.intelligence@ejemplo.local
SMTP_PASSWORD=TU_CONTRASEÑA_AQUI

# Destinatarios
ALERT_EMAIL_TO=soc@ejemplo.local,ciso@ejemplo.local
REPORT_EMAIL_TO=ciso@ejemplo.local,cto@ejemplo.local

# Admin
ADMIN_EMAIL=administrador.sistemas@ejemplo.local
```

### 4️⃣ Validar instalación

```bash
# Activar entorno virtual
source venv/bin/activate

# Validar sistema
python scripts/validate_system.py
```

### 5️⃣ Ejecutar prueba inicial

```bash
# Modo prueba (no envía emails)
python src/inteligencia_amenazas/main.py --test
```

---

## 🎯 COMANDOS PRINCIPALES

### Con Makefile (Recomendado)

```bash
# Ver todos los comandos
make help

# Ejecutar tests
make test

# Validar sistema
make validate

# Modo prueba
make run-test

# Recolección diaria
make run-daily

# Informe mensual
make run-monthly

# Modo daemon (continuo)
make run-daemon
```

### Directamente con Python

```bash
# Activar entorno virtual primero
source venv/bin/activate

# Modo prueba
python src/inteligencia_amenazas/main.py --test

# Recolección diaria (una vez)
python src/inteligencia_amenazas/main.py --once daily

# Informe mensual (una vez)
python src/inteligencia_amenazas/main.py --once monthly

# Modo daemon (ejecución continua)
python src/inteligencia_amenazas/main.py --daemon

# Ver estado
python src/inteligencia_amenazas/main.py --status
```

---

## 📁 ESTRUCTURA DEL PROYECTO

```
inteligencia_amenazas_completo/
├── config/                      # Configuración
│   ├── agents.yaml              # Definición de agentes
│   ├── tasks.yaml               # Definición de tareas
│   ├── sources.json             # Fuentes RSS/API
│   ├── technologies.json        # Inventario de tecnologías
│   └── credentials.env          # Credenciales (EDITAR)
│
├── src/inteligencia_amenazas/   # Código fuente
│   ├── crew.py                  # Orquestación de agentes
│   ├── main.py                  # Punto de entrada
│   └── tools/                   # Herramientas especializadas
│       ├── rss_parser.py
│       ├── api_client.py
│       ├── email_sender.py
│       ├── docx_generator.py
│       └── web_scraper.py
│
├── tests/                       # Tests (90+)
├── scripts/                     # Scripts de utilidad
├── data/                        # Datos generados
├── reports/                     # Informes generados
└── logs/                        # Logs del sistema
```

---

## 🔧 SOLUCIÓN RÁPIDA DE PROBLEMAS

### Ollama no responde

```bash
sudo systemctl restart ollama
ollama list
```

### Python no encuentra módulos

```bash
# Asegúrate de estar en el entorno virtual
source venv/bin/activate

# Reinstalar dependencias
pip install -r requirements.txt
```

### Credenciales incorrectas

```bash
# Verificar archivo
cat config/credentials.env

# Editar
nano config/credentials.env

# Validar
python scripts/validate_system.py
```

---

## 📚 DOCUMENTACIÓN COMPLETA

- **README.md** - Documentación principal del proyecto
- **Documentacion/GUIA_COMPLETA_INSTALACION.md** - Guía detallada de instalación
- **Documentacion/GUIA_TESTING_VALIDACION.md** - Guía de testing

---

## 💡 EJEMPLOS DE USO

### Ejemplo 1: Primera ejecución

```bash
# 1. Instalar
./INSTALL.sh

# 2. Configurar
nano config/credentials.env

# 3. Probar
source venv/bin/activate
make run-test
```

### Ejemplo 2: Producción

```bash
# Activar entorno
source venv/bin/activate

# Ejecutar en modo daemon
make run-daemon

# O configurar como servicio systemd
# (ver GUIA_COMPLETA_INSTALACION.md)
```

---

## 🆘 SOPORTE

**Email**: 
- soc@ejemplo.local
- administrador.sistemas@ejemplo.local

**Documentación**: Ver carpeta `Documentacion/`

---

## ✅ CHECKLIST POST-INSTALACIÓN

- [ ] INSTALL.sh ejecutado exitosamente
- [ ] credentials.env configurado
- [ ] `make validate` pasa sin errores
- [ ] `make test` ejecuta correctamente
- [ ] `make run-test` funciona en modo prueba
- [ ] Emails de prueba llegan correctamente

---

**¡Sistema listo para producción!** 🎉
