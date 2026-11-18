# Dockerfile para Inteligencia de Amenazas
# Usa Python 3.13 en Alpine Linux para minimizar la imagen
FROM python:3.13-alpine

# Metadatos
LABEL maintainer="Inteligencia de Amenazas Team"
LABEL description="Sistema de Inteligencia de Amenazas - Recolección y Alertamiento"

# Variables de entorno
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libxml2-dev \
    libxslt-dev \
    openssl-dev \
    libffi-dev \
    sqlite \
    curl

# Crear usuario no-root para ejecutar la aplicación
RUN addgroup -S appuser && adduser -S appuser -G appuser

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código de la aplicación
COPY --chown=appuser:appuser . .

# Crear directorios necesarios
RUN mkdir -p /app/data /app/logs /app/config/mapeos && \
    chown -R appuser:appuser /app

# Cambiar a usuario no-root
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/ || exit 1

# Puerto de la aplicación web
EXPOSE 9090

# Comando de inicio
CMD ["python", "-m", "webui.app"]
