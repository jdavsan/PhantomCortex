#!/bin/sh
# Entrypoint script para contenedor Docker de Inteligencia de Amenazas

set -e

# Importar variables del archivo .env si existe
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Crear directorios necesarios
mkdir -p data logs config/mapeos

# Inicializar base de datos si no existe
if [ ! -f data/threat_intel.db ]; then
    echo "Inicializando base de datos..."
    python -c "from threatintel import db; db.init_db()"
fi

# Ejecutar migraciones o preparación si es necesario
echo "Preparando aplicación..."

# Iniciar la aplicación
exec python -m webui.app
