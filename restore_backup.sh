#!/bin/bash
# ================================================================
# SCRIPT DE RESTAURACIÓN - THREAT INTELLIGENCE SYSTEM
# ================================================================


# ----------------------------------------------------------------------
# Clave de cifrado del backup
# ----------------------------------------------------------------------
# La clave ya NO esta en este script. Antes estaba escrita en el codigo
# (permisos 775, legible por cualquier usuario) y ademas se imprimia en
# logs/backup.log, donde aparecia 17 veces: el criptograma viajaba junto a su
# clave, de modo que el cifrado no protegia nada.
CRED_FILE="/opt/inteligencia_amenazas/config/credentials.env"
BACKUP_PASSPHRASE="$(grep -m1 '^BACKUP_PASSPHRASE=' "$CRED_FILE" 2>/dev/null | cut -d= -f2-)"

if [ -z "$BACKUP_PASSPHRASE" ]; then
    echo "   ERROR: falta BACKUP_PASSPHRASE en $CRED_FILE"
    echo "   Generela con: openssl rand -base64 33"
    exit 1
fi
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  📦 RESTAURACIÓN DESDE BACKUP                             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Verificar argumento
if [ -z "$1" ]; then
    echo "❌ Error: Debes proporcionar la ruta del backup"
    echo ""
    echo "Uso: $0 /ruta/al/threat_intel_backup_YYYYMMDD_HHMMSS.tar.gz"
    echo ""
    echo "Backups disponibles:"
    echo ""
    ls -lh /opt/inteligencia_amenazas/backups/*.tar.gz 2>/dev/null | \
        awk '{print "   " $9 " (" $5 " - " $6 " " $7 " " $8 ")"}'
    
    if [ $? -ne 0 ]; then
        echo "   (ninguno encontrado)"
    fi
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ Error: Archivo de backup no encontrado: $BACKUP_FILE"
    exit 1
fi

echo "📦 Backup a restaurar: $(basename $BACKUP_FILE)"
echo "📅 Fecha: $(stat -c %y "$BACKUP_FILE" | cut -d'.' -f1)"
echo "📏 Tamaño: $(du -h "$BACKUP_FILE" | cut -f1)"
echo ""

read -p "¿Continuar con la restauración? (s/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Ss]$ ]]; then
    echo "❌ Restauración cancelada"
    exit 0
fi

# Crear directorio temporal
TEMP_DIR=$(mktemp -d)
echo ""
echo "📂 Extrayendo a: $TEMP_DIR"

# Extraer backup
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

if [ $? -ne 0 ]; then
    echo "❌ Error al extraer backup"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Encontrar carpeta extraída
EXTRACTED_DIR=$(find "$TEMP_DIR" -maxdepth 1 -type d -name "threat_intel_backup_*" | head -n1)

if [ -z "$EXTRACTED_DIR" ]; then
    echo "❌ Error: No se encontró el contenido del backup"
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo "✅ Backup extraído"
echo ""

# ================================================================
# RESTAURAR COMPONENTES
# ================================================================

BASE_DIR="/opt/inteligencia_amenazas"

# 1. Codigo
echo "📄 [1/7] Restaurando el codigo..."
if [ -d "$EXTRACTED_DIR/codigo" ]; then
    cp -r "$EXTRACTED_DIR/codigo"/* "$BASE_DIR/"
    chmod +x "$BASE_DIR"/*.sh 2>/dev/null
    chmod +x "$BASE_DIR"/*.py 2>/dev/null
    echo "   ✅ Codigo restaurado y permisos configurados"
else
    echo "   ⚠️  Este backup no tiene codigo (formato antiguo)"
fi

# 2. Configuración (desencriptar)
echo ""
echo "🔒 [2/7] Restaurando configuración..."
if [ -f "$EXTRACTED_DIR/config/credentials.env.enc" ]; then
    mkdir -p "$BASE_DIR/config"
    
    echo "   🔑 Desencriptando credentials.env..."
    BACKUP_PASSPHRASE="$BACKUP_PASSPHRASE" openssl enc -aes-256-cbc -d -pbkdf2 -iter 200000 \
        -in "$EXTRACTED_DIR/config/credentials.env.enc" \
        -out "$BASE_DIR/config/credentials.env" \
        -pass env:BACKUP_PASSPHRASE
    
    if [ $? -eq 0 ]; then
        chmod 600 "$BASE_DIR/config/credentials.env"
        echo "   ✅ credentials.env desencriptado"
    else
        echo "   ❌ Error al desencriptar credentials.env"
    fi
fi

# 3. Datos
echo ""
echo "💾 [3/7] Restaurando datos..."
if [ -d "$EXTRACTED_DIR/data" ]; then
    mkdir -p "$BASE_DIR/data"

    # La base de datos va aparte: sobrescribe la real, asi que pide
    # confirmacion explicita en vez de machacarla junto con los JSON sueltos.
    if [ -f "$EXTRACTED_DIR/data/threat_intel.db" ]; then
        echo "   ⚠️  Este backup incluye threat_intel.db, que REEMPLAZARIA la base de datos actual."
        read -p "   ¿Sobrescribir la base de datos actual? (s/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Ss]$ ]]; then
            cp "$EXTRACTED_DIR/data/threat_intel.db" "$BASE_DIR/data/threat_intel.db"
            echo "   ✅ Base de datos restaurada"
        else
            echo "   ⏭️  Base de datos omitida (se conserva la actual)"
        fi
    fi

    find "$EXTRACTED_DIR/data" -maxdepth 1 -type f ! -name "threat_intel.db" \
         -exec cp {} "$BASE_DIR/data/" \; 2>/dev/null
    COUNT=$(ls -1 "$BASE_DIR/data" 2>/dev/null | wc -l)
    echo "   ✅ $COUNT archivos de datos restaurados"
fi

# 4. Informes
echo ""
echo "📊 [4/7] Restaurando informes..."
if [ -d "$EXTRACTED_DIR/reports" ]; then
    mkdir -p "$BASE_DIR/reports"
    cp -r "$EXTRACTED_DIR/reports"/* "$BASE_DIR/reports/" 2>/dev/null
    COUNT=$(ls -1 "$BASE_DIR/reports"/*.docx 2>/dev/null | wc -l)
    if [ $COUNT -gt 0 ]; then
        echo "   ✅ $COUNT informes Word restaurados"
    fi
fi

# 5. Logs
echo ""
echo "📝 [5/7] Restaurando logs..."
if [ -d "$EXTRACTED_DIR/logs" ]; then
    mkdir -p "$BASE_DIR/logs"
    cp -r "$EXTRACTED_DIR/logs"/* "$BASE_DIR/logs/" 2>/dev/null
    COUNT=$(ls -1 "$BASE_DIR/logs" 2>/dev/null | wc -l)
    echo "   ✅ $COUNT archivos de logs restaurados"
fi

# 6. Modelo ArgosTranslate
echo ""
echo "🤖 [6/7] Restaurando modelo de traducción..."
if [ -d "$EXTRACTED_DIR/argos_model" ]; then
    MODEL_DIR="$HOME/.local/share/argos-translate/packages"
    mkdir -p "$MODEL_DIR"
    cp "$EXTRACTED_DIR/argos_model"/*.argosmodel "$MODEL_DIR/" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "   ✅ Modelo ArgosTranslate restaurado"
    else
        echo "   ⚠️  Modelo no encontrado en backup (se puede re-descargar)"
    fi
else
    echo "   ℹ️  Modelo no incluido en backup (se puede re-descargar)"
fi

# 7. Crontab
echo ""
echo "⏰ [7/7] Restaurando crontab..."
if [ -f "$EXTRACTED_DIR/crontab_backup.txt" ]; then
    echo "   Contenido del crontab a restaurar:"
    echo ""
    cat "$EXTRACTED_DIR/crontab_backup.txt" | grep -v "^#" | grep -v "^$"
    echo ""
    read -p "   ¿Restaurar crontab? (s/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        crontab "$EXTRACTED_DIR/crontab_backup.txt"
        echo "   ✅ Crontab restaurado"
    else
        echo "   ⏭️  Crontab omitido"
    fi
fi

# Limpiar temporal
rm -rf "$TEMP_DIR"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✅ RESTAURACIÓN COMPLETADA                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 PASOS POST-RESTAURACIÓN:"
echo ""
echo "1. Verificar dependencias Python:"
echo "   cd $BASE_DIR"
echo "   pip install -r requirements.txt"
echo ""
echo "2. Probar traducción:"
echo "   .venv/bin/python -m unittest discover -s tests"
echo ""
echo "3. Probar recolección:"
echo "   .venv/bin/python bin/ejecucion_diaria.py --dry-run"
echo ""
echo "4. Verificar credenciales SMTP:"
echo "   cat config/credentials.env | grep SMTP"
echo ""
echo "5. Probar sistema completo:"
echo "   .venv/bin/python bin/ejecucion_diaria.py"
echo ""

