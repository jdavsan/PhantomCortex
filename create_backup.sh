#!/bin/bash
# ================================================================
# SCRIPT DE BACKUP COMPLETO - SISTEMA DE THREAT INTELLIGENCE
# Versión actualizada con ruta correcta del modelo ArgosTranslate
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
BACKUP_DIR="/opt/inteligencia_amenazas/backups"
FECHA=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="threat_intel_backup_${FECHA}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  📦 BACKUP COMPLETO - THREAT INTELLIGENCE SYSTEM          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Destino: ${BACKUP_PATH}"
echo ""

# Crear directorio de backup
mkdir -p "$BACKUP_PATH"

# ================================================================
# 1. CODIGO DEL SISTEMA
# ================================================================
# Se respalda el arbol COMPLETO del sistema nuevo. La version anterior de este
# script listaba a mano los 10 ficheros del sistema viejo, asi que tras la
# reescritura de septiembre de 2026 el backup no contenia threatintel/, webui/,
# bin/ ni tests/: un backup que no habria permitido restaurar nada.
echo "[1/8] Respaldando el codigo del sistema..."

mkdir -p "$BACKUP_PATH/codigo"
CODIGO_OK=0

# Paquetes y directorios de codigo, con su estructura
for dir in threatintel webui bin tests docs; do
    if [ -d "/opt/inteligencia_amenazas/$dir" ]; then
        cp -r "/opt/inteligencia_amenazas/$dir" "$BACKUP_PATH/codigo/" 2>/dev/null \
            && CODIGO_OK=$((CODIGO_OK+1))
    fi
done

# Ficheros sueltos de la raiz que hacen falta para reconstruir
for f in requirements.txt README.md .gitignore \
         create_backup.sh restore_backup.sh; do
    [ -f "/opt/inteligencia_amenazas/$f" ] \
        && cp "/opt/inteligencia_amenazas/$f" "$BACKUP_PATH/codigo/" 2>/dev/null
done

# Los scripts del sistema anterior, por si hay que consultarlos
if [ -d "/opt/inteligencia_amenazas/obsoleto" ]; then
    cp -r "/opt/inteligencia_amenazas/obsoleto" "$BACKUP_PATH/codigo/" 2>/dev/null
fi

# Limpiar cache de Python del respaldo: no aporta y abulta
find "$BACKUP_PATH/codigo" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
find "$BACKUP_PATH/codigo" -name "*.pyc" -delete 2>/dev/null

N_PY=$(find "$BACKUP_PATH/codigo" -name "*.py" | wc -l)
N_HTML=$(find "$BACKUP_PATH/codigo" -name "*.html" | wc -l)
echo "   OK  $CODIGO_OK directorios, $N_PY ficheros .py, $N_HTML plantillas"

# La unidad de systemd de la interfaz
if [ -f /etc/systemd/system/threat-intel-webui.service ]; then
    mkdir -p "$BACKUP_PATH/systemd"
    cp /etc/systemd/system/threat-intel-webui.service "$BACKUP_PATH/systemd/" 2>/dev/null
    echo "   OK  unidad systemd de la interfaz"
fi

# ================================================================
# 2. CONFIGURACIÓN (ENCRIPTADA)
# ================================================================
echo ""
echo "🔒 [2/8] Respaldando configuración (ENCRIPTADA)..."

mkdir -p "$BACKUP_PATH/config"

if [ -f "/opt/inteligencia_amenazas/config/credentials.env" ]; then
    BACKUP_PASSPHRASE="$BACKUP_PASSPHRASE" openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 \
        -in "/opt/inteligencia_amenazas/config/credentials.env" \
        -out "$BACKUP_PATH/config/credentials.env.enc" \
        -pass env:BACKUP_PASSPHRASE
    
    if [ $? -eq 0 ]; then
        echo "   ✅ credentials.env (ENCRIPTADO con AES-256)"
    else
        echo "   ❌ Error encriptando credentials.env"
    fi
else
    echo "   ⚠️  credentials.env (no encontrado)"
fi

# ================================================================
# 3. DATOS OPERATIVOS
# ================================================================
echo ""
echo "💾 [3/8] Respaldando datos operativos..."

if [ -d "/opt/inteligencia_amenazas/data" ]; then
    mkdir -p "$BACKUP_PATH/data"

    # Base de datos: con el comando de respaldo en linea de SQLite, no con cp.
    # cp copiaria el fichero mientras la aplicacion puede tener escrituras a
    # medias (WAL); .backup toma una copia consistente aunque el servicio este
    # corriendo. Sin esto, el backup nunca contuvo la base de datos real.
    DB_FILE="/opt/inteligencia_amenazas/data/threat_intel.db"
    if [ -f "$DB_FILE" ]; then
        sqlite3 "$DB_FILE" ".backup '$BACKUP_PATH/data/threat_intel.db'"
        if [ $? -eq 0 ]; then
            DB_SIZE=$(du -h "$BACKUP_PATH/data/threat_intel.db" | cut -f1)
            echo "   ✅ Base de datos ($DB_SIZE)"
        else
            echo "   ❌ Error respaldando la base de datos"
        fi
    else
        echo "   ⚠️  threat_intel.db no encontrada"
    fi

    for file in seen_threats_this_month.json monthly_threats_*.json \
                daily_collected_threats.json analyzed_threats.json \
                last_execution.json; do
        find "/opt/inteligencia_amenazas/data" -name "$file" \
             -exec cp {} "$BACKUP_PATH/data/" \; 2>/dev/null
    done

    COUNT=$(ls -1 "$BACKUP_PATH/data" 2>/dev/null | wc -l)
    echo "   ✅ $COUNT archivos de datos respaldados (incluye la base de datos)"
else
    echo "   ⚠️  Directorio data/ no encontrado"
fi

# ================================================================
# 4. INFORMES GENERADOS
# ================================================================
echo ""
echo "📊 [4/8] Respaldando informes mensuales..."

if [ -d "/opt/inteligencia_amenazas/reports" ]; then
    mkdir -p "$BACKUP_PATH/reports"
    cp "/opt/inteligencia_amenazas/reports"/*.docx "$BACKUP_PATH/reports/" 2>/dev/null
    
    COUNT=$(ls -1 "$BACKUP_PATH/reports"/*.docx 2>/dev/null | wc -l)
    if [ $COUNT -gt 0 ]; then
        echo "   ✅ $COUNT informes Word respaldados"
    else
        echo "   ⚠️  No hay informes Word para respaldar"
    fi
fi

# ================================================================
# 5. CRONTAB
# ================================================================
echo ""
echo "⏰ [5/8] Respaldando configuración de cron..."

crontab -l > "$BACKUP_PATH/crontab_backup.txt" 2>/dev/null
if [ $? -eq 0 ]; then
    CRON_LINES=$(cat "$BACKUP_PATH/crontab_backup.txt" | grep -v "^#" | grep -v "^$" | wc -l)
    echo "   ✅ Crontab guardado ($CRON_LINES tareas programadas)"
else
    echo "   ⚠️  No hay crontab configurado"
fi

# ================================================================
# 6. LOGS RECIENTES (últimos 30 días)
# ================================================================
echo ""
echo "📝 [6/8] Respaldando logs recientes..."

if [ -d "/opt/inteligencia_amenazas/logs" ]; then
    mkdir -p "$BACKUP_PATH/logs"
    find "/opt/inteligencia_amenazas/logs" -name "*.log" -mtime -30 \
         -exec cp {} "$BACKUP_PATH/logs/" \; 2>/dev/null
    
    COUNT=$(ls -1 "$BACKUP_PATH/logs" 2>/dev/null | wc -l)
    echo "   ✅ $COUNT archivos de logs (últimos 30 días)"
else
    echo "   ⚠️  No hay logs para respaldar"
fi

# ================================================================
# 7. MODELO ARGOSTRANSLATE (CARPETA COMPLETA)
# ================================================================
echo ""
echo "🤖 [7/8] Respaldando modelo de traducción ArgosTranslate..."

MODEL_DIR="$HOME/.local/share/argos-translate/packages/en_es"

if [ -d "$MODEL_DIR" ]; then
    mkdir -p "$BACKUP_PATH/argos_model"
    
    # Copiar toda la carpeta en_es
    cp -r "$MODEL_DIR" "$BACKUP_PATH/argos_model/"
    
    if [ $? -eq 0 ]; then
        MODEL_SIZE=$(du -sh "$BACKUP_PATH/argos_model" | cut -f1)
        echo "   ✅ Modelo ArgosTranslate EN→ES ($MODEL_SIZE)"
    else
        echo "   ❌ Error copiando modelo"
    fi
else
    echo "   ⚠️  Modelo ArgosTranslate no encontrado"
    echo "      Ubicación esperada: $MODEL_DIR"
    echo "      Se puede re-descargar después de restaurar"
fi

# ================================================================
# 8. COMPRIMIR BACKUP
# ================================================================
echo ""
echo "🗜️  [8/8] Comprimiendo backup..."

cd "$BACKUP_DIR"
tar -czf "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}/" 2>/dev/null

if [ $? -eq 0 ]; then
    rm -rf "${BACKUP_NAME}/"
    
    BACKUP_SIZE=$(du -h "${BACKUP_NAME}.tar.gz" | cut -f1)
    
    echo "   ✅ Backup comprimido: ${BACKUP_NAME}.tar.gz"
    echo "   📦 Tamaño total: $BACKUP_SIZE"
else
    echo "   ❌ Error al comprimir"
    exit 1
fi

# ================================================================
# 9. LIMPIAR BACKUPS ANTIGUOS (>30 días)
# ================================================================
echo ""
echo "🧹 Limpiando backups antiguos (>30 días)..."

DELETED=$(find "$BACKUP_DIR" -name "threat_intel_backup_*.tar.gz" -mtime +30 -delete -print 2>/dev/null | wc -l)
if [ $DELETED -gt 0 ]; then
    echo "   ✅ $DELETED backups antiguos eliminados"
else
    echo "   ✅ No hay backups antiguos para eliminar"
fi

# ================================================================
# 10. RESUMEN FINAL
# ================================================================
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✅ BACKUP COMPLETADO EXITOSAMENTE                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📍 Ubicación: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
echo "📦 Tamaño: $BACKUP_SIZE"
echo "📅 Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
echo "📋 Contenido respaldado:"
echo "   OK  codigo completo: threatintel/, webui/, bin/, tests/, docs/"
echo "   ✅ Configuración SMTP (encriptada)"
echo "   ✅ Datos operativos del mes actual"
echo "   ✅ Informes Word generados"
echo "   ✅ Configuración de cron"
echo "   ✅ Logs de últimos 30 días"
echo "   ✅ Modelo ArgosTranslate EN→ES"
echo ""
echo "🔐 SEGURIDAD:"
echo "   • credentials.env encriptado con AES-256-CBC"
echo "   • Clave de cifrado: definida en config/credentials.env (BACKUP_PASSPHRASE)"
echo "   • La clave NO se imprime aqui a proposito: este log es legible"
echo "   • Guarde este backup en ubicación segura externa"
echo ""
echo "🔄 RESTAURACIÓN:"
echo "   ./restore_backup.sh ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
echo ""

# Registro histórico
LOG_FILE="$BACKUP_DIR/backup_history.log"
echo "$(date '+%Y-%m-%d %H:%M:%S') | SUCCESS | ${BACKUP_NAME}.tar.gz | $BACKUP_SIZE" >> "$LOG_FILE"

