#!/bin/bash
# PhantomCortex - Daily Execution Script
# Collects threats, analyzes them, and sends alerts

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Change to project directory
cd "$PROJECT_DIR"

# Logging
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="logs/daily_${TIMESTAMP}.log"
mkdir -p logs

echo "================================================================" | tee -a "$LOG_FILE"
echo "🛡️  PhantomCortex - Daily Threat Intelligence Collection" | tee -a "$LOG_FILE"
echo "================================================================" | tee -a "$LOG_FILE"
echo "Started: $(date)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    echo -e "${BLUE}📦 Activating virtual environment...${NC}" | tee -a "$LOG_FILE"
    source venv/bin/activate
else
    echo -e "${YELLOW}⚠️  No virtual environment found${NC}" | tee -a "$LOG_FILE"
fi

# Step 1: Collect threats from RSS feeds
echo -e "${BLUE}🔍 Step 1: Collecting threats from RSS feeds...${NC}" | tee -a "$LOG_FILE"
if python core/collector.py >> "$LOG_FILE" 2>&1; then
    echo -e "${GREEN}✅ Collection complete${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${RED}❌ Collection failed${NC}" | tee -a "$LOG_FILE"
    exit 1
fi

# Step 2: Translate threat descriptions (if translation module exists)
if [ -f "modules/translator.py" ]; then
    echo -e "${BLUE}🌐 Step 2: Translating threat descriptions...${NC}" | tee -a "$LOG_FILE"
    if python modules/translator.py >> "$LOG_FILE" 2>&1; then
        echo -e "${GREEN}✅ Translation complete${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${YELLOW}⚠️  Translation failed, continuing...${NC}" | tee -a "$LOG_FILE"
    fi
fi

# Step 3: Send email alerts (if alerting module exists)
if [ -f "modules/alerting.py" ]; then
    echo -e "${BLUE}📧 Step 3: Sending email alerts...${NC}" | tee -a "$LOG_FILE"
    if python modules/alerting.py >> "$LOG_FILE" 2>&1; then
        echo -e "${GREEN}✅ Alerts sent${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${YELLOW}⚠️  Alert sending failed${NC}" | tee -a "$LOG_FILE"
    fi
fi

# Step 4: Generate summary
echo "" | tee -a "$LOG_FILE"
echo -e "${BLUE}📊 Summary:${NC}" | tee -a "$LOG_FILE"

# Count threats in daily file
if [ -f "data/daily_threats.json" ]; then
    THREAT_COUNT=$(python -c "import json; data=json.load(open('data/daily_threats.json')); print(data.get('count', 0))" 2>/dev/null || echo "0")
    echo "   Threats collected today: $THREAT_COUNT" | tee -a "$LOG_FILE"
fi

# Show disk usage
DISK_USAGE=$(du -sh data/ 2>/dev/null | cut -f1 || echo "N/A")
echo "   Data directory size: $DISK_USAGE" | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "================================================================" | tee -a "$LOG_FILE"
echo -e "${GREEN}✅ Daily execution complete!${NC}" | tee -a "$LOG_FILE"
echo "================================================================" | tee -a "$LOG_FILE"
echo "Finished: $(date)" | tee -a "$LOG_FILE"
echo "Log saved to: $LOG_FILE" | tee -a "$LOG_FILE"

# Cleanup old logs (keep last 30 days)
find logs/ -name "daily_*.log" -mtime +30 -delete 2>/dev/null || true

exit 0
