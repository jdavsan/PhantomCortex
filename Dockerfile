# PhantomCortex Dockerfile
# Multi-stage build for optimized image size

# Stage 1: Build stage
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Download translation model
RUN pip install --no-cache-dir --user argostranslate && \
    python -c "import argostranslate.package; \
    argostranslate.package.update_package_index(); \
    available = argostranslate.package.get_available_packages(); \
    en_es = next((p for p in available if p.from_code == 'en' and p.to_code == 'es'), None); \
    if en_es: argostranslate.package.install_from_path(en_es.download())"

# Stage 2: Runtime stage
FROM python:3.11-slim

# Set labels
LABEL maintainer="PhantomCortex Community"
LABEL description="Open Source Cyber Threat Intelligence Platform"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/root/.local/bin:$PATH

# Create app user
RUN useradd -m -u 1000 phantomcortex && \
    mkdir -p /app /data /logs /reports && \
    chown -R phantomcortex:phantomcortex /app /data /logs /reports

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application files
COPY --chown=phantomcortex:phantomcortex core/ ./core/
COPY --chown=phantomcortex:phantomcortex modules/ ./modules/
COPY --chown=phantomcortex:phantomcortex scripts/ ./scripts/
COPY --chown=phantomcortex:phantomcortex config/ ./config/
COPY --chown=phantomcortex:phantomcortex requirements.txt .

# Create necessary directories
RUN mkdir -p data logs reports backups && \
    chmod +x scripts/*.sh scripts/*.py

# Switch to app user
USER phantomcortex

# Health check
HEALTHCHECK --interval=5m --timeout=3s \
    CMD python -c "import sys; sys.exit(0)"

# Default command
CMD ["python", "core/collector.py"]
