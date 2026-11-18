"""Acceso a SQLite. Esquema, migraciones y helpers de conexion.

Toda escritura pasa por aqui para que el esquema sea la unica fuente de verdad.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Optional

from .paths import DB_FILE, ensure_dirs

SCHEMA_VERSION = 16

# --------------------------------------------------------------------------
# ESQUEMA
# --------------------------------------------------------------------------
_SCHEMA_BASE = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ---------------------------------------------------------------- fuentes
CREATE TABLE IF NOT EXISTS sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    slug        TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    url         TEXT    NOT NULL,
    kind        TEXT    NOT NULL DEFAULT 'rss',     -- rss | kev_json | nvd_api | epss_api
    category    TEXT    NOT NULL DEFAULT 'news',    -- government|vendor|news|blog|database|exploits
    priority    TEXT    NOT NULL DEFAULT 'medium',  -- critical|high|medium|low
    enabled     INTEGER NOT NULL DEFAULT 1,
    timeout_s   INTEGER NOT NULL DEFAULT 30,
    notes       TEXT,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS source_health (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id   INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    checked_at  TEXT    NOT NULL,
    ok          INTEGER NOT NULL,
    http_status INTEGER,
    entries     INTEGER NOT NULL DEFAULT 0,
    accepted    INTEGER NOT NULL DEFAULT 0,
    latency_ms  INTEGER,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_health_source  ON source_health(source_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_health_checked ON source_health(checked_at DESC);

-- ------------------------------------------------------- inventario tecnico
CREATE TABLE IF NOT EXISTS technologies (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    slug              TEXT    NOT NULL UNIQUE,
    name              TEXT    NOT NULL,
    vendor            TEXT,
    category          TEXT    NOT NULL DEFAULT 'aplicacion',
    version_installed TEXT,
    version_latest    TEXT,
    criticality       TEXT    NOT NULL DEFAULT 'medium',  -- critical|high|medium|low
    systems_count     INTEGER NOT NULL DEFAULT 0,
    exposure          TEXT    NOT NULL DEFAULT 'interna', -- internet|dmz|interna
    cpe               TEXT,
    owner             TEXT,
    notes             TEXT,
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL,
    -- v4: lo que OCS Inventory dice de la tecnologia (activos reales y versiones)
    activos_ocs       INTEGER,
    versiones_ocs     TEXT,
    ocs_actualizado_at TEXT
);

-- Alias de busqueda. is_exclusion=1 => si aparece, DESCARTA el match.
CREATE TABLE IF NOT EXISTS tech_aliases (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    technology_id    INTEGER NOT NULL REFERENCES technologies(id) ON DELETE CASCADE,
    alias            TEXT    NOT NULL,
    match_mode       TEXT    NOT NULL DEFAULT 'word',  -- word|phrase|regex
    is_exclusion     INTEGER NOT NULL DEFAULT 0,
    context_required TEXT,                             -- JSON array: al menos uno debe aparecer
    UNIQUE(technology_id, alias, is_exclusion)
);

-- ---------------------------------------------------------------- amenazas
CREATE TABLE IF NOT EXISTS threats (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint        TEXT    NOT NULL UNIQUE,
    cve                TEXT,
    title_en           TEXT    NOT NULL,
    title_es           TEXT,
    summary_en         TEXT,
    summary_es         TEXT,
    severity           TEXT    NOT NULL DEFAULT 'Medium',
    severity_source    TEXT    NOT NULL DEFAULT 'heuristic', -- nvd|kev|vector|heuristic
    cvss_score         REAL,
    cvss_vector        TEXT,
    cvss_version       TEXT,
    epss_score         REAL,
    in_kev             INTEGER NOT NULL DEFAULT 0,
    kev_due_date       TEXT,
    published_at       TEXT,
    first_seen_at      TEXT    NOT NULL,
    last_seen_at       TEXT    NOT NULL,
    times_seen         INTEGER NOT NULL DEFAULT 1,
    impact_es          TEXT,
    remediation_es     TEXT,
    translation_engine TEXT    NOT NULL DEFAULT 'none',      -- none|argos|ollama
    enriched_at        TEXT,
    month              TEXT    NOT NULL,
    alerted_at         TEXT,
    relevance          REAL    NOT NULL DEFAULT 0,
    raw_json           TEXT,
    -- Gestion (v3): estado operativo y trazabilidad del filtro de alertas
    estado             TEXT    NOT NULL DEFAULT 'nueva',   -- nueva|en_analisis|mitigada|aceptada|descartada|falso_positivo
    estado_at          TEXT,
    estado_por         TEXT,
    estado_motivo      TEXT,
    digest_at          TEXT,                               -- incluida en el resumen semanal
    alert_skip_reason  TEXT,                               -- ultimo motivo por el que NO se alerto
    descripcion_origen TEXT,                               -- v7: nvd|cve.org|msrc|fuente|sin_dato
    descripcion_buscada_at TEXT,                           -- v7: cuando se busco la descripcion real
    alert_skip_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_threats_month  ON threats(month);
CREATE INDEX IF NOT EXISTS idx_threats_cve    ON threats(cve);
CREATE INDEX IF NOT EXISTS idx_threats_sev    ON threats(severity, month);
CREATE INDEX IF NOT EXISTS idx_threats_alert  ON threats(alerted_at);
CREATE INDEX IF NOT EXISTS idx_threats_seen   ON threats(first_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_estado ON threats(estado);

CREATE TABLE IF NOT EXISTS threat_sources (
    threat_id INTEGER NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    url       TEXT    NOT NULL,
    seen_at   TEXT    NOT NULL,
    PRIMARY KEY (threat_id, source_id, url)
);

CREATE TABLE IF NOT EXISTS threat_technologies (
    threat_id        INTEGER NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
    technology_id    INTEGER NOT NULL REFERENCES technologies(id) ON DELETE CASCADE,
    matched_alias    TEXT,
    confidence       REAL    NOT NULL DEFAULT 1.0,
    version_verdict  TEXT    NOT NULL DEFAULT 'unknown',  -- affected|not_affected|unknown
    version_evidence TEXT,
    PRIMARY KEY (threat_id, technology_id)
);

-- ------------------------------------------------------------ credenciales
CREATE TABLE IF NOT EXISTS credentials_meta (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    key                   TEXT    NOT NULL UNIQUE,   -- 'smtp_password'
    rotated_at            TEXT    NOT NULL,
    rotation_days         INTEGER NOT NULL DEFAULT 30,
    last_verified_at      TEXT,
    last_verify_ok        INTEGER,
    last_verify_error     TEXT,
    consecutive_failures  INTEGER NOT NULL DEFAULT 0,
    notified_stages       TEXT    NOT NULL DEFAULT '[]',
    updated_at            TEXT    NOT NULL
);

-- --------------------------------------------------------------- ejecucion
CREATE TABLE IF NOT EXISTS executions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT    NOT NULL,   -- daily|monthly|health|smtp_verify|enrich
    started_at      TEXT    NOT NULL,
    finished_at     TEXT,
    status          TEXT    NOT NULL DEFAULT 'running', -- running|success|partial|failed
    sources_ok      INTEGER NOT NULL DEFAULT 0,
    sources_failed  INTEGER NOT NULL DEFAULT 0,
    threats_new     INTEGER NOT NULL DEFAULT 0,
    threats_alerted INTEGER NOT NULL DEFAULT 0,
    log_path        TEXT,
    error           TEXT,
    detail_json     TEXT
);
CREATE INDEX IF NOT EXISTS idx_exec_kind ON executions(kind, started_at DESC);

-- -------------------------------------------------------------------- GUI
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'admin',  -- admin|viewer
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL,
    last_login_at TEXT,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT,
    must_change   INTEGER NOT NULL DEFAULT 0,
    -- v6: segundo factor (TOTP). El secreto se guarda cifrado con la clave de la
    -- aplicacion; los codigos de recuperacion, como hashes de un solo uso.
    totp_secret        TEXT,
    totp_activado_at   TEXT,
    totp_recuperacion  TEXT,
    totp_fallos        INTEGER NOT NULL DEFAULT 0,
    -- v6: recorrido guiado completo (una sola invitacion por usuario, en cualquier navegador)
    -- v9: nombre de la persona; es lo que se muestra en la interfaz en lugar del correo
    nombre             TEXT,
    tour_estado        TEXT,                -- NULL (pendiente) | empezado | rechazado | completado
    tour_at            TEXT,
    -- v11 (2026-09-08): rotacion de credenciales. Fecha del ultimo cambio de contrasena;
    -- pasados «password_max_dias» dias la cuenta entra en el cambio obligatorio.
    password_changed_at TEXT
);

-- v11 (2026-09-08): historial de contrasenas (solo hashes bcrypt) para impedir reutilizar
-- cualquiera de las ultimas «password_historial» (12 por defecto). Se recorta al cambiar.
CREATE TABLE IF NOT EXISTS password_historial (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    cambiado_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_password_hist_user ON password_historial(username, id DESC);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    username  TEXT,
    action    TEXT NOT NULL,
    entity    TEXT,
    entity_id TEXT,
    detail    TEXT,
    ip        TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT NOT NULL
);

-- Logo de la organizacion (v16, 2026-11-17): una sola fila (id=1). Va en la base, no
-- en un fichero bajo data/, para que viajar con ella sea automatico: el backup, la
-- restauracion y una copia de la base para pruebas ya se llevan esta tabla sin tener
-- que acordarse de un fichero aparte. El contenido se valida con Pillow antes de
-- guardarse (formato real, no la extension; limite de tamano y de dimension) en
-- webui/vistas/ajustes.py.
CREATE TABLE IF NOT EXISTS marca (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    logo_datos      BLOB NOT NULL,
    logo_tipo       TEXT NOT NULL,   -- image/png | image/jpeg
    logo_nombre     TEXT,            -- nombre original del fichero, solo para mostrarlo
    actualizado_at  TEXT NOT NULL,
    actualizado_por TEXT
);

-- Sesiones de la interfaz web, en servidor (A07:2025).
-- La cookie del navegador lleva SOLO un identificador aleatorio opaco; todo lo
-- demas vive aqui. Asi la cookie no contiene nada legible y las sesiones se
-- pueden revocar (cerrar sesion en todas partes, invalidar al cambiar la
-- contrasena), cosa imposible con una cookie autocontenida firmada o cifrada.
-- El identificador se guarda como hash SHA-256: leer la tabla no da tokens
-- utilizables.
CREATE TABLE IF NOT EXISTS web_sessions (
    sid_hash      TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    role          TEXT NOT NULL,
    csrf          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    ip            TEXT,
    agente_hash   TEXT,
    mfa_pendiente INTEGER NOT NULL DEFAULT 0,  -- v6: contrasena correcta, falta el segundo factor
    -- v11 (2026-09-08): sesion opaca completa en servidor. «datos» guarda en JSON lo que
    -- antes viajaba en la cookie firmada de Flask (avisos flash, destino tras el segundo
    -- factor, credencial mostrada una vez); la cookie solo lleva ya el token aleatorio.
    -- «rotado_at» es la ultima vez que se emitio un token nuevo para esta sesion.
    -- v12 (2026-09-08): «sid_hash_anterior» conserva el hash del token anterior durante un
    -- periodo de gracia de 60 segundos tras la rotacion periodica, para que una peticion
    -- concurrente con el token viejo no expulse al usuario (revision adversaria).
    datos         TEXT,
    rotado_at     TEXT,
    sid_hash_anterior TEXT
);
CREATE INDEX IF NOT EXISTS idx_websess_user ON web_sessions(username);
CREATE INDEX IF NOT EXISTS idx_websess_exp  ON web_sessions(expires_at);

-- Cache de traducciones: nunca traducir dos veces el mismo texto
CREATE TABLE IF NOT EXISTS translation_cache (
    hash       TEXT PRIMARY KEY,
    source_txt TEXT NOT NULL,
    target_txt TEXT NOT NULL,
    engine     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Avisos enviados al administrador, para no repetirlos
CREATE TABLE IF NOT EXISTS admin_notices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,        -- source_down|smtp_rotation|smtp_failure|run_failed
    subject_key TEXT NOT NULL,       -- identificador del asunto (p.ej. slug de fuente)
    sent_at    TEXT NOT NULL,
    detail     TEXT,
    UNIQUE(kind, subject_key, sent_at)
);
CREATE INDEX IF NOT EXISTS idx_notices ON admin_notices(kind, subject_key, sent_at DESC);

-- ------------------------------------------------- activos (OCS Inventory, v4)
-- Inventario real de equipos y servidores sincronizado desde las dos bases de
-- OCS Inventory (solo lectura). Es la base de la aplicabilidad por activo.
CREATE TABLE IF NOT EXISTS activos (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    origen            TEXT    NOT NULL,                 -- servidores|equipos
    ocs_id            INTEGER NOT NULL,
    device_id         TEXT,
    nombre            TEXT    NOT NULL,
    so_nombre         TEXT,
    so_version        TEXT,
    so_detalle        TEXT,
    so_familia        TEXT    NOT NULL DEFAULT 'otro',  -- ubuntu|debian|freebsd|windows|centos|otro|desconocido
    so_ciclo          TEXT,                             -- ciclo de endoflife.date: 22.04, 12, 14.4, 11-25h2-w
    ecosistema        TEXT,                             -- ecosistema OSV: Ubuntu:22.04, Debian:12
    ip                TEXT,
    usuario           TEXT,
    arquitectura      TEXT,
    grupo             TEXT,
    descripcion       TEXT,
    ultima_conexion   TEXT,
    ultimo_inventario TEXT,
    zona              TEXT    NOT NULL DEFAULT 'interna', -- internet|dmz|interna
    entorno           TEXT,                             -- produccion|contingencia|desarrollo|pruebas|soporte
    proceso           TEXT,                             -- proceso de negocio (TAG de OCS en servidores)
    etiqueta_ocs      TEXT,                             -- TAG tal como viene de OCS
    -- v6: nivel de parche de Windows deducido de las actualizaciones (KB) instaladas
    windows_build          TEXT,                        -- compilacion efectiva, p. ej. 10.0.26200.6584
    windows_kb             TEXT,                        -- KB acumulativa mas reciente instalada
    windows_kb_publicado   TEXT,                        -- fecha de publicacion de esa KB
    windows_evaluado_at    TEXT,
    hash_software     TEXT,
    n_software        INTEGER NOT NULL DEFAULT 0,
    presente          INTEGER NOT NULL DEFAULT 1,       -- sigue existiendo en OCS
    primera_vez_at    TEXT    NOT NULL,
    visto_at          TEXT    NOT NULL,
    cambiado_at       TEXT,
    UNIQUE(origen, ocs_id)
);
CREATE INDEX IF NOT EXISTS idx_activos_nombre ON activos(nombre);
CREATE INDEX IF NOT EXISTS idx_activos_so     ON activos(so_familia, so_ciclo);

CREATE TABLE IF NOT EXISTS activo_software (
    activo_id     INTEGER NOT NULL REFERENCES activos(id) ON DELETE CASCADE,
    nombre        TEXT    NOT NULL,                  -- tal como lo informa OCS
    nombre_norm   TEXT    NOT NULL,                  -- minusculas, sin sufijo de arquitectura
    version       TEXT    NOT NULL DEFAULT '',
    fabricante    TEXT,
    technology_id INTEGER REFERENCES technologies(id) ON DELETE SET NULL,
    PRIMARY KEY (activo_id, nombre, version)
);
CREATE INDEX IF NOT EXISTS idx_actsoft_norm ON activo_software(nombre_norm);
-- Cubre el recuento de activos por nombre de programa que necesita la columna
-- «Activos» de las reglas del mapa: 1.816 ms -> 184 ms sobre los 922.638 instalados
-- (medido el 2026-09-07); con el, la pagina de Software deja de ser la mas lenta.
CREATE INDEX IF NOT EXISTS idx_actsoft_norm_activo ON activo_software(nombre_norm, activo_id);
CREATE INDEX IF NOT EXISTS idx_actsoft_tec  ON activo_software(technology_id);

CREATE TABLE IF NOT EXISTS sync_ocs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    origen        TEXT    NOT NULL,
    started_at    TEXT    NOT NULL,
    finished_at   TEXT,
    status        TEXT    NOT NULL DEFAULT 'running',  -- running|success|failed
    activos       INTEGER NOT NULL DEFAULT 0,
    software      INTEGER NOT NULL DEFAULT 0,
    nuevos        INTEGER NOT NULL DEFAULT 0,
    cambiados     INTEGER NOT NULL DEFAULT 0,
    desaparecidos INTEGER NOT NULL DEFAULT 0,
    duracion_ms   INTEGER,
    error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_sync_ocs ON sync_ocs(origen, started_at DESC);

-- Mapa nombre de software en OCS -> tecnologia del inventario
CREATE TABLE IF NOT EXISTS tecnologia_ocs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    patron         TEXT    NOT NULL,                      -- en minusculas
    modo           TEXT    NOT NULL DEFAULT 'exacto',     -- exacto|prefijo|regex
    technology_id  INTEGER NOT NULL REFERENCES technologies(id) ON DELETE CASCADE,
    paquete_fuente TEXT,                                  -- paquete fuente (OSV) si difiere del binario
    origen         TEXT    NOT NULL DEFAULT 'manual',     -- manual|semilla|automatico
    created_at     TEXT    NOT NULL,
    created_by     TEXT,
    UNIQUE(patron, modo)
);

-- Veredicto (CVE, activo, paquete) del motor de aplicabilidad
CREATE TABLE IF NOT EXISTS aplicabilidad (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    activo_id         INTEGER NOT NULL REFERENCES activos(id) ON DELETE CASCADE,
    threat_id         INTEGER REFERENCES threats(id) ON DELETE CASCADE,
    cve               TEXT    NOT NULL,
    paquete           TEXT    NOT NULL DEFAULT '',
    version_instalada TEXT,
    version_corregida TEXT,
    veredicto         TEXT    NOT NULL,   -- afectado|no_afectado|sin_dato
    motor             TEXT    NOT NULL,   -- osv|vuxml|version|manual
    evidencia         TEXT,
    aviso             TEXT,               -- USN-..., DSA-..., FreeBSD-SA-...
    evaluado_at       TEXT    NOT NULL,
    -- v7: por que no se conoce la version que corrige (aviso_sin_version, sin_parche_publicado…)
    sin_parche_motivo TEXT,
    -- v8: direccion oficial que sustenta el veredicto ante quien aplica el parche (nota de
    -- seguridad del fabricante, rastreador de la distribucion, entrada de VuXML o ficha del NIST)
    referencia        TEXT,
    UNIQUE(activo_id, cve, paquete)
);
CREATE INDEX IF NOT EXISTS idx_aplic_threat ON aplicabilidad(threat_id, veredicto);
CREATE INDEX IF NOT EXISTS idx_aplic_activo ON aplicabilidad(activo_id, veredicto);
CREATE INDEX IF NOT EXISTS idx_aplic_cve    ON aplicabilidad(cve);

-- Resumen por amenaza de la ultima evaluacion (que ecosistemas se miraron y
-- con que resultado), para explicarlo en la ficha y decidir cuando reevaluar
CREATE TABLE IF NOT EXISTS aplicabilidad_amenaza (
    threat_id    INTEGER PRIMARY KEY REFERENCES threats(id) ON DELETE CASCADE,
    evaluado_at  TEXT    NOT NULL,
    afectados    INTEGER NOT NULL DEFAULT 0,
    no_afectados INTEGER NOT NULL DEFAULT 0,
    sin_dato     INTEGER NOT NULL DEFAULT 0,
    afectados_expuestos INTEGER NOT NULL DEFAULT 0,  -- en produccion o contingencia
    parche_disponible   INTEGER NOT NULL DEFAULT 0,  -- hay version corregida para los afectados
    detalle      TEXT
);

-- Detalle del CVE segun CVE.org (CNA): productos y versiones afectados, CWE
CREATE TABLE IF NOT EXISTS cve_detalle (
    cve           TEXT PRIMARY KEY,
    encontrado    INTEGER NOT NULL DEFAULT 1,
    json          TEXT,
    consultado_at TEXT NOT NULL
);

-- Componentes declarados en un SBOM (CycloneDX o SPDX) importado por activo
CREATE TABLE IF NOT EXISTS activo_componentes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    activo_id    INTEGER NOT NULL REFERENCES activos(id) ON DELETE CASCADE,
    nombre       TEXT    NOT NULL,
    version      TEXT    NOT NULL DEFAULT '',
    ecosistema   TEXT,                 -- PyPI|npm|Maven|Go|crates.io|NuGet|RubyGems|Packagist|...
    purl         TEXT,
    fichero      TEXT,
    importado_at TEXT    NOT NULL,
    UNIQUE(activo_id, nombre, version, ecosistema)
);
CREATE INDEX IF NOT EXISTS idx_componentes_activo ON activo_componentes(activo_id);

-- Resultados OpenSCAP (XCCDF) importados por activo
CREATE TABLE IF NOT EXISTS cumplimiento (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    activo_id   INTEGER NOT NULL REFERENCES activos(id) ON DELETE CASCADE,
    perfil      TEXT,
    regla       TEXT    NOT NULL,
    titulo      TEXT,
    severidad   TEXT,                  -- high|medium|low|info|unknown
    resultado   TEXT    NOT NULL,      -- pass|fail|error|unknown|notapplicable|notchecked|informational|fixed
    evaluado_at TEXT,
    fichero     TEXT,
    importado_at TEXT   NOT NULL,
    UNIQUE(activo_id, perfil, regla)
);
CREATE INDEX IF NOT EXISTS idx_cumplimiento_activo ON cumplimiento(activo_id, resultado);

-- Cache de registros OSV.dev (UBUNTU-CVE-..., DEBIAN-CVE-...)
CREATE TABLE IF NOT EXISTS osv_cache (
    id            TEXT    PRIMARY KEY,
    encontrado    INTEGER NOT NULL DEFAULT 1,
    json          TEXT,
    consultado_at TEXT    NOT NULL
);

-- Ciclos de vida de endoflife.date
CREATE TABLE IF NOT EXISTS fin_soporte (
    producto       TEXT NOT NULL,        -- ubuntu|debian|freebsd|windows|windows-server
    ciclo          TEXT NOT NULL,
    etiqueta       TEXT,
    eol            TEXT,                 -- fecha ISO; NULL si no caduca
    soporte        TEXT,
    soporte_extendido TEXT,           -- Debian LTS; en Ubuntu es de pago y no cuenta
    ultima_version TEXT,
    lts            INTEGER NOT NULL DEFAULT 0,
    actualizado_at TEXT NOT NULL,
    PRIMARY KEY (producto, ciclo)
);

-- Hallazgos de politica por activo (sin CVE): fin de soporte, software de
-- riesgo, activos ciegos, sin agente de proteccion
CREATE TABLE IF NOT EXISTS hallazgos_activos (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    activo_id    INTEGER NOT NULL REFERENCES activos(id) ON DELETE CASCADE,
    tipo         TEXT    NOT NULL,   -- fin_soporte|software_riesgo|sin_reportar|sin_edr
    clave        TEXT    NOT NULL,
    detalle      TEXT,
    detectado_at TEXT    NOT NULL,
    resuelto_at  TEXT,
    UNIQUE(activo_id, tipo, clave)
);
CREATE INDEX IF NOT EXISTS idx_hallazgos_tipo ON hallazgos_activos(tipo, resuelto_at);

-- v6 (2026-09-05): correcciones de Windows publicadas por Microsoft (MSRC CVRF): que
-- compilacion (FixedBuild) y que KB corrigen cada CVE en cada producto Windows.
CREATE TABLE IF NOT EXISTS msrc_documentos (
    documento     TEXT PRIMARY KEY,      -- identificador mensual, p. ej. '2026-Aug'
    publicado_at  TEXT,
    revisado_at   TEXT,
    descargado_at TEXT NOT NULL,
    n_cve         INTEGER NOT NULL DEFAULT 0,
    n_windows     INTEGER NOT NULL DEFAULT 0,
    error         TEXT
);
CREATE TABLE IF NOT EXISTS msrc_correcciones (
    cve             TEXT NOT NULL,
    producto_id     TEXT NOT NULL,
    producto        TEXT NOT NULL,        -- 'Windows 11 Version 24H2 for x64-based Systems'
    kb              TEXT,
    build_corregida TEXT,                 -- '10.0.26100.6584'
    documento       TEXT NOT NULL,
    publicado_at    TEXT,
    PRIMARY KEY(cve, producto_id)
);
CREATE INDEX IF NOT EXISTS idx_msrc_producto ON msrc_correcciones(producto_id);
CREATE INDEX IF NOT EXISTS idx_msrc_kb       ON msrc_correcciones(kb);

-- v6: seguimiento de remediacion por activo y CVE. Se abre cuando la evaluacion confirma
-- la version vulnerable y se cierra solo cuando una sincronizacion posterior ve la
-- correccion instalada (o el activo desaparece de OCS).
CREATE TABLE IF NOT EXISTS remediaciones (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    activo_id          INTEGER NOT NULL REFERENCES activos(id) ON DELETE CASCADE,
    threat_id          INTEGER,
    cve                TEXT NOT NULL,
    paquete            TEXT NOT NULL,
    version_vulnerable TEXT,
    version_corregida  TEXT,
    motor              TEXT,
    -- v14 (2026-09-10): valor nuevo 'esperando_datos'. La evaluacion de hoy no puede
    -- afirmar ni negar que el activo siga afectado (veredicto 'sin_dato'): en produccion
    -- eran 2.480 remediaciones de cuatro equipos de computo con Windows 11 cuya
    -- compilacion no se puede calcular porque OCS no informa de ninguna actualizacion
    -- acumulativa reconocida. No se cierran (nadie ha comprobado que esten corregidas) y
    -- no cuentan como trabajo pendiente (nadie puede hacerlas). Es REVERSIBLE: el paso 5
    -- de remediacion.sincronizar las devuelve a 'abierta' con su detectado_at original en
    -- cuanto la evaluacion vuelva a confirmar. No hace falta ninguna columna nueva: el
    -- motivo va en cerrado_motivo, como en 'activo_ausente'.
    estado             TEXT NOT NULL DEFAULT 'abierta',   -- abierta|esperando_datos|corregida|activo_ausente
    detectado_at       TEXT NOT NULL,
    comprobado_at      TEXT NOT NULL,                     -- ultima vez que se vio (abierta) o se comprobo
    corregido_at       TEXT,
    version_final      TEXT,                              -- version instalada al cerrar
    cerrado_motivo     TEXT,
    UNIQUE(activo_id, cve, paquete)
);
CREATE INDEX IF NOT EXISTS idx_remed_estado ON remediaciones(estado, corregido_at);
CREATE INDEX IF NOT EXISTS idx_remed_activo ON remediaciones(activo_id);

-- v10: «ya lo remedie, compruebalo». Peticion del usuario del 2026-09-07: Servicios
-- Tecnologicos marca una vulnerabilidad de un activo como remediada y la PLATAFORMA
-- verifica, no la persona: lee la version que OCS reporto de ese paquete en ese equipo y
-- la compara con la que corrige el fallo. Cada intento queda aqui, con su veredicto, de
-- modo que se puede auditar quien dijo que estaba corregido y que respondio la
-- comprobacion. Una remediacion NO se cierra porque alguien lo diga.
CREATE TABLE IF NOT EXISTS remediacion_comprobaciones (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    remediacion_id     INTEGER NOT NULL REFERENCES remediaciones(id) ON DELETE CASCADE,
    activo_id          INTEGER NOT NULL REFERENCES activos(id) ON DELETE CASCADE,
    cve                TEXT NOT NULL,
    paquete            TEXT NOT NULL,
    solicitado_por     TEXT NOT NULL,          -- quien pulso «ya esta remediada»
    solicitado_at      TEXT NOT NULL,
    veredicto          TEXT NOT NULL,          -- corregida|sigue_vulnerable|desinstalado|sin_datos
    version_instalada  TEXT,                   -- la que OCS reporta AHORA
    version_corregida  TEXT,                   -- la que hace falta
    inventario_at      TEXT,                   -- fecha del inventario con el que se comprobo
    detalle            TEXT,                   -- explicacion en espanol de lo que se decidio
    ip                 TEXT
);
CREATE INDEX IF NOT EXISTS idx_remed_comp ON remediacion_comprobaciones(remediacion_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_remed_comp_activo ON remediacion_comprobaciones(activo_id, id DESC);

-- v10: notas de Redes sobre una vulnerabilidad de un activo concreto
-- (que se hizo, cuando, por que no se puede aun). Es lo unico que ese perfil puede
-- escribir, ademas de pedir la comprobacion.
CREATE TABLE IF NOT EXISTS remediacion_notas (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    remediacion_id     INTEGER NOT NULL REFERENCES remediaciones(id) ON DELETE CASCADE,
    activo_id          INTEGER NOT NULL REFERENCES activos(id) ON DELETE CASCADE,
    autor              TEXT NOT NULL,
    creado_at          TEXT NOT NULL,
    texto              TEXT NOT NULL,
    ip                 TEXT
);
CREATE INDEX IF NOT EXISTS idx_remed_notas ON remediacion_notas(remediacion_id, id DESC);

-- v6: alertas por proceso de negocio (TAG de OCS): cada proceso puede recibir su propio
-- correo con solo sus servidores afectados; destinatario y activacion propios.
CREATE TABLE IF NOT EXISTS alertas_proceso (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    proceso         TEXT NOT NULL UNIQUE,
    correo          TEXT,
    activa          INTEGER NOT NULL DEFAULT 0,
    solo_expuestos  INTEGER NOT NULL DEFAULT 0,         -- solo produccion y contingencia
    creado_at       TEXT NOT NULL,
    actualizado_at  TEXT NOT NULL,
    ultimo_envio_at TEXT,
    ultimo_envio_n  INTEGER
);
CREATE TABLE IF NOT EXISTS alertas_proceso_envios (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    proceso     TEXT NOT NULL,
    correo      TEXT NOT NULL,
    enviado_at  TEXT NOT NULL,
    n_amenazas  INTEGER NOT NULL,
    n_activos   INTEGER NOT NULL,
    asunto      TEXT,
    threat_ids  TEXT                                    -- JSON con los identificadores enviados
);
CREATE INDEX IF NOT EXISTS idx_ap_envios_proceso ON alertas_proceso_envios(proceso, enviado_at);

-- v7 (2026-09-06): seguimiento de las correcciones que todavia no existen. Una fila por
-- (CVE, paquete, ecosistema) cuya evaluacion dice «afectado» pero sin version corregida:
-- el aviso no la publica, el fabricante no ha sacado parche o la distribucion no lo ha
-- empaquetado. Se vuelve a buscar cada dia y, cuando aparece, se avisa en el correo.
CREATE TABLE IF NOT EXISTS parches_pendientes (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    cve               TEXT NOT NULL,
    paquete           TEXT NOT NULL,
    ecosistema        TEXT NOT NULL DEFAULT '',   -- 'Ubuntu:22.04', 'Debian:12', 'FreeBSD', 'windows'
    threat_id         INTEGER,
    motivo            TEXT NOT NULL,              -- aviso_sin_version|sin_parche_publicado|distro_sin_empaquetar|desconocido
    motivo_detalle    TEXT,
    n_activos         INTEGER NOT NULL DEFAULT 0,
    n_activos_expuestos INTEGER NOT NULL DEFAULT 0,
    detectado_at      TEXT NOT NULL,
    buscado_at        TEXT,
    intentos          INTEGER NOT NULL DEFAULT 0,
    version_corregida TEXT,                       -- NULL hasta que aparece
    aviso             TEXT,                       -- identificador del aviso que la publica
    encontrado_at     TEXT,
    avisado_at        TEXT,                       -- cuando se incluyo en un correo de alerta
    UNIQUE(cve, paquete, ecosistema)
);
CREATE INDEX IF NOT EXISTS idx_parches_pend_estado ON parches_pendientes(encontrado_at, avisado_at);
CREATE INDEX IF NOT EXISTS idx_parches_pend_cve    ON parches_pendientes(cve);

"""

# ---------------------------------------------------------------- excepciones
# v13 (2026-09-10): excepciones con vencimiento (aceptacion de riesgo).
# v15 (2026-09-10): excepciones PERMANENTES, sin fecha de vencimiento.
#
# Peticion original del usuario: «falta aceptar un riesgo con responsable,
# justificacion y fecha de caducidad, que es lo que pide una auditoria y lo que evita
# que algo quede olvidado». Peticion del 2026-09-10 por la tarde: «en excepciones se
# debe agregar la opcion de fecha permanente, ya que no va a tener una fecha de
# vencimiento».
#
# Una excepcion vigente saca la vulnerabilidad de la cola de trabajo y de las cifras de
# riesgo, pero NO la borra ni la oculta: sigue consultable en /excepciones/ y en la
# ficha del activo, marcada como riesgo aceptado. Si tiene plazo, cuando la fecha pasa
# la vulnerabilidad vuelve sola, sin que nadie ejecute nada: la vigencia se CALCULA
# comparando `vence_at` con la fecha de hoy (threatintel/excepciones.py, SQL_VIGENTE),
# nunca se guarda un estado «vencida» que dependiera de un proceso.
#
# Por eso `estado` solo tiene dos valores GUARDADOS, 'vigente' y 'revocada'; el tercer
# estado que ve la persona, «vencida», es 'vigente' con la fecha pasada.
#
# La DDL vive en esta constante y no dentro de `_SCHEMA_BASE` porque la migracion de la
# v14 a la v15 tiene que RECONSTRUIR la tabla (SQLite no sabe quitar un NOT NULL con
# ALTER TABLE) y necesita crear una tabla gemela con otro nombre. Teniendo una sola
# definicion, la tabla que se crea desde cero y la que sale de la migracion son
# identicas por construccion, y `tests/test_esquema.py` lo comprueba comparando las dos.
_DDL_EXCEPCIONES = """
CREATE TABLE IF NOT EXISTS {tabla} (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Que cubre: una vulnerabilidad en un activo (activo_cve), un CVE en toda la
    -- organizacion (cve) o un paquete completo en un activo (activo_paquete).
    alcance            TEXT    NOT NULL,
    activo_id          INTEGER REFERENCES activos(id) ON DELETE CASCADE,  -- NULL si alcance='cve'
    cve                TEXT,                       -- NULL si alcance='activo_paquete'
    paquete            TEXT,                       -- NULL salvo alcance='activo_paquete'
    justificacion      TEXT    NOT NULL,           -- por que se acepta el riesgo
    responsable_nombre TEXT    NOT NULL,           -- persona que ACEPTA el riesgo, no una cuenta
    responsable_correo TEXT    NOT NULL,
    compensacion       TEXT,                       -- medida compensatoria aplicada (opcional)
    registrado_por     TEXT    NOT NULL,           -- usuario de la plataforma que la registro
    registrado_at      TEXT    NOT NULL,
    -- v15: `vence_at` es NULL, y SOLO NULL, cuando la excepcion es permanente. No se
    -- guarda una fecha lejana de mentira para simularlo: seria falso en la base, la
    -- veria la auditoria y ensuciaria los avisos de «por vencer».
    vence_at           TEXT,                       -- fecha ISO 'YYYY-MM-DD'; NULL si permanente
    vence_at_inicial   TEXT,                       -- primera fecha; NULL si nacio permanente
    -- v15: 1 = riesgo aceptado sin fecha de vencimiento. No caduca nunca, asi que en su
    -- lugar se REVISA cada `excepciones_revision_dias` dias (ajuste, 180 por omision).
    permanente         INTEGER NOT NULL DEFAULT 0,
    revisada_at        TEXT,                       -- ultima confirmacion de que sigue valiendo
    revisada_por       TEXT,
    revisada_nota      TEXT,
    revisiones         INTEGER NOT NULL DEFAULT 0,
    revision_avisada_at TEXT,                      -- ultimo recordatorio de revision enviado
    estado             TEXT    NOT NULL DEFAULT 'vigente',   -- vigente|revocada (vencida se calcula)
    kev                INTEGER NOT NULL DEFAULT 0, -- habia explotacion activa confirmada al registrarla
    prorrogas          INTEGER NOT NULL DEFAULT 0,
    prorrogada_at      TEXT,
    prorrogada_por     TEXT,
    prorroga_motivo    TEXT,
    revocada_at        TEXT,
    revocada_por       TEXT,
    revocada_motivo    TEXT,
    avisado_at         TEXT,                       -- ultimo aviso anticipado enviado por correo
    -- La regla que impide que las dos columnas se contradigan: o hay fecha y no es
    -- permanente, o es permanente y no hay fecha. Sin esto, un fallo de codigo podria
    -- dejar una permanente con fecha (y la avisaria como «por vencer») o una temporal
    -- sin fecha (y no venceria nunca en silencio).
    CHECK ((permanente = 1 AND vence_at IS NULL)
        OR (permanente = 0 AND vence_at IS NOT NULL))
);
"""

_INDICES_EXCEPCIONES = """
-- Una sola excepcion NO revocada por alcance: dos vigentes sobre lo mismo se
-- contradirian y la segunda ocultaria a la primera. Para volver a aceptar el riesgo de
-- algo ya vencido se PRORROGA, que deja constancia; revocada la anterior, se puede
-- registrar una nueva. Indice parcial: las revocadas no estorban.
CREATE UNIQUE INDEX IF NOT EXISTS idx_exc_unica ON excepciones(
    alcance, COALESCE(activo_id, -1), COALESCE(cve, ''), COALESCE(paquete, ''))
    WHERE estado <> 'revocada';
CREATE INDEX IF NOT EXISTS idx_exc_activo ON excepciones(activo_id, estado);
CREATE INDEX IF NOT EXISTS idx_exc_cve    ON excepciones(cve, estado);
CREATE INDEX IF NOT EXISTS idx_exc_vence  ON excepciones(vence_at, estado);
-- v15: la lista y el recordatorio de revision preguntan por las permanentes vigentes.
CREATE INDEX IF NOT EXISTS idx_exc_permanente ON excepciones(permanente, estado, revisada_at);
"""

#: Esquema completo. La tabla de excepciones se pega desde su propia constante para que
#: la creacion desde cero y la reconstruccion de la migracion v15 no puedan separarse.
SCHEMA = _SCHEMA_BASE + _DDL_EXCEPCIONES.format(tabla="excepciones") + _INDICES_EXCEPCIONES


def utcnow() -> str:
    """Timestamp ISO-8601 en UTC, con sufijo Z. Formato unico en toda la app."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def connect(path=None) -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(str(path or DB_FILE), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


# Columnas anadidas despues de la version 2. executescript no altera tablas ya
# creadas, asi que se comparan con PRAGMA table_info y se agregan las que falten.
_COLUMNAS_NUEVAS: dict[str, list[tuple[str, str]]] = {
    "threats": [
        ("estado", "TEXT NOT NULL DEFAULT 'nueva'"),
        ("estado_at", "TEXT"), ("estado_por", "TEXT"), ("estado_motivo", "TEXT"),
        ("digest_at", "TEXT"), ("alert_skip_reason", "TEXT"), ("alert_skip_at", "TEXT"),
        # v7: de donde salio la descripcion util cuando la fuente envia un texto de relleno
        ("descripcion_origen", "TEXT"), ("descripcion_buscada_at", "TEXT"),
    ],
    # v4: lo que OCS Inventory dice de cada tecnologia (activos reales y versiones)
    "technologies": [
        ("activos_ocs", "INTEGER"),          # activos presentes con software mapeado
        ("versiones_ocs", "TEXT"),           # JSON [{"version": "...", "activos": n}, ...]
        ("ocs_actualizado_at", "TEXT"),
    ],
    "fin_soporte": [("soporte_extendido", "TEXT")],
    # v7: por que no se conoce la version que corrige
    "aplicabilidad": [("sin_parche_motivo", "TEXT"), ("referencia", "TEXT")],
    # v6: segundo factor, nivel de parche de Windows
    "users": [("totp_secret", "TEXT"), ("totp_activado_at", "TEXT"), ("totp_recuperacion", "TEXT"),
              ("totp_fallos", "INTEGER NOT NULL DEFAULT 0"),
              ("tour_estado", "TEXT"), ("tour_at", "TEXT"),
              # v9: nombre de la persona para mostrarlo en lugar del correo
              ("nombre", "TEXT"),
              # v11: fecha del ultimo cambio de contrasena (rotacion de credenciales)
              ("password_changed_at", "TEXT")],
    # v11: datos de sesion en servidor (JSON) y ultima rotacion del token
    "web_sessions": [("mfa_pendiente", "INTEGER NOT NULL DEFAULT 0"),
                     ("datos", "TEXT"), ("rotado_at", "TEXT"), ("sid_hash_anterior", "TEXT")],
    "activos": [("entorno", "TEXT"), ("proceso", "TEXT"), ("etiqueta_ocs", "TEXT"),
                # v6: nivel de parche de Windows deducido de las KB instaladas
                ("windows_build", "TEXT"), ("windows_kb", "TEXT"), ("windows_kb_publicado", "TEXT"),
                ("windows_evaluado_at", "TEXT")],
    "aplicabilidad_amenaza": [("afectados_expuestos", "INTEGER NOT NULL DEFAULT 0"),
                              ("parche_disponible", "INTEGER NOT NULL DEFAULT 0")],
    # v10: quien dijo que estaba remediada y que respondio la comprobacion. La marca de
    # una persona NO cierra la remediacion: solo deja constancia de que se pidio.
    "remediaciones": [("comprobacion_pedida_por", "TEXT"),
                      ("comprobacion_pedida_at", "TEXT"),
                      ("comprobacion_veredicto", "TEXT"),
                      ("comprobacion_at", "TEXT"),
                      ("notas", "INTEGER NOT NULL DEFAULT 0")],
}


# --------------------------------------------------------------------------
# v15 (2026-09-10): reconstruccion de `excepciones` para admitir las permanentes
# --------------------------------------------------------------------------
#: Columnas que tenia `excepciones` en las versiones 13 y 14, en el orden del esquema.
#: La reconstruccion copia EXACTAMENTE estas y deja que las nuevas tomen su valor por
#: omision; escribirlas a mano (y no leerlas de la tabla vieja) evita copiar columnas
#: inventadas por una edicion manual de la base.
_COLUMNAS_EXCEPCIONES_V14 = (
    "id", "alcance", "activo_id", "cve", "paquete", "justificacion",
    "responsable_nombre", "responsable_correo", "compensacion", "registrado_por",
    "registrado_at", "vence_at", "vence_at_inicial", "estado", "kev", "prorrogas",
    "prorrogada_at", "prorrogada_por", "prorroga_motivo", "revocada_at",
    "revocada_por", "revocada_motivo", "avisado_at",
)


def reconstruir_excepciones(conn: sqlite3.Connection) -> bool:
    """Migra `excepciones` de la v14 a la v15 sin perder ni una fila. Idempotente.

    Por que hace falta reconstruir la tabla y no basta un ALTER TABLE: hasta la v14
    `vence_at` era `TEXT NOT NULL`, y SQLite no sabe quitar un NOT NULL de una columna
    ya creada. Una excepcion permanente no tiene fecha de vencimiento y su `vence_at`
    tiene que quedar en NULL: guardar una fecha lejana de mentira (el 31 de diciembre de
    9999, por ejemplo) seria falso en la base, apareceria en la auditoria y la colaria en
    los avisos de «vence pronto» el dia que alguien cambiara el plazo del aviso.

    Se sigue el procedimiento oficial de SQLite para cambiar el esquema de una tabla:
    claves ajenas desactivadas, transaccion, tabla gemela con la definicion NUEVA (la
    misma constante `_DDL_EXCEPCIONES` que usa el esquema, asi que no pueden separarse),
    copia, borrado de la vieja, renombrado y comprobacion de integridad referencial. Los
    indices los vuelve a crear `SCHEMA` justo despues (`CREATE INDEX IF NOT EXISTS`).

    Devuelve True si ha reconstruido la tabla y False si no habia nada que hacer (base
    nueva, o base ya migrada). No toca ninguna otra tabla.
    """
    columnas = {r[1] for r in conn.execute("PRAGMA table_info(excepciones)")}
    if not columnas:
        return False                      # base nueva: la crea `SCHEMA` ya en la v15
    if "permanente" in columnas:
        return False                      # ya migrada
    comunes = [c for c in _COLUMNAS_EXCEPCIONES_V14 if c in columnas]
    lista = ", ".join(comunes)
    antes = int(conn.execute("SELECT COUNT(*) FROM excepciones").fetchone()[0] or 0)
    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.execute("BEGIN")
        conn.execute("DROP TABLE IF EXISTS excepciones_v15")
        conn.execute(_DDL_EXCEPCIONES.format(tabla="excepciones_v15"))
        conn.execute(f"INSERT INTO excepciones_v15({lista}) SELECT {lista} FROM excepciones")
        despues = int(conn.execute("SELECT COUNT(*) FROM excepciones_v15").fetchone()[0] or 0)
        if despues != antes:
            raise RuntimeError(
                f"la migracion v15 de excepciones copio {despues} filas de {antes}")
        conn.execute("DROP TABLE excepciones")
        conn.execute("ALTER TABLE excepciones_v15 RENAME TO excepciones")
        problemas = conn.execute("PRAGMA foreign_key_check(excepciones)").fetchall()
        if problemas:
            raise RuntimeError(f"la migracion v15 dejo {len(problemas)} claves ajenas rotas")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        conn.execute("PRAGMA foreign_keys=ON")
        raise
    conn.execute("PRAGMA foreign_keys=ON")
    return True


def migrar_columnas(conn: sqlite3.Connection) -> list[str]:
    """Agrega las columnas que falten a bases creadas con un esquema anterior.
    Devuelve la lista 'tabla.columna' anadida. Idempotente y sin perdida de datos."""
    anadidas: list[str] = []
    for tabla, columnas in _COLUMNAS_NUEVAS.items():
        existentes = {r[1] for r in conn.execute(f"PRAGMA table_info({tabla})")}
        if not existentes:
            continue
        for nombre, tipo in columnas:
            if nombre not in existentes:
                conn.execute(f"ALTER TABLE {tabla} ADD COLUMN {nombre} {tipo}")
                anadidas.append(f"{tabla}.{nombre}")
    return anadidas


def init_db(path=None) -> None:
    """Crea el esquema si no existe y agrega columnas nuevas. Idempotente."""
    with connect(path) as conn:
        # v15 (2026-09-10): `excepciones.vence_at` deja de ser NOT NULL para admitir
        # las permanentes. Va lo PRIMERO porque reconstruye la tabla entera: si se
        # hiciera despues de `SCHEMA`, los indices recien creados se perderian al
        # borrarla y no volverian hasta la siguiente ejecucion.
        reconstruir_excepciones(conn)
        # Primero las columnas nuevas de tablas ya existentes: el script del
        # esquema crea indices sobre ellas y fallaria en una base antigua.
        migrar_columnas(conn)
        conn.executescript(SCHEMA)
        # Y otra vez DESPUES: en una base nueva las tablas no existian en la primera
        # pasada, asi que sus columnas de `_COLUMNAS_NUEVAS` se saltaban y quedaban
        # fuera. Es idempotente, cuesta un PRAGMA por tabla y evita que una instalacion
        # nueva salga con menos columnas que una migrada (detectado el 2026-09-08).
        migrar_columnas(conn)
        conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )
    try:
        DB_FILE.chmod(0o600)
    except (PermissionError, FileNotFoundError):
        pass


@contextmanager
def session(path=None) -> Iterator[sqlite3.Connection]:
    """Conexion con transaccion explicita: commit al salir, rollback si excepcion."""
    conn = connect(path)
    try:
        conn.execute("BEGIN")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


# --------------------------------------------------------------------------
# settings: configuracion editable desde la GUI
# --------------------------------------------------------------------------
def get_setting(conn: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row is None or row["value"] is None:
        return default
    try:
        return json.loads(row["value"])
    except (json.JSONDecodeError, TypeError):
        return row["value"]


def set_setting(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        "INSERT INTO settings(key, value, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, json.dumps(value, ensure_ascii=False), utcnow()),
    )


def get_logo(conn: sqlite3.Connection) -> Optional[dict]:
    """Datos, tipo MIME y nombre del logo de la organizacion, o None si no hay ninguno."""
    fila = conn.execute(
        "SELECT logo_datos, logo_tipo, logo_nombre, actualizado_at "
        "FROM marca WHERE id=1").fetchone()
    return dict(fila) if fila else None


def set_logo(conn: sqlite3.Connection, datos: bytes, tipo: str, nombre: str,
            actor: Optional[str]) -> None:
    conn.execute(
        "INSERT INTO marca(id, logo_datos, logo_tipo, logo_nombre, actualizado_at, actualizado_por) "
        "VALUES(1,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET logo_datos=excluded.logo_datos, "
        "logo_tipo=excluded.logo_tipo, logo_nombre=excluded.logo_nombre, "
        "actualizado_at=excluded.actualizado_at, actualizado_por=excluded.actualizado_por",
        (datos, tipo, nombre, utcnow(), actor),
    )


def borrar_logo(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM marca WHERE id=1")


def audit(conn: sqlite3.Connection, username: Optional[str], action: str,
          entity: str = None, entity_id: Any = None, detail: str = None, ip: str = None) -> None:
    conn.execute(
        "INSERT INTO audit_log(at, username, action, entity, entity_id, detail, ip) "
        "VALUES(?,?,?,?,?,?,?)",
        (utcnow(), username, action, entity,
         None if entity_id is None else str(entity_id), detail, ip),
    )


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict]:
    return [dict(r) for r in rows]
