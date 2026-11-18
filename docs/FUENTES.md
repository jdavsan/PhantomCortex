# Catálogo de fuentes de inteligencia

**Última verificación en vivo:** 3 de septiembre de 2026 · **55 fuentes activas, 55 operativas**

> Actualizado el 3 de septiembre: se eliminaron las 3 fuentes sin arreglo posible y se renombró `threatpost` → `the_record`. Ver §3.

Todas las URL de este documento se han comprobado en vivo desde el propio servidor. Ninguna se ha incluido por reputación: si no devolvió entradas reales en la prueba, está marcada como inactiva con el motivo.

---

## 1. Resumen

| | |
|---|---|
| Fuentes registradas | 78 |
| **Activas y operativas** | **55** (52 feeds RSS/Atom + 3 API) |
| Inactivas documentadas | 23 |
| Entradas recolectadas por ejecución | ~6.000 |
| Entradas que superan los filtros | ~980 |

### Qué cambió

| | Antes | Ahora |
|---|---|---|
| Fuentes que funcionaban | 25 de 35 | **55 de 55** |
| Fuentes gubernamentales | 0 de 5 | **6 de 6** |
| Feeds descargados dos veces | 11 pares | 0 |
| Entradas por ejecución | 4.912 | 6.015 |

**El hallazgo clave:** las tres fuentes de CISA no estaban muertas. Devolvían `403` porque `feedparser` consultaba sin cabecera `User-Agent`. La capa HTTP nueva la envía y **CISA responde con normalidad**. Se recuperó la fuente más valiosa del sistema sin cambiar de proveedor.

---

## 2. Fuentes recomendadas, por prioridad

La prioridad no mide la calidad de la fuente, sino **su relevancia para el inventario de esta organización**: Windows, Debian, Ubuntu, PostgreSQL, Moodle, GitLab, pfSense, Check Point, Carbonio, Apache, PHP, Chrome/Edge/Firefox, Docker, Proxmox, Asterisk y Wazuh.

### 2.1 Prioridad crítica — 8 fuentes

Lo que no se puede permitir perder. Si una de estas cae, el aviso al administrador salta al tercer día.

| Fuente | URL | Por qué |
|---|---|---|
| **CISA KEV** | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | **La más importante.** 1.694 CVE con explotación **confirmada en la práctica**. Es la única fuente que distingue «grave en teoría» de «se está explotando ahora». Manda sobre cualquier puntuación CVSS |
| **NVD API 2.0** | `services.nvd.nist.gov/rest/json/cves/2.0` | Puntuación y vector CVSS oficiales. Sustituye al RSS que el NIST retiró |
| **CISA Advisories** | `cisa.gov/cybersecurity-advisories/all.xml` | Avisos del organismo estadounidense. **Recuperada** tras 33 días caída |
| **CISA Current Activity** | `us-cert.cisa.gov/ncas/current-activity.xml` | Sustituye al feed de alertas retirado |
| **CERT-EU** | `cert.europa.eu/publications/security-advisories-rss` | **Nueva.** Avisos del CERT europeo: centrados en vulnerabilidades, no en noticias |
| **Microsoft MSRC** | `api.msrc.microsoft.com/update-guide/rss` | 4.342 entradas. Windows, Edge y Office son el grueso del parque |
| **GitLab Security Releases** | `about.gitlab.com/security-releases.xml` | **Nueva.** La organización usa GitLab. Del propio fabricante, con las versiones corregidas |
| **Check Point Research** | `research.checkpoint.com/feed/` | **Nueva.** La organización usa Check Point VPN y Gaia |

### 2.2 Prioridad alta — 13 fuentes

| Fuente | URL | Por qué |
|---|---|---|
| **Debian Security (DSA)** | `debian.org/security/dsa-long` | **Reparada.** Los `.rdf` antiguos dan 404. La versión `-long` incluye el texto completo, que mejora la correlación |
| **Debian LTS (DLA)** | `debian.org/lts/security/dla-long` | **Nueva.** Para equipos en versión LTS |
| **Ubuntu Security** | `ubuntu.com/security/notices/rss.xml` | Este mismo servidor es Ubuntu 22.04 |
| **openSUSE Security** | `lists.opensuse.org/.../security-announce@.../feed/` | Sustituto verificado del feed de SUSE, que acaba en 404 |
| **Cisco Security** | `sec.cloudapps.cisco.com/.../CiscoSecurityAdvisory.xml` | **URL nueva:** `tools.cisco.com` dejó de servirlo |
| **Fortinet PSIRT** | `fortiguard.com/rss/ir.xml` | **Nueva.** Aunque no haya Fortinet, marca la tendencia de ataques a VPN perimetral |
| **Palo Alto PSIRT** | `security.paloaltonetworks.com/rss.xml` | **Nueva.** Mismo razonamiento |
| **NCSC Reino Unido** | `ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml` | **Nueva.** Avisos gubernamentales británicos |
| **CISA ICS Advisories** | `cisa.gov/cybersecurity-advisories/ics-advisories.xml` | Sistemas de control industrial |
| **Zero Day Initiative** | `zerodayinitiative.com/rss/published/` | 200 avisos independientes del fabricante. Suele publicar **antes** que el propio fabricante |
| **SANS ISC** | `isc.sans.edu/rssfeed_full.xml` | **Nueva.** Análisis diario de lo que se explota de verdad |
| **EPSS (FIRST)** | `api.first.org/data/v1/epss` | Probabilidad de explotación a 30 días. Ordena la cola cuando hay muchos CVE con el mismo CVSS |
| **BleepingComputer** | `bleepingcomputer.com/feed/` | El medio que suele dar primero las explotaciones activas |

### 2.3 Prioridad media — 20 fuentes

Investigación técnica de calidad y cobertura complementaria: **Cisco Talos**, **Google Project Zero**, **Palo Alto Unit 42**, **Mandiant / Google TI**, **Kaspersky Securelist**, **ESET WeLiveSecurity**, **SentinelLabs**, **Tenable Research**, **Trend Micro Research**, **Rapid7**, **Red Hat Security**, **Chrome Releases**, **CERT-FR Avis**, **CIRCL Vulnerability-Lookup**, **Exploit-DB**, **SecurityWeek**, **The Hacker News**, **The Record**, **Hispasec Una al día** (español), **Segu-Info** (español).

### 2.4 Prioridad baja — 14 fuentes

Cobertura periodística amplia, útil para contexto pero con mucho ruido: Ars Technica, Dark Reading, Krebs, CyberScoop, Infosecurity Magazine, The Register, Help Net Security, GBHackers, Cyber Security News, Malwarebytes, Schneier, Troy Hunt, Bitdefender Labs, PostgreSQL News.

### 2.5 Disponibles pero desactivadas — 10 fuentes

Registradas y **verificadas como operativas**, apagadas porque no aplican hoy. Se activan con un clic en **Fuentes**:

| Fuente | Activar si… |
|---|---|
| Apple Security Releases | hay equipos macOS o iOS en el parque |
| Splunk Advisories | se usa Splunk |
| GreyNoise Labs | interesa telemetría de escaneo masivo en tiempo real |
| Elastic Security Labs | se usa Elastic/ELK |
| Huntress | interesa cobertura de MSP (695 entradas: mucho volumen) |
| Qualys, CrowdStrike, JPCERT/CC, Microsoft Security Blog, Google Security Blog | se quiere ampliar cobertura |

---

## 3. Fuentes eliminadas

Tres fuentes se **eliminaron** del catálogo el 3 de septiembre de 2026, por decisión expresa: no tenían arreglo posible.

| Fuente | Diagnóstico | Referencias históricas | Sustituto |
|---|---|---|---|
| **ZDNet Security** | `404` en todas sus rutas. ZDNet retiró sus feeds RSS | 264 → **reasignadas** | The Register + Help Net Security |
| **Securelist (ES)** | El dominio `securelist.lat` **ya no resuelve** | 0 | Securelist en inglés, activa |
| **Naked Security (Sophos)** | Sophos cerró el sitio; `news.sophos.com` agota el tiempo de espera incluso con 45 s | 0 | Sin sustituto directo |

### Cómo se preservó la trazabilidad

Borrar una fuente elimina en cascada sus filas de `threat_sources`, que es donde vive la procedencia de cada amenaza histórica. ZDNet tenía 264 referencias.

Antes de borrarla, esas 264 referencias se **reasignaron** a una entrada contenedora, `fuente_retirada` («Fuente retirada (histórico)»), que nunca se consulta (`enabled=0`). La URL concreta de cada artículo vive en `threat_sources.url`, así que se conserva intacta: lo único que cambia es la etiqueta de la fuente.

Resultado: **las 5.837 amenazas del histórico siguen teniendo procedencia citable.**

### Un caso aparte: Threatpost

Threatpost cerró en 2023, pero su entrada **no se borró**: se reapuntó a **The Record** (`therecord.media`), que cubre el mismo ámbito, y se renombró el identificador de `threatpost` a `the_record` para que el catálogo no mienta sobre lo que consulta. Está activa y operativa.

Al revisar sus entradas antes de borrarla se vio que el feed de ZDNet no era de seguridad: los títulos almacenados eran *«Is 8GB of RAM enough for a Mac in 2026»* y *«Dell XPS 14 review»*. Aportaba ruido, no inteligencia.

### Y 23 desactivadas: duplicados y opcionales

Once pares descargaban **el mismo feed dos veces en cada ejecución**: `microsoft_msrc`/`msrc_update_guide`, `cisco_security`/`cisco_psirt`, `securityweek`/`security_week`, `securelist_en`/`kaspersky_securelist_en`, `malwarebytes_blog`/`malwarebytes_labs`, `sans_isc`/`sans_isc_full`, `zdi_published`/`zdi_advisories`, `troy_hunt`/`troy_hunt_blog`, `circl_*`, `cisco_talos*`, `cyber_security_news`/`cybersecurity_news`.

En cada par se conservó activa **la que arrastra más procedencia histórica**, no la de nombre más bonito. Ejemplo: se conservó `microsoft_msrc` (2.636 amenazas la citan) y se apagó `msrc_update_guide` (654).

---

## 4. Cómo funciona la consulta y la extracción

### 4.1 El recorrido completo

```
  ┌─────────────────────────────────────────────────────────────────┐
  │ 1. DESCARGA          threatintel/http.py                        │
  │                                                                  │
  │   requests.Session con:                                          │
  │     · User-Agent de navegador real  ← esto recuperó CISA        │
  │     · Accept: application/rss+xml, application/atom+xml, ...     │
  │     · allow_redirects=True          ← recuperó Bitdefender (308) │
  │     · timeout por fuente (5-120 s, configurable)                 │
  │                                                                  │
  │   Reintentos con espera 1s → 2s → 4s, SOLO en:                  │
  │     errores de red, 5xx y 429 (respetando Retry-After)          │
  │   NUNCA en 404 ni 403: eso es configuración mala, no un fallo    │
  │   pasajero, y reintentar solo gasta tiempo                        │
  └──────────────────────────┬──────────────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │ 2. PARSEO Y NORMALIZACIÓN                                        │
  │                                                                  │
  │   feedparser.parse(bytes_ya_descargados)                         │
  │     ↑ sobre el contenido, no sobre la URL, para controlar        │
  │       nosotros las cabeceras y los reintentos                     │
  │                                                                  │
  │   Detecta el caso «200 pero HTML en vez de XML» y lo devuelve    │
  │   como error `no_es_feed`, no como éxito con 0 entradas          │
  │                                                                  │
  │   Cada entrada se normaliza a: title, summary, link,             │
  │   published, published_parsed, id                                │
  └──────────────────────────┬──────────────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │ 3. FILTRO TEMPORAL       ventana móvil de 45 días                │
  │                                                                  │
  │   Sustituye al filtro «mes actual» del sistema anterior, que     │
  │   cada día 1 perdía definitivamente lo publicado a fin de mes    │
  │   Descarta ~3.265 de 6.015 entradas                              │
  └──────────────────────────┬──────────────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │ 4. CORRELACIÓN           threatintel/matching.py                 │
  │                                                                  │
  │   Los regex del inventario se compilan UNA vez por ejecución,    │
  │   no una por entrada (con 6.000 entradas × 68 tecnologías el     │
  │   coste importa)                                                 │
  │                                                                  │
  │   Por cada alias:                                                │
  │     word    → \balias\b     «edge» NO casa en «knowledge»        │
  │     phrase  → frase entera  «Check Point VPN»                    │
  │     regex   → propio, validado al guardarlo                      │
  │     contexto exigido → «access» solo si además hay «microsoft»   │
  │     exclusión        → si aparece «edge device», se descarta      │
  │                                                                  │
  │   Sin ninguna coincidencia → se descarta (~1.769 entradas)       │
  └──────────────────────────┬──────────────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │ 5. VEREDICTO DE VERSIÓN  threatintel/versions.py                 │
  │                                                                  │
  │   Busca restricciones a ±200 caracteres de la mención:           │
  │     «prior to 4.3», «before 4.3», «up to and including 4.2»,     │
  │     «4.2 and earlier», «fixed in 4.3», «anteriores a 4.3»        │
  │                                                                  │
  │   Compara con la versión del inventario:                         │
  │     affected      → el aviso aplica                              │
  │     not_affected  → se descarta automáticamente                  │
  │     unknown       → ante CUALQUIER duda                          │
  │                                                                  │
  │   Nunca devuelve not_affected por conjetura: en seguridad un     │
  │   falso negativo cuesta más que un falso positivo                 │
  └──────────────────────────┬──────────────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │ 6. IDENTIDAD             threatintel/identity.py                 │
  │                                                                  │
  │   Por orden de fiabilidad:                                       │
  │     1. CVE                    dos fuentes del mismo CVE = 1 fila │
  │     2. ID de aviso            DSA-6157-1 ≠ DSA-6151-1            │
  │     3. URL del artículo       (descartando URL genéricas)        │
  │     4. Título normalizado                                        │
  │                                                                  │
  │   La FECHA no forma parte de la identidad. Ése era el defecto    │
  │   del sistema anterior: los feeds republican la misma entrada    │
  │   con fecha nueva cada día, y con md5(título+fecha) DSA-6374-1   │
  │   se guardó 29 veces y se re-alertó 29 veces                     │
  └──────────────────────────┬──────────────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │ 7. TRADUCCIÓN            threatintel/translate.py                │
  │                                                                  │
  │   Solo la PRIMERA vez que se ve una amenaza. Si reaparece, no    │
  │   se retraduce                                                   │
  │                                                                  │
  │   limpiar HTML → proteger términos → traducir → restaurar → caché│
  │                                                                  │
  │   Argos (~0,3 s) para el volumen, con marcadores que protegen    │
  │   nombres de producto, siglas, CVE y versiones                    │
  │   Ollama (~20 s) solo en severidad crítica, con instrucciones    │
  │   explícitas y SIN marcadores (llegó a interpretar el marcador   │
  │   como una sigla e inventarse su significado)                     │
  └──────────────────────────┬──────────────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │ 8. ENRIQUECIMIENTO       threatintel/enrich.py                   │
  │                                                                  │
  │   Solo para las que tienen CVE:                                  │
  │     NVD 2.0  → puntuación y vector CVSS oficiales                │
  │     CISA KEV → ¿explotación confirmada? (índice en caché 12 h)   │
  │     EPSS     → probabilidad a 30 días (lotes de 100 CVE)         │
  │                                                                  │
  │   Sin clave de API: 5 peticiones cada 30 s → 150 CVE/ejecución   │
  │   Las esperas de red ocurren FUERA de toda transacción, para no  │
  │   bloquear la interfaz web                                        │
  └──────────────────────────┬──────────────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │ 9. SALUD DE LA FUENTE    threatintel/sources.py + health.py      │
  │                                                                  │
  │   De CADA consulta se registra: ok, código HTTP, entradas,       │
  │   aceptadas, latencia y error                                     │
  │                                                                  │
  │   Tras 3 ejecuciones seguidas sin aportar nada → correo al       │
  │   administrador, agrupando todas las caídas en UN mensaje         │
  │                                                                  │
  │   Ésta es la pieza que faltaba: la causa de que 10 fuentes       │
  │   llevaran 33 días caídas no era la URL rota, era que nadie      │
  │   se enteraba                                                     │
  └─────────────────────────────────────────────────────────────────┘
```

### 4.2 Los cuatro tipos de fuente

El sistema no trata todo como RSS. La columna `kind` decide el extractor:

| `kind` | Qué es | Cómo se consulta | Qué se extrae |
|---|---|---|---|
| `rss` | Feed RSS o Atom | `GET` + `feedparser` | title, summary, link, published |
| `kev_json` | Catálogo CISA KEV | `GET` JSON, caché 12 h | CVE, fecha límite, fabricante, uso en ransomware |
| `nvd_api` | API 2.0 del NIST | `GET` con `?cveId=`, respetando cuota | CVSS, vector, CWE, referencias, fechas |
| `epss_api` | API de FIRST | `GET` por lotes de 100 CVE | probabilidad y percentil |

### 4.3 Del volumen al dato útil

Números reales de la ejecución del 3 de septiembre de 2026:

```
  6.015 entradas descargadas de 52 feeds
    ├─ 3.265 descartadas  fuera de la ventana de 45 días
    ├─ 1.769 descartadas  ninguna tecnología del inventario
    └─   981 aceptadas
            ├─ 889 reaparición de algo ya conocido (no se re-alerta)
            └─  92 amenazas nuevas
                    └─ las que alcanzan la severidad mínima → alerta
```

De 6.015 entradas a 92 amenazas nuevas: **el 98,5 % se descarta**, y eso es exactamente lo que debe ocurrir. El valor del sistema no está en recolectar mucho, sino en descartar bien.

---

## 5. Operación

### Probar una fuente

**Interfaz → Fuentes → botón «Probar»**. Consulta en vivo sin guardar nada y devuelve un error accionable:

| Error | Significado | Qué hacer |
|---|---|---|
| `http_403` | El servidor bloquea la petición | Suele ser el User-Agent; ya se envía uno real |
| `http_404` | La URL no existe | Buscar la nueva o desactivar |
| `http_429` | Demasiadas peticiones | Transitorio; subir el tiempo de espera |
| `no_es_feed` | Devuelve HTML, no XML | La URL apunta a la web, no al feed |
| `timeout` | No responde a tiempo | Subir el tiempo de espera; si persiste, desactivar |
| `dns` | El dominio no resuelve | El sitio ha desaparecido |

### Añadir una fuente

1. **Fuentes → Añadir fuente**, dejándola **inactiva**
2. **Probar**: si devuelve entradas, activarla
3. Asignar prioridad según su relevancia para el inventario, no según su fama

### Desde consola

```bash
# Reparar el catálogo y añadir las recomendadas, verificando en vivo
.venv/bin/python bin/reparar_fuentes.py --dry-run
.venv/bin/python bin/reparar_fuentes.py

# Probar una sola fuente
.venv/bin/python bin/ejecucion_diaria.py --fuente cisa_kev --dry-run
```

---

## 6. Fuentes consultadas para esta selección

- [ThreatFilter — directorio de fuentes de seguridad](https://threatfilter.dev/sources/)
- [VMRay — 12 Free Threat Intelligence Feeds (2026)](https://www.vmray.com/best-threat-intelligence-feeds/)
- [ANY.RUN — Best Threat Intelligence Feeds for SOCs (2026)](https://any.run/cybersecurity-blog/best-threat-intelligence-feeds-2026/)
- [Debian — Security Information](https://www.debian.org/security/)
- [Feedspot — Cyber Security RSS Feeds by Category](https://rss.feedspot.com/cyber_security_rss_feeds/)

Cada candidata se verificó después contra este servidor. **Las cinco listas anteriores incluían feeds que ya no funcionan**, así que la prueba en vivo no era opcional: de las 42 candidatas probadas, 2 fallaron.

---

*Documento generado el 3 de septiembre de 2026. Para reproducir la verificación: `bin/reparar_fuentes.py --dry-run`.*
