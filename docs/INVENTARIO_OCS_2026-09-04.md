# Inventario real (OCS Inventory) y validación por activo — propuesta 2026-09-04

Estado: **implementado el 4 de septiembre de 2026** (fases 1 a 4 del apartado 4; la fase 5,
comparación con la última versión estable de navegadores, queda pendiente). Véase el
apartado 5 «Implementación» al final. Conexión a los dos OCS validada el
2026-09-04 (usuario de solo lectura, MariaDB 10.11, esquema OCS 2.4+
normalizado: `hardware`, `software`, `software_name`, `software_version`,
`software_publisher`, `networks`, `accountinfo`). Credenciales en
`config/credentials.env` (`OCS_SERVIDORES_*`, `OCS_EQUIPOS_*`). Prueba:
`bin/probar_ocs.py`.

## 1. Lo que hay (medido)

| | Servidores (10.1.2.100) | Equipos de usuario (10.1.1.204) |
|---|---|---|
| Activos | 557 | 323 |
| Sistemas | Ubuntu 24.04 (112), 22.04 (103), 20.04 (8); Debian 13.x (146), 12 (39), 11.1 (7); FreeBSD 14.x/15.0 (101), 11.4 (6) | Ubuntu 22.04 (230), 24.04/26.04 (6); Windows 11 (43), 10 (4), 7 (1); 39 sin SO |
| Software | ~450.000 registros; containerd/Docker en ~150 servidores con 34 versiones; apache2, certbot, curl, postgres… | ~468.000 registros; Sophos Endpoint (48), TightVNC (46), DWAgent (48), Chrome 150-152, Firefox 130-155, Java 7/8, 7-Zip 15-26, Acrobat, OpenVPN, ownCloud, LibreOffice, VS Code |
| Sin reportar > 30 días | 45 | 42 |

Conclusión: la organización es Linux/BSD en servidores (sin Windows Server) y
mayoritariamente Ubuntu en puestos, con un núcleo Windows 11. La precisión viene de
**comparar versiones de paquete por equipo**, no de leer noticias.

## 2. Fuentes: decisión

**Desactivadas el 2026-09-04** (0 accionables en 90 días, ruido y coste): Troy Hunt,
Schneier, Krebs, The Record, CyberScoop, Ars Technica, The Register, Help Net, SANS ISC,
Unit 42, ESET, SentinelLabs, Trend Micro, Malwarebytes, Kaspersky, Mandiant, Project
Zero, Infosecurity Magazine, Dark Reading. Se conservan desactivadas (no eliminadas)
porque las amenazas históricas las citan.

**Se mantienen**: NVD, EPSS, CISA KEV, CISA Advisories/Current Activity/ICS, MSRC,
Ubuntu Security (USN RSS), Debian DSA/DLA, Red Hat, openSUSE, Chrome Releases,
PostgreSQL, GitLab, Bitdefender, Exploit-DB, ZDI, CERT-FR, CERT-EU, NCSC, CIRCL, y los
medios que sí aportan (The Hacker News, Bleeping Computer, Cyber Security News,
SecurityWeek, Segu-Info, Rapid7, GBHackers, Hispasec, Tenable, Check Point Research).
Pendiente de confirmar equipos de red: Cisco, Fortinet, Palo Alto, Check Point.

**Nuevas, verificadas en vivo el 2026-09-04:**

| Fuente | Tipo | Verificación | Uso |
|---|---|---|---|
| FreeBSD Security Advisories | RSS `https://www.freebsd.org/security/feed.xml` | 200, 31 KB | Avisos FreeBSD-SA/EN → alerta (107 servidores). **Añadida.** |
| FreeBSD VuXML | XML `https://vuxml.freebsd.org/freebsd/vuln.xml` | 200, 10 MB | Vulnerabilidades por *port* con rangos de versión → aplicabilidad por servidor |
| OSV.dev | API `POST https://api.osv.dev/v1/query` (paquete, ecosistema `Ubuntu:22.04`, `Debian:12`…, versión) | 200; devuelve UBUNTU-CVE-*/DEBIAN-CVE-* con rangos corregidos | **Motor principal de aplicabilidad** Debian/Ubuntu por equipo: pregunta exacta «¿esta versión de este paquete tiene vulnerabilidades sin corregir?» |
| Debian Security Tracker | JSON `https://security-tracker.debian.org/tracker/data/json` | 200, 72 MB | Estado por paquete y release (fixed/vulnerable/no-dsa); descarga diaria a disco, no por la ruta de 15 MB de los feeds |
| Ubuntu USN | RSS ya activo; base `usn-db/database.json` (344 MB) y OVAL por release (1,3 MB bz2) | 200 | El RSS alerta; para aplicabilidad basta OSV (ecosistema Ubuntu) |
| CVE.org (CVE List 5.x) | API `https://cveawg.mitre.org/api/cve/<CVE>` | 200, JSON 5.2 | Enriquecimiento cuando NVD aún no puntuó: descripción, CNA, versiones afectadas |
| endoflife.date | API `https://endoflife.date/api/<producto>.json` | 200 (ubuntu, debian, freebsd, windows, java, chrome, firefox…) | Fin de soporte por versión → alerta «fuera de soporte» sin CVE |
| ColCERT | sitio `https://www.colcert.gov.co/` | 200 pero **sin RSS** (`/rss.xml`, `/feed` → 404) | Contexto local; hace falta la URL exacta del canal o extraer de la página |
| CSIRT Financiero (Asobancaria) | `csirtfinanciero.com` | **sin respuesta desde este servidor** | Contexto local; confirmar dominio/URL |

Las de tipo API/conjunto de datos se registran en el catálogo con el tipo nuevo
`dataset`: se les hace seguimiento de salud (disponibilidad, tamaño, latencia) pero
**no generan amenazas por sí solas**: las consume el motor de aplicabilidad.

## 3. Motor de aplicabilidad por activo (lo que hay que construir)

### 3.1 Sincronización con OCS (diaria, antes de la recolección)
- Tablas nuevas: `activos` (id_ocs, origen servidores/equipos, nombre, SO, versión SO,
  IP, última conexión, etiquetas: DMZ/Internet si la IP lo indica), `activo_software`
  (activo, nombre, versión, fabricante), `sync_ocs` (fecha, filas, duración, errores).
- Lectura con `pymysql`, usuario de solo lectura, en lotes; ~1 millón de filas en
  pocos minutos. Se guarda un hash por activo para detectar **cambios** (software
  nuevo, versión cambiada, equipo nuevo).
- **Mapa de nombres** OCS → tecnología del inventario (`tecnologia_ocs`): reglas por
  patrón («Google Chrome» → chrome; «Mozilla Firefox (x64 es-ES)» → firefox; paquete
  `apache2` → apache-httpd; `containerd.io` → containerd…). Propuestas automáticas por
  similitud; el operador confirma en la interfaz. Lo no mapeado queda visible como
  «software sin clasificar» ordenado por número de equipos.
- El inventario actual (`technologies.version_installed`, `systems_count`) pasa a
  calcularse desde OCS: versión mínima instalada (peor caso), número de activos,
  desglose servidores/equipos. Lo que hoy es manual se rellena solo.

### 3.2 Aplicabilidad exacta
Para cada amenaza con CVE y para cada activo con software mapeado:
1. **Debian/Ubuntu**: `OSV.dev` con (paquete, `Debian:13` / `Ubuntu:22.04`, versión
   dpkg exacta) → lista de CVE sin corregir en esa versión. Cruce con la amenaza:
   `afectado` / `no afectado` (versión ya corregida) / `sin dato`. Complemento diario
   con el Debian Security Tracker para el estado por release.
2. **FreeBSD**: VuXML por *port* y rango; el sistema base por FreeBSD-SA (versión
   `14.4-RELEASE-p6` frente al parche que corrige).
3. **Windows y software de escritorio**: versión OCS frente a versión corregida del
   aviso (extracción actual `versions.py`) y, para navegadores, frente a la última
   versión estable publicada (Chrome Releases, Mozilla).
4. **Fin de soporte**: `endoflife.date` por producto y ciclo (Windows 7, Ubuntu 20.04,
   Debian 11, FreeBSD 11.4, Java 7/8…) → hallazgo propio, sin CVE.
Resultado por (amenaza, activo): veredicto, evidencia («apache2 2.4.58-1ubuntu8.11 <
2.4.58-1ubuntu8.16 corregida en USN-7123-1»), fecha. La relevancia usa el número de
activos afectados y su exposición real.

### 3.3 Interfaz: visualización por activo
- **Activos** (página nueva): lista con búsqueda por nombre/IP/SO, filtros
  (servidores/equipos, SO, sin reportar, con vulnerabilidades confirmadas), columnas:
  activo, SO, última conexión, software mapeado, **vulnerabilidades que le aplican**
  (confirmadas/KEV), estado del agente.
- **Ficha de activo**: datos OCS, software con versión y su tecnología, tabla de
  amenazas que le aplican con veredicto y evidencia, fin de soporte, cambios recientes,
  y el botón «**¿Le aplica este CVE?**»: se escribe un CVE y responde sí/no/sin dato
  con la evidencia (versión instalada frente a corregida).
- **Ficha de amenaza**: bloque «Activos afectados» con la lista (nombre, IP, versión,
  veredicto) y enlace a cada activo; la relevancia explica cuántos activos y cuáles.
- **Panel**: activos afectados por vulnerabilidades confirmadas, fuera de soporte, sin
  reportar; gráfico de cobertura del mapa de nombres.
- **Inventario**: cada tecnología muestra activos y versiones reales (desde OCS) en vez
  del campo manual; el operador solo ajusta criticidad y exposición.

### 3.4 Informe y alerta
- Alerta diaria: cada amenaza «requiere acción» trae los activos afectados (máx. 10 y
  «y N más»), con nombre e IP; el asunto indica «N activos afectados».
- Informe mensual: apartado **«Activos afectados»** (por activo: qué vulnerabilidades
  confirmadas tuvo, cuáles se corrigieron en el mes —desaparecen del inventario— y
  cuáles siguen), **«Fin de soporte»**, **«Cobertura del inventario»** (activos sin
  reportar, software sin clasificar), y en cada ficha la lista de activos. Anexo por
  activo exportable a CSV.
- Alertas nuevas y exactas: vulnerabilidad confirmada por activo; KEV presente; fuera
  de soporte; parche pendiente frente a última versión; software de riesgo (TightVNC,
  DWAgent, Java 7); activos ciegos (> 30 días sin reportar); cobertura de agente
  (Ubuntu de usuario sin EDR); dispersión de versiones; software nuevo en servidor.

## 4. Orden de implementación propuesto
1. Sincronización OCS + mapa de nombres + página Activos con búsqueda y ficha (base).
2. Aplicabilidad Debian/Ubuntu con OSV (cubre 445 servidores y 236 equipos) y
   FreeBSD con VuXML/SA; fin de soporte con endoflife.date.
3. Activos afectados en alerta, ficha de amenaza e informe; «¿Le aplica este CVE?».
4. Alertas de política (software de riesgo, ciegos, agente) y dispersión.
5. Windows/escritorio: comparación con última versión estable.

## 5. Implementación (2026-09-04)

| Pieza | Dónde |
|---|---|
| Esquema v4: `activos`, `activo_software`, `sync_ocs`, `tecnologia_ocs`, `aplicabilidad`, `aplicabilidad_amenaza`, `osv_cache`, `fin_soporte`, `hallazgos_activos`; columnas `technologies.activos_ocs`, `versiones_ocs`, `ocs_actualizado_at` | `threatintel/db.py` |
| Sincronización OCS (lector con cursor sin almacenar, hash por activo, normalización del sistema, zona por CIDR), mapa de nombres (exacto / empieza por / expresión regular, mapa base de 90 reglas), inventario alimentado por OCS, hallazgos de política (sin reportar, software de riesgo, sin agente) | `threatintel/ocs.py` |
| Comparación de versiones dpkg y pkg de FreeBSD | `threatintel/versiones_distro.py` |
| Motor de aplicabilidad: OSV.dev (caché 7 días, cupo por ejecución), VuXML (caché diaria en `data/cache/vuxml.xml`), comparación con el aviso, endoflife.date, consulta manual, relevancia | `threatintel/aplicabilidad.py`, `threatintel/scoring.py`, `threatintel/enrich.py` |
| Páginas Activos, ficha y Software; activos en ficha de amenaza, panel e inventario | `webui/vistas/activos.py`, plantillas `activos.html`, `activo_detalle.html`, `software.html` |
| Alerta diaria con activos afectados y asunto; informe mensual con apartado 4 y fila por ficha; carta mensual | `threatintel/notify.py`, `emails/alerta.html`, `emails/mensual.html`, `threatintel/report.py` |
| Ejecución diaria: paso 0 (sincronización y fin de soporte) y aplicabilidad tras el enriquecimiento; guion independiente | `bin/ejecucion_diaria.py`, `bin/sincronizar_ocs.py` |
| Ajustes (grupo «Activos e inventario real») | `threatintel/config.py`, `webui/vistas/ajustes.py` |
| Pruebas (sin red ni MariaDB) | `tests/test_activos_ocs.py`, `tests/test_pagina_activos.py` |

Decisiones tomadas al implementar:

- Debian y Ubuntu se evalúan **por paquete instalado aunque no esté mapeado** a una
  tecnología: OSV.dev da el paquete fuente y, en Ubuntu, la lista de binarios con su
  versión corregida. El mapa de nombres sirve para el inventario de tecnologías y para
  la comparación de versión del software que no es de la distribución (Chrome, Java…).
- Si OSV.dev no lista una versión de la distribución entre las afectadas, el activo se
  da por **no afectado**; si no existe registro para la distribución, **sin dato**.
- Un activo con la versión vulnerable suma hasta 25 puntos de relevancia; si todos los
  evaluados ya están corregidos, la relevancia se reduce a un tercio.
- Los hallazgos de política se cierran solos cuando dejan de darse (`resuelto_at`).
- Fechas de OCS (hora local del servidor) se guardan en UTC.

## 6. Ajustes del 5 de septiembre de 2026

Peticiones del usuario tras el primer día de uso y su resolución:

| Petición | Resolución |
|---|---|
| Clasificar el software pendiente | `ocs.TECNOLOGIAS_SUGERIDAS` (44 tecnologías con alias y reglas) y `PATRONES_RUIDO` (bibliotecas, parches KB, fuentes, idiomas…) que no cuentan como pendientes |
| Buscar activos al escribir y sin recargar; botones sin recarga | Lista completa con `data-*` y filtrado, orden y vistas en `app.js`; la URL se actualiza con `history.replaceState` |
| Ver las vulnerabilidades de un activo sin salir de la lista | Botón «N · ver» que carga `/activos/<id>/vulnerabilidades.json` y despliega una tabla |
| «Sin agente de protección» y «software de riesgo» no se entienden | «Sin antivirus Sophos» con explicación; software de riesgo con nombre, versión y motivo (`MOTIVO_RIESGO`, `TIPO_HALLAZGO_EXPLICACION`) |
| «Ver avisos» parece no hacer nada | El enlace lleva a `#resultados` con `estado=todas` |
| Remediación | `aplicabilidad.plan_remediacion` y páginas `/amenazas/<id>/remediacion`, `/activos/<id>/remediacion` (+ `formato=txt`) |
| Detalle en vulnerabilidad | Panel «Detalle del CVE según CVE.org» (`enrich.detalle_cve`, caché `cve_detalle`) y «Cómo se calcula la prioridad» |
| OpenSCAP y SBOM | `threatintel/openscap.py`, `threatintel/sbom.py`, tablas `cumplimiento` y `activo_componentes`, importación en la ficha y `bin/importar_activo.py` |
| Modelo de prioridad con exposición por entorno, facilidad y parche | `scoring.relevancia` / `desglose_relevancia`; `activos.entorno` desde OCS (`accountinfo`) o sufijo del nombre |
| Columna TAG (proceso) | `activos.proceso` para servidores; panel «Servidores por proceso» y filtro |
| Tabla de activos afectados en el correo; quitar «Filtro de hoy» | `emails/alerta.html` |
| No alertar si ningún activo tiene la versión vulnerable | Motivo `sin_activos_afectados` en `queries.motivo_exclusion` (ajuste `alert_skip_without_assets`) |
| Correo diario aunque no haya novedades | Ajuste `alert_send_when_empty`; asunto «sin novedades que requieran acción» con el estado de los activos |
| Gestión de usuarios | `webui/vistas/usuarios.py` (correo como usuario, política de contraseña, auditoría) |
| Pruebas de seguridad | `tests/test_seguridad_plataforma.py` (todas las rutas: sesión, CSRF, rol, cabeceras, XSS con datos de OCS, XXE, subidas, secretos) y `pip-audit` sin vulnerabilidades conocidas |

## 7. Ajustes del 5 de septiembre de 2026 (segunda tanda)

| Petición | Resolución |
|---|---|
| Buscar al escribir en todos los campos, sin recargar ni Enter | `data-filtro-vivo` en los formularios de Amenazas, Inventario, Software y software del activo: `app.js` pide la misma página con los filtros y sustituye solo la zona de resultados; la URL se actualiza. Activos ya filtraba en el navegador |
| Colores del diagrama de entornos parecidos | `CLAVE_ENTORNO` (rojo producción, ámbar contingencia, verde azulado desarrollo, violeta pruebas, pizarra soporte, gris sin entorno) e insignias `.insignia.entorno-*` con contraste en claro y oscuro |
| Clasificar todo el software pendiente | `clasificar_respaldo`: paquetes de Debian/Ubuntu, FreeBSD y CentOS a su tecnología de respaldo; en Windows, componentes y controladores a «Componentes de Windows» y los programas a una tecnología propia con alias exacto (reglas automáticas trazables). Prioridad: manual > mapa base > automática. Cobertura: 100 % de las instalaciones |
| Regla manual frente a automática | `retirar_automaticas` al crear una regla manual; `aplicar_mapa` vuelve a NULL los nombres sin regla antes del respaldo; corregido el fallo por el que el software reinsertado en una sincronización quedaba sin tecnología |
| Página Software lenta | Recuento de activos por regla en memoria; las reglas automáticas solo se listan al buscar |
| Usuario soc | Renombrado a `soc@ejemplo.local` conservando contraseña, rol y sesiones (auditado) |
