# Precisión de alertas e informe — especificación 2026-09-04

> **Estado (2026-09-04, tarde): implementado y aplicado en producción.** Secciones 2 a 6
> en el código con 375 pruebas en verde; alias con contexto y exclusiones aplicados a la
> base (16 + 13), lista de paquetes de este servidor en `data/paquetes/`, histórico
> recorrelado (7.540 → 6.286 correlaciones; Windows 2.098 → 1.435, Linux 642 → 322),
> relevancia recalculada, traducciones de avisos reparadas (1.327 títulos). Ajuste
> posterior del mismo día: `ignore_low_severity` e `ignore_low_criticality` (activados):
> la severidad Baja y las tecnologías de criticidad baja no se tienen en cuenta.
> Pendiente del operador:
> versiones del inventario (sección 0) y clave de API de NVD.

Objetivo: que la alerta diaria contenga solo lo que **realmente impacta** a la
organización y que el informe distinga con claridad lo que exige acción de lo que
es contexto. Se implementa todo lo que no depende de registrar versiones en el
inventario (eso queda para el operador y multiplicará el efecto de lo demás).

## 0. Diagnóstico que motiva los cambios (datos reales, 2026-09-04)

| Hallazgo | Dato |
|---|---|
| Alertas con severidad **estimada** (sin CVSS oficial) | 4.604 de 5.721 (80 %) |
| Estimadas que NVD **rebajó** después por debajo de Alta | 264 de 1.129 (23 %) |
| Alertas con EPSS < 1 % y sin KEV | 886 de 1.122 (79 %) |
| Alertas **sin CVE ni identificador de aviso** | 2.693 |
| Alertas sin ninguna tecnología correlacionada | 556 |
| Avisos Debian (DSA/DLA) jul–sep cuyo paquete **no está en el inventario** | 170 de 225 (76 %) |
| Correlaciones por la palabra suelta «windows / chrome / edge» (confianza 0,4–0,6) | 5.150 |
| Alertas reales de septiembre con relevancia ≥ 50 | 2 de 46 |

Simulación del criterio de alerta (julio / agosto / septiembre parcial):
severidad ≥ Alta → 369 / 307 / 46; **relevancia ≥ 50 o KEV → 17 / 19 / 2**, con las
mismas KEV cubiertas (10 / 11 / 1). Traducción defectuosa de nombres de paquete
(«chromium» → «cromo», «bubblewrap» → «burbujas») en títulos de DSA.

## 1. Cambios ya aplicados por el orquestador (base común; no rehacer)

- `threatintel/db.py`: esquema v3. `threats` tiene `estado` (nueva | en_analisis |
  mitigada | aceptada | descartada | falso_positivo, por defecto `nueva`),
  `estado_at`, `estado_por`, `estado_motivo`, `digest_at`, `alert_skip_reason`,
  `alert_skip_at`. `init_db()` migra bases antiguas (`migrar_columnas`). La base
  real ya está migrada.
- `threatintel/queries.py`: `_THREAT_COLS` incluye las columnas nuevas; constantes
  `ESTADOS`, `ESTADOS_CERRADOS = ("descartada", "falso_positivo")`, `ESTADO_ES`;
  `cambiar_estado(conn, threat_id, estado, *, usuario, motivo=None) -> bool`;
  `buscar(..., estados=None)`. Cada tecnología del `ThreatView` trae
  `confidence` y `matched_alias`.
- `threatintel/scoring.py`: `relevancia(..., min_confianza=0.0)`: las
  coincidencias con `confidence` < `min_confianza` **no cuentan como exposición**
  (son «mención»). `enrich.recalcular_relevancia(conn, cfg=None)` y el
  colector ya pasan `alert_min_match_confidence`.
- `threatintel/config.py` `DEFAULT_SETTINGS` nuevos: `alert_min_relevance=50`,
  `alert_require_identifier=True`, `alert_defer_heuristic_hours=24`,
  `alert_min_match_confidence=0.6`, `digest_enabled=True`, `digest_weekday=1`
  (lunes, isoweekday), `digest_max_items=60`, `debian_packages_file=""`.

## 2. Criterio de alerta (grupo A)

`queries.pendientes_de_alerta(conn, *, cfg, limite=None) -> list[dict]` sustituye a
la firma actual (mantener compatibilidad con `min_severidad`/`solo_afectadas`
como parámetros opcionales que, si se pasan, se respetan). Candidatas:
`alerted_at IS NULL AND estado NOT IN ESTADOS_CERRADOS`. Para cada candidata se
evalúa **en este orden** y el primer motivo que aplique la excluye:

| Motivo (`alert_skip_reason`) | Regla | Excepción |
|---|---|---|
| `estado_cerrado` | estado descartada / falso_positivo | — |
| `sin_identificador` | `cve IS NULL` y `identity.extraer_id_aviso(title_en, summary_en)` es None | `in_kev = 1`; o `alert_require_identifier = False` |
| `heuristica_en_espera` | `severity_source = 'heuristic'`, sin id de aviso oficial, y `first_seen_at` hace menos de `alert_defer_heuristic_hours` | `in_kev = 1` |
| `no_afectada` | `alert_only_affected_versions` y todas sus tecnologías con `version_verdict = 'not_affected'` | — |
| `relevancia_baja` | `relevance < alert_min_relevance` | `in_kev = 1` |

Las que pasan se ordenan por relevancia desc, severidad, CVSS. Una función
hermana `clasificar_pendientes(conn, *, cfg) -> dict` devuelve
`{"alertar": [views], "excluidas": {motivo: [ids]}, "conteo": {motivo: n}}` y
**persiste** `alert_skip_reason`/`alert_skip_at` en las excluidas (solo se
escribe si cambia). `heuristica_en_espera` se reevalúa cada día: pasadas las
horas, la amenaza vuelve a competir con las demás reglas.

`bin/ejecucion_diaria.py`: usa `clasificar_pendientes`; imprime el desglose de
excluidas por motivo; pasa a `notify.render_alert_email` un `meta["filtro"]` con
`{"alertadas": n, "excluidas": {motivo: n}, "umbral_relevancia": 50,
"min_confianza": 0.6}` (contrato con el grupo D2). Nuevo argumento
`--comparar`: imprime, sin enviar nada, cuántas alertaría el criterio antiguo
(severidad ≥ Alta) frente al nuevo, con los títulos de las 10 primeras de cada
uno; sirve para enseñar la diferencia al operador antes de activar.

`webui/vistas/ajustes.py`: grupo «Alertas diarias» con los ajustes nuevos, con
etiquetas y ayudas en español (con tilde) que expliquen el efecto («Relevancia
mínima para alertar (0-100). KEV alerta siempre. Con 50, en julio-agosto se
habrían enviado 17-19 alertas al mes en lugar de 300»).

### Resumen semanal (grupo A)

`threatintel/digest.py` + `threatintel/emails/semanal.html` + `bin/resumen_semanal.py`.
Se envía el `digest_weekday` a las 08:30 (línea nueva en el crontab de `si`:
`30 8 * * 1 cd $DIR && $PY bin/resumen_semanal.py >> logs/cron_semanal.log 2>&1`).
Contenido, con amenazas de los últimos 7 días **no alertadas** y con
`digest_at IS NULL` y estado no cerrado:

1. **Seguimiento**: correlacionadas con el inventario (confianza ≥ 0,6) con
   relevancia 25–49 o severidad ≥ Alta estimada. Agrupadas por tecnología.
2. **Informativo**: el resto con severidad ≥ Media (noticias, campañas), máx.
   `digest_max_items` en total.
3. **Lo que el filtro descartó y por qué**: conteo por `alert_skip_reason` de la
   semana, en una frase por motivo, en lenguaje llano.
4. **Recordatorio de alertadas** de la semana (títulos, enlace).
Usa `notify.entorno()`, la plantilla base de correos existente (mismo aspecto
que la alerta) y `notify.Mailer`. Marca `digest_at` en las incluidas. `--dry-run`
imprime el HTML a `data/revision/semanal_prueba.html`. Asunto:
`[SOC] Resumen semanal de amenazas · semana del <d> de <mes>`.

## 3. Correlación precisa (grupo B) — `threatintel/matching.py`

1. **Avisos de distribución por paquete.** Si el título contiene un identificador
   DSA/DLA (Debian) o USN (Ubuntu), `extraer_paquete_aviso(titulo)` devuelve el
   nombre del paquete (`DSA-6479-1 roundcube - security update` → `roundcube`;
   `USN-7123-1: Linux kernel vulnerabilities` → `linux kernel`). Reglas:
   - El paquete se busca en el inventario (alias word/phrase y slug, insensible a
     mayúsculas; `firefox-esr` casa con `firefox`, `linux` con `linux`,
     `chromium` con `chrome`). Si casa, esa tecnología se correlaciona con
     confianza 0,95 y `version_evidence` conserva lo que diga el aviso.
   - La distribución (Debian/Ubuntu) **deja de correlacionarse por el mero
     identificador**: los alias regex `DS[AL]-…`, `DLA-…`, `USN-…` pasan a
     confianza base 0,3 (mención) en `_confianza_base` o se retiran del seed, y el
     alias `debian`/`ubuntu` como palabra solo cuenta con contexto de
     vulnerabilidad. Resultado: un DSA de un paquete que no tenemos no alerta.
   - Si `cfg.debian_packages_file` apunta a un fichero existente (una línea por
     paquete, salida de `dpkg-query -W -f '${Package}\n'`, se admiten varios
     hosts concatenados), un paquete presente en la lista correlaciona la
     distribución con confianza 1,0 y evidencia «paquete instalado en la lista
     de <fichero>». `bin/detectar_versiones.py --paquetes` genera esa lista en un
     host Debian/Ubuntu.
2. **Alias genéricos con contexto.** En `INVENTARIO_BASE`, los alias de una sola
   palabra común (Windows, Linux, Chrome, Chromium, Edge, Firefox, Java, PHP,
   Docker, LDAP, Nginx, Git, Python, Node, Redis, Apache, Ubuntu, Debian) llevan
   `context_required` con términos de vulnerabilidad (vulnerability, CVE,
   flaw, patch, security update, exploit, zero-day, RCE, privilege escalation,
   actualización de seguridad, vulnerabilidad, parche…). Los alias multi-palabra
   («Microsoft Windows», «Linux kernel», «Google Chrome») no cambian.
3. **Exclusiones**: «Chrome for Android», «Chrome OS», «ChromeOS», «Windows
   Phone», «Windows Mobile», «Xbox», «Edge computing», «edge device(s)»,
   «Java Script» (JavaScript ya está fuera por `\b`), «Docker Hub» solo si no
   habla de vulnerabilidad… Añadir las que la muestra real justifique (consultar
   la base en lectura: alias `windows`/`edge` con confianza ≤ 0,6 en títulos de
   noticias).
4. `bin/actualizar_alias.py`: aplica a la base existente (idempotente) el
   `context_required`, las exclusiones y las confianzas del seed nuevo sin
   borrar alias creados por el operador; imprime el diff. **No** ejecutar la
   recorrelación de toda la base desde el agente: el orquestador la lanza al
   final (`bin/recorrelacionar.py`) y compara antes/después.
5. Pruebas: `tests/test_matching_precision.py` (paquete de DSA/USN, distro sin
   correlación por id, lista de paquetes, contexto en genéricos, exclusiones,
   compatibilidad con los alias regex existentes).

## 4. Traducción fiel (grupo C) — `threatintel/translate.py`

`proteger()` añade, **antes de los literales**, patrones para: identificador de
aviso + nombre de paquete (`\b(?:DSA|DLA|USN|RHSA|ELSA|GHSA|ICSA)-\d+(?:-\d+)?\s+[\w.+-]+`
protegido completo), tokens de paquete con guion o dígito (`libdbi-perl`,
`gst-plugins-bad1.0`, `webkit2gtk`), y nombres entre comillas simples/dobles que
no sean frases (una sola palabra). `bin/reparar_traducciones.py` vuelve a
traducir `title_es` (y `summary_es` si el título coincidía) de las amenazas cuyo
`title_en` contiene un identificador de aviso, de los últimos 90 días, con
`--dry-run` que muestra antes/después y `--aplicar` que escribe (como `si`).
Pruebas en `tests/test_traduccion_paquetes.py` con Argos real si está disponible
(si no, se omiten con `skipTest`) y siempre con `proteger/restaurar` puros.

## 5. Estados y realimentación (grupo D1) — interfaz

`webui/vistas/amenazas.py` (solo añadir rutas; `tendencias()` y `lista()` cambian
lo mínimo), `amenaza_detalle.html`, `amenazas.html`, pruebas en
`tests/test_estados_amenaza.py`.

- Ficha: panel «Gestión» con el estado actual (insignia), quién y cuándo, y un
  formulario (solo admin, CSRF) con `select` de estado (etiquetas `ESTADO_ES`),
  `motivo` (texto), y para **falso positivo** dos casillas: «No volver a
  correlacionar «alias» con «tecnología» sin contexto de vulnerabilidad» (pone
  `context_required` con la lista estándar en ese alias) y «Excluir esta
  amenaza de las tecnologías marcadas» (borra las filas de
  `threat_technologies` elegidas). Ruta `POST /amenazas/<id>/estado`, auditoría
  (`db.audit`), mensajes flash claros. Recalcular la relevancia de esa amenaza
  tras el cambio (`scoring.relevancia` con las tecnologías restantes).
- Lista: filtro «Estado» (todos / abiertas / cerradas / cada estado) usando
  `queries.buscar(estados=…)`; columna «Estado» con insignia; por defecto
  «abiertas» (no cerradas) para que lo descartado deje de estorbar; el CSV
  exporta el estado. La ficha muestra `alert_skip_reason` traducido («No se
  alertó: relevancia 31 por debajo del umbral 50»).
- Las tecnologías con confianza < `alert_min_match_confidence` se muestran en la
  ficha como «mención (confianza 0,4)», separadas de las de exposición.

## 6. Correo de alerta e informe (grupo D2)

`threatintel/notify.py`, `threatintel/emails/alerta.html`, `threatintel/emails/mensual.html`,
`threatintel/report.py`, pruebas en `tests/test_informe_precision.py`.

Alerta diaria (`render_alert_email(threats, meta)`):
- Cada amenaza lleva una línea **«Por qué está aquí»**: `KEV: explotación
  activa confirmada` / `Relevancia 72: afecta a <tec> (crítica, Internet)` /
  `Versión instalada vulnerable`. La calcula `notify` a partir del `ThreatView`.
- Tecnologías con etiqueta de confianza: «coincidencia exacta» (≥ 0,8),
  «probable» (0,6–0,79); las < 0,6 se listan aparte como «menciones» y no como
  afectadas.
- Pie **«Filtro de hoy»** con `meta["filtro"]` si existe: «Se han excluido N
  amenazas: X por relevancia baja, Y sin identificador, Z a la espera del dato
  oficial, W descartadas por el equipo», con enlace a la interfaz. Sin `filtro`
  en `meta`, el pie no aparece (compatibilidad).
- `asunto_alerta` incluye el número de amenazas que requieren acción.

Informe mensual (`report.py`):
- Sección **1. Resumen ejecutivo** reorganizada en tres bloques: **Requiere
  acción** (alertadas o relevancia ≥ umbral o KEV, no cerradas), **Seguimiento**
  (correlacionadas, relevancia 25–49), **Informativo** (resto). Cifras y una
  frase por bloque.
- Nueva sección **«Precisión del filtro»** (antes de la metodología): tabla con
  las excluidas del periodo por motivo (`alert_skip_reason`), falsos positivos
  y descartadas marcados por el equipo, y qué porcentaje del total supuso cada
  cosa; una frase que explique qué significa cada motivo.
- Fichas detalladas (sección 4) **agrupadas por tecnología** (la más expuesta
  primero) y con el estado operativo cuando no sea «nueva». Las cerradas no
  aparecen como fichas; se cuentan en «Precisión del filtro».
- `mensual.html` (carta del correo) refleja los tres bloques.
- Sin cambios en estilo visual del DOCX ni del correo más allá de lo necesario.

## 7. Reglas comunes

- Nada de git. Ficheros `si:si`. Python como `si`. Suite completa en verde:
  `sudo -n -u si .venv/bin/python -m unittest discover -s tests -p "test_*.py"` (331 hoy).
- No enviar correo real: `--dry-run` o `notify.Mailer(cfg, dry_run=True)`.
- No escribir en `data/threat_intel.db` salvo lo indicado (estado desde la
  interfaz, reparación de traducciones con `--aplicar` si el orquestador lo
  pide). Las pruebas usan bases temporales bajo `data/`.
- Español con tilde en todo texto visible; números en formato español.
- Cada grupo edita solo sus ficheros. Lo que necesite de otro fichero se
  describe en `pendientes` con el cambio exacto.

## 8. Sin afectación confirmada no se alerta (2026-09-10)

> Petición del usuario, sobre el correo del 10 de septiembre de 2026: «en el correo de
> alertamiento de hoy veo que no hay activos afectados según la vulnerabilidad, esa alerta
> sobre esas vulnerabilidades que no me afectan ningún activo no tiene sentido, repito,
> **me debe alertar lo que realmente me esté afectando, de lo contrario no**».

### 8.1 El problema, con la medida

Ese día se alertaron **35 amenazas** y **4 no tenían ningún activo afectado confirmado**.
Las cuatro tenían algo en común: **nunca se habían evaluado** contra el inventario (no
había fila en `aplicabilidad_amenaza`), así que el filtro de afectación se abstenía —para
no callar una vulnerabilidad por un fallo propio— y pasaban al correo con el bloque
«Afectación todavía sin evaluar».

| CVE | Severidad | Explotación activa | Relevancia | Evaluada |
|---|---|---|---|---|
| CVE-2025-53521 | Crítica | sí (CISA KEV) | 73,8 | nunca |
| CVE-2025-25249 | Crítica | sí (CISA KEV) | 69,5 | nunca |
| CVE-2026-85102 | Crítica | no | 61,9 | nunca |
| CVE-2026-12087 | Crítica | no | 51,8 | nunca |

**Causa raíz medida.** `aplicabilidad.evaluar_pendientes` reparte un cupo de
`applicability_max_threats_per_run` (150) entre las primeras evaluaciones y las
reevaluaciones de amenazas antiguas con explotación activa y relevancia alta. Ese día
entraron **923 amenazas nuevas**: amenazas de relevancia 74 y 70 se quedaron sin evaluar y
el filtro las dejó pasar por abstención.

### 8.2 Qué se cambió

1. **Evaluar antes de decidir, no abstenerse.** La ejecución diaria, en el paso de alerta
   y antes de aplicar el filtro, pide las candidatas a alertar sin evaluación utilizable
   (`queries.candidatas_sin_evaluacion`) y las evalúa **dirigidas**
   (`aplicabilidad.evaluar_dirigido`): sin el cupo de reparto, en el orden que importa
   (explotación activa primero, después relevancia) y con su propio tope de seguridad
   (`LIMITE_EVALUACION_DIRIGIDA`, 250; las candidatas de un día normal son 4). Así la
   decisión se toma **con datos en la mano** en vez de por abstención.
2. **Sin confirmación no se alerta.** La rama de abstención de `queries.motivo_exclusion`
   ya no alerta: si tras el paso 1 la amenaza sigue sin evaluación o con la evaluación
   incompleta, queda con el motivo nuevo **`sin_evaluar_todavia`** («a la espera de la
   evaluación contra el inventario») y no entra en el correo. Nada se pierde: `alerted_at`
   sigue a NULL, la clasificación se repite cada día, la amenaza es consultable con su
   motivo, entra en el resumen semanal y se alerta en cuanto la evaluación confirme un
   activo. El motivo tiene su texto en los tres sitios de siempre (ficha,
   pie del correo diario y resumen semanal).
   **Solo se aplica a las candidatas reales**: si la relevancia no llega al umbral y no hay
   explotación activa, el motivo sigue siendo `relevancia_baja`. Sin esa condición, medido
   sobre la base real, el motivo nuevo se llevaba **241 amenazas irrelevantes** y el
   resumen semanal habría dicho «241 a la espera de la evaluación» sobre amenazas que
   nunca se habrían alertado.
3. **La explotación activa confirmada tampoco alerta sin afectación.**
   `alert_kev_sin_activos` pasa a valer **False** por omisión (`threatintel/config.py`), con
   su texto de ayuda reescrito en Ajustes. El ajuste se conserva: la decisión es reversible
   y, activado, el correo vuelve a llevarlas diciendo con todas sus letras que no se ha
   confirmado en ninguna máquina.
4. **La única abstención que queda es «no hay inventario».** Sin un solo activo con
   `presente = 1` —o con `applicability_enabled` apagado— el criterio no significa nada y
   se alerta como antes de que existiera: es la válvula de escape para que un fallo de la
   sincronización con OCS Inventory no deje el correo vacío en silencio.
5. **Un fallo técnico no puede callar nada en silencio.** Lo que no se consigue evaluar
   sale en un **aviso de administración** (`aplicabilidad.avisar_sin_evaluar`, tabla
   `admin_notices`, tipo `aplicabilidad_sin_evaluar`), con la lista, la severidad, la
   explotación activa, la relevancia y **por qué** no se pudo evaluar (sin CVE, evaluación
   incompleta, cupo de la evaluación dirigida, fallo del motor, sin inventario). Severidad
   `critical` si alguna tiene explotación activa confirmada; como mucho **un aviso al día
   por vulnerabilidad**, y si el correo no se puede enviar no se marca nada como avisado y
   se reintenta al día siguiente.
6. **El correo, revisado con el mismo criterio.** Se retiró de `threatintel/emails/alerta.html`
   el bloque «Afectación todavía sin evaluar» (ya no puede ocurrir) y la frase de cabecera
   dice la cifra **sobre el total del correo**: «Las 42 amenazas de este correo tienen
   activos de la organización con la versión vulnerable instalada» o «31 de las 35…»
   cuando difieren, en cuyo caso explica la diferencia («las otras están aquí por su
   explotación activa confirmada aunque NO se haya confirmado la versión vulnerable en
   ninguna máquina»), que con el ajuste apagado no puede pasar.

### 8.3 Efecto medido (copia de producción, 2026-09-10)

Reconstruyendo la clasificación del día sobre una copia de la base real (35 amenazas
alertadas, se olvida que se alertaron; la base ya había avanzado desde el correo de la
mañana, de ahí que los totales sean 41-42 y no 35):

| Medida | Antes de la evaluación dirigida | Después |
|---|---|---|
| Amenazas que alertarían | 41 | **42** |
| Excluidas `sin_evaluar_todavia` | 4 | **0** |
| Excluidas `sin_activos_confirmados` | 194 | 197 |
| Excluidas `relevancia_baja` | 812 | 812 |
| Amenazas del correo con activos confirmados | — | **42 de 42** |

* **Evaluación dirigida**: 4 candidatas evaluadas en **4,0 s** con **8 consultas a
  OSV.dev** (cupo de red intacto: el tope son 300).
* De las cuatro del incidente: **CVE-2026-12087 SÍ nos afecta** (335 activos afectados,
  182 ya corregidos) y entra en el correo con su lista de máquinas; las otras tres
  (CVE-2025-53521, CVE-2025-25249 y CVE-2026-85102) quedan fuera con el motivo exacto
  `sin_activos_confirmados`, no con «no se sabe». Es el dato que importa: el arreglo bueno
  era **evaluarlas a tiempo**, no callarlas.
* Con `alert_kev_sin_activos` activado (el valor guardado hoy en producción) serían **44**
  amenazas, 2 de ellas con explotación activa y sin afectación confirmada.
* El correo generado con el criterio nuevo **no contiene** ninguna frase de «afectación
  sin evaluar» ni «sin haber confirmado».

### 8.4 Pruebas

`tests/test_alerta_solo_confirmada.py` (19 pruebas, sin red y sin correo real): el motivo
nuevo y su persistencia; que la evaluación dirigida cambia la decisión en los dos sentidos;
que no se piden las que no se pueden o no hace falta evaluar (sin CVE, irrelevantes,
severidad baja, ya evaluadas) y que la explotación activa va primero; que el cupo de
reparto no la limita; el tope de seguridad; la explotación activa con el valor por omisión
nuevo y con el ajuste activado; el aviso de administración con su silencio de 24 horas, sin
destinatarios y con el correo rechazado; y que el correo no lleva ninguna frase de
afectación sin evaluar. `tests/test_criterio_afectados.py` conserva los casos de la
revisión del 2026-09-08 reescritos con la regla nueva (cinco pruebas de `TestSalvaguardas`
y el valor por omisión de `alert_kev_sin_activos`).

### 8.5 Pendientes y riesgos

* **El ajuste guardado en producción** vale `true` (`alert_kev_sin_activos`): el valor por
  omisión nuevo solo aplica a bases nuevas. El coordinador lo cambia al desplegar; hasta
  entonces las KEV sin afectación confirmada siguen alertándose (2 el 2026-09-10).
* Un aviso de proveedor **sin CVE** (DSA, USN, RHSA) no se puede evaluar, así que con el
  criterio nuevo no se alerta y queda con `sin_evaluar_todavia`. Medido el 2026-09-10:
  ninguna de las 35 amenazas alertadas venía sin CVE, así que el cambio no quita nada de
  lo que hoy se reporta; si en el futuro llegara alguno relevante, saldrá en el aviso de
  administración con el motivo «no trae CVE».
* La evaluación dirigida usa red (OSV.dev y, con FreeBSD en el parque, VuXML). Si la red
  falla, las candidatas quedan sin evaluar, no se alertan y **sí** se avisa a
  administración.
