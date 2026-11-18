# Afectación real, claridad de las cifras y deduplicación de remediaciones

**8 de septiembre de 2026.** Tres frentes pedidos por el usuario el mismo día, más las
correcciones de la revisión adversaria que rechazó los tres en su primera versión.

## 1. Qué se pidió

Textualmente:

1. *«la idea es que me registre las amenazas que sí me afectan, no las que no me
   afectan porque no tiene sentido… como el correo que se envió hoy, no me afecta ningún
   activo pero me alertó»*.
2. *«las amenazas no son claras: en servidores dice 30.827 pero no dice qué son, después
   dice 485 equipos, pero luego no son servidores? y 602 amenazas, falta especificación en
   los datos, usted no puede asumir que al ver una cifra cualquiera entienda qué es. En la
   tabla de tipo de equipo necesito una fila de total»*, y *«en la gráfica de
   vulnerabilidades por proceso de negocio, solo necesito que diga vulnerabilidades por
   proceso, y que si son servidores que diga servidores»*, y *«muchas cifras no cuadran
   porque en activos me dice que hay 511 servidores y 325 equipos, pero en amenazas veo
   cifras diferentes»*.
3. *«sigo viendo duplicidad en el reporte de vulnerabilidades… si hay una vulnerabilidad
   de kernel que se repite que se cuente como una y se vea la trazabilidad de las versiones
   a las que se solicita actualizar»*, y *«no veo tampoco la opción de que servicios
   tecnológicos pueda documentar sobre una vulnerabilidad en un activo»*.

## 2. Criterio de afectación real

`threatintel/queries.py`, regla 4c de `motivo_exclusion`. Una amenaza se alerta solo si
al menos un activo con `presente = 1` tiene veredicto `afectado` en `aplicabilidad`.

Ajustes: `alert_solo_con_activos_afectados` (activado) y `alert_kev_sin_activos`
(activado, excepción para la explotación activa confirmada).

### Medido sobre producción (392 amenazas pendientes de alertar)

| | Amenazas |
|---|---|
| Alertarían sin el criterio | 15 |
| Alertarían con el criterio | **13** |
| De ellas, con activo presente confirmado | 13 (todas) |
| KEV que se alertan sin confirmar | 0 |

Motivos de exclusión hoy: 159 sin afectación confirmada, 98 severidad baja, 61 sin
identificador, 51 relevancia baja, 9 sin activos afectados, 1 versión no vulnerable.

Histórico, con la afectación tal como está hoy en la base: de las 1.290 amenazas
alertadas desde el 1 de agosto, 289 (22,4 %) tenían afectación confirmada.

### Las tres salvaguardas (hallazgo ALTO de la revisión)

La primera versión leía la **ausencia** de evaluación como un cero. No es lo mismo:

- **`evaluado_at` obligatorio.** Solo se calla una amenaza que tenga fila en
  `aplicabilidad_amenaza` con marca de evaluación. El motor se queda corto a diario
  (`applicability_max_threats_per_run`, 150 por ejecución) y puede fallar por red: en
  `logs/cron_diario.log` consta un «fallo la aplicabilidad por activo [Response ended
  prematurely]» con 26 amenazas nuevas y **cero** evaluadas.
  Reproducido sobre una copia de producción: borradas `aplicabilidad` y
  `aplicabilidad_amenaza`, la primera versión dejaba las 15 alertas del día en **0**; con
  la salvaguarda vuelven a ser 15.
- **Amenazas sin CVE exceptuadas.** `aplicabilidad.evaluar_pendientes` solo evalúa las que
  tienen CVE, así que un aviso de proveedor sin CVE (DSA, USN, RHSA, SUSE-SU) nunca podría
  confirmarse: callarlo sería definitivo, no un retraso de un día.
- **Sin inventario, evaluación incompleta o `applicability_enabled` apagado**: el filtro
  se abstiene, como ya hacía.

### Conteo por CVE, no solo por amenaza (hallazgo MEDIO)

La fila de `aplicabilidad` es única por `(activo_id, cve, paquete)` y su `threat_id` lo
sobrescribe la última amenaza evaluada. El mismo CVE llega por dos fuentes en 139 casos
(297 amenazas implicadas), así que una de las hermanas se quedaba con cero activos propios
y se callaba una vulnerabilidad confirmada de verdad (caso real: CVE-2026-50508, amenazas
5668 y 2607). `_adjuntar_activos_afectados` cuenta por `threat_id` y por `cve`, y toma el
mayor de los dos.

### La excepción KEV, ahora visible (hallazgo ALTO)

La marca `kev_sin_activos_confirmados` no la leía ninguna plantilla, así que en el correo
esa KEV salía sin cifras de activos y sin advertencia: indistinguible de una confirmada.
`threatintel/emails/alerta.html` imprime ahora, en el detalle de esa amenaza,
«Explotación activa confirmada, afectación NO confirmada… revísese a mano», y el pie dice
cuántas van así. De las 76 KEV de la base, 67 no están confirmadas en ninguna máquina.

### El pie del correo dice el porqué

Hasta hoy solo imprimía el total de excluidas. Ahora imprime el **desglose por motivo**,
con la frase de `notify.MOTIVOS_FILTRO_ES`. Y `digest.FRASES_MOTIVO` tiene la frase del
motivo nuevo: sin ella el resumen semanal habría escrito «196 por
«sin_activos_confirmados».», con guiones bajos y sin tildes, en un correo que lee el
usuario. Una prueba recorre `queries.MOTIVOS_EXCLUSION` y falla si a algún motivo le falta
su frase en cualquiera de los tres sitios, para que el próximo motivo nuevo no vuelva a
salir en crudo.

## 3. Claridad de las cifras

### Un nombre para cada cosa

Regla: **servidores** y **equipos de cómputo**; **activos** solo cuando la cifra mezcla
los dos tipos; «equipos» a secas **prohibido** en todo texto visible.

Había tres nombres para la misma cosa: `ocs.ORIGEN_PLURAL_ES` decía «Equipos de usuario»
(página de Activos, resumen semanal, informe mensual, libro de la alerta),
`queries.ORIGEN_AMENAZAS_ES` decía «Equipos de cómputo» (página de Amenazas) y el Panel
usaba «equipos» como unidad de sus cuatro cifras de cabecera. Unificado en «equipos de
cómputo», con dos pruebas: una exige que las dos tablas coincidan y otra barre la página
de Amenazas entera —glosario incluido, que era la exclusión que quedaba— buscando el
plural ambiguo.

### Cada cifra de máquinas con su denominador

`queries.resumen_amenazas` devuelve ahora `presentes` (total, servidores, equipos),
`presentes` en cada fila de `por_origen`, y `presentes` / `presentes_servidores` /
`presentes_equipos` / `activos_de_servidores` / `activos_de_equipos` en cada grupo de
proceso. Vive en la misma función que el numerador para que no puedan divergir; la vista
usa `cifras["presentes"]` y `_parque_presente` se conserva como comprobación
independiente, con una prueba que exige que las dos cuenten lo mismo.

Consecuencias:

- La nota de cada barra de proceso lleva denominador («171 de 175 servidores afectados»):
  sin él, «33 servidores afectados» de un grupo y «171» de otro no se podían comparar.
- La nota de un proceso con los dos tipos de máquina cuenta **máquinas**, no
  vulnerabilidades: antes devolvía «1.234 en servidores · 567 en equipos de cómputo» en la
  misma columna en la que las notas hermanas cuentan máquinas.
- `queries.filtro_parque` es pública: la vista ya no depende de un nombre privado.

### La fila de total

Las vulnerabilidades y los activos afectados **sí** se suman entre filas; las amenazas
distintas **no**, porque la misma amenaza está en los dos tipos de máquina (602 + 963 =
1.565 frente a 1.032 reales), y la tabla lo dice.

Hallazgo ALTO: la clave del rótulo se decidía con `len(filas) > 1`, y también hay una sola
fila cuando uno de los dos tipos no tiene ninguna vulnerabilidad viva. En ese caso el
denominador seguía siendo el parque completo y la fila quedaba rotulada «485 de 836
servidores», que incluye los 325 equipos de cómputo: la queja original, reaparecida en la
fila nueva. Ahora la clave la decide el filtro (`origen_parque`), no el número de filas.

### Con filtro puesto, la pantalla dice de qué habla

- «6.150 no se han confirmado en ningún activo» era falso con un proceso seleccionado: el
  numerador estaba acotado y el denominador no. `resumen_amenazas` devuelve
  `confirmadas_global` y `sin_confirmar_global`, y la tarjeta escribe las dos cifras con
  su ámbito.
- La promesa «coinciden con lo que allí se ve y puede cotejarlos» solo se hace **sin
  filtro**: la página de Activos muestra el parque completo sea cual sea el filtro con el
  que se llegue. Con filtro, la frase lo dice.
- El enlace de la tarjeta «Activos afectados» arrastra ahora también el tipo de máquina:
  con `?origen=equipos` se pulsaba la cifra y se aterrizaba en una página que decía otra.
- Concordancia de número en la frase de ámbito y en el rótulo: el proceso «Fcaeldi» tiene
  un solo servidor y se leía «1 activos con inventario presente, de los que 1 tienen».
- «Amenazas registradas» cuenta con el **mismo** criterio de cierre que el listado de la
  propia página (`ESTADOS_CERRADOS`): antes excluía también las mitigadas, así que en
  cuanto alguien marcaba una amenaza como mitigada la misma pantalla mostraba dos totales
  distintos sin explicación.
- Se retiraron las cifras escritas a mano del recorrido guiado («485 de 511 servidores»),
  que quedan obsoletas en cuanto cambia el inventario.

## 4. Deduplicación de remediaciones

### La unidad de trabajo es la actualización

`remediacion.listar_actualizaciones` agrupa por `(activo, paquete)`: en producción, 19.284
actualizaciones que cubren 47.526 vulnerabilidades. La **versión objetivo** es la más alta
del grupo con el comparador de la distribución, nunca por orden de texto: con las nueve
versiones que los avisos pidieron para un mismo kernel Debian, el texto elige `6.12.96-1`
y la correcta es `6.12.105-1`. La trazabilidad lista cada versión solicitada, de la más
alta a la más baja, con los CVE que pedían cada una.

### Correcciones de la revisión

| Hallazgo | Corrección |
|---|---|
| **ALTO.** El mismo CVE en la misma máquina seguía contando como varias actualizaciones: 8.746 pares (activo, CVE) repartidos entre más de una fila, y el CVE del núcleo aparecía 3 veces en 108 servidores; `CVE-2026-68743`, 18 veces en un mismo equipo de cómputo (los 18 binarios de `sssd`) | Cada fila dice qué paquetes hermanos del mismo activo pide el mismo aviso, con enlace a sus grupos. El indicador dice cuántas vulnerabilidades hay contando **una sola vez** la misma en la misma máquina (`vulnerabilidades_unicas`) y cuántas distintas en total (`cve_distintos`) |
| **MEDIO.** Al filtrar por un CVE, la versión objetivo bajaba sin avisar y la página mandaba instalar una versión que deja el equipo vulnerable | La versión objetivo y la cola se calculan siempre sobre TODAS las filas del grupo. La fila dice «coincide 1 de sus 29 vulnerabilidades con su búsqueda» |
| **MEDIO.** «Instalada: X» era `version_vulnerable`, congelada al detectar: 164 actualizaciones mandaban instalar algo que la máquina ya tenía | Se lee de `activo_software`, la misma fuente que usa `comprobar`, y se elige la más alta con el comparador de la distribución. Si OCS no reporta el paquete, la fila dice «Instalada (según la detección)» |
| **MEDIO.** `_version_instalada` elegía por orden de texto: con dos arquitecturas del mismo paquete (315 casos con remediación abierta) podía comparar contra la más baja y decir «sigue vulnerable» un equipo ya corregido | Se elige el máximo con `comparar_versiones` |
| **MEDIO.** El orden de la consulta agrupada no era total: terminaba en `a.nombre, r.paquete` y hay activos distintos con el mismo nombre en las dos bases de OCS (58 pares). Con LIMIT/OFFSET un grupo podía salir en dos páginas y otro en ninguna | El orden termina en `r.activo_id`, que junto al paquete es la clave del grupo. Con prueba |
| **MEDIO.** Insignia verde «Corregida» en un grupo con dos de tres vulnerabilidades abiertas, porque se pintaba el veredicto de la última comprobación | Veredicto por consenso: «corregida» solo si lo están todas; si no, «sigue vulnerable» o «corregida en parte» |
| **MEDIO.** 4.414 de las 19.284 actualizaciones (22,9 %) no tienen ninguna versión que instalar, y el indicador afirmaba que instalando la más alta se resuelven todas | Se separan `actualizaciones_con_version` y `actualizaciones_sin_version`, con enlace a Correcciones pendientes |
| **MEDIO.** El pie decía «19.284 remediaciones» a veinte píxeles de «19.284 actualizaciones que cubren 47.526 remediaciones» | El pie de la vista agrupada dice «actualizaciones». Las pruebas de `tests/test_paginacion.py` que exigían el texto antiguo se adaptaron, con el motivo escrito |
| **BAJO.** «se comprobaron las 1 vulnerabilidad» en el 77 % de los grupos | «se comprobó la única vulnerabilidad que cubre» |
| **BAJO.** «304 días esperando» de un grupo cuyo pendiente se detectó hace tres | Los días se cuentan solo sobre lo pendiente; cerrado el grupo, «tardó N días en corregirse» |
| **BAJO.** Los grupos ya corregidos o de activos retirados seguían diciendo «Actualizar a X» | «Se actualizó a X» con `version_final`, o «Actualización que quedó sin hacer: el activo ya no figura en OCS Inventory» |
| **BAJO.** «9 versiones solicitadas» y al abrir el desplegable había diez elementos | El resumen cuenta también las vulnerabilidades sin versión conocida |
| **BAJO.** El objetivo táctil del `<summary>` era de 12 px | `summary { min-height: 24px; padding: 4px 0; }` en `estilo.css` (WCAG 2.2, 2.5.8) |

### Rol «Servicios Tecnológicos»

Puede pedir la comprobación de una actualización y documentarla, desde **Remediación** y
desde la ficha del activo, y nada más. No hay ruta nueva: las dos acciones van por
`/remediaciones/<id>/comprobar` y `/<id>/nota` con un campo `alcance=grupo`, a propósito,
porque el mapa de rutas es lo que fija el alcance del perfil. El grupo se resuelve en la
base a partir del identificador recibido, así que un identificador ajeno no alcanza filas
de otro activo ni de otro paquete.

**El sistema verifica**: `remediacion.comprobar` compara la versión instalada que reporta
OCS Inventory con la que corrige el aviso y solo cierra la remediación si de verdad está
corregida o el paquete ya no está instalado. Los veredictos son `corregida`,
`sigue_vulnerable`, `desinstalado` y `sin_datos`, y `parcial` para el conjunto de una
actualización. Cada acción deja su fila en `remediacion_comprobaciones` o
`remediacion_notas` y su entrada de auditoría, una por vulnerabilidad.

## 5. Revisión de seguridad del lote (misma fecha)

La revisión adversaria de seguridad **rechazó** la primera versión del lote por un hallazgo
crítico y devolvió cinco más. Todos corregidos y con prueba antes de desplegar.

| Gravedad | Hallazgo | Corrección |
|---|---|---|
| **CRÍTICO** | `remediacion.comprobar` leía «el paquete no está en `activo_software`» como «desinstalado» y cerraba la remediación. Los parches de Windows (motor `msrc`, paquete `windows`) y el sistema base de FreeBSD (`freebsd`, `freebsd-kernel`) **nunca** están en esa tabla, por diseño. Con la acción de grupo nueva, un solo clic del perfil Servicios Tecnológicos habría cerrado como corregidas **797 vulnerabilidades** de un equipo de cómputo sin ninguna prueba, y la sincronización no las reabría (su aplicabilidad está en `sin_dato`). Alcance en producción: 6.989 remediaciones abiertas (6.553 de Windows en 13 equipos, 434 del sistema base de FreeBSD en 105 servidores) | `comprobar` distingue las dos familias igual que ya hacía `sincronizar`: Windows se compara por **compilación** (`activos.windows_build` frente a la que corrige el boletín, con `msrc.comparar_builds`) y FreeBSD por `version_base_freebsd(activos.so_version)`. Sin dato, «sin datos»: **jamás** «desinstalado». La vista agrupada muestra la instalada de esas dos familias con la misma regla. Cinco pruebas nuevas, incluida la que reproduce el grupo de 797 |
| MEDIO | El enlace «Activos afectados» de Amenazas con un grupo sintético («Servidores sin proceso asignado», «Equipos de cómputo (Mantenimiento)») aterrizaba en una lista de Activos **vacía**: esa página aplicaba el nombre como proceso literal | `webui/vistas/activos.py` usa `queries.filtro_parque`, el mismo recorte que Amenazas |
| MEDIO | El enlace a un «paquete hermano» buscaba el nombre con `q` y llevaba a los grupos de **todos** los activos (106 en vez de 1) | Filtro `activo` en la lista de Remediación (`_filtros_sql(..., activo_id)`), el enlace lo lleva y la página dice «Solo las actualizaciones del activo X», con vuelta a todos |
| BAJO | Las acciones de grupo escribían sin cota (797 filas y 797 asientos de auditoría por petición; notas de 2.000 caracteres por fila) | `LIMITE_ACCION_GRUPO = 1000` por petición, con mensaje claro; por debajo no cambia nada |
| BAJO | `sin_confirmar = registradas − confirmadas` mezclaba dos conjuntos de estados: una amenaza **mitigada** confirmada en un activo contaría como «no confirmada en ningún activo» | «Sin confirmar» se calcula por diferencia de **conjuntos** (registradas cuyo identificador no está confirmado en ningún activo presente), del ámbito y global |
| BAJO | La amenaza alertada porque el filtro se abstuvo (todavía sin evaluar) no llevaba ningún aviso en el correo | Marca `afectacion_sin_evaluar` y bloque «Afectación todavía sin evaluar» en el detalle del correo |
| INFORMATIVO | `nombre_norm` no es `lower(trim(nombre))` (399.890 de 941.433 filas difieren por el sufijo de arquitectura) | Las búsquedas usan `ocs.normalizar_nombre`, la misma función que lo escribe |
| INFORMATIVO | Un `flash` mostraba la excepción cruda al navegador | Mensaje fijo y detalle al registro del servicio |

Lo que la revisión verificó y salió limpio: inyección SQL (todo parametrizado; las cadenas
concatenadas son constantes o marcas `?`), XSS (ningún `|safe` nuevo, autoescape en
correos y plantillas), CSP estricta (0 violaciones, cabeceras sin `unsafe-*`), control de
acceso (ninguna ruta nueva, `viewer` sin escrituras, Servicios Tecnológicos sin permisos
nuevos), fuga de información (ninguna), y coste: la primera página de la vista agrupada
cuesta 156 ms de mediana y la última 201 ms; `_paquetes_hermanos` 24 ms en el peor caso;
`resumen_amenazas` 254 ms.

## 6. Tres severidades y la unidad en cada cifra (tarde del 8 de septiembre)

Segunda ronda del usuario sobre la página de Amenazas:

> «el primer valor de las métricas no especifica, dice por ejemplo 30827 y ya no dice nada,
> en equipos dice 15.902 pero no dice de qué… las gráficas tienen que estar bien
> segmentadas, críticas, altas y medias, las amenazas o vulnerabilidades bajas no se
> reportan y es regla interna… y eso también se debe de tener en cuenta con los correos».

Qué cambia:

- **La unidad va escrita junto al número.** `graficos.barras_horizontales(unidad=...)`
  escribe «28.247 vulnerabilidades · 484 de 511 servidores afectados» en la barra; la fila
  de total de la tabla dice «43.151 vulnerabilidades» y «1.024 amenazas distintas». En
  Panel e Inventario las barras de tecnologías dicen «N amenazas».
- **Exactamente tres segmentos: críticas, altas y medias.** La severidad Baja queda fuera
  de **todas** las cifras cuando el ajuste `ignore_low_severity` está activo (lo está):
  - `queries.resumen_amenazas(incluir_bajas=False)`: catálogo, confirmadas, vulnerabilidades,
    activos afectados, reparto por tipo y por proceso; la columna `resto` pasa a `medias`.
    `procesos_del_parque` usa el mismo criterio.
  - `queries.evolucion_mensual(excluir_bajas=True)`: la serie mensual del Panel y de
    Tendencias (total, media de CVSS) sin las bajas; `estadisticas_mes` ya lo admitía.
  - Panel (`_series_evolucion`, `_porciones_severidad`, `_items_tecnologias`), Tendencias
    (serie, dona y tabla) e Inventario (`_items_top`, `_series_evolucion`) dejan de pintar
    el segmento y la columna «Bajas».
  - `ocs.estado_activos` (las cuatro cifras que abren el resumen semanal y el Panel) no
    cuenta vulnerabilidades de severidad Baja.
  - Informe mensual (`report.py`): sin fila de «Baja» en las tablas y con la frase «las de
    severidad baja no se reportan, por regla interna».
  - El correo diario ya no tenía tarjeta de bajas (Críticas, Altas, Medias, En KEV) y el
    filtro de alerta ya las excluía (regla 1b); el resumen semanal ya usaba `excluir_bajas`.
- Con el ajuste desactivado, todo vuelve a mostrar las bajas como cuarto segmento: la
  regla es del equipo, no del código.

Medido sobre producción tras el cambio: **43.151 vulnerabilidades** (6.229 críticas,
19.794 altas, 17.128 medias) frente a 46.729 con las 3.578 bajas; **1.024 amenazas
distintas** (eran 1.032) en **730 de 836 activos**; 6.003 amenazas registradas.

**No se ha tocado Remediación**: es la cola de trabajo, no un informe, y hoy tiene 3.581
remediaciones abiertas de severidad Baja. Si también deben salir de la cola, es una decisión
del usuario.

## 7. Qué NO se ha hecho

- El servicio `threat-intel-webui` se reinició a las 12:17 del 8 de septiembre con todo el
  lote, tras la suite (1.057 pruebas en verde) y la revisión de seguridad.
- No se ha tocado el cron, no se ha enviado ningún correo y no se ha escrito en la base de
  producción (las mediciones se hicieron sobre copias con la API `backup`, borradas al
  terminar). Nada de git.
- La exportación CSV de Remediación sigue siendo por vulnerabilidad, a propósito: es el
  detalle completo y lleva la `version_corregida` de cada aviso. El botón lo dice.
- `ancho=900` en las dos gráficas de Amenazas reduce un 16 % el tamaño del texto respecto
  a 760 a cualquier anchura; el compromiso era inevitable porque con 760 las notas nuevas
  dejaban las barras en un 28 % del gráfico. No se ha revisado en pantalla de móvil.

## 8. Unidad de conteo: un CVE por activo (2026-09-09)

### Por qué

La plataforma llamaba «vulnerabilidades» a `COUNT(*)` de filas de `aplicabilidad`, y esa
tabla tiene **una fila por paquete binario**. Un mismo CVE del núcleo en un servidor contaba
cuatro o cinco veces (`linux-image`, `linux-headers`, `linux-modules`, `linux-tools`,
`linux-tools-common`) y un CVE de sssd contaba dieciocho veces (`sssd`, `sssd-ad`,
`libnss-sss`…). El usuario lo leyó como duplicidad y lo reclamó dos veces: «si hay una
vulnerabilidad de kernel que se repite que se cuente como una».

**Definición nueva:** una vulnerabilidad es **un CVE en un activo**, con independencia de
cuántos paquetes de esa máquina toque. Los paquetes son la trazabilidad (qué actualizar),
no la unidad de conteo. En SQL: `COUNT(DISTINCT ap.activo_id || char(31) || ap.cve)`.

### Medido sobre producción (base real, solo lectura, veredicto afectado, activos presentes, sin severidad Baja)

| Cifra | Antes (filas de paquete) | Después (pares activo-CVE) |
|---|---|---|
| Vulnerabilidades confirmadas | 43.135 | **25.325** |
| Críticas | 6.225 | **3.949** |
| Altas | 19.795 | **12.419** |
| Medias | 17.115 | **8.957** |
| Con explotación activa (KEV) | 622 | **413** |
| En servidores | 28.247 | **13.757** |
| En equipos de cómputo | 14.888 | **11.568** |
| En producción o contingencia (estado de los activos) | 18.170 | **8.479** |
| En activos fuera de soporte | 3.209 | **3.201** |
| CVE distintos / amenazas confirmadas / activos afectados | 1.024 / 1.024 / 729 | sin cambio |

### Un solo punto de verdad

`threatintel/queries.py` define `VULNERABILIDAD_DISTINTA = "ap.activo_id || char(31) || ap.cve"`
y `sql_vulnerabilidades(alias="ap", condicion=None)`, que devuelve el `COUNT(DISTINCT …)`
liso o condicionado (`COUNT(DISTINCT CASE WHEN <condición> THEN … END)`), en sustitución de
los `SUM(t.severity = 'Critical')` que contaban filas. Todo conteo de vulnerabilidades pasa
por esa función.

### Sitios cambiados

- `threatintel/queries.py` · `resumen_amenazas`: total, `vulnerabilidades_kev`, por tipo de
  activo (total, críticas, altas, medias) y por proceso (total, críticas, altas, medias,
  `de_servidores`, `de_equipos`). `evolucion_mensual` y `serie_anual` cuentan amenazas
  registradas (`threats`), no filas de aplicabilidad: no cambian.
- `threatintel/ocs.py` · `estado_activos`: `vulnerabilidades`, `expuestos_vulnerabilidades` y
  `fuera_soporte_vulnerabilidades` (las cifras que abren el resumen semanal y el Panel).
- `webui/vistas/panel.py` · `_estado_activos_en_alcance` (mismas tres cifras acotadas al tipo
  de máquina del perfil).
- `webui/vistas/amenazas.py` · detalle acotado a un perfil: «afectados», «afectados en
  producción», «ya corregidos» y «sin dato» pasan de contar filas a contar **activos**
  distintos, el mismo criterio que `aplicabilidad.recalcular_resumenes` usa para el parque.
- `threatintel/aplicabilidad.py` · `resumen_informe` devuelve además `activos_afectados`,
  `vulnerabilidades` y `vulnerabilidades_kev` del periodo sin el recorte de la tabla (antes
  el informe decía «en total 40 activos» porque contaba las filas de la tabla, limitada a 40).
- `threatintel/report.py` · apartado 4 del informe mensual: escribe el total de
  vulnerabilidades confirmadas del periodo y la nota de la unidad.
- `threatintel/libro_alerta.py` · la hoja de cada amenaza ya contaba activos (no paquetes);
  la clave del registro pasa de `vulnerabilidades` a `amenazas` porque cuenta hojas.
- Textos donde la cifra aparece por primera vez: `webui/templates/amenazas.html` (recorrido
  guiado, nota de la métrica, gráfica y cabecera de la tabla), `webui/templates/panel.html`
  (subtítulo de «Estado de los activos») y `threatintel/emails/semanal.html`: «Una
  vulnerabilidad es un CVE en un activo; si afecta a varios paquetes de la misma máquina
  cuenta una sola vez».
- Ya contaban por CVE o por activo y no cambian: desplegable y ficha del activo
  (`vulnerabilidades_activo`, `conteo_activo`), SBOM (`COUNT(DISTINCT cve)`), tabla de
  activos del informe (`COUNT(DISTINCT ap.cve)` por activo), libro de la alerta
  (`aplicabilidad_amenaza.afectados`), Remediación (`vulnerabilidades_unicas`, trabajo
  paralelo de otro agente, no tocado), Tendencias (serie de amenazas registradas).

### Pruebas

`tests/test_cifras_amenazas.py`: las cifras del inventario sembrado pasan de 6 a 5
vulnerabilidades (los dos paquetes de curl del mismo servidor son una), y la clase nueva
`TestUnCvePorActivo` siembra un servidor con el mismo CVE en cuatro paquetes y un equipo de
cómputo con uno: dos vulnerabilidades en la consulta (total, severidad, tipo, proceso, KEV),
en la página de Amenazas (métrica y fila de total), en `ocs.estado_activos`, en el Panel
(completo y acotado), en el libro de la alerta («2 activos con la versión vulnerable») y
en el informe mensual («2 vulnerabilidades confirmadas» más la nota de la unidad).

### Desempate de severidad

El catálogo tiene 28 CVE con avisos de severidad distinta (por ejemplo uno crítico y otro
bajo del mismo CVE). Con la condición puesta directamente sobre la severidad, un par
(activo, CVE) con dos avisos de severidad distinta caería en dos segmentos y
«críticas + altas + medias» superaría el total: la misma vulnerabilidad, dos veces. La
regla es que **una vulnerabilidad tiene una sola severidad, la más alta** de los avisos que
la declaran. Se calcula en `queries.sql_vulnerabilidades_severidad` sin subconsulta
correlacionada, como diferencia entre los pares de severidad igual o superior y los de
severidad estrictamente superior, de modo que los segmentos son excluyentes y su suma nunca
pasa del total. Hoy no hay ningún par en esa situación, pero nada lo impedía.

### Coherencia entre páginas (revisión de precisión del 9 de septiembre)

La revisión con datos reales aprobó la definición nueva y encontró que otras páginas
seguían contando de otra manera, con lo que el operador veía dos números de lo mismo. Se
corrigió:

| Dónde | Qué decía | Qué dice | Medida |
|---|---|---|---|
| Página de Activos, «Con vulnerabilidades confirmadas» | 747 activos, porque incluía severidad Baja | 746, la misma cifra que Amenazas, el Panel y el resumen semanal | 1 activo cuyos únicos CVE son bajos |
| Atajo «con vulnerabilidades» y columnas de la lista de activos | contaban con las bajas dentro; el enlace desde Amenazas aterrizaba en una lista más larga que su propia cifra | misma condición que el número que se pulsa | — |
| Ficha del activo, paginación | «334 amenazas evaluadas» mientras el reparto de la misma página decía «94 CVE evaluados» | «filas evaluadas (una por CVE y paquete)» | afectaba a 683 de 849 activos |
| Alertas por proceso | «Pila 171» frente a «170» en Amenazas: no filtraba estado ni severidad | misma condición que Amenazas | — |
| Informe mensual, apartados 6.1 y 6.3 | llamaba «vulnerabilidades» a las amenazas del periodo, junto a la definición nueva del apartado 4 | «amenazas relacionadas con el inventario tecnológico» | 1.134 amenazas frente a 22.807 vulnerabilidades: dos cosas distintas, dos nombres |
| Informe mensual, cifras nuevas | «22807», «13726» | 22.807, 13.726 (formato español, `report._numero`) | — |
| Alerta diaria por correo | «631 activos en total», suma por amenaza: un servidor afectado por doce amenazas contaba doce veces | activos distintos; la ejecución diaria pasa la cifra exacta contada sobre la base y, si la lista viene recortada, el correo dice «al menos» | parque de 841 activos |

Las cifras del parque quedaron así, comprobadas llamando a las funciones reales sobre
producción: 746 activos afectados en las tres páginas, la suma por tipo de máquina iguala
el total (26.462 en equipos de cómputo más 14.338 en servidores) y la suma de las tres
severidades también.

### Con la severidad baja incluida (revisión de seguridad del 9 de septiembre)

El desempate anterior es exacto, pero la revisión encontró que los segmentos solo cubrían
el total mientras el ajuste **«Ignorar la severidad baja»** estuviera activo, que es lo
normal. Al desactivarlo, la página de Amenazas contaba las bajas en el total y las dejaba
fuera de los tres segmentos: la barra perdía ese trozo, el total escrito a su derecha no
era la suma de lo dibujado y el párrafo seguía afirmando que «las de severidad baja no se
reportan… y no están en ninguna cifra de esta página». Medido sobre la base real (solo
lectura, veredicto afectado, activos presentes, amenazas vivas):

| Ajuste «Ignorar la severidad baja» | Tipo de activo | Vulnerabilidades | Críticas + altas + medias | Fuera de todo segmento |
|---|---|---|---|---|
| Activo (lo normal) | Equipos de cómputo | 26.462 | 26.462 | 0 |
| Activo (lo normal) | Servidores | 14.338 | 14.338 | 0 |
| Desactivado (antes) | Equipos de cómputo | 26.740 | 26.462 | 278 |
| Desactivado (antes) | Servidores | 15.293 | 14.338 | 955 |
| Desactivado (ahora) | Equipos de cómputo | 26.740 | 26.462 más 278 bajas | 0 |
| Desactivado (ahora) | Servidores | 15.293 | 14.338 más 955 bajas | 0 |

Eran **1.233 vulnerabilidades** (278 de equipos de cómputo y 955 de servidores) contadas en
el total y en ningún segmento. Lo que se hizo:

* **Cuarto segmento «Bajas»**, con el azul `--bajo` de la paleta (el mismo que ya usa
  Tendencias con esta regla desactivada), y **solo** cuando el ajuste está desactivado. Con
  el ajuste activo la página sigue pintando tres segmentos y no nombra la severidad baja en
  ninguna parte: ni en la leyenda, ni en el párrafo, ni en el recorrido guiado.
* **Quinto segmento «Sin severidad conocida»**, en el gris `--neutro` de «sin dato», y solo
  cuando existe alguna: son los pares (activo, CVE) cuyo veredicto no apunta a ninguna
  amenaza del catálogo (`aplicabilidad.threat_id` nulo, caso que el criterio de la consulta
  ya contemplaba con `t.id IS NULL`). Una severidad ausente no es una severidad baja, así
  que este segmento aparece en los dos estados del ajuste; hoy en producción no hay
  ninguna. Se calcula restando los cuatro segmentos del total, que es exacto porque son
  excluyentes y cuesta cero; `queries.sql_vulnerabilidades_sin_severidad` es la definición
  declarativa equivalente y una prueba comprueba que los dos caminos coinciden.
* **Suma garantizada**: en el total del ámbito y en cada fila del reparto por tipo de activo
  y por proceso se cumple `críticas + altas + medias + bajas + sin severidad = total`, y el
  total que la gráfica escribe a la derecha de cada barra es la suma de lo dibujado.
* **Texto condicional**: el párrafo de cada gráfica, la nota de «Amenazas registradas» y el
  paso del recorrido guiado dicen cuántos segmentos hay, los nombran y, cuando las bajas
  cuentan, dicen cuántas son («2 de las 6 vulnerabilidades de este ámbito son bajas»). Con
  el ajuste activo se mantiene la frase de la regla interna.
* **«Procesos disponibles» (Alertas por proceso)** tenía `t.severity <> 'Low'` fijo y no
  miraba el ajuste: al desactivarlo, esa página seguía sin contar las bajas mientras
  Amenazas sí las contaba. Ahora `alertas_proceso.procesos_disponibles` lee
  `ignore_low_severity` de la tabla `settings` con la misma conexión de la consulta
  (`alertas_proceso.incluir_bajas`), así que cualquiera que la llame —la página, `listar`,
  `guardar` o la ejecución diaria— cuenta lo mismo que Amenazas sin tener que acordarse de
  pasar el ajuste; un parámetro `incluir_severidad_baja` permite forzarlo en pruebas.
* **La ayuda del ajuste** en Ajustes decía que las bajas solo quedaban fuera de «alertas,
  resumen semanal ni informe». También quedan fuera de las cifras y gráficas de Panel,
  Amenazas, Tendencias, Activos, Inventario y Alertas por proceso; ahora lo dice, y dice
  qué cambia al desactivarlo.

Coste medido en la base real: con el ajuste activo el resumen tarda lo mismo (el segmento
de bajas se escribe como la constante 0, porque sus filas ya no están en la consulta); con
el ajuste desactivado sube de unos 800 ms a unos 905 ms por los dos `COUNT(DISTINCT)` de
más que exige contar las bajas (tres medidas de cada caso).

Pruebas: `tests/test_cifras_amenazas.py::TestSeveridadBajaIncluida` (nueve pruebas: tres
segmentos y suma igual al total con el ajuste activo, cuatro y suma igual al total con el
ajuste desactivado, la leyenda y el total de la barra, el texto de la página y del
recorrido, la vulnerabilidad sin severidad conocida en los dos estados, los dos caminos de
cálculo y la coherencia de «Procesos disponibles» con Amenazas en los dos estados),
`tests/test_cifras_amenazas.py::TestColorDeLosSegmentos` (los cinco rellenos con contraste
≥ 3:1 sobre el fondo del panel en los dos temas y los dos nuevos a distancia perceptual
≥ 25 de todos los demás) y `tests/test_pagina_amenazas.py::TestBarrasConSeveridadBajaIncluida`
(renderizado con el cuarto segmento, leyenda, total de la barra, texto y CSP estricta).

Contraste medido (relleno sobre `--fondo-panel`): tema claro, «Bajas» 5,17:1 y «Sin
severidad conocida» 4,83:1; tema oscuro, 6,82:1 y 6,15:1. Distancia perceptual mínima de
los dos colores nuevos frente a los otros segmentos: 34,3 (dE76), muy por encima del 25 que
exige la paleta del proyecto. La identificación nunca depende solo del color: cada segmento
lleva nombre y cifra con su unidad en la leyenda, nombre y porcentaje en la descripción
emergente y la tabla de debajo repite los números.

## 9. Remediación: una actualización por origen de paquete (2026-09-09)

**Qué se pidió.** El usuario reclamó por segunda vez la duplicidad de la vista «Por
actualización»: en el activo 413 el núcleo aparecía cinco veces (`linux-headers-6.8.0-60-generic`,
`linux-image-…`, `linux-modules-…`, `linux-tools-…`, todos de `6.8.0-60.63` a `6.8.0-60.63.1`
con los mismos 32 CVE; y `linux-tools-common`, de `6.8.0-101.101` a `6.8.0-139.139` con 29) y
`sssd` dieciocho veces (los dieciocho binarios con el mismo CVE). «Si hay una vulnerabilidad de
kernel que se repite que se cuente como una y se vea la trazabilidad de las versiones.» El
mecanismo anterior de «paquetes hermanos» solo los enlazaba.

**La regla (sin diccionarios ni red).** Dentro de un mismo activo, los grupos (activo, paquete)
que comparten la **misma versión instalada**, la **misma versión objetivo** y el **mismo conjunto
de CVE pendientes** son una sola actualización: vienen del mismo paquete fuente y una única orden
los resuelve todos. Se detecta con una *firma* por paquete —la lista ordenada de
`cve=version_corregida@version_vulnerable` de sus filas pendientes— calculada en SQL
(`remediacion._cte_firmas`, `GROUP_CONCAT` sobre una subconsulta ordenada, porque SQLite 3.37 no
admite `ORDER BY` dentro del agregado). Verificada contra el mismo cálculo en Python en los
19.283 grupos de producción: cero discrepancias (sin la subconsulta ordenada discrepaban 3.338).
Un paquete que no cumple la regla (`linux-tools-common`) queda en su fila y sigue apareciendo
como «hermano» de la fusión, con enlace acotado al activo.

**Lo que se ve.**

- La fila se llama «Núcleo Linux 6.8.0-60-generic» si todos los paquetes empiezan por `linux-`
  (`remediacion.nombre_actualizacion` extrae la variante común tras los componentes image,
  headers, modules, extra, tools, signed…), o «sssd y 17 paquetes más» (el paquete principal es
  el que coincide con el prefijo común o el más corto). La lista completa de paquetes, cada uno
  con su versión instalada según OCS Inventory y sus filas, se despliega con `<details>` dentro
  de la fila (HTML puro; CSS nuevo al final de `estilo.css`: `.nombre-actualizacion`,
  `.paquetes-fusion`, `.tabla-actualizaciones-activo`).
- «Vulnerabilidades» de la fila son CVE distintos (ya no se multiplican por paquete); debajo, las
  filas de remediación y los paquetes. La trazabilidad lista cada CVE una vez y dice «en 4
  paquetes».
- «Comprobar» y «Documentar» actúan sobre **todas** las filas pendientes de todos los paquetes de
  la fusión (`_remediaciones_del_grupo` resuelve la firma solo dentro de ese activo), con el
  mismo tope `LIMITE_ACCION_GRUPO` de 1.000 filas; el mensaje dice «se comprobaron las 32
  vulnerabilidades que cubre en sus 4 paquetes (128 filas de remediación)».
- Indicadores de la cabecera y del avance por tipo de máquina: **Actualizaciones pendientes** =
  fusiones (`resumen.actualizaciones`, con la misma firma que la lista); **Vulnerabilidades
  pendientes** = pares (activo, CVE) distintos (`vulnerabilidades_unicas`), con las filas de
  remediación relegadas a la nota. El porcentaje corregido sigue en filas de remediación para no
  mezclar unidades.
- La vista «Por vulnerabilidad» se mantiene; su subtítulo dice que son filas de trazabilidad, no
  vulnerabilidades distintas.
- La ficha del activo (`_remediaciones_activo.html`) lleva un panel nuevo «Actualizaciones
  pendientes» con la misma fusión (paso 11 del recorrido) y el historial plano pasa a llamarse
  «Detalle por vulnerabilidad y paquete» (paso 12). El plan de remediación (`remediacion.html`)
  junta los grupos con la misma orden con `remediacion.fusionar_plan`: el núcleo con 32 CVE es
  un grupo, no 32. Como esas dos vistas las pinta `webui/vistas/activos.py`, las ayudas llegan a
  las plantillas por un `app_context_processor` del blueprint de remediaciones
  (`actualizaciones_del_activo`, `fusionar_plan`, `nombre_actualizacion`): funciones perezosas,
  de solo lectura, acotadas a un activo.

**Medido en producción (solo lectura, 2026-09-09).** Antes de la recolección de las 08:00:
47.510 filas pendientes, 19.283 grupos (activo, paquete) → 8.864 actualizaciones, 4.359 de ellas
con más de un paquete (la mayor, 18); el núcleo, de 688 grupos a 554 actualizaciones; el activo
413, de 84 grupos a 29. Tras la recolección (62.985 filas pendientes, 19.300 grupos → 8.881
actualizaciones, mismas cifras del núcleo y del activo 413), sobre la misma base y con la
máquina descargada: `listar_actualizaciones` antes 186 ms la primera página y 230 ms la última;
ahora `pagina_actualizaciones` (primera página **con el total en la misma consulta**) 375 ms y la
última 386 ms; `contar_actualizaciones` 38 → 231 ms (ya no se llama en la carga normal de la
página); `resumen` 536 → 584 ms (el conteo de fusiones sustituye a dos `COUNT(DISTINCT)` sobre
cadenas). La firma cuesta unos 110 ms por cálculo; para no pagarla dos veces, la vista pide la
página y el total juntos (`COUNT(*) OVER ()`) y solo llama a `contar_actualizaciones` si la
página pedida queda fuera de rango. Los agregados de la consulta agrupada se redujeron a los que
sirven para ordenar (los dos `julianday` por fila que no se usaban desaparecen). Ocho
actualizaciones superan hoy las 1.000 filas pendientes del tope por petición: para ellas la
página dice que se actúe desde la ficha del activo, fila a fila.

**Pruebas.** `tests/test_remediacion_agrupada.py`: clases `TestNombreActualizacion`,
`TestFusionPorOrigen` y `TestFusionEnLasPaginas` (cuatro binarios del núcleo → una fila con 3
vulnerabilidades y 4 paquetes; `linux-tools-common` aparte y hermano; 18 binarios de sssd → «sssd
y 17 paquetes más»; misma versión con distinto conjunto de CVE o distinta versión instalada → no
se fusionan; comprobar y documentar tocan todas las filas y respetan el tope; indicadores;
paginación sin partir fusiones; fusión también en «corregidas» y «todas»; firma independiente
del orden de inserción; página, ficha del activo y plan). Se adaptaron tres pruebas que fijaban
el comportamiento anterior (los binarios con la misma versión y el mismo CVE ya no son
«hermanos» sino una actualización: ahora llevan versiones distintas para seguir probando el
enlace) y la etiqueta «Vulnerabilidades que cubren» pasa a «Vulnerabilidades pendientes».

**Lo que NO se ha hecho.** La descarga en texto del plan (`aplicabilidad.plan_remediacion_texto`)
sigue sin fusionar, porque ese módulo no era de este lote: la fusión del plan se hace en la
plantilla con `fusionar_plan`; lo limpio es mover esa llamada al final de
`aplicabilidad.plan_remediacion`. La exportación CSV sigue siendo por fila, a propósito. La firma
se recalcula en cada petición (unos 110 ms); si algún día pesara, un índice
`remediaciones(activo_id, paquete, cve)` no la acelera (medido: 122 → 111 ms), así que la
alternativa sería una tabla de firmas mantenida por `sincronizar`.

### Correcciones de la revisión de seguridad (9 de septiembre, tarde)

La revisión adversaria rechazó el lote con ocho hallazgos. Todos corregidos, con la medida que
lo demuestra (base real copiada con la API `backup` de sqlite3, en solo lectura salvo donde se
indica; 62.985 filas pendientes, 8.881 actualizaciones, 881 activos).

**1. ALTO · denegación de servicio autenticada.** El límite de veinte de la página agrupada
acotaba FILAS, no CONTENIDO: las veinte actualizaciones de `?q=windows` sumaban 17.030
vulnerabilidades (la mayor, 1.358 en un solo equipo de cómputo con Windows) y el desplegable de
trazabilidad las pintaba todas. Medido antes: `?q=w` 7,81 MiB y 1.920 ms de proceso, `?q=windows`
8,32 MiB y 1.940 ms, `?estado=todas&q=windows` 8,32 MiB y 1.938 ms, alcanzable con el perfil de
solo lectura. Ahora cada actualización pinta como máximo `remediacion.LIMITE_CVES_GRUPO` (25)
vulnerabilidades y como máximo 25 entradas de la cola de versiones, y la fila lo dice sin
adornos: «Se muestran las 25 primeras de 741 vulnerabilidades; las otras 716 están en la ficha de
srv-ejemplo-201, de veinte en veinte. La versión objetivo se calculó con todas», con enlace a la
ficha. Medido después: **0,330 MiB y 1.025 ms** (`?q=w`), **0,327 MiB y 1.039 ms** (`?q=windows`),
**0,327 MiB y 1.032 ms** (`?estado=todas&q=windows`): un 96 % menos de respuesta y un 46 % menos
de proceso. También se recortó lo que se TRAE: `_detalle_de_grupos` pide de todas las filas del
grupo solo los campos que se agregan (`_CAMPOS_AGREGADO`, sin el título de la amenaza, el motivo
de cierre ni el `LEFT JOIN` con `aplicabilidad`) y `_completar_cves_pintados` trae los textos
largos y el aviso solo de las ≤ 500 vulnerabilidades que se pintan, por lotes de 400
identificadores. Las cifras del grupo y la versión objetivo siguen saliendo de TODAS sus filas:
verificado sobre 100 actualizaciones reales (`?q=windows`, primera página, `estado=todas`,
`?q=linux` y la página 21) comparando `version_objetivo`, `vulnerabilidades`, `filas`,
`pendientes`, `severidad`, `in_kev` y `versiones_pedidas` contra el cálculo directo en SQL: cero
discrepancias. No se activó la compresión de nginx (sigue apagada a propósito por BREACH).

**2. MEDIO · un botón que nunca funcionaba.** `LIMITE_ACCION_GRUPO` era 1.000 y su comentario
hablaba de 797 filas, pero hoy hay **ocho actualizaciones por encima de 1.000, la mayor de
1.358**, todas del paquete `windows`: se pintaba «Ya se actualizó: comprobar las 1.358» y la
petición respondía siempre con el aviso del tope. El tope sube a **2.000** (47 % de margen sobre
el máximo real) y el comentario lleva la medida de hoy. Coste medido de la acción completa sobre
la actualización mayor (1.358 filas, copia de escritura): 166 ms `comprobar_grupo` y 45 ms
`anotar_grupo`. Mientras exista tope, ninguna de las dos plantillas pinta acciones de grupo por
encima de él: en su lugar sale la insignia «Demasiadas filas para una sola acción» y la frase que
explica cuántas filas hay, cuál es el tope y dónde trabajarlas (ficha del activo, fila a fila).
Con el tope en 2.000 esa situación no se da hoy en producción: las veinte filas de `?q=windows`
pintan su botón y las veinte funcionan.

**3. MEDIO · el plan en texto venía duplicado (queja del usuario).** La página fusionaba en la
plantilla, pero `aplicabilidad.plan_remediacion_texto` recibía los grupos SIN fusionar: en el
activo 20 la página decía «40 grupos de remediación» y el fichero descargado traía **105
bloques**. La fusión se hace ahora dentro de `aplicabilidad.plan_remediacion` (importación local
de `remediacion.fusionar_plan`, sin ciclo) y también en `plan_remediacion_texto`, que además
recibe planes ya recortados al alcance del perfil; `fusionar_plan` se hizo idempotente
(`grupos_fusionados` se acumula en lugar de reiniciarse). Cada bloque del fichero lleva el nombre
de la actualización en el encabezado y debajo sus paquetes y sus vulnerabilidades:
`1. Ubuntu:24.04 · Núcleo Linux 6.8.0-60-generic · versión objetivo 6.8.0-60.63.1`,
`Paquetes (4): …`, `Vulnerabilidades (3): …`. Medido en el activo 20: la página dice 40 grupos y
el fichero trae **40 bloques** (24,3 KiB); en la amenaza 6110 (499 activos), 10 y 10. El plan más
grande por activo (1.358 filas de aplicabilidad) queda en 6 grupos y 45,2 KiB.

**4. MEDIO · una nota de grupo escribía 797 entradas de auditoría.** `anotar_grupo` llamaba a
`anotar` fila a fila y cada `anotar` auditaba. Ahora `anotar` acepta `auditar=False` y
`anotar_grupo` deja **una sola entrada** (`remediacion.nota_grupo`) con el recuento de filas, las
vulnerabilidades, el activo y los paquetes. La nota se sigue guardando en cada fila porque ahí es
donde la leen la ficha del activo (por CVE) y la vista agrupada. Y hay freno a la repetición: la
misma nota (ya normalizada) sobre el mismo grupo se rechaza con un mensaje claro. Medido sobre la
actualización mayor (1.358 filas, texto de 1.935 caracteres, copia de escritura): antes 1.358
entradas de auditoría y +3,28 MB de base; ahora **1 entrada** y +2,81 MB, y el reenvío del mismo
formulario añade **0 notas y 0 entradas**.

**5. MEDIO · `/remediaciones/<id>/nota` caía con 500 ante un error de base.** Solo atrapaba
`ValueError`. Ahora atrapa además `Exception`, la registra en el diario del servicio con
`exc_info` y responde con un mensaje neutro conservando el destino de vuelta, igual que la ruta
hermana `comprobar`. Probado con `sqlite3.OperationalError` en los dos alcances (una sola y
grupo): 302 al destino original, mensaje «No se pudo guardar la nota por un error interno; quedó
anotado en el registro del servicio» y ni una nota escrita.

**6. MEDIO · la página calculaba tres veces lo mismo.** `remediacion.resumen` costaba 590 ms y se
pedía una vez para las cifras de arriba, otra por cada tipo de máquina del bloque «Avance» y otra
más en cada carga de la lista de Activos. Dos medidas: `resumen(solo_cifras=True)` no calcula el
reparto por proceso, el reparto por tipo de máquina ni la serie semanal —que solo pinta la propia
página de Remediación— y devuelve esas tres claves en `None` (nunca cero: «no se calculó» no
puede leerse como «no hay»); y `webui/vistas/remediaciones.resumen_memorizado` lo memoriza en `g`
por (origen, días) durante la petición, de modo que un resumen completo ya calculado sirve
también a quien solo pide cifras. Además `_serie_semanal` se reescribió: antes eran dos
subconsultas por semana (hasta 52 recorridos de `remediaciones`) y ahora son dos recorridos con
el número de semana calculado en SQL; se comprobó que la serie es **idéntica** para 7, 30, 60, 90
y 182 días y para los dos tipos de máquina, y cuesta 268 → 62 ms a 30 días y 1.467 → 62 ms a 182.
Medido de punta a punta: `resumen` completo 590 → **411 ms** y con `solo_cifras` **220 ms**;
`/remediaciones/` con el perfil de Servicios Tecnológicos 1.961 → **1.259 ms**, con el de solo
lectura 1.050 → **843 ms**; `/activos/` 1.667 → **1.289 ms**.

**7. BAJO · un fallo silencioso posible.** La firma de fusión se calcula en dos consultas y, si
alguna vez no coincidieran (por ejemplo si cambiara el orden del `GROUP_CONCAT`), el respaldo
`paquetes_por_fusion.get(...) or [c["paquete"]]` mostraba un solo paquete en una fila que
agrupaba varios, sin aviso. Las dos consultas reciben ya la MISMA condición desde una sola
variable, y el respaldo es ruidoso: deja un `WARNING` en el diario del servicio con el paquete y
el activo, y el grupo sale con `fusion_incompleta`, que la página pinta como insignia ámbar
«Fusión incompleta» con la explicación y el enlace a la ficha.

**8. BAJO · dos paneles atados.** `_remediaciones_activo.html` envolvía todo en una sola
condición sobre el historial paginado, así que una página de historial sin filas se llevaba por
delante la tabla de actualizaciones fusionadas. Ahora son independientes; y si la página del
historial viene vacía, la tabla lo dice y la paginación sigue accesible.

**Pruebas.** `tests/test_remediacion_revision_seguridad.py` (34 pruebas, ocho clases, una por
hallazgo más `TestSerieSemanal`): recorte con indicador y cifras que no dependen de él, textos
largos solo de lo pintado, peso de la página que no crece con el tamaño del grupo, concordancia
en singular, tope por encima del máximo real y botón ausente por encima del tope en las dos
páginas, plan fusionado y fichero con los mismos bloques que la página, una sola entrada de
auditoría por acción de grupo y rechazo de la nota repetida, error de base sin 500 en las dos
rutas, resumen calculado una vez por (origen, días) y `solo_cifras` sin mentir, reparto semanal,
fusión incompleta con rastro en el diario y paneles independientes. En
`tests/test_remediacion_agrupada.py` se adaptó `test_el_plan_de_remediacion_junta_los_grupos_con_la_misma_orden`,
que fijaba el comportamiento anterior (fusionar en la plantilla): ahora comprueba que el plan
sale ya fusionado del módulo y que fusionar dos veces no cambia nada.

**Lo que sigue pendiente.** Una nota de grupo sobre la actualización mayor escribe 1.358 filas en
`remediacion_notas` con el mismo texto (2,81 MB medidos con 1.935 caracteres): el tope de 2.000
filas y el freno a la repetición acotan cada acción, pero guardar el texto una sola vez y
referenciarlo desde cada fila exige un cambio de esquema (tabla de notas de grupo o columna
`nota_id`), que corresponde al coordinador. `comprobar_grupo` sigue dejando una entrada de
auditoría por fila —así lo fija `test_comprobar_el_grupo_comprueba_las_tres_y_ninguna_mas`,
porque cada veredicto es trazabilidad por CVE—: sobre la actualización mayor son 1.358 entradas
por acción, del mismo orden que las 1.358 filas de `remediacion_comprobaciones` que sí hacen
falta. La exportación CSV sigue siendo por fila, a propósito.

## Una entrada por actualización en la ficha del activo (2026-09-09)

**Lo que el usuario vio y rechazó.** Mirando `/activos/511` (SRV-EJEMPLO-511), la tabla
«Amenazas evaluadas para este activo» tenía **182 filas** —una por CVE y paquete— con los tres
veredictos: 155 afectadas, 22 no afectadas y 5 sin dato, para **69 vulnerabilidades reales**.
Entre ellas, **29 filas del paquete `linux-tools-common`**, todas con la misma versión instalada
(6.8.0-106.106) y siete versiones destino distintas (6.8.0-117.117, 124.124, 134.134, 136.136,
137.137, 138.138 y 139.139). Sus palabras:

> «si una vulnerabilidad se repite se cuente solo como una y en esa misma se deje la
> trazabilidad de las versiones y de la última versión a la que se debe actualizar… que la
> remediación indique sí o sí la última versión a la que se debe actualizar y no una por una
> porque entonces estaría contando 3 vulnerabilidades y no una sola»

> «necesito que se haga ese ajuste para todas las vulnerabilidades que se repitan y las futuras
> que se lleguen a detectar en las fuentes»

> «En amenazas por activo necesito ver solo lo que afecta, no me sirve que me muestre lo que no
> me afecta, no tiene sentido» · «recuerda eliminar lo que no me afecta… CVE-2023-42366 · Media ·
> No afectado · busybox-initramfs 1:1.36.1-6ubuntu3.1 → 1:1.36.1-6ubuntu3.1 · ya incluye la
> corrección»

No es un caso del núcleo: medido en producción el 2026-09-09, **1.456 pares (activo, paquete)**
tienen cola de versiones y se veían como **24.033 filas**; en total, **20.848 pares afectados**
frente a **65.532 filas**. El peor caso es Windows: `windows` con 1.358 vulnerabilidades y 6
compilaciones destino en `pc-ejemplo-305`, y 1.233 en `srv-ejemplo-410`.

### Qué se hizo

1. **La tabla de la ficha es de ACTUALIZACIONES.** La tabla «Amenazas evaluadas para este
   activo» desaparece y la sustituye «Actualizaciones pendientes»
   (`webui/templates/_remediaciones_activo.html`), que sale de
   `remediacion.pagina_actualizaciones(conn, estado="abierta", activo_id=…)`: una entrada por
   cosa que hay que actualizar (activo y origen de paquete). Cada fila dice el nombre, la
   versión instalada, la **última versión a la que hay que actualizar** destacada
   (`.version-objetivo`), cuántas vulnerabilidades resuelve con su unidad escrita, cuántas filas
   de remediación y en cuántos paquetes, la severidad peor, la explotación activa y los días de
   espera.
2. **Trazabilidad completa dentro de la fila.** Un desplegable con la cola de versiones de la
   más alta a la más baja; la primera lleva «la que hay que instalar: resuelve las N versiones
   pedidas» y un filete de acento. Cada versión lista las vulnerabilidades que la pidieron con
   su severidad, su explotación activa, el aviso enlazado a la fuente oficial, la fecha de
   detección, la comparación de versiones, la orden reproducible que la verifica y, si el aviso
   todavía no publica corrección, por qué (`_evidencia_de_los_pintados`, que llama a las mismas
   funciones de `aplicabilidad` que usaba la tabla retirada, no a una copia de sus reglas).
   En la ficha de un activo **la cola de versiones no se recorta nunca**: lo que se acota son
   los CVE de cada versión (`remediacion.LIMITE_CVES_POR_VERSION_FICHA = 20`, con un presupuesto
   global de `LIMITE_CVES_FICHA = 400`), y cada línea dice cuántos no se listan y dónde están.
3. **Solo lo que afecta.** No hay ninguna fila de veredicto «no afectado» ni «sin dato», ni las
   tarjetas «No le afectan» y «Sin dato», ni el panel «Veredictos» con su reparto. Queda **una
   línea** al pie del panel de actualizaciones: «Se evaluaron 88 identificadores CVE en este
   activo: 69 le afectan, 18 no le afectan porque la versión instalada ya lleva la corrección o
   queda fuera del rango vulnerable y 1 no precisa versiones en el aviso. Los que no le afectan
   no se listan aquí… están todos, con su evidencia, en Exportar veredictos (CSV)». La
   exportación en CSV **no se tocó**: sigue trayendo todos los veredictos.
4. **La cifra grande cuenta lo mismo que la tabla.** La primera tarjeta es «Actualizaciones
   pendientes» (28 en el activo 511) y su nota dice «cubren 69 vulnerabilidades en 77 paquetes
   (155 filas de remediación)». Las tres magnitudes salen de una sola consulta
   (`_cifras_pendientes_del_activo`) y el diccionario `act` se calcula **una vez** en
   `activo_detalle.html` y lo comparte el parcial: la tarjeta y la tabla no pueden discrepar.
5. **El plan del activo, también a la última versión.** `remediacion.fusionar_plan` ya no mete
   la versión en la clave de la fusión: `linux-tools-common` daba **tres órdenes** (una por
   versión) y el plan del activo 511 decía **35** donde la ficha decía 28. Ahora es una orden
   por sistema y origen de paquete, a la versión más alta comparada con el comparador de la
   distribución, con `cola_versiones` y `versiones_pedidas` para la trazabilidad, y el plan del
   activo 511 dice **28**, la misma cifra que su ficha. La fusión sigue siendo idempotente.
6. **Desfase honesto.** La tabla sale de la cola de remediación, que se llena en cada
   sincronización con OCS Inventory. Si la evaluación confirmó vulnerabilidades que todavía no
   están en la cola, la ficha lo dice en un aviso en vez de dejar creer que no hay nada que
   hacer.

### Medidas, antes y después

| Medida | Antes | Después |
| --- | --- | --- |
| Activo 511, filas de la tabla principal | 182 filas de veredicto (155 afectadas, 22 no afectadas, 5 sin dato) | **28 actualizaciones** |
| Activo 511, `linux-tools-common` | 29 filas, una por vulnerabilidad, siete versiones destino sueltas | 1 fila: «Actualizar a 6.8.0-139.139», 29 vulnerabilidades, cola de 7 versiones |
| Activo 511, plan de remediación | 35 órdenes (tres para `linux-tools-common`) | **28 órdenes**, la misma cifra que la ficha |
| Activo 511, filas «no afectado» o «sin dato» visibles | 27 | **0** |
| Activo 79, peso del HTML de la ficha | 253.768 caracteres | 314.703 caracteres |
| Activo 511, peso del HTML | no capturado antes del cambio | 330.715 caracteres (323,0 KiB), 35 ms |
| `pc-ejemplo-305` (Windows, 1.358 vulnerabilidades en 6 compilaciones) | 1 actualización con 1 sola versión visible de las 6 | 246.826 caracteres (241,0 KiB), 151 ms, **las 6 versiones** con hasta 20 CVE cada una |
| `pc-ejemplo-305` sin el recorte por versión | — | 1.344.827 caracteres (1.313,3 KiB): por eso existe el recorte |
| `srv-ejemplo-410` (1.233 vulnerabilidades) | — | 272.124 caracteres (265,7 KiB); sin recorte, 1.279.291 |

La ficha pesa más que antes porque la evidencia de cada vulnerabilidad (comparación de
versiones, orden que la verifica y referencia oficial) viaja ahora dentro de la trazabilidad de
su actualización, en vez de en una tabla aparte de veinte filas por página. A cambio, lo que se
lee es una lista de veintiocho cosas que hacer y no de ciento ochenta y dos filas.

### Lo que sigue en otras pantallas

El detalle de una amenaza (`webui/templates/amenaza_detalle.html`) sigue pintando la insignia
«No afectada» en su tabla de activos y las notas «N activos ya llevan la corrección»: ahí la
comparación entre lo que afecta y lo que no es el sentido del panel, y además es de otro agente.
`webui/templates/tecnologia_detalle.html` mantiene sus tarjetas de veredicto por tecnología (no
por activo). Quedan señaladas para que el coordinador decida.

---

## La severidad baja no cuenta en nada (2026-09-10)

**Orden del usuario, literal:** *«las amenazas y vulnerabilidades de severidad baja no se deben
tener en cuenta en absolutamente nada, así que no cuentan, recuerde que solo es lo de severidad
crítica, alta y media»*.

Era una regla que el usuario venía repitiendo y que hoy se cierra: la severidad baja desaparece
de **toda cifra, lista, cola de trabajo, gráfica, correo, informe y exportación**. La gobierna el
ajuste `ignore_low_severity` (activo) como el resto del código, de modo que si alguna vez se
desactiva vuelve a aparecer en todo **sin migración ninguna**: nada se borra de la base y la
sincronización sigue abriendo la remediación.

### Evaluar no es contar

La distinción que hay que conservar, y que está escrita en el propio código
(`threatintel/aplicabilidad.py`, cabecera «La severidad BAJA no cuenta en nada»):

- **Evaluar** (`evaluar_amenaza`, `evaluar_pendientes`, `responder_cve`, `repasar_referencias`,
  `recalcular_resumenes`, `msrc.evaluar_activos`, `parches.sincronizar`, `parches.buscar`,
  `remediacion.sincronizar`): se sigue evaluando **todo**, también la severidad baja. El veredicto
  es un hecho comprobado contra OCS Inventory; la severidad de un CVE cambia (un fallo publicado
  como bajo sube a alto cuando llega la puntuación oficial o entra en el catálogo KEV de CISA), y
  ese día la remediación tiene que aparecer con su antigüedad verdadera, no empezando de cero.
- **Contar y mostrar**: la severidad baja queda fuera, siempre, en todas las lecturas.

### Decisión sobre `remediacion.sincronizar`

**Se sigue sincronizando la severidad baja: no se deja de abrir la remediación.** Tres motivos,
escritos también en el docstring de la función:

1. **Reversibilidad inmediata.** El usuario pidió que al desactivar el ajuste la severidad baja
   volviera a aparecer sin migración. Si `sincronizar` dejara de abrirla, al desactivarlo no
   habría nada que enseñar hasta la siguiente sincronización con OCS Inventory (una vez al día) y
   las filas nuevas habrían perdido su fecha de detección real.
2. **La severidad cambia.** Sin la fila abierta, el día que el CVE sube de severidad los días de
   espera y el tiempo medio hasta corregir mentirían.
3. **No cuesta nada.** Son 2.774 filas de 48.216 pendientes (menos del 6 % de la tabla), sin
   efecto medible en el tiempo de sincronización.

### Sitios corregidos

| Fichero | Qué se filtró |
| --- | --- |
| `threatintel/remediacion.py` | `excluir_bajas`, `_SIN_BAJAS_SQL` y `_y_sin_bajas` nuevos, y con ellos: `resumen` (las cuatro cifras, el reparto por tipo de máquina, el reparto por proceso), `_serie_semanal` (las dos series de la gráfica), `contar`, `listar`, `_filtros_sql`, `contar_actualizaciones`, `pagina_actualizaciones`, `listar_actualizaciones`, `_cte_firmas`, `_paquetes_de_fusiones`, `_detalle_de_grupos`, `_paquetes_hermanos`, `procesos`, `historial_activo`, `contar_historial_activo`, `_remediaciones_del_grupo` |
| `threatintel/parches.py` | `excluir_bajas`, `_SIN_BAJAS_SQL` y `_SIN_BAJAS_APLICABILIDAD_SQL` nuevos, y con ellos: `resumen` (las once cifras), `_condicion` (que ahora recibe la conexión, y con ella `listar` y `contar`), `sin_correccion` y `novedades` (la sección del correo diario) |
| `webui/vistas/parches.py` | `_contar_acotado`, `_listar_acotado` y `_resumen_acotado` (la página acotada al tipo de máquina de los perfiles Redes y Mantenimiento) |
| `threatintel/msrc.py` | `resumen_activo` (las tres cifras de la tarjeta «Parches de Windows» de la ficha del activo) |
| `threatintel/sbom.py` | `resumen_activo` (vulnerabilidades del inventario de componentes) |
| `threatintel/aplicabilidad.py` | `excluir_bajas`, `_SIN_BAJAS_SQL` y `_y_sin_bajas` nuevos, y con ellos: `plan_remediacion` (y por tanto `plan_remediacion_texto`, que parte de sus grupos), `activos_distintos`, `versiones_pedidas_por_paquete`, `anotar_version_ultima_sistemas`, `conteo_activo`, `contar_veredictos_activo`, `veredictos_de_activo`, `resumen_informe`, y `vulnerabilidades_activo` (que ahora lee el ajuste cuando no se le fuerza) |
| `webui/vistas/remediaciones.py` | `_cifras_pendientes_del_activo` y el filtro «Severidad», que ya no ofrece la baja |
| `webui/templates/remediaciones.html` | Se retira la fila «De todo lo anterior, de severidad baja» del panel «Qué cuenta cada cifra» (el resto del panel, que explica las unidades, se conserva), la ayuda del filtro, la línea de bajas de cada fila del avance por tipo de máquina y las notas de las tarjetas |
| `webui/templates/_remediaciones_resumen.html` | El párrafo que explicaba la diferencia entre 748 y 746 activos por la severidad baja |
| `webui/templates/activos.html`, `amenazas.html`, `informes.html`, `panel.html`, `tendencias.html`, `tecnologias.html`, `_glosario.html` | Ninguna pantalla nombra la severidad baja mientras el ajuste está activo; los textos y las columnas que sí la nombran quedan condicionados a que el ajuste esté **desactivado** |
| `threatintel/digest.py`, `threatintel/notify.py` | Las frases del resumen semanal y del pie «Filtro de hoy» del correo diario dicen cuántas amenazas quedaron fuera **por su severidad**, sin nombrarla |
| `threatintel/queries.py` | `MOTIVO_EXCLUSION_ES["severidad_baja"]`, que pintan la ficha de la amenaza y el informe mensual, pasa a «por su severidad: por decisión del equipo no se reporta» |
| `threatintel/report.py` | El informe mensual (DOCX) ya no nombra la severidad baja: el reparto por severidad, la fila de la tabla de precisión del filtro y el párrafo del orden de los motivos de exclusión |

### Medidas, antes y después (base real, 10 de septiembre de 2026)

El «antes» se midió con la misma función sobre una copia de la base hecha con la API `backup` de
sqlite3 y el ajuste desactivado en la copia, que es exactamente el comportamiento anterior de
todo lo que no filtraba. La copia se borró al terminar.

| Cifra | Antes | Después | Diferencia |
| --- | --- | --- | --- |
| Remediación · filas pendientes | 48.216 filas | **45.442 filas** | 2.774 filas de severidad baja |
| Remediación · vulnerabilidades pendientes (activo y CVE) | 33.695 vulnerabilidades | **32.731 vulnerabilidades** | 964 vulnerabilidades |
| Remediación · CVE distintos | 1.673 CVE | **1.665 CVE** | 8 CVE |
| Remediación · actualizaciones pendientes | 6.871 actualizaciones | **6.054 actualizaciones** | 817 actualizaciones |
| Remediación · actualizaciones con versión que instalar | 5.076 | **4.547** | 529 |
| Remediación · activos con pendientes | 602 activos | **601 activos** | 1 activo cuyas únicas pendientes eran bajas |
| Remediación · filas de activos retirados | 13.621 filas | **12.706 filas** | 915 filas |
| Remediación · filas totales (todos los estados) | 66.326 filas | **62.637 filas** | 3.689 filas |
| Avance · servidores (filas / vulnerabilidades / actualizaciones / activos) | 21.128 / 10.647 / 4.633 / 347 | **19.355 / 9.964 / 4.098 / 346** | 1.773 / 683 / 535 / 1 |
| Avance · equipos de cómputo (filas / vulnerabilidades / actualizaciones / activos) | 27.088 / 23.048 / 2.238 / 255 | **26.087 / 22.767 / 1.956 / 255** | 1.001 / 281 / 282 / 0 |
| Gráfica semanal · remediaciones detectadas (5 semanas) | 52.705 filas | **49.931 filas** | 2.774 filas |
| Correcciones pendientes · en seguimiento | 152 correcciones | **140 correcciones** | 12 correcciones |
| Correcciones pendientes · por motivo (aviso sin versión / distribución sin empaquetar) | 32 / 99 | **26 / 93** | 6 / 6 |
| Correcciones pendientes · activos expuestos del resumen «sin corrección» | 2.917 activos | **2.416 activos** | 501 activos |
| Parches de Windows · ficha del activo 830 (`n_afectados`) | 1.358 vulnerabilidades | **1.355 vulnerabilidades** | 3 vulnerabilidades |
| Ficha del activo 830 · `conteo_activo` afectado | 1.358 CVE | **1.355 CVE** | 3 CVE |
| Plan de remediación del activo 756 · órdenes | 31 órdenes | **24 órdenes** | 7 órdenes |
| Plan de remediación del activo 756 · CVE | 67 CVE | **63 CVE** | 4 CVE |
| Plan de remediación del activo 756 · líneas del fichero descargado | 254 líneas | **198 líneas** | 56 líneas |
| Ficha del activo 756 · filas de veredicto que se paginan | 358 filas | **331 filas** | 27 filas |
| Informe mensual 2026-09 · activos con vulnerabilidades confirmadas | 568 activos | **557 activos** | 11 activos |
| Informe mensual 2026-09 · vulnerabilidades | 15.018 vulnerabilidades | **14.071 vulnerabilidades** | 947 vulnerabilidades |
| Informe mensual 2026-09 · vulnerabilidades corregidas | 20.275 | **19.497** | 778 |

### Las cifras de activos cuadran entre páginas

Medido con la función real de cada página sobre la base de producción, el 10 de septiembre de
2026:

| Página | Función | Antes | Después |
| --- | --- | --- | --- |
| Activos, «Con vulnerabilidades confirmadas» | `webui.vistas.activos._existe_afectado` | 597 activos | **597 activos** |
| Amenazas, «Activos afectados» | `queries.resumen_amenazas` | 597 activos | **597 activos** |
| Panel, «Con al menos una vulnerabilidad confirmada» | `ocs.estado_activos` | 597 activos | **597 activos** |
| Resumen semanal, estado de los activos | `digest._estado_activos` | 597 activos | **597 activos** |
| Remediación, «Activos con pendientes» | `remediacion.resumen` | 602 activos | **601 activos** |

También cuadran los CVE distintos: Remediación decía 1.673 y el Panel 1.665; ahora las dos dicen
**1.665 CVE**.

**Los 4 activos de diferencia que quedan no son de severidad**: son activos con remediaciones
pendientes cuyas filas de `aplicabilidad` pasaron a `sin_dato` en la última evaluación (por
ejemplo porque la consulta a OSV.dev agotó el cupo del día) o cuya amenaza se descartó a mano. La
plataforma **no cierra** una remediación por ninguna de esas dos cosas: espera a que OCS
Inventory vea la versión corregida instalada. Son los activos 705, 712, 763 y 833, todos con
remediaciones críticas, altas y medias abiertas y con las 1.422 filas de `aplicabilidad` en
`sin_dato`. La página de Activos y la de Remediación lo dicen con esas palabras, con la cifra
calculada, en vez de dejar dos números sin explicación.

### El filtro «Severidad» de `/remediaciones/`

El filtro que se añadió el 2026-09-09 ofrecía seis opciones y la de omisión era «Todas, incluida
la baja (la cola completa)». Ahora ofrece cuatro y ninguna incluye la baja:

- «Todas las que se reportan (crítica, alta y media)» — la de omisión;
- «Solo severidad crítica», «Solo severidad alta», «Solo severidad media».

Un valor antiguo guardado en un enlace (`?severidad=low`, `?severidad=sin_bajas`) no filtra nada
y **no devuelve** la severidad baja a la lista: la deja fuera `_SIN_BAJAS_SQL`, que se aplica
siempre y no depende de este filtro.

### Lo que NO se filtró, y por qué

- **`aplicabilidad.activos_de_amenaza`** (la lista de activos afectados de la ficha de UNA
  amenaza). La consulta está acotada a una sola amenaza, así que todas sus filas tienen la
  severidad de esa amenaza: para las que no son bajas el filtro no cambiaría nada, y para una baja
  vaciaría la lista mientras los recuentos guardados de la evaluación
  (`aplicabilidad_amenaza.afectados`, que la evaluación sigue escribiendo sobre todo por orden del
  usuario) seguirían diciendo 326 activos en el caso mayor de producción (CVE-2026-73281). Serían
  dos cifras de lo mismo en la misma pantalla. Nada que cuente ni que se reporte llega ahí con una
  amenaza baja: `adjuntar_activos` solo se llama con amenazas que ya pasaron el filtro de
  severidad, una baja nunca genera alerta (`queries.motivo_exclusion` devuelve «severidad_baja») y
  el informe mensual no la incluye. **Queda pendiente de decisión del coordinador**: o el catálogo
  de Amenazas deja de ofrecer la severidad baja en su filtro (`webui/vistas/amenazas.py`,
  `SEVERIDADES`) y en su ficha, o la ficha dice que esa amenaza no se reporta por su severidad.
- **`aplicabilidad.responder_cve`**, **`msrc._totales_amenazas`**, **`msrc.evaluar_activos`**,
  **`aplicabilidad.recalcular_resumenes`**, **`parches.sincronizar`**, **`parches.buscar`**
  (`_SQL_A_BUSCAR`), **`sbom.evaluar`** y **`remediacion.sincronizar`**: son funciones de
  evaluación y escritura. Siguen viendo la severidad baja a propósito, y es lo que hace que el
  cambio sea reversible sin migración.

### Qué sigue nombrando la severidad baja, a propósito

- El **texto de ayuda del ajuste `ignore_low_severity`** en Ajustes, que tiene que seguir
  explicando qué pasa si se desactiva.
- Los textos y las columnas «Bajas» de Panel, Amenazas y Tendencias que solo se pintan **cuando
  el ajuste está desactivado**: entonces la severidad baja cuenta y hay que nombrarla, o la
  gráfica perdería un segmento sin decirlo.

Y lo que queda por decidir: el **filtro de severidad del catálogo de Amenazas**
(`webui/vistas/amenazas.py`, `SEVERIDADES = ["Critical", "High", "Medium", "Low"]`) sigue
ofreciendo «Baja» y la ficha de una amenaza baja sigue mostrando su insignia de severidad y su
banda de CVSS. Es el único sitio de la interfaz, fuera de Ajustes, que nombra la severidad baja
con el ajuste activo, y cambiarlo es del dominio de Amenazas.
