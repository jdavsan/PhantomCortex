# Top 10 en el correo diario e informe ejecutivo mensual — 2026-09-15

Dos peticiones del usuario, resueltas en el mismo cambio porque tocan lo mismo: **decir
menos y decirlo mejor**.

---

## 1. El correo de alertamiento diario muestra un top 10

### 1.1 Qué pidió el usuario

> «En el correo de alertamiento diario dice que hay muchas vulnerabilidades o amenazas
> detectadas en el día, así que necesito que esto se ajuste y se muestren solo el top 10 y
> ya lo demás que lo muestre de acuerdo a lo indicado, es decir que en prioridad de
> actuación debe mostrar un top 10 y seguir manteniendo las 3 más críticas en detalle.»

### 1.2 Qué había

La tabla **«Prioridad de actuación»** era el índice completo del correo: **una fila por
cada amenaza alertada**, con un tope de seguridad de 200 filas (`meta["max_tabla"]`). El 11
de septiembre fueron 76 filas; el 9, 89. Solo las tres primeras se desarrollaban en detalle
(`meta["detalle_top"]`, ajuste `alert_detalle_top`).

### 1.3 Qué hay desde hoy

* La tabla lista **las diez de mayor relevancia**. El número lo decide el ajuste nuevo
  **`alert_tabla_top`** (valor por omisión **10**).
* **`alert_max_items` se conserva como tope de seguridad** de esa tabla: la ejecución
  diaria lo pasa como `max_tabla` y `notify` toma `min(tabla_top, max_tabla)`. Si alguien
  configurara un top de 50 con `alert_max_items = 25`, la tabla enseñaría 25.
* **Las tres más críticas siguen en detalle**, exactamente igual que antes
  (`alert_detalle_top`, sin cambios).
* **Se dice dos veces, y sin rodeos, cuántas quedan fuera y dónde están:**
  1. **antes de la tabla**, debajo del encabezado: «Las 10 de mayor relevancia de las 76
     amenazas que requieren acción hoy. Las 66 restantes no se listan aquí: están donde
     dice el recuadro azul de debajo de la tabla.» Va arriba a propósito: nadie puede leer
     la tabla creyendo que son todas.
  2. **debajo de la tabla**, en un recuadro con la cifra en grande: «**Faltan 66 amenazas
     por ver.** La tabla de arriba enseña las 10 de mayor relevancia de las 76 amenazas que
     requieren acción hoy. Las 66 restantes no se han descartado y hay que atenderlas
     igual.» Y a continuación, **«Dónde ver las 66 que faltan»**, con los dos sitios
     numerados: la hoja de cálculo adjunta (que lleva **todas**, una pestaña por
     vulnerabilidad más la pestaña de resumen) y la plataforma, **con su enlace**.
* Los días sin adjunto el recuadro no promete una hoja de cálculo que no va: dice
  «En la plataforma: …, con su ficha, su impacto y los activos afectados. Hoy no se adjunta
  la hoja de cálculo.»
* Con **diez amenazas o menos** el correo no miente: el recuadro dice «**Están todas en la
  tabla**» y no aparece ninguna cifra de «faltan».
* En el recuadro hay **una sola cifra de lo que no se ve**. La frase «73 quedan sin
  desarrollar aquí» (que se refiere al detalle, no a la tabla) solo se escribe cuando la
  tabla las lista todas: con las dos a la vez se leían «66 faltan» y «73 sin desarrollar»
  como una contradicción.

### 1.4 La cabecera y el pie siguen cuadrando

Todo lo que no es la tabla sigue hablando del **total alertado**, no de las diez:

| Parte del correo | Qué dice el 11 de septiembre |
|---|---|
| Preencabezado | «76 amenazas que requieren acción: 9 críticas y 67 altas» |
| Título | «76 amenazas detectadas hoy que requieren acción» |
| Cuadro «Vulnerabilidades detectadas hoy» | 9 críticas · 67 altas · 0 medias · 0 en KEV |
| Exposición real | «75 de las 76 amenazas de este correo tienen activos… (41 activos distintos)» |
| Tabla de prioridad | **10 filas**, y lo dice antes y después |
| Detalle | «Las 3 más críticas, en detalle» |
| Pie «Filtro de hoy» | lo excluido por el filtro, con su motivo |

### 1.5 Medido con los datos reales

Copia de la base de producción hecha con la API `backup` de sqlite3, bajo `data/`, borrada
al terminar. **No se envió ningún correo**: el HTML y el mensaje MIME se componen en
memoria con la misma estructura que `notify.Mailer.send` y se miden.

| Día | Amenazas alertadas | Filas de la tabla antes | Filas ahora | HTML antes | HTML ahora | Correo completo antes | Correo completo ahora | Quedan fuera |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 9 de septiembre | 89 | 89 | **10** | 400,2 KB | **292,4 KB** | 1.348,2 KB | **1.188,9 KB** | 79 |
| 10 de septiembre | 35 | 35 | **10** | 217,3 KB | **183,4 KB** | 597,8 KB | **547,9 KB** | 25 |
| 11 de septiembre | 76 | 76 | **10** | 315,7 KB | **225,7 KB** | 982,3 KB | **849,4 KB** | 66 |
| 12 de septiembre | 4 | 4 | **4** | 123,7 KB | 123,7 KB | 226,4 KB | 226,4 KB | **0** |
| 15 de septiembre | 62 | 62 | **10** | 348,6 KB | **277,7 KB** | 1.029,9 KB | **925,2 KB** | 52 |

* El **cuerpo HTML** del correo del 11 de septiembre baja de 315,7 KB a 225,7 KB: **90,0 KB
  menos, un 28,5 %**.
* El **mensaje completo** (texto plano + HTML + la hoja de cálculo adjunta en base64) baja
  de 982,3 KB a 849,4 KB: **132,9 KB menos, un 13,5 %**.
* El día de cuatro amenazas el correo **no cambia ni un byte**: con menos de diez no hay
  nada que recortar.

**Aviso para el coordinador sobre el tamaño.** El usuario recordaba «unos 170 KB con el
adjunto» para el correo del 11 de septiembre; lo medido hoy sobre la copia de la base es
**849,4 KB** después del cambio. La diferencia no está en la tabla: está en la **hoja de
cálculo adjunta**, que lleva una pestaña por vulnerabilidad (76 pestañas ese día) y pesa
más de 600 KB en base64. Si el objetivo es un correo ligero, la palanca siguiente es el
adjunto (`alert_adjuntar_excel`, `alert_excel_max_activos`), no el cuerpo. **No se ha
tocado**: la hoja es justamente donde el correo dice que están las que faltan.

### 1.6 El ajuste nuevo (lo tiene que aplicar el coordinador)

`threatintel/config.py` y `webui/vistas/ajustes.py` son ficheros compartidos y **no se han
modificado**. El correo ya funciona con el valor por omisión (`cfg.get("alert_tabla_top",
10)` devuelve 10 cuando la clave no existe), pero para que el ajuste sea **editable desde
Administración → Ajustes** hacen falta estas tres líneas:

**`threatintel/config.py`**, en `DEFAULT_SETTINGS`, junto a `alert_detalle_top`:

```python
    "alert_tabla_top": 10,               # filas de la tabla «Prioridad de actuación» del correo
```

**`webui/vistas/ajustes.py`**, en el grupo de alertas, justo antes de `alert_detalle_top`:

```python
        ("alert_tabla_top", "Vulnerabilidades en la tabla del correo diario", "int",
         "Cuántas filas tiene la tabla «Prioridad de actuación» del correo de alertamiento "
         "diario: las de mayor relevancia del día. El correo dice siempre cuántas quedan "
         "fuera y dónde verlas (la hoja de cálculo adjunta y la plataforma), y la cabecera "
         "sigue dando el total del día. Con 10 el correo se lee en una pantalla; subirlo "
         "alarga el correo sin añadir información, porque todas están en la hoja de cálculo. "
         "El ajuste «Amenazas detalladas por correo» sigue siendo el tope de seguridad: si "
         "es menor que este número, manda él."),
```

**`webui/vistas/ajustes.py`**, en `RANGOS_ENTEROS`:

```python
    "alert_tabla_top": (1, 50, "debe estar entre 1 y 50"),
```

---

## 2. Informe ejecutivo mensual de diez páginas

### 2.1 Qué pidió el usuario

> «Necesito que a final de mes también se genere un informe ejecutivo sobre las amenazas
> del mes que no exceda las 10 páginas, donde debe ser muy conciso, concreto, directo y lo
> que normalmente le interesa a un gerente: temas de cifras, comparación entre meses o años
> y avances entre meses con detectadas y remediadas.»

### 2.2 Qué es

Un documento **nuevo y aparte**. El informe mensual completo **no cambia ni una coma**:
sigue siendo el mismo que compone `report.construir_documento` y que compara párrafo a
párrafo `tests/test_informes_medida.py`. El ejecutivo lo compone
`report.construir_documento_ejecutivo`, que **no comparte una sola línea** con él.

### 2.3 Índice del documento

| | Apartado | Qué lleva |
|---|---|---|
| — | **Portada del informe ejecutivo** | Mes, alcance y **la situación en cuatro cifras** (vulnerabilidades confirmadas, activos afectados sobre el parque, con explotación activa confirmada, trabajo pendiente hoy), cada una con su variación respecto al mes anterior |
| 1 | **Las cifras del mes** | Amenazas registradas, de ellas críticas o altas, vulnerabilidades confirmadas, activos afectados sobre el parque y su porcentaje, con explotación activa confirmada, y trabajo pendiente agrupado en actualizaciones. Una tabla de seis filas con una columna «Qué significa» y un párrafo que explica la diferencia entre «amenaza» y «vulnerabilidad» |
| 2 | **Comparación con el mes anterior y con el año pasado** | Las cinco magnitudes, mes actual · mes anterior · mismo mes del año pasado · variación **en número, en porcentaje y en palabras** («mejoró», «empeoró», «se mantiene»). Si no hay dato del año pasado lo dice y no inventa un porcentaje |
| 3 | **Avance mes a mes: detectadas y remediadas** | Una fila por mes con detectadas, remediadas, saldo de la deuda («la deuda sube en N» / «baja en N» / «sin cambio»), tiempo medio en corregir y una barra de bloques que compara las dos series. Los meses en los que no había cola **no se pintan a cero**: no serían un cero, sería una ausencia de dato, y se dice |
| 4 | **Dónde está el trabajo pendiente** | Cuánto queda, en cuántos activos, en cuántas actualizaciones, cuántas todavía no tienen versión que instalar, el reparto por proceso de negocio (seis filas como mucho) y qué parte es urgente |
| 5 | **Qué conviene hacer el mes que viene** | Tres o cuatro puntos, cada uno con **«Qué cambia si se hace»**. Salen de los datos: cerrar lo que se está explotando, fijar un objetivo de cierre, pedir ventana de mantenimiento al área con más trabajo y recuperar el inventario de las máquinas que no reportan |

### 2.4 Que sea de diez páginas, medido

Generado con los datos reales (copia de la base de producción) y **convertido a PDF con
LibreOffice para contar las páginas de verdad**:

| Mes | Tamaño del `.docx` | Tiempo de generación | **Páginas reales** |
|---|---:|---:|---:|
| septiembre de 2026 | 40,6 KB | 1,06 s | **4** |
| agosto de 2026 | 40,0 KB | 0,89 s | **4** |
| julio de 2026 | 40,0 KB | 0,84 s | **4** |

**Por qué no puede crecer.** Ningún apartado lleva una fila por vulnerabilidad: no hay
fichas, no hay anexo, no hay cola de remediación. Las tablas más largas tienen doce filas
(la serie mensual) y seis (el reparto por proceso). Con la base real —1.523 amenazas y
15.731 vulnerabilidades en septiembre— el documento sale igual de largo que con la base de
pruebas. `tests/test_informe_ejecutivo.py` lo fija por dos caminos: mide las páginas con
LibreOffice cuando está instalado y, siempre, comprueba el guardián estructural (como mucho
45 filas de tabla, 60 párrafos y dos saltos de página).

### 2.5 Que sea «para un gerente»

El documento **no escribe** ningún identificador de vulnerabilidad, ningún nombre de
paquete, ninguna versión, ninguna puntuación técnica y ninguna orden que ejecutar. Hay una
prueba que lo comprueba palabra por palabra (`CVE-`, `openssl`, `3.0.14`, `apt-get`,
`sudo`, `dpkg`, `CVSS`, `Ficha`, `fingerprint`). Toda cifra lleva su unidad y su
comparación, y los decimales van con coma.

### 2.6 De dónde salen las cifras

Todo del mismo sitio que las pantallas, para que no haya dos verdades:

| Dato | Origen |
|---|---|
| Amenazas del mes y serie mensual | `informe_seleccion.evolucion` (la serie de Tendencias, acotada por el alcance y por las severidades que se reportan) |
| Vulnerabilidades confirmadas y activos afectados | `aplicabilidad` cruzada con `threats`, contando con `queries.sql_vulnerabilidades` (un CVE en un activo), **sin la severidad baja y sin el riesgo aceptado**, igual que la página de Activos |
| Parque | `activos` presentes del alcance |
| Detectadas y remediadas por mes, y tiempo medio | `remediaciones`, con las mismas exclusiones y dejando fuera los activos retirados, igual que la gráfica semanal de Remediación |
| Trabajo pendiente y reparto por proceso | `remediacion.resumen` |

La severidad **baja no se cuenta ni se nombra** en ninguna cifra ni en ningún apartado.

### 2.7 Cuándo se genera

* **Ejecución mensual programada** (`bin/ejecucion_mensual.py`): el último día del mes se
  generan **los dos** documentos y el correo los lleva **los dos adjuntos**. El paso nuevo
  es `[2/3]`. Si el ejecutivo fallara, el informe completo se envía igualmente: el correo de
  la dirección no puede perderse porque el resumen corto no se haya podido componer.
  El fichero se llama `Informe_Ejecutivo_AAAA_MM.docx` y se guarda al lado del completo, con
  permisos `0640` y la misma regla de archivado a los doce meses.
* **Correo mensual** (`threatintel/emails/mensual.html`): el bloque de adjuntos dice ahora
  «Documentos adjuntos: 2», describe cada uno y para quién es. Si el ejecutivo no se generó,
  el correo es el de siempre, con un solo adjunto.
* **A demanda, desde `/informes/`**: plantilla **«Informe ejecutivo del mes (diez
  páginas)»**, de cualquier mes con datos.

### 2.8 En `/informes/`

* Es una plantilla más de la rejilla, pero **de estructura fija**: el formulario solo pide
  el **mes** y los datos de portada (título, destinatario y nota). El periodo, el alcance,
  las severidades y los apartados **no se pueden cambiar**, y esa es justamente la garantía
  del tope de páginas. Una dirección web manipulada
  (`?plantilla=ejecutivo&apartado=anexo&periodo=anio&alcance=kev`) no consigue nada:
  `Seleccion.desde_parametros` los vuelve a fijar después de validar.
* Al revés también: los apartados del ejecutivo **no se cuelan** en otro informe.
  `ordenar_apartados` no mezcla los dos catálogos.
* La vista previa enseña su esquema con la numeración real y dice «Estructura fija… nunca
  pasa de diez páginas».
* **Permisos, alcance y auditoría, como el resto**: `requiere_informes` (administrador y
  operador SOC), CSRF en el `POST`, alcance del perfil aplicado por encima de la dirección,
  auditoría `informe.medida` con `entity_id = "ejecutivo"` y el mes en el detalle,
  **documento en memoria** (no queda copia en el servidor) y **sin modelo de lenguaje**.
* Nombre de la descarga: `informe_ejecutivo_AAAA-MM.docx`, compuesto solo con claves
  internas y fechas.

---

## 3. Ficheros

| Fichero | Qué cambia |
|---|---|
| `threatintel/notify.py` | `render_alert_email` admite `meta["tabla_top"]` (10 por omisión) y pasa `tabla_top` a la plantilla; `max_tabla` sigue siendo el tope de seguridad |
| `threatintel/emails/alerta.html` | Encabezado de la tabla con la frase del top; recuadro de «faltan N por ver» con los dos sitios donde están y el enlace |
| `threatintel/emails/mensual.html` | Anuncia los dos documentos adjuntos y para quién es cada uno |
| `threatintel/report.py` | **Nuevo:** `resumen_ejecutivo_mensual`, `construir_documento_ejecutivo`, `generar_ejecutivo_en_memoria`, `generar_ejecutivo`, `nombre_fichero_ejecutivo` y sus apartados `_ej_*`; `construir_documento` delega cuando los apartados son los del ejecutivo |
| `threatintel/informe_seleccion.py` | `APARTADOS_EJECUTIVO`, la plantilla `ejecutivo`, `Seleccion.es_ejecutivo()`, la selección forzada y la estimación de páginas |
| `webui/vistas/informes.py` | Rama del informe ejecutivo en `POST /informes/generar` y su auditoría |
| `webui/templates/_informe_campos.html` | Formulario reducido cuando la plantilla es la ejecutiva |
| `webui/templates/_informe_vista_previa.html` | Nota de estructura fija y tope de páginas |
| `webui/templates/informes.html` | Textos y el apartado «El informe ejecutivo del mes, aparte» |
| `bin/ejecucion_diaria.py` | Pasa `tabla_top` (`alert_tabla_top`) y `max_tabla` (`alert_max_items`) |
| `bin/ejecucion_mensual.py` | Paso `[2/3]`: genera el ejecutivo y lo adjunta; archivado de los dos |
| `tests/test_informe_ejecutivo.py` | **Nuevo.** 51 pruebas |
| `tests/test_correo_top.py` | Clase `TestTablaDePrioridadTopDiez` (7 pruebas) y `TestAjusteDelTopDeLaTabla` (3) |
| `tests/test_informes_medida.py`, `tests/test_informes_vista_previa_pegada.py`, `tests/test_interaccion_sin_recarga.py` | Adaptadas a la plantilla nueva |
| `docs/CORREO_TOP10_E_INFORME_EJECUTIVO_2026-09-15.md` | Este documento |

## 4. Lo que queda pendiente

* **El ajuste `alert_tabla_top` en la interfaz**: las tres líneas de la sección 1.6, en
  `threatintel/config.py` y `webui/vistas/ajustes.py` (ficheros compartidos).
* **`bin/enviar_prueba.py`** no pasa `tabla_top`, así que usa el valor por omisión (10). Es
  el comportamiento correcto, pero si se quiere que respete el ajuste hay que añadirle
  `"tabla_top": int(cfg.get("alert_tabla_top", 10) or 10)` al `meta` de la alerta.
* **Comparación entre años**: hoy la base no tiene septiembre de 2025, así que el informe
  ejecutivo escribe «No hay comparación con septiembre de 2025: la plataforma no tiene datos
  de ese mes». La comparación funciona y está probada; se verá sola cuando el histórico
  llegue a doce meses.
* **Serie de detectadas y remediadas**: la cola de remediación se registra desde el **4 de
  septiembre de 2026**, así que hoy la tabla tiene una sola fila y el documento lo explica y
  añade el avance semanal del mes. Desde octubre tendrá dos filas y comparará mes contra
  mes sin ayuda.
* **Tamaño del correo diario**: la palanca que queda es el adjunto, no el cuerpo
  (sección 1.5).
