# Informes a medida (`/informes/`) — 2026-09-10

## 1. Qué pidió el usuario

> «El apartado de /informes/ es para que se puedan crear informes con lo que uno desee, es
> decir que uno pueda agregar lo que desea y no descargar los informes de cada mes,
> entonces ajusta eso, la idea es poder crear informes personalizados y tener plantillas
> de informes preconfiguradas.»

Hasta el 2026-09-10 `/informes/` era una lista de meses con un botón por fila que
descargaba el informe mensual completo tal cual lo compone
`threatintel.report.construir_documento`. Ahora es un **generador**: se elige el periodo,
el alcance, las severidades y los apartados, se ve en cifras qué va a entrar en el
documento y se descarga. El informe mensual completo sigue existiendo como una plantilla
más y conserva su descarga rápida por mes.

## 2. Cómo funciona

### 2.1 Una sola dirección con parámetros

Toda la pantalla vive en `GET /informes/`. La selección viaja en la dirección web
(`?plantilla=…&periodo=…&mes=…&alcance=…&sev=…&apartado=…&titulo=…`), de modo que:

* al elegir una plantilla se entra por `?plantilla=<clave>` y el formulario se rellena con
  sus valores;
* cualquier ajuste posterior queda en la dirección;
* el botón **«Copiar el enlace de este informe»** copia esa dirección (campo de solo
  lectura + `data-copiar` de `app.js`, sin scripts en línea). Guardar el enlace es, hoy, la
  forma de guardar una plantilla propia.

**Pendiente conocido y deliberado:** no se guarda nada en la base de datos. Las plantillas
propias guardadas necesitan una tabla nueva (`informe_plantillas`) y el usuario las hará
después; el enlace es el paso previo. La sección 7 propone el esquema.

La generación es `POST /informes/generar` (token CSRF, rol comprobado, auditoría). La
descarga rápida del mes sigue en `POST /informes/<mes>/descargar`, sin cambios.

### 2.2 Periodo

| Opción | Cómo se filtra | Nota |
|---|---|---|
| Un mes concreto | `threats.month = ?` (índice `idx_threats_month`) | Solo meses con amenazas |
| Un intervalo de fechas | `first_seen_at >= ? AND first_seen_at < ?` (índice `idx_threats_seen`) | Los dos extremos entran; tope de 1.830 días |
| Los últimos N días | igual, desde hace N-1 días hasta hoy | Tope de 366 días |
| El año en curso | igual, del 1 de enero a hoy | |

Nunca se usa `date(first_seen_at)`: anularía el índice. Una amenaza entra por la fecha en
que la plataforma la vio por primera vez.

### 2.3 Alcance

| Opción | Cómo se filtra |
|---|---|
| Toda la organización | sin recorte (salvo el del perfil) |
| Un proceso de negocio | `EXISTS` en `aplicabilidad` con `queries.filtro_parque(proceso)` |
| Un tipo de máquina | igual, con `activos.origen` (`servidores` / `equipos`) |
| Un activo concreto | igual, con `activos.id` |
| Una tecnología | `EXISTS` en `threat_technologies` por `technologies.slug` |
| Solo con explotación activa confirmada | `threats.in_kev = 1` |

El recorte por proceso y por tipo de máquina lo escribe `queries.filtro_parque`, el mismo
que usan las páginas de Amenazas y de Activos: un informe «de Impuestos» cuenta
exactamente los activos que cuenta la pantalla de Impuestos.

**Alcance del perfil.** `webui.auth.alcance_origen()` entra en la selección como
`origen_perfil` y se aplica por encima de cualquier parámetro de la dirección. Un perfil de
Redes (servidores) que pida `?alcance=tipo&tipo=equipos` recibe **404**, igual que en
Activos: un identificador del otro tipo de máquina no debe revelar que existe. Pedir un
activo del otro tipo también es 404. Y cuando pide «toda la organización», el informe queda
acotado a sus servidores, incluidas las máquinas que se nombran en las fichas
(`report._adjuntar_activos_del_alcance`).

### 2.4 Severidades

Se ofrecen **críticas, altas y medias**. La severidad baja no está en
`informe_seleccion.SEVERIDADES`, no se ofrece en el formulario y se descarta al validar
aunque se escriba en la dirección web. En un informe a medida los apartados solo nombran y
pintan las severidades pedidas: no aparece un «0 media» de una severidad que el informe no
cubre.

### 2.5 Apartados

Doce apartados, siempre en el orden del documento y numerados seguidos (sin huecos):

| Clave | Título en el documento | Función de `report.py` |
|---|---|---|
| `portada` | Portada | `_portada` |
| `indice` | Índice | `_indice` |
| `resumen_ejecutivo` | Resumen ejecutivo | `_resumen_ejecutivo` |
| `panorama` | Panorama y cifras | `_panorama` |
| `tecnologias` | Tecnologías más afectadas | `_exposicion` |
| `activos` | Exposición y activos afectados | `_activos` |
| `prioritarias` | Fichas de las amenazas prioritarias | `_prioritarias` |
| `remediacion` | Cola de remediación con la versión a la que actualizar | `_remediacion` (nuevo) |
| `anexo` | Anexo con el resto de hallazgos | `_anexo` |
| `conclusiones` | Conclusiones y recomendaciones | `_conclusiones` |
| `precision` | Precisión del filtro | `_precision_filtro` |
| `metodologia` | Metodología | `_metodologia` + `_metodologia_activos` |

Las referencias cruzadas se ajustan: si el informe no lleva el apartado de activos, el
resumen ejecutivo no dice «detalle en el apartado 4», dice «detalle en la página de
Activos de la interfaz». Lo mismo con el anexo y con las fichas.

El apartado **cola de remediación** es nuevo y **no forma parte del informe mensual**: una
fila por actualización pendiente (activo y origen de paquete) con la versión instalada, la
versión objetivo (la más alta que piden sus avisos, con el comparador de la distribución) y
cuántas vulnerabilidades cierra. Sale de `remediacion.pagina_actualizaciones`, el mismo
camino que pinta la página de Remediación, y el documento advierte que **la cola es la
situación de hoy, no la foto del periodo**: la versión que hay que instalar no depende del
mes en que se detectó el problema.

### 2.6 Vista previa

**Dónde está (corrección del 2026-09-10, tarde).** El usuario dijo: «No veo lo que pedí
del apartado de informes, de previsualizar la construcción de informes según lo que yo
vaya escogiendo». La vista previa existía y se actualizaba sola, pero el panel empezaba en
el **píxel 2.574** del documento (medido con el navegador a 1.440 px de ventana): quien
marcaba un apartado tenía el resultado a casi tres pantallas de distancia y no lo veía.

Desde hoy, en pantallas de **1.180 px o más** la pantalla es de dos columnas:

* a la izquierda, lo que se elige: «Cómo quiere empezar» y «Qué informe quiere»;
* a la derecha, **pegada al desplazamiento** (`position: sticky` bajo la barra superior),
  la «Vista previa y descarga», con las cifras, el esquema del documento y el botón de
  generar.

Por debajo de 1.180 px las dos columnas se apilan en el mismo orden de siempre (elegir
arriba, vista previa debajo). **El orden del HTML no cambia**: el formulario va primero y
la vista previa después, así que el recorrido con teclado y con lector de pantalla es el
de antes; la disposición es solo CSS (`.disposicion-informe`, `.columna-informe-formulario`
y `.columna-informe-resumen` en `estilo.css`).

Medido con el navegador sin cabeza contra la copia de la base real (7.121 amenazas,
1.168 vulnerabilidades en el periodo por omisión):

| Medida a 1.440 × 900 px | Antes | Después |
|---|---:|---:|
| Dónde empieza el panel «Vista previa y descarga» | píxel 2.574 | píxel **228** |
| Píxeles del panel dentro de la ventana al marcar el primer apartado | **0** | **740** |
| Alto total del documento | 5.185 px | 4.416 px |
| Apartados del esquema a la vista sin desplazarse dentro del panel | 0 | 9 de 10 |

A 1.280 × 800 px el panel también se pega: empieza en el píxel 228 (antes, 2.590), tiene
640 px dentro de la ventana al marcar (antes, 0) y se ven el título del esquema y sus tres
primeros apartados; el resto, con el desplazamiento propio del panel. A 390 px la pantalla
se apila igual que antes (el panel empieza en el píxel 5.008 frente a 4.953, y el
documento mide 9.877 px frente a 9.782: los 95 px de más son el encabezado nuevo «Detalle
de la selección» y la separación de los bloques).

Detalles de la columna pegada:

* el panel se limita a `100vh` menos la barra superior, y **lo que se desplaza es su
  contenido**, no la página: un esquema largo no empuja nada;
* el botón **«Generar y descargar en Word»** queda fuera de ese bloque, fijo al pie del
  panel y con sus 44 px de alto, así que nunca hay que buscarlo;
* las cuatro cifras pasan a filas compactas (número, etiqueta al lado y la nota completa
  debajo) porque en una columna de 433 px se leen mejor así que como cuatro tarjetas;
* en esa columna el esquema es la lista numerada a secas: la explicación de cada apartado
  está a la vista en el formulario de al lado, y sin repetirla la lista pasa de 983 px a
  262 px de alto. En una sola columna (móvil o pantalla estrecha) la explicación se lee;
* el esquema ya no pinta su propio número de lista: la numeración real del documento va en
  el texto y verlas las dos («1. 1. Resumen ejecutivo») se leía como un error;
* los avisos de recorte (fichas, anexo, cola, tiempo de generación) se leen ahora **junto
  al esquema**, que es de lo que hablan, y no delante de las cifras: así el esquema entra
  en la parte visible del panel;
* el detalle de la selección (título, periodo, alcance, severidades, destinatario y punto
  de partida) va después del esquema, con su propio encabezado «Detalle de la selección»:
  es la confirmación escrita de lo que ya dice el formulario, no lo que cambia al marcar;
* la rejilla de apartados del formulario reparte el espacio con `minmax(240px, 1fr)`: en la
  columna de la izquierda caben dos columnas de casillas (301 px a 1.440 px de ventana;
  con los 340 px de antes se habría quedado en una sola columna y una lista de doce).

Contraste y foco comprobados en los dos temas con el navegador: todo el texto del panel
pegado está por encima de 4,5:1 (lo más bajo, 4,82:1 en la cifra grande del tema claro,
que además es texto grande y solo necesita 3:1), los botones miden 44 px de alto y el foco
del teclado se ve con un contorno de 2 px en los dos temas, sin que el panel pegado tape
ningún control (todos los que se recorren con el tabulador quedan dentro de la ventana).

**Qué dice.** De arriba abajo: una línea de resumen (de qué plantilla se partió y cuántas
vulnerabilidades y cuántos apartados van), las cifras, el esquema del documento con su
numeración real, los avisos de recorte, el detalle de la selección, el enlace copiable y
el botón de generar. Antes de descargar se ven el título, el periodo, el alcance, las
severidades, los apartados y cuatro cifras: vulnerabilidades del periodo (con su reparto por severidad),
activos afectados sobre los activos presentes del alcance, cuántas tienen explotación
activa confirmada y —cuando se pide la cola— cuántas actualizaciones pendientes hay. Si la
selección no devuelve **nada** (ni vulnerabilidades ni actualizaciones), se dice y no se
ofrece el botón; el `POST` también lo rechaza con un mensaje.

### 2.7 Portada

Título, destinatario y una nota libre. Los tres se recortan (120, 120 y 600 caracteres) y
se limpian de caracteres de control. **Nunca entran en el nombre del fichero**, que se
compone solo con la clave de la plantilla y la fecha:
`informe_<plantilla>_<periodo>.docx`.

## 3. Plantillas preconfiguradas

Están en código, en `threatintel/informe_seleccion.py` (`PLANTILLAS`), con nombre,
descripción, para quién es, apartados y filtros. Al elegir una se rellena el formulario y
se puede cambiar todo antes de generar.

| Clave | Nombre | Apartados | Periodo | Alcance |
|---|---|---|---|---|
| `mensual` | Informe mensual completo | los once de siempre | un mes | toda la organización |
| `direccion` | Resumen para dirección | portada, resumen ejecutivo, panorama, conclusiones | un mes | toda la organización |
| `remediacion` | Informe técnico de remediación | portada, índice, activos, cola de remediación, conclusiones | un mes | toda la organización |
| `proceso` | Informe por proceso de negocio | portada, resumen ejecutivo, panorama, activos, cola, conclusiones | un mes | un proceso (se pide) |
| `kev` | Vulnerabilidades con explotación activa | portada, resumen ejecutivo, activos, fichas, cola, conclusiones | el año en curso | solo KEV |
| `activo` | Informe de un activo | portada, resumen ejecutivo, activos, fichas, cola, conclusiones | el año en curso | un activo (se pide) |

La plantilla `mensual` es **idéntica** al informe de siempre: cuando la selección es esa
(mes completo, toda la organización, las tres severidades, los once apartados y sin título,
destinatario ni nota propios), `Seleccion.es_mensual_clasico()` devuelve `True` y la vista
llama a `report.generar_en_memoria(conn, mes, cfg=…)` **sin argumentos nuevos**: el mismo
camino de código que la ejecución mensual programada. Se audita como `informe.generado` con
el mes, para que la tabla de meses lo refleje.

## 4. Rendimiento medido (2026-09-10, copia de la base real)

Base real: 7.121 amenazas, 717 activos presentes, 179.429 filas de aplicabilidad, 48.216
remediaciones abiertas. Copia hecha con la API `backup` de sqlite3 y borrada al terminar.

| Plantilla | Pantalla (vista previa) | Generar el documento | Tamaño |
|---|---|---|---|
| Informe mensual completo (agosto) | 203 ms | **16,2 s** | 66,2 KB |
| Resumen para dirección (agosto) | 206 ms | 0,5 s | 39,6 KB |
| Informe técnico de remediación (agosto) | 415 ms | 1,2 s | 42,5 KB |
| Informe por proceso (Apizco, agosto) | 454 ms | 0,8 s | 40,3 KB |
| Vulnerabilidades con explotación activa (año) | 390 ms | 3,4 s | 58,8 KB |
| Informe de un activo (año) | 238 ms | 5,0 s | 43,1 KB |
| Tecnología (Google Chrome, agosto) | 208 ms | 0,4 s | 40 KB |

La página completa tarda 270 ms en cargar (51,6 KB de HTML). Todos los recuentos de la
vista previa están por debajo de 110 ms.

Márgenes y topes:

* nginx corta la respuesta a los 120 segundos (`proxy_read_timeout`): el peor caso medido
  es 16 segundos, con margen de sobra;
* `report_max_detail_items` (120) limita las fichas y `report_max_anexo_items` (250) el
  anexo; la cola de remediación se limita al doble de las fichas (240 filas);
* la pantalla **avisa antes** de que se pulse el botón cuando la selección va a recortarse
  o cuando la generación puede tardar (a partir de `UMBRAL_AVISO_LENTO`, 700
  vulnerabilidades con algún apartado pesado), con el texto «No cierre la página: la
  descarga empieza sola cuando el documento está listo»;
* la interfaz **no usa el modelo de lenguaje** para redactar (`_cfg_para_interfaz`): medido
  el 2026-09-08, con Ollama la redacción tardaba 200 segundos y la descarga no llegaba
  nunca. El informe que llega por correo el último día del mes sí lleva la redacción del
  modelo cuando está disponible; las cifras son las mismas.

## 5. Seguridad

* **Permiso**: `requiere_informes` (administrador y operador SOC, `auth.ROLES_INFORMES`).
  Cualquier otro perfil recibe 403 sin que se le diga qué perfil haría falta.
* **CSRF** en los dos `POST`; `GET` solo lee.
* **Auditoría**: `informe.medida` (con la plantilla en `entity_id` y el periodo, el alcance,
  las severidades y los apartados en el detalle) o `informe.generado` (con el mes) cuando la
  selección es el informe mensual clásico.
* **Validación**: todo por listas blancas; los números se acotan; los textos se recortan y
  se limpian; el SQL va siempre parametrizado (`Seleccion.where()` devuelve tantos `?` como
  parámetros); ningún texto de la persona entra en una consulta ni en un nombre de fichero.
* **Sin ficheros en el servidor**: el documento se construye en memoria y viaja en la
  respuesta. No queda copia en `reports/` ni en `data/`.
* **Alcance del perfil**: 404 al pedir otro tipo de máquina o un activo ajeno, y las fichas
  no nombran máquinas de fuera del alcance.
* **Enlace absoluto sin inyección de Host**: el enlace copiable es la primera dirección
  absoluta que genera la interfaz. Es seguro porque nginx solo acepta dos cabeceras `Host`
  conocidas (el resto se corta con 444) y la aplicación no confía en `X-Forwarded-Host`
  (`ProxyFix(x_host=0)`, revisión adversaria del 2026-09-08).
* **CSP estricta**: sin `style=`, sin `on*=`, sin scripts en línea. El único comportamiento
  es `data-autosubmit` (enviar el formulario al cambiar el periodo o el alcance, con su
  aviso escrito al lado del control, WCAG 3.2.2) y `data-copiar` (copiar el enlace), los dos
  ya existentes en `app.js`.

## 6. Ficheros

| Fichero | Qué es |
|---|---|
| `threatintel/informe_seleccion.py` | **Nuevo.** La selección (periodo, alcance, severidades, apartados), las plantillas, las consultas acotadas y la vista previa. Sin Word y sin Flask. |
| `threatintel/report.py` | `construir_documento` y `generar_en_memoria` aceptan `secciones` y `filtros`; cada apartado recibe su número (histórico por omisión); nuevos `_remediacion`, `cola_remediacion`, `resumen_a_medida`, `_adjuntar_activos_del_alcance`. |
| `webui/vistas/informes.py` | Rutas del generador: `GET /informes/`, `POST /informes/generar`; la descarga mensual sigue igual. |
| `webui/templates/informes.html` | Plantillas, formulario, vista previa, enlace copiable y la tabla de meses. Seis pasos de recorrido guiado. Desde la tarde del 2026-09-10, las dos columnas (`.disposicion-informe`). |
| `webui/templates/_informe_campos.html` | Campos del formulario (zona viva `campos-informe`). |
| `webui/templates/_informe_vista_previa.html` | La vista previa (zona viva `vista-previa-informe`): resumen, cifras, esquema, avisos, detalle, enlace y, al pie y fuera del bloque que se desplaza, el botón de generar. |
| `webui/templates/_informe_fragmento.html` | Respuesta de `/informes/vista-previa`: los dos parciales, sin armazón. |
| `webui/static/estilo.css` | Añadido al final: tarjetas de plantilla, rejilla de apartados, acciones del formulario y campo del enlace. |
| `tests/test_informes_medida.py` | 45 pruebas. |
| `tests/test_informes_vista_previa_pegada.py` | **Nuevo (2026-09-10, tarde).** 22 pruebas: disposición en dos columnas, botón fuera del bloque que se desplaza, esquema con su numeración real y su reordenación, cero apartados, vista previa viva en los siete modos y guardián de la medida de lectura. |
| `docs/INFORMES_A_MEDIDA_2026-09-10.md` | Este documento. |

## 7. Lo que falta (para cuando el usuario quiera plantillas guardadas)

Esquema propuesto, para hacerlo con la habilidad `cambio-de-esquema`:

```sql
CREATE TABLE IF NOT EXISTS informe_plantillas (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre      TEXT NOT NULL,
  descripcion TEXT,
  parametros  TEXT NOT NULL,   -- la dirección web de la selección, tal cual
  username    TEXT NOT NULL,   -- quién la guardó
  compartida  INTEGER NOT NULL DEFAULT 0,
  creado_at   TEXT NOT NULL,
  usado_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_informe_plantillas_user ON informe_plantillas(username);
```

Con eso, `Seleccion.desde_parametros` y `Seleccion.a_parametros` siguen valiendo sin
cambios: lo que se guarda es exactamente lo que hoy viaja en el enlace. Haría falta un
`POST /informes/plantillas` (crear, con CSRF y auditoría) y un `POST
/informes/plantillas/<id>/borrar`, y una fila más en la pantalla de plantillas.

Otras ideas que quedan fuera de este cambio:

* **Otro formato** (PDF o CSV). No se ha añadido: el PDF exigiría una dependencia nueva
  (LibreOffice en el servidor o una biblioteca) y el CSV ya existe en Amenazas y en
  Remediación. Si se pide, el sitio natural es un selector «Formato» en el formulario.
* **Envío por correo del informe a medida.** Hoy solo la ejecución mensual programada
  envía correo. Se puede añadir con `notify` y la lista de destinatarios del dominio de la
  empresa, con confirmación previa.
* **Recuento exacto de «ya corregidos» y «sin dato» por activo en las fichas de un informe
  acotado**: hoy se omiten (se ponen a cero) porque los recuentos guardados son de todo el
  parque; recalcularlos por alcance exige otra evaluación.
