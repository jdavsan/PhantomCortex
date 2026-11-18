# Informe ejecutivo en blanco y negro y ficheros de activos que no reportan — 2026-09-15

Dos encargos del usuario, resueltos el mismo día:

1. **«solo se debe ajustar el color donde todo debe ser a blanco y negro»** — el informe
   ejecutivo mensual, entero en blanco y negro, sin perder nada de lo que decía el color.
2. **«necesito además un informe para equipos y para servidores que me indique cuántos
   servidores o equipos han dejado de reportar y me los envíe en archivos diferentes, uno
   de equipos y otro de servidores, de manera detallada de proceso, hostname, IP y demás»**
   — dos hojas de cálculo adjuntas al correo de inventario.

---

## 1. El informe ejecutivo, en blanco y negro

### 1.1 Qué cambia y qué no

* Cambia **solo el informe ejecutivo mensual** (`report.construir_documento_ejecutivo` y
  sus apartados `_ej_*`).
* El **informe mensual completo no cambia ni una coma**: sigue en color, con su estilo de
  tabla «Light Grid Accent 1» y sus títulos azules. Lo comprueban dos pruebas:
  `tests/test_informes_medida.py` (párrafo a párrafo, como siempre) y
  `tests/test_informe_ejecutivo_bn.py::test_el_informe_mensual_completo_sigue_en_color`.
* Ninguna función compartida se ha teñido de negro. Donde había una función común se ha
  **parametrizado por composición**: `_preparar_documento_ejecutivo()` llama a
  `_preparar_documento()` (la del informe completo, intacta) y después pone los estilos en
  tinta negra solo en **su** documento; `_sombrear` se usa tal cual, con un gris.

### 1.2 Qué significaba cada color y con qué se ha sustituido

| Apartado | Qué había en color | Qué significaba | Con qué se ha sustituido |
|---|---|---|---|
| Portada | Título «INFORME EJECUTIVO DE CIBERSEGURIDAD» en azul corporativo (`1F4E78`) | Marca y jerarquía: «esto es lo primero» | Negro puro, 26 pt y negrita. La jerarquía la marcan el cuerpo de letra y la negrita |
| Portada | «Mi Organización S.A.» en azul claro (`4472C4`) | Firma de la empresa, distinta del título | Negro, negrita y **versalitas** |
| Portada | «MES: SEPTIEMBRE DE 2026» en `1F2933` (gris azulado: es un color) | Dato principal de la portada | Negro puro (`000000`) |
| Portada | Nota de cierre en gris cursiva, sin rótulo | «esto es secundario» | Gris neutro `595959` + cursiva + **rótulo en negrita** «Cómo leer este informe.», y una frase nueva que avisa de que el documento va en blanco y negro y de que ninguna cifra depende del color |
| Portada, tabla «La situación en cuatro cifras» | Columna «Respecto al mes anterior» en texto plano dentro de una tabla de bordes azules | La palabra ya estaba, pero se leía apoyada en el color del borde y del estilo | La palabra **en versalitas y negrita**: «EMPEORÓ: 4.583 más (41,1 %)» |
| Todas las tablas (6) | Estilo «Light Grid Accent 1»: bordes en azul de acento y cabecera distinguida **solo por el color** | «esta fila es la cabecera» | Estilo «Table Grid» (rejilla negra) + cabecera en **negrita** sobre **sombreado gris muy claro** (`D9D9D9`, contraste 12,6:1) + repetición de cabecera en cada página |
| Apartados 1 a 5 | Títulos de apartado en azul (`365F91`, estilo «Heading 1» de la plantilla de Word, con `themeColor="accent1"`) | Jerarquía de apartado | Estilo «Heading 1» en negro y negrita, en **este** documento |
| Apartado 2, tabla de comparación | Última columna, «Mejoró/Empeoró», en texto normal dentro de la tabla azul | Si la cifra va bien o mal | **Versalitas y negrita**, y un párrafo nuevo que lo dice: «al lado de cada variación se dice con todas sus letras, en versalitas, si MEJORÓ, EMPEORÓ o SE MANTIENE según el criterio de riesgo» |
| Apartado 3, tabla de avance | Columna «Saldo del mes» en texto normal | Si la deuda sube o baja | **Versalitas y negrita**: «LA DEUDA SUBE EN 33.617» |
| Apartado 3, barras | Barra de bloques (`█`/`░`) precedida de «D» y «R», con una leyenda de una línea en gris claro | Qué serie es cada barra | Leyenda completa con rótulo en negrita: «**Leyenda de las barras.** las dos barras de la última columna **no llevan color**: la de arriba, marcada con «D», son las vulnerabilidades DETECTADAS y la de abajo, marcada con «R», las REMEDIADAS. Cada barra se dibuja con bloques llenos (█) sobre una escala de huecos (░) del mismo largo para todos los meses… Las cifras exactas están en las columnas «Detectadas» y «Remediadas» de esa misma fila.» |
| Apartado 4 | Nota en gris | «esto es contexto» | Gris neutro + frase nueva que dice que la tabla está ordenada de más a menos trabajo pendiente |
| Apartado 5 | «Qué cambia si se hace: …» en gris, sin rótulo | Separaba la decisión de su efecto por el color del párrafo | **Rótulo en negrita** «Qué cambia si se hace:» y el texto en gris neutro |
| Pie de página | Gris `7F7F7F` | Texto de pie | Gris neutro `595959` (más contraste al imprimir) |

Ningún dato se ha perdido: lo que antes solo se veía (azul = marca, borde azul = tabla,
gris = secundario) ahora se lee.

### 1.3 Los recursos que sí funcionan en blanco y negro

Negro puro para el texto principal, gris neutro `595959` para las notas (contraste 7,0:1
sobre blanco), **negrita**, **versalitas**, rejilla de bordes negros, sombreado gris muy
claro `D9D9D9` para las cabeceras de tabla y rótulos en negrita al principio de cada nota.
Ningún gris se usa para distinguir dos cosas entre sí: el gris solo separa «principal» de
«secundario», y siempre acompañado de cursiva o de rótulo.

### 1.4 La red de seguridad: `_a_blanco_y_negro`

El último paso de `construir_documento_ejecutivo` recorre **todas las partes del paquete
`.docx`** y neutraliza cualquier color que quede, propio o heredado de la plantilla de Word:

* `w:val` de `<w:color>` (texto), `w:fill` de `<w:shd>` (sombreados) y `w:color` de los
  bordes se convierten al **gris de la misma luminosidad** (`_a_gris`: `B3261E` → `4F4F4F`);
* se borran los atributos de tema (`w:themeColor`, `w:themeFill`, `w:themeTint`…), porque
  un `themeColor="accent1"` pinta azul aunque el valor literal diga gris;
* se anula el resaltado (`<w:highlight>`);
* las partes que python-docx no expone como árbol (`word/theme/theme1.xml`,
  `word/stylesWithEffects.xml`) se tratan por texto con el mismo criterio;
* se quita la relación de la **miniatura de vista previa** (`docProps/thumbnail.jpeg`), la
  única pieza en color de la plantilla que no es XML y que no se puede pasar a gris sin un
  codificador de imagen (el proyecto no instala ninguno). No se pierde nada: es el icono de
  vista previa del fichero, no contenido del informe.

Así, aunque mañana alguien añada al ejecutivo un párrafo en rojo, el documento saldrá en
blanco y negro igual.

### 1.5 La comprobación, con los datos reales

Copia de la base de producción hecha con la API `backup` de sqlite3, bajo `data/`, borrada
al terminar. **No se ha enviado ningún correo.**

| Medida | Antes | Ahora |
|---|---:|---:|
| Elementos con color en el paquete `.docx` (`w:color`, `w:fill`, bordes, tema, `themeColor`) | **1.998** | **0** |
| — de ellos, en `word/document.xml` | 3 | 0 |
| — en `word/styles.xml` (incluye «Heading 1» y «Light Grid Accent 1», que sí se aplicaban) | 1.985 | 0 |
| — en `word/theme/theme1.xml` | 10 | 0 |
| Piezas del paquete que no son XML (la miniatura en color) | 1 | **0** |
| Píxeles con color al convertir a PDF y rasterizar (5 páginas a 80 puntos por pulgada, 2.992.000 píxeles) | 410.594 (13,7 %) | **0** |
| Tamaño del `.docx` de septiembre de 2026 | 40,6 KB | 35,9 KB |
| Tiempo de generación | 1,10 s | 1,14 s |
| Páginas reales (PDF con LibreOffice) | 4 | **5** (el tope sigue siendo 10) |

La cifra «antes» de píxeles se obtuvo reconstruyendo el documento anterior (estilos de la
plantilla y tabla «Light Grid Accent 1»); las cifras de color del XML se midieron sobre el
documento original, antes de tocar el código.

El documento pasa de 4 a 5 páginas porque la leyenda de las barras y los rótulos de las
notas ocupan sitio. Sigue muy por debajo del tope de diez páginas que fija
`tests/test_informe_ejecutivo.py`.

---

## 2. Dos ficheros de activos que han dejado de reportar

### 2.1 Formato elegido y por qué

**Hoja de cálculo `.xlsx`** (openpyxl), un fichero por tipo de máquina:

* Servicios Tecnológicos **filtra, ordena y reparte** esta lista: el `.xlsx` llega con el
  autofiltro puesto, la cabecera inmovilizada y los anchos de columna listos.
* Conserva el **tipo** de cada dato: las fechas se ordenan como fechas y los días como
  números. En un CSV todo es texto, y Excel además destroza las tildes si no acierta con la
  codificación.
* Un PDF no se puede filtrar ni repartir por áreas.
* Se reutiliza el estilo, los anchos y —sobre todo— el **escapado de fórmulas** de
  `threatintel/libro_alerta.py`: toda celda pasa por `_celda`, que fuerza a texto lo que
  empieza por `=`, `+`, `-` o `@`. Los nombres de máquina vienen de OCS Inventory, es decir,
  de fuera: sin ese filtro, un nombre como `=cmd|' /c calc'!A0` sería una fórmula real (y
  una petición DDE) en el libro que abre el técnico. Hay una prueba que lo comprueba.

### 2.2 Los ficheros

`Servidores_sin_reportar_2026-09-15.xlsx` y
`Equipos_de_computo_sin_reportar_2026-09-15.xlsx`: se entienden al verlos en el escritorio y
llevan la fecha. El nombre va sin tildes a propósito (viaja como adjunto y acaba en
escritorios Windows); **el contenido sí lleva tildes**, que es lo que se lee.

Cada fichero tiene dos hojas:

1. **«Resumen»** — cuántos han dejado de reportar de cuántos y su porcentaje, desde cuándo
   se considera que no reportan (ajuste `ocs_stale_days`), cuántos no han reportado nunca,
   cuántos días lleva el más antiguo, cuántas vulnerabilidades confirmadas arrastran (y
   cuántas con explotación activa confirmada), el total del parque, **qué hay que hacer**
   en cuatro puntos, cómo está ordenada la hoja de detalle, qué significa «días sin
   reportar» y el enlace a la lista en la plataforma.
2. **«Servidores sin reportar» / «Equipos de cómputo sin reportar»** — una fila por máquina
   y una **fila de totales** al final, separada por una fila en blanco para que no se la
   lleve por delante quien ordene la tabla.

### 2.3 Columnas

| # | Columna | Por qué está |
|---|---|---|
| 1 | Nombre del activo | Pedida («hostname») |
| 2 | Dirección IP | Pedida |
| 3 | Proceso de negocio | Pedida; es quien tiene que atenderlo |
| 4 | Entorno | Pedida (producción, contingencia, desarrollo, pruebas, soporte) |
| 5 | Sistema operativo | Pedida |
| 6 | Versión del sistema operativo | Pedida |
| 7 | Zona de red | Pedida (Internet, perimetral, interna) |
| 8 | Usuario o responsable | Pedida, «si consta» |
| 9 | Días sin reportar | Pedida. Desde el último inventario; si nunca reportó, desde que la plataforma lo vio por primera vez (y la columna 10 lo dice) |
| 10 | Fecha del último inventario | Pedida. «Nunca ha reportado» cuando no hay ninguna |
| 11 | Fecha en que se vio por última vez | Pedida (la última sincronización en la que OCS Inventory lo listaba) |
| 12 | Última conexión registrada | **Añadida**: distingue la máquina apagada de la que está encendida con el agente parado |
| 13 | Vulnerabilidades confirmadas | Pedida («si tiene vulnerabilidades confirmadas cuántas son») |
| 14 | De ellas, con explotación activa confirmada | **Añadida**: no es lo mismo estar a oscuras con riesgo conocido que con riesgo conocido y explotado |
| 15 | Grupo en OCS Inventory | **Añadida**: por dónde repartir el trabajo |
| 16 | Identificador en OCS Inventory | **Añadida**: para dar de baja la máquina en OCS sin buscarla por nombre |
| 17 | Qué conviene revisar primero | **Añadida**: una frase por fila, distinta según nunca haya reportado, lleve N días o arrastre vulnerabilidades |

Las vulnerabilidades se cuentan con **el mismo criterio que la página de Activos**: pares
(activo, CVE) distintos con veredicto «afectado», sin las amenazas descartadas, falsos
positivos ni mitigadas, **sin la severidad baja** y sin el riesgo aceptado con excepción
vigente. Un mismo CVE en cuatro paquetes es **una** vulnerabilidad.

### 2.4 Orden, totales y grupos vacíos

* **Orden**: primero las que nunca han reportado; después, de más a menos días sin
  reportar y, a igualdad de días, de más a menos vulnerabilidades confirmadas (y, dentro,
  las de explotación activa).
* **Fila de totales**: cuántas máquinas son, el **máximo** de días sin reportar y la
  **suma** de las dos columnas de vulnerabilidades, con una nota al lado que dice
  exactamente eso, para que nadie lea el máximo como una suma.
* **Grupo vacío**: no se genera su fichero, y el correo escribe «No se adjunta el fichero
  de equipos de cómputo: los N equipos de cómputo del inventario han reportado dentro del
  plazo».

### 2.5 El correo de inventario

`bin/informe_inventario.py` genera los dos ficheros y los adjunta. El cuerpo, además del
recuento general que ya tenía, escribe ahora **las dos cifras**:

> **32 servidores** de 391 (8,2 %) llevan más de 30 días sin enviar su inventario.
> **44 equipos de cómputo** de 339 (13,0 %) llevan más de 30 días sin enviar su inventario.
> La lista completa, con su ficha y su historial, está en la plataforma: …/activos/?vista=sin_reportar

Y un bloque **«Ficheros adjuntos (2)»** que dice, de cada uno, cuántas filas lleva, de
cuántas máquinas, qué columnas trae y cómo está ordenado. El correo se entiende sin abrir
los adjuntos.

### 2.6 A demanda, desde la línea de órdenes

```
bin/informe_inventario.py --ficheros                     # los dos ficheros, sin enviar nada
bin/informe_inventario.py --ficheros --en /ruta/carpeta  # en la carpeta que se indique
bin/informe_inventario.py --dry-run                      # HTML del correo + los dos ficheros
```

`--ficheros` termina antes de componer el correo: no envía nada y no consulta destinatarios.
Por omisión deja los ficheros en `data/revision/inventario/`. En el envío real van a
`data/informes/` con permisos `0600` y el directorio a `0700`, igual que la hoja de la
alerta diaria: llevan el mapa de las máquinas a oscuras con sus direcciones.

### 2.7 Medido con los datos reales

Copia de la base de producción, 15 de septiembre de 2026, umbral `ocs_stale_days` = 30 días:

| | Sin reportar | Del total | Nunca han reportado | Día más antiguo | Vulnerabilidades confirmadas | Con explotación activa | Fichero |
|---|---:|---:|---:|---:|---:|---:|---:|
| Servidores | **32** | 391 (8,2 %) | 0 | 565 días | 1.483 | 8 | 12,1 KB |
| Equipos de cómputo | **44** | 339 (13,0 %) | 0 | 1.131 días | 1.598 | 4 | 12,7 KB |
| **Total** | **76** | 730 (10,4 %) | 0 | 1.131 días | 3.081 | 12 | 24,8 KB |

* Consulta de los datos (dos consultas por conjuntos sobre 730 activos presentes y 178.007
  filas de `aplicabilidad`): **0,34 s**.
* Escritura de los dos ficheros: **0,08 s**.
* Cuerpo del correo con los dos bloques nuevos: 88.343 caracteres (sube unos 2 KB).

---

## 3. Ficheros

| Fichero | Qué cambia |
|---|---|
| `threatintel/report.py` | **Nuevo:** `TINTA`, `TINTA_SUAVE`, `SOMBREADO_CABECERA`, `ESTILO_TABLA_EJECUTIVA`, `_a_gris`, `_blanco_y_negro_en_xml`, `_blanco_y_negro_en_texto`, `_a_blanco_y_negro`, `_preparar_documento_ejecutivo`. `_tabla_ejecutiva`, `_fila_ejecutiva` (parámetros `versalitas` y `sombreado`), `_parrafo_ejecutivo` (parámetro `rotulo`), `_pie_ejecutivo` y los cinco apartados `_ej_*` pasan a blanco y negro. **El informe mensual completo no se toca** |
| `threatintel/ocs.py` | **Nuevo:** `inventario_sin_reportar_detallado` y `_dias_desde`. `inventario_sin_reportar` no cambia |
| `threatintel/libro_inventario.py` | **Nuevo.** Las dos hojas de cálculo: columnas, resumen, totales, nombres de fichero y permisos |
| `threatintel/notify.py` | `render_inventario_email` admite `adjuntos` |
| `threatintel/emails/inventario.html` | Las dos cifras escritas y el bloque «Ficheros adjuntos» |
| `bin/informe_inventario.py` | Genera y adjunta los dos ficheros, modo `--ficheros`, opción `--en`, cifras del terminal en formato español |
| `tests/test_informe_ejecutivo_bn.py` | **Nuevo.** 24 pruebas |
| `tests/test_inventario_ficheros.py` | **Nuevo.** 28 pruebas |
| `docs/EJECUTIVO_BLANCO_Y_NEGRO_E_INVENTARIO_2026-09-15.md` | Este documento |

---

## 4. Lo que queda pendiente

* **Un ajuste para desactivar los adjuntos del correo de inventario**, al estilo de
  `alert_adjuntar_excel`. Hoy los dos ficheros van siempre que haya máquinas sin reportar
  (pesan 25 KB entre los dos, así que no urge). Si se quiere, en `threatintel/config.py`:
  `"inventario_adjuntar_ficheros": True,` y en `webui/vistas/ajustes.py`, junto a
  «Enviar el informe de inventario», su casilla; después, en `bin/informe_inventario.py`,
  envolver la llamada a `libro_inventario.generar` en ese ajuste.
* **Limpieza de `data/informes/`**: los ficheros del envío real se acumulan un fichero por
  día y tipo (unos 25 KB al día). Conviene una tarea de borrado a los N días, igual que
  para las hojas de la alerta diaria, que tampoco la tienen hoy.
* **Comparación entre años del ejecutivo**: sigue pendiente de que el histórico llegue a
  doce meses (documento del 2026-09-15 sobre el informe ejecutivo, apartado 4).
* **El ajuste `alert_tabla_top`** sigue sin aparecer en Administración → Ajustes; las tres
  líneas siguen siendo las del documento
  `docs/CORREO_TOP10_E_INFORME_EJECUTIVO_2026-09-15.md`, apartado 1.6.
