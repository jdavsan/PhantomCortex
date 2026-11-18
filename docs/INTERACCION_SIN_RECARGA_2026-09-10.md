# Interacción sin recarga: contrato del motor de actualización parcial

**Fecha:** 2026-09-10 · **Ámbito:** `webui/static/app.js`, `webui/templates/*.html`

> Petición del usuario: «Ajusta que el uso de funcionalidades se utilice sin que la
> página se recargue porque eso es muy molesto».

Desde hoy, filtrar, ordenar, paginar, cambiar de pestaña y **ejecutar acciones de
escritura** (cambiar el estado de una amenaza, guardar una nota, registrar o revocar una
excepción, cambiar el perfil de una persona, guardar un ajuste, comprobar una
remediación…) actualizan **solo el trozo de página afectado**. La pantalla no parpadea, no
se pierde la posición de desplazamiento y el mensaje de resultado aparece en su sitio.

Todo funciona **por mejora progresiva**: sin JavaScript la plataforma se comporta
exactamente como antes (formularios y enlaces normales, con recarga completa). No hay
ninguna interfaz de datos nueva: se pide **la misma dirección de siempre**, el servidor
devuelve **el mismo HTML de siempre** y el navegador se queda con el trozo que cambia.

---

## 1. Cómo funciona, en una frase

`app.js` intercepta el envío de un formulario o la pulsación de un enlace, pide esa misma
dirección con `fetch`, busca en la respuesta el elemento con el identificador de la zona,
sustituye su contenido, copia el contenedor de mensajes y actualiza la dirección del
navegador. Si algo no cuadra, se aparta y deja que el navegador haga lo de siempre.

---

## 2. Contrato de atributos

Para sumar una página nueva **no hay que tocar el JavaScript**: basta con marcarla.

### 2.1 Zonas vivas

```html
<div id="resultados" data-zona-viva data-zona-nombre="Resultados" tabindex="-1">
```

| Atributo | Dónde | Para qué |
|---|---|---|
| `data-zona-viva` | en el elemento que se puede sustituir | lo declara zona viva. **Obliga** a que el elemento tenga `id` único en la página |
| `data-zona-nombre="…"` | en la zona | nombre en español que se anuncia («Resultados: actualizado») |
| `data-zona-foco` | en un elemento **dentro** de la zona | dónde va el foco al terminar, si el que lo tenía desapareció |
| `data-zona-resumen` | en un elemento **dentro** de la zona | su texto es lo que se anuncia en vez del nombre. Lo lleva el recuento de `_paginacion.html` («1.402 entradas · página 2 de 71 · filas 21 a 40») |

Reglas:

* el identificador tiene que ser **el mismo** en la respuesta del servidor (es lo que se
  busca en el HTML devuelto);
* `tabindex="-1"` en la zona permite devolverle el foco a quien navega con teclado sin
  saltar al principio del documento (si no lo lleva, el motor se lo pone al vuelo);
* la zona tiene que contener **todo lo que depende de lo que cambia**: el listado, su
  recuento, sus atajos, su exportación y **su paginación**. Si algo de eso queda fuera, se
  quedará con los datos anteriores.

### 2.2 Filtros, orden y búsquedas (GET)

```html
<form method="get" action="/amenazas/" class="filtros"
      data-filtro-vivo="resultados"
      data-filtro-vivo-retardo="300"
      data-vivo-fragmento="/informes/vista-previa">
```

| Atributo | Para qué |
|---|---|
| `data-filtro-vivo="zona1 zona2"` | zonas que actualiza este formulario (una o varias, separadas por espacios) |
| `data-filtro-vivo-retardo="300"` | milisegundos de gracia al escribir en un campo de texto (220 por omisión) |
| `data-vivo-fragmento="/ruta"` | dirección alternativa que devuelve **solo los trozos**, con los mismos parámetros. La dirección que se escribe en la barra sigue siendo la del `action` |
| `data-vivo-zonas="zona1 zona2"` | **en un control**: ese control actualiza esas zonas en vez de las del formulario (por ejemplo un selector que cambia la forma del propio formulario) |
| `data-sin-vivo` | **en un control**: ese control no dispara nada |

Comportamiento: al escribir en un campo de texto se espera el retardo de gracia; al
cambiar un selector o una casilla se pide al momento; al enviar el formulario (tecla Intro
o botón) se pide sin esperar. **El botón «Filtrar» se oculta cuando el motor está activo**
y sigue visible sin JavaScript, que es la única forma de filtrar entonces.

### 2.3 Enlaces (paginación, orden, vistas rápidas, pestañas)

* Todo `<a>` **dentro de una zona viva** que apunte a **la misma dirección de página** con
  otros parámetros se intercepta y actualiza esa zona. Un enlace a otra página (la ficha de
  una amenaza) es una navegación de verdad y se deja al navegador.
* `data-enlace-vivo="zona1 zona2"` marca un enlace explícitamente, esté donde esté, y
  puede actualizar varias zonas.
* `data-sin-vivo` lo excluye siempre.
* Nunca se interceptan: descargas (`.csv`, `.docx`, `.json`, `.pdf`…), enlaces con
  `download` o `target`, otro origen, `mailto:`, ni las pulsaciones con Ctrl, Mayúsculas,
  Alt o botón central.

En `_paginacion.html` basta con pasar el parámetro `zona`:

```jinja
{{ paginacion('panel.auditoria', request.args.to_dict(flat=false), pagina, paginas,
              total, por_pagina, singular='entrada', plural='entradas',
              ancla='registro-auditoria', zona='registro-auditoria') }}
```

Solo se pasa `zona` cuando la paginación está **dentro** del elemento con ese
identificador; si estuviera fuera, se quedarían a la vista los controles de la página
anterior.

### 2.4 Acciones de escritura (POST)

```html
<form method="post" action="{{ url_for('usuarios.editar', usuario_id=u.id) }}"
      data-accion-viva="pagina-usuarios"
      data-accion-espera="Guardando…"
      data-accion-tiempo="120000">
  <input type="hidden" name="csrf" value="{{ csrf }}">
```

| Atributo | Para qué |
|---|---|
| `data-accion-viva="zona1 zona2"` | zonas que se actualizan con el resultado. **Vacío** = la zona que contiene el formulario |
| `data-accion-espera="Guardando…"` | texto del botón mientras la acción está en vuelo (queda deshabilitado) |
| `data-accion-tiempo="120000"` | tiempo de espera propio, en milisegundos, para las acciones que consultan la red (probar una fuente, verificar el correo, comprobar una remediación). Tope: 120 000, que es lo que aguanta nginx |

**El modelo de seguridad no cambia**: mismo método POST, mismo campo `csrf`, misma
dirección, mismos decoradores y misma auditoría en el servidor. El motor solo evita la
recarga: envía el formulario tal cual, sigue la redirección del servidor y extrae del
documento resultante la zona y el mensaje.

### 2.5 Mensajes de resultado

`base.html` trae siempre:

```html
<div id="mensajes-plataforma" role="status" aria-live="polite" aria-atomic="true">
```

* Está **vacío** cuando no hay nada que decir, así que no reserva espacio ni desplaza el
  contenido.
* El motor copia ahí el contenedor equivalente de la respuesta: ningún mensaje del
  servidor (los *flash* de Flask) se pierde por haberse consumido en una petición que no
  recargaba la página.
* Al ser una región viva educada (`polite`), un lector de pantalla anuncia el resultado
  **sin mover el foco**.
* Un error se trata igual que hoy: sale con su clase `aviso error`, nunca en silencio.

---

## 3. Qué hace el motor con el foco, el historial y los fallos

**Foco.** Mientras carga, la zona lleva `aria-busy="true"`. Al terminar: si quien tenía el
foco sigue en el documento (el campo en el que se escribe), **no se le toca**; si
desapareció, se busca un elemento con su mismo identificador (y se restaura la posición
del cursor); si tampoco, se enfoca `[data-zona-foco]` o la propia zona, siempre con
`preventScroll` para no dar saltos. No hay animaciones: se respeta
`prefers-reduced-motion` porque no se anima nada.

**Historial.** Los cambios de contenido usan `pushState`, así que **el botón de atrás
deshace** el filtro o la página. Escribir en un filtro no crea una entrada por pulsación:
el primer cambio de cada control empuja una entrada y los siguientes la reemplazan. Al
volver atrás (`popstate`) se repone la zona **sin recargar** y se vuelven a poner los
valores de los formularios de filtro. Las **acciones de escritura no ensucian el
historial**: solo ponen al día la dirección, y únicamente si el servidor redirigió
(patrón enviar-redirigir-mostrar); si el servidor responde en el sitio, la dirección
visible no cambia (si no, recargar daría un 405). Si la redirección lleva a **otra**
página, el motor navega de verdad: eso ya no es actualizar un trozo.

**Fallos.** Las respuestas que llegan fuera de orden se descartan con un contador. Hay
tiempo de espera (20 s en lectura, 45 s en escritura, hasta 120 s con
`data-accion-tiempo`). No se admite un segundo envío del mismo formulario mientras hay uno
en vuelo. Si en una **lectura** algo no cuadra (la respuesta no es HTML, la zona no viene,
la red falla), se cae a la navegación normal en vez de dejar la pantalla a medias. En una
**escritura no se reintenta nunca sola**: la acción puede haberse aplicado ya, así que se
avisa en español y decide la persona.

**Recorrido guiado y confirmaciones.** Todo va por **delegación de eventos en
`document`**: al sustituir una zona no hay que volver a enganchar nada. Las
confirmaciones en la página (`data-confirm`, `data-confirmar`), los plegables
(`data-toggle`), «Copiar» (`data-copiar`), el envío al cambiar (`data-autosubmit`) y el
desplegable de vulnerabilidades (`data-vulns`) siguen funcionando dentro de una zona
recién sustituida. El recorrido guiado recuenta sus pasos cada vez que se abre y cuando el
motor avisa con el suceso `vivo:zona-actualizada`.

El orden de los escuchadores importa y está fijado: **primero** la confirmación, **después**
el motor. Una acción delicada se confirma antes de enviarse; si se cancela, no se envía
nada (`stopImmediatePropagation`).

---

## 4. Cómo sumar una página nueva

1. Envolver lo que cambia en un elemento con `id` único, `data-zona-viva`,
   `data-zona-nombre` y `tabindex="-1"`.
2. Comprobar que **todo lo que depende de los filtros** (recuento, atajos, exportación,
   paginación) queda dentro de esa zona.
3. Marcar el formulario de filtros con `data-filtro-vivo="<id>"`.
4. Pasar `zona='<id>'` a `_paginacion.html`.
5. Marcar los formularios POST rápidos con `data-accion-viva` y su `data-accion-espera`;
   si la acción consulta la red, añadir `data-accion-tiempo`.
6. Ejecutar `tests/test_interaccion_sin_recarga.py`: comprueba que cada referencia apunta
   a una zona viva que existe en esa misma página y que el motor implementa cada atributo
   que la plantilla usa.
7. Comprobar con navegador: `data/revision/verificar_sin_recarga.py`.

### Qué NO se marca

* Las acciones que **descargan un fichero** (informes en Word, exportaciones CSV): el
  navegador las gestiona mejor.
* Las que **cambian la sesión o las credenciales** (contraseña, segundo factor,
  cerrar sesión): tienen que verse como una navegación completa.
* Las **subidas de fichero** grandes (SBOM, OpenSCAP) y la sincronización con OCS
  Inventory, que puede durar minutos: el navegador enseña su propio progreso.
* El **Panel**: no tiene filtros, ni formularios, ni paginación; todo son enlaces a otras
  páginas.

---

## 5. Páginas cubiertas

| Página | Zonas vivas | Qué se actualiza sin recargar |
|---|---|---|
| Amenazas | `cifras-amenazas`, `resultados` | filtro del parque, filtros y búsqueda, orden, paginación y la búsqueda global de la barra superior |
| Ficha de amenaza | `ficha-amenaza` | cambiar el estado (y los ajustes de falso positivo) |
| Tendencias | `pagina-tendencias` | selector de mes y de año |
| Auditoría | `registro-auditoria` | paginación |
| Activos | `lista-activos` | filtros, vistas rápidas, orden y paginación |
| Ficha de activo | `consulta-cve`, `scap-fallos`, `tabla-software-activo`, `actualizaciones-activo`, `remediaciones-lista` | consulta de un CVE, filtro de software, paginación, comprobar una remediación y guardar su nota |
| Software | `sin-clasificar`, `tecnologias-con-activos`, `reglas-del-mapa` | filtro, tres paginaciones, crear y borrar reglas, sembrar el mapa |
| Inventario de tecnologías | `pagina-tecnologias`, `tabla-tecnologias` | filtro, paginación, alta, borrado, versión rápida e importación |
| Ficha de tecnología | `pagina-tecnologia` | editar, añadir y borrar alias |
| Remediación | `tabla-remediaciones` | filtros, paginación, comprobar y anotar |
| Correcciones pendientes | `tabla-parches` | filtros y paginación |
| Excepciones | `pagina-excepciones`, `lista-excepciones` | filtros, paginación, registrar, prorrogar y revocar |
| Informes | `plantillas-informe`, `campos-informe`, `vista-previa-informe` | elegir plantilla o empezar de cero, y **vista previa viva** en los dos modos |
| Fuentes y ficha de fuente | `pagina-fuentes`, `catalogo-fuentes`, `pagina-fuente` | probar, activar, crear, editar y paginación |
| Usuarios | `pagina-usuarios` | crear, editar, perfil y estado, restablecer, desbloquear y eliminar |
| Ajustes | `pagina-ajustes` | guardar y restaurar |
| Credenciales | `pagina-credenciales` | rotar, verificar, prueba de envío, clave de NVD y destinatarios |
| Alertas por proceso | `pagina-alertas-proceso` | guardar y probar |
| Consultas a OCS | `tabla-sincronizaciones` | filtros y paginación |

---

### 5.1 Informes: la zona viva dentro de la columna pegada (2026-09-10, tarde)

La pantalla de Informes pasó a dos columnas, con la vista previa pegada al desplazamiento
a la derecha. **El contrato no cambia**: la zona sigue siendo el mismo elemento
`#vista-previa-informe`, el mismo identificador viene en `/informes/vista-previa` y el
motor sustituye la zona entera. Lo único que hay que saber:

* dentro de la zona hay ahora un bloque `.previa-desplazable` (lo que se lee) y, fuera de
  él, el pie con el botón de generar; los dos viajan en la zona, así que el fragmento y la
  página siguen pintando exactamente lo mismo;
* al sustituirse la zona, el desplazamiento interno del panel vuelve al principio, que es
  donde están las cifras: es lo que se quiere ver después de cambiar algo;
* el elemento pegado (`.columna-informe-resumen`) está **fuera** de la zona viva, así que
  el motor no lo toca y el panel no da saltos al actualizarse.

## 6. Comprobado con navegador

`data/revision/verificar_sin_recarga.py` recorre catorce interacciones reales contra una
copia de la base de producción, con el navegador sin cabeza y el protocolo de depuración
de Chrome. En cada una pone una marca en `window` y en `<html>`, ejecuta la acción, espera
a que ninguna zona tenga `aria-busy` y comprueba que **la marca sobrevive** (no hubo
recarga) **y que el contenido cambió de verdad** (no vale que no pase nada). Con
`sin-motor` se bloquea la descarga de `app.js` y se comprueba lo contrario: que todo sigue
funcionando con recarga completa.

Medido el 2026-09-10 contra la copia de producción (7.121 amenazas, 918 activos, 179.429
evaluaciones de aplicabilidad, 1.411 entradas de auditoría). «Con motor» es el tiempo
desde la acción hasta que la zona ya está cambiada; «sin motor» es lo mismo con `app.js`
bloqueado, es decir con recarga completa de la página.

| Recorrido | Con motor | Sin motor (recarga) |
|---|---:|---:|
| Filtrar en Amenazas («windows», con 220 ms de gracia al escribir) | 1.098 ms | 984 ms |
| Paginar en Auditoría (página siguiente) | 57 ms | 130 ms |
| Cambiar el estado de una amenaza | 472 ms | 651 ms |
| Registrar una excepción | 178 ms | 144 ms |
| Revocar una excepción | 144 ms | 280 ms |
| Cambiar el perfil de una persona | 55 ms | 172 ms |
| Informes, empezar de cero: marcar un apartado | 54 ms | 212 ms |
| Informes, plantilla «Informe mensual completo»: marcar un apartado | 54 ms | 73 ms |
| Informes, plantilla «Resumen para dirección»: marcar un apartado | 55 ms | 71 ms |
| Informes, plantilla «Informe técnico de remediación»: marcar un apartado | 260 ms | 265 ms |
| Informes, plantilla «Explotación activa»: marcar un apartado | 259 ms | 281 ms |
| Informes, plantilla «Resumen para dirección»: cambiar el alcance | 60 ms | 160 ms |
| Informes: elegir la plantilla «Informe mensual completo» desde su tarjeta | 106 ms | 194 ms |
| Informes: elegir la plantilla «Explotación activa» desde su tarjeta | 259 ms | 389 ms |

El botón de atrás se comprobó en los dos recorridos que cambian de contenido por
navegación (filtrar en Amenazas y paginar en Auditoría): vuelve a la dirección anterior,
repone el contenido anterior y **no recarga** la página.

La diferencia de tiempo no lo es todo: sin recarga no se vuelven a descargar ni a
interpretar la hoja de estilos y el JavaScript, no parpadea la pantalla, no se pierde la
posición de desplazamiento y el foco se queda donde estaba. Eso es lo que el usuario
llamaba «muy molesto».
