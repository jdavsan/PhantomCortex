# Interacción sin recarga

Contrato del motor de actualización parcial implementado en `webui/static/app.js`. La mejora es progresiva: sin JavaScript, formularios y enlaces siguen funcionando mediante navegación normal; con el motor activo, las zonas marcadas se actualizan con `fetch` sin recargar la página. El servidor conserva el renderizado HTML y las mismas rutas, métodos y protecciones CSRF.

## Zonas vivas

Marca con `data-zona-viva` cada contenedor que pueda sustituirse. Su `id` debe ser único en la página y aparecer también en la respuesta del servidor.

```html
<div id="resultados" data-zona-viva data-zona-nombre="Resultados">
  <h2 data-zona-foco>Resultados</h2>
  <p data-zona-resumen>Se encontraron resultados.</p>
</div>
```

- `data-zona-viva`: identifica una zona que el motor puede reemplazar.
- `data-zona-nombre`: nombre alternativo para anunciar una actualización cuando no hay resumen.
- `data-zona-foco`: elemento al que se puede mover el foco si el elemento enfocado desaparece al sustituir la zona.
- `data-zona-resumen`: texto que se anuncia después de actualizarla.

## Filtros, búsquedas y controles

Los formularios de filtro usan GET y mantienen un envío clásico funcional como mejora progresiva:

```html
<form method="get" data-filtro-vivo="resultados"
      data-filtro-vivo-retardo="300"
      data-vivo-fragmento="/ruta/parcial">
```

- `data-filtro-vivo`: identificadores de las zonas que actualiza el formulario, separados por espacios.
- `data-filtro-vivo-retardo`: retardo en milisegundos antes de actualizar tras escribir; si no se especifica un valor positivo, se usan 220 ms.
- `data-vivo-fragmento`: ruta opcional del endpoint que devuelve el fragmento HTML. Se envían los mismos parámetros del formulario.
- `data-vivo-zonas`: permite que un control concreto seleccione las zonas que se actualizarán, en lugar de las del formulario.
- `data-sin-vivo`: excluye un control o enlace de la actualización parcial. En un control, no activa el filtro vivo.

Al cambiar controles, la consulta se actualiza sin recargar. Si no existe en la página alguna zona indicada, el navegador conserva el envío clásico del formulario.

## Enlaces

Los enlaces dentro de una zona viva que cambian los parámetros de esa misma página —por ejemplo, paginación, orden o vistas rápidas— actualizan la zona. Un enlace externo a la zona puede declarar explícitamente el destino:

```html
<a href="?pagina=2" data-enlace-vivo="resultados">Siguiente</a>
```

- `data-enlace-vivo`: zonas que se reemplazarán al seguir el enlace.
- `data-sin-vivo`: deja el enlace fuera del motor; el navegador lo sigue normalmente.

Descargas, enlaces a otra página, enlaces con destino nuevo y enlaces abiertos con modificadores del teclado no se interceptan.

## Acciones de escritura (POST)

Las acciones pueden actualizar una zona sin recargar, manteniendo el POST y el campo CSRF del formulario:

```html
<form method="post" data-accion-viva="resultados"
      data-accion-espera="Guardando…"
      data-accion-tiempo="120000">
  <!-- incluir el testigo CSRF requerido por el servidor -->
</form>
```

- `data-accion-viva`: identificadores de las zonas que se actualizarán. Si no se indica, el motor puede usar la zona viva que contiene el formulario.
- `data-accion-espera`: texto temporal del botón de envío mientras la acción está en curso.
- `data-accion-tiempo`: tiempo de espera personalizado en milisegundos, limitado a 120 000 ms. Sirve, por ejemplo, para acciones que consultan servicios externos.

El botón se deshabilita durante el envío y no se admite un segundo envío simultáneo del mismo formulario. Si la escritura falla o vence el tiempo de espera, el motor no repite el POST automáticamente: la acción podría haberse aplicado ya. Se informa del problema para que la persona compruebe el estado antes de decidir si vuelve a intentarlo. Si la respuesta exige ir a otra página, se navega a ella mediante la redirección del servidor.

## Mensajes accesibles

La plantilla base debe incluir siempre una región para los mensajes:

```html
<div id="mensajes-plataforma" role="status" aria-live="polite" aria-atomic="true"></div>
```

El motor copia los mensajes devueltos por el servidor o anuncia el resumen/nombre de la zona actualizada. La región viva permite que las tecnologías de asistencia comuniquen el resultado sin recargar la página.

## Historial, errores y seguridad

- Las lecturas actualizan el historial del navegador; Atrás vuelve a solicitar las zonas y sincroniza los valores de los filtros.
- Si una lectura devuelve algo que no es HTML, no contiene las zonas esperadas o falla la conexión, el motor vuelve a la navegación normal para no dejar la página en un estado incoherente.
- Una escritura nunca se reintenta automáticamente.
- Las acciones de escritura mantienen el método POST y el testigo CSRF. No se debe cambiar una acción POST a GET para habilitar la actualización parcial.
- No se requiere JavaScript en línea ni atributos de evento HTML; el motor usa los atributos `data-*` y respeta la política de seguridad de contenido.

## Verificación

Las pruebas automatizadas de `tests/test_interaccion_sin_recarga.py` verifican el contrato entre el motor, las plantillas y las zonas renderizadas. La comprobación de comportamiento en un navegador real se realiza con `data/revision/verificar_sin_recarga.py` contra una copia de la base de datos.
