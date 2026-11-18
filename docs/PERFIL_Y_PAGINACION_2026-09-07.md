# Perfil de usuario y paginación — 7 de septiembre de 2026 (v9)

Documento de referencia de la entrega del 7 de septiembre de 2026. Recoge los cambios
pedidos por el usuario el mismo día y las decisiones que se tomaron para resolverlos.

> **Retirado el mismo día.** Se probó además un apartado «Validación de hardening» con
> OpenSCAP para todo el parque. El usuario lo descartó al verlo («elimina el módulo de
> hardening, no me sirve; pensé que era diferente»), así que se retiraron sus páginas, su
> entrada de menú y sus pruebas. **Sigue en pie** el panel «Cumplimiento de configuración
> (OpenSCAP)» de la ficha de cada activo, que es anterior y no se tocó:
> `threatintel/openscap.py` conserva `analizar`, `importar`, `resumen_activo` y
> `fallos_activo`.

---

## 1. El cambio de contraseña inicial bloquea de verdad

**El fallo.** Cuando un administrador crea una cuenta o restablece una contraseña,
`users.must_change` queda a 1. Hasta esta versión solo se redirigía a la pantalla de
cambio **justo después del acceso**: bastaba escribir cualquier otra dirección para
entrar y consultar toda la plataforma con la contraseña que había escrito el
administrador. El aviso era cosmético. El usuario lo describió como «un fallo grave».

**Reproducido antes de corregir.** Con `users.must_change=1`, las direcciones `/`,
`/activos/`, `/amenazas/`, `/usuarios/`, `/ajustes/` y `/remediaciones/` devolvían todas
200. Tras la corrección, las seis devuelven 302 a `/cambiar-contrasena`.

**La corrección.** `webui/auth.py` lee `must_change` y `enabled` en **cada petición**
(una consulta de dos columnas por clave única, con caché en `g`) y el decorador
`requiere_login` redirige **cualquier** dirección a `/cambiar-contrasena` mientras valga 1.
Las únicas excepciones son esa pantalla, `/logout`, los ficheros estáticos y la dirección
histórica `/mi-password`, que a su vez reenvía a la pantalla.

Que el valor se lea en cada petición tiene un efecto buscado: si un administrador
restablece la contraseña de alguien que ya está dentro, esa sesión queda bloqueada en la
pantalla en la petición siguiente, no en su próximo acceso.

**La pantalla** (`webui/templates/cambiar_password_obligatorio.html`) está aislada: solo
la marca, el formulario y el botón de salir. Sin menú lateral, sin barra superior, sin
buscador y sin recorrido guiado. Pide la contraseña nueva dos veces, exige doce
caracteres y tres de cuatro clases, y **rechaza repetir la actual**. No pide la
contraseña actual porque la sesión se abrió con ella hace un instante. Cabeceras
`Cache-Control: no-store`.

Al guardarla: `must_change` pasa a 0, se revocan las demás sesiones del usuario, se
renueva el identificador de la sesión que hizo el cambio (fijación de sesión), se
audita con `usuario.password` y `password.cambio_obligatorio`, y se entra.

**Orden con el segundo factor:** primero la contraseña, después el código. Si
`mfa_obligatorio_admin` está activo, al terminar el cambio se pasa a la activación.

**`/salud.json`.** No lleva `requiere_login` porque es la ruta de métricas de Zabbix.
Sin `HEALTH_TOKEN` configurado se conformaba con que hubiera sesión, así que era el
único hueco del control. Ahora exige además que la sesión no esté pendiente de cambiar
la contraseña ni la cuenta deshabilitada. `tests/test_perfil.py` vigila que no se reabra.

## 2. Mi perfil (`/perfil`)

Sustituye al botón «Contraseña» de la barra superior. **Se entra con el botón «Mi perfil»**,
arriba a la derecha, junto al nombre de la persona.

> Primero se puso solo el nombre como enlace, y el usuario no lo encontró («no veo la
> opción de ir al perfil»). Con razón: un texto que resulta que se puede pulsar no es una
> ruta visible. Ahora el nombre es texto y al lado hay un botón con icono de persona y la
> etiqueta «Mi perfil», igual que el resto de los controles de la barra.

Cuatro bloques:

- **Quién soy:** nombre de la persona, correo de acceso, perfil (Administrador o Solo
  lectura, con una frase de qué puede hacer cada uno) y fecha de creación de la cuenta.
- **Mi acceso:** último inicio de sesión con fecha, hora y «hace…», sesiones abiertas,
  intentos fallidos y si la cuenta está bloqueada con los minutos que quedan.
- **Registro de mis accesos:** los diez más recientes, leídos de `audit_log` con las
  acciones `login.ok`, `login.2fa.ok`, `login.password_ok` y `login.fallo`. Los fallos se
  guardan con `username` a NULL y el usuario en `entity_id`, así que la consulta busca
  por las dos columnas.
- **Mi contraseña** y **Segundo factor de autenticación:** activación con código QR y
  ocho códigos de recuperación de un solo uso, regeneración y desactivación, cada una con
  contraseña y código.

La vista **no recibe ningún identificador**: solo puede mostrar el perfil de la sesión.
Para consultar a los demás está Usuarios, que es solo para administradores.

## 3. El nombre de la persona, no su correo

`users.nombre` (esquema v9). La barra superior muestra el nombre; el correo sigue visible
en el perfil y en Usuarios, porque es con lo que se entra.

- **Validación:** entre 3 y 80 caracteres; letras con tilde o eñe, espacios, guiones,
  apóstrofos y puntos. Sin cifras ni signos de marcado. Los espacios repetidos se
  colapsan al guardar.
- **Obligatorio en el alta**, también desde el servidor:
  `bin/gestionar_usuario.py crear <correo> --nombre "Nombre Apellidos"`. Si se omite ahí,
  la cuenta queda sin nombre, la barra muestra el correo y la lista invita a completarlo.
- **El correo no se puede cambiar.** Si la persona cambia de correo se crea otro usuario
  y se elimina el anterior: el correo es la referencia de las sesiones y de la auditoría.
- **Edición completa:** `/usuarios/?editar=<id>` abre un panel propio (nombre, perfil,
  estado y contraseña nueva con repetición) y `POST /usuarios/<id>/actualizar` lo guarda.
  La contraseña es opcional: si se deja vacía no se toca. Al cambiarla se cierran todas
  las sesiones de esa persona y se marca `must_change`. Nadie cambia su propia contraseña
  desde Usuarios: eso se hace en Mi perfil, que exige la actual.
- **Auditoría:** acciones nuevas `usuario.actualizar` (nombre, perfil y estado anteriores
  y nuevos, y sesiones revocadas) y `usuario.nombre`. Las contraseñas no aparecen nunca.

## 4. Confirmaciones dentro de la página

El usuario pidió quitar «los mensajes que se ven reflejados como si se ejecutara código
JavaScript»: eran los tres `window.confirm` de `webui/static/app.js`. Un diálogo del
navegador no se puede maquetar ni redactar en español correcto, y no dice qué va a pasar.

Ahora la pregunta se inserta **en la propia página**, junto a la acción:

```html
<div class="confirmacion-en-linea" role="group" aria-live="polite">
  <p class="confirmacion-texto">¿Eliminar al usuario …?</p>
  <div class="confirmacion-botones">
    <button class="btn pequeno peligro" type="button" data-confirmar-si>Sí, eliminar</button>
    <button class="btn pequeno" type="button" data-confirmar-no>Cancelar</button>
  </div>
</div>
```

Reglas: el botón de la acción se oculta mientras se pregunta; el foco pasa al botón que
confirma; «Cancelar» y la tecla **Escape** cierran y devuelven el foco; solo puede haber
una confirmación abierta a la vez; en un selector, cancelar devuelve el valor anterior.
Atributos de plantilla: `data-confirm` (mensaje), `data-confirm-si` (texto del botón que
confirma, «Sí, continuar» por omisión) y `data-confirmar` en un `<option>` para que el
mensaje dependa de la opción elegida. Sin `style=` ni `on*=`: la CSP no cambia.

**Efecto lateral corregido de paso.** El proyecto no anulaba `[hidden]`. El
`display: none` que le pone el navegador es de especificidad cero, así que
`.btn { display: inline-flex }` lo vencía: había botones que el código daba por ocultos y
seguían a la vista (el «Copiar la orden» de hardening, el «Filtrar» que la búsqueda en
vivo retira y el de la acción mientras se confirma). Se añadió
`[hidden] { display: none !important; }` al principio de `webui/static/estilo.css`.

## 5. Paginación de todos los listados

Un único componente, `webui/templates/_paginacion.html` (macro `paginacion`), **20 filas
por página** en todos los listados largos. El usuario pidió ese tamaño expresamente: «que
en cada uno solo muestre de a 20, aún me muestra de a muchas por página y no es lo más
adecuado». Se aplica en `POR_PAGINA` / `LIMITE_PAGINA` de cada vista y en Auditoría:

```jinja
{% from "_paginacion.html" import paginacion %}
{{ paginacion('activos.lista', request.args.to_dict(flat=false), pagina, paginas,
              total, por_pagina, singular='activo', plural='activos',
              ancla='lista-activos', titulo='Paginación de los activos') }}
```

| Argumento | Para qué |
|---|---|
| `endpoint` | vista a la que apuntan los enlaces |
| `args` | filtros y orden que hay que conservar al cambiar de página, sin `pagina`; admite valores simples o listas |
| `pagina`, `paginas`, `total`, `por_pagina` | ya validados por la vista |
| `singular` / `plural` | nombre de lo que se lista, para el texto en español |
| `ancla` | zona del listado a la que volver, con `tabindex="-1"` para no perder el teclado |
| `titulo` | etiqueta accesible de la navegación |
| `clave` | nombre del parámetro de página; una página con varios listados le da a cada uno el suyo (`pagina_reglas`, `pagina_tecnologias`) |

**Normas.** Cada vista valida la página con su `_pagina_valida()`: fuera de rango va a la
primera o a la última, nunca a un error ni a una tabla vacía. El total sale de una
consulta de recuento, nunca de contar las filas traídas. Los controles que no llevan a
ninguna parte son `<button disabled>` de verdad, no desaparecen, para que la fila no
cambie de tamaño al navegar. La página actual lleva `aria-current="page"`. Objetivo táctil
de 44 px. Clases: `paginacion`, `paginacion-info`, `paginacion-boton`, `paginacion-numero`,
`paginacion-actual`, `paginacion-elipsis`.

**Listados cubiertos:** Activos, Software (tres listados con su propio parámetro),
Inventario de tecnologías, Fuentes, Remediación, Correcciones pendientes, Amenazas,
Auditoría y la **ficha de cada activo**, con sus cuatro listados: amenazas evaluadas
(`pagina_cve`), remediaciones (`pagina_rem`), reglas de configuración que no cumple
(`pagina_scap`) y software instalado (`pagina_soft`). En la ficha, cambiar de página en
uno conserva la página de los otros tres y el filtro del software: la vista los añade a
los argumentos que el componente reenvía, y el componente sobrescribe solo su propia
clave. Antes la ficha traía hasta 300 filas evaluadas, 150 reglas y 100 remediaciones de
una vez.

**Cambio de sentido de `LIMITE_PAGINA`** en Remediación y Correcciones pendientes: de
«las 500 primeras filas con aviso de recorte» a «filas por página» (50). La exportación
CSV no cambia: sigue completa.

**Rendimiento medido** sobre la base real (876 activos, 922.638 instalados, 42.902
remediaciones):

| Consulta | Antes | Después |
|---|---|---|
| Última página de Remediación | 1.114 ms | 299 ms (`desplazamiento` con `LIMIT ? OFFSET ?`) |
| Recuento de activos por programa (página de Software) | 1.816 ms | 184 ms (índice `idx_actsoft_norm_activo`) |

**Orden total.** Los `ORDER BY` de `remediacion.listar` y `parches.listar` terminan ahora
en la clave única de la tabla (`r.id`, `p.id`). Con un orden que empataba, SQLite podía
devolver la misma fila en dos páginas y perder otra.

**Activos ya no filtra en el navegador.** El filtrado, el orden y las vistas rápidas los
aplica el servidor; la búsqueda en vivo (`data-filtro-vivo`) sustituye la zona
`#lista-activos`. En `app.js` queda solo el desplegable de vulnerabilidades de cada
equipo, delegado en `document` para que siga funcionando después de un filtrado. El
buscador dejó de mirar la columna `descripcion` de OCS (guarda arquitectura y tiempo de
encendido, «x86_64/00-02-13 08:06:05»: 798 de 838 descripciones no aportan nada buscable)
y mira `nombre`, `ip`, `so_nombre`, `so_version`, `usuario` y `proceso`, que es lo que
anuncia la etiqueta del campo.

## 6. El perfil «Solo lectura» no modifica nada

«Hay usuarios de solo lectura que pueden editar cosas.» Era cierto: tres rutas que
escriben en la base llevaban `@requiere_login` en vez de `@requiere_admin`
(A01:2025, control de acceso roto).

| Ruta | Qué escribía | Gravedad |
|---|---|---|
| `POST /tecnologias/<id>/version` | `technologies.version_installed` | **Alta.** De esa versión depende el veredicto de aplicabilidad de todo el parque |
| `POST /activos/<id>/aplica` | una fila de `aplicabilidad` | Media. Parece una consulta («¿Le aplica este CVE?») pero llama a `responder_cve`, que evalúa y guarda |
| `POST /fuentes/<id>/probar` | nada en la base, pero saca al servidor a Internet y deja rastro en la auditoría | Baja. Es una acción, no una consulta |

Las tres pasan a `@requiere_admin`. Se comprobó además que **ninguna ruta GET escribe**,
con un recorrido por el árbol de sintaxis de las vistas buscando `INSERT`, `UPDATE`,
`DELETE` y las llamadas que escriben.

**La interfaz tampoco los ofrece.** Un botón que devuelve 403 al pulsarlo es un error de
interfaz, así que el perfil de consulta ya no ve el formulario de versión (ve la versión
como texto), ni el panel «¿Le aplica este CVE?» (sigue viendo la tabla de veredictos ya
calculados), ni «Probar ahora». Los dos textos que decían «Pulse Probar ahora» dicen ahora,
para ese perfil, que la recolección diaria la comprueba por su cuenta.

**La prueba que evita que vuelva.** `tests/test_solo_lectura.py` no comprueba esas tres
rutas: recorre el mapa de rutas de la aplicación, encuentra las **41** que aceptan POST
(51 menos las 10 de la propia cuenta) y exige que todas rechacen a un usuario de solo
lectura con 403 o con el 400 del token. Una ruta nueva con el decorador equivocado hace
fallar la suite sin que nadie tenga que acordarse de añadirla a una lista.

Lo único que el perfil de consulta puede enviar es lo de su propia cuenta: acceso, salida,
segundo factor, cambio de su contraseña, su perfil y la respuesta a la invitación del
recorrido guiado, que es una preferencia suya y no toca ningún dato de la organización.

## 7. Una sola sesión por usuario

«Ajusta que solamente permita una sesión por usuario y no varias». Al completar el acceso
se cierran las demás sesiones de esa persona: entrar desde otro navegador o desde otro
equipo deja fuera al anterior, que en su siguiente petición vuelve a la pantalla de acceso.

**Cuándo se cierran, y por qué ahí.** En el momento en que el acceso queda **completo**
(contraseña, y el código del segundo factor si la cuenta lo tiene activado), no cuando
solo se ha comprobado la contraseña. Si se revocara con la contraseña, quien la robase sin
tener el código podría echar de la plataforma al usuario legítimo cuantas veces quisiera
—una denegación de servicio— y además sabría por el efecto que la contraseña es correcta.
Con la comprobación tardía, una sesión a medio abrir no cierra nada. `tests/test_sesion_unica.py`
fija esa garantía: la prueba entra con la cuenta que tiene segundo factor, después escribe
la contraseña correcta desde otro navegador sin el código, y comprueba que la sesión
legítima sigue dentro (también con un código equivocado).

**Dónde está.** `webui/auth.py::dejar_solo_esta_sesion` borra de `web_sessions` todas las
filas de ese usuario menos la actual, reutilizando `revocar_sesiones(excepto_sid=…)`, y lo
deja anotado en la auditoría con la acción `sesion.unica`. Se llama desde
`webui/vistas/sesion.py::_tras_acceso`, que es el único punto por donde pasan los dos
caminos de acceso una vez completados; `iniciar_sesion` sigue siendo el único sitio que
crea sesiones.

**Lo que ve la persona.** Un aviso al entrar: «Se ha cerrado la sesión que tenía abierta en
otro navegador o equipo: esta plataforma admite una sola sesión por usuario. Si no ha sido
usted, cambie su contraseña y avise a Seguridad de la Información.» En el primer acceso no
aparece nada. En Mi perfil, «Sesiones abiertas» siempre dice 1 y explica la política, para
que nadie lo lea como un error; ese recuento ya excluía las sesiones pendientes de segundo
factor y las caducadas.

**Lo que no cambia.** El acceso de una persona no toca las sesiones de las demás. Las
sesiones pendientes de segundo factor caducan por su cuenta a los pocos minutos y
`limpiar_sesiones_caducadas` las borra en el siguiente acceso.

## 8. Tipo, entorno y proceso separados en Activos

La tabla tenía una sola columna «Tipo y entorno» que apilaba tres datos distintos, y la
exportación a CSV no llevaba ni el entorno ni el proceso. El usuario los necesita por
separado para repartir el trabajo: «necesito saber en una columna si es servidor, en otra
el entorno si es de desarrollo y en otra a qué proceso pertenece».

Ahora son tres columnas propias, cada una con su encabezado y su explicación al pasar el
ratón: **Tipo** (servidor o equipo de usuario, según lo que reporta OCS Inventory),
**Entorno** (producción, contingencia, desarrollo, pruebas o soporte; «Sin entorno» cuando
falta) y **Proceso** (el TAG de OCS, con «Jefa del Proceso» y «Admin-JT» normalizados a
«Servicios Tecnológicos»; «Sin proceso» cuando falta).

El CSV de `/activos/exportar.csv` pasa de 15 a 17 columnas: `activo; tipo; entorno;
proceso; ip; sistema; version_sistema; zona; …`. `zona` es otra cosa (la zona de red) y se
conserva. Comprobado sobre los 876 activos reales: 218 en producción, 123 en contingencia,
134 en pruebas de usuario, 71 en desarrollo, 35 en soporte y 295 sin entorno; los procesos
con más equipos son Pila (182), Helpvoz (92) y Servicios Tecnológicos (74).

## 9. Consultas a OCS Inventory y la alerta a las 08:00 en punto

Dos peticiones del mismo día: «un módulo en administración que me deje ver las fechas y
horas en las que se ejecutó la consulta a las 2 bases de datos», y que la consulta diaria
pase a las 07:30 «para que de esta forma las alertas se envíen a las 8 am y no después».

### Por qué el correo salía tarde

Medido en `logs/cron_diario.log`: la ejecución empezaba a las 08:00 y el correo salía a las
08:07, 08:09, 08:20 y 08:22 según el día. **La consulta a OCS no era la culpable**: cuesta
unos 65 segundos entre las dos bases (54 s los servidores, 10 s los equipos). El retraso se
reparte entre todos los pasos que van antes del envío.

Desglose real de la ejecución del 7 de septiembre de 2026, la más rápida de la serie:

| Paso | Duración |
|---|---|
| Consulta a los dos OCS | 65 s |
| Recolección de las 36 fuentes | 132 s |
| Enriquecimiento y repaso de descripciones | 196 s |
| Hoja de cálculo y envío | 17 s |
| **Total** | **7 min 21 s** |

Los días 3 y 4 de septiembre fueron peores (correo a las 08:20 y 08:22) porque la clave de
API del NIST tenía entonces 21 caracteres en lugar de los 36 de un UUID y se ignoraba, con
lo que el enriquecimiento caía al límite público de cinco peticiones cada treinta segundos.
**Eso ya está resuelto**: la clave se corrigió el 5 de septiembre, está verificada contra
NVD («50 peticiones cada 30 s») y las ejecuciones del 6 y del 7 ya la usaron.

Aun así, mover solo la consulta a OCS habría ganado 65 segundos de siete minutos. Lo que
pone el correo a las 08:00 es sacar del camino crítico **todo** lo que va antes del envío.
La ejecución se parte en dos fases:

| Hora | Orden | Qué hace |
|---|---|---|
| **07:30** | `ejecucion_diaria.py --sin-alerta` | Consulta a los dos OCS, recolección de fuentes, enriquecimiento, salud de fuentes y exportaciones |
| **08:00** | `ejecucion_diaria.py --solo-alerta` | Solo clasificar y enviar. Nada más |

`--solo-alerta` es una bandera nueva que omite los pasos 0, 1, 2, 4 y 6 y ejecuta el 3
(comprobación de la credencial de correo, que hace falta antes de enviar) y el 5 (la
alerta). El paso 5 ya era independiente: lee de la base con `queries.clasificar_pendientes`
y no depende de nada que quede en memoria de los pasos anteriores.

**Comprobación de frescura.** Con `--solo-alerta` la fase de las 08:00 mira cuándo fue la
última consulta correcta a OCS y lo imprime. Si pasa de seis horas lo avisa y lo registra
como error, porque significa que la fase de las 07:30 falló y el correo saldría con
inventario viejo. Se envía igual —vale más una alerta con datos de ayer que ninguna—, pero
queda dicho. También se añadió `--sin-ocs` para omitir solo la consulta a OCS.

La fase de las 08:00 se registra en «Últimas ejecuciones» con el tipo `alerta`, no `daily`,
para que las dos fases no se confundan entre sí.

### El módulo (`/sincronizaciones/`, Administración → Consultas a OCS)

Todo sale de la tabla `sync_ocs`, que ya existía y que `ocs.sincronizar_origen` rellena en
cada intento: una fila por base, con hora de inicio y de fin, estado, activos y programas
leídos, nuevos, cambiados, ausentes, duración y el error. La página **no lanza nada**: no
tiene ninguna ruta con POST, y la sincronización a demanda sigue en Activos.

Qué muestra: una tarjeta por base con su última consulta y la media de los últimos treinta
días; un aviso arriba si algún inventario pasa de seis horas; el horario del programador; a
qué servidor y base se conecta cada origen, con el usuario y **sin la contraseña**; y el
registro completo paginado de veinte en veinte, filtrable por base y por resultado. Una fila
«en curso» de más de media hora se marca como ejecución que murió a medias.

### El horario: quién puede leerlo

La hora la fija el cron, y esa es la única fuente de verdad; no se escribe en el código ni
en un ajuste que pueda quedar desfasado. Pero **la interfaz no puede leerlo**: su unidad de
systemd tiene `NoNewPrivileges=true` y `RestrictSUIDSGID=true`, así que la orden `crontab`
no puede tomar el grupo `crontab` con el que lee el spool, cuyo directorio está en modo 730.
Eso es endurecimiento correcto y no se debilitó por una etiqueta.

La solución es que lo registre quien sí puede: `threatintel/programacion.py` lee el crontab
y guarda el horario en `settings`, y **la propia ejecución diaria lo llama** en cada carrera,
en un shell normal sin esas restricciones. La página lee el valor guardado y dice cuándo se
tomó. Si alguien cambia el cron, la página lo refleja al día siguiente y mientras tanto no
miente sobre la fecha del dato. Solo se extraen las líneas de las órdenes de la plataforma:
el respaldo semanal y el guion del RAID no salen de ahí, y los horarios que no son una hora
fija (`*/5`, `7,19`) se descartan en lugar de mostrarse mal.

### La clave del NIST: estado real

La variable se llama **`NIST_NVD_API_KEY`** (no `NVD_API_KEY`) y está correctamente
configurada: 36 caracteres con formato de UUID, aceptada por NVD en la verificación del
5 de septiembre de 2026 con «50 peticiones cada 30 s». Credenciales → clave de API de NVD
muestra su estado y la vuelve a verificar cuando se pide.

Queda por delante la cola de enriquecimiento: 918 CVE pendientes de puntuación oficial, con
un tope de `enrich_max_per_run = 150` por ejecución, son unos siete días. Con la clave válida
cada CVE cuesta 0,65 segundos en lugar de 6,5, así que subir ese tope en Ajustes vaciaría la
cola en dos o tres días sin acercarse al límite de la media hora que tiene la fase de las
07:30. Es una decisión del usuario, no se ha cambiado.

---

## Ficheros

**Nuevos:** `webui/templates/perfil.html`, `cambiar_password_obligatorio.html`,
`_paginacion.html`; pruebas `tests/test_perfil.py`, `test_paginacion.py`,
`test_usuarios_nombre.py`, `test_sesion_unica.py`, `test_solo_lectura.py`,
`test_sincronizaciones.py`; `threatintel/programacion.py`,
`webui/vistas/sincronizaciones.py`, `webui/templates/sincronizaciones.html`.

**Modificados:** `webui/auth.py`, `webui/app.py`, `webui/static/app.js`,
`webui/static/estilo.css`, `webui/templates/base.html`, `webui/vistas/sesion.py`,
`usuarios.py`, `activos.py`, `fuentes.py`, `tecnologias.py`, `parches.py`,
`remediaciones.py`, `amenazas.py`, `panel.py`, `threatintel/db.py`, `threatintel/openscap.py`,
`threatintel/remediacion.py`, `threatintel/parches.py`, `bin/gestionar_usuario.py`.

## Pendiente

- **Rellenar `users.nombre` de los tres usuarios reales** (`soc@ejemplo.local`,
  `usuario1@ejemplo.local`, `usuario2@ejemplo.local`, todos a NULL). Se hace
  desde Usuarios → «Editar»; no hace falta tocar la base. Hasta entonces la barra
  superior y el perfil muestran el correo, con la nota que lo explica.
- **Optimizar `ocs.resumen()`** (764 ms, se llama en `/activos/` y `/activos/software`) y
  **`remediacion.resumen(dias=30)`** (246 ms, en `/activos/`): son el 85 % del tiempo de
  la página de Activos.
- **Índice de `audit_log`** por `(username, id)` o `(action, id)` si la auditoría crece a
  cientos de miles de filas. Hoy son 987 y el recorrido cuesta menos de 1 ms.
- **`/mi-password`** sigue mostrando el perfil en lugar de redirigir a `/perfil`; es una
  dirección histórica que se conserva para no romper enlaces ni marcadores.
