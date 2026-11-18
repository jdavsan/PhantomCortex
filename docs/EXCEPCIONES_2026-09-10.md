# Excepciones con vencimiento: aceptación de riesgo (2026-09-10)

> Petición del usuario: «Falta aceptar un riesgo con responsable, justificación y fecha de
> caducidad, que es lo que pide una auditoría y lo que evita que algo quede olvidado».

## 1. El problema que resuelve

Hasta hoy una vulnerabilidad solo podía salir de la cola de trabajo por dos caminos:
corregirla, o marcar la amenaza como **falso positivo** o **mitigada** (los estados de
`threats.estado`). Los dos últimos tienen tres defectos graves para un programa de
vulnerabilidades que se pueda auditar:

1. **No tienen dueño.** Queda quién pulsó el botón en la plataforma, pero no quién
   *asumió el riesgo* ante la organización. No es lo mismo el operador del SOC que registra
   la decisión que el jefe de proceso o el director que la acepta.
2. **No caducan.** Lo que se «mitiga» hoy sigue mitigado dentro de tres años, aunque el
   parche llevara dos años publicado.
3. **Son un juicio técnico, no una decisión de riesgo.** «Falso positivo» significa que la
   plataforma se equivocó; «mitigada» que ya no aplica. Ninguno de los dos dice «esto nos
   afecta de verdad, no lo vamos a corregir todavía y lo aceptamos hasta el 30 de
   noviembre».

Una excepción con vencimiento cubre exactamente ese tercer caso, que es el que pide la
auditoría (ISO/IEC 27001 A.5.36, y el «risk acceptance» de cualquier marco de gestión de
vulnerabilidades).

## 2. Qué hace y qué NO hace una excepción vigente

| Hace | No hace |
| --- | --- |
| Saca la vulnerabilidad de la **cola de trabajo** (`remediaciones`) | No la borra de la base |
| La saca de las **cifras de riesgo** (`aplicabilidad`) | No la oculta: sigue en `/excepciones/` y en la ficha del activo, marcada «riesgo aceptado hasta el 30 de noviembre de 2026» |
| Cuenta en su propio indicador: «vulnerabilidades cubiertas» | No cambia el veredicto de aplicabilidad ni el estado de la amenaza |
| **Caduca sola** y la vulnerabilidad vuelve sin que nadie haga nada | No necesita ningún proceso, cron ni botón para caducar |

La última fila es la decisión de diseño más importante del módulo y la razón de que el
esquema sea como es (apartado 4).

## 3. Alcance: los tres que se admiten

| Alcance | Qué cubre | Cuándo se usa |
| --- | --- | --- |
| `activo_cve` | un CVE en un activo | el caso normal, y el más estrecho: es el que se ofrece por omisión |
| `cve` | un CVE en toda la organización, incluidos los activos que se incorporen mientras esté vigente | el fallo que afecta a todo el parque y cuya corrección depende de un tercero |
| `activo_paquete` | todas las vulnerabilidades de un paquete en un activo, también las que aparezcan mientras esté vigente | «esta aplicación heredada no se puede actualizar en este servidor» |

**Por qué los tres y no dos.** Los tres se expresan con la misma condición SQL y sobre los
mismos índices (`aplicabilidad` y `remediaciones` están indexadas por activo y por CVE),
así que el tercero no cuesta nada más. Y sin él, el caso real («no podemos tocar el
`openssl` de este servidor hasta que el fabricante certifique la versión») obligaría a
registrar una excepción por cada CVE del paquete —en producción, un solo paquete de un
equipo llega a acumular más de mil— y a repetir el trámite cada vez que aparece uno nuevo:
la gente dejaría de usarlo y volvería a marcar «mitigada» a mano, que es justo lo que se
quiere eliminar. El alcance por paquete es también el más peligroso, así que hereda la
explotación activa de todos los CVE de ese paquete en ese activo (apartado 6).

Un alcance «todo un proceso de negocio» o «todo un entorno» se ha descartado a propósito:
aceptar de golpe el riesgo de decenas de máquinas no es una excepción, es una política, y
no debe caber en un formulario de una pantalla.

## 4. Modelo de datos (`SCHEMA_VERSION` 12 → 13)

Tabla nueva `excepciones` (`threatintel/db.py`, al final de `SCHEMA`). Al ser una tabla
nueva y no una columna añadida, no toca `_COLUMNAS_NUEVAS`: `init_db()` ejecuta `SCHEMA`
siempre, así que la creación y la migración dicen lo mismo por construcción, y
`tests/test_esquema.py` lo comprueba.

| Columna | Tipo | Para qué |
| --- | --- | --- |
| `id` | INTEGER PK | |
| `alcance` | TEXT | `activo_cve` \| `cve` \| `activo_paquete` |
| `activo_id` | INTEGER → `activos(id)` ON DELETE CASCADE | NULL si `alcance='cve'` |
| `cve` | TEXT | NULL si `alcance='activo_paquete'` |
| `paquete` | TEXT | NULL salvo `alcance='activo_paquete'`; en minúsculas, como en `aplicabilidad` |
| `justificacion` | TEXT NOT NULL | por qué se acepta el riesgo (mínimo 20 caracteres) |
| `responsable_nombre` | TEXT NOT NULL | **la persona** que acepta el riesgo |
| `responsable_correo` | TEXT NOT NULL | su correo |
| `compensacion` | TEXT | medida compensatoria (opcional, salvo con explotación activa) |
| `registrado_por` | TEXT NOT NULL | usuario de la plataforma que la registró |
| `registrado_at` | TEXT NOT NULL | fecha y hora ISO en UTC |
| `vence_at` | TEXT NOT NULL | fecha `AAAA-MM-DD`; **obligatoria, nunca indefinida** |
| `vence_at_inicial` | TEXT NOT NULL | la primera fecha, aunque se prorrogue |
| `estado` | TEXT NOT NULL | `vigente` \| `revocada` |
| `kev` | INTEGER | 1 si había explotación activa confirmada al registrarla |
| `prorrogas`, `prorrogada_at`, `prorrogada_por`, `prorroga_motivo` | | historia de la última prórroga y cuántas van |
| `revocada_at`, `revocada_por`, `revocada_motivo` | | quién retiró la aceptación y por qué |
| `avisado_at` | TEXT | último aviso anticipado enviado por correo |

Índices: `idx_exc_activo(activo_id, estado)`, `idx_exc_cve(cve, estado)`,
`idx_exc_vence(vence_at, estado)` y un índice **único parcial**
`idx_exc_unica(alcance, COALESCE(activo_id,-1), COALESCE(cve,''), COALESCE(paquete,''))
WHERE estado <> 'revocada'`.

### Por qué «vencida» no es un valor de `estado`

`estado` solo guarda `vigente` y `revocada`. El tercer estado que ve la persona,
**vencida**, se *calcula*: es `vigente` con la fecha ya pasada. Si «vencida» se guardara,
alguien tendría que escribirla —un cron, la ejecución diaria, un botón— y el día que ese
algo fallara la vulnerabilidad seguiría fuera de las cifras y de la cola **sin que nadie lo
notara**. Es exactamente el fallo silencioso que el usuario quiere evitar («que no quede
olvidado»). Calculándola, el peor caso posible es que la interfaz no llegue a avisar; la
vulnerabilidad vuelve igual.

El cálculo está escrito en **un solo sitio**, `threatintel/excepciones.py`:

```python
SQL_VIGENTE = "(e.estado = 'vigente' AND date('now') <= substr(e.vence_at, 1, 10))"
SQL_ESTADO  = "CASE WHEN e.estado='revocada' THEN 'revocada' " \
              "WHEN date('now') > substr(e.vence_at,1,10) THEN 'vencida' ELSE 'vigente' END"
```

y su espejo en Python (`esta_vencida`, `estado_efectivo`, `dias_restantes`) para los
mensajes y los correos. `tests/test_excepciones.py` compara los dos caminos en los días
frontera (−10, −1, 0, +1, +10): si alguien cambia uno y no el otro, la prueba falla.

**Zona horaria.** `date('now')` es la fecha en UTC y la empresa está en UTC-5, así que una
excepción deja de valer hasta cinco horas antes de la medianoche local de su último día. Se
acepta a propósito: el error va en la dirección segura (la vulnerabilidad vuelve *antes* a
la cola, nunca después) y no depende de la zona horaria del servidor.

### El índice único parcial

Dos excepciones vigentes sobre lo mismo se contradirían y la segunda taparía a la primera
en la auditoría. El índice deja **una sola no revocada por alcance**: una vencida sigue
ocupando el sitio, y para volver a aceptar el riesgo se **prorroga** (que deja constancia
de cada prórroga con su motivo) en lugar de registrar una nueva que borraría la historia.
Revocada la anterior, se puede registrar otra.

## 5. La condición que saca las vulnerabilidades de la cola y de las cifras

`threatintel/excepciones.py` publica la condición y no la escribe cada consulta:

```python
sql_sin_excepcion(activo="r.activo_id", cve="r.cve", paquete="r.paquete")   # cola
SQL_SIN_EXCEPCION_APLICABILIDAD   # cifras (alias ap)
SQL_SIN_EXCEPCION_REMEDIACION     # cola (alias r)
y_sin_excepcion(conn, ...)        # « AND …» o cadena vacía si no hay ninguna vigente
```

Se escribe con tres `NOT IN` sobre subconsultas **no correlacionadas**, y no con un
`NOT EXISTS` correlacionado. Medido sobre una copia de la base real el 2026-09-10
(179.429 filas de `aplicabilidad`, 48.216 remediaciones abiertas, 41 excepciones vigentes),
`EXPLAIN QUERY PLAN` confirma que SQLite materializa cada subconsulta **una vez**
(`LIST SUBQUERY` + `SCAN e`) en lugar de recorrerla por fila:

| Consulta | Sin la condición | Con la condición y 0 excepciones | Con 41 excepciones |
| --- | --- | --- | --- |
| `COUNT(*)` de la cola abierta | 1 ms | 42 ms | 50 ms (47.797 filas: 419 cubiertas) |
| Vulnerabilidades confirmadas (pares activo-CVE) | 98 ms | 140 ms | 151 ms (29.878: 376 cubiertas) |
| `excepciones.resumen()` | — | — | 79 ms |
| `excepciones.listar(limite=20)` | — | — | 3 ms |

`y_sin_excepcion()` devuelve cadena vacía mientras no haya ninguna excepción vigente, así
que hoy —sin excepciones registradas— las consultas de la cola y de las cifras quedan
**exactamente** como estaban, sin ni un milisegundo de más. Es el mismo patrón que
`remediacion._y_sin_bajas`.

Los `NOT IN` descartan explícitamente los nulos (`e.activo_id IS NOT NULL`,
`e.cve IS NOT NULL`): un solo NULL dentro de un `NOT IN` haría que la condición no fuera
cierta para **ninguna** fila y vaciaría la página entera. Hay una prueba dedicada a eso.

## 6. Reglas de negocio

1. **Fecha de vencimiento obligatoria**, posterior a hoy y como máximo a **365 días**. Una
   aceptación de riesgo a más de un año no es una aceptación: es un abandono con papeles.
   Para mantenerla más tiempo se prorroga, y cada prórroga exige un motivo nuevo y queda
   registrada (`prorrogas`, `prorroga_motivo`, auditoría).
2. **Justificación** de al menos 20 caracteres y **responsable con nombre, apellido y
   correo**. El responsable es una persona, no una cuenta de la plataforma ni un área: el
   usuario de la plataforma que registra la excepción se guarda aparte, en
   `registrado_por`. La auditoría necesita los dos.
3. **El CVE tiene que existir** en el catálogo de amenazas o en alguna evaluación, y para el
   alcance por activo tiene que estar **evaluado contra ese activo**: si no, no hay ningún
   riesgo que aceptar y lo más probable es que sea un error de tecleo. Igual con el nombre
   del paquete, que se comprueba contra `aplicabilidad` y contra el inventario de software
   de OCS de ese activo.
4. **Explotación activa confirmada (CISA KEV): se advierte, no se prohíbe.** Ver el
   apartado siguiente.
5. **La revocación devuelve la vulnerabilidad en el acto** a la cola y a las cifras, y exige
   un motivo de al menos 20 caracteres.
6. **Nada se borra nunca**: una excepción vencida o revocada sigue en la lista con su
   historia completa (quién la registró, quién la prorrogó y por qué, quién la revocó y por
   qué). No hay ninguna operación de borrado en el módulo ni en la interfaz.

### Explotación activa (KEV): advertir con confirmación, no prohibir

Decisión: **se advierte y se exige confirmación explícita**, con tres candados añadidos:

* aviso en rojo en pantalla con **los CVE concretos** que CISA declara explotados;
* **casilla de confirmación obligatoria**: el primer envío del formulario nunca registra
  nada, solo devuelve la advertencia;
* **medida compensatoria obligatoria** y **plazo máximo de 30 días** en lugar de 365,
  también para las prórrogas.

Por qué no se prohíbe: una prohibición no elimina la decisión, la saca de la plataforma. El
jefe de proceso que necesita esperar quince días seguiría esperando, pero sin excepción
registrada: la vulnerabilidad se quedaría en la cola como ruido permanente o alguien la
marcaría «mitigada» a mano, sin dueño y sin fecha. Se perdería justo lo que la auditoría
pide. Con la advertencia dura, el riesgo queda aceptado *por escrito*, con nombre, con
medida compensatoria, por treinta días como máximo y marcado con la insignia KEV en la
lista, en el indicador «Con explotación activa» y en el correo de aviso.

## 7. Permisos

Se usan los conjuntos que ya existen en `webui/auth.py`; no se ha creado ningún sistema de
permisos paralelo ni se ha tocado ese fichero.

| Perfil | Ver | Solicitar | Crear | Prorrogar | Revocar |
| --- | --- | --- | --- | --- | --- |
| `admin` | sí | sí | sí | sí | sí |
| `operador_soc` | sí | sí | sí | sí | sí |
| `servicios_tecnologicos` | sí | sí | no | no | no |
| `redes` | solo servidores | no | no | no | no |
| `mantenimiento` | solo equipos de cómputo | no | no | no | no |
| `viewer` | sí | no | no | no | no |

* **Crear, prorrogar y revocar** = `auth.ROLES_OPERACION` (`admin`, `operador_soc`), el
  mismo conjunto que ya decide el estado de una amenaza y evalúa un CVE contra un activo.
  Aceptar un riesgo es esa misma clase de decisión operativa, así que reutilizarlo evita
  que dos listas de permisos se separen con el tiempo.
* **Solicitar** (`servicios_tecnologicos`): el formulario se envía a `/excepciones/solicitar`
  y **no crea nada**. Valida los mismos campos, deja la solicitud en el registro de
  auditoría (`action='excepciones.solicitud'`) y la enseña en el panel «Solicitudes de los
  últimos noventa días» de la propia página, para que el SOC la registre o la descarte. Así
  quien *pide* el riesgo y quien lo *acepta* no son la misma persona, que es lo que hace
  útil una aceptación de riesgo. No se ha añadido un estado `solicitada` a la tabla para no
  romper los tres estados que pidió el usuario ni convertir la solicitud en algo que
  parezca media excepción.
* **Alcance por tipo de máquina**: `redes` y `mantenimiento` ven solo las excepciones de sus
  máquinas **y las de un CVE en toda la organización**, porque esas también tapan
  vulnerabilidades de sus máquinas. Se aplica con `auth.alcance_origen()` en el servidor y
  con `auth.exigir_alcance()` en el filtro `?activo=<id>`, que responde **404** (no 403)
  para un activo del otro tipo: la misma respuesta que un identificador inventado, para no
  revelar que existe.
* Toda ruta GET lleva `@auth.requiere_login`; toda ruta POST, `@auth.requiere_csrf` más la
  comprobación de rol.

## 8. Aviso anticipado (ejecución diaria)

`excepciones.avisar(conn, cfg=cfg, mailer=mailer)` envía un correo de administración
(`notify.render_admin_email`, la misma estética que el aviso de caducidad del certificado)
con dos secciones: **ya vencidas** y **vencen en los próximos N días**.

* **N** sale del ajuste nuevo **`excepciones_aviso_dias`**, por omisión **15**.
* **Va en la ejecución diaria, no en el resumen semanal.** El semanal puede llegar hasta
  seis días tarde: una excepción avisada con quince días de antelación se quedaría con
  nueve, y una que venció el martes seguiría sin avisarse el domingo, con la vulnerabilidad
  ya de vuelta en la cola y nadie enterado. Para que no sea ruido, **cada excepción entra en
  un correo como mucho una vez por semana en cada situación** («por vencer» y «vencida»),
  con el mismo mecanismo de silencio que usa el certificado (`admin_notices`, tipo
  `excepciones`, 168 horas). Una excepción que se prorroga vuelve a ser avisable
  (`avisado_at` se pone a NULL y la clave del silencio incluye la fecha de vencimiento).
* Severidad `critical` (asunto «ACCION REQUERIDA») si hay alguna vencida; `warning` si solo
  hay por vencer.
* Destinatarios: los de administración (`admin_to`). El responsable que acepta el riesgo
  aparece con nombre y correo **en el cuerpo** del mensaje, pero no se le escribe
  directamente: el SMTP interno solo acepta destinatarios del dominio de la empresa y el
  responsable puede no tener buzón. Si en el futuro se quiere avisar también al responsable,
  el sitio es esa lista de destinatarios, con la comprobación de dominio de
  `alertas_proceso.aviso_dominio`.
* Si no hay destinatarios de administración, o si el servidor de correo no acepta el envío,
  **no se marca nada como avisado**: el aviso se reintenta al día siguiente.

## 9. Interfaz

`/excepciones/` (entrada de menú «Excepciones» en el grupo Inventario, junto a
Remediación, porque es su contrapartida: lo que sale de la cola con un responsable y una
fecha). Seis paneles, con recorrido guiado (`data-tour` 1 a 6):

1. **Título** con el propósito y los plazos máximos.
2. **Cuatro indicadores**: vigentes (y cuántas vulnerabilidades tapan), vencen pronto,
   vencidas sin decisión, con explotación activa. Los colores solo con significado: ámbar
   para el riesgo aceptado que sigue en pie, rojo para el vencido sin decisión, verde para
   el cero, gris para lo neutro.
3. **Formulario de alta** (o de solicitud, o la explicación si el perfil no puede ninguna
   de las dos cosas), con etiqueta visible en cada campo y toda la validación en servidor.
   Al fallar, la página se vuelve a pintar **con lo que ya se había escrito**.
4. **Filtros**: situación (vigentes, vencen en N días o menos, vencidas, revocadas), qué
   cubre, proceso de negocio y buscador por CVE, paquete, activo, responsable o
   justificación.
5. **Lista** paginada de 20 en 20, **con las que exigen decisión arriba** (vencidas, luego
   las que vencen pronto, luego el resto por fecha y al final las revocadas). Cada fila
   lleva un `<details>` con la trazabilidad completa y, para quien puede, los formularios
   de prórroga y revocación (también `<details>`, HTML puro). Revocar pide confirmación con
   `data-confirm`, que atiende `app.js`.
6. **Solicitudes** de los últimos noventa días, leídas del registro de auditoría.

Sin `style=`, sin `on*=`, sin `<script>` en línea y sin una sola regla de CSS nueva: todas
las clases usadas ya existen en `estilo.css`.

## 10. Aplicado: las cifras y la cola respetan la excepción (2026-09-10, tarde)

Ya está hecho. La condición se pegó **en los mismos sitios donde se aplica la exclusión de
la severidad baja**, que es la regla que hace todo esto verificable con un `grep`: las dos
condiciones significan lo mismo, «esta fila no cuenta».
`tests/test_excepciones_aplicadas.py::TestReglaDelGrep` recorre el árbol de sintaxis de
`threatintel/remediacion.py` y de `threatintel/aplicabilidad.py` y falla si alguna función
deja fuera la severidad baja y no el riesgo aceptado.

### 10.1 Sitio por sitio

`threatintel/remediacion.py` (gemelos `_SIN_EXCEPCION_SQL` y `_y_sin_excepcion` junto a los
de la severidad baja):

| Función | Qué se pegó |
|---|---|
| `_filtros_sql` | parámetro `sin_excepcion` y la condición, incondicional (ningún parámetro de la dirección la desactiva) |
| `contar`, `listar` | pasan `excepciones.hay_excepciones(conn)` |
| `contar_actualizaciones`, `pagina_actualizaciones` | igual, y lo propagan a `_cte_firmas`, `_paquetes_de_fusiones`, `_detalle_de_grupos` y `_paquetes_hermanos` |
| `resumen` | en los cuatro sitios de la exclusión de bajas: la consulta principal (`de_donde`), el reparto por tipo de máquina, el reparto por proceso y las llamadas a `_cte_firmas`; devuelve `"sin_excepcion": bool(...)` |
| `_serie_semanal` | las dos series (detectadas y corregidas) |
| `_cte_firmas` | la firma de fusión: una vulnerabilidad aceptada no puede fijar la versión objetivo ni partir una fusión |
| `_detalle_de_grupos`, `_paquetes_hermanos` | el detalle y los paquetes hermanos de la página |
| `procesos` | un proceso cuyas únicas pendientes están aceptadas no aparece en el selector |
| `_remediaciones_del_grupo` | la acción de grupo actúa **exactamente** sobre las filas que la página enseña |

**NO** se pegó, a propósito, en `contar_historial_activo`, `historial_activo` (la ficha del
activo y su historial: la fila debe seguir viéndose, con su insignia) ni en `sincronizar`
(la remediación se sigue abriendo, comprobando, cerrando y reabriendo igual: la excepción
caduca sola y el día que venza la cola tiene que quedar como si nunca hubiera existido, con
su fecha de detección real). Los tres llevan el comentario que lo explica.

`threatintel/queries.py`:

* `resumen_amenazas`: la condición en `base` (y por tanto en el total, el reparto por tipo
  de máquina y el reparto por proceso), en `confirmadas_global` y en `confirmadas_en`;
  devuelve `con_excepciones` y `vulnerabilidades_aceptadas`, que es la **diferencia exacta**
  entre lo que habría y lo que hay (no un conteo de filas cubiertas: un par activo-CVE con
  un paquete cubierto y otro pendiente NO desaparece de las cifras, así que no se puede
  contar como aceptado).
* `procesos_del_parque`: el selector no ofrece un proceso cuyas cifras saldrían a cero.
* `_adjuntar_activos_afectados`: las dos consultas (por `threat_id` y por `cve`) cuentan
  aparte los activos cuyo riesgo está aceptado (`activos_afectados_aceptados`), así que un
  riesgo aceptado **no dispara la alerta diaria por afectación confirmada** y el motivo que
  se registra es el suyo, `riesgo_aceptado`, y no «sin afectación confirmada», que sería
  falso. Con cero excepciones vigentes la columna no se pide y la consulta es la de siempre.
* Motivo de exclusión nuevo **`riesgo_aceptado`** con su texto en los tres sitios
  (`MOTIVO_EXCLUSION_ES`, `notify.MOTIVOS_FILTRO_ES` y `digest.FRASES_MOTIVO`), para que el
  correo diga con su nombre por qué no alertó. **Excepción razonada**: una vulnerabilidad
  con explotación activa confirmada (CISA KEV) sigue alertando aunque su riesgo esté
  aceptado, si el ajuste `alert_kev_sin_activos` está activo, igual que la explotación
  activa pesa más que la severidad baja; en ese caso el correo NO dice «no confirmado en
  ninguna máquina» (sería mentira) y la vista lleva `riesgo_aceptado_vigente`.
* **NO** en `top_tecnologias` ni en `evolucion_mensual` (series del catálogo, no del parque).

`threatintel/aplicabilidad.py` (gemelo local `_y_sin_excepcion`, cuyo docstring escribe la
frontera): sí en `versiones_pedidas_por_paquete`, en el bloque de sistemas de
`anotar_version_ultima_sistemas`, en `activos_distintos`, en `plan_remediacion` y en las dos
consultas de vulnerabilidades confirmadas de `resumen_informe`. **NO** en
`contar_veredictos_activo`, `veredictos_de_activo`, `conteo_activo`,
`vulnerabilidades_activo` ni en nada que evalúe o recalcule: el veredicto de aplicabilidad
es un **hecho técnico** y la excepción es una **decisión de riesgo**.

Los dos casos dudosos, con su porqué:

* `activos_de_amenaza` (la tabla de activos de la ficha de la amenaza): **no** se filtra. Es
  una lista, no una cifra de riesgo, y es donde hay que poder ver que ese servidor sigue
  teniendo la versión vulnerable; si se filtrara, la tabla saldría vacía mientras los
  recuentos guardados de la evaluación seguirían diciendo 326 activos en el caso mayor de
  producción: dos cifras de lo mismo en la misma pantalla. Los activos cubiertos se marcan
  con la insignia «Riesgo aceptado». Lo que sí queda fuera es el **plan de remediación** de
  esa amenaza, que es la orden de trabajo.
* `adjuntar_resumen`: **no** se filtra. Lee los recuentos guardados de
  `aplicabilidad_amenaza`, que son el resultado de la última evaluación técnica; restar ahí
  las excepciones haría que el motivo guardado fuera `sin_activos_afectados` («los activos
  ya llevan la corrección»), que es falso. Quien decide callar la alerta es
  `_adjuntar_activos_afectados`, que cuenta contra la base en el momento.

`webui/vistas/remediaciones.py`: la condición en `_cifras_pendientes_del_activo` (la
consulta que ya llevaba la de bajas); `_cifras_riesgo_aceptado`, que dice en **una** consulta
cuántas vulnerabilidades y cuántas filas están fuera de la cola por una aceptación de riesgo
(otra vez como diferencia exacta); e `indice_riesgo_aceptado` + `marcar_riesgo_aceptado`,
que resuelven las excepciones vigentes de **una vez** (una consulta por página) y cruzan en
Python: nunca una consulta por fila.

Interfaz: insignia ámbar «Riesgo aceptado» con la fecha de vencimiento, los días que
faltan, el responsable y el enlace a `/excepciones/` en el historial de la ficha del activo
(`_remediaciones_activo.html`, con `excepciones.por_activo`), en la tabla de activos
afectados de la ficha de la amenaza (`amenaza_detalle.html`, con `excepciones.por_cve` y el
índice de vigentes para el alcance por paquete) y en la vista por vulnerabilidad de
Remediación. Aviso de cabecera en las dos fichas y fila propia «Vulnerabilidades con el
riesgo aceptado» en el panel «Qué cuenta cada cifra» de Remediación, con enlace a la página
de Excepciones. La insignia va corta (`.insignia` lleva `white-space: nowrap`: una frase
dentro estira la tabla) y la fecha, el responsable y el enlace van en texto debajo, nunca
solo en un `title`. **Sin una sola regla de CSS nueva.**

Ajuste `excepciones_aviso_dias` expuesto en Ajustes (grupo «Alertas diarias», entero de 1 a
120) y métricas para Zabbix en `/salud.json`: `ti.excepciones.vencidas`,
`ti.excepciones.por_vencer` y `ti.excepciones.vulnerabilidades_cubiertas`.

### 10.2 Medido sobre una copia de la base real (2026-09-10)

Copia con la API `backup` (179.429 filas de `aplicabilidad`, 66.326 remediaciones, 48.216
abiertas), cinco excepciones representativas —una por alcance, una vencida, una revocada y
la que más filas cubre (el paquete `windows` de un equipo, 1.358 filas)— y borrada al
terminar. Las tres vigentes cubren **1.742 vulnerabilidades** y 2.107 filas:

| Medida | Antes | Después |
|---|---|---|
| Filas pendientes (`resumen.abiertas`) | 45.442 | 43.335 |
| Vulnerabilidades pendientes (pares activo-CVE) | 32.731 | 30.989 |
| Actualizaciones pendientes | 6.054 | 6.053 |
| Activos con pendientes | 601 | 600 (346 servidores y 254 equipos de cómputo) |
| Filas de la gráfica semanal (detectadas) | 49.931 | 47.824 |
| Vulnerabilidades confirmadas (Amenazas) | 30.254 | 28.512 |
| Activos afectados (Amenazas) | 597 | 596 |
| Amenazas confirmadas | 1.665 | 1.664 |
| Críticas / altas / medias | 3.424 / 17.124 / 9.706 | 3.384 / 15.820 / 9.308 |
| Informe mensual: activos afectados / vulnerabilidades | 557 / 14.071 | 556 / 13.124 |
| `vulnerabilidades_aceptadas` (Amenazas) | 0 | **1.742** |

Las dos cifras cuadran entre módulos: lo que desaparece de la cola (32.731 − 30.989 =
1.742) es exactamente lo que Amenazas declara como riesgo aceptado.
`excepciones.vulnerabilidades_cubiertas` dice **1.745**, tres más, y es correcto: cuenta los
pares con **alguna** fila cubierta, y hay tres pares cuyo otro paquete sigue pendiente, así
que no desaparecen de las cifras. Conviene que la página de Excepciones lo diga con esa
precisión (pendiente para el módulo, apartado 12).

Comprobado además, sobre la misma copia:

* la ficha del activo **no cambia**: historial de 1.355 filas antes y después, y los
  veredictos (1.420) y `conteo_activo` idénticos;
* `plan_remediacion` de ese activo pasa de 1 grupo a 0: la orden de trabajo ya no manda
  corregir lo aceptado;
* `sincronizar` dos veces seguidas: 0 nuevas, 0 cerradas y las 1.358 filas cubiertas siguen
  **pendientes** (nada se borra ni se cierra);
* la alerta: la amenaza del CVE aceptado en toda la organización queda con
  `activos_afectados_presentes = 0`, `activos_afectados_aceptados = 386` y motivo
  **`riesgo_aceptado`**.

**Coste.** Con **cero** excepciones vigentes el ayudante devuelve cadena vacía y las
consultas quedan **exactamente** como estaban (`_y_sin_excepcion(conn) == ""`, comprobado en
las pruebas). Con excepciones vigentes, medido en la copia:

| Consulta | Sin la condición | Con la condición |
|---|---|---|
| `COUNT(*)` de la cola abierta | 1,3 ms | 45,1 ms |
| Pares (activo, CVE) confirmados | 76,5 ms | 120,0 ms |
| `remediacion.resumen` (30 días) | 415 ms | 646 ms |
| `remediacion.contar` | 31 ms | 71 ms |
| `contar_actualizaciones` | 188 ms | 257 ms |
| `pagina_actualizaciones` (20 filas) | 299 ms | 414 ms |
| `queries.resumen_amenazas` | 609 ms | 893 ms |
| `aplicabilidad.resumen_informe` | 944 ms | 1.011 ms |
| `versiones_pedidas_por_paquete` (300 pares) | 77 ms | 129 ms |
| `activos_distintos` (300 amenazas) | 5,0 ms | 9,1 ms |
| Cifra «vulnerabilidades con el riesgo aceptado» | — | 161 ms |
| `/salud.json` (`health.exportar_metricas`) | 11 ms | 89 ms |

De los 284 ms de más de `resumen_amenazas`, unos 150 son la consulta añadida que calcula
`vulnerabilidades_aceptadas`, y solo se ejecuta cuando hay alguna excepción vigente. Los 78
ms de `/salud.json` son `excepciones.resumen` → `vulnerabilidades_cubiertas`, que recorre
`aplicabilidad`; si Zabbix consulta cada minuto conviene añadir a `excepciones.resumen` un
parámetro para omitir esa cifra (apartado 12).

### 10.3 Pruebas

`tests/test_excepciones_aplicadas.py`, 26 pruebas, base temporal bajo `data/`, sin red y
sin correo: que una excepción vigente saca la vulnerabilidad de la cola, de los indicadores,
del reparto por proceso, del avance por tipo de máquina, de la gráfica semanal y de las
cifras de Amenazas; que NO la saca de la ficha del activo, de su historial, de los
veredictos ni de `sincronizar`, y que ahí aparece con su insignia y su fecha; que al vencer
vuelve sola y que la revocación la devuelve en el acto; los tres alcances (el CVE en toda la
organización tapa sus tres activos, el paquete tapa solo ese paquete y no toca otros
activos); que la alerta diaria no dispara por un riesgo aceptado y el motivo registrado es
`riesgo_aceptado`, con la explotación activa como excepción razonada; que el conteo
«vulnerabilidades con el riesgo aceptado» cuadra con lo que desaparece; que con cero
excepciones nada cambia; las métricas de Zabbix; el ajuste de días de aviso y su rango; y la
regla del `grep` sobre el árbol de sintaxis de los dos módulos.

Suite completa: **1.497 pruebas en verde** (1.471 anteriores + 26).

## 11. Lo que sigue sin respetar la excepción (para el coordinador)

Tres ficheros que no pertenecen a esta tarea calculan cifras de riesgo y **todavía cuentan
las vulnerabilidades con el riesgo aceptado**. Mientras no se toquen, la página de Activos y
el Panel dirán cifras un poco más altas que Amenazas y Remediación:

1. `threatintel/ocs.py`: `resumen()` (tarjeta «Con vulnerabilidades confirmadas» de la
   página de Activos y del correo) y `estado_activos()`. Es la que el documento original ya
   señalaba.
2. `webui/vistas/panel.py`: las consultas locales de vulnerabilidades del Panel
   (líneas de `_cifras_por_origen` y siguientes).
3. `webui/vistas/activos.py`: `_subconsultas`, `_existe_afectado` y `_existe_kev` (la
   columna «Afectados» de la lista, el atajo «Afectados» y el orden por riesgo). **No se
   aplicaron a propósito**: la tarjeta grande de esa misma página sale de `ocs.resumen`, y
   cambiar solo la mitad dejaría dos cifras distintas de lo mismo en la misma pantalla, que
   es el defecto que este proyecto no admite. Los tres puntos se aplican juntos, con la
   forma `excepciones.y_sin_excepcion(conn, activo="ap.activo_id", cve="ap.cve",
   paquete="ap.paquete")`.
4. `threatintel/parches.py`: «Correcciones pendientes» (`_y_sin_bajas` en cuatro sitios) es
   la cola de lo que **todavía no tiene parche**; con una excepción vigente sobre esas
   vulnerabilidades, la página seguirá contándolas.

## 12. Pendientes del propio módulo de excepciones

* `excepciones.vulnerabilidades_cubiertas` cuenta los pares con **alguna** fila cubierta
  (1.745 en la medición) y la página lo presenta como «vulnerabilidades fuera de las
  cifras», que son 1.742. Son tres pares cuyo otro paquete sigue pendiente: conviene decir
  «vulnerabilidades cubiertas por alguna excepción» o calcular la diferencia exacta, como
  hacen `queries.resumen_amenazas` y `webui.vistas.remediaciones._cifras_riesgo_aceptado`.
* `excepciones.resumen()` calcula siempre esa cifra (78 ms sobre la base real): un parámetro
  `con_cubiertas=False` dejaría `/salud.json` en los 11 ms de antes.
* La página de Excepciones puede dejar de decir que la exclusión «todavía no se aplica»:
  ya se aplica.

## 13. Pruebas del módulo (2026-09-10, mañana)

`tests/test_excepciones.py`, 62 pruebas, base temporal bajo `data/`, sin red y sin enviar
un solo correo (Mailer falso). Cubren: alta con todos los campos y sin cada uno de ellos;
los tres alcances; el índice único; la explotación activa (advertencia, confirmación,
medida compensatoria y plazo corto); que una excepción vigente saca la vulnerabilidad de la
cola y de las cifras y que **al vencer vuelve sola**; que la revocación la devuelve en el
acto; que una vencida o revocada no cuenta como vigente en ninguna cifra; que el SQL y el
Python del vencimiento coinciden en los días frontera; las prórrogas y sus topes; el aviso
anticipado con su silencio semanal, sin destinatarios y con un correo rechazado; los
permisos de los seis perfiles; el 404 uniforme fuera de alcance; el CSRF de las cuatro
rutas de escritura; la auditoría con quién, cuándo, qué y desde qué dirección; y la
plantilla (recorrido guiado, `<div>` cuadrados, sin `style=` ni `on*=`, etiqueta visible en
cada campo y números con el filtro español).

`tests/test_esquema.py` añade la comprobación de la tabla, sus cuatro índices y la versión
13.

---

# 14. Excepciones permanentes, sin fecha de vencimiento (2026-09-10, tarde)

> Petición del usuario: «en excepciones se debe agregar la opción de **fecha permanente**,
> ya que no va a tener una fecha de vencimiento».

El apartado 6.1 de este mismo documento decía lo contrario: «fecha de vencimiento
obligatoria… una aceptación de riesgo a más de un año no es una aceptación, es un
abandono con papeles». **Manda la decisión del usuario y se implementa.** Pero el
argumento que había detrás —que nada quede olvidado— sigue siendo válido, así que lo que
se quita (el vencimiento) se sustituye por otra cosa que cumpla la misma función: un
**recordatorio de revisión periódica**.

## 14.1 Modelo de datos (`SCHEMA_VERSION` 14 → 15)

| Columna | Tipo | Para qué |
| --- | --- | --- |
| `vence_at` | TEXT, **ahora anulable** | fecha `AAAA-MM-DD`; **NULL y solo NULL cuando es permanente** |
| `vence_at_inicial` | TEXT, ahora anulable | la primera fecha que tuvo; NULL si nació permanente |
| `permanente` | INTEGER NOT NULL DEFAULT 0 | 1 = riesgo aceptado sin fecha de vencimiento |
| `revisada_at` | TEXT | última confirmación de que sigue siendo válida |
| `revisada_por` | TEXT | quién la confirmó |
| `revisada_nota` | TEXT | nota opcional de esa revisión |
| `revisiones` | INTEGER NOT NULL DEFAULT 0 | cuántas revisiones se han confirmado |
| `revision_avisada_at` | TEXT | último recordatorio de revisión enviado por correo |

Índice nuevo `idx_exc_permanente(permanente, estado, revisada_at)`, y una **restricción
`CHECK`**:

```sql
CHECK ((permanente = 1 AND vence_at IS NULL)
    OR (permanente = 0 AND vence_at IS NOT NULL))
```

**Por qué dos columnas y no una.** Con solo `vence_at IS NULL` bastaría para saber que es
permanente, pero la intención quedaría implícita: un NULL puede ser también un dato que
falta. Con solo `permanente = 1` habría que decidir qué guardar en `vence_at`, que es
`NOT NULL` desde la v13. Se guardan las dos y el `CHECK` impide que se contradigan: sin
él, un fallo de código podría dejar una permanente **con** fecha (y la avisaría como «por
vencer») o una temporal **sin** fecha (y no vencería nunca, en silencio). El `CHECK` es la
única forma de que eso sea imposible y no solo improbable.

**Por qué NO se guarda una fecha lejana.** Lo pidió el usuario expresamente y es lo
correcto: un `vence_at = '9999-12-31'` sería falso en la base, lo leería la auditoría, lo
imprimiría cualquier informe y colaría la excepción en el aviso de «vence pronto» el día
que alguien subiera `excepciones_aviso_dias`. La ausencia de fecha se representa con la
ausencia de fecha.

## 14.2 Cómo migra (v14 → v15)

`vence_at` era `TEXT NOT NULL` y **SQLite no sabe quitar un NOT NULL con `ALTER TABLE`**,
así que hay que **reconstruir la tabla**. Lo hace `db.reconstruir_excepciones()`, que
`init_db()` llama **lo primero**, antes de `migrar_columnas` y de `SCHEMA` (si fuera
después, los índices recién creados se perderían al borrar la tabla vieja y no volverían
hasta la siguiente ejecución):

1. si la tabla no existe (base nueva) o ya tiene `permanente`, no hace nada y devuelve `False`;
2. `PRAGMA foreign_keys=OFF`, `BEGIN`;
3. crea `excepciones_v15` con la definición **nueva**;
4. copia las 23 columnas de la v14 por nombre (`_COLUMNAS_EXCEPCIONES_V14`, escritas a
   mano y no leídas de la tabla vieja, para no arrastrar una columna añadida a mano);
5. **compara el número de filas** antes y después y aborta la transacción si no coincide;
6. `DROP TABLE excepciones`, `ALTER TABLE excepciones_v15 RENAME TO excepciones`;
7. `PRAGMA foreign_key_check(excepciones)` y aborta si hay algo roto;
8. `COMMIT` y `PRAGMA foreign_keys=ON`. Los índices los vuelve a crear `SCHEMA` justo
   después (`CREATE INDEX IF NOT EXISTS`).

La definición de la tabla vive en **una sola constante**, `db._DDL_EXCEPCIONES`, con un
hueco para el nombre: la usan tanto el esquema (`SCHEMA = _SCHEMA_BASE +
_DDL_EXCEPCIONES.format(tabla="excepciones") + _INDICES_EXCEPCIONES`) como la
reconstrucción. Así la tabla que sale de una instalación nueva y la que sale de migrar son
idénticas **por construcción**, no por disciplina. Es la misma razón por la que la tabla no
entra en `_COLUMNAS_NUEVAS` (y por tanto no puede repetir la clave que rompió la migración
del 2026-09-06).

## 14.3 Vigencia: qué cambia en el único sitio donde se calcula

`threatintel/excepciones.py`, tal como estaba escrito, seguía siendo el único sitio:

```python
SQL_VIGENTE = ("(e.estado = 'vigente' "
               "AND (e.permanente = 1 OR date('now') <= substr(e.vence_at, 1, 10)))")
SQL_ESTADO  = ("CASE WHEN e.estado = 'revocada' THEN 'revocada' "
               "WHEN e.permanente = 1 THEN 'vigente' "
               "WHEN date('now') > substr(e.vence_at, 1, 10) THEN 'vencida' "
               "ELSE 'vigente' END")
SQL_DIAS_RESTANTES = ("CASE WHEN e.permanente = 1 THEN NULL ELSE "
                      "CAST(julianday(...) - julianday(date('now')) AS INTEGER) END")
```

* Una permanente **está siempre vigente** mientras no se revoque.
* **Nunca puede dar «vencida»**: no hay fecha que pasar.
* **Los días restantes son NULL, no un número.** `dias_restantes()` devuelve `None` y
  `_fila()` deja la clave a `None`. Es deliberado y algo incómodo: obliga a que cada
  pantalla decida qué escribe cuando no hay número, en lugar de imprimir el cero que
  `| numero` habría producido. La lista escribe «No vence» y «Permanente (sin fecha de
  vencimiento)».
* **«Permanente» NO es un cuarto estado.** Los estados siguen siendo tres (vigente,
  vencida, revocada) y lo permanente es una **propiedad** (`permanente`), con su propia
  insignia. Si fuera un estado habría que preguntar «¿está vigente?» en dos sitios.

Expresiones nuevas, en el mismo módulo y con su espejo en Python
(`dias_sin_revisar`, `necesita_revision`):

```python
SQL_BASE_REVISION    = "COALESCE(e.revisada_at, e.registrado_at)"
SQL_DIAS_SIN_REVISAR = "CAST(julianday(date('now')) - julianday(substr(<base>,1,10)) AS INTEGER)"
sql_pendiente_revision(":revision")  # permanente + vigente + días >= plazo
```

Repasados uno a uno todos los usos: `sql_sin_excepcion` (la condición que saca las
vulnerabilidades de la cola y de las cifras, que hereda la permanencia sin tocarse),
`SQL_CANDIDATAS`, `hay_excepciones`, `_filtros`, `_ORDEN`, `contar`, `listar`, `obtener`,
`por_activo`, `por_cve`, `cubre`, `resumen`, `vulnerabilidades_cubiertas`,
`pendientes_de_aviso`, `avisar` y `webui.vistas.remediaciones.excepciones_vigentes`.

## 14.4 Avisos: una permanente no vence, así que no se avisa de que va a vencer

`pendientes_de_aviso()` lleva ahora `AND e.permanente = 0` **escrito explícitamente**,
aunque `SQL_DIAS_RESTANTES` ya devolvería NULL para ellas y `NULL <= 15` no es cierto: se
lee de un vistazo y no depende de cómo trate SQLite los nulos en una comparación.

Lo demás **no cambia**, y hay una prueba dedicada que lo fija (comportamiento verificado
por el coordinador el 2026-09-10): con quince días de antelación entra una que vence en
tres días y una vencida hace dos, y queda fuera una que vence dentro de doscientos.

## 14.5 La salvaguarda: recordatorio de revisión periódica

Es lo que sustituye al vencimiento y lo que responde a la preocupación real del usuario.

* **Ajuste nuevo `excepciones_revision_dias`**, por omisión **180** días, rango de **30 a
  730**. Está en `config.DEFAULT_SETTINGS` y expuesto en Ajustes, grupo «Alertas diarias»,
  con la ayuda escrita. **Viene activado y no se puede desactivar** poniéndolo a cero: el
  rango empieza en 30. Por debajo sería ruido (llegaría antes de que nada pudiera cambiar)
  y por encima de dos años dejaría de ser una salvaguarda.
* **Desde cuándo se cuenta**: `COALESCE(revisada_at, registrado_at)`.
* **Qué pasa al cumplirse el plazo**: la excepción entra en el correo diario de
  administración en una sección propia, «Permanentes que llevan más de N días aceptadas sin
  revisarse (siguen vigentes)», con la frase exacta «lleva N días aceptada sin revisarse:
  confirme que sigue siendo válida o revóquela»; y sube al grupo 2 del orden de la página,
  con la insignia ámbar «Revisión pendiente».
* **NO es un vencimiento**, y las dos pantallas y el correo lo dicen con esas palabras: la
  excepción sigue vigente y su vulnerabilidad sigue fuera de la cola y de las cifras
  aunque nadie conteste nunca. El texto está en una sola constante
  (`REVISION_EXPLICACION`) para que la página y el correo no puedan decir cosas distintas.
* **Severidad del correo**: `critical` si hay alguna vencida, `warning` si hay alguna por
  vencer, e **`info`** si lo único que hay es el recordatorio de revisión. Un recordatorio
  no es una acción requerida.
* **Silencio semanal**, igual que el resto: la clave de `admin_notices` es
  `<id>|revision|<fecha desde la que se cuenta el plazo>`. Al confirmar la revisión esa
  fecha cambia y el ciclo empieza de cero; mientras nadie conteste, el mismo correo se
  repite una vez por semana. Se anota en `revision_avisada_at`, **una columna distinta** de
  `avisado_at`: con una sola, confirmar una revisión borraría la memoria del aviso de
  vencimiento.
* **Acción en la página**: «Confirmar la revisión» (`POST /excepciones/<id>/revisar`), que
  guarda `revisada_at`, `revisada_por`, `revisada_nota`, incrementa `revisiones`, pone
  `revision_avisada_at` a NULL y **audita** (`excepciones.revisar`).
* **La nota es opcional, a propósito.** La evidencia que pide la auditoría es quién y
  cuándo, y eso queda siempre. Exigir un texto largo cada seis meses para decir «sigue
  igual» conseguiría que nadie confirmara y que el recordatorio se volviera correo de
  fondo, que es justo lo que se quiere evitar.

## 14.6 Restricciones y por qué

| Regla | Dónde se aplica | Por qué |
| --- | --- | --- |
| **Solo `admin` concede lo permanente** | `webui/vistas/excepciones.py`, `ROLES_PERMANENTE = ("admin",)`; 403 para los demás | Una excepción con fecha se corrige sola el día que vence, así que equivocarse cuesta como mucho el plazo. Una permanente no se corrige nunca sola: ya no es una decisión operativa del turno |
| **Confirmar la revisión, también solo `admin`** | misma ruta y mismo conjunto | Reiniciar el plazo —decir «sigue siendo válida» y callar el recordatorio otros 180 días— es la misma decisión que concederla |
| **Ponerle fecha a una permanente lo puede el operador SOC** | `ROLES_GESTION` | Va en la dirección que **reduce** el riesgo: la excepción vuelve a caducar sola. No tiene sentido pedir más permisos para eso que para revocarla |
| **Nunca permanente con explotación activa confirmada (KEV)** | `threatintel/excepciones.py`, en `validar()` y en `convertir_en_permanente()` | Es la única prohibición dura del módulo. En una temporal la explotación activa se advierte y se admite treinta días porque **el plazo corto es la garantía**; sin plazo no queda ninguna. Va en el modelo y no solo en la pantalla, para que ninguna ruta futura pueda saltárselo. En la conversión se vuelve a consultar el catálogo de CISA **en ese momento**: un CVE puede entrar meses después de aceptarse el riesgo |
| **Justificación de 60 caracteres en lugar de 20** | `MIN_JUSTIFICACION_PERMANENTE` | Una temporal se corrige sola el día que vence; esta no, y su texto es lo único que leerá quien la audite dentro de tres años |
| **Un jefe de proceso sí puede *solicitar* una permanente** | `/excepciones/solicitar` | Una solicitud no registra nada: la decisión sigue siendo de administración, y prohibir pedirlo solo sacaría la conversación de la plataforma |

Discrepancia razonada con el criterio del coordinador: ninguna. Las tres restricciones que
pidió se aplican tal cual; lo único que se ha añadido por criterio propio es que la
prohibición de KEV se **vuelve a comprobar contra el catálogo actual** al convertir una
temporal en permanente, y que ponerle fecha a una permanente no exija ser administrador.

## 14.7 Prórroga, revocación y conversiones

| Operación | Sobre una temporal | Sobre una permanente |
| --- | --- | --- |
| Prorrogar | sí, con motivo y tope | **no**: «no tiene fecha de vencimiento, así que no hay nada que prorrogar» |
| Revocar | sí | **sí**, y la vulnerabilidad vuelve a la cola en el acto |
| Convertir | `convertir_en_permanente` (solo `admin`, motivo de 60 caracteres, veto KEV) | `convertir_en_temporal` (`ROLES_GESTION`, fecha con las reglas de siempre, motivo de 20 caracteres) |

* Convertir en permanente **cuenta como revisión** (`revisada_at` de hoy): alguien acaba
  de mirar la excepción y ha decidido; contar el plazo desde una fecha de registro de hace
  un año haría saltar el recordatorio el mismo día.
* `vence_at_inicial` conserva la primera fecha que tuvo la excepción; si nació permanente,
  la primera fecha que se le ponga se guarda como inicial.
* Auditoría: `excepciones.revisar`, `excepciones.permanente` y `excepciones.temporal`,
  además de las tres que ya había. El alta de una permanente se audita con
  `vence_at=permanente permanente=1`.

## 14.8 Interfaz

`webui/templates/excepciones.html` (recorrido guiado de 1 a 7, un paso más que antes) y
`webui/vistas/excepciones.py`:

1. **Título**: explica los dos plazos y que lo permanente se revisa cada N días.
2. **Cuatro indicadores** de siempre, sin cambios.
3. **Dos indicadores nuevos** (`rejilla c2`): «Permanentes (sin fecha de vencimiento)» y
   «Permanentes pendientes de revisión», con la advertencia de que siguen vigentes.
4. **Formulario**: grupo de dos opciones «Con fecha de vencimiento» / «Permanente (sin
   fecha de vencimiento)». Para el perfil que no puede concederla, la segunda sale
   `disabled` con la explicación al lado.
5. **Filtros**: dos situaciones nuevas, «Permanentes» y «Permanentes pendientes de revisión».
6. **Lista**: insignia azul «Permanente» junto al alcance, insignia ámbar «Revisión
   pendiente» cuando toca, columna «Vence o se revisa» que para una permanente escribe «No
   vence» y cuándo toca revisarla, y trazabilidad con la última revisión y su nota.
   **Orden en seis grupos**, con las permanentes agrupadas aparte de las que vencen:
   vencidas (0), por vencer (1), permanentes sin revisar (2), resto de temporales (3),
   resto de permanentes (4), revocadas (5).
7. **Acciones**: «Confirmar la revisión» y «Ponerle fecha de vencimiento» en las
   permanentes; «Prorrogar» y «Quitarle la fecha (permanente)» en las temporales.

**Sin una sola regla de CSS nueva** (`rejilla c2`, `insignia info`, `insignia alto`,
`txt-alto` y `txt-b` ya existen), sin `style=`, sin `on*=` y sin `<script>`. Todos los
atributos `data-zona-viva`, `data-accion-viva`, `data-filtro-vivo` y `data-enlace-vivo`
del motor de actualización sin recarga se conservan, y las acciones nuevas los llevan.

### Lo único que falta y depende del coordinador

**Deshabilitar el campo de la fecha al marcar «Permanente» necesita JavaScript**, y
`webui/static/app.js` no es de esta tarea. La página **funciona igual sin él**: el campo
de la fecha ya no lleva `required` (con la opción permanente marcada tiene que poder
quedarse vacío), el servidor **ignora** la fecha si el plazo es permanente y la exige si no
lo es, y la ayuda visible lo explica. El HTML ya lleva los enganches
`data-grupo-vigencia="vence_at"` en el grupo de opciones y `data-campo-vigencia="temporal"`
en el campo de la fecha, para que añadirlo sea sumar un bloque a `app.js` sin tocar la
plantilla.

## 14.9 Las insignias de las otras pantallas (pendiente del coordinador)

Las insignias «Riesgo aceptado» de la ficha del activo, del detalle de la amenaza y de
Remediación viven en plantillas que **no** pertenecen a esta tarea. Hoy, con una excepción
permanente, escriben «hasta el - (0 días)»: la fecha no existe y `| numero` convierte el
`None` en un cero. Los datos ya llegan preparados (`permanente`, `vence_at` a `None`,
`dias_restantes` a `None` y `vigencia_es` con el texto exacto), así que solo falta el
cambio de texto. Está detallado, línea por línea, en el informe de la tarea.

## 14.10 Medido sobre una copia de la base real (2026-09-10, tarde)

Copia con la API `backup` (179.429 filas de `aplicabilidad`, 66.326 remediaciones, 918
activos, 380,8 MB), borrada al terminar.

* **Migración v14 → v15 con filas**: 5 excepciones creadas con el esquema v14 y migradas.
  `init_db()` tardó **13 milisegundos**, las cinco filas quedaron **idénticas** campo por
  campo, ninguna se volvió permanente, `PRAGMA integrity_check` dice `ok`,
  `PRAGMA foreign_key_check` no devuelve nada, los cinco índices están, la tabla de trabajo
  `excepciones_v15` no queda, y `aplicabilidad`, `remediaciones` y `activos` conservan su
  número de filas exacto. La segunda ejecución tardó **2 milisegundos** y no hizo nada.
* **Coste con cinco excepciones vigentes**, dos de ellas permanentes (el paquete
  `linux-tools-common` de un activo y un CVE presente en 386 activos), mínimo de tres
  pasadas:

| Consulta | Coste |
|---|---|
| `COUNT(*)` de la cola abierta, **sin** la condición | 1,3 ms |
| `COUNT(*)` de la cola abierta, condición **v14** (sin permanentes) | 42,3 ms |
| `COUNT(*)` de la cola abierta, condición **v15** | 46,9 ms |
| Pares (activo, CVE) confirmados, sin la condición | 72,6 ms |
| Pares (activo, CVE) confirmados, con la condición | 120,4 ms |
| `remediacion.contar()` | 85,9 ms |
| `remediacion.resumen(30 días)` | 671,2 ms |
| `queries.resumen_amenazas()` | 937,1 ms |
| `excepciones.resumen()` | 2,6 ms |
| `excepciones.resumen(con_cubiertas=False)` | 0,1 ms |
| `excepciones.listar(limite=20)` | 0,6 ms |
| `excepciones.contar(estado='revision')` | 0,0 ms |
| `excepciones.pendientes_de_revision()` | 0,1 ms |
| `excepciones.vulnerabilidades_cubiertas()` | 2,5 ms |
| Página `/excepciones/` completa | 168 ms |

  Las consultas **cuestan lo mismo que en la v14**: el `EXPLAIN QUERY PLAN` sigue dando
  `LIST SUBQUERY` + `SCAN e` (una materialización por subconsulta, no una por fila) y la
  condición añadida (`e.permanente = 1 OR …`) se evalúa sobre la tabla `excepciones`, que
  tiene decenas de filas. Los 4,6 milisegundos de diferencia en la cola son las 775 filas
  de más que la v15 sí reconoce como cubiertas. Con **cero** excepciones vigentes,
  `y_sin_excepcion()` sigue devolviendo cadena vacía y las consultas quedan exactamente
  como estaban.
* **Cuadre entre módulos**: las excepciones vigentes sacan 784 filas de la cola (48.216 →
  47.432) y 411 vulnerabilidades de las cifras (31.215 → 30.804);
  `excepciones.vulnerabilidades_cubiertas()` dice **411** y
  `queries.resumen_amenazas()["vulnerabilidades_aceptadas"]` dice **411**. Las mismas
  cifras que con excepciones temporales: una permanente sale de la cola y de las cifras
  exactamente igual.
* **El veto de KEV se disparó con datos reales**: el primer intento de aceptar de forma
  permanente el paquete con más filas del parque lo rechazó nombrando los tres CVE que
  CISA declara explotados (`CVE-2026-33824`, `CVE-2026-68820`, `CVE-2026-81963`).
* **Otras páginas con una permanente registrada**: `/excepciones/`, `/remediaciones/`,
  la ficha del activo y `/salud.json` responden 200.

## 14.11 Pruebas

`tests/test_excepciones_permanentes.py`, **44 pruebas**, base temporal bajo `data/`, sin
red y sin enviar un solo correo (Mailer falso): alta permanente y temporal; que la
permanente guarda NULL y nunca una fecha inventada; la justificación más larga; que una
temporal sin fecha se sigue rechazando; que la permanente no vence por mucho que pase el
tiempo y que sus días restantes no son un número; que el SQL y el Python coinciden; que no
entra en ningún aviso de vencimiento y que el comportamiento de las que sí vencen no
cambia; el recordatorio de revisión completo (se emite al pasar el plazo, dice que sigue
vigente, se silencia al confirmar, no se repite al día siguiente y sí a la semana, y no se
marca nada si el correo no sale); el correo con las tres situaciones a la vez y su
severidad; el ajuste y su rango; el veto de KEV en el alta, en el paquete que hereda una
KEV, en la conversión y con una KEV sobrevenida; las conversiones en los dos sentidos con
su validación y su auditoría; los permisos de los cuatro perfiles con sus 403; el CSRF y
el 404 de las tres rutas nuevas; y la página (insignias, cifras, filtros, orden agrupado,
botones por perfil, recorrido guiado y ausencia de un cero engañoso).

`tests/test_esquema.py` añade la comprobación de las columnas nuevas, del `CHECK` en sus
dos direcciones, del índice nuevo, de la versión 15 y **de la migración desde una base v14
con filas** (que no pierde ninguna, que los datos llegan intactos, que los índices vuelven,
que la tabla reconstruida es idéntica a la creada desde cero y que la segunda pasada no
hace nada).

Dos pruebas anteriores se adaptaron porque el cambio las afecta a propósito: el mensaje de
«falta la fecha» ya no dice «nunca es indefinida» (ahora sí puede serlo) y el título de la
página pasó de «Excepciones con vencimiento» a «Excepciones: riesgo aceptado», porque ya no
todas vencen.
