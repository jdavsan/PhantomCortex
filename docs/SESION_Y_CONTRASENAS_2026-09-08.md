# Sesión opaca, tiempo de sesión y rotación de credenciales

**8 de septiembre de 2026.** Peticiones del usuario, literales: «implementar el cambio de clave
cada 30 días por seguridad como rotación de credenciales y que no permita reutilizar
contraseñas»; «Establecer el tiempo de sesión máximo de 30 minutos»; «El valor de las cookies
debe estar ofuscado y no exponer información»; «las cookies deben tener secure, httponly y
samesite»; «valida el tiempo de validación de cada token donde siempre se pueda renovar después
de cierto tiempo»; «Ajustar el mensaje de error 403 donde no se mencione que requiera acceso de
administrador sino que solamente diga acceso inválido»; «valida vulnerabilidades del jwt».

## JWT

La aplicación **no usa JWT**: ni biblioteca instalada ni código. La sesión es un token opaco
aleatorio en una cookie, resuelto contra la base de datos; los vectores de ataque de JWT
(algoritmo «none», confusión de claves, tokens sin caducidad) no aplican.

## Sesión en servidor (`webui/sesion_servidor.py`)

- La cookie `session` es `secrets.token_urlsafe(32)` (43 caracteres, validada por forma antes
  de tocar la base). **No lleva ningún dato**: antes era la cookie firmada de Flask, un JSON en
  Base64 legible por quien la capturase (identificador de sesión y avisos).
- El estado vive en `web_sessions.datos` (JSON) indexado por `sid_hash = SHA-256(token)`, en la
  misma fila que ya guardaba usuario, perfil, CSRF, caducidad y segundo factor pendiente. Ahí
  van los avisos, el destino tras el segundo factor y el identificador de la contraseña generada
  que se muestra una sola vez (la contraseña misma no: ver «Contraseña generada» más abajo;
  corrección de la misma noche, la primera versión sí la guardaba aquí).
- Atributos: `HttpOnly`; `SameSite=Lax` (los enlaces de los correos deben abrir la plataforma
  con la sesión; Strict lo impediría; Lax bloquea igualmente POST y subrecursos de otro origen
  y todo formulario lleva CSRF); `Secure` con `webui_https`; `Path=/`; sin `Domain`; sin
  `Max-Age` (la duración la decide el servidor).
- Las sesiones anónimas (solo avisos antes de identificarse) se crean únicamente cuando hay algo
  que guardar; un acceso fallido no crea fila ni cookie. Las cookies firmadas antiguas se
  rechazan sin consultar la base: tras el despliegue cada persona se identifica una vez.
- El token se regenera al iniciar sesión, al superar el segundo factor y al completar el cambio
  obligatorio (protección contra fijación de sesión, con pruebas). Sigue habiendo una sola
  sesión por usuario.

## Tiempos

| Ajuste | Valor | Significado |
|---|---|---|
| `webui_session_minutos` | 30 | caduca a los 30 minutos **sin actividad**; cada petición autenticada la renueva |
| `webui_session_maximo_horas` | 12 | tope absoluto desde el acceso, para que la renovación no sea infinita |
| `webui_session_rotacion_minutos` | 15 | cada 15 minutos de actividad se emite un **token nuevo** (0 lo desactiva). El anterior sigue sirviendo **solo para leer durante 60 segundos** (ver «Corrección 2026-09-08 (noche)»); en el acceso, el segundo factor y el cambio obligatorio no hay gracia: el token viejo muere en el acto. El token CSRF no cambia en la rotación periódica para no romper formularios abiertos; sí cambia en esos tres momentos |

Al volver tras caducar, la pantalla de acceso dice «Su sesión caducó por inactividad tras 30
minutos. Vuelva a identificarse.» o «alcanzó la duración máxima de 12 horas». La fila caducada
se borra cuando el navegador la presenta. `webui_session_hours` ya no existe.

### Corrección 2026-09-08 (noche) · gracia de 60 segundos tras la rotación

La primera versión asumía este riesgo: «dos peticiones concurrentes justo en el límite de los
15 minutos pueden dejar a la segunda con el token viejo (redirige al acceso)». La revisión
adversaria del mismo día lo reprodujo con un caso real y peor: la respuesta tardía de la
petición vieja llegaba con `Set-Cookie: session=;` (el servidor pedía borrar la cookie por
token desconocido) y **pisaba la cookie nueva** que el navegador acababa de recibir, así que
la persona quedaba fuera aunque la primera petición hubiera ido bien. Con el filtro en vivo de
Activos o Amenazas, que dispara una petición por tecla, y con dos pestañas abiertas, no era un
caso teórico.

Lo que se cambió:

- `web_sessions.sid_hash_anterior` (esquema **v12**) guarda el hash del token anterior al rotar
  (`auth.renovar_identificador_sesion` con `rotar_csrf=False`). En el acceso, el segundo factor
  y el cambio obligatorio la columna se pone a NULL: ahí la fijación de sesión pesa más que la
  comodidad y el token viejo muere en el acto.
- `sesion_servidor.open_session` busca primero por `sid_hash`; si no hay fila, por
  `sid_hash_anterior` con `rotado_at` dentro de los últimos `auth.SEGUNDOS_GRACIA_ROTACION`
  (**60 segundos**). Si la encuentra, la sesión se marca `gracia`: se atiende la petición con
  los datos de la sesión pero `save_session` **no escribe nada ni toca la cookie** (la buena ya
  está en el navegador). 60 segundos cubre con holgura una petición en vuelo (la página más
  lenta medida el 7 de septiembre, la última de Software, tardaba 1.816 ms antes de paginar y
  184 ms después) y es un plazo demasiado corto para que una cookie copiada gane algo: seguiría
  sin poder escribir.
- Un token desconocido o fuera de la gracia **ya no pide borrar la cookie**: se responde como
  sesión vacía y la redirección al acceso decide el navegador con la cookie que tenga. Solo se
  pide borrar la cookie cuando la fila existe y ha caducado (inactividad o tope) o cuando la
  cookie no tiene ni la forma de un token.
- Precio asumido: los avisos (`flash`) que encolara una petición atendida en gracia se pierden,
  porque esa petición no escribe. Es preferible a expulsar a la persona.

Prueba: `tests/test_sesion_30_minutos.py` fuerza una rotación, repite la petición con el token
viejo desde otro cliente y exige 200 sin ningún `Set-Cookie`; adelanta `rotado_at` dos minutos
y exige la redirección al acceso; y comprueba que sigue habiendo **una sola fila** de sesión.

## Contraseñas

- `users.password_changed_at` (al migrar, todas las cuentas reciben la fecha de hoy para no
  expulsar a nadie el primer día) y tabla `password_historial(username, password_hash,
  cambiado_at)` recortada a las últimas 12.
- `auth.cambiar_password` es la única vía (perfil, cambio obligatorio, Usuarios,
  restablecimiento, `bin/gestionar_usuario.py`): rechaza la actual y las 12 anteriores con «No
  puede reutilizar ninguna de sus últimas 12 contraseñas.», comparando todas las filas para no
  revelar por tiempo cuál coincide.
- `password_max_dias` = 30 (0 = sin caducidad) y `password_historial` = 12, en Administración →
  Ajustes → Interfaz. Pasados 30 días la cuenta entra en el flujo bloqueante existente de cambio
  obligatorio («Su contraseña tiene más de 30 días: por política de seguridad debe cambiarla
  ahora»); desde cinco días antes, al entrar se avisa cuántos quedan. Mi perfil muestra «Último
  cambio de contraseña» y «Caducidad de la contraseña».

## Contraseña generada: una sola vez y solo en memoria (corrección 2026-09-08, noche)

Al crear un usuario con «Generar una contraseña segura automáticamente» o al restablecerla, la
contraseña se muestra una vez en un panel propio de Usuarios. La primera versión de la sesión
opaca la guardaba en `web_sessions.datos` hasta esa carga de página; la revisión de seguridad lo
señaló: la contraseña quedaba **en claro en la base de datos**, aunque fuera unos segundos, y una
copia de seguridad hecha en ese instante la conservaría. Ahora (`webui/vistas/usuarios.py`):

- la contraseña vive en un diccionario en memoria del proceso (`_CREDENCIALES_UNA_VEZ`) bajo un
  identificador aleatorio de 24 bytes; en la sesión del administrador viaja **solo ese
  identificador** (`credencial_una_vez`);
- la primera carga de la página de Usuarios la recoge (`_recoger_una_vez`), la borra del
  diccionario y quita el identificador de la sesión: al recargar ya no está;
- caduca a los **120 segundos** (`SEGUNDOS_CREDENCIAL_UNA_VEZ`): es el tiempo que tarda la
  redirección tras crear o restablecer, con margen; pasado el plazo se descarta y hay que
  restablecer de nuevo. Un reinicio del servicio en ese intervalo la pierde igual.

`tests/test_cookie_opaca.py` comprueba que en la sesión viaja una cadena (el identificador), que
la contraseña no aparece ni en la base ni en ninguna decodificación de la cookie, que el HTML la
muestra una vez y que después no está ni en memoria ni en la segunda carga.

## Inicio de sesión: un solo mensaje para todo fallo (corrección 2026-09-08, noche)

`auth.autenticar` responde «Usuario o contraseña incorrectos.» en los cuatro casos: usuario
inexistente, contraseña incorrecta, **cuenta deshabilitada** y **cuenta bloqueada
temporalmente**. Antes los dos últimos decían su motivo, y eso confirmaba a quien probaba que
el correo existía (un correo inexistente nunca se bloquea ni se deshabilita): el mismo oráculo
de enumeración que ya se había cerrado por tiempo con el hash ficticio de bcrypt (A07:2025). El
detalle no se pierde: la auditoría registra «la cuenta estaba deshabilitada», «la cuenta estaba
bloqueada temporalmente» o «contraseña incorrecta (intento N de M)», y la propia persona lo ve
en «Registro de mis accesos» de Mi perfil. El aviso «Cuenta bloqueada temporalmente. Vuelva a
intentarlo en …» solo se muestra en el segundo paso (código del segundo factor), cuando la
contraseña ya se validó y la existencia de la cuenta no es secreto para quien la escribió.

## Cambiar el perfil o deshabilitar una cuenta cierra sus sesiones

En Usuarios, al cambiar el rol de una cuenta o deshabilitarla, `auth.revocar_sesiones` borra
todas sus filas de `web_sessions` y la auditoría anota `sesiones_revocadas=N`. Sin esto, una
persona degradada de Administrador a Solo lectura seguiría operando con el perfil viejo hasta
que la sesión caducara (hasta 12 horas), porque el perfil se lee de la fila de sesión, no de
`users`, en cada petición. Cambiar la contraseña ya revocaba las sesiones; ahora el rol también.

## 403 y 405

- **403**: título «Acceso inválido», detalle fijo `auth.MENSAJE_403` («No tiene permiso para
  realizar esta acción.»). El manejador de `webui/app.py` ignora la descripción del `abort` y
  ningún `abort(403)` nombra un perfil; la plantilla `error.html` tampoco menciona al
  administrador. `tests/test_roles_alcance.py` lo comprueba para los cuatro perfiles nuevos.
- **405** (petición GET a una ruta que solo acepta POST, o al revés): antes salía la página en
  blanco de Flask en inglés. Ahora usa la misma plantilla con «Método no permitido» y el texto
  «Esta dirección solo acepta el envío de un formulario de la plataforma. Vuelva a la página
  anterior y use el botón correspondiente.». Prueba: `tests/test_seguridad_plataforma.py`
  acepta el código 405 en el barrido sin sesión y `test_405_con_mensaje_en_espanol_y_sin_pistas` fija el mensaje en español, sin nombres de ficheros internos ni menciones al administrador (añadida el 2026-09-09).

## Perfiles y alcance

Los seis perfiles (`auth.ROLES`), su alcance por tipo de máquina y las listas de permiso están
descritos en la tabla «Perfiles de acceso» del `README.md` y en la sección «Perfiles segmentados
(2026-09-08)» de `docs/DISENO_INTERFAZ_2026-09-03.md`. Aquí solo lo que toca a la sesión: el
perfil se copia a `web_sessions.role` al iniciar sesión y es el que aplican los decoradores; por
eso el cambio de rol revoca la sesión (apartado anterior).

## Esquema

- Versión **11**: `users.password_changed_at`, `web_sessions.datos`, `web_sessions.rotado_at`,
  tabla `password_historial` con su índice.
- Versión **12** (misma noche): `web_sessions.sid_hash_anterior` para la gracia de 60 segundos.

Migración idempotente en `threatintel/db.py` (`SCHEMA_VERSION = 12`, columnas también en las
sentencias de creación y en `_COLUMNAS_NUEVAS`).

## Pruebas

Recuento del 9 de septiembre de 2026 (`unittest` por módulo): `tests/test_cookie_opaca.py`
(10), `tests/test_sesion_30_minutos.py` (15), `tests/test_rotacion_password.py` (17),
`tests/test_roles_alcance.py` (29), `tests/test_informes.py` (13); los 84 en verde en 48
segundos. Más las adaptaciones de `test_perfil.py`, `test_segundo_factor.py` (mensaje genérico
también tras códigos incorrectos repetidos), `test_seguridad_plataforma.py` (403 sin nombres de
perfil; mensaje genérico para cuenta deshabilitada y bloqueada) y `test_regresiones.py` (cookie
sin carga legible; historial al restaurar la contraseña de pruebas).

## Pendientes y riesgos asumidos

- Los avisos encolados por una petición atendida con el token de gracia se pierden (no escribe).
- La contraseña de un solo uso se pierde si el servicio se reinicia dentro de los 120 segundos.
- Una cookie copiada sigue sirviendo hasta la siguiente rotación (15 minutos) o los 30 minutos
  sin actividad; el remedio de fondo es el segundo factor obligatorio para administradores
  (`mfa_obligatorio_admin`), todavía desactivado.
