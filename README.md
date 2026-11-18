# Sistema de Inteligencia de Amenazas

Plataforma de código abierto para recolectar, correlacionar, priorizar y alertar
vulnerabilidades de ciberseguridad **contra el inventario tecnológico real** de una
organización, con un informe mensual automático y una interfaz web de administración.

> Este documento describe el sistema tal como está instalado. El razonamiento detallado
> de cada decisión de diseño vive en `docs/` (ver la tabla de Documentación más abajo).

---

## Qué es y para quién

Pensado para un equipo de seguridad pequeño o mediano que necesita saber, cada
mañana, **qué vulnerabilidades nuevas le afectan de verdad** — no solo lo que
publican los boletines, sino lo que realmente tiene instalado — sin pagar una
plataforma de inteligencia de amenazas comercial ni montar un equipo dedicado a
mantenerla.

Lo que lo diferencia de "otro agregador de CVE más":

- **Correlación contra el inventario real**, no contra una lista genérica de
  productos: una amenaza solo se considera relevante si hay al menos un activo con
  la versión vulnerable confirmada.
- **Conecta con el inventario que ya tengas**: adaptador nativo para OCS Inventory y
  un adaptador genérico por CSV/JSON para cualquier otro sistema (GLPI, Snipe-IT,
  Lansweeper, una exportación de Active Directory...). Ver
  [«Inventario: una o varias fuentes»](#inventario-una-o-varias-fuentes).
- **Prioriza, no solo lista**: severidad oficial (NVD), explotación activa
  confirmada (CISA KEV), probabilidad de explotación (EPSS) y exposición real de la
  organización, combinados en una sola puntuación de relevancia.
- **Filtra el ruido**: solo alerta lo nuevo y lo que de verdad aplica; lo demás
  queda disponible en un resumen semanal, nunca se pierde.
- **Pensado para auditoría**: aceptación de riesgo con responsable y vencimiento,
  registro de quién hizo qué y cuándo, roles con alcance distinto por tipo de
  activo.

## Qué hace

```
┌─ CADA DÍA ─────────────────────────────────────────────────────────┐
│  bin/ejecucion_diaria.py                                           │
│                                                                     │
│  1. Sincroniza      el inventario (una o varias fuentes)           │
│  2. Recolecta       fuentes RSS/Atom y API configuradas            │
│  3. Correlaciona    contra el inventario tecnológico con versiones │
│  4. Enriquece       NVD (CVSS oficial) + CISA KEV + EPSS           │
│  5. Verifica        la credencial SMTP y avisa si caduca           │
│  6. Revisa          la salud de las fuentes y avisa si caen        │
│  7. Alerta          por correo, solo lo nuevo y priorizado         │
└─────────────────────────────────────────────────────────────────────┘

┌─ ÚLTIMO DÍA DEL MES ────────────────────────────────────────────────┐
│  bin/ejecucion_mensual.py                                          │
│                                                                     │
│  1. Genera          informe Word (resumen ejecutivo + detalle)     │
│  2. Envía           por correo, con el informe adjunto             │
│  3. Limpia          aplica la política de retención                │
└─────────────────────────────────────────────────────────────────────┘

┌─ PERMANENTE ──────────────────────────────────────────────────────┐
│  Interfaz web: fuentes, inventario, amenazas, activos, informes,   │
│  excepciones de riesgo, credenciales, usuarios, auditoría          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Arquitectura

```
inteligencia_amenazas/
├── threatintel/                   # paquete de dominio
│   ├── paths.py                   # rutas base
│   ├── db.py                      # esquema SQLite y acceso
│   ├── config.py                  # secretos (fichero) + ajustes (base de datos)
│   ├── logging_setup.py           # logging estructurado en JSON
│   ├── identity.py                # identidad y deduplicación de amenazas
│   ├── http.py                    # capa HTTP con User-Agent y reintentos
│   ├── sources.py                 # catálogo de fuentes y su salud
│   ├── versions.py                # extracción y comparación de versiones
│   ├── matching.py                # correlación con el inventario (agnóstico de la fuente)
│   ├── scoring.py                 # severidad real y relevancia organizativa
│   ├── enrich.py                  # NVD 2.0, CISA KEV, EPSS
│   ├── translate.py               # traducción única con términos protegidos
│   ├── collector.py               # orquestación de la recolección
│   ├── queries.py                 # consultas de lectura
│   ├── notify.py                  # envío de correo
│   ├── emails/                    # plantillas Jinja2 de los correos
│   ├── report.py                  # generador del informe .docx
│   ├── credentials.py             # rotación y verificación SMTP
│   ├── health.py                  # salud del sistema y avisos
│   ├── inventario/                # fuentes de inventario (ver más abajo)
│   │   ├── base.py                #   contrato común (FuenteInventario)
│   │   ├── ocs_mysql.py           #   adaptador OCS Inventory (MariaDB, solo lectura)
│   │   ├── csv_generico.py        #   adaptador genérico CSV/JSON
│   │   └── registro.py            #   qué fuentes están configuradas
│   └── ocs.py                     # módulo de compatibilidad (reexporta inventario/ocs_mysql.py)
│
├── webui/                         # interfaz de administración (Flask)
│   ├── app.py  auth.py  filtros.py
│   ├── vistas/                    # panel, fuentes, inventario, amenazas, activos…
│   ├── templates/
│   └── static/estilo.css  app.js
│
├── bin/                           # puntos de entrada
│   ├── ejecucion_diaria.py        # recolección + alerta
│   ├── ejecucion_mensual.py       # informe + envío
│   ├── enriquecer.py              # enriquecimiento con NVD/KEV/EPSS
│   ├── recorrelacionar.py         # recalcula la correlación del histórico
│   ├── consolidar_inventario.py   # depura el inventario tecnológico
│   ├── reparar_fuentes.py         # repara y amplía el catálogo de fuentes
│   ├── detectar_versiones.py      # detecta versiones instaladas en un host
│   ├── migrar_desde_json.py       # importa el histórico JSON a SQLite
│   ├── limpiar.py                 # aplica la retención de datos y logs
│   └── gestionar_usuario.py       # usuarios de la interfaz
│
├── tests/                         # pruebas unitarias e de integración (sin red)
├── config/
│   ├── credentials.env.example    # plantilla de configuración (sin secretos reales)
│   └── inventarios.yml.example    # plantilla de fuentes de inventario
├── data/                          # base de datos y cachés (no se versiona)
├── deploy/                        # unidad de systemd y configuración de referencia de nginx
├── docs/                          # documentación ampliada
├── requirements.txt
└── .venv/                         # entorno virtual (no se versiona)
```

**Principio de diseño**: el motor de correlación (`threatintel/matching.py`) y el
esquema de base de datos (tablas `activos`/`activo_software`) son agnósticos de
dónde vino el inventario. Cualquier fuente nueva solo necesita entregar los datos en
esa misma forma — por eso añadir un inventario distinto de OCS no exige tocar el
motor de amenazas.

---

## Inventario: una o varias fuentes

La plataforma no depende de un único sistema de inventario. Declara tus fuentes en
`config/inventarios.yml` (plantilla en `config/inventarios.yml.example`):

```yaml
fuentes:
  - nombre: servidores
    tipo: ocs_mysql          # lee de OCS Inventory (MariaDB), solo lectura
    prefijo_credenciales: OCS_SERVIDORES   # variables en config/credentials.env
  - nombre: equipos
    tipo: ocs_mysql
    prefijo_credenciales: OCS_EQUIPOS
  - nombre: portatiles_glpi
    tipo: csv                # cualquier otro inventario que pueda exportar CSV/JSON
    ruta: data/importados/glpi_activos.csv
    mapeo: config/mapeos/glpi.yml
```

Si el fichero no existe, la plataforma usa automáticamente las dos fuentes OCS de
siempre (compatibilidad con instalaciones existentes: no hace falta cambiar nada).

Para conectar un inventario que no sea OCS ni se pueda exportar a CSV, se escribe un
adaptador nuevo implementando el contrato de `threatintel/inventario/base.py`
(`hardware()`, `accountinfo()` opcional, `software()`) y se registra como un `tipo`
más en `registro.py` — el resto de la plataforma (correlación, alertas, interfaz) no
necesita ningún cambio.

---

## Funcionalidades principales

| Área | Qué hace |
|---|---|
| **Alerta por relevancia** | No alerta por severidad a secas: exige CVE o identificador, relevancia mínima configurable o presencia en KEV, y **al menos un activo con la versión vulnerable confirmada**. Lo excluido nunca se pierde: queda en el resumen semanal con el motivo. |
| **Resumen semanal** | Lo que la alerta diaria no envió, agrupado por tecnología, con lo informativo y el motivo de cada exclusión. |
| **Remediación con cierre automático** | Una fila por activo, CVE y paquete; se cierra sola cuando el inventario confirma la versión corregida (o el paquete desinstalado) y se reabre si vuelve a ser vulnerable. Agrupa paquetes que se resuelven con la misma actualización. |
| **Parches de Windows (MSRC)** | Cruza los boletines mensuales de Microsoft con las actualizaciones (KB) instaladas para dar un veredicto por CVE y equipo. |
| **Excepciones (aceptación de riesgo)** | Alcance (vulnerabilidad en un activo, CVE en toda la organización o paquete en un activo), responsable, justificación, medida compensatoria opcional y vencimiento — con fecha (máximo 365 días) o **permanente con revisión periódica obligatoria**. Nunca se admite sin salvaguardas sobre una amenaza con explotación activa confirmada. Vuelve sola a la cola de trabajo al vencer, sin intervención. |
| **Informes a medida** | Generador con plantillas preconfiguradas, periodo, alcance y severidades a elegir, con vista previa antes de descargar. El informe mensual completo se genera por el mismo camino, automáticamente. |
| **Filtro por tecnología, CVE o vulnerabilidad** | Desde Activos se puede filtrar directamente por una tecnología o por un CVE concreto para ver qué activos afecta; desde la ficha de una amenaza, un enlace lleva al listado de activos afectados ya filtrado. |
| **Roles con alcance** | Seis perfiles (administrador, operador SOC, jefe de proceso, dos acotados por tipo de activo y uno de solo lectura), aplicados siempre en el servidor, nunca solo en el menú. |
| **Seguridad de sesión** | Sesión opaca en servidor, caducidad por inactividad y máxima, rotación periódica con gracia, segundo factor (TOTP) opcional, política e historial de contraseñas, mensajes de acceso sin oráculos. |
| **Interfaz sin recargas** | Filtrar, ordenar, paginar y las acciones de escritura actualizan solo el fragmento afectado, con mejora progresiva: sin JavaScript todo sigue funcionando igual, con recarga. |
| **Auditoría** | Quién cambió qué, cuándo y desde dónde, en una tabla aparte que no se puede editar desde la interfaz. |

---

## Cómo se decide la severidad

Por orden de fiabilidad; el origen aplicado se indica siempre en la interfaz, el
correo y el informe:

| Origen | Qué es | ¿Hay puntuación CVSS? |
|---|---|---|
| `nvd` | Puntuación oficial publicada por el NVD | Sí |
| `vector` | Calculada a partir del vector CVSS 3.x oficial | Sí |
| `kev` | Presencia en el catálogo KEV de CISA | No, eleva a Alta |
| `heuristic` | Estimación por indicios textuales | **No** — se muestra «no disponible» |

Cuando no hay dato oficial, el sistema escribe **«no disponible»**; no inventa un
número.

La **relevancia** (0-100) combina la severidad técnica con la exposición real:
criticidad y exposición de las tecnologías afectadas, número de sistemas, veredicto
de versión, presencia en KEV y probabilidad EPSS. Es el criterio que ordena las
alertas.

## Correlación con el inventario

Cada hallazgo se compara con el inventario por **palabra completa**, con alias y
exclusiones por tecnología:

- `word` — límites de palabra: `edge` no coincide dentro de `knowledge`
- `phrase` — frase completa: `Check Point VPN`
- `regex` — expresión propia, validada al guardarla
- **contexto exigido** — por ejemplo, un alias genérico solo cuenta si aparece
  también el nombre del fabricante
- **exclusión** — una frase concreta descarta una coincidencia ambigua

Con la **versión instalada** registrada, el sistema compara contra el rango
declarado en el aviso y emite un veredicto:

| Veredicto | Significado |
|---|---|
| `affected` | La versión instalada está en el rango vulnerable |
| `not_affected` | No lo está: se descarta automáticamente |
| `unknown` | Falta la versión, o el aviso no la especifica |

Ante cualquier ambigüedad se devuelve `unknown`, nunca `not_affected`: en seguridad
un falso negativo cuesta más que un falso positivo.

**Registrar las versiones es lo que más reduce el ruido.** Se hace en Inventario, en
línea o importando un CSV.

## Activos y aplicabilidad por activo

- **Activos** (`/activos/`): lista con búsqueda, filtros por tipo de activo, sistema,
  entorno, proceso de negocio, **tecnología y CVE**, y vistas rápidas (con
  vulnerabilidades confirmadas, KEV, fuera de soporte, sin reportar, sin agente de
  protección, software de riesgo). Exportación a CSV.
- **Ficha de activo**: datos del inventario, fin de soporte, hallazgos de política,
  amenazas evaluadas con veredicto y evidencia, software instalado con su tecnología
  y la pregunta **«¿Le aplica este CVE?»**, que responde al momento.
- **Software** (`/activos/software`): mapa de nombres del inventario a tecnología
  (por ejemplo, un navegador concreto a su tecnología genérica), propuestas
  automáticas, software sin clasificar y tecnologías con activos y dispersión de
  versiones.
- **Motor de aplicabilidad** (`threatintel/aplicabilidad.py`): Debian y Ubuntu con
  los registros `DEBIAN-CVE-*`/`UBUNTU-CVE-*` de OSV.dev y comparación exacta de
  dpkg; FreeBSD con VuXML; Windows y escritorio comparando la versión instalada con
  la que enuncia el aviso. Veredictos `afectado`/`no_afectado`/`sin_dato`, con
  evidencia textual.
- **Alerta e informe**: cada amenaza alertada lista sus activos afectados (nombre,
  IP, paquete, versión corregida); el informe mensual añade el apartado de activos
  de la organización.

```bash
# Sincronizar el inventario y evaluar a mano (la ejecución diaria ya lo hace)
sudo -n -u si .venv/bin/python bin/sincronizar_ocs.py
sudo -n -u si .venv/bin/python bin/sincronizar_ocs.py --solo-aplicabilidad --max-amenazas 300
# Comprobar la conexión y consultar el inventario en modo lectura
sudo -n -u si .venv/bin/python bin/probar_ocs.py
```

## Traducción

Un solo flujo: `limpiar HTML → proteger términos → traducir → restaurar → cachear`.

| Motor | Cuándo | Velocidad aproximada |
|---|---|---|
| ArgosTranslate | Todo el volumen | ~0,3 s por texto |
| Ollama (modelo local) | Solo severidad crítica y el resumen ejecutivo | ~20 s por texto |

Los nombres de producto, siglas, CVE y versiones **no llegan al traductor**: se
sustituyen por marcadores y se reponen al final. Las traducciones se cachean, así
que un texto no se traduce dos veces.

Se configura en **Ajustes → Traducción** (`translate_engine`: `none`, `argos`,
`ollama`, `hybrid`). Si Ollama no está disponible, el sistema no se detiene: cae a
ArgosTranslate y registra un aviso.

---

## Despliegue con Docker

La forma más rápida para instalar y ejecutar la plataforma.

```bash
# 1. Descargar código
git clone https://github.com/jdavsan/PhantomCortex.git
cd PhantomCortex

# 2. Configurar credenciales
cp config/credentials.env.example config/credentials.env
nano config/credentials.env

# 3. Ejecutar con Docker Compose
docker-compose up -d

# 4. Acceder en http://localhost:9090
```

Consulta `docs/DOCKER_DEPLOYMENT_2026-11-16.md` para configuración avanzada, despliegue en máquina directa y operación.

---

## Instalación desde cero

Requisitos: Linux, Python 3.10 o superior (**usa la misma versión mayor con la que
crees el entorno virtual**: si el sistema actualiza su Python después, el entorno
virtual queda roto — ver [Solución de problemas](#solución-de-problemas)), y acceso
de solo lectura a tu inventario tecnológico.

```bash
# 0. (Recomendado) Un usuario de sistema dedicado para ejecutar la plataforma,
#    para no correrla como root ni como tu usuario personal
sudo useradd --system --create-home --shell /usr/sbin/nologin si

# 1. Entorno virtual y dependencias
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. Modelo de traducción EN->ES (opcional, una sola vez, ~120 MB)
#    IMPORTANTE: ejecutar como el usuario que luego correrá el cron
.venv/bin/python -c "
import argostranslate.package as p
p.update_package_index()
[p.install_from_path(q.download()) for q in p.get_available_packages()
 if q.from_code=='en' and q.to_code=='es']"

# 3. Credenciales
cp config/credentials.env.example config/credentials.env
chmod 600 config/credentials.env
nano config/credentials.env

# 4. Fuentes de inventario (opcional; sin este fichero usa las dos fuentes OCS de siempre)
cp config/inventarios.yml.example config/inventarios.yml
nano config/inventarios.yml

# 5. Base de datos, catálogo de fuentes e inventario
.venv/bin/python -c "
import sys; sys.path.insert(0,'.')
from threatintel import db, config, sources, matching
db.init_db()
with db.session() as c:
    config.seed_settings(c)
    sources.seed(c)
    matching.seed_inventario(c)"

# 6. Usuario de la interfaz (--nombre es lo que se ve en la barra superior)
.venv/bin/python bin/gestionar_usuario.py crear soc@ejemplo.local --nombre "Nombre Apellidos" --rol admin --generar

# 7. Comprobar
.venv/bin/python bin/ejecucion_diaria.py --dry-run
.venv/bin/python -m unittest discover -s tests -p "test_*.py"

# 8. Arrancar la interfaz web (modo producción, servidor WSGI waitress)
chown -R si:si .
sudo -n -u si .venv/bin/python -m webui.app
```

Para que arranque sola con el sistema y se recupere si el proceso muere, instala la
unidad de systemd y el nginx de referencia en `deploy/` (ajusta antes el nombre de
dominio o la IP a los tuyos):

```bash
sudo deploy/servicio/asegurar_arranque.sh            # instala/habilita y muestra el estado
sudo deploy/servicio/asegurar_arranque.sh --probar   # además mata el proceso y comprueba que vuelve solo
```

### Variables obligatorias en `config/credentials.env`

| Variable | Descripción |
|---|---|
| `SMTP_SERVER`, `SMTP_PORT` | Servidor de correo saliente |
| `SMTP_USER`, `SMTP_PASSWORD` | Credencial de envío (se recomienda rotarla periódicamente) |
| `ALERT_EMAIL_TO` | Destinatarios de la alerta diaria |
| `REPORT_EMAIL_TO` | Destinatarios del informe mensual |
| `ADMIN_EMAIL` | Avisos operativos: fuente caída, credencial por caducar |
| `BACKUP_PASSPHRASE` | Clave de cifrado del backup (`openssl rand -base64 33`) |
| `OCS_SERVIDORES_HOST/PORT/DB/USER/PASSWORD`, `OCS_EQUIPOS_HOST/PORT/DB/USER/PASSWORD` | Conexión de solo lectura a OCS Inventory, si se usa ese adaptador |

Opcionales: `ALERT_EMAIL_CC`, `REPORT_EMAIL_CC`, `EMAIL_FROM`, `EMAIL_FROM_NAME`,
`EMAIL_REPLY_TO`, `NIST_NVD_API_KEY`, `HEALTH_TOKEN`.

> `NIST_NVD_API_KEY` debe ser un UUID de 36 caracteres. Si el valor no tiene ese
> formato, el sistema **lo ignora y avisa**: una clave inválida hace que NVD
> responda 404 y se pierdan todas las consultas, peor que no usar clave. Se pide
> gratis en <https://nvd.nist.gov/developers/request-an-api-key>. También se puede
> pegar y verificar desde **Interfaz → Credenciales**, sin editar el fichero.

---

## Operación diaria

```bash
# Ejecución completa a mano (el cron la puede partir en dos fases: todo el trabajo
# y, un poco más tarde, solo la clasificación y el envío)
.venv/bin/python bin/ejecucion_diaria.py
.venv/bin/python bin/ejecucion_diaria.py --sin-alerta    # solo inventario, recolección y enriquecimiento
.venv/bin/python bin/ejecucion_diaria.py --solo-alerta   # solo clasificar y enviar

# Sin escribir ni enviar nada
.venv/bin/python bin/ejecucion_diaria.py --dry-run

# Probar una sola fuente
.venv/bin/python bin/ejecucion_diaria.py --fuente cisa_kev --dry-run
```

### Informe mensual

```bash
# Solo funciona el último día del mes, salvo que se fuerce
.venv/bin/python bin/ejecucion_mensual.py

# Generar el de un periodo concreto sin enviarlo
.venv/bin/python bin/ejecucion_mensual.py --mes 2026-08 --solo-generar
```

Códigos de salida: `0` correcto · `1` error · `2` no procede (no es fin de mes).

### Enriquecimiento

```bash
.venv/bin/python bin/enriquecer.py --limite 400     # lo pendiente, por lotes
.venv/bin/python bin/enriquecer.py --todo            # todo el histórico
.venv/bin/python bin/enriquecer.py --solo-relevancia # recalcular solo relevancia tras cambiar el inventario
```

### Detectar versiones instaladas

```bash
.venv/bin/python bin/detectar_versiones.py --aplicar               # en este servidor
.venv/bin/python bin/detectar_versiones.py --csv inventario_host2.csv  # en otro host, por CSV
```

Detecta unas 30 tecnologías (sistema operativo, bases de datos, servidores web,
lenguajes, contenedores, navegadores). Es conservador: si no puede determinar una
versión con certeza, no la registra.

### Tras modificar el inventario

```bash
.venv/bin/python bin/recorrelacionar.py --dry-run   # ver el efecto primero
.venv/bin/python bin/recorrelacionar.py
```

---

## Interfaz de administración

Interfaz web interna con usuario y contraseña, pensada para publicarse detrás de un
proxy con TLS (ver `deploy/nginx/`), nunca directamente en Internet.

| Pantalla | Para qué sirve |
|---|---|
| **Panel** | Diagrama del proceso, métricas con tendencia, evolución por severidad, reparto del mes, tecnologías más expuestas, estado de fuentes, calidad del dato |
| **Fuentes** (administradores) | Estado de salud, qué aporta cada una, probar una fuente en vivo, activar, editar, eliminar |
| **Inventario** | Criticidad del inventario, cobertura de versiones, tecnologías con más amenazas, alias, exclusiones, importación por CSV |
| **Amenazas** | Histórico con filtros (incluido el estado) y exportación a CSV; ficha con CVSS, EPSS, relevancia, hitos y por qué se alertó o no |
| **Activos** | Lista con filtros, incluido por tecnología y por CVE; ficha con software instalado y la pregunta «¿Le aplica este CVE?» |
| **Excepciones** | Aceptación de riesgo con responsable, justificación y plazo (con vencimiento o permanente con revisión periódica) |
| **Tendencias** | Serie histórica por severidad, madurez del dato, CVSS medio, CVE recurrentes |
| **Informes** | Generador a medida: plantillas, periodo, alcance, severidades y vista previa antes de descargar |
| **Credenciales** | Servidor SMTP (servidor, puerto, usuario, cifrado, remitente), renovar la contraseña, verificar, destinatarios, clave de API de NVD |
| **Ajustes** | Todos los parámetros que el código lee de verdad, agrupados por efecto; logo de la organización |
| **Mi perfil** | Identidad, último acceso, sesiones abiertas, cambio de contraseña y segundo factor |
| **Consultas al inventario** (administradores) | Fecha, duración y resultado de cada sincronización con cada fuente configurada |
| **Auditoría** | Quién cambió qué, cuándo y desde dónde |

**Gráficos**: todos son SVG generados en el servidor, sin librerías externas ni
JavaScript de terceros, para que la cabecera CSP siga sin `unsafe-inline`. Tema claro
y oscuro. Especificación completa en `docs/DISENO_INTERFAZ_2026-09-03.md`.

```bash
systemctl status threat-intel-webui     # estado (si se instaló como servicio)
systemctl restart threat-intel-webui
journalctl -u threat-intel-webui -f     # log en vivo
```

### Usuarios

```bash
.venv/bin/python bin/gestionar_usuario.py listar
.venv/bin/python bin/gestionar_usuario.py crear <correo> --nombre "Nombre Apellidos" --rol redes
.venv/bin/python bin/gestionar_usuario.py password <usuario>
.venv/bin/python bin/gestionar_usuario.py desbloquear <usuario>
```

`--rol` admite los perfiles de la tabla siguiente (`webui/auth.py`, constante
`ROLES`); sin `--rol` crea un administrador.

### Perfiles de acceso

Los perfiles, sus nombres visibles y su alcance están definidos en un solo sitio
(`webui/auth.py`), así que la ayuda de la interfaz nunca queda desfasada del
comportamiento real.

| Perfil (`users.role`) | Nombre visible | Qué ve | Qué puede hacer | Alcance de activos |
|---|---|---|---|---|
| `admin` | Administrador | Todo, incluida Administración | Configuración, fuentes, inventario, usuarios, estado de amenazas, informes y remediación | Todos los tipos de activo |
| `ciberseguridad` | Ciberseguridad | Operación e Inventario completos | Cambia el estado de una amenaza, evalúa un CVE contra un activo | Todos los tipos de activo (no genera informes ni remedia) |
| `redes` | Redes | Operación e Inventario acotados a servidores | Pide y documenta la comprobación de una remediación | Solo servidores (equipos de cómputo responde 404, no 403) |
| `mantenimiento` | Mantenimiento | Operación e Inventario acotados a equipos de cómputo | Pide y documenta la comprobación de una remediación | Solo equipos de cómputo |

El alcance se aplica siempre en el servidor (consultas SQL, fichas, exportaciones y
acciones), nunca solo ocultando botones en el menú.

### Monitorización

`GET /salud.json?token=<HEALTH_TOKEN>` devuelve métricas planas con prefijo `ti.`
para un sistema de monitorización (Zabbix, Prometheus con un exportador, etc.). Sin
`HEALTH_TOKEN` configurado basta una sesión completa.

```
ti.estado                  0=ok 1=atención 2=crítico
ti.fuentes.caidas          fuentes sin funcionar
ti.credencial.estado       0=ok 1=por caducar 2=caducada o fallando
ti.credencial.dias_restantes
ti.amenazas.sin_enriquecer
```

---

## Pruebas

```bash
# Suite completa
.venv/bin/python -m unittest discover -s tests -p "test_*.py"

# Un módulo o una prueba concreta
.venv/bin/python -m unittest tests.test_activos
.venv/bin/python -m unittest tests.test_activos.TestFiltros.test_filtra_por_cve
```

Sin red: todas las pruebas usan una base de datos temporal y, cuando necesitan un
inventario, una fuente falsa en memoria. No tocan la base de datos real ni los
servicios externos.

---

## Mantenimiento

### Logs

```bash
tail -f logs/threatintel.jsonl                       # en vivo
grep '"level":"ERROR"' logs/threatintel.jsonl         # solo errores
```

Una línea JSON por evento, con rotación automática.

### Backup

```bash
./create_backup.sh                    # manual (o por cron)
./restore_backup.sh <archivo.tar.gz>
```

Incluye el código, la base de datos completa (con `sqlite3 .backup`, consistente aunque
la plataforma esté corriendo) y la configuración cifrada; borra solo los `.tar.gz` de
más de 30 días. Se ejecuta en cron una vez por semana.

La clave de cifrado está en `BACKUP_PASSPHRASE` dentro de `config/credentials.env`,
nunca en el script. Sin esa clave el backup de credenciales no se puede descifrar:
guárdela aparte.

### Retención

Se aplica en la ejecución mensual, según el ajuste `data_retention_days` y el
historial de salud.

---

## Solución de problemas

**El entorno virtual no importa ningún paquete tras actualizar el sistema.** Un
entorno virtual queda atado a la versión mayor de Python con la que se creó
(`.venv/pyvenv.cfg`). Si el sistema actualiza su `python3` por defecto a otra
versión (por ejemplo, tras una actualización del sistema operativo), el entorno
virtual queda roto aunque los ficheros sigan ahí: hay que recrearlo
(`rm -rf .venv && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`).

**Falla `sudo -n -u si ...` con «unknown user».** El usuario de sistema dedicado no
existe en esta máquina: créalo (paso 0 de la instalación) o sustitúyelo por el
usuario que vaya a ejecutar la plataforma en tu entorno.

**Una fuente dejó de funcionar.** Interfaz → Fuentes → botón «Probar». El error es
específico: `http_403` (bloqueo), `http_404` (URL muerta), `no_es_feed` (devuelve
HTML), `timeout`. Si la URL ya no existe, desactive la fuente.

**No llegan las alertas.** Interfaz → Credenciales → «Verificar conexión». Distingue
`AUTH:` (contraseña inválida) de `RED:` (servidor inalcanzable, la contraseña está
bien).

**La contraseña SMTP caducó.** Interfaz → Credenciales → renovar con la
verificación activada: si la nueva no funciona, no se guarda y el sistema sigue
enviando con la actual.

**Demasiadas amenazas «sin determinar».** Falta la versión instalada. Inventario →
exportar CSV → rellenar `version_instalada` → importar → `bin/recorrelacionar.py`.

**El informe sale muy largo.** Ajustes → Informe mensual →
`report_max_detail_items` y `report_max_anexo_items`.

**Ollama no responde.**
```bash
systemctl status ollama
curl http://localhost:11434/api/tags
```
Si no está disponible el sistema **no se detiene**: cae a ArgosTranslate y registra
un aviso.

---

## Limitaciones conocidas

- El límite público de peticiones a NVD (sin clave de API) hace que enriquecer todo
  el histórico desde cero lleve horas; con clave de API válida es mucho más rápido.
- El segundo factor (TOTP) es opcional por cuenta; puede exigirse a los
  administradores desde Ajustes.
- El adaptador CSV de inventario necesita que el fichero de origen tenga, como
  mínimo, nombre, sistema operativo y lista de software con versión; sin eso, los
  activos quedan sin datos suficientes para evaluar aplicabilidad.
- Sin repositorio de control de versiones inicializado, no hay historial de
  cambios del propio código hasta que se decida publicarlo.

---

## Documentación

| Documento | Contenido |
|---|---|
| `docs/DISENO_INTERFAZ_2026-09-03.md` | Especificación del diseño de la interfaz: paleta, componentes, gráficos SVG |
| `docs/PRECISION_ALERTAS_2026-09-04.md` | Criterio de alerta por relevancia, resumen semanal, correlación por paquete, estados |
| `docs/INVENTARIO_OCS_2026-09-04.md` | Inventario real, fuentes de aplicabilidad y validación por activo |
| `docs/EXCEPCIONES_2026-09-10.md` | Aceptación de riesgo: con vencimiento o permanente, revisión periódica |
| `docs/OWASP_2026-09-03.md` | Revisión de seguridad según OWASP Top 10 |

## Licencia y contribuciones

Publicado bajo licencia MIT (ver `LICENSE`): libre para adaptar a tu propio inventario
y tus propias fuentes. Las contribuciones (incidencias, mejoras) son bienvenidas por
`pull request`. 
