# Agentes y habilidades del proyecto (2026-09-05)

Claude Code permite definir **agentes** (roles con instrucciones y herramientas propias, en
`.claude/agents/*.md`) y **habilidades** (procedimientos reutilizables con guiones, en
`.claude/skills/<nombre>/SKILL.md`). Hasta hoy el proyecto solo tenía la habilidad externa
`ui-ux-pro-max`; los agentes de los flujos de trabajo eran temporales y sus reglas se repetían a
mano en cada encargo. Desde hoy quedan fijadas en el proyecto. Todos parten de
`.claude/skills/reglas-proyecto/SKILL.md`, que recoge las reglas inamovibles (sin git, ficheros
de `si`, español con tildes, CSP estricta, base real de solo lectura, correo interno, suite en
verde) y prevalece sobre cualquier otra instrucción.

## Agentes (`.claude/agents/`)

| Agente | Para qué | Herramientas | Qué no hace |
|---|---|---|---|
| `implementador` | Implementar una funcionalidad o corrección completa con pruebas y suite en verde, respetando la lista de ficheros que se le asigna. | Leer, buscar, ejecutar, editar, crear | No toca ficheros compartidos ni la base real; no usa git. |
| `revisor-seguridad` | Revisión adversaria de un cambio según OWASP Top 10 2025 y OWASP API Security Top 10 2023, con lista de comprobación ejecutable y hallazgos reproducibles. | Leer, buscar, ejecutar | No corrige (solo `chown`); no ataca la instancia real. |
| `pentester-interno` | Pruebas de intrusión controladas contra una copia (autenticación, sesión, CSRF, IDOR, inyección, cargas, límites, cabeceras) que convierte en pruebas automáticas. | Leer, buscar, ejecutar, editar, crear | Nunca fuerza bruta ni carga contra la instancia real; sin correos. |
| `probador` | Escribir y reparar pruebas con las convenciones de la suite; reproducir fallos como prueba antes de corregir. | Leer, buscar, ejecutar, editar, crear | No debilita ni borra pruebas para «pasar». |
| `revisor-interfaz` | Revisar la interfaz con capturas reales en claro y oscuro: claridad, español, CSP, paleta con significado, contraste, recorrido guiado, tablas y gráficos. | Leer, buscar, ejecutar | No corrige: propone. |
| `revisor-precision` | Medir con datos reales (solo lectura) correlaciones falsas, veredictos erróneos, alertas que sobran o faltan, prioridades incoherentes. | Leer, buscar, ejecutar | No cambia código ni datos. |
| `operador-diario` | Diagnosticar el estado operativo (servicio, cron, última ejecución, OCS, correo, fuentes) y proponer la acción mínima. | Leer, buscar, ejecutar | Solo lectura salvo orden expresa. |
| `documentador` | Actualizar README, docs con fecha y docstrings con el estilo del proyecto tras un cambio, verificando cada afirmación. | Leer, buscar, ejecutar, editar, crear | No documenta lo que no puede comprobar. |

Se eligen desde `/agents` en Claude Code o los invoca el coordinador en un flujo de trabajo.
Todos usan el modelo de la sesión.

## Habilidades (`.claude/skills/`)

| Habilidad | Para qué | Cómo se usa |
|---|---|---|
| `reglas-proyecto` | Reglas inamovibles; base de todos los agentes. | Se carga antes de cualquier cambio. |
| `pruebas` | Suite completa o un módulo, como `si`, resumiendo solo los fallos. | `bash .claude/skills/pruebas/scripts/suite.sh [tests.test_x]` |
| `revision-visual` | Capturas en claro y oscuro con un usuario temporal de solo lectura que se crea y se borra solo; informe de CSP por página. | `bash .claude/skills/revision-visual/scripts/capturar.sh [/ruta ...]` → `data/revision/capturas/<fecha>/` |
| `auditoria-seguridad` | Auditoría de solo lectura: `pip-audit`, dependencias fijadas, permisos de ficheros con secretos, fugas en logs, cabeceras y CSP de la instancia, plantillas sin código en línea, pruebas de seguridad, cuentas y sesiones. | `bash .claude/skills/auditoria-seguridad/scripts/auditar.sh` (0 hallazgos el 2026-09-05) |
| `operacion-diaria` | Procedimientos de operación: comprobaciones, ejecución diaria (`--dry-run` primero), sincronización con OCS, reinicio tras cambios, copias de seguridad. | Se consulta; los comandos están en el documento. |
| `cambio-de-esquema` | Lista de comprobación para migraciones de la base (versión, columnas en creación y en `_COLUMNAS_NUEVAS` sin claves duplicadas, copia previa, aplicación y verificación). | Se consulta; incluye un guion de comprobación. |
| `ui-ux-pro-max` | Base de conocimiento de diseño (accesibilidad, color, tipografía, gráficos). Obligatoria en cambios visuales (CLAUDE.md). | `python3 .claude/skills/ui-ux-pro-max/scripts/search.py "<consulta>" --domain <dominio>` |

## Decisión: propios en vez de descargados

Se valoró descargar agentes de colecciones públicas de GitHub. Sirven como inspiración para
roles genéricos, pero no conocen las reglas del proyecto y un agente ajeno es texto con
capacidad de ejecutar órdenes en una máquina con credenciales del SOC. Por eso los agentes se
escribieron aquí, en español, con las reglas incorporadas, herramientas limitadas por rol y
límites explícitos para las pruebas de seguridad (solo contra copias, nunca fuerza bruta contra
la instancia real). Si en el futuro se adopta un agente externo, se revisa línea a línea, se
traduce y se le añade `reglas-proyecto` como bloque obligatorio.
