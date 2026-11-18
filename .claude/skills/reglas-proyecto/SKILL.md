---
name: reglas-proyecto
description: "Reglas inamovibles del proyecto Inteligencia de Amenazas (Mi Organización): git prohibido, ficheros de si:si, Python vía sudo, español con tildes, CSP estricta, base real solo lectura, correo interno, suite en verde. Cargar SIEMPRE antes de cualquier cambio de código, plantilla, base de datos u operación; todos los agentes del proyecto la referencian."
---

# Reglas del proyecto (obligatorias para personas y agentes)

Estas reglas prevalecen sobre cualquier otra habilidad o costumbre. Si una tarea exige
romper alguna, se detiene el trabajo y se pregunta al usuario; no se improvisa.

## 1. Control de versiones
- **Prohibido usar git**: ningún `git add`, `commit`, `stash`, `checkout`, `reset` ni similar
  hasta que el usuario lo autorice expresamente en ese momento. La red de seguridad son las
  copias en `backups/` (`tar.gz` del código sin `.venv`, `data`, `logs`; y copia de la base con
  la API `backup` de sqlite3) antes de un cambio grande.

## 2. Usuarios, permisos y ejecución
- Los ficheros del proyecto son de `si:si`. Quien edita como root ejecuta después
  `chown si:si <ruta>` (y `chown -R` en directorios nuevos).
- Python siempre como `sudo -n -u si .venv/bin/python` (también `pip`, `pip-audit` y los
  scripts de `bin/`). El servicio web es `threat-intel-webui` (systemd); se reinicia con
  `systemctl restart threat-intel-webui` solo cuando el coordinador lo decide.
- `config/credentials.env` mantiene permisos 600 y sus valores nunca aparecen en logs, base,
  HTML, informes ni conversación. Las contraseñas se escriben en ese fichero, no en el chat.
- El directorio temporal de Claude (`/tmp/claude-0/...`) no es legible por `si`: lo que deba
  leer ese usuario va a `data/revision/` o a un directorio bajo `data/`.

## 3. Idioma y formato
- Español con tildes en todo texto visible (plantillas, mensajes, correos, informes, CSV).
  Sin abreviaturas («configuración», no «config»). Siglas explicadas la primera vez o con
  `<abbr title>`. Números en formato español (1.234,5) con los filtros `numero`, `fecha_es`,
  `hace` de `webui/filtros.py` o `notify.numero`/`notify.fecha_larga` en correos.
- Claridad para alguien nuevo: nada de etiquetas vagas («Resto», «Otros» sin cifra), cada
  panel dice qué es y para qué sirve.

## 4. Interfaz web (CSP estricta)
- En HTML: nada de `style=`, `on*=`, `<script>` en línea ni recursos externos (tampoco fuentes
  de Google). Todo el CSS en `webui/static/estilo.css`; todo el JS en `webui/static/app.js`
  mediante atributos `data-*`. Los correos HTML (`threatintel/emails/`) sí admiten CSS en
  línea porque los clientes de correo lo exigen.
- Colores: solo con significado (rojo riesgo, ámbar atención, verde correcto, azul marca,
  gris sin dato); repartos categóricos con la paleta `cat-1..cat-8` (colores vivos y
  distinguibles, verificada por `tests/test_recorridos_paleta.py`); ceros en neutro.
- Toda página que extienda `base.html` lleva recorrido guiado (≥ 2 pasos `data-tour` en la
  etiqueta de apertura de `.titulo-pagina` y de los `.panel`).
- Toda ruta GET exige sesión (`@auth.requiere_login` o `@auth.requiere_admin`); toda ruta
  POST exige CSRF (`@auth.requiere_csrf` y campo oculto `csrf`) y el rol adecuado. Las
  escrituras se auditan con `db.audit(...)`. `tests/test_seguridad_plataforma.py` recorre
  todas las rutas.
- En cambios visuales, consultar la habilidad `ui-ux-pro-max` (accesibilidad, contraste 4,5:1,
  objetivos táctiles de 44 px, sin emojis como iconos, gráficos con leyenda).

## 5. Datos y operación
- La base real `data/threat_intel.db` es de solo lectura para pruebas y análisis:
  `sqlite3.connect("file:/opt/inteligencia_amenazas/data/threat_intel.db?mode=ro", uri=True)`.
  Para probar con datos reales se hace una copia temporal bajo `data/` con la API `backup` y
  se borra al terminar. Escribir en la base real solo lo hace el coordinador con orden del usuario.
- OCS Inventory (servidores 10.1.2.100, equipos 10.1.1.204) es de solo lectura.
- Correo: nunca envíos reales desde pruebas; el SMTP interno solo acepta destinatarios del
  dominio de la empresa; envíos de prueba únicamente a la dirección que el usuario indique y
  cuando lo pida. En pruebas automáticas, `dry_run` o un `Mailer` falso.
- Nada de ataques de denegación, fuerza bruta ni pruebas destructivas contra la instancia
  real: bloquearían cuentas reales. Las pruebas dinámicas van contra una copia.

## 6. Calidad
- Suite en verde antes de dar algo por hecho:
  `sudo -n -u si .venv/bin/python -m unittest discover -s tests -p "test_*.py"`.
  Las pruebas nuevas van en `tests/test_<tema>.py`, sin red (mocks), con base temporal
  `tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))` y `db.init_db(ruta)`.
- No debilitar pruebas existentes; si un cambio intencional las afecta, adaptarlas y explicarlo.
- Cambios de esquema: seguir la habilidad `cambio-de-esquema` (versión, columnas también en
  las tablas de creación, sin claves duplicadas en `_COLUMNAS_NUEVAS`, copia previa).
- Documentar en `README.md` y `docs/` con fecha; los documentos de referencia son
  `docs/DISENO_INTERFAZ_2026-09-03.md`, `docs/PRECISION_ALERTAS_2026-09-04.md` y
  `docs/INVENTARIO_OCS_2026-09-04.md`.

## 7. Trabajo en paralelo (agentes)
- Cada agente toca solo los ficheros que le asigna el coordinador. Los compartidos
  (`threatintel/db.py`, `threatintel/config.py`, `webui/app.py`, `base.html`, `estilo.css`,
  `app.js`, `webui/vistas/ajustes.py`, `bin/*.py`, `docs/`, `README.md`, `requirements.txt`)
  los edita el coordinador; lo que falte (CSS, ajustes, documentación) se devuelve en el informe.
- Informe final estructurado: qué se hizo, ficheros creados y modificados, pruebas y
  resultado de la suite, verificación con datos reales, pendientes y riesgos.
