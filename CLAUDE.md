# Instrucciones del proyecto para Claude Code

## Habilidad obligatoria para la interfaz
Para CUALQUIER trabajo que cambie cómo se ve, se siente o se usa la interfaz web
(`webui/`: plantillas, CSS, gráficos, formularios, correos HTML), cargar SIEMPRE la
habilidad `ui-ux-pro-max` (instalada en `.claude/skills/ui-ux-pro-max/`) y consultar su
base de conocimiento antes de diseñar o corregir:

    python3 .claude/skills/ui-ux-pro-max/scripts/search.py "<consulta>" --domain <ux|style|color|typography|chart|icons>
    python3 .claude/skills/ui-ux-pro-max/scripts/search.py "<producto>" --design-system --density 8

Aplicar sus reglas por prioridad (accesibilidad y contraste 4,5:1, objetivos táctiles
de 44 px, foco visible, etiquetas visibles en formularios, sin emojis como iconos,
gráficos con leyenda y sin depender solo del color). Los resultados son recomendaciones:
nunca anulan las reglas de este proyecto.

## Reglas del proyecto (prevalecen sobre cualquier habilidad)
- Nada de git hasta que el usuario lo autorice expresamente.
- CSP estricta en la interfaz: sin `style=`, sin `on*=`, sin scripts ni recursos externos
  (tampoco fuentes de Google): todo CSS en `webui/static/estilo.css`, todo JS en `webui/static/*.js`.
- Ficheros propiedad de `si:si`; Python como `sudo -n -u si .venv/bin/python`.
- Español con tilde en todo texto visible, sin abreviaturas; números en formato español.
- Suite en verde antes de dar algo por hecho:
  `sudo -n -u si .venv/bin/python -m unittest discover -s tests -p "test_*.py"`.
- Documentación de referencia: `README.md`, `docs/DISENO_INTERFAZ_2026-09-03.md`,
  `docs/PRECISION_ALERTAS_2026-09-04.md`, `docs/INVENTARIO_OCS_2026-09-04.md`.

## Agentes y habilidades del proyecto
- Reglas inamovibles ampliadas: `.claude/skills/reglas-proyecto/SKILL.md` (cargar antes de cualquier cambio).
- Agentes en `.claude/agents/`: `implementador`, `revisor-seguridad`, `pentester-interno`, `probador`,
  `revisor-interfaz`, `revisor-precision`, `operador-diario`, `documentador`. Todo cambio pasa por
  revisión de seguridad antes de darse por hecho.
- Habilidades en `.claude/skills/`: `pruebas`, `revision-visual`, `auditoria-seguridad`,
  `operacion-diaria`, `cambio-de-esquema` (además de `ui-ux-pro-max`).
- Descripción completa: `docs/AGENTES_Y_HABILIDADES_2026-09-05.md`.
