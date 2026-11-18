---
name: revision-visual
description: "Captura páginas de la consola web de Inteligencia de Amenazas en tema claro y oscuro con un usuario temporal de solo lectura que se crea y se elimina automáticamente. Úsalo para verificar cualquier cambio visual con imágenes reales antes de informar al usuario."
---

# Revisión visual con capturas

El usuario exige ver la interfaz «bien hecha»; nunca se da por terminado un cambio visual sin
mirar la captura real en ambos temas. Este procedimiento crea un usuario temporal de solo
lectura con contraseña aleatoria, captura las rutas con Chrome sin cabeza a 1440 px de ancho,
guarda también el HTML y elimina el usuario al terminar.

## Uso

```bash
bash .claude/skills/revision-visual/scripts/capturar.sh /activos/ /amenazas/tendencias
bash .claude/skills/revision-visual/scripts/capturar.sh            # páginas principales
ALTO=3000 bash .claude/skills/revision-visual/scripts/capturar.sh / # más alto para páginas largas
ROL=admin bash .claude/skills/revision-visual/scripts/capturar.sh /usuarios/ /ajustes/ /alertas-proceso/
```

Por defecto el usuario temporal es de **solo lectura**: las páginas de administración (Usuarios,
Ajustes, Credenciales, Alertas por proceso) responden 403, que es lo correcto. Para capturarlas,
`ROL=admin`.

Salida en `data/revision/capturas/<fecha-hora>/`: `<ruta>-claro.png`, `<ruta>-oscuro.png` y
`<ruta>.html`. El directorio queda de `si:si`. Mirar las imágenes con la herramienta de lectura;
para una zona concreta recortar con Pillow (`Image.open(...).crop((x0, y0, x1, y1))`).

## Qué comprobar en cada captura
1. Claridad: títulos, subtítulos y notas explican qué es cada cosa sin siglas sueltas.
2. Colores: solo con significado; categorías con colores vivos y distinguibles; ceros en gris;
   contraste suficiente en claro y en oscuro.
3. Gráficos: leyenda, etiquetas completas (categorías sin omitir, año completo en meses),
   totales legibles.
4. Tablas: anchos de columna razonables, sin recortes ni desbordes horizontales.
5. Recorrido guiado: la invitación global solo para usuarios nuevos; el aviso fijo no debe tapar
   contenido importante.
6. La comprobación de CSP la hace el propio guion: informa de `style=`/`on*=` en línea, colores
   literales en SVG y recursos externos en cada HTML capturado (todos deben ser 0).

## Reglas
- El usuario temporal se llama `revision@ejemplo.local`, es de solo lectura y se borra
  siempre, incluso si el guion falla (trampa `EXIT`). Nunca se captura con la cuenta real del usuario.
- No se envía correo ni se cambia nada más; las capturas son locales.
- Borrar directorios de capturas antiguos cuando ya no sirvan de evidencia.
