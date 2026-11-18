# Especificación de rediseño de la interfaz web — 2026-09-03

Documento de referencia para el rediseño visual de la interfaz de administración
(`webui/`). Fija la paleta, la tipografía, los componentes, el módulo de gráficos
SVG y qué gráfico va en cada página. Todo el trabajo debe atenerse a esto para
que el resultado sea coherente aunque lo implementen varias personas.

## 1. Restricciones duras (no negociables)

1. **CSP estricta se mantiene tal cual**: `default-src 'none'; script-src 'self';
   style-src 'self'; img-src 'self' data:; ...`. Por tanto:
   - Prohibido cualquier atributo `style="..."` en HTML o SVG.
   - Prohibido cualquier `on*="..."` y cualquier `<script>` o `<style>` en línea.
   - Prohibido cargar nada externo (fuentes, CDN, librerías). Cero dependencias nuevas.
   - Los gráficos son **SVG generados en el servidor** (Python). La geometría va en
     atributos SVG (`x`, `y`, `width`, `height`, `d`, `r`, `cx`, `cy`, `points`,
     `transform`, `stroke-dasharray`, `stroke-dashoffset`), que **no** son CSS y la
     CSP los permite. Los **colores nunca van en atributos**: van por **clase**
     (`class="serie-critico"`) y la hoja de estilos los resuelve con variables,
     así el modo oscuro funciona solo.
   - Los atributos SVG `fill`/`stroke` solo se permiten con los valores
     `none`, `currentColor` o `transparent`. Nunca un color literal.
2. **Escapado**: todo texto que salga de la base de datos (nombres de tecnologías,
   fuentes, títulos, CVE) pasa por `markupsafe.escape` antes de insertarse en el
   SVG. Un nombre de fuente es dato de terceros y puede contener `<`.
   Los `href` de los gráficos solo se aceptan si son rutas relativas que empiezan
   por `/` (generadas con `url_for`); cualquier otra cosa se descarta.
3. **Sin git**: no se ejecuta ningún comando git. La red de seguridad es
   `backups/snapshot_pre_rediseno_2026-09-03.tar.gz`.
4. **Propiedad de ficheros**: tras editar, `chown si:si` de lo tocado. Las pruebas
   se ejecutan como `sudo -n -u si .venv/bin/python -m unittest ...`.
5. **No romper nada**: las 74 pruebas existentes (`tests/test_regresiones.py`)
   deben seguir en verde. Todas las clases CSS que hoy usan las plantillas deben
   seguir existiendo (se pueden restilizar, no eliminar).
6. **No se tocan** los correos (`threatintel/emails/`), el informe DOCX, la lógica
   de dominio (`collector`, `matching`, `scoring`, `enrich`, `notify`), `webui/auth.py`,
   ni `webui/app.py`. Solo `webui/filtros.py` admite un cambio: registrar el módulo
   de gráficos como global de Jinja.
7. **Idioma**: toda etiqueta visible en español, sin abreviaturas (regla ya
   establecida: «Relevancia», no «Rel.»). Las siglas CVSS/EPSS/KEV llevan `title`.
8. **Accesibilidad**: cada `<svg>` lleva `role="img"` y `aria-label` descriptivo;
   cada barra/porción lleva un `<title>` con etiqueta y valor (tooltip nativo).
   Contraste mínimo 4.5:1 en texto normal, en claro y en oscuro.
9. **Números en español**: separador de miles `.` y decimales `,` (1.234 · 7,5).
10. **Estado vacío**: si no hay datos, el gráfico devuelve
    `<div class="grafico-vacio">Sin datos suficientes</div>`, nunca un SVG roto
    ni una excepción. Cero, `None` y listas vacías se toleran.

## 2. Paleta

Se declara en `:root` (claro) y se redefine en oscuro en **dos** sitios:
`@media (prefers-color-scheme: dark) { :root:not([data-tema="claro"]) {...} }` y
`:root[data-tema="oscuro"] {...}`, con los mismos valores. El selector manual
gana sobre la preferencia del sistema.

| Token | Claro | Oscuro | Uso |
|---|---|---|---|
| `--fondo` | `#f4f6f9` | `#0f141a` | fondo de página |
| `--fondo-panel` | `#ffffff` | `#171d25` | tarjetas y paneles |
| `--fondo-alt` | `#f8fafc` | `#1c232c` | cabeceras de tabla, pies |
| `--fondo-hover` | `#eef2f7` | `#222b36` | hover de filas y botones |
| `--borde` | `#e2e8f0` | `#2a3441` | bordes suaves |
| `--borde-fuerte` | `#cbd5e1` | `#3b4756` | bordes de controles |
| `--texto` | `#0f1b2d` | `#e6ebf2` | texto principal |
| `--texto-suave` | `#475569` | `#a7b3c2` | texto secundario |
| `--texto-tenue` | `#607087` | `#7d8a9b` | etiquetas, notas (antes `#7c8aa0`, 3,5:1 sobre blanco; ahora 5,0:1) |
| `--acento` | `#1e4d8c` | `#6fa8e6` | marca, enlaces, botón primario |
| `--acento-claro` | `#e6eef9` | `#1a2a40` | fondo del elemento activo |
| `--acento-hover` | `#163c6e` | `#8fbdf0` | hover del primario |
| `--secundario` | `#0e8c8a` | `#3fc1bd` | acento complementario (verde azulado) |
| `--secundario-claro` | `#e1f4f3` | `#10312f` | fondo del secundario |
| `--critico` | `#b91c1c` | `#f87171` | severidad Crítica |
| `--critico-fondo` | `#fdecec` | `#3a1a1a` | |
| `--alto` | `#dd6b20` | `#f5a25a` | severidad Alta |
| `--alto-fondo` | `#fdf1e7` | `#35251a` | |
| `--medio` | `#b7791f` | `#e3c25a` | severidad Media |
| `--medio-fondo` | `#fbf3e0` | `#302a17` | |
| `--bajo` | `#2b6cb0` | `#7bb4ea` | severidad Baja |
| `--bajo-fondo` | `#e8f1fb` | `#17273a` | |
| `--exito` | `#15803d` | `#5fd08a` | correcto / operativo |
| `--exito-fondo` | `#e6f6ec` | `#15301f` | |
| `--critico-texto` | `#b91c1c` | `#f87171` | **texto** Crítica (insignias, `.txt-*`, valores de métrica, avisos, chips) |
| `--alto-texto` | `#9a4a0c` | `#f5a25a` | **texto** Alta (el relleno `--alto` solo da 3,0:1 sobre `--alto-fondo`) |
| `--medio-texto` | `#7a5209` | `#e3c25a` | **texto** Media (el relleno `--medio` solo da 3,3:1 sobre `--medio-fondo`) |
| `--bajo-texto` | `#2b6cb0` | `#7bb4ea` | **texto** Baja |
| `--exito-texto` | `#136f37` | `#5fd08a` | **texto** correcto (`--exito` daba 4,48:1 sobre `--exito-fondo`) |
| `--secundario-texto` | `#0a6e6c` | `#3fc1bd` | **texto** sobre `--secundario-claro` (`.insignia.secundario`) |
| `--neutro` | `#94a3b8` | `#6b7a8f` | sin datos, desactivado, «otros» |
| `--kev` | `#7f1d1d` | `#fca5a5` | línea/insignia de explotación confirmada |
| `--cat-1` … `--cat-8` | `#1e4d8c #0e8c8a #d97706 #6d5bd0 #db5461 #5b7083 #2f9e6f #b56aa8` | `#6fa8e6 #3fc1bd #f5b95a #a99bf0 #f08a93 #8a9bb0 #5fd08a #d69bd0` | series categóricas (categorías, fuentes) |
| `--radio` | `8px` | | radio de paneles |
| `--radio-pequeno` | `6px` | | botones, controles |

Reglas de color: la severidad **siempre** usa su color semántico, en tablas, insignias
y gráficos. Los tokens base (`--critico`, `--alto`, `--medio`, `--bajo`, `--exito`, `--secundario`) son
**rellenos** (series SVG, `.barra span`, `.progreso`, `.punto`, bordes); cuando el color va en
**texto** se usa siempre la variante `*-texto`, calibrada para ≥ 4,5:1 (WCAG AA) sobre
`--fondo-panel` y sobre su `*-fondo` en ambos temas. En oscuro coinciden con el relleno. Las series categóricas (categorías de fuente, de tecnología) usan
`--cat-N` en orden. Éxito/fallo usa `--exito`/`--critico`. Lo desconocido o
desactivado usa `--neutro`. Nada más inventa colores.

## 3. Tipografía y ritmo

- Familia (desde 2026-09-04, recomendación de la habilidad `ui-ux-pro-max` para paneles de
  datos densos): **Fira Sans** para texto y **Fira Code** para datos y monoespaciado,
  alojadas en `webui/static/fonts/` (OFL, subconjunto latin, `font-display: swap`) con la
  pila del sistema como respaldo. No se cargan fuentes externas: la CSP solo admite
  `font-src 'self'`.
- Reglas de la habilidad aplicadas: objetivos interactivos ≥ 30 px (34 px los botones
  normales), `cursor: pointer` en todo lo interactivo, transiciones de 150 ms,
  `prefers-reduced-motion` respetado, ningún texto por debajo de 11 px, punto de
  ruptura a 480 px con una sola columna.
- Tamaños: cuerpo 14px; tablas 13px; etiquetas y notas 12px; etiquetas de eje 11px;
  títulos de página 22px/650; títulos de panel 14px/600; valor de métrica 30px/650
  con `letter-spacing: -.02em` y `font-variant-numeric: tabular-nums`.
- Espaciado en múltiplos de 4px. Rejilla de paneles con `gap: 18px`.
- Sombras suaves; en oscuro casi imperceptibles. Bordes de 1px siempre presentes.

## 4. Componentes

**Cabecera**: fondo `--fondo-panel`, borde inferior, y una **línea superior de 3px**
con degradado `--acento → --secundario` como firma de marca. Marca con icono SVG
en línea (escudo) + nombre + empresa. Navegación con estado activo por
**subrayado de 2px en `--acento`** y texto en `--texto`. A la derecha: usuario,
botón de tema (icono sol/luna, `data-tema-toggle`), contraseña, salir.

**Tema manual**: `webui/static/tema.js` se carga en `<head>` **sin `defer`** y aplica
`document.documentElement.dataset.tema` desde `localStorage['tema']` antes del
primer pintado (evita el parpadeo). `app.js` gestiona el botón y persiste. Valores:
`claro` | `oscuro` | ausente (sigue al sistema).

**Pie de sitio**: `<footer class="pie-sitio">` discreto: «Inteligencia de Amenazas ·
Mi Organización S.A. · Uso interno» y enlace a `/salud.json` solo para admin.

**Tarjeta de métrica** (`.panel.metrica`): borde izquierdo de 3px en el color del
estado (`.critico`, `.alto`, `.medio`, `.bajo`, `.exito`, `.neutro`; por defecto
`--acento`), valor grande, etiqueta en mayúsculas pequeñas, nota. Variante
`.metrica.con-chispa` en rejilla de dos columnas: texto a la izquierda y un
`graficos.chispa(...)` a la derecha (≈120×36).

**Panel** (`.panel`): radio 8px, cabecera con `h2` + `.sub` opcional + acciones a la
derecha; cuerpo; pie en `--fondo-alt`. `.panel-cuerpo.sin-relleno` para tablas.

**Tablas**: cabecera en `--fondo-alt`, sticky, 11px mayúsculas; filas con hover; sin
zebra; numéricas alineadas a la derecha con `tabular-nums`; `.tabla-compacta` más
densa. Columna de acciones al final, `nowrap`.

**Insignias** (`.insignia.{critical|high|medium|low|ok|neutra|kev}`): fondo suave y
texto en el color semántico; `kev` fondo sólido `--kev` texto blanco. Se mantienen
los alias en español (`critico`, `alto`, `medio`, `bajo`, `exito`).

**Botones**: `.btn` contorno, `.btn.primario` sólido acento, `.btn.peligro` contorno
crítico, `.btn.pequeno`. Foco visible (`outline` 2px acento).

**Avisos** (`.aviso.{exito|error|aviso-nivel|info}`): borde izquierdo 3px, fondo
suave, icono SVG en línea opcional.

**Formularios**: sin cambios funcionales; controles con radio pequeño, foco acento.

**Estado vacío** (`.vacio`): icono SVG en línea gris y dos líneas de texto.

**Impresión** (`@media print`): ocultar cabecera, botones, filtros y pie; paneles
sin sombra; gráficos a todo el ancho; el panel debe poder imprimirse como informe
de una hoja.

**Responsivo**: ≤ 820px la navegación pasa a segunda línea; las rejillas a una
columna; las tablas desplazan horizontalmente dentro de `.tabla-envoltorio`.

## 5. Módulo de gráficos `webui/graficos.py`

Funciones puras que devuelven `markupsafe.Markup`. Se registran como global de Jinja
en `webui/filtros.py`: `app.jinja_env.globals["graficos"] = graficos`. Las
plantillas los llaman así: `{{ graficos.dona(porciones, centro_valor=stats.total) }}`.
Los datos se preparan en las vistas (Python) como listas y diccionarios simples.

Estructura común del resultado:

```html
<figure class="grafico-envoltorio grafico-<tipo>">
  <svg class="grafico" viewBox="0 0 W H" role="img" aria-label="...">…</svg>
  <ul class="leyenda"><li><span class="leyenda-punto serie-critico"></span>Críticas <b>6</b></li>…</ul>
</figure>
```

Claves de serie admitidas (→ clase `serie-<clave>`, `linea-<clave>`, `area-<clave>`):
`critico`, `alto`, `medio`, `bajo`, `exito`, `neutro`, `acento`, `secundario`,
`kev`, `cat-1` … `cat-8`. Cualquier otra clave se sustituye por `neutro`.

### API

```python
fmt(valor, decimales=0) -> str
    # 1234 -> "1.234"; 7.5 -> "7,5"; None -> "—"

chispa(valores, *, ancho=120, alto=36, clave="acento", area=True) -> Markup
    # Sparkline sin ejes. Serie de números (None se trata como 0).

barras_apiladas(categorias, series, *, ancho=760, alto=240, linea=None,
                mostrar_totales=True, leyenda=True, aria="") -> Markup
    # categorias: etiquetas del eje X en orden cronológico ascendente (["may 2026", ...]).
    # series: [{"clave": "critico", "nombre": "Críticas", "valores": [..]}, ...]
    #         una posición por categoría. Se apilan en el orden dado.
    # linea: {"clave": "kev", "nombre": "En KEV", "valores": [..]} opcional,
    #        se dibuja como línea con puntos sobre las barras, misma escala Y.
    # Eje Y con 3 a 5 líneas de rejilla de paso redondo (la escala que menos eje desperdicia); totales sobre cada barra.
    # Etiquetas X: se espacian solo si no caben en su ranura; la primera y la última siempre se muestran.
    # La línea superpuesta lleva un halo (clase linea-halo) y, si sus valores son < 5 % del eje, se rotula cada punto.

barras_horizontales(items, *, ancho=760, alto_fila=28, max_etiqueta=30,
                    mostrar_total=True, leyenda=True, aria="") -> Markup
    # items: [{"etiqueta": "Windows Server", "valores": [("critico", 3), ("alto", 5), ("neutro", 10)],
    #          "href": "/amenazas/?tec=windows", "nota": "sin versión"}]
    # Una fila por ítem, barras apiladas de izquierda a derecha, escala común al máximo.
    # La etiqueta se recorta a max_etiqueta con «…» y el nombre completo va en <title>.
    # Si hay href válido, la etiqueta es un <a> dentro del SVG (xlink no hace falta: href directo).

dona(porciones, *, tamano=200, grosor=24, centro_valor=None, centro_etiqueta=None,
     leyenda=True, aria="") -> Markup
    # porciones: [{"clave": "critico", "nombre": "Críticas", "valor": 6}, ...]
    # Anillo con arcos (path). Porciones de 0 se omiten del dibujo pero siguen en la leyenda.
    # Leyenda con valor y porcentaje. Si la suma es 0 → estado vacío.

linea_tiempo(etiquetas, series, *, ancho=760, alto=220, area=True, leyenda=True,
             unidad="", aria="", tope=None) -> Markup
    # tope: máximo fijo del eje Y (10 para CVSS), con divisiones redondas.
    # series: [{"clave": "acento", "nombre": "Latencia (ms)", "valores": [..]}]
    # Líneas suavizadas no: polilíneas rectas con puntos; rejilla horizontal; eje Y auto.

barra_progreso(partes, *, alto=10, leyenda=True, total=None, aria="") -> Markup
    # Barra 100 % apilada (HTML+SVG). partes: [{"clave": "exito", "nombre": "Con CVSS oficial", "valor": 120}, ...]
    # Muestra porcentaje de cada parte en la leyenda. Ideal para «procedencia», «cobertura».

medidor(valor, maximo, *, etiqueta="", decimales=1, umbrales=None, tamano=160,
        sufijo="", aria="") -> Markup
    # Semicírculo (180°) con aguja o arco de progreso; el color se decide por umbrales:
    # umbrales: [(4.0, "bajo"), (7.0, "medio"), (9.0, "alto"), (inf, "critico")] para CVSS.
    # Para EPSS (0-100 %): [(10,"bajo"),(30,"medio"),(60,"alto"),(inf,"critico")], sufijo="%".
    # valor None → muestra «—» y arco neutro.

flujo(pasos, *, aria="") -> Markup
    # Diagrama de proceso horizontal (HTML+SVG de flechas): pasos: [{"titulo": "Recolección",
    #   "valor": "52 / 55", "nota": "fuentes operativas", "estado": "ok|atencion|critico|inactivo",
    #   "href": "/fuentes/"}]. Cada paso es una tarjeta con punto de estado; entre pasos una flecha.
```

Detalles de implementación obligatorios:

- Márgenes internos calculados para que las etiquetas de eje **nunca se corten**:
  eje Y ancho según el número más largo formateado; eje X con altura para una línea.
- Texto SVG: `<text class="eje">`, `<text class="etiqueta-valor">`, `<text class="dona-centro">`.
  La hoja de estilos fija `font-size`, `fill` y `font-family: inherit`.
- Cada `<rect>`/`<path>` de dato lleva `<title>Nombre: 1.234 (37 %)</title>`.
- Las funciones no lanzan excepciones con datos irregulares (longitudes distintas,
  `None`, negativos → se tratan como 0 y se registra nada).
- Sin estado global, sin `random`, sin `datetime.now()`.
- Pruebas en `tests/test_graficos.py`: escapado de `<script>` en etiquetas; ausencia
  de `style=` y de colores literales; estado vacío; suma de porciones; descarte de
  `href` externo o `javascript:`; formato de números; longitudes desiguales.

### Contrato CSS para los gráficos (en `estilo.css`)

```css
.grafico-envoltorio { margin: 0; }
.grafico { display: block; width: 100%; height: auto; font-family: inherit; overflow: visible; }
.grafico-dona .grafico { width: min(100%, 220px); margin: 0 auto; }
.grafico text { fill: var(--texto-suave); font-size: 11px; }
.grafico .etiqueta-valor { fill: var(--texto); font-weight: 600; }
.grafico .dona-centro { fill: var(--texto); font-size: 26px; font-weight: 650; }
.grafico .dona-centro-etiqueta { fill: var(--texto-tenue); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
.grafico .rejilla { stroke: var(--borde); stroke-width: 1; }
.grafico .eje-linea { stroke: var(--borde-fuerte); }
.grafico a text { fill: var(--acento); }
.grafico a:hover text { text-decoration: underline; }
.serie-critico { fill: var(--critico); }  .linea-critico { stroke: var(--critico); fill: none; stroke-width: 2; }  .area-critico { fill: var(--critico); opacity: .12; }
/* … igual para alto, medio, bajo, exito, neutro, acento, secundario, kev, cat-1 … cat-8 */
.grafico .punto { stroke: var(--fondo-panel); stroke-width: 2; }
.grafico .linea-halo { stroke: var(--fondo-panel); stroke-width: 5; fill: none; }   /* halo bajo la línea superpuesta */
.grafico .etiqueta-linea { font-size: 10px; paint-order: stroke; stroke: var(--fondo-panel); stroke-width: 3px; }
.leyenda { list-style: none; display: flex; flex-wrap: wrap; gap: 6px 16px; margin: 10px 0 0; padding: 0; font-size: 12px; color: var(--texto-suave); }
.leyenda li { display: inline-flex; align-items: center; gap: 6px; }
.leyenda b { color: var(--texto); font-weight: 600; }
.leyenda-punto { width: 10px; height: 10px; border-radius: 3px; display: inline-block; background: currentColor; }
.leyenda-punto.serie-critico { background: var(--critico); } /* … idem resto de claves */
.grafico-vacio { padding: 28px; text-align: center; color: var(--texto-tenue); font-size: 13px; border: 1px dashed var(--borde); border-radius: var(--radio); }
.progreso { height: 10px; border-radius: 5px; overflow: hidden; display: flex; background: var(--fondo-hover); }
.progreso span { display: block; height: 100%; }   /* ancho vía clases .ancho-N ya existentes (pasos de 5 %) o vía SVG */
.flujo { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0; align-items: stretch; }
.flujo-paso { position: relative; padding: 12px 14px; border: 1px solid var(--borde); border-radius: var(--radio); background: var(--fondo-panel); }
.flujo-paso .titulo { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: var(--texto-tenue); font-weight: 600; }
.flujo-paso .valor { font-size: 20px; font-weight: 650; margin-top: 2px; }
.flujo-paso .nota { font-size: 12px; color: var(--texto-suave); }
.flujo-paso.ok { border-top: 3px solid var(--exito); }  .flujo-paso.atencion { border-top: 3px solid var(--medio); }
.flujo-paso.critico { border-top: 3px solid var(--critico); }  .flujo-paso.inactivo { border-top: 3px solid var(--neutro); }
.flujo-flecha { display: flex; align-items: center; justify-content: center; color: var(--texto-tenue); }
```

Nota sobre `barra_progreso`: como no se puede escribir `width: 37%` en línea, o bien se
dibuja con SVG (`<rect width="37">` en un `viewBox="0 0 100 10"` con
`preserveAspectRatio="none"`), que es la opción preferida por precisión, o bien se
usan las clases `.ancho-N` existentes (pasos del 5 %).

## 6. Qué gráfico va en cada página

Orden de lectura en cada página: **1) qué pasa ahora, 2) cuánto y cómo evoluciona,
3) detalle en tabla, 4) glosario**. Un gráfico nunca sustituye a la tabla: la
acompaña. Cada gráfico lleva título de panel y una frase `.sub` que dice qué
pregunta responde.

### Panel (`/`) — `panel.html`, `vistas/panel.py`
1. Avisos de estado global y credenciales (existentes, restilizados).
2. **Diagrama de flujo** (`flujo`) con la última ejecución: Recolección (fuentes
   operativas/activas), Correlación (amenazas nuevas), Enriquecimiento (CVE
   pendientes y % con CVSS oficial), Alerta (alertadas y última alerta), Informe
   mensual (próxima fecha o último generado). Estado por umbrales razonables.
3. **Fila de métricas con chispa** (`chispa` de los últimos 6 meses): Amenazas del
   periodo, Críticas, Altas, En KEV; quinta tarjeta: Pendientes de alertar.
4. **Fila de dos paneles**: izquierda (2/3) `barras_apiladas` de los últimos 6
   meses por severidad (Críticas, Altas, Medias, Bajas) con línea KEV; derecha (1/3)
   `dona` de severidad del mes actual con el total en el centro.
5. **Fila de dos paneles**: izquierda `barras_horizontales` de las 8 tecnologías
   más afectadas (Críticas, Altas, Resto), con nota «sin versión» cuando falta y
   enlace a la consulta filtrada; derecha `dona` del estado de las fuentes
   (Operativas, Degradadas, Caídas, Sin comprobar) + lista de las no operativas.
6. **Calidad del dato** (tres `barra_progreso`): procedencia de la severidad
   (NVD, vector CVSS, KEV, heurística); progreso de enriquecimiento (con CVSS
   oficial vs pendientes); cobertura del inventario (con versión vs sin versión).
7. Pendientes de alertar y últimas ejecuciones (tablas existentes); estado
   técnico con `barra_progreso` del disco y estado del traductor.
8. Glosario (ya incluido).

Para las consultas que no existen en `queries.py` (procedencia por
`severity_source`, cobertura del inventario, categorías) se usa SQL local en
`vistas/panel.py`; **no** se edita `queries.py` desde el panel (lo edita Tendencias).

### Tendencias (`/amenazas/tendencias`) — `tendencias.html`, `vistas/amenazas.py::tendencias`, `threatintel/queries.py`
1. Métricas del periodo (existentes) y selector de mes.
2. **`barras_apiladas` de hasta 24 meses** por severidad con línea KEV; debajo la
   tabla «Serie mensual» existente.
3. Fila: `dona` de severidad del mes seleccionado; `barras_apiladas` en modo
   100 % o `barra_progreso` por mes de la **procedencia** (NVD oficial vs estimada) para
   ver la madurez del dato; `linea_tiempo` del CVSS medio mensual.
   `evolucion_mensual` puede ampliarse con `bajas`, `sev_nvd`, `con_cve`,
   `cvss_medio` conservando las claves actuales.
4. **`barras_horizontales`** de las 20 tecnologías más afectadas apiladas por
   veredicto (Confirmadas, Sin determinar, Descartadas), con enlace; tabla debajo.
5. CVE recurrentes: tabla existente más `barras_horizontales` compacta de «meses
   presentes» para los 10 primeros.
6. Glosario.

### Fuentes (`/fuentes/`) e Inventario (`/tecnologias/`) — `fuentes.html`, `fuente_detalle.html`, `tecnologias.html`, `tecnologia_detalle.html`, `vistas/fuentes.py`, `vistas/tecnologias.py`
Fuentes: `dona` de estado (Operativas, Degradadas, Caídas, Sin comprobar,
Desactivadas en neutro); `barras_horizontales` de las 10 fuentes que más amenazas
han aportado (recuento en `threat_sources`) coloreadas por categoría (`cat-N` por
categoría, leyenda de categorías); en la tabla, columna «Últimas comprobaciones»
con `chispa` de las 15 últimas (1 = correcta, 0 = fallo) o de entradas aceptadas.
Detalle de fuente: `linea_tiempo` de latencia y de entradas aceptadas de las
últimas 60 comprobaciones; `barra_progreso` de tasa de éxito.

Inventario: `dona` por criticidad; `barras_apiladas` por categoría de tecnología
(Con versión / Sin versión) para ver dónde falta completar; `barras_horizontales`
de las 10 tecnologías con más amenazas. Detalle de tecnología: `dona` de
veredictos (Afectada, No afectada, Sin determinar) y `barras_apiladas` por mes
de sus amenazas por severidad (consulta local `GROUP BY month`).

### Amenazas (`/amenazas/`, `/amenazas/<id>`) — `amenazas.html`, `amenaza_detalle.html` (solo plantillas)
Detalle: tres `medidor`: CVSS (0-10, umbrales 4/7/9), EPSS (0-100 %, umbrales
10/30/60), Relevancia (0-100, umbrales 25/50/75), en una fila encima de la ficha;
si el valor es `None` el medidor muestra «—». Debajo, línea de hitos simple
(primera vez visto, última vez, alertada) con `flujo` en modo compacto.
Lista: restilizado; sin gráficos nuevos (la consulta paginada no tiene agregados).
**No se edita `vistas/amenazas.py`** desde aquí (lo edita Tendencias).

### Resto de páginas
Credenciales, Ajustes, Auditoría, Login, Contraseña, Error: solo cambian por la
hoja de estilos. Login: marca con icono, tarjeta centrada, sin gráficos.

## 7. Verificación

1. `sudo -n -u si .venv/bin/python -m unittest discover -s tests -p "test_*.py"` en verde.
2. Ninguna plantilla ni SVG contiene `style=`, `on[a-z]+=`, `<script>` en línea,
   colores literales en `fill=`/`stroke=` (salvo `none`/`currentColor`/`transparent`),
   ni URL externas.
3. Captura de pantalla de cada página en claro y oscuro con
   `/tmp/claude-0/-home-si-IA-inteligencia-amenazas/eaa2eadf-2bc7-48d0-bf0d-96806d3225fc/scratchpad/capturas/capturar.sh`
   y revisión visual: legibilidad, sin solapes, colores coherentes con la tabla
   adyacente, cifras del gráfico iguales a las de la tabla, modo oscuro correcto.
4. `systemctl restart threat-intel-webui` y comprobación en vivo de HTTP 200 en
   todas las rutas con sesión, y de que la cabecera CSP sigue sin `unsafe-`.

## Ampliación 2026-09-04 · armazón de consola

Tras aplicar la habilidad `ui-ux-pro-max` (dirección «Data-Dense Dashboard», tipografía Fira alojada en local), la interfaz pasó de una barra superior con enlaces planos a un armazón de consola:

- **Barra lateral fija** (`.nav-lateral`, 232 px) con la navegación agrupada en Operación (Panel, Amenazas, Tendencias), Inventario (Inventario, Fuentes) y Administración (Credenciales, Ajustes, Auditoría), cada entrada con icono SVG en línea y marca de sección activa. Se puede plegar a solo iconos; la preferencia se guarda en `localStorage` («nav»). En pantallas de hasta 900 px se convierte en cajón deslizante con botón en la barra superior y cierre con Escape.
- **Barra superior** (`.barra-superior`) con el nombre de la sección actual, el **buscador global** (envía a Amenazas con todos los estados; la tecla `/` lo enfoca) y la zona de sesión (tema, contraseña, salir).
- **Variación a 30 días** en las cuatro métricas del panel (`_variaciones_30_dias` en `webui/vistas/panel.py`, macro `variacion` en `panel.html`): flecha, porcentaje y texto «más/menos que los 30 días anteriores», con el detalle de ambas cifras en el atributo `title`. El texto de la tarjeta va agrupado en `.metrica-texto` para no romper la rejilla texto | gráfico.
- **Vistas rápidas** en Amenazas (`.chips-rapidos`): Abiertas, Críticas, KEV, Este periodo, Más recientes, Cerradas, Todas.
- **Versionado de estáticos**: `url_for('static', …)` añade `?v=<mtime>` (`_version_estaticos` en `webui/app.py`) para que CSS/JS nuevos no queden atrapados en la caché del navegador.

Todo sigue bajo la misma CSP estricta (sin estilos ni scripts en línea; el comportamiento vive en `app.js`/`tema.js` con atributos `data-*`). Verificación: 386 pruebas, capturas a 1440 px (claro/oscuro) y 375 px.

## Ampliación 2026-09-04 · Activos, ficha de activo y Software

Tres páginas nuevas en el grupo «Inventario» de la barra lateral, con el mismo orden de
lectura que el resto (qué pasa ahora → cuánto y cómo → detalle en tabla) y la misma CSP:

- **Activos** (`/activos/`): cinco métricas (activos; con vulnerabilidades confirmadas; fuera
  de soporte; sin reportar; tecnologías con activos), dona por familia de sistema, barras
  horizontales de las diez versiones de sistema con más activos coloreadas por situación de
  soporte (fuera / menos de seis meses / con soporte), tabla «Fin de soporte» y tabla de
  activos con filtros (texto, tipo, sistema, orden), vistas rápidas con recuento y paginación
  de 50. Cada fila enlaza a la ficha y muestra insignias de soporte, «sin reportar», KEV y
  hallazgos de política. Pie con el estado de la última sincronización de cada OCS.
- **Ficha de activo** (`/activos/<id>`): métricas de veredictos, avisos de fin de soporte y
  de activo ciego, formulario «¿Le aplica este CVE?» (POST, respuesta en bloque
  `.respuesta-cve` coloreado por veredicto con líneas de explicación y tabla por paquete),
  datos de OCS en tabla clave-valor (`.tabla-datos`), dona de veredictos, hallazgos, tabla de
  amenazas evaluadas (afectadas primero) y software instalado con búsqueda y casilla para
  ver el no clasificado. Exportación CSV de los veredictos.
- **Software** (`/activos/software`): cobertura del mapa de nombres (barra de progreso),
  formulario de regla nueva (administradores), propuestas automáticas con botón «Aceptar»,
  software sin clasificar con clasificación en línea, tecnologías con activos y dispersión de
  versiones, y tabla de reglas con baja.

Integraciones: bloque «Activos afectados» en la ficha de amenaza (con «Cómo se evaluó»),
panel «Activos de la organización» en el Panel (fila de cuatro paneles), columna «Sistemas»
del Inventario enlazada a los activos de cada tecnología y panel «Versiones instaladas según
OCS Inventory» en la ficha de tecnología. Glosario ampliado con Activo, Aplicabilidad por
activo, OSV.dev y VuXML, Fin de soporte y Mapa de nombres.

## Ampliación 2026-09-05 · paleta sobria, recorrido guiado y claridad

- **Paleta**: acento azul marino (#1f4e79) y tonos semánticos apagados (rojo #a33a3a, naranja #b5662f, ocre #a3892f, azul #3d6b9e, verde #2f7a5a); categorías en tonos afines (marino, azul acero, verde azulado, mostaza, ciruela, pizarra, salvia, terracota). Todos los pares texto/fondo superan 5,5:1 en claro y oscuro (comprobado). Entornos: rojo producción, ámbar contingencia, verde azulado desarrollo, violeta pruebas, pizarra soporte.
- **Recorrido guiado**: icono de ayuda en la barra superior; cada página declara sus pasos con `data-tour`, `data-tour-titulo` y `data-tour-texto` en el contenedor del panel; `app.js` resalta cada bloque con un foco y una tarjeta (flechas y Escape). La primera visita muestra un aviso abajo a la derecha; se recuerda en `localStorage`.
- **Claridad**: sin etiquetas vagas («Resto» → «Medias y bajas», «Otras categorías» → «Otras N categorías»); las siglas se explican en su primera aparición y en el glosario; el indicador «Pendientes de alertar» del panel usa el criterio real de la alerta.
- **Tabla de activos**: anchos fijos por columna (`colgroup`) y salto de línea en celdas; ninguna columna se come a las demás.

## Ampliación 2026-09-05 (noche) · regla de color en Activos y recorrido en todas las páginas

- **Regla de color** (aplicada primero en Activos, extensible al resto): el color solo se usa
  cuando significa algo. Rojo = riesgo o sin soporte; naranja/ocre = atención o soporte próximo
  a terminar; verde = correcto; azul corporativo = exposición o marca; gris = sin dato o cero.
  Un indicador a cero **no** se pinta de verde: va neutro (`.metrica.neutro`), porque un cero en
  color llama la atención sobre nada.
- **Gama monocroma** `tono-1`…`tono-6` (variables `--tono-*` en claro y en ambos bloques
  oscuros; clases `.serie-tono-*`, `.linea-tono-*`, `.leyenda-punto.serie-tono-*`; los dos
  tonos más claros llevan borde fino en la leyenda). Se usa para repartos sin significado
  propio: la dona de **familias de sistema** va de mayor a menor (el azul más oscuro es la
  familia con más activos; «sin datos» en gris al final).
- **Entornos como escala de exposición**: producción `tono-1`, contingencia `tono-2`,
  desarrollo `tono-3`, pruebas `tono-4`, soporte `tono-5`, sin entorno gris; orden fijo en la
  dona (`ORDEN_ENTORNOS`). Las insignias `.insignia.entorno-*` ya no llevan un tono por
  entorno: solo distinguen expuesto (azul corporativo, negrita) de no expuesto (gris).
- **Lo desconocido en gris**: «Sin ciclo conocido» dejó de pintarse con el color de marca; se
  agrupa con «Sin dato de soporte» (neutro) en el gráfico de versiones.
- **Botón «N · ver»** de vulnerabilidades: sobrio en reposo (borde neutro, cifra en rojo,
  numeración tabular); se tiñe al pasar el ratón o al estar desplegado. Así la insignia KEV es
  lo único que destaca en cada fila.
- **Recorrido guiado en todas las páginas**: se añadieron pasos a Tendencias (8), ficha de
  fuente (7), plan de remediación (3, el primer grupo lleva el paso), cambiar contraseña (2),
  Ajustes (3) y Auditoría (2); la ficha de tecnología incorpora «Versiones reales» y «Ficha del
  inventario» (8 pasos). Los atributos van siempre en la etiqueta de apertura del panel, nunca
  en `panel-cabecera` ni en una etiqueta de cierre.
- Pruebas nuevas en `tests/test_recorridos_paleta.py` (toda plantilla con `base.html` salvo
  `error.html` tiene al menos dos pasos; la gama y la regla del cero neutro están fijadas).
  Copia previa de la hoja de estilos: `backups/estilo_pre_paleta2_2026-09-05.css`.

### Corrección 2026-09-05 (noche, segunda pasada) · colores distintos por categoría

El usuario rechazó la gama monocroma («solo veo escalas de colores sobre uno mismo… la idea es
que se diferencie bien la información»). Queda así:

- **Paleta categórica** `cat-1`…`cat-8`: azul marino #1f4e79, turquesa #1f8f85, ámbar #c9871d,
  violeta #7a5aa6, verde oliva #7d9a2f, frambuesa #c2507a, azul cielo #3d93cc, marrón #8d6b4b
  (tema oscuro: #6f9bd6, #5ccdc0, #f2b64f, #b48ce4, #a7d05c, #ee8bb0, #7fd0ec, #c9a57e). Cualquier
  par, incluido el gris de «sin datos», tiene distancia perceptual dE76 ≥ 25 y cada color
  contrasta ≥ 3:1 con el fondo; `tests/test_recorridos_paleta.py` lo comprueba leyendo la hoja de
  estilos (tema claro, oscuro explícito y oscuro del sistema; la hoja de impresión usa la clara).
  La gama `tono-*` se retiró.
- **Sistemas operativos** (Activos): color fijo por familia (Ubuntu ámbar, Debian frambuesa,
  FreeBSD violeta, Windows azul cielo, CentOS oliva, otros marrón, sin datos gris), porciones de
  mayor a menor.
- **Entornos** (Activos): producción azul marino, contingencia turquesa, desarrollo oliva,
  pruebas violeta, soporte marrón, sin entorno gris; orden fijo de más a menos expuesto. Las
  insignias de la tabla siguen distinguiendo solo expuesto (azul) de no expuesto (gris).
- **Tecnologías con más amenazas** (Inventario y Panel): «Medias y bajas» se separa en Medias
  (ocre) y Bajas (azul); la consulta suma también `medias`.
- **Tecnologías más afectadas** (Tendencias): apiladas por severidad con los cuatro colores de
  la plataforma. Apilar por veredicto dejaba el gráfico de un solo color mientras falten
  versiones (217 «sin determinar» frente a 1 confirmada). El veredicto va en la nota de cada
  barra («3 confirmadas», «sin versión») y en la tabla.
- **CVE recurrentes** (Tendencias): cada barra con el color de la severidad mayor del CVE, la
  severidad escrita junto al total y la marca «explotación activa (KEV)»; la tabla añade la
  columna Severidad con la insignia KEV. Sin leyenda: sumaría meses por color.
- Se unificó el gris `--neutro` del tema oscuro explícito (#7f8b98, igual que el del sistema).

### Corrección 2026-09-05 (noche, tercera pasada) · colores vivos

El usuario pidió «colores vivos y que hagan contraste» en Entornos, «no algo pálido». La paleta
categórica pasa a tonos saturados: azul #1d5fbf, cian #0891b2, naranja #e0700f, violeta #7c3aed,
lima #65a30d, magenta #c2185b, dorado #b8860b, esmeralda #0f9d58 (oscuro: #5b9cf6, #22c3e6,
#fb923c, #a78bfa, #a3d94a, #f472b6, #facc15, #34d399); mismas garantías (dE76 ≥ 25 entre pares,
contraste ≥ 3:1) y misma prueba. Entornos: producción azul, contingencia naranja, desarrollo
esmeralda, pruebas violeta, soporte magenta, sin entorno gris. Sistemas: Ubuntu naranja, Debian
magenta, FreeBSD violeta, Windows cian, CentOS lima, otros dorado.

### Corrección 2026-09-05 (noche) · eje X: año completo y nombres de categoría siempre visibles

- **Meses en dos líneas**: en «Serie mensual» (Tendencias), «Evolución de los últimos meses»
  (Panel), la evolución de la ficha de tecnología y el CVSS medio mensual, cada etiqueta del eje X
  lleva el mes abreviado arriba y el **año completo** debajo («sep» / «2026»). Así caben doce o
  más meses sin omitir ninguno y el año se lee entero (antes «sep 26»). El módulo de gráficos
  admite `\n` en las etiquetas (`<tspan>` por línea), reserva una línea más de margen inferior
  y escribe la etiqueta en una sola línea en los `<title>` y en el texto accesible.
- **Modo categórico** (`barras_apiladas(..., categorico=True)`, usado en «Cobertura de versiones
  por categoría»): nunca se omite el nombre de una categoría. Si no cabe en su ranura se
  reparte por palabras en hasta tres líneas («Otras 14» / «categorías») y, en último extremo, se
  recorta con «…» dejando el nombre completo en un `<title>`. El espaciado de etiquetas
  (primera y última siempre) queda solo para series temporales.
- Pruebas: `test_graficos` (dos líneas, categórico, margen), `_mes_corto` en Panel e Inventario
  y las páginas de Tendencias y Panel actualizadas al nuevo formato.

### Ampliación 2026-09-05 (tarde) · recorrido completo para usuarios nuevos e icono de pestaña

- **Una sola invitación por usuario.** Antes cada sección mostraba «¿Primera vez en esta
  sección?» en la primera visita, guardado por navegador, y la pregunta parecía repetirse.
  Ahora la invitación es única y global: `<body data-tour-estado="pendiente">` cuando el
  usuario nunca respondió; su respuesta (empezado, rechazado, completado) se guarda en
  `users.tour_estado` / `tour_at` mediante `POST /tour/respuesta` (sesión y CSRF), así que no
  se repite en el siguiente acceso ni cambia por navegador o equipo. Con «pendiente» se
  reinicia (por si se quiere volver a invitar a alguien).
- **Recorrido completo encadenado.** «Empezar el recorrido» lleva a la primera sección del
  menú lateral y, al terminar los pasos de cada sección, el botón pasa a «Siguiente sección:
  …» hasta la última («Terminar el recorrido»). La tarjeta indica «Sección k de N · Paso i de
  m». El encadenado vive en `sessionStorage` (`tour:completo`); salir a mitad lo da por
  terminado y no se vuelve a preguntar. Desde la tarjeta del recorrido de cualquier sección
  hay un enlace «Recorrido completo por todas las secciones» para repetirlo cuando se quiera;
  el icono de ayuda sigue recorriendo solo la sección actual.
- **Icono de pestaña**: `webui/static/favicon.svg` (escudo con marca sobre azul corporativo)
  enlazado desde `base.html`; pendiente añadirlo a `login.html` cuando termine el trabajo del
  segundo factor sobre esa plantilla.

---

## Ampliación 2026-09-07 · paginación, confirmación en la página y dos piezas nuevas

### `[hidden]` tiene que ganar siempre

Al principio de `estilo.css`, junto al `box-sizing`:

```css
[hidden] { display: none !important; }
```

El `display: none` que el navegador da a `[hidden]` es de **especificidad cero**, así que
cualquier clase con `display` propio lo vencía. `.btn { display: inline-flex }` dejaba a la
vista botones que el código daba por ocultos: el «Filtrar» que la búsqueda en vivo retira
y el de una acción mientras se confirma. Es una
regla de reinicio, no un parche puntual: cualquier `el.hidden = true` de `app.js` depende
de ella.

### Paginación (`_paginacion.html`)

Pieza nueva del catálogo. Macro con parámetros (un `include` no los admite), **20 filas por
página** (tamaño pedido por el usuario), en todos los listados largos. Clases y reglas:

| Clase | Qué es |
|---|---|
| `.paginacion` | la barra, con `border-top` y `flex-wrap` |
| `.paginacion-info` | el recuento, en su propia línea (`flex: 1 1 100%`) y con `tabular-nums` |
| `.paginacion-boton` | Primera, Anterior, Siguiente, Última: **44 × 44 px mínimo** |
| `.paginacion-numero` | los números de página, con `tabular-nums` |
| `.paginacion-actual` | la página actual, en negrita y con `aria-current="page"` |
| `.paginacion-elipsis` | el salto entre tramos de números |

Decisiones: los controles que no llevan a ninguna parte son `<button disabled>` de verdad
y **no desaparecen**, para que la fila no cambie de tamaño al navegar y para que un lector
de pantalla los anuncie como no disponibles. El recuento va en su propia línea para que no
empuje a los botones. Por debajo de 640 px se esconden los números intermedios (siguen en
el recuento) y quedan los cuatro botones y la página actual. Las cifras de los `aria-label`
pasan por el filtro `numero`, porque un lector de pantalla las lee en voz alta.

### Confirmación en la propia página (`.confirmacion-en-linea`)

Pieza nueva. Sustituye a `window.confirm`, que el usuario veía «como si se ejecutara
código JavaScript». La construye `app.js` a partir de `data-confirm` y `data-confirm-si`,
sin `style=` ni `on*=`.

```css
.confirmacion-en-linea { display: flex; flex-direction: column; gap: 8px;
  align-items: flex-start; margin-top: 8px; padding: 10px 12px; max-width: 340px;
  background: var(--medio-fondo); border-left: 3px solid var(--medio);
  border-radius: var(--radio-pequeno); text-align: left; white-space: normal; }
```

`text-align: left` y `white-space: normal` anulan lo que heredaría de una celda de
acciones (`text-align: right`, `nowrap`). El texto usa `--medio-texto` sobre
`--medio-fondo`: **5,97:1 en tema claro y 8,68:1 en oscuro**, medidos. Los dos botones
llevan `min-height: 44px` porque uno de ellos ejecuta una acción destructiva. El botón que
confirma hereda la clase `peligro` solo si la traía el botón original.

### Cabecera de panel: los hijos deben poder encoger

```css
.panel-cabecera > * { min-width: 0; }
.panel-cabecera h2 { overflow-wrap: anywhere; }
.panel-cabecera .sub { flex: 1 1 100%; order: 3; overflow-wrap: anywhere; }
```

Sin `min-width: 0` un título o una descripción larga desborda el cuadro en las columnas
estrechas y al aumentar la página. Es la regla «Long Token Wrapping» de la base de
conocimiento de interfaz: dejar que el hijo flexible encoja y que la palabra rompa, en
lugar de recortar el texto. Nunca `overflow: hidden` sobre prosa.

El cuadro «Estado de los activos (OCS Inventory)» era la cuarta columna de una rejilla de
190 px mínimos: ahí no cabían ni su descripción ni sus cuatro cifras. Pasó a **ancho
completo**, con los tres cuadros de calidad del dato en una rejilla de tres columnas y sus
cuatro cifras en fila. Comprobado sin fugas entre 500 y 1.920 px de ancho.

### Icono de Remediación

Era un visto grande con un ángulo suelto arriba a la izquierda, que se confundía con los
vistos de Auditoría. Ahora es una **llave inglesa**: se entiende como «arreglar» sin leer
la etiqueta. La base de iconos de la habilidad `ui-ux-pro-max` no tiene filas, así que se
siguió la convención propia del proyecto (24 × 24, `fill="none"`, trazo 1,8, extremos y
uniones redondeados).

### Activos: tipo, entorno y proceso en columnas propias

«Tipo y entorno» apilaba tres datos en una celda. Ahora son tres columnas, cada una con
`title` explicativo en el encabezado, y las dos que pueden faltar dicen «Sin entorno» y
«Sin proceso» en gris atenuado en lugar de quedarse vacías: una celda vacía no distingue
entre «no lo sabemos» y «no aplica». El CSV lleva las mismas tres columnas.

## Ampliación del 8 de septiembre de 2026: paleta de doce colores, versiones de sistema, informes

**Paleta categórica de ocho a doce colores** (`--cat-1…--cat-12`): claro `#1d5fbf` azul,
`#0891b2` cian, `#e0700f` naranja, `#7c3aed` violeta, `#65a30d` lima, `#c2185b` magenta,
`#b8860b` dorado, `#0f9d58` esmeralda, `#7a3e12` marrón, `#6d1b7b` ciruela, `#0d9488` verde
azulado, `#5b5a17` oliva; oscuro `#5b9cf6`, `#22c3e6`, `#fb923c`, `#a78bfa`, `#a3d94a`,
`#f472b6`, `#facc15`, `#34d399`, `#c98a5e`, `#d946ef`, `#0d9488`, `#d9d26b` (corrección del 9
de septiembre de 2026: este párrafo decía `#0f766e` y `#a7f3d0` para `--cat-11`; los valores
vigentes en `estilo.css` son `#0d9488` en los dos temas). Cualquier par,
incluido el gris de «sin datos», guarda una distancia perceptual dE76 ≥ 25 y cada color tiene
contraste ≥ 3:1 sobre el fondo del panel en los dos temas (`tests/test_recorridos_paleta.py`).

**Gráfica «Versiones de sistema con más activos»** (Activos): a petición del usuario («que se
diferencien y no se repitan los colores»), cada versión lleva un color categórico propio sin
repetir; por eso se limita a las doce versiones con más activos y dice debajo cuántas versiones
y activos quedan fuera. El estado de soporte ya no se codifica en color: se escribe en la nota
de cada barra con **mes y año** («sin soporte desde abril de 2025», «fin de soporte en abril
de 2027», «soporte hasta junio de 2027», «sin dato de soporte»; `activos._nota_soporte`), el
número lleva la unidad («314 activos», «1 activo») y la leyenda lista las versiones. La
primera versión escribía la fecha completa con el día y la nota se comía el ancho de la barra
(la menor medía 4,6 px, revisión del 2026-09-08); el día exacto sigue en la tabla «Fin de
soporte» y en la ficha de cada activo. «Sin datos de sistema»
sigue en gris y no consume color de la paleta.

**Informes** (`/informes/`, administradores y operador SOC): lista de meses con amenazas (tres
severidades por la regla interna, con unidad) y botón «Generar y descargar» que produce en
memoria el informe mensual `.docx` («informe_amenazas_AAAA-MM.docx») sin correo ni copia en
disco, auditado como «informe.generado». El resumen ejecutivo se redacta con la plantilla
determinista, no con el modelo de lenguaje (200 s medidos frente a los 120 s de tiempo máximo
de nginx), y la página lo indica. **Tendencias**: botón «Descargar el informe de <mes>» junto
al selector (mismo permiso) y panel «Serie anual de amenazas»: una barra por año con
críticas, altas y medias, leyenda, unidad «amenazas» y meses con datos; selector «Año del
detalle mensual» y los doce meses del año elegido con los meses sin amenazas marcados; el total
anual es la suma exacta de los meses (`queries.serie_anual` y `queries.evolucion_mensual`).

## Perfiles segmentados (2026-09-08)

Petición del usuario, literal: «Se debe de segmentar los roles, uno para redes y otro para
mantenimiento donde redes solo ve vulnerabilidades de servidores y mantenimiento solo vea
vulnerabilidades de equipos de cómputo […] y el rol servicios tecnológicos se les dé solo a los
jefes del proceso donde pueda ver vulnerabilidades de servidores y de equipos al mismo tiempo y
los avances de cada uno»; «Crear el rol de operador soc»; «el apartado de fuentes que se
encuentra en el menú debe ir en administración para que no todos los roles lo vean». La lógica
vive en `webui/auth.py` (`ROLES`, `ROL_ES`, `ROL_ALCANCE_ES`, `ROL_ORIGEN`, `ROLES_*`) y se
describe en la tabla «Perfiles de acceso» del `README.md`; aquí, lo que cambia en la interfaz.

### Qué ve cada perfil en el menú (`base.html`)

| Grupo del menú | Administrador | Operador SOC | Servicios Tecnológicos | Redes | Mantenimiento | Solo lectura |
|---|---|---|---|---|---|---|
| Operación: Panel, Amenazas, Tendencias | sí | sí | sí | sí | sí | sí |
| Operación: **Informes** | sí | sí | no | no | no | no |
| Inventario: Activos, Software, Remediación, Correcciones pendientes, Inventario | sí | sí | sí | sí, «Inventario · servidores» | sí, «Inventario · equipos de cómputo» | sí |
| Administración: **Fuentes**, Credenciales, Ajustes, Alertas por proceso, Usuarios, Consultas a OCS, Auditoría | sí | no | no | no | no | no |

Regla: **un enlace que respondiera 403 sería un callejón sin salida**, así que el menú solo
pinta lo que el perfil puede abrir (`puede_informes`, `es_admin`, `alcance_origen` y
`alcance_es` llegan a las plantillas desde `webui.auth`, la misma fuente que aplican los
decoradores). `tests/test_roles_alcance.py::test_ningun_enlace_del_menu_devuelve_403` sigue
todos los enlaces del menú con cada perfil. La barra superior dice el perfil junto al nombre, y
Mi perfil y el selector de Usuarios muestran `ROL_ALCANCE_ES` (más de 20 caracteres por perfil,
exigido por prueba) para que nadie tenga que adivinar qué puede hacer.

### El recorte se nota, pero no se explica dos veces

Con un perfil acotado (Redes o Mantenimiento):

- **Selectores de tipo de máquina ocultos**: en Amenazas y en Activos el `<select>` de tipo va
  dentro de `{% if not alcance_origen %}` (`amenazas.html` línea 65, `activos.html` línea 221).
  Un selector con una sola opción que además no puede cambiar es ruido; el servidor ignora el
  parámetro de todos modos (`auth.origen_efectivo`). Las opciones que sí se ofrecen salen de
  `ocs.ORIGEN_PLURAL_ES` filtradas por `auth.dentro_del_alcance`.
- **Frase del Panel**: el bloque «Estado de los activos (OCS Inventory)» dice «N activos
  (servidores)» o «N activos (equipos de cómputo)» (`panel.html` línea 453, `activos.acotado`)
  en lugar de «N activos (X servidores y Y equipos de cómputo)», y sus cuatro cifras se calculan
  solo sobre el tipo del perfil (`panel._estado_activos_en_alcance`). Una cifra del otro tipo,
  aunque fuera cero, revelaría que existe.
- **Título de Remediación**: «Remediación · servidores» y la primera frase «Solo servidores: su
  perfil no ve el otro tipo de máquina.» (`remediaciones.html` líneas 26 y 27). El panel de
  avance por tipo de máquina (`_avances_por_tipo`, `auth.ROLES_AVANCES`) solo se pinta para
  Administrador, Operador SOC y Servicios Tecnológicos: comparar dos tipos no tiene sentido
  para quien ve uno.
- **Ficha de tecnología**: la cifra de activos de OCS es de toda la organización y la nota lo
  dice («la lista de Activos solo muestra servidores», `tecnologia_detalle.html` línea 45),
  porque el inventario de tecnologías no está partido por tipo de máquina.
- El resto de páginas no cambia de forma: las consultas llevan `auth.filtro_alcance_sql` y las
  tablas simplemente no tienen filas del otro tipo. Las exportaciones a CSV aplican el mismo
  filtro.

### 403 y 404 uniformes

- **403** para una sección que el perfil no puede abrir (Administración, Informes, acciones de
  operación o remediación sin permiso): «Acceso inválido» y el detalle fijo «No tiene permiso
  para realizar esta acción.» (`auth.MENSAJE_403`). El manejador ignora la descripción del
  `abort` y `error.html` no nombra al administrador ni al perfil que haría falta: decirlo le
  indicaría a quien prueba qué cuenta tendría que robar.
- **404** para un activo fuera del alcance (`auth.exigir_alcance`), **idéntico** al de un
  identificador inventado: «No encontrado — La página solicitada no existe.». Un 403 aquí
  confirmaría que el activo existe. Se aplica en la ficha del activo, su remediación, sus
  descargas y las acciones sobre él (`webui/vistas/activos.py` líneas 533 y 561 a 565).
- **405** con el mismo `error.html`: «Método no permitido — Esta dirección solo acepta el envío
  de un formulario de la plataforma. Vuelva a la página anterior y use el botón
  correspondiente.». Antes era la página en blanco de Flask en inglés.

### Paleta de doce colores y unidad escrita

- `--cat-1` a `--cat-12` (valores en la ampliación del 8 de septiembre, corregidos arriba);
  `graficos.py` admite las doce claves. Se usan **solo** en «Versiones de sistema con más
  activos» (`activos.MAX_VERSIONES_GRAFICA = 12`, un color por barra en orden de activos); los
  repartos por familia y por entorno siguen con sus claves fijas de `cat-1` a `cat-8`
  (`FAMILIA_CLAVE`, `CLAVE_ENTORNO`). «Sin datos de sistema» va en `neutro` (gris), no consume
  color y enlaza a `/activos/?familia=desconocido`; con la base real la primera versión le
  daba un color de la paleta porque la sincronización guarda ese literal con familia
  «desconocido» (`activos._sistema_desconocido`).
- **Nota de soporte con mes y año** (`activos._nota_soporte`): «sin soporte desde abril de
  2025», «fin de soporte en abril de 2027», «soporte hasta junio de 2027», «sin dato de
  soporte». Es la única forma de leer el soporte, porque el color de la barra ya identifica la
  versión y no el estado; con la fecha completa la nota se comía el ancho de la barra (4,6 px
  la menor, medido el 2026-09-08).
- **Unidad escrita en leyendas, totales y notas**: `graficos._con_unidad` acepta una cadena o
  una pareja (singular, plural) y escribe «1 activo» / «314 activos», «6 amenazas»; la serie
  anual de Tendencias y los meses del año llevan «amenazas» en la leyenda y en los totales,
  y las barras de tecnologías llevan la severidad en la nota. Un número sin unidad obliga a
  buscar el título del panel para saber de qué habla.

## Correcciones de la revisión visual (2026-09-09)

La revisión con capturas en tema claro y oscuro a 1.440 píxeles rechazó el trabajo del día.
Lo que sigue es lo corregido, con la medida que lo demuestra. Todas las medidas se tomaron
sobre el **HTML renderizado** con Chrome sin interfaz (ventana de 1.440 × 1.200 píxeles,
perfil de administración) y contra una **copia** de la base real, nunca sobre la base de
producción.

### 1. La severidad baja: se cuenta, se explica y se puede filtrar

Remediación es la **cola de trabajo** y cuenta todas las severidades; Amenazas, el Panel, la
página de Activos y el informe mensual dejan fuera la severidad baja por regla interna
(ajuste `ignore_low_severity`). Esa diferencia dejaba dos cifras de lo mismo en la página de
Activos: «746 con vulnerabilidades confirmadas» arriba y «748 activos con pendientes» más
abajo.

Medido sobre la base real el 2026-09-09: 62.985 filas de remediación pendientes y 42.830
vulnerabilidades (pares activo y CVE); sin la severidad baja, 59.404 y 41.594; de severidad
baja, 3.581 filas, 1.236 vulnerabilidades y 8 CVE distintos. La diferencia entre 748 y 746
son exactamente dos activos: **1** cuyas únicas pendientes son de severidad baja
(`SRV-EJEMPLO-223`) y **1** con 797 pendientes cuyas filas de aplicabilidad ya no
existen y que por eso Amenazas no cuenta (`srv-ejemplo-224`); ninguna remediación se cierra
por una evaluación incompleta.

Decisiones tomadas, y lo que **no** se hizo: la severidad baja **no** se saca de la cola,
porque es una decisión del usuario que todavía no está tomada. Lo que se añade es:

- Un **filtro de severidad visible** en Remediación (`remediacion.SEVERIDADES_FILTRO`), con
  «Todas, incluida la baja (la cola completa)» como valor de omisión, «Todas menos la baja
  (como en Amenazas y en el informe)» y las cuatro severidades por separado. Recorta la
  lista y su recuento, igual que el texto buscado; las tarjetas siguen dando la situación
  global, que es su función. El CSV conserva el filtro.
- Un panel nuevo, **«Qué cuenta cada cifra de esta página»** (`#unidades-remediacion`), con
  una fila por magnitud: actualizaciones, vulnerabilidades, filas de remediación, CVE
  distintos, la parte de severidad baja de todo lo anterior, los activos con pendientes y
  las filas de activos retirados. Cada fila dice qué cuenta y dónde se ve.
- La página de Activos explica la diferencia **con su descomposición calculada** (no escrita
  a mano) en la nota del panel «Remediación», y la tarjeta «Con vulnerabilidades
  confirmadas» avisa de que no cuenta la severidad baja.

### 2. Una unidad por cifra, escrita

- «Por proceso de negocio» cuenta **filas de remediación**, no vulnerabilidades: subtítulo y
  cabeceras pasan a «Remediaciones pendientes / expuestas / corregidas», con la unidad
  repetida en el título emergente.
- El encabezado de la vista «Por vulnerabilidad» pasa a «Filas de trazabilidad, una por
  activo, amenaza y paquete», que es lo que cuentan sus 62.985.
- «1.674 vulnerabilidades distintas» pasa a «1.674 **CVE distintos**».
- La columna «Vulnerabilidades» pasa a «**Vulnerabilidades que resuelve**» con la unidad en
  pantalla («29 vulnerabilidades») y una sublínea **siempre presente** («29 filas de
  remediación en 1 paquete»), no solo en las filas fusionadas.
- La barra de progreso del avance por tipo de máquina comparaba filas corregidas con
  vulnerabilidades pendientes: ahora las dos partes son filas de remediación, la misma
  unidad que el porcentaje que tiene al lado.

### 3. La gráfica semanal

- Excluye las remediaciones de **activos retirados** (`estado='activo_ausente'`): sumaba
  66.326 detecciones cuando la página decía 62.985, porque contaba las 3.341 filas de
  activos que ya no figuran en OCS Inventory. Después: **62.985**, exactamente la cifra de
  la tarjeta.
- La leyenda escribe la unidad («Remediaciones detectadas», «Remediaciones corregidas») y
  una serie cuyo total es **cero se pinta en neutro**, no en su color: la leyenda decía
  «Corregidas 0» con el cuadrado verde.
- Las **semanas sin datos** se dicen debajo de la gráfica con su fecha completa («la del 10
  de agosto de 2026 …»), porque una semana sin barra y una semana con cero se ven igual.
- El eje pasa de «10 ago» a dos líneas, «10 de agosto» y «2026» (`_etiqueta_semana`, con
  `larga=True` para el texto corrido).

### 4. Tablas que cabían mal a 1.440 píxeles

Causa raíz: `estilo.css` aplicaba a **todos** los `th`, incluidos los `th scope="row"` del
cuerpo, mayúsculas, once píxeles, una sola línea, fondo alternativo y `position: sticky`.
Reglas nuevas al final de la hoja: `tbody th` sin mayúsculas, con varias líneas, fondo
transparente y `position: static`; `.tabla-compacta thead th` y `.tabla-activos thead th`
admiten dos líneas; y anchos mínimos ajustados (`.minw-100` a `.minw-240`).

| Elemento | Antes | Después |
| --- | --- | --- |
| Envoltorio de la tabla de Remediación | 1.143 px | 1.143 px |
| Tabla de Remediación (perfil con acciones) | 1.319,3 px (se cortaba «Ya se actualizó…») | **1.143 px** |
| Tabla «Avance por tipo de máquina» | 1.340,3 px (la barra de progreso salía del panel) | **1.143 px** |
| Celda de cabecera de fila «Equipos de cómputo…» | 308,8 px en una línea | 150 px en varias |
| Cabecera «Último inventario» | 114 px para 131 px de texto | 114 px, dos líneas, sin recorte |
| Cabecera «Vulnerabilidades» | 103 px para 132 px de texto | **137,2 px**, sin recorte |
| Celda de vulnerabilidades de la lista de activos | 103 px para 144 px («KEV 7» se leía «KE») | 125,7 px, la insignia en su línea |

Reparto de la tabla de activos: `col-tipo` 9 % → 8 %, `col-vulns` 9 % → 12 %,
`col-hallazgos` 12 % → 10 %; los nueve porcentajes siguen sumando 100.

### 5. El nombre de la fila fusionada dice la versión

`remediacion.nombre_actualizacion` elegía la variante del núcleo solo cuando todas eran
prefijo de la más larga. En producción `linux-image-6.12.90+deb13.1-amd64` convive con
`linux-image-amd64` y «6.12.90+deb13.1-amd64» no empieza por «amd64», así que **121 de las
124** fusiones del núcleo se llamaban «Núcleo Linux» a secas (65 servidores con el mismo
nombre de fila). Ahora la variante se elige por este orden: la más específica que contenga
un número de versión (`\d+\.\d+`, para que «amd64» no cuente como versión); si ninguna la
lleva, la más larga cuando todas son prefijo de ella; y si tampoco, la versión que OCS
Inventory ve instalada, con `variante_origen` para que la plantilla explique de dónde sale.

Medido sobre la copia de la base real: antes **3 con versión y 121 sin versión** de 124;
después **124 con versión** (111 por el nombre de un paquete y 13 por la versión
instalada), 0 sin versión. Ejemplo: `linux-image-6.1.0-37-amd64` + `linux-image-amd64` pasa
de «Núcleo Linux» a «Núcleo Linux 6.1.0-37-amd64».

### 6. Objetivos táctiles, foco y desplegables

`CLAUDE.md` y `.claude/skills/reglas-proyecto/SKILL.md` exigen 44 píxeles y **prevalecen**
sobre los 24 píxeles que recomienda la habilidad `ui-ux-pro-max` para la web (WCAG 2.2
2.5.8). Medido antes: `summary` 26,6 px, `.btn.pequeno` 30 px, `.btn` 34 px y los botones de
icono 30 × 30 px. Después: 44 px en todos (`summary` centrado con relleno vertical para no
perder el triángulo del desplegable, que es su única señal de que se puede abrir), botones
de icono de 44 × 44 px y los chips de vistas rápidas de la lista de activos también a 44 px.
`summary` entra además en el selector de foco visible y se pinta con el color de acento y
subrayado al enfocarlo o al pasar por encima.

### 7. Un solo texto por cosa

- El desplegable de paquetes dice lo mismo, palabra por palabra, en las tres plantillas que
  lo pintan: «N paquetes del mismo origen: una sola orden los actualiza».
- La tarjeta «Corregidas en N días» dice en las dos páginas «filas de remediación vistas
  corregidas por OCS Inventory».
- El plan de remediación llamaba «grupos de remediación» a lo que el resto de la plataforma
  llama **actualizaciones**: ahora «Actualizaciones por aplicar», con el singular cuando es
  una, «Activo por corregir» en singular, y una nota que dice de dónde sale la cifra (la
  última evaluación de aplicabilidad) y por qué puede no coincidir con «Actualizaciones
  pendientes» de la ficha, que cuenta la cola de remediación. Las siglas de los avisos se
  explican con `<abbr>`: DSA, USN y DLA.

### 8. Idioma y numeración

- «equipo» a secas por una máquina desaparece de las siete plantillas revisadas; se admite
  solo «equipo de cómputo» y «equipos de cómputo». Lo fija
  `tests/test_revision_visual_20260909.py`.
- «nº» y «Nº» pasan a «Remediación número 43127», que significa algo para alguien nuevo.
- Las cinco fechas ISO de los títulos emergentes de la lista de activos («2025-10-14») pasan
  por el filtro `fecha_es`. La prueba exige que toda fecha interpolada en un `title` lleve
  `fecha_es` o `hace`.
- **Recorrido guiado de la ficha del activo**: `app.js` ordena los pasos por el número de
  `data-tour`, y los pasos de remediación estaban numerados 11 y 12 apareciendo antes que el
  7 y el 9, así que el recorrido saltaba hacia atrás. Renumerado al orden visual: 1 título,
  2 indicadores, 3 consulta de un CVE, 4 datos del activo, 5 veredictos, 6 actualizaciones
  de Windows, 7 amenazas evaluadas, 8 actualizaciones pendientes, 9 detalle por
  vulnerabilidad, 10 SBOM, 11 OpenSCAP, 12 software. En la lista de activos, el panel de
  remediación pasa de 9 a 8 y los dos siguientes a 9 y 10. Los únicos huecos posibles son
  los de los paneles que un activo o un perfil no tiene (el de Windows en una máquina que no
  lo es); la prueba exige que los pasos que se pintan vayan siempre en orden creciente.

### 9. Tarjetas y color

- Las cinco tarjetas de una fila comparten altura, así que una con once líneas y tres con
  dos estiraba la fila. Medido: la fila de indicadores de Remediación pasa de 402,1 px (con
  la explicación dentro de una tarjeta) a **160,9 px**, con notas de una a tres líneas; la de
  la lista de activos, a 179,5 px. El detalle largo vive en el panel «Qué cuenta cada cifra»
  y en la nota del panel, que van a todo el ancho.
- Criterio de color de las tarjetas, uniforme en las dos páginas: **rojo** lo que exige
  acción hoy (actualizaciones pendientes, activos con vulnerabilidad confirmada), **ámbar**
  lo que pide atención (vulnerabilidades pendientes, activos con pendientes, fuera de
  soporte, sin reportar), **verde** lo correcto (corregidas en el periodo) y **gris** lo que
  no tiene dato o es solo informativo (días de media, tecnologías).
- `--medio` del tema claro pasa de `#d97706` a `#a54e08`: la diferencia con `--alto`
  (`#ea580c`) era de 1,12:1 y «Altas» y «Medias» se leían como una sola barra. Después,
  1,60:1 entre ambos, 5,69:1 sobre el panel, 5,07:1 sobre el fondo de página y 5,48:1 sobre
  el fondo de su insignia. Además, los tramos contiguos de `.progreso` se separan con
  1,5 píxeles del color del panel.

## Ampliación 2026-09-10 · medida de lectura común (`--medida-texto`)

Petición literal del usuario: «Ajusta bien las intros de cada apartado, que se ajuste
porque veo que después de cada título de cada sección está solo a la parte izquierda y la
idea es que se ajusten a la vista y espacio… sube el límite a algo razonable para este
ancho (del orden de 110 a 120 caracteres) o reparte en columnas».

**Lo que había** (medido con el navegador a 1.440 px de ventana, panel de 1.145 px):

| Texto | Antes | Caracteres por línea |
|---|---:|---:|
| `.titulo-pagina p` (introducción de la página) | 566 px (`max-width: 78ch`) | 78 |
| `.panel-cabecera .sub` (subtítulo de panel) | 1.111 px, sin límite | **166** |
| `.ayuda` (texto de ayuda de un campo o panel) | 1.077 px, sin límite | **166** |

Es decir, dos problemas opuestos a la vez: la introducción dejaba una franja muerta de
579 px a su derecha y los subtítulos y ayudas se iban a 166 caracteres por línea, más del
doble de lo legible.

**Lo que hay desde hoy.** Un solo token en `:root`:

```css
--medida-texto: 110ch;   /* ≈ 798 px con la tipografía de 13 px */
```

lo usan `.titulo-pagina p`, `.panel-cabecera .sub` y `.campo .ayuda, .ayuda`. Son 110
caracteres: el extremo bajo del rango que pidió el usuario, que es lo más cerca que se
puede quedar de la regla «Line Length» de la habilidad `ui-ux-pro-max` (65-75 caracteres
recomendados, «nada de texto a todo el ancho en pantallas grandes»). Se escribe tal cual,
**sin** envolverlo en `min(100%, …)`: el porcentaje deja de contar cuando el navegador
calcula el ancho natural de un elemento flexible y el bloque del título pedía entonces el
párrafo entero en una línea, empujando los botones de cabecera a la línea de abajo. Un
límite en `ch` no desborda: un bloque nunca pasa del ancho de su contenedor.

Además, el bloque de título crece con el espacio que le deja la fila de acciones:

```css
@media (min-width: 481px) {
  .titulo-pagina > div:first-child { flex: 1 1 320px; min-width: 0; }
}
```

La base son 320 px y no `auto` para que la fila de acciones (Tendencias, Activos,
Software, Inventario tecnológico y Fuentes tienen varios botones) siga en la misma línea
que el título. Y solo por encima de 480 px: por debajo, `.titulo-pagina` pasa a
`flex-direction: column` y una base en píxeles se convertiría en **alto mínimo** (se vio
en la pantalla de 390 px como un hueco vacío de 420 px bajo el título).

**Comprobado en las dieciocho pantallas de la consola** con el navegador sin cabeza
(`data/revision/medir_anchos_plataforma.py`, contra la copia de la base real), a 1.440,
1.280 y 390 px:

| Medida | Antes | Después |
|---|---|---|
| Introducción de la página a 1.440 px | 566 px / 78 caracteres en todas | 603-798 px / 83-110 caracteres según los botones de la cabecera |
| Línea más larga de la pantalla | 166 caracteres en 15 de 18 pantallas | 110 caracteres como máximo |
| Fila de acciones en la misma línea que el título | sí | sí (las dieciocho) |
| Desbordamiento horizontal a 1.440 y 1.280 px | ninguno | ninguno |

A 390 px nada cambia (el ancho disponible manda y la introducción sigue ocupando los
366 px del panel). Las dos pantallas que ya desbordaban a 390 px (`/usuarios/` y
`/alertas-proceso/`, por el ancho mínimo de sus tablas) desbordan igual que antes: no es
efecto de este cambio y queda pendiente.

La prueba `tests/test_informes_vista_previa_pegada.py::TestMedidaDeLectura` fija el token
(entre 100 y 120 caracteres), que los tres selectores lo usan, que `max-width: 78ch` ya no
existe en la hoja y que la base en píxeles del bloque de título vive dentro del `@media
(min-width: 481px)`.

## Revisión de claridad (2026-09-15)

Revisión de las páginas de operación (Panel, Amenazas, ficha de amenaza, Tendencias,
Inventario tecnológico, ficha de tecnología y Software) leídas como las lee alguien que
entra por primera vez. El criterio, por encima de cualquier otro: **dos cifras de la
misma magnitud que se leen en la misma pantalla —o en dos pantallas seguidas— tienen que
coincidir**, y lo que no se puede hacer coincidir tiene que estar explicado con su cifra.
Todas las medidas de esta sección se tomaron sobre una **copia** de la base de producción
(API `backup` de sqlite3, borrada al terminar) con el navegador sin cabeza y con el
cliente de pruebas de Flask.

### Las cifras que se contradecían

| Qué decía la pantalla | Antes | Después |
|---|---|---|
| `/amenazas/`: cabecera «amenazas coinciden con el filtro» frente a la tarjeta «Amenazas registradas» | 7.514 y 7.293 | 7.293 y 7.293 |
| `/amenazas/`: insignias «Baja» en la última página | 221 amenazas de severidad baja | ninguna (365 páginas en lugar de 376) |
| Panel: total del mes en la tarjeta frente a la barra «Procedencia de la severidad» | 1.532 y 1.622 | 1.532 y 1.532 |
| Panel: «% del mes con CVSS oficial» en el flujo frente a la barra de procedencia | 80 % y 77 % | 80 % y 80 % (1.228 de 1.532) |
| `/tecnologias/6`: barra de septiembre frente a la fila de la tabla | 726 y 734 | 726 y 726 |
| Amenazas y Panel («vulnerabilidades confirmadas») frente a Remediación («pendientes») | 32.701 y 32.823, sin explicación | 32.701 + 122 = 32.823, con la frase que lo explica en las dos pantallas |

La causa de cada una:

1. **Severidad baja en la lista de amenazas.** `webui/vistas/amenazas.py::_filtros()` solo
   aplicaba severidades cuando la persona elegía alguna, y `queries.buscar` sin
   `severidades` no filtraba nada. Ahora `_filtros()` devuelve `excluir_bajas` leído del
   ajuste `ignore_low_severity` y `queries.buscar` lo aplica con la MISMA condición que el
   resto de la plataforma (`t.severity IS NULL OR t.severity <> 'Low'`: una severidad
   desconocida no es una baja y sigue contando). La exportación CSV usa los mismos filtros,
   así que tampoco la lleva.
2. **Dos totales del mismo mes en el Panel.** `panel._procedencia_severidad()` agrupaba por
   `severity_source` sin excluir la baja mientras la tarjeta usaba
   `queries.estadisticas_mes(excluir_bajas=True)`. Con el mismo filtro en las dos, el
   denominador del porcentaje de CVSS oficial es también único.
3. **La tabla de la ficha de tecnología.** `tecnologias._evolucion_tecnologia()` contaba
   todas las severidades y la gráfica solo pintaba tres; además la tabla tenía una columna
   «Bajas», la única de toda la plataforma que nombraba esa severidad. La consulta acepta
   ahora `excluir_bajas` (activo por omisión), la columna desaparece y se añade un segmento
   «Sin severidad conocida» cuando de verdad existe, para que el alto de cada barra sea
   exactamente el «Total» de su fila.
4. **Confirmadas frente a pendientes.** No era un error de conteo: son dos conjuntos
   distintos y uno contiene al otro. Medido sobre la copia, las 122 de diferencia son
   remediaciones abiertas cuya fila de `aplicabilidad` desapareció mientras el paquete sigue
   instalado con la misma versión; `remediacion.sincronizar` (paso 4) las deja abiertas a
   propósito, porque cerrarlas sería afirmar una corrección que nadie ha comprobado. La
   función nueva `queries.vulnerabilidades_pendientes_sin_confirmar()` cuenta exactamente
   esa diferencia con los mismos criterios de las dos cifras que concilia (160 ms sobre la
   base real), y el Panel y la página de Amenazas lo escriben: «32.701 + 122 = 32.823».

### Rótulos, unidades y concordancia

* `/tecnologias/<id>`: «Versión afectada 0» y «Versión no afectada 0» contaban **amenazas**,
  no versiones. Pasan a «Amenazas que afectan a la versión instalada» y «Amenazas
  descartadas por la versión instalada», concordadas en singular.
* Panel, columna «Confirmadas»: «—» en seis de ocho filas se leía como cero y no lo era.
  Ahora se distingue **0** (se comprobó y no hay ninguna) de **«sin dato»** (no se ha podido
  comprobar: el aviso no precisa versiones o falta la versión instalada), con su explicación
  al pie y en el glosario.
* Concordancia de las cifras: «12 versiónes distintas» → «12 versiones distintas»;
  «1 críticas» → «1 crítica»; plurales de reglas, categorías, tecnologías y activos.
* Fechas: el Panel ya no escribe ninguna fecha en formato numérico («previsto el
  30/09/2026» → «previsto el 30 de septiembre de 2026»; la cifra grande del paso «Informe
  mensual» es «31 de agosto» y el año va en la nota).

### Jerga fuera de la pantalla

«Traductor · Ollama · llama3.1:8b» pasa a «Traducción de las descripciones ·
funcionando / no disponible», con la consecuencia escrita («los avisos nuevos se guardarán
solo en inglés»); el nombre del motor y del modelo siguen en Ajustes, que es de
administración. «Disponible también en /salud.json para Zabbix» pasa a «Estas mismas
cifras se publican en formato JSON para que el sistema de vigilancia de la organización
las recoja automáticamente». En la ficha de amenaza, «Identificador 0a95fcf17…» pasa a
«Huella interna de la plataforma · solo para soporte técnico: no es un identificador
público». En el inventario se explican «slug» (identificador interno) y «CPE»
(identificador estándar del producto, con `<abbr>`).

### Traducción automática poco fiable

Las descripciones traídas de las fuentes se traducen con el motor local, que vierte
literalmente términos que deben quedarse en inglés: «fijar el uso después de la compra»
(use-after-free), «codificado duro» (hardcoded), «lo decree por 1» (decrement it by 1).
La corrección de raíz es que el traductor no los traduzca
(`threatintel/translate.py::TERMINOS_PROTEGIDOS`), y está propuesta en el informe del
2026-09-15 para que la aplique el coordinador. Mientras tanto, la ficha **detecta** esas
vueltas mal dadas (`webui/vistas/amenazas.py::TERMINOS_SIN_TRADUCIR` y
`terminos_mal_traducidos()`), avisa de que la traducción no es fiable para ese texto,
**enseña el original en inglés** y deja la traducción plegada. Medido sobre la copia de
producción: 150 de 7.494 amenazas con descripción (2,0 %) llevan el aviso.

### Altura de las páginas y disciplina de los desplegables

La ficha de una amenaza medía 15.790 píxeles de alto. Los dos bloques más largos —«Activos
afectados» (117.000 de sus 176.000 caracteres de HTML) y «Qué hay que hacer en cada sistema
operativo»— pasan a `<details>` cerrados, HTML puro, sin una línea de JavaScript: la
cabecera, el resumen de la evaluación, el aviso de riesgo aceptado y el botón «Plan de
remediación» siguen visibles. Lo mismo con el bloque «Si es un falso positivo» del
formulario de estado, que estaba siempre desplegado aunque el estado fuera «Nueva», y con
la orden de comprobación (`dpkg --compare-versions …`), que no es «qué hacer con el
paquete» sino «cómo verificarlo» y vive en su propio desplegable.

Las tarjetas de cifras dejan de llevar párrafos de siete a nueve líneas: cifra, nombre y
**una** línea, y el detalle completo en un desplegable «Qué cuenta exactamente cada cifra»,
como ya hacía Remediación.

Medido con el navegador sin cabeza a 1.440 px, contra la copia de la base real:

| Pantalla o bloque | Antes | Después |
|---|---|---|
| Ficha de una amenaza (documento completo) | 15.790 px | 4.398 px |
| Ficha: bloque «Activos afectados» | 11.125 px | 559 px |
| Ficha: bloque «Qué hay que hacer en cada sistema operativo» | 1.395 px | 192 px |
| `/amenazas/`: rejilla de las cuatro tarjetas | 265 px | 133 px |
| `/amenazas/`: bloque «Cuántas amenazas hay» completo | 1.367 px | 1.291 px |
| Panel: bloque «Estado de los activos» | 535 px | 364 px |
| Panel (documento completo) | 4.697 px | 4.948 px |
| `/amenazas/` (documento completo) | 5.287 px | 5.481 px |
| `/tecnologias/6` (documento completo) | 4.933 px | 5.293 px |

Tres documentos crecen a propósito y se dice por qué: el Panel gana la nota que explica
que el reparto por tecnología no suma el total del mes y la frase que concilia con
Remediación; `/amenazas/` gana esa misma frase y una lista cuyas veinte filas ya no son
las mismas (al salir las bajas entran amenazas con más tecnologías, que ocupan más alto);
y la ficha de tecnología gana el aviso de versiones que no encajan con el patrón y una
gráfica más alta para que quepan las diez etiquetas del eje. Lo que la revisión señaló
—los bloques y las tarjetas— baja en todos los casos.

### Etiquetas del eje: todas o ninguna

`webui/graficos.py::barras_apiladas` acepta `etiquetas_todas=True`: si las etiquetas no
caben rectas, en lugar de saltarse las que no quepan se escriben **todas** en una línea y
giradas 45 grados, y los márgenes inferior e izquierdo crecen lo necesario. El giro va en
el atributo `transform` del SVG, que no es CSS y la política de seguridad de contenido no
lo toca. La ficha de tecnología pintaba diez barras y seis meses; ahora pinta los diez, y
con la preposición: «marzo de 2026», como el resto de la plataforma.

### Comparaciones honestas y avisos con sujeto

* La flecha de tendencia del Panel compara **dos ventanas de 30 días** y ahora lo escribe
  con las dos cifras al lado del porcentaje («2.501 en los últimos 30 días frente a 736 en
  los 30 anteriores»), porque «↑ 240 %» al lado de «1.532 amenazas del periodo» se leía
  como si comparase esa cifra, que es el acumulado de medio mes. La tarjeta del periodo
  dice además cuántos días lleva el mes y que el gráfico pequeño es de meses naturales con
  el último a medias: esa es la razón de que la línea pueda bajar mientras la flecha sube.
  La flecha tampoco cuenta ya la severidad baja.
* El aviso de estado del Panel dejaba de repetir el motivo de la credencial de correo, que
  ya tiene su propio aviso debajo (`panel.motivos_sin_repetir()`), y ese aviso dice ahora
  **qué** caduca y **qué pasa** si no se renueva.

### Versiones del inventario que no encajan con el patrón

La ficha de una tecnología presentaba como buena la versión declarada («Microsoft Windows
6.0.25.33020», «PHP 1.0»), que es la **más antigua** de las instaladas y la que se compara
con los avisos. Ahora la cabecera lo dice con esas palabras y con el número de versiones
distintas, y `tecnologias.marcar_versiones_atipicas()` marca en ámbar, con su motivo, las
versiones cuya **serie mayor** (el primer número) reúne menos de la décima parte de los
activos cuando otra serie reúne al menos la mitad; si conviven tres series o más, el pie
avisa de que el mapa de nombres puede estar clasificando ahí programas que no lo son. La
regla es estadística y comprobable a propósito: no hay catálogo de versiones por producto
y no se inventa uno, así que el texto pide **comprobar**, no afirma. Medido sobre el
inventario real: 121 de las 166 tecnologías con activos tienen una sola serie y 21 tienen
dos; las 24 restantes son las que llevan el aviso, entre ellas Microsoft Windows (series
6, 8, 10, 48 y 64) y PHP (1, 2 y 3).

### Una sola lista de categorías

El formulario «Nueva tecnología» ofrecía diez categorías fijas con guion bajo
(`sistema_operativo`) y la tabla «Cobertura de versiones por categoría» enseñaba otras
diez, las reales, con guion (`sistema-operativo`): elegir una del formulario creaba una
categoría que nadie más usaba. `tecnologias.categorias_del_inventario()` devuelve LA lista,
la del inventario (21 categorías en producción), ordenada por su nombre visible; la
constante `CATEGORIAS` queda solo como respaldo para una base recién creada.

### Recorrido guiado por perfil

La invitación al recorrido promete «las N secciones del menú» con N contado sobre los
enlaces realmente pintados (`aside nav a[href]` en `webui/static/app.js`). Medido con el
cliente de pruebas: administración ve **17**, y los perfiles de consulta (solo lectura,
Redes y Mantenimiento) ven **9**. La prueba
`tests/test_claridad_operacion.py::TestRecorridoPorPerfil` fija esos números y comprueba
que todos los enlaces del menú responden 200 para el perfil que los ve.

### Pruebas

`tests/test_claridad_operacion.py` (60 pruebas) fija cada punto anterior y, en particular,
**un par de números por cada discrepancia**: cabecera y tarjeta de `/amenazas/`, barra de
procedencia y tarjeta del Panel, porcentaje de CVSS oficial en los dos sitios, barra y fila
de la ficha de tecnología, y confirmadas más huérfanas igual a pendientes (con la
comprobación de conjuntos en las dos direcciones).

## Auditoría de tableros (2026-09-15) · Panel, Inventario, Fuentes y Excepciones

Una auditoría de todos los tableros encontró trece cifras que se contradecían entre sí,
casi siempre **en la misma pantalla**. Esta sección documenta las de Panel, inventario
tecnológico (`/tecnologias/` y la ficha), Fuentes, Excepciones y Software; las de
Amenazas, Tendencias, Activos, Remediación y Parches van en la sección del mismo día del
otro frente de trabajo. Cada punto lleva la cifra **antes** y **después**, medida sobre
una copia de producción hecha con la API `backup` de sqlite3 y borrada al terminar.

### 1. El paso «Correlación» hablaba de la corrida que no recolecta

El cron lanza **dos** corridas de tipo `daily` cada día: la recolección de las 12:30, que
consulta las fuentes y escribe `threats_new`, y el envío de la alerta de las 13:00, que no
consulta ninguna fuente y escribe `threats_alerted`. El flujo tomaba la última fila de
`executions` y por eso decía «**0** amenazas nuevas en la última recolección» el mismo día
en que la tabla «Últimas ejecuciones» de la misma página decía **261**.
`panel._ultima_recoleccion()` devuelve ahora la última corrida con `sources_ok > 0` para el
paso «Correlación»; el paso «Alerta» sigue mirando la más reciente. Medido: **0 → 261**.

### 2. La ficha de una tecnología confundía instalaciones con activos

La cabecera decía «en **56** activos» y la tarjeta de al lado «**50** activos». No eran
activos: 56 son pares (activo, versión), porque un equipo con dos versiones instaladas
cuenta en las dos filas. Además, **29 instalaciones sin versión declarada** desaparecían de
la tabla sin que nada las mencionara, y los porcentajes de la columna «Reparto» usaban 50
como denominador, de modo que sumaban más del cien por cien.

* la columna se llama **«Instalaciones (activo y versión)»**;
* el pie escribe «**56 instalaciones (activo y versión) en 50 activos; 29 más sin versión
  declarada**, que no se pueden comparar con ningún aviso» y, cuando la tabla no muestra
  todas las versiones, cuántas de cuántas muestra;
* los porcentajes se calculan sobre **56**;
* la cabecera dice «**en 50 activos, con 12 versiones distintas**».

Las cuatro cifras salen de `ocs.resumen_instalaciones()`, una sola consulta sobre
`activo_software`. Medido en Microsoft Windows: 85 instalaciones, 50 activos, 56 con
versión, 29 sin versión, 12 versiones distintas.

### 3. La misma ficha daba 2.159 y 2.142 amenazas

La serie mensual excluía la severidad que no se reporta y las tarjetas, la dona de
veredictos y la tabla de amenazas asociadas no. Ahora **toda** la ficha usa el mismo
filtro. Medido en Microsoft Windows: tarjetas y dona **2.159 → 2.142**, que es lo que ya
apilaba la gráfica.

### 4. El pie de `/tecnologias/` sumaba lo que no se puede sumar

«Sistemas **22.236**» en un parque de **730** máquinas: sumaba `systems_count` de cada
tecnología, contando el mismo activo una vez por cada tecnología instalada, y ni siquiera
sumaba la columna que se ve (al filtrar «windows», la columna sumaba 100 y el pie decía
50). «Amenazas **8.363**» superaba el catálogo entero (7.284) porque una amenaza que
menciona cuatro tecnologías se contaba cuatro veces.

El pie enseña ahora dos **recuentos distintos**, con enlace y con su explicación debajo:
los **activos del parque** que tienen instalada alguna de las tecnologías del filtro
(`tecnologias._activos_con_estas_tecnologias()`) y las **amenazas distintas** que las
mencionan (`tecnologias._amenazas_distintas()`), con la suma de la columna escrita al lado
para que se entienda la diferencia. Medido sin filtro: **22.236 → 688 activos** (de 730
presentes) y **8.363 → 5.820 amenazas distintas** (la suma de la columna, 8.071, repite).
Con el filtro «windows»: **50 activos** y **2.157 amenazas distintas** de 2.190 sumadas.

### 5. La columna «Amenazas» del inventario contaba lo que la gráfica no

Windows salía con 2.159 en la tabla y 2.142 en la gráfica de la misma página. El filtro
está ahora en las subconsultas de la lista, en el agregado del pie y en
`tecnologias._top_tecnologias()`. Medido: columna de Microsoft Windows **2.159 → 2.142**;
suma de la columna **8.363 → 8.071**.

### 6. La única fila de la plataforma que nombraba la severidad que no se reporta

`queries.cve_recurrentes()` (tabla «CVE presentes en varios periodos» de Tendencias)
escribía «Baja» en la columna de severidad. Tiene ahora un parámetro `excluir_bajas` con
valor por omisión **`True`** —al revés que el resto de funciones del módulo, a propósito:
quien la llama no tiene que acordarse— que deja fuera esa severidad y las amenazas ya
cerradas por el equipo. Medido: **185 → 179 CVE recurrentes** (6 fuera, uno de ellos entre
los 20 que se enseñan).

### 7. El selector de Excepciones ofrecía cifras infladas

`excepciones._activos_del_selector()` contaba CVE sin filtrar la severidad que no se
reporta, las amenazas descartadas o mitigadas ni el riesgo ya aceptado, así que **348 de
los 652 activos** enseñaban un número distinto del de su propia ficha (el primero de la
lista, 30 aquí y 27 allí) justo en el formulario donde se justifica una aceptación de
riesgo. Con los mismos filtros que la ficha: **348 activos discrepantes → 0**, los 652
activos siguen ofreciéndose.

### 8. Tres leyendas que sumaban un «top N» con repetición

`webui/graficos.py::barras_horizontales` acepta `leyenda_nota`, que escribe una línea bajo
la leyenda. Se usa en el Panel («Exposición de la organización»: la leyenda decía
**Críticas 156** y la tarjeta de la misma página **118**), en `/tecnologias/`
(«Tecnologías con más amenazas»: 927/3.106/3.117 frente a las columnas de la tabla) y en
`/fuentes/` («Fuentes que más aportan», que además escribe el total sin repeticiones). El
modelo era correcto: lo que faltaba era decirlo donde se lee la cifra. Las consultas no
cambian.

### 9. El catálogo de Fuentes contaba 230 amenazas de más

El pie decía «**7.514** distintas» donde Amenazas y Tendencias decían **7.284** del mismo
histórico. El filtro está ahora en el pie, en la columna «Amenazas» de cada fuente, en el
gráfico «Fuentes que más aportan» y en la ficha de la fuente, las cuatro a la vez
(`fuentes._filtro_severidad()`). Medido: pie **7.514 → 7.284**; primera fuente del gráfico
**4.484 → 4.372**.

### 10. «100,0 % del software clasificado» con «1 sin clasificar» al lado

El Panel y `/activos/software` redondeaban a un decimal 813.506 de 813.507 y lo convertían
en un cien por cien que no era cierto, mientras `/activos/` decía **99,99 %**.
`ocs.resumen()` ya devolvía el valor honesto (`pct_mapeado_valor` y
`pct_mapeado_decimales`, de `ocs.porcentaje_honesto()`): ahora lo usan las tres pantallas y
las dos primeras dicen además cuántas instalaciones quedan fuera. Medido: **100,0 % →
99,99 % (1 instalación sin clasificar)**.

### 11. «0 de 4.515 CVE siguen sin consultar»

No eran CVE: eran **amenazas con CVE** (los CVE distintos son 4.308). El rótulo lo dice, y
el recuento aplica el criterio del resto de la plataforma (sin la severidad que no se
reporta ni las amenazas cerradas). Medido: **4.515 → 4.402**, que es exactamente el «4.402
de las 7.284 tienen identificador CVE» de la página de Amenazas.

### 12. Tres rótulos del Panel que confundían

* La leyenda de «Evolución de los últimos meses» sumaba **seis meses** sin decirlo y ponía
  «En KEV» en la misma lista que las tres severidades, como si fuera un cuarto grupo
  sumable. La línea se llama ahora «**Con explotación confirmada (ya contadas arriba)**» y
  un párrafo bajo la gráfica dice que la leyenda suma los seis meses (6.397 amenazas) y que
  esa línea no se suma.
* La tabla «Últimas ejecuciones» llamaba «Recolección diaria» a las dos corridas del día y
  la de la alerta salía con «Fuentes 0», que se lee como un fallo. Ahora se llama «**Envío
  de la alerta diaria**» (`panel._es_envio_de_alerta()`: diaria y sin ninguna fuente
  consultada, ni correcta ni fallida) y su columna «Fuentes» escribe «—» con la explicación
  al pasar el ratón.
* «1.409 excluidas por el filtro» incluía **150** excluidas por una severidad que la
  plataforma no nombra ni cuenta en ninguna otra cifra. Medido: **1.409 → 1.259**.

### 13. «Confirmadas» significaba dos cosas distintas

La columna de la tabla de tecnologías del Panel cuenta las amenazas cuya **versión de la
tecnología** resulta vulnerable, no las «amenazas confirmadas en algún activo» de Amenazas,
Activos y Remediación, que se comprueban máquina por máquina contra el paquete instalado.
La columna se llama ahora «**Confirmadas por versión de la tecnología**» y el pie explica
la diferencia con enlace a la otra cifra.

### Coste medido (sobre la copia de producción del 2026-09-15)

| Página | Antes | Después |
| --- | --- | --- |
| Panel | 1.700 ms | 1.750 ms |
| `/tecnologias/` | 88 ms | 135 ms |
| Ficha de Microsoft Windows | 27 ms | 31 ms |
| Ficha de «Componentes, controladores y actualizaciones de Windows» | 19 ms | 576 ms |
| `/fuentes/` | 28 ms | 58 ms |
| `/excepciones/` | 94 ms | 130 ms |

La única página que se degrada de verdad es la ficha de la tecnología «cajón de sastre»,
que reúne **699.000 instalaciones y 10.903 versiones distintas**: contarlas cuesta medio
segundo porque no hay índice que cubra `(technology_id, activo_id, version)`. Un índice de
cobertura lo deja en 404 ms y persistir las cuatro cifras en `technologies` durante la
sincronización lo dejaría en cero; las dos cosas tocan el esquema y quedan para el
coordinador.

### Pruebas

`tests/test_cifras_tableros_20260915.py` (44 pruebas) fija **un par de cifras por cada
discrepancia**, con un parque sembrado que descuadra a propósito: dos corridas diarias
(recolección y alerta), amenazas de las cuatro severidades en dos meses, un CVE recurrente
de severidad alta y otros dos que no se pueden enseñar, una tecnología con dos versiones
instaladas —un activo tiene las dos— y una instalación sin versión declarada, y
vulnerabilidades confirmadas de una amenaza descartada y de otra que no se reporta. Cubre
además los casos límite: base vacía, tecnología sin software y dos peticiones seguidas de
la misma página con el mismo resultado.

## Auditoría de tableros (2026-09-15) · Amenazas, Tendencias, Activos, Correcciones pendientes, Alertas por proceso y Remediación

Segundo frente de la misma auditoría (el primero, arriba, cubre Panel, Inventario, Fuentes
y Excepciones). Casi todo eran **rótulos que no decían lo que la cifra contaba**; dos eran
incoherencias de verdad. Todo se midió sobre una copia de producción hecha con la API
`backup` de sqlite3 y borrada al terminar.

### 1. La leyenda de «Tecnologías más afectadas» contradecía a la tarjeta de su página

En Tendencias, la leyenda decía **Críticas 168, Altas 938 y Medias 699** y la tarjeta
«Amenazas del periodo» de la misma pantalla decía **118, 834 y 571**. El modelo es
correcto: la leyenda suma las **veinte barras dibujadas** y las suma **con repetición**,
porque una amenaza que menciona dos tecnologías afecta a las dos. La consulta no se ha
tocado: se escribe la advertencia donde se lee, con el argumento `leyenda_nota` de
`graficos.barras_horizontales`, y debajo de la gráfica va la misma explicación completa que
el Panel ya tenía (no todas las tecnologías, repetición, y amenazas sin ninguna tecnología
del inventario que no están en ninguna barra).

### 2. «Confirmadas» en la tabla de tecnologías de Tendencias

Significa «amenazas cuya **versión de la tecnología** resulta vulnerable» y chocaba con
«Amenazas confirmadas en algún activo»: Microsoft Windows salía con **0** en esa columna y
con **1.545** amenazas confirmadas en activos. La columna se llama ahora «**Confirmadas por
versión de la tecnología**» y el pie explica la diferencia con enlace a la página de
Amenazas, que es donde vive la otra cifra. (Es el mismo cambio que el frente del Panel hizo
en su tabla; aquí se aplica a Tendencias.)

### 3. «Apariciones» en la tabla de CVE recurrentes

No son activos ni periodos: son las **veces que los avisos recolectados citaron el
identificador**, y hasta hoy solo lo decía el título emergente. La columna se llama
«**Veces citado en avisos**» en las dos páginas que la enseñan (Amenazas y Tendencias).

### 4. «176 con explotación activa (KEV)» en `/activos/`

La cifra no llevaba unidad y se leía como vulnerabilidades, que en el resto de la
plataforma son **343**. Son **activos**: un activo con veinte vulnerabilidades KEV cuenta
una vez. La nota dice ahora «**176 de ellos** con explotación activa (KEV)», atada a los
652 activos de su propia tarjeta.

### 5. La nota de «Activos con pendientes» era falsa

Decía «con alguna remediación abierta, **de cualquier severidad**», y `remediacion.resumen`
deja fuera la severidad baja (desde el 2026-09-10) y las remediaciones cubiertas por una
excepción vigente. La nota dice ahora «de severidad crítica, alta o media; el riesgo
aceptado con excepción vigente no cuenta», que es el mismo criterio de la tarjeta «Con
vulnerabilidades confirmadas» de arriba.

### 6. «Sin datos de sistema» dentro de un top de versiones

En la gráfica «Versiones de sistema con más activos» esa barra salía **la quinta**, con 42
activos, compitiendo con Debian 12 y Windows 11 Pro sin ser una versión de nada (no tiene
fecha de fin de soporte ni se puede comparar). Además robaba un puesto al top, así que el
pie prometía «las 12 versiones con más activos» cuando solo dibujaba once. Ahora el top
contiene **doce versiones reales** y esos activos van **debajo, en su propia línea**, con su
cifra, su unidad y enlace a su lista. El pie cuadra: 12 dibujadas + 14 fuera = 26
versiones distintas.

### 7. «191 en seguimiento» en `/parches-pendientes/`

Son **filas del catálogo**, una por identificador CVE, paquete y versión del sistema
operativo: en realidad **34 identificadores distintos en 58 paquetes**, presentes en **185
activos**. El rótulo es ahora «**191 correcciones en seguimiento**» con la nota que lo
explica, y la columna «Filas» de la tabla de motivos pasa a «Correcciones en seguimiento».
`threatintel.parches.resumen` devuelve para eso tres claves nuevas (`cve_distintos`,
`paquetes`, `ecosistemas`), calculadas en la misma consulta que ya contaba las filas.

**Conciliación con Remediación.** Esa página cuenta **1.748 actualizaciones sin versión que
instalar** sobre los mismos datos, y las dos cifras convivían sin que nadie dijera que son
unidades distintas: aquí se cuenta el **catálogo del problema** (una fila por identificador,
paquete y versión del sistema, cuente el parque una máquina o mil) y allí el **trabajo por
máquina** (una tarea por activo y origen de paquete). El pie de `/parches-pendientes/` lo
dice con las dos cifras delante, y la de Remediación se pide con `resumen_memorizado`, que
la guarda en `g` durante la petición.

### 8. «334 con vulnerabilidades» en `/alertas-proceso/`

Las tarjetas suman los procesos, así que solo hablan de los **servidores con proceso
asignado**: **356 de 391**, y **334 de esos 356** con vulnerabilidades, mientras en todo el
parque hay **357 servidores afectados de 391**. Quien leía la página creía estar viendo el
parque entero. Los rótulos dicen ahora el alcance («Servidores con proceso asignado»,
«Servidores con proceso y con vulnerabilidades») y las notas dan el total del parque y los
servidores sin proceso, que no reciben ningún correo por proceso. El recuento del parque se
calcula en la vista con el mismo criterio de severidad y de estado que
`alertas_proceso.procesos_disponibles`.

### 9. La ficha de amenaza contaba tecnologías que no listaba

Decía «2 tecnologías correlacionadas: 0 afectadas, 2 sin determinar» y la tabla enseñaba
**una sola fila**, porque la otra estaba por debajo del umbral de confianza y va a la nota
«Menciones sin prueba de exposición». Ahora la cabecera cuenta **lo que se lista** («Se
lista 1 tecnología con prueba suficiente: 0 con versión afectada y 1 sin determinar») y lo
que no se lista lleva su propio recuento: las descartadas por versión y las menciones sin
prueba, estas últimas también en el encabezado de su nota. De paso, una amenaza cuyas
correlaciones estén **todas descartadas por versión** ya no dice «sin correlación con el
inventario», que era justo lo contrario: dice que se comprobaron y no afectan.

### 10. «0,6 % corregido: 140 de 22.731» en el avance por tipo de máquina

Ese 22.731 era **140 filas corregidas en 30 días** (un flujo) más **22.591 pendientes hoy**
(un stock): un denominador que no existe en ninguna parte. Es el mismo error que ya se
corrigió en la gráfica semanal.

**Decisión y porqué.** La columna se llama ahora «**Avance del periodo**» y mide una sola
cosa: de las filas de remediación que **ya estaban pendientes al empezar el periodo**,
cuántas se han cerrado dentro del periodo. Numerador y denominador tienen la misma unidad
(filas de remediación), el mismo conjunto de filas y el mismo periodo, así que la barra
dibuja exactamente el porcentaje que tiene al lado. Se descartaron dos alternativas: el
porcentaje sobre «lo detectado en el periodo» castiga lo que acaba de llegar y no responde
a la pregunta del jefe de proceso («¿estamos bajando la cola?»), y una proyección del tipo
«a este ritmo faltan N años» es una extrapolación, no una medida. **Cuando no hay cola
anterior no se enseña ningún porcentaje**: se dan las dos cifras por separado, cada una con
su unidad y su referencia de tiempo («140 filas cerradas en 30 días (movimiento)» y «22.591
pendientes hoy (foto de hoy)») y se dice que no se dividen entre sí. Hoy es el caso de los
dos tipos de máquina, porque la remediación más antigua de producción se detectó el
**2026-09-04** y el periodo son 30 días: todo lo pendiente nació dentro del periodo. En
cuanto haya más de un mes de historia, la columna empezará a dar el porcentaje sola.

### 11. Concordancia en la ficha del activo

«1 actualización **que cubren** N vulnerabilidades» pasa a «que cubre» en singular.

### Coste medido (sobre la copia de producción del 2026-09-15)

| Página | Antes | Después | Por qué |
| --- | --- | --- | --- |
| `/amenazas/tendencias` | 67 ms | 67 ms | solo texto |
| `/activos/` | 1.455 ms | 1.455 ms | solo texto y un filtro en memoria |
| `/alertas-proceso/` | 11 ms | 11 ms | un recuento más sobre 730 filas |
| `/parches-pendientes/` | ~130 ms | 388 ms | pide el resumen de Remediación (260 ms) para conciliar |
| `/remediaciones/` | 1.560 ms | 1.656 ms | un recorrido de `remediaciones` (99 ms) para la cola anterior |

La única subida apreciable es `/parches-pendientes/`, que necesita
`actualizaciones_sin_version` de `remediacion.resumen`. Bajaría a casi cero si ese módulo
expusiera esa cifra sola (hoy se calcula con el resto del resumen) o si `remediaciones`
tuviera un índice por `detectado_at`; las dos cosas están fuera de este frente.

### Pruebas

`tests/test_rotulos_tableros_2026_09_15.py` (22 pruebas) fija **un rótulo o una cifra por
punto**, con un parque sembrado que reproduce cada caso: una amenaza que menciona dos
tecnologías (para que la leyenda discrepe de la tarjeta a propósito), otra con una
tecnología con prueba y otra solo mencionada, un equipo de cómputo sin datos de sistema, un
servidor sin proceso de negocio, cuatro filas de catálogo para dos identificadores y una
remediación sin versión que instalar. Cubre los dos estados del avance por tipo de máquina
(con cola anterior y sin ella) y los casos límite de las funciones de la gráfica de
versiones (lista vacía, solo lo desconocido). Se adaptaron además
`tests/test_roles_alcance.py`, `tests/test_pagina_amenazas.py`,
`tests/test_estados_amenaza.py` y `tests/test_recorridos_paleta.py`, que fijaban los
textos y el porcentaje antiguos.
