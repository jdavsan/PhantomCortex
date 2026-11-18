"""Gráficos SVG generados en el servidor para la interfaz de administración.

Por qué SVG del lado servidor y por qué colores por clase
---------------------------------------------------------
La interfaz sirve una CSP estricta (``default-src 'none'; script-src 'self';
style-src 'self'``) sin ``'unsafe-inline'`` en ningún directorio. Eso prohíbe:

* atributos ``style=""`` en HTML o SVG (los bloquea ``style-src``),
* manejadores ``on*=""`` y ``<script>`` en línea (``script-src``),
* recursos externos (librerías de gráficos, fuentes, CDN).

Por tanto los gráficos se construyen aquí, en Python, como SVG en línea. La
geometría viaja en atributos SVG (``x``, ``y``, ``width``, ``height``, ``d``,
``points``, ``r``…), que no son CSS y la CSP no los toca. Los colores NUNCA van
en atributos: cada elemento de dato lleva una clase ``serie-<clave>``,
``linea-<clave>`` o ``area-<clave>`` y la hoja de estilos (``static/estilo.css``)
la resuelve con las variables de la paleta, así el modo oscuro funciona sin
código adicional. Los atributos ``fill``/``stroke`` solo se emiten con los
valores ``none`` o ``currentColor``.

Seguridad
---------
Todo texto que llega a un gráfico puede proceder de la base de datos (nombres
de fuentes RSS, tecnologías, títulos, CVE) y por tanto de terceros: se escapa
siempre con :func:`markupsafe.escape` antes de insertarse en el SVG, tanto en
contenido como en atributos (``aria-label``, ``href``). Los ``href`` solo se
aceptan si son rutas locales que empiezan por ``/`` y no por ``//``.

Robustez
--------
Las funciones son puras (sin estado global, sin ``random`` ni relojes) y no
lanzan excepciones con datos irregulares: ``None``, los valores no numéricos y
los negativos cuentan como 0; las listas de longitud distinta se rellenan o
recortan; y cuando no hay nada que dibujar se devuelve
``<div class="grafico-vacio">Sin datos suficientes</div>``.

Los números visibles siguen el formato español (``1.234`` y ``7,5``) y las
etiquetas van en español sin abreviaturas.

Clases que este módulo emite además de las del contrato de la especificación
(sección 5) y que la hoja de estilos debe resolver:

* ``polyline.linea-halo``: trazo grueso del color del panel bajo la línea de
  ``barras_apiladas`` (``stroke: var(--fondo-panel); stroke-width: 5; fill: none``).
* ``text.etiqueta-valor.etiqueta-linea``: valor rotulado sobre cada punto de una
  línea pegada al eje X (``font-size: 10px``).
* ``span.leyenda-punto.linea-<clave>``: marcador de raya en la leyenda para una
  serie dibujada como línea.
"""
from __future__ import annotations

import math
from typing import Any, Iterable, Optional, Sequence

from markupsafe import Markup, escape

__all__ = [
    "fmt", "chispa", "barras_apiladas", "barras_horizontales", "dona",
    "linea_tiempo", "barra_progreso", "medidor", "flujo", "CLAVES", "VACIO",
]

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

#: Claves de serie con color definido en la hoja de estilos. Cualquier otra
#: clave se sustituye por ``neutro`` para que nunca quede un elemento sin color.
#: La paleta categórica creció de 8 a 12 colores el 2026-09-08 para que la gráfica de
#: versiones de sistema pinte cada barra con un color distinto sin repetir ninguno.
CLAVES = frozenset({
    "critico", "alto", "medio", "bajo", "exito", "neutro", "acento",
    "secundario", "kev", *(f"cat-{i}" for i in range(1, 13)),
})

#: Nombre visible cuando el llamante no lo indica (barras horizontales).
NOMBRES_POR_DEFECTO = {
    "critico": "Críticas", "alto": "Altas", "medio": "Medias", "bajo": "Bajas",
    "exito": "Correctas", "neutro": "Otras", "acento": "Principal",
    "secundario": "Secundaria", "kev": "En KEV",
}

#: Estados admitidos en el diagrama de flujo y su descripción accesible.
ESTADOS_FLUJO = {
    "ok": "Correcto", "atencion": "Requiere atención",
    "critico": "Crítico", "inactivo": "Inactivo",
}

#: Resultado común cuando no hay datos que dibujar.
VACIO = Markup('<div class="grafico-vacio">Sin datos suficientes</div>')

# Anchura media estimada de un carácter en píxeles para la pila tipográfica
# del sistema. Solo sirve para reservar márgenes y decidir cuántas etiquetas
# caben; se redondea al alza para que el texto nunca se corte ni se solape.
_PX_CARACTER = 6.6          # texto de eje, 11px
_PX_CARACTER_NEGRITA = 7.2  # etiqueta-valor, 11px semibold
_ALTO_LINEA = 14            # altura de una línea de texto de 11px

# Divisiones admitidas en un eje Y automático (líneas de rejilla): se elige,
# entre 3 y 5, la que menos eje desperdicia con un paso «redondo».
_DIVISIONES_MIN, _DIVISIONES_MAX = 3, 5
#: Mantisas de paso redondas, en orden de preferencia ante empate.
_FACTORES_PASO = (1, 2, 5, 2.5)

# Una línea superpuesta cuyo máximo no llega a esta fracción del tope del eje
# queda pegada al eje X: además del halo, se rotula el valor de cada punto.
_UMBRAL_LINEA_BAJA = 0.05


# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------

def _e(texto: Any) -> str:
    """Escapa cualquier texto para insertarlo en HTML/SVG (contenido o atributo)."""
    return str(escape("" if texto is None else texto))


def _texto(valor: Any) -> str:
    """Texto crudo (sin escapar) a partir de cualquier valor; None → cadena vacía."""
    return "" if valor is None else str(valor)


def _num(x: float) -> str:
    """Número compacto para atributos SVG: 12.0 → '12', 3.14159 → '3.14'."""
    if x != x or x in (math.inf, -math.inf):  # NaN / infinito
        return "0"
    texto = f"{x:.2f}".rstrip("0").rstrip(".")
    return "0" if texto in ("", "-0") else texto


def _valor(v: Any) -> float:
    """Convierte un dato en número ≥ 0. None, texto no numérico, NaN,
    infinito y negativos cuentan como 0 (regla de la especificación)."""
    if v is None:
        return 0.0
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.0
    if f != f or f in (math.inf, -math.inf) or f < 0:
        return 0.0
    return f


def _numero_o_none(v: Any) -> Optional[float]:
    """Como :func:`_valor` pero distingue «sin dato» (None) de 0."""
    if v is None or isinstance(v, str) and not v.strip():
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if f != f or f in (math.inf, -math.inf):
        return None
    return max(f, 0.0)


def _dim(valor: Any, defecto: float) -> float:
    """Dimensión positiva y finita; si no lo es, el valor por defecto."""
    try:
        f = float(valor)
    except (TypeError, ValueError):
        return float(defecto)
    if f != f or f in (math.inf, -math.inf) or f <= 0:
        return float(defecto)
    return f


def _clave(clave: Any) -> str:
    """Clave de serie válida; las desconocidas pasan a ``neutro``."""
    texto = _texto(clave).strip().lower()
    return texto if texto in CLAVES else "neutro"


def _href_seguro(valor: Any) -> str:
    """Solo rutas locales generadas por ``url_for``: empiezan por una única barra.

    Se rechazan ``//dominio`` (URL relativa al esquema, externa), ``/\\dominio``
    (los navegadores normalizan la barra invertida) y cualquier carácter de
    control, además de esquemas como ``javascript:`` o ``https:``.
    """
    texto = _texto(valor).strip()
    if not texto.startswith("/") or texto.startswith(("//", "/\\")):
        return ""
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in texto):
        return ""
    return texto


def _recortar(texto: str, largo: int) -> str:
    """Recorta a ``largo`` caracteres añadiendo «…»; el nombre completo va aparte."""
    largo = max(2, int(largo))
    return texto if len(texto) <= largo else texto[: largo - 1].rstrip() + "…"


def _pct(parte: float, total: float) -> str:
    """Porcentaje entero en español: '37 %'. Las fracciones no nulas menores
    del 1 % se indican como '<1 %' para no mostrar un 0 engañoso."""
    if total <= 0:
        return "0 %"
    p = 100.0 * parte / total
    if 0 < p < 0.5:
        return "<1 %"
    return f"{fmt(int(round(p)))} %"


def _porcentajes(valores: Sequence[float], total: float) -> list[str]:
    """Porcentajes enteros de varias partes de un mismo total que suman
    exactamente el 100 % (método del mayor resto).

    El redondeo independiente de cada parte puede sumar 99 o 101 (33+33+33);
    aquí se reparte la diferencia entre las partes con mayor resto decimal.
    Una parte no nula que se queda en 0 se muestra como «<1 %». Si las partes
    no cubren el total (barra de progreso con hueco), suman el porcentaje que
    les corresponde, no 100.
    """
    if total <= 0 or not valores:
        return ["0 %" for _ in valores]
    exactos = [100.0 * v / total for v in valores]
    enteros = [int(math.floor(p + 1e-9)) for p in exactos]
    objetivo = int(round(sum(exactos)))
    faltan = max(0, objetivo - sum(enteros))
    orden = sorted(range(len(valores)), key=lambda i: exactos[i] - enteros[i], reverse=True)
    for i in orden[:faltan]:
        enteros[i] += 1
    salida = []
    for v, entero in zip(valores, enteros):
        if v <= 0:
            salida.append("0 %")
        elif entero == 0:
            salida.append("<1 %")
        else:
            salida.append(f"{fmt(entero)} %")
    return salida


def _ancho_texto(texto: str, *, negrita: bool = False) -> float:
    """Anchura estimada en px de un texto de 11px."""
    return len(texto) * (_PX_CARACTER_NEGRITA if negrita else _PX_CARACTER)


def _escala(maximo: float) -> tuple[float, float]:
    """Devuelve ``(tope, paso)`` para un eje Y automático de 0 a ≥ ``maximo``.

    El paso es siempre «redondo» (1, 2, 2,5 o 5 × 10ⁿ) y entero (nada de
    0,5 en recuentos) y el número de divisiones se elige entre 3 y 5 para
    desperdiciar el menor eje posible: 24 → 25 (5×5), 540 → 600 (3×200),
    1.361 → 1.500 (3×500). Para máximos de hasta 3 el eje es 0-3 con paso 1.
    """
    if maximo != maximo or maximo in (math.inf, -math.inf) or maximo <= _DIVISIONES_MIN:
        return float(_DIVISIONES_MIN), 1.0
    exponente = math.floor(math.log10(maximo))
    mejor: Optional[tuple[float, float]] = None
    for e in (exponente - 1, exponente, exponente + 1):
        base = 10.0 ** e
        for factor in _FACTORES_PASO:
            paso = factor * base
            if paso < 1 - 1e-9 or (factor == 2.5 and e < 1):
                continue  # solo pasos enteros
            divisiones = math.ceil(maximo / paso - 1e-9)
            if _DIVISIONES_MIN <= divisiones <= _DIVISIONES_MAX:
                tope = paso * divisiones
                if mejor is None or tope < mejor[0] - 1e-9:
                    mejor = (tope, paso)
    if mejor is None:  # inalcanzable con máximo > 3; red de seguridad
        paso = 10.0 ** exponente
        return paso * math.ceil(maximo / paso), paso
    return mejor


def _escala_fija(tope: float) -> tuple[float, float]:
    """``(tope, paso)`` para un eje Y con máximo impuesto por el llamante
    (p. ej. 10 para CVSS). Se busca un paso redondo con 5, 4 o 3 divisiones
    (10 → 0/2/4/6/8/10; 1 → 0/0,2/…); si no lo hay, cuatro divisiones."""
    for divisiones in (5, 4, 3):
        paso = tope / divisiones
        mantisa = paso / 10.0 ** math.floor(math.log10(paso))
        if any(abs(mantisa - f) < 1e-9 for f in _FACTORES_PASO):
            return tope, paso
    return tope, tope / 4


def _ticks(tope: float, paso: float) -> list[float]:
    """Valores de las líneas de rejilla de 0 a ``tope`` inclusive."""
    n = max(1, int(round(tope / paso)))
    return [paso * k for k in range(n + 1)]


def _punto_polar(cx: float, cy: float, r: float, angulo: float) -> tuple[float, float]:
    """Punto sobre una circunferencia; ángulo en grados desde las 12, horario."""
    rad = math.radians(angulo)
    return cx + r * math.sin(rad), cy - r * math.cos(rad)


def _sector(cx: float, cy: float, r_ext: float, r_int: float,
            inicio: float, fin: float) -> str:
    """Trayectoria (``d``) de un sector anular relleno entre dos ángulos.

    Se dibuja como forma rellena (no como trazo) para que el color venga de
    ``fill`` vía clase ``serie-<clave>``. Un giro completo se divide en dos
    mitades porque un arco SVG de 360° con inicio y fin coincidentes no se pinta.
    """
    amplitud = fin - inicio
    if amplitud <= 0 or r_ext <= 0:
        return ""
    if amplitud >= 360 - 1e-6:
        mitad = inicio + 180
        return (_sector(cx, cy, r_ext, r_int, inicio, mitad) + " "
                + _sector(cx, cy, r_ext, r_int, mitad, inicio + 360))
    grande = 1 if amplitud > 180 else 0
    r_int = max(0.0, min(r_int, r_ext))
    x0, y0 = _punto_polar(cx, cy, r_ext, inicio)
    x1, y1 = _punto_polar(cx, cy, r_ext, fin)
    x2, y2 = _punto_polar(cx, cy, r_int, fin)
    x3, y3 = _punto_polar(cx, cy, r_int, inicio)
    return (f"M{_num(x0)} {_num(y0)} "
            f"A{_num(r_ext)} {_num(r_ext)} 0 {grande} 1 {_num(x1)} {_num(y1)} "
            f"L{_num(x2)} {_num(y2)} "
            f"A{_num(r_int)} {_num(r_int)} 0 {grande} 0 {_num(x3)} {_num(y3)} Z")


def _svg(ancho: float, alto: float, aria: str, cuerpo: str, *, extra: str = "") -> str:
    """Envoltorio ``<svg>`` con ``viewBox``, ``role="img"`` y ``aria-label``."""
    return (f'<svg class="grafico" viewBox="0 0 {_num(ancho)} {_num(alto)}" '
            f'role="img" aria-label="{_e(aria)}"{extra}>{cuerpo}</svg>')


def _figura(tipo: str, *partes: str) -> Markup:
    return Markup(f'<figure class="grafico-envoltorio grafico-{tipo}">'
                  + "".join(p for p in partes if p) + "</figure>")


def _leyenda(filas: Iterable[tuple]) -> str:
    """``<ul class="leyenda">`` a partir de (clave, nombre, valor, extra[, tipo]).

    ``tipo`` es ``serie`` (cuadrado de color, por defecto) o ``linea`` (raya,
    para una serie dibujada como línea): el marcador lleva la clase
    ``leyenda-punto serie-<clave>`` o ``leyenda-punto linea-<clave>``.
    """
    elementos = []
    for clave, nombre, valor, extra, *resto in filas:
        tipo = "linea" if resto and resto[0] == "linea" else "serie"
        li = f'<li><span class="leyenda-punto {tipo}-{_clave(clave)}"></span>{_e(nombre)}'
        if valor is not None:
            li += f" <b>{_e(valor)}</b>"
        if extra:
            li += f" {_e(extra)}"
        elementos.append(li + "</li>")
    return f'<ul class="leyenda">{"".join(elementos)}</ul>' if elementos else ""


def _titulo(texto: str) -> str:
    return f"<title>{_e(texto)}</title>"


def _normalizar_series(series: Any, n: int) -> list[dict[str, Any]]:
    """Series homogéneas: clave válida, nombre y exactamente ``n`` valores ≥ 0."""
    if isinstance(series, dict):
        series = [series]
    salida: list[dict[str, Any]] = []
    for s in series or []:
        if not isinstance(s, dict):
            continue
        clave = _clave(s.get("clave"))
        crudos = s.get("valores")
        if isinstance(crudos, (str, bytes)) or crudos is None:
            crudos = []
        valores = [_valor(v) for v in list(crudos)[:n]]
        valores += [0.0] * (n - len(valores))
        nombre = _texto(s.get("nombre")).strip() or NOMBRES_POR_DEFECTO.get(clave, clave)
        salida.append({"clave": clave, "nombre": nombre, "valores": valores,
                       "hay_dato": any(_numero_o_none(v) is not None for v in list(crudos)[:n])})
    return salida


def _normalizar_partes(partes: Any) -> list[tuple[str, str, float]]:
    """Porciones/partes homogéneas: (clave, nombre, valor ≥ 0)."""
    if isinstance(partes, dict):
        partes = [partes]
    salida = []
    for p in partes or []:
        if not isinstance(p, dict):
            continue
        clave = _clave(p.get("clave"))
        nombre = _texto(p.get("nombre")).strip() or NOMBRES_POR_DEFECTO.get(clave, clave)
        salida.append((clave, nombre, _valor(p.get("valor"))))
    return salida


def _segmento(seg: Any, nombres: Optional[dict]) -> Optional[tuple[str, float, str]]:
    """Segmento de barra horizontal: admite (clave, valor), (clave, valor, nombre)
    o {"clave":…, "valor":…, "nombre":…}. Devuelve (clave, valor, nombre)."""
    if isinstance(seg, dict):
        clave, valor, nombre = seg.get("clave"), seg.get("valor"), seg.get("nombre")
    elif isinstance(seg, (list, tuple)) and len(seg) >= 2:
        clave, valor = seg[0], seg[1]
        nombre = seg[2] if len(seg) >= 3 else None
    else:
        return None
    clave = _clave(clave)
    nombre = _texto(nombre).strip() or _texto((nombres or {}).get(clave)).strip() \
        or NOMBRES_POR_DEFECTO.get(clave, clave)
    return clave, _valor(valor), nombre


def _paso_etiquetas(n: int, ancho_maximo: float, ranura: float) -> int:
    """Cada cuántas posiciones se escribe una etiqueta para que no se solapen:
    1 (todas) si la etiqueta más ancha, con 8 px de holgura, cabe en la ranura;
    si no, las posiciones necesarias para que quepa."""
    if ranura <= 0:
        return max(1, n)
    return max(1, math.ceil((ancho_maximo + 8) / ranura))


def _indices_etiquetas(n: int, paso: int) -> list[int]:
    """Posiciones a rotular con un paso dado: la última (más reciente) siempre,
    hacia atrás cada ``paso``, y la primera siempre. Si la rotulada más cercana
    a la primera quedara a menos de ``paso`` posiciones, se sustituye por la
    primera para que no se solapen."""
    if n <= 0:
        return []
    paso = max(1, int(paso))
    indices = list(range(n - 1, -1, -paso))
    if indices[-1] != 0:
        if indices[-1] < paso and len(indices) > 1:
            indices[-1] = 0
        else:  # la última nunca se sacrifica: primera y última siempre
            indices.append(0)
    return sorted(indices)


def _eje_y(px0: float, pw: float, y_de, ticks: Sequence[float], unidad: str = "") -> str:
    """Rejilla horizontal con etiquetas formateadas; la línea 0 es el eje."""
    salida = []
    for k, t in enumerate(ticks):
        y = _num(y_de(t))
        clase = "eje-linea" if k == 0 else "rejilla"
        salida.append(f'<line class="{clase}" x1="{_num(px0)}" x2="{_num(px0 + pw)}" '
                      f'y1="{y}" y2="{y}"/>')
        etiqueta = f"{fmt(t)} {unidad}".strip() if unidad else fmt(t)
        salida.append(f'<text class="eje" x="{_num(px0 - 8)}" y="{_num(y_de(t) + 4)}" '
                      f'text-anchor="end">{_e(etiqueta)}</text>')
    return "".join(salida)


def _plano(texto: str) -> str:
    """Etiqueta de varias líneas («sep\n2026») en una sola, para títulos y textos accesibles."""
    return " ".join(str(texto).split("\n"))


def _ajustar_categoria(texto: str, ancho: float) -> tuple[list[str], Optional[str]]:
    """Reparte el nombre de una categoría en hasta tres líneas que quepan en ``ancho``
    px, cortando por espacios. Si una palabra sola no cabe, se recorta con «…» y se
    devuelve el nombre completo como segundo valor (para el ``<title>``)."""
    lineas_dadas = str(texto).split("\n")
    if all(_ancho_texto(l) <= ancho for l in lineas_dadas):
        return lineas_dadas, None
    palabras = _plano(texto).split()
    lineas: list[str] = []
    actual = ""
    for palabra in palabras:
        candidata = f"{actual} {palabra}".strip()
        if actual and _ancho_texto(candidata) > ancho:
            lineas.append(actual)
            actual = palabra
        else:
            actual = candidata
    if actual:
        lineas.append(actual)
    recortado = False
    if len(lineas) > 3:  # demasiadas líneas: se juntan las sobrantes en la tercera
        lineas = lineas[:2] + [" ".join(lineas[2:])]
    for i, linea in enumerate(lineas):
        if _ancho_texto(linea) > ancho:
            caben = max(1, int(ancho / _PX_CARACTER) - 1)
            lineas[i] = linea[:caben].rstrip() + "…"
            recortado = True
    return lineas, (_plano(texto) if recortado else None)


def _lineas_eje_x(etiquetas: Sequence[str], ranura: float, categorico: bool) -> list[tuple[list[str], Optional[str]]]:
    """Líneas a dibujar por etiqueta (y nombre completo si se recortó)."""
    if categorico:
        return [_ajustar_categoria(e, max(ranura - 8, 3 * _PX_CARACTER)) for e in etiquetas]
    return [(str(e).split("\n"), None) for e in etiquetas]


def _n_lineas_eje_x(etiquetas: Sequence[str], ranura: float, categorico: bool) -> int:
    """Cuántas líneas de texto ocupa el eje X (para reservar el margen inferior)."""
    if not etiquetas:
        return 1
    return max(len(lineas) for lineas, _ in _lineas_eje_x(etiquetas, ranura, categorico))


def _hace_falta_rotar(etiquetas: Sequence[str], ranura: float) -> bool:
    """¿Hay que girar las etiquetas para poder pintarlas TODAS sin solaparse?

    Solo cuando, escritas como están (una o varias líneas), el paso necesario para que
    no se toquen es mayor que 1: es decir, cuando pintarlas todas rectas obligaría a
    saltarse alguna.
    """
    if not etiquetas:
        return False
    partes = _lineas_eje_x(etiquetas, ranura, False)
    ancho_max = max(_ancho_texto(l) for lineas, _ in partes for l in lineas)
    return _paso_etiquetas(len(etiquetas), ancho_max, ranura) > 1


def _ancho_rotado(etiquetas: Sequence[str]) -> float:
    """Anchura de la etiqueta más larga escrita en UNA línea (para girarla)."""
    if not etiquetas:
        return 0.0
    return max(_ancho_texto(_plano(e)) for e in etiquetas)


#: Seno y coseno de 45 grados: una etiqueta girada ‑45° ocupa esa fracción de su
#: anchura hacia abajo y otro tanto hacia la izquierda de su ancla.
_DIAGONAL = 0.7071


def _eje_x(etiquetas: Sequence[str], x_de, y: float, ranura: float, *,
           categorico: bool = False, rotar: bool = False) -> str:
    """Etiquetas del eje X sin solapes.

    Serie temporal (por defecto): se muestran todas mientras la más ancha (≈6,6 px
    por carácter a 11 px) quepa en su ranura; si no, se espacian lo justo y la
    primera y la última se rotulan siempre. Una etiqueta puede tener varias
    líneas separadas por «\n» (mes arriba, año completo debajo).

    Categórico (``categorico=True``): cada categoría lleva siempre su nombre; si no
    cabe, se reparte en hasta tres líneas por palabras y, en último extremo, se
    recorta con «…» dejando el nombre completo en un ``<title>``.

    Girado (``rotar=True``, 2026-09-15): TODAS las etiquetas se escriben, en una sola
    línea y giradas 45 grados, ancladas por su extremo derecho al centro de la barra.
    Lo usa quien no puede permitirse saltarse ninguna —la ficha de una tecnología pintaba
    diez barras y solo seis meses en el eje, así que cuatro barras no tenían nombre
    (revisión de claridad del 2026-09-15)—. El giro va en el atributo ``transform`` del
    SVG, que no es CSS y la política de seguridad de contenido no lo toca.
    """
    n = len(etiquetas)
    if n == 0:
        return ""
    if rotar and not categorico:
        salida = []
        for i, etiqueta in enumerate(etiquetas):
            texto = _plano(etiqueta)
            x, y_t = x_de(i), y
            salida.append(
                f'<text class="eje" x="{_num(x)}" y="{_num(y_t)}" text-anchor="end" '
                f'transform="rotate(-45 {_num(x)} {_num(y_t)})">{_e(texto)}</text>')
        return "".join(salida)
    partes = _lineas_eje_x(etiquetas, ranura, categorico)
    if categorico:
        indices = list(range(n))
    else:
        ancho_max = max(_ancho_texto(l) for lineas, _ in partes for l in lineas)
        indices = _indices_etiquetas(n, _paso_etiquetas(n, ancho_max, ranura))
    salida = []
    for i in indices:
        lineas, completo = partes[i]
        x = _num(x_de(i))
        if len(lineas) == 1 and not completo:
            salida.append(f'<text class="eje" x="{x}" y="{_num(y)}" text-anchor="middle">{_e(lineas[0])}</text>')
            continue
        titulo = _titulo(completo) if completo else ""
        tspans = "".join(f'<tspan x="{x}" dy="{0 if k == 0 else _ALTO_LINEA}">{_e(l)}</tspan>'
                         for k, l in enumerate(lineas))
        salida.append(f'<text class="eje" x="{x}" y="{_num(y)}" text-anchor="middle">{titulo}{tspans}</text>')
    return "".join(salida)


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def fmt(valor: Any, decimales: int = 0) -> str:
    """Formatea un número en español: 1234 → «1.234»; 7.5 → «7,5»; None → «—».

    Con ``decimales=0`` (por defecto) se muestran solo los decimales necesarios,
    hasta dos (7.0 → «7», 7.5 → «7,5», 0.333 → «0,33»). Con ``decimales>0`` se
    fuerza ese número exacto (7 → «7,0»). Un texto no numérico se devuelve tal
    cual; NaN e infinito se muestran como «—» porque no son datos.
    """
    if valor is None:
        return "—"
    if isinstance(valor, bool):
        valor = int(valor)
    try:
        f = float(valor)
    except (TypeError, ValueError):
        return str(valor)
    if f != f or f in (math.inf, -math.inf):
        return "—"
    try:
        decimales = int(decimales)
    except (TypeError, ValueError):
        decimales = 0
    if decimales <= 0:
        if f == int(f):
            texto = f"{int(f):,}"
        else:
            texto = f"{f:,.2f}".rstrip("0").rstrip(".")
    else:
        texto = f"{f:,.{decimales}f}"
    # Intercambio de separadores: coma de miles → punto; punto decimal → coma.
    texto = texto.replace(",", "\x00").replace(".", ",").replace("\x00", ".")
    return "0" if texto in ("-0", "-0,0", "-0,00") else texto


def chispa(valores: Any, *, ancho: float = 120, alto: float = 36,
           clave: str = "acento", area: bool = True) -> Markup:
    """Sparkline sin ejes para tarjetas de métrica y celdas de tabla.

    Serie de números; ``None`` y negativos cuentan como 0. Una serie toda a 0
    se dibuja plana (es un dato: «no hubo actividad»); una lista vacía devuelve
    el estado vacío.
    """
    if isinstance(valores, (str, bytes)) or valores is None:
        valores = []
    serie = [_valor(v) for v in list(valores)]
    if not serie:
        return VACIO
    ancho, alto = _dim(ancho, 120), _dim(alto, 36)
    clave = _clave(clave)
    n = len(serie)
    maximo = max(serie) or 1.0
    m = 3.0  # margen para el grosor de la línea y el punto final
    ancho_util, alto_util = ancho - 2 * m, alto - 2 * m

    def px(i: int) -> float:
        return m + (ancho_util * i / (n - 1) if n > 1 else ancho_util / 2)

    def py(v: float) -> float:
        return m + alto_util - alto_util * v / maximo

    puntos = [(px(i), py(v)) for i, v in enumerate(serie)]
    resumen = (f"Serie de {fmt(n)} {'valor' if n == 1 else 'valores'}: "
               f"último {fmt(serie[-1])}, máximo {fmt(max(serie))}")
    cuerpo = []
    if n > 1:
        cadena = " ".join(f"{_num(x)},{_num(y)}" for x, y in puntos)
        if area:
            base = _num(m + alto_util)
            trazo = " ".join(f"L{_num(x)} {_num(y)}" for x, y in puntos)
            cuerpo.append(f'<path class="area-{clave}" d="M{_num(puntos[0][0])} {base} '
                          f'{trazo} L{_num(puntos[-1][0])} {base} Z"/>')
        cuerpo.append(f'<polyline class="linea-{clave}" points="{cadena}">'
                      f'{_titulo(resumen)}</polyline>')
    # Con un solo valor no hay línea que ver: el marcador se hace más visible.
    x_fin, y_fin = puntos[-1]
    radio = 3 if n == 1 else 2.5
    cuerpo.append(f'<circle class="serie-{clave} punto" cx="{_num(x_fin)}" '
                  f'cy="{_num(y_fin)}" r="{_num(radio)}">{_titulo(f"Último valor: {fmt(serie[-1])}")}</circle>')
    return _figura("chispa", _svg(ancho, alto, resumen, "".join(cuerpo)))


def barras_apiladas(categorias: Any, series: Any, *, ancho: float = 760, alto: float = 240,
                    linea: Any = None, mostrar_totales: bool = True, leyenda: bool = True,
                    aria: str = "", categorico: bool = False,
                    etiquetas_todas: bool = False) -> Markup:
    """Barras verticales apiladas por categoría, con línea opcional superpuesta.

    ``categorias`` son las etiquetas del eje X en orden cronológico ascendente;
    cada serie aporta una posición por categoría y se apila en el orden dado.

    ``etiquetas_todas`` (2026-09-15) obliga a rotular TODAS las categorías: si no caben
    rectas, se giran 45 grados en una sola línea y el margen inferior e izquierdo crecen
    lo necesario. Sin él, las etiquetas que no caben se saltan, y una gráfica de diez
    barras con seis nombres deja cuatro barras sin identificar.
    ``linea`` ({"clave","nombre","valores"}) se dibuja con puntos sobre las
    barras en la misma escala Y, con un halo del color del panel debajo
    (``polyline.linea-halo``) para que no se confunda con las barras ni con el
    eje; si su máximo no llega al 5 % del tope del eje (línea pegada al eje X)
    se rotula además el valor de cada punto (``text.etiqueta-valor.etiqueta-linea``,
    ceros omitidos). Eje Y con tres a cinco líneas de rejilla y totales sobre
    cada barra; las etiquetas X se muestran todas si caben y, si no, espaciadas,
    siempre con la primera y la última.
    """
    if isinstance(categorias, (str, bytes)) or categorias is None:
        categorias = []
    cats = [_texto(c) for c in list(categorias)]
    n = len(cats)
    series_n = _normalizar_series(series, n)
    linea_n = _normalizar_series(linea, n)[0] if isinstance(linea, dict) else None
    if n == 0 or not series_n:
        return VACIO
    totales = [sum(s["valores"][i] for s in series_n) for i in range(n)]
    maximo = max(totales + (linea_n["valores"] if linea_n else []))
    if maximo <= 0:
        return VACIO

    ancho, alto = _dim(ancho, 760), _dim(alto, 240)
    tope, paso = _escala(maximo)
    ticks = _ticks(tope, paso)

    # Márgenes calculados: el eje Y según el número más largo; una línea para X.
    izq = max(_ancho_texto(fmt(t)) for t in ticks) + 14
    ranura_aprox = (ancho - izq - 12) / n
    # Anchura de la etiqueta X más ancha, ya repartida en líneas si es categórica.
    ancho_etq_x = max((_ancho_texto(l) for lineas, _ in _lineas_eje_x(cats, ranura_aprox, categorico)
                       for l in lineas), default=0)
    der = max(12.0, ancho_etq_x / 2 - ranura_aprox / 2 + 6)
    arriba = 22.0 if mostrar_totales else 10.0
    pw = max(ancho - izq - der, 40.0)
    # ¿Hay que girar las etiquetas para pintarlas todas? Se decide con la ranura
    # provisional y después se reservan los márgenes que el giro necesita: hacia abajo
    # y hacia la izquierda de la primera, que es la que se sale del dibujo.
    rotar = bool(etiquetas_todas) and not categorico and _hace_falta_rotar(cats, pw / n)
    if rotar:
        ancho_rot = _ancho_rotado(cats)
        der = max(der, 12.0)
        izq = max(izq, ancho_rot * _DIAGONAL - (pw / n) / 2 + 6)
        pw = max(ancho - izq - der, 40.0)
        abajo = ancho_rot * _DIAGONAL + 14.0
    else:
        # Margen inferior: una línea por cada línea de etiqueta («sep» / «2026»; nombres largos).
        abajo = _ALTO_LINEA * _n_lineas_eje_x(cats, pw / n, categorico) + 12.0
    ph = max(alto - arriba - abajo, 40.0)
    ancho, alto = izq + pw + der, arriba + ph + abajo
    px0, py0 = izq, arriba

    def y_de(v: float) -> float:
        return py0 + ph - ph * v / tope

    ranura = pw / n
    ancho_barra = min(max(ranura * 0.62, 3.0), 64.0)

    def x_centro(i: int) -> float:
        return px0 + ranura * i + ranura / 2

    cuerpo = [_eje_y(px0, pw, y_de, ticks)]
    for i, cat in enumerate(cats):
        x = x_centro(i) - ancho_barra / 2
        acumulado = 0.0
        for s in series_n:
            v = s["valores"][i]
            if v <= 0:
                continue
            y_sup = y_de(acumulado + v)
            h = ph * v / tope
            titulo = f"{_plano(cat)} · {s['nombre']}: {fmt(v)} ({_pct(v, totales[i])})"
            cuerpo.append(
                f'<rect class="serie-{s["clave"]}" x="{_num(x)}" y="{_num(y_sup)}" '
                f'width="{_num(ancho_barra)}" height="{_num(h)}">{_titulo(titulo)}</rect>')
            acumulado += v

    y_totales: dict[int, float] = {}  # línea base de cada total rotulado
    if mostrar_totales:
        ancho_total = max(_ancho_texto(fmt(t), negrita=True) for t in totales)
        paso_t = _paso_etiquetas(n, ancho_total, ranura)
        for i, total in enumerate(totales):
            if total <= 0 or (n - 1 - i) % paso_t:
                continue
            y_totales[i] = y_de(total) - 5
            cuerpo.append(f'<text class="etiqueta-valor" x="{_num(x_centro(i))}" '
                          f'y="{_num(y_totales[i])}" text-anchor="middle">{_e(fmt(total))}</text>')

    if linea_n:
        valores_linea = linea_n["valores"]
        puntos = [(x_centro(i), y_de(v)) for i, v in enumerate(valores_linea)]
        if n > 1:
            cadena = " ".join(f"{_num(x)},{_num(y)}" for x, y in puntos)
            # Halo del color del panel bajo la línea: la separa de las barras y del eje.
            cuerpo.append(f'<polyline class="linea-halo" fill="none" points="{cadena}"/>')
            cuerpo.append(f'<polyline class="linea-{linea_n["clave"]}" points="{cadena}">'
                          f'{_titulo(linea_n["nombre"])}</polyline>')
        # Línea pegada al eje X (valores ínfimos frente al tope): se rotula cada punto.
        rotular = 0 < max(valores_linea) < _UMBRAL_LINEA_BAJA * tope
        for i, (x, y) in enumerate(puntos):
            v = valores_linea[i]
            titulo = f"{_plano(cats[i])} · {linea_n['nombre']}: {fmt(v)}"
            cuerpo.append(
                f'<circle class="serie-{linea_n["clave"]} punto" cx="{_num(x)}" cy="{_num(y)}" r="3.5">'
                f'{_titulo(titulo)}</circle>')
            if not rotular or v <= 0:
                continue
            y_texto = y - 7
            # Si el total de la barra cae a la misma altura, el rótulo se omite
            # (el valor sigue en el <title> del punto) para no pisar el total.
            y_total = y_totales.get(i)
            if y_total is not None and -15 <= y_total - y <= 1:
                continue
            cuerpo.append(f'<text class="etiqueta-valor etiqueta-linea" x="{_num(x)}" '
                          f'y="{_num(y_texto)}" text-anchor="middle">{_e(fmt(v))}</text>')

    cuerpo.append(_eje_x(cats, x_centro, py0 + ph + _ALTO_LINEA + 4, ranura,
                         categorico=categorico, rotar=rotar))

    nombres = ", ".join(s["nombre"] for s in series_n)
    if not aria:
        aria = (f"Gráfico de barras apiladas ({nombres}) en {fmt(n)} periodos, "
                f"de {_plano(cats[0])} a {_plano(cats[-1])}; máximo {fmt(maximo)}")
    filas: list[tuple] = [(s["clave"], s["nombre"], fmt(sum(s["valores"])), "") for s in series_n]
    if linea_n:
        filas.append((linea_n["clave"], linea_n["nombre"], fmt(sum(linea_n["valores"])), "", "linea"))
    return _figura("barras-apiladas", _svg(ancho, alto, aria, "".join(cuerpo)),
                   _leyenda(filas) if leyenda else "")


def _con_unidad(total: float, unidad: Any) -> str:
    """«1.234 vulnerabilidades» o «1 activo»: la unidad admite una cadena o una pareja
    (singular, plural) y se elige según el total, para no escribir «1 activos»
    (peticion del frente de colores, 2026-09-08)."""
    if isinstance(unidad, (tuple, list)) and len(unidad) == 2:
        u = unidad[0] if total == 1 else unidad[1]
    else:
        u = _texto(unidad).strip()
    return f"{fmt(total)} {u}".strip()


def barras_horizontales(items: Any, *, ancho: float = 760, alto_fila: float = 28,
                        max_etiqueta: int = 30, mostrar_total: bool = True,
                        leyenda: bool = True, aria: str = "",
                        nombres: Optional[dict] = None, unidad: Any = "",
                        leyenda_nota: str = "") -> Markup:
    """Una fila por ítem con barras apiladas de izquierda a derecha, escala común.

    ``items``: ``[{"etiqueta": "Windows Server", "valores": [("critico", 3), ("alto", 5)],
    "href": "/amenazas/?tec=windows", "nota": "sin versión"}]``. Cada segmento
    admite ``(clave, valor)``, ``(clave, valor, nombre)`` o un diccionario;
    ``nombres`` ({clave: nombre}) fija los nombres de la leyenda cuando los
    segmentos no lo traen. La etiqueta se recorta a ``max_etiqueta`` con «…» y
    el nombre completo va en ``<title>``; si hay ``href`` local, la etiqueta es
    un enlace dentro del SVG. La nota se escribe tras el total de la fila.
    """
    if isinstance(items, dict):
        items = [items]
    filas = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        segmentos = []
        for seg in (it.get("valores") or []):
            s = _segmento(seg, nombres)
            if s is not None:
                segmentos.append(s)
        filas.append({
            "etiqueta": _texto(it.get("etiqueta")).strip() or "—",
            "segmentos": segmentos,
            "total": sum(v for _, v, _ in segmentos),
            "href": _href_seguro(it.get("href")),
            "nota": _texto(it.get("nota")).strip(),
        })
    if not filas:
        return VACIO
    maximo = max(f["total"] for f in filas)
    if maximo <= 0:
        return VACIO

    ancho, alto_fila = _dim(ancho, 760), _dim(alto_fila, 28)
    try:
        max_etiqueta = max(4, int(max_etiqueta))
    except (TypeError, ValueError):
        max_etiqueta = 30
    n = len(filas)
    recortadas = [_recortar(f["etiqueta"], max_etiqueta) for f in filas]
    izq = max(_ancho_texto(r) for r in recortadas) + 14
    textos_der = []
    for f in filas:
        # ``unidad`` escribe que es la cifra junto al numero («30.827 vulnerabilidades»):
        # un total sin unidad al lado de una nota que cuenta maquinas no se entiende
        # (queja del usuario del 2026-09-08: «dice 30.827 y ya no dice nada»).
        t = _con_unidad(f["total"], unidad) if mostrar_total else ""
        if f["nota"]:
            t = f"{t} · {f['nota']}" if t else f["nota"]
        textos_der.append(t)
    der = (max(_ancho_texto(t, negrita=True) for t in textos_der) + 10) if any(textos_der) else 8.0
    arriba = abajo = 4.0
    pw = max(ancho - izq - der, 40.0)
    ancho = izq + pw + der
    alto = arriba + n * alto_fila + abajo
    hb = alto_fila * 0.6

    cuerpo = [f'<line class="eje-linea" x1="{_num(izq)}" x2="{_num(izq)}" '
              f'y1="{_num(arriba)}" y2="{_num(alto - abajo)}"/>']
    totales_clave: dict[str, tuple[str, float]] = {}
    for i, f in enumerate(filas):
        cy = arriba + i * alto_fila + alto_fila / 2
        y_texto = cy + 4
        etiqueta = (f'<text class="eje" x="{_num(izq - 10)}" y="{_num(y_texto)}" text-anchor="end">'
                    f'{_titulo(f["etiqueta"])}{_e(recortadas[i])}</text>')
        if f["href"]:
            etiqueta = f'<a href="{_e(f["href"])}">{etiqueta}</a>'
        cuerpo.append(etiqueta)
        x = izq
        for clave, v, nombre in f["segmentos"]:
            nombre_ant, acumulado = totales_clave.get(clave, (nombre, 0.0))
            totales_clave[clave] = (nombre_ant, acumulado + v)
            if v <= 0:
                continue
            w = pw * v / maximo
            titulo = (f"{f['etiqueta']}: {_con_unidad(v, unidad)}" if nombre == f["etiqueta"]
                      else f"{f['etiqueta']} · {nombre}: {_con_unidad(v, unidad)}")
            if v < f["total"]:  # un único segmento es el 100 %: no se repite
                titulo += f" ({_pct(v, f['total'])})"
            cuerpo.append(
                f'<rect class="serie-{clave}" x="{_num(x)}" y="{_num(cy - hb / 2)}" '
                f'width="{_num(w)}" height="{_num(hb)}">{_titulo(titulo)}</rect>')
            x += w
        if textos_der[i]:
            contenido = _e(_con_unidad(f["total"], unidad)) if mostrar_total else ""
            if f["nota"]:
                contenido += f'<tspan class="nota">{" · " if contenido else ""}{_e(f["nota"])}</tspan>'
            cuerpo.append(f'<text class="etiqueta-valor" x="{_num(x + 6)}" y="{_num(y_texto)}">'
                          f'{contenido}</text>')

    if not aria:
        mayor = max(filas, key=lambda f: f["total"])
        aria = (f"Gráfico de barras horizontales de {fmt(n)} elementos; "
                f"el mayor es {mayor['etiqueta']} con {fmt(mayor['total'])}")
    filas_leyenda = [(clave, nombre, _con_unidad(total, unidad), "")
                     for clave, (nombre, total) in totales_clave.items()]
    # La leyenda suma SOLO las barras dibujadas, y en una grafica de «los N que mas...» eso
    # no es el total de la organizacion: ademas, si un elemento puede estar en dos barras
    # (una amenaza que menciona dos tecnologias), la suma repite. Sin decirlo, la leyenda
    # contradecia a las tarjetas de la misma pagina: «Criticas 156» frente a «118 criticas»
    # (auditoria de tableros del 2026-09-15). `leyenda_nota` obliga a escribirlo donde se lee.
    pie = (f'<p class="leyenda-nota pequeno tenue">{_e(leyenda_nota)}</p>'
           if leyenda and leyenda_nota else "")
    return _figura("barras-horizontales", _svg(ancho, alto, aria, "".join(cuerpo)),
                   (_leyenda(filas_leyenda) + pie) if leyenda else "")


def dona(porciones: Any, *, tamano: float = 200, grosor: float = 24,
         centro_valor: Any = None, centro_etiqueta: Any = None,
         leyenda: bool = True, aria: str = "") -> Markup:
    """Anillo de porciones con valor opcional en el centro.

    ``porciones``: ``[{"clave": "critico", "nombre": "Críticas", "valor": 6}, …]``.
    Las porciones a 0 no se dibujan pero siguen en la leyenda (con valor y
    porcentaje; los porcentajes se redondean por mayor resto y suman 100).
    Si la suma es 0 se devuelve el estado vacío.
    """
    partes = _normalizar_partes(porciones)
    total = sum(v for _, _, v in partes)
    if not partes or total <= 0:
        return VACIO
    tamano = _dim(tamano, 200)
    grosor = min(max(_dim(grosor, 24), 4.0), tamano / 2 - 4)
    c = tamano / 2
    r_ext = c - 2
    r_int = r_ext - grosor
    pcts = _porcentajes([v for _, _, v in partes], total)

    cuerpo = []
    visibles = [i for i, (_, _, v) in enumerate(partes) if v > 0]
    angulo = 0.0
    for i in visibles:
        clave, nombre, v = partes[i]
        fin = 360.0 if i == visibles[-1] else angulo + 360.0 * v / total
        cuerpo.append(f'<path class="serie-{clave}" d="{_sector(c, c, r_ext, r_int, angulo, fin)}">'
                      f'{_titulo(f"{nombre}: {fmt(v)} ({pcts[i]})")}</path>')
        angulo = fin

    if centro_valor is not None or _texto(centro_etiqueta).strip():
        texto_valor = fmt(centro_valor) if isinstance(centro_valor, (int, float)) \
            else _texto(centro_valor).strip()
        etiqueta = _texto(centro_etiqueta).strip()
        if texto_valor and etiqueta:
            cuerpo.append(f'<text class="dona-centro" x="{_num(c)}" y="{_num(c + 4)}" '
                          f'text-anchor="middle">{_e(texto_valor)}</text>')
            cuerpo.append(f'<text class="dona-centro-etiqueta" x="{_num(c)}" y="{_num(c + 20)}" '
                          f'text-anchor="middle">{_e(etiqueta)}</text>')
        elif texto_valor:
            cuerpo.append(f'<text class="dona-centro" x="{_num(c)}" y="{_num(c + 9)}" '
                          f'text-anchor="middle">{_e(texto_valor)}</text>')
        else:
            cuerpo.append(f'<text class="dona-centro-etiqueta" x="{_num(c)}" y="{_num(c + 4)}" '
                          f'text-anchor="middle">{_e(etiqueta)}</text>')

    if not aria:
        detalle = "; ".join(f"{nombre} {fmt(v)} ({p})" for (_, nombre, v), p in zip(partes, pcts))
        aria = f"Gráfico de anillo, total {fmt(total)}: {detalle}"
    filas = [(clave, nombre, fmt(v), f"({p})") for (clave, nombre, v), p in zip(partes, pcts)]
    return _figura("dona", _svg(tamano, tamano, aria, "".join(cuerpo)),
                   _leyenda(filas) if leyenda else "")


def linea_tiempo(etiquetas: Any, series: Any, *, ancho: float = 760, alto: float = 220,
                 area: bool = True, leyenda: bool = True, unidad: str = "",
                 aria: str = "", tope: Any = None) -> Markup:
    """Polilíneas rectas con puntos sobre rejilla horizontal; eje Y automático.

    ``series``: ``[{"clave": "acento", "nombre": "Latencia (ms)", "valores": [...]}]``.
    ``None`` cuenta como 0. Una serie toda a 0 se dibuja plana (es un dato);
    si ninguna serie trae un número, estado vacío. ``unidad`` se añade a las
    etiquetas del eje Y y a los valores de la leyenda. ``tope`` fija el máximo
    del eje Y en lugar de calcularlo (10 para un CVSS medio → 0/2/4/6/8/10);
    un valor que lo supere se dibuja en el borde superior, con su cifra real
    en el ``<title>``.
    """
    if isinstance(etiquetas, (str, bytes)) or etiquetas is None:
        etiquetas = []
    etqs = [_texto(e) for e in list(etiquetas)]
    n = len(etqs)
    series_n = _normalizar_series(series, n)
    if n == 0 or not series_n or not any(s["hay_dato"] for s in series_n):
        return VACIO
    unidad = _texto(unidad).strip()

    ancho, alto = _dim(ancho, 760), _dim(alto, 220)
    maximo = max(max(s["valores"]) for s in series_n)
    tope_fijo = _numero_o_none(tope)
    if tope_fijo is not None and tope_fijo > 0:
        tope, paso = _escala_fija(tope_fijo)
    else:
        tope, paso = _escala(maximo)
    ticks = _ticks(tope, paso)

    def con_unidad(v: float) -> str:
        return f"{fmt(v)} {unidad}".strip() if unidad else fmt(v)

    izq = max(_ancho_texto(con_unidad(t)) for t in ticks) + 14
    ancho_etq_x = max(_ancho_texto(l) for e in etqs for l in str(e).split("\n"))
    der = max(12.0, ancho_etq_x / 2 + 4)
    arriba, abajo = 12.0, _ALTO_LINEA * _n_lineas_eje_x(etqs, 0, False) + 12.0
    pw = max(ancho - izq - der, 40.0)
    ph = max(alto - arriba - abajo, 40.0)
    ancho, alto = izq + pw + der, arriba + ph + abajo
    px0, py0 = izq, arriba

    def y_de(v: float) -> float:
        return py0 + ph - ph * min(v, tope) / tope

    def x_de(i: int) -> float:
        return px0 + (pw * i / (n - 1) if n > 1 else pw / 2)

    radio = 3.5 if n <= 30 else 2.5
    cuerpo = [_eje_y(px0, pw, y_de, ticks, unidad)]
    for s in series_n:
        puntos = [(x_de(i), y_de(v)) for i, v in enumerate(s["valores"])]
        if n > 1:
            if area:
                base = _num(py0 + ph)
                trazo = " ".join(f"L{_num(x)} {_num(y)}" for x, y in puntos)
                cuerpo.append(f'<path class="area-{s["clave"]}" d="M{_num(puntos[0][0])} {base} '
                              f'{trazo} L{_num(puntos[-1][0])} {base} Z"/>')
            cadena = " ".join(f"{_num(x)},{_num(y)}" for x, y in puntos)
            cuerpo.append(f'<polyline class="linea-{s["clave"]}" points="{cadena}">'
                          f'{_titulo(s["nombre"])}</polyline>')
        for i, (x, y) in enumerate(puntos):
            titulo = f"{_plano(etqs[i])} · {s['nombre']}: {con_unidad(s['valores'][i])}"
            cuerpo.append(
                f'<circle class="serie-{s["clave"]} punto" cx="{_num(x)}" cy="{_num(y)}" r="{_num(radio)}">'
                f'{_titulo(titulo)}</circle>')
    cuerpo.append(_eje_x(etqs, x_de, py0 + ph + _ALTO_LINEA + 4, pw / n))

    if not aria:
        nombres = ", ".join(s["nombre"] for s in series_n)
        aria = (f"Gráfico de líneas ({nombres}) con {fmt(n)} puntos, de {_plano(etqs[0])} a {_plano(etqs[-1])}; "
                f"máximo {con_unidad(maximo)}")
    filas = [(s["clave"], s["nombre"], con_unidad(s["valores"][-1]), "(último valor)")
             for s in series_n]
    return _figura("linea-tiempo", _svg(ancho, alto, aria, "".join(cuerpo)),
                   _leyenda(filas) if leyenda else "")


def barra_progreso(partes: Any, *, alto: float = 10, leyenda: bool = True,
                   total: Any = None, aria: str = "") -> Markup:
    """Barra apilada al 100 % (HTML + SVG) para procedencia, cobertura, progreso.

    ``partes``: ``[{"clave": "exito", "nombre": "Con CVSS oficial", "valor": 120}, …]``.
    Si se indica ``total`` mayor que la suma, el resto queda como fondo sin
    pintar (progreso). Como la CSP impide ``width: 37%`` en línea, cada parte
    es un ``<rect width="37">`` en un ``viewBox="0 0 100 alto"`` con
    ``preserveAspectRatio="none"``, que escala con precisión al ancho del
    contenedor ``.progreso`` (la altura la fija la hoja de estilos). Los
    porcentajes de la leyenda se redondean por mayor resto: suman 100.
    """
    items = _normalizar_partes(partes)
    suma = sum(v for _, _, v in items)
    base = max(_valor(total) if total is not None else 0.0, suma)
    if not items or base <= 0:
        return VACIO
    alto = _dim(alto, 10)
    pcts = _porcentajes([v for _, _, v in items], base)
    x = 0.0
    cuerpo = []
    for (clave, nombre, v), p in zip(items, pcts):
        if v <= 0:
            continue
        w = 100.0 * v / base
        cuerpo.append(f'<rect class="serie-{clave}" x="{_num(x)}" y="0" width="{_num(w)}" '
                      f'height="{_num(alto)}">{_titulo(f"{nombre}: {fmt(v)} ({p})")}</rect>')
        x += w
    detalle = "; ".join(f"{nombre} {fmt(v)} ({p})" for (_, nombre, v), p in zip(items, pcts))
    if not aria:
        aria = f"Barra de progreso, total {fmt(base)}: {detalle}"
    svg = (f'<svg class="progreso-svg" viewBox="0 0 100 {_num(alto)}" preserveAspectRatio="none" '
           f'width="100%" height="100%" role="img" aria-label="{_e(aria)}">{"".join(cuerpo)}</svg>')
    clase_div = "progreso" if _num(alto) == "10" else f"progreso progreso-{_num(alto)}"
    filas = [(clave, nombre, fmt(v), f"({p})") for (clave, nombre, v), p in zip(items, pcts)]
    leyenda_html = _leyenda(filas) if leyenda else ""
    if leyenda and total is not None and base > suma:
        leyenda_html = leyenda_html.replace(
            "</ul>", f'<li class="leyenda-total">Total <b>{_e(fmt(base))}</b></li></ul>')
    return _figura("progreso", f'<div class="{clase_div}">{svg}</div>', leyenda_html)


def _clave_umbral(valor: float, umbrales: Any, maximo: float) -> str:
    """Clave de color según el primer umbral que supera al valor (valor < límite).

    Con ``[(4.0, "bajo"), (7.0, "medio"), (9.0, "alto"), (inf, "critico")]`` un
    CVSS 3.9 es «bajo», 4.0 es «medio» y 9.0 «crítico», como en NVD. Sin
    umbrales se usan cuartiles del máximo.
    """
    pares: list[tuple[float, str]] = []
    for u in umbrales or []:
        try:
            limite, clave = u[0], u[1]
        except (TypeError, IndexError, KeyError):
            continue
        try:
            lim = math.inf if limite is None else float(limite)
        except (TypeError, ValueError):
            lim = math.inf
        if lim != lim:
            lim = math.inf
        pares.append((lim, _clave(clave)))
    if not pares:
        pares = [(maximo * 0.25, "bajo"), (maximo * 0.5, "medio"),
                 (maximo * 0.75, "alto"), (math.inf, "critico")]
    pares.sort(key=lambda p: p[0])
    for lim, clave in pares:
        if valor < lim:
            return clave
    return pares[-1][1]


def medidor(valor: Any, maximo: Any, *, etiqueta: str = "", decimales: int = 1,
            umbrales: Any = None, tamano: float = 160, sufijo: str = "",
            aria: str = "") -> Markup:
    """Semicírculo (180°) con arco de fondo neutro y arco de valor coloreado.

    El color del arco lo deciden los ``umbrales`` ``[(límite, clave), …]``;
    por ejemplo ``[(4.0, "bajo"), (7.0, "medio"), (9.0, "alto"), (inf, "critico")]``
    para CVSS o ``[(10, "bajo"), (30, "medio"), (60, "alto"), (inf, "critico")]``
    con ``sufijo="%"`` para EPSS. ``valor`` None → «—» y solo el arco neutro.
    El valor se muestra grande y centrado con la etiqueta debajo.
    """
    maximo_f = _numero_o_none(maximo)
    if maximo_f is None or maximo_f <= 0:
        return VACIO
    tamano = _dim(tamano, 160)
    valor_f = _numero_o_none(valor)
    etiqueta = _texto(etiqueta).strip()
    sufijo = _texto(sufijo).strip()

    grosor = max(8.0, tamano * 0.11)
    c = tamano / 2
    r_ext = c - 4
    r_int = r_ext - grosor
    cy = r_ext + 4
    alto = cy + 26

    cuerpo = [f'<path class="serie-neutro medidor-fondo" d="{_sector(c, cy, r_ext, r_int, -90, 90)}"/>']
    if valor_f is not None:
        texto_valor = fmt(valor_f, decimales) + (f" {sufijo}" if sufijo else "")
        fraccion = min(valor_f, maximo_f) / maximo_f
        clave = _clave_umbral(valor_f, umbrales, maximo_f)
        if fraccion > 0:
            titulo = f"{etiqueta or 'Valor'}: {texto_valor} de {fmt(maximo_f)}"
            cuerpo.append(
                f'<path class="serie-{clave} medidor-valor" '
                f'd="{_sector(c, cy, r_ext, r_int, -90, -90 + 180 * fraccion)}">'
                f'{_titulo(titulo)}</path>')
        clase_texto = f"dona-centro medidor-texto texto-{clave}"
    else:
        texto_valor = "—"
        clase_texto = "dona-centro medidor-texto texto-neutro"

    cuerpo.append(f'<text class="{clase_texto}" x="{_num(c)}" y="{_num(cy - 4)}" '
                  f'text-anchor="middle">{_e(texto_valor)}</text>')
    if etiqueta:
        cuerpo.append(f'<text class="dona-centro-etiqueta" x="{_num(c)}" y="{_num(cy + 16)}" '
                      f'text-anchor="middle">{_e(etiqueta)}</text>')
    # Extremos de la escala (0 y máximo) solo si no chocan con la etiqueta.
    texto_max = f"{fmt(maximo_f)} {sufijo}".strip() if sufijo else fmt(maximo_f)
    if _ancho_texto(etiqueta) + 2 * _ancho_texto(texto_max) + 24 <= 2 * r_ext:
        x_izq = c - r_ext + grosor / 2
        x_der = c + r_ext - grosor / 2
        cuerpo.append(f'<text class="eje" x="{_num(x_izq)}" y="{_num(cy + 16)}" '
                      f'text-anchor="middle">0</text>')
        cuerpo.append(f'<text class="eje" x="{_num(x_der)}" y="{_num(cy + 16)}" '
                      f'text-anchor="middle">{_e(texto_max)}</text>')

    if not aria:
        aria = (f"Medidor {etiqueta}: {texto_valor} de {texto_max}" if valor_f is not None
                else f"Medidor {etiqueta}: sin dato").replace("Medidor :", "Medidor:")
    return _figura("medidor", _svg(tamano, alto, aria, "".join(cuerpo)))


_FLECHA_SVG = ('<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" focusable="false">'
               '<path d="M4 12h14M13 6l6 6-6 6" fill="none" stroke="currentColor" '
               'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>')


def flujo(pasos: Any, *, aria: str = "", compacto: bool = False) -> Markup:
    """Diagrama de proceso horizontal en HTML con flechas SVG entre pasos.

    ``pasos``: ``[{"titulo": "Recolección", "valor": "52 / 55", "nota": "fuentes
    operativas", "estado": "ok|atencion|critico|inactivo", "href": "/fuentes/"}]``.
    Cada paso es una tarjeta ``div.flujo-paso.<estado>`` con punto de estado,
    título (enlace si hay ``href`` local), valor y nota; entre pasos, una
    ``div.flujo-flecha``. Un estado desconocido pasa a ``inactivo``.
    ``compacto`` añade la clase ``compacto`` al contenedor (hitos de una ficha).
    """
    if isinstance(pasos, dict):
        pasos = [pasos]
    tarjetas = []
    for p in pasos or []:
        if not isinstance(p, dict):
            continue
        estado = _texto(p.get("estado")).strip().lower()
        if estado not in ESTADOS_FLUJO:
            estado = "inactivo"
        titulo = _texto(p.get("titulo")).strip() or "—"
        valor = p.get("valor")
        texto_valor = fmt(valor) if isinstance(valor, (int, float)) and not isinstance(valor, bool) \
            else _texto(valor).strip()
        nota = _texto(p.get("nota")).strip()
        href = _href_seguro(p.get("href"))
        titulo_html = f'<a href="{_e(href)}">{_e(titulo)}</a>' if href else _e(titulo)
        tarjeta = (f'<div class="flujo-paso {estado}">'
                   f'<div class="titulo"><span class="punto {estado}" title="{_e(ESTADOS_FLUJO[estado])}"></span>'
                   f'{titulo_html}</div>')
        if texto_valor:
            tarjeta += f'<div class="valor">{_e(texto_valor)}</div>'
        if nota:
            tarjeta += f'<div class="nota">{_e(nota)}</div>'
        tarjetas.append(tarjeta + "</div>")
    if not tarjetas:
        return VACIO
    if not aria:
        aria = f"Diagrama de proceso de {fmt(len(tarjetas))} pasos"
    flecha = f'<div class="flujo-flecha" aria-hidden="true">{_FLECHA_SVG}</div>'
    clase = "flujo compacto" if compacto else "flujo"
    return Markup(f'<div class="{clase}" role="group" aria-label="{_e(aria)}">'
                  + flecha.join(tarjetas) + "</div>")
