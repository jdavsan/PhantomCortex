"""Severidad y relevancia.

El sistema anterior devolvia constantes 9.0 / 7.5 / 5.0 segun palabras clave y
el informe las imprimia como "Puntuacion CVSS: 9.0/10.0" ante la direccion. Aqui
la severidad tiene siempre un ORIGEN declarado, y cuando no hay dato oficial el
campo `cvss_score` queda en None para que la interfaz y el informe escriban
"no disponible" en lugar de inventar un numero.

Precedencia: NVD > vector CVSS calculado > CISA KEV > heuristica.
"""
from __future__ import annotations

import math
import re
from typing import Any, Iterable, Optional

SEVERIDADES = ("Critical", "High", "Medium", "Low")
_ORDEN = {s: i for i, s in enumerate(SEVERIDADES)}

# --------------------------------------------------------------------------
# Utilidades de orden
# --------------------------------------------------------------------------
def orden_severidad(severidad: Optional[str]) -> int:
    """0 = Critical ... 3 = Low. Un valor desconocido se trata como el mas bajo."""
    return _ORDEN.get(str(severidad or "").capitalize(), len(SEVERIDADES))


def cumple_minimo(severidad: Optional[str], minimo: Optional[str]) -> bool:
    """True si `severidad` es igual o mas grave que `minimo`."""
    return orden_severidad(severidad) <= orden_severidad(minimo or "Low")


def de_cvss(score: Optional[float]) -> Optional[str]:
    """Convierte una puntuacion CVSS a severidad segun los cortes oficiales."""
    if score is None:
        return None
    try:
        valor = float(score)
    except (TypeError, ValueError):
        return None
    if valor >= 9.0:
        return "Critical"
    if valor >= 7.0:
        return "High"
    if valor >= 4.0:
        return "Medium"
    return "Low"


# --------------------------------------------------------------------------
# Vector CVSS 3.x
# --------------------------------------------------------------------------
_PESOS_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},          # sin cambio de alcance
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},         # con cambio de alcance
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _redondear_arriba(valor: float) -> float:
    """Redondeo al alza a un decimal, como exige la especificacion CVSS 3.1."""
    entero = int(round(valor * 100000))
    if entero % 10000 == 0:
        return entero / 100000.0
    return (math.floor(entero / 10000) + 1) / 10.0


def de_vector(vector: Optional[str]) -> tuple[Optional[float], Optional[str]]:
    """Calcula la puntuacion base a partir de un vector CVSS.

    Devuelve (puntuacion, version) o (None, None) si el vector no es utilizable.
    Implementa la formula de CVSS 3.0/3.1. Para vectores 4.0 no se calcula:
    la formula es sustancialmente distinta y preferimos declarar que no hay dato
    antes que publicar una aproximacion.
    """
    if not vector or not isinstance(vector, str):
        return None, None

    texto = vector.strip().upper()
    version = None
    if texto.startswith("CVSS:3.1/"):
        version, texto = "3.1", texto[len("CVSS:3.1/"):]
    elif texto.startswith("CVSS:3.0/"):
        version, texto = "3.0", texto[len("CVSS:3.0/"):]
    elif texto.startswith("CVSS:4.0/"):
        return None, "4.0"
    elif texto.startswith("CVSS:2.0/") or texto.startswith("AV:"):
        version = "2.0"
        if not texto.startswith("AV:"):
            texto = texto[len("CVSS:2.0/"):]
        if "/S:" not in texto and "/UI:" not in texto:
            return None, "2.0"          # v2 usa otra formula
    else:
        return None, None

    metricas: dict[str, str] = {}
    for parte in texto.split("/"):
        if ":" in parte:
            clave, _, valor = parte.partition(":")
            metricas[clave.strip()] = valor.strip()

    obligatorias = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(k in metricas for k in obligatorias):
        return None, version

    alcance_cambia = metricas["S"] == "C"
    try:
        av = _PESOS_V3["AV"][metricas["AV"]]
        ac = _PESOS_V3["AC"][metricas["AC"]]
        pr = _PESOS_V3["PR_C" if alcance_cambia else "PR"][metricas["PR"]]
        ui = _PESOS_V3["UI"][metricas["UI"]]
        conf = _PESOS_V3["CIA"][metricas["C"]]
        integ = _PESOS_V3["CIA"][metricas["I"]]
        disp = _PESOS_V3["CIA"][metricas["A"]]
    except KeyError:
        return None, version

    impacto_iss = 1 - ((1 - conf) * (1 - integ) * (1 - disp))
    if alcance_cambia:
        impacto = 7.52 * (impacto_iss - 0.029) - 3.25 * (impacto_iss - 0.02) ** 15
    else:
        impacto = 6.42 * impacto_iss

    if impacto <= 0:
        return 0.0, version

    explotabilidad = 8.22 * av * ac * pr * ui
    bruto = min((1.08 if alcance_cambia else 1.0) * (impacto + explotabilidad), 10.0)
    return _redondear_arriba(bruto), version


# --------------------------------------------------------------------------
# Heuristica: ultimo recurso
# --------------------------------------------------------------------------
# Palabras que indican una vulnerabilidad explotable. El sistema anterior
# marcaba Critical cualquier texto que contuviera 'ransomware', asi que un
# articulo periodistico sobre el fenomeno del ransomware acababa como critico.
# Aqui se exige que el texto hable de una vulnerabilidad concreta.
_SENAL_VULNERABILIDAD = re.compile(
    r"\b(vulnerabilit(?:y|ies)|vulnerabilidad(?:es)?|cve-\d{4}-\d+|flaw|fallo|"
    r"bug|advisory|aviso|security update|actualizaci[oó]n de seguridad|patch|"
    r"parche|exploit(?:ed|able)?|0-day|zero[- ]day|weakness|debilidad|"
    # Nombrar la clase tecnica tambien es hablar de una vulnerabilidad concreta
    r"rce|remote code execution|code execution|command injection|sql injection|"
    r"privilege escalation|elevation of privilege|authentication bypass|"
    r"buffer overflow|use[- ]after[- ]free|path traversal|directory traversal|"
    r"ssrf|xss|cross[- ]site scripting|csrf|deserializ\w*|"
    r"denial of service|out[- ]of[- ]bounds|integer overflow|type confusion|"
    r"ejecuci[oó]n de c[oó]digo|escalada de privilegios|desbordamiento)\b",
    re.IGNORECASE)

_CRITICO = (
    (re.compile(r"\bunauthenticated\s+(?:remote\s+)?(?:code\s+execution|rce)\b", re.I), 1.0),
    (re.compile(r"\bpre[- ]auth(?:enticated)?\s+(?:rce|code execution)\b", re.I), 1.0),
    (re.compile(r"\b(?:wormable|self[- ]propagating)\b", re.I), 1.0),
    (re.compile(r"\bactively\s+exploited\b|\bexplotad[ao]\s+activamente\b", re.I), 0.95),
    (re.compile(r"\bexploited\s+in\s+the\s+wild\b", re.I), 0.95),
    (re.compile(r"\bzero[- ]day\b|\b0-day\b", re.I), 0.9),
    (re.compile(r"\bcritical\b.{0,40}\b(?:rce|remote code execution)\b", re.I), 0.9),
    (re.compile(r"\b(?:remote code execution|rce)\b.{0,40}\bcritical\b", re.I), 0.9),
    (re.compile(r"\bauthentication\s+bypass\b|\bevasi[oó]n\s+de\s+autenticaci[oó]n\b", re.I), 0.85),
    (re.compile(r"\bcvss(?:\s*(?:v[34](?:\.\d)?)?)?[:\s]*(?:9|10)(?:\.\d)?\b", re.I), 0.95),
)

_ALTO = (
    (re.compile(r"\b(?:remote code execution|rce)\b", re.I), 0.85),
    (re.compile(r"\bprivilege\s+escalation\b|\bescalada\s+de\s+privilegios\b", re.I), 0.8),
    (re.compile(r"\belevation\s+of\s+privilege\b", re.I), 0.8),
    (re.compile(r"\bsql\s+injection\b|\binyecci[oó]n\s+sql\b", re.I), 0.8),
    (re.compile(r"\barbitrary\s+(?:code|command)\s+execution\b", re.I), 0.8),
    (re.compile(r"\bcommand\s+injection\b|\binyecci[oó]n\s+de\s+comandos\b", re.I), 0.8),
    (re.compile(r"\bdeserializ", re.I), 0.75),
    (re.compile(r"\bpath\s+traversal\b|\bdirectory\s+traversal\b", re.I), 0.7),
    (re.compile(r"\bssrf\b|\bserver[- ]side\s+request\s+forgery\b", re.I), 0.7),
    (re.compile(r"\bbuffer\s+overflow\b|\bdesbordamiento\s+de\s+b[uú]fer\b", re.I), 0.7),
    (re.compile(r"\buse[- ]after[- ]free\b", re.I), 0.7),
    (re.compile(r"\bsensitive\s+(?:data|information)\s+(?:disclosure|exposure)\b", re.I), 0.65),
    (re.compile(r"\bcvss(?:\s*(?:v[34](?:\.\d)?)?)?[:\s]*(?:7|8)(?:\.\d)?\b", re.I), 0.85),
)

_MEDIO = (
    (re.compile(r"\bcross[- ]site\s+scripting\b|\bxss\b", re.I), 0.7),
    (re.compile(r"\bcsrf\b|\bcross[- ]site\s+request\s+forgery\b", re.I), 0.65),
    (re.compile(r"\bdenial\s+of\s+service\b|\bdenegaci[oó]n\s+de\s+servicio\b", re.I), 0.65),
    (re.compile(r"\binformation\s+disclosure\b", re.I), 0.6),
    (re.compile(r"\bspoofing\b|\bsuplantaci[oó]n\b", re.I), 0.6),
    (re.compile(r"\bopen\s+redirect\b", re.I), 0.55),
    (re.compile(r"\brace\s+condition\b|\bcondici[oó]n\s+de\s+carrera\b", re.I), 0.55),
    (re.compile(r"\bmemory\s+leak\b|\bnull\s+pointer\b", re.I), 0.5),
)

# Textos que NO describen una vulnerabilidad concreta: noticias de sector,
# detenciones, informes de mercado. No deben elevar la severidad.
_NO_ES_VULNERABILIDAD = re.compile(
    r"\b(arrested|detenid\w*|sentenced|condenad\w*|indicted|lawsuit|demanda|"
    r"acquisition|adquisici[oó]n|funding round|ronda de financiaci\w*|"
    r"market\s+report|informe\s+de\s+mercado|"
    r"survey|encuesta|hiring|contrataci[oó]n|podcast)\b", re.IGNORECASE)

# Formatos que hablan DE seguridad pero no informan de una vulnerabilidad
# concreta. Es un veto absoluto: un webinar sobre zero-days no es un zero-day.
_NO_ES_AVISO = re.compile(
    r"\b(webinar|seminario|conference|congreso|summit|cumbre|keynote|"
    r"training|formaci[oó]n|curso|course|certification|certificaci[oó]n|"
    r"how\s+to\s+(?:defend|protect|prepare|secure)|"
    r"c[oó]mo\s+(?:defenderse|protegerse|prepararse)|"
    r"best\s+practices|buenas\s+pr[aá]cticas|guide\s+to|gu[ií]a\s+(?:de|para)|"
    r"top\s+\d+\s+(?:tips|ways|trends)|predictions|predicciones|"
    r"year\s+in\s+review|resumen\s+del\s+a[nñ]o|roundup|"
    r"interview|entrevista|opinion\s+piece|editorial|"
    r"sponsored|patrocinad\w*|whitepaper|e-?book)\b", re.IGNORECASE)


def heuristica(titulo: Optional[str], resumen: Optional[str] = None
               ) -> tuple[str, float]:
    """Estima la severidad por indicios textuales.

    Devuelve (severidad, confianza 0-1). NO devuelve puntuacion CVSS: cuando el
    origen es heuristico ese campo se queda vacio a proposito.

    Orden de decision:
      1. Veto de formato (webinar, guia, entrevista) -> Low, sin excepcion
      2. Veto de contenido no tecnico (detencion, informe de mercado) -> Low
      3. Requiere alguna senal de vulnerabilidad para poder escalar
      4. Patrones critico / alto / medio, exigiendo que lo critico este en el titulo
    """
    texto = " ".join(filter(None, (titulo, resumen)))
    if not texto.strip():
        return "Low", 0.1

    titulo_txt = titulo or ""

    # 1. Veto absoluto de formato: aunque mencione 'zero-day', no es un aviso
    if _NO_ES_AVISO.search(titulo_txt) or _NO_ES_AVISO.search(texto[:400]):
        return "Low", 0.5

    # 2. Contenido no tecnico, salvo que el titulo hable de una vulnerabilidad
    if _NO_ES_VULNERABILIDAD.search(texto) and not _SENAL_VULNERABILIDAD.search(titulo_txt):
        return "Low", 0.45

    # 3. Sin ninguna senal de vulnerabilidad no se escala por encima de Medium
    habla_de_vuln = bool(_SENAL_VULNERABILIDAD.search(texto))

    for grupo, severidad in ((_CRITICO, "Critical"), (_ALTO, "High"), (_MEDIO, "Medium")):
        for patron, confianza in grupo:
            if not patron.search(texto):
                continue
            if not habla_de_vuln:
                return "Medium", round(confianza * 0.5, 2)
            if severidad == "Critical" and not patron.search(titulo_txt):
                # El indicio critico solo aparece en el cuerpo: se rebaja un nivel
                return "High", round(confianza * 0.8, 2)
            return severidad, confianza

    return ("Medium", 0.4) if habla_de_vuln else ("Low", 0.3)


# --------------------------------------------------------------------------
# Decision final
# --------------------------------------------------------------------------
def decidir(*, nvd_score: Optional[float] = None,
            nvd_severity: Optional[str] = None,
            vector: Optional[str] = None,
            in_kev: bool = False,
            epss: Optional[float] = None,
            titulo: str = "", resumen: str = "") -> dict[str, Any]:
    """Resuelve severidad y origen aplicando la precedencia del sistema.

    Devuelve un dict con severity, severity_source, cvss_score, cvss_vector,
    cvss_version y confianza.
    """
    resultado: dict[str, Any] = {
        "severity": None, "severity_source": None, "cvss_score": None,
        "cvss_vector": vector or None, "cvss_version": None, "confianza": 0.0,
    }

    # 1. Puntuacion oficial de NVD
    if nvd_score is not None:
        try:
            score = float(nvd_score)
        except (TypeError, ValueError):
            score = None
        if score is not None and 0.0 <= score <= 10.0:
            resultado.update(
                severity=de_cvss(score) or (nvd_severity or "Medium").capitalize(),
                severity_source="nvd", cvss_score=score, confianza=1.0)
            _, version = de_vector(vector)
            resultado["cvss_version"] = version

    # 2. Vector CVSS: se calcula la puntuacion base
    if resultado["severity"] is None and vector:
        score, version = de_vector(vector)
        resultado["cvss_version"] = version
        if score is not None:
            resultado.update(severity=de_cvss(score), severity_source="vector",
                             cvss_score=score, confianza=0.9)

    # 3. Severidad textual de NVD sin puntuacion
    if resultado["severity"] is None and nvd_severity:
        candidata = str(nvd_severity).capitalize()
        if candidata in SEVERIDADES:
            resultado.update(severity=candidata, severity_source="nvd",
                             confianza=0.8)

    # 4. Heuristica
    if resultado["severity"] is None:
        severidad, confianza = heuristica(titulo, resumen)
        resultado.update(severity=severidad, severity_source="heuristic",
                         confianza=confianza)

    # 5. KEV eleva el suelo: explotacion confirmada en la practica
    if in_kev and orden_severidad(resultado["severity"]) > orden_severidad("High"):
        resultado["severity"] = "High"
        if resultado["severity_source"] == "heuristic":
            resultado["severity_source"] = "kev"
        resultado["confianza"] = max(resultado["confianza"], 0.9)

    # 6. EPSS muy alto con severidad baja: probablemente se ha subestimado
    if (epss is not None and epss >= 0.5
            and orden_severidad(resultado["severity"]) > orden_severidad("High")
            and resultado["severity_source"] == "heuristic"):
        resultado["severity"] = "High"
        resultado["severity_source"] = "kev" if in_kev else "heuristic"

    return resultado


# --------------------------------------------------------------------------
# Relevancia para la organizacion
# --------------------------------------------------------------------------
_PESO_CRITICIDAD = {"critical": 1.0, "high": 0.8, "medium": 0.55, "low": 0.3}
_PESO_EXPOSICION = {"internet": 1.0, "dmz": 0.75, "interna": 0.5}
_PESO_SEVERIDAD = {"Critical": 40.0, "High": 28.0, "Medium": 14.0, "Low": 5.0}


def relevancia(*, severity: Optional[str], cvss_score: Optional[float] = None,
               epss: Optional[float] = None, in_kev: bool = False,
               tecnologias: Optional[Iterable[dict]] = None,
               min_confianza: float = 0.0,
               ignorar_criticidad_baja: bool = False,
               activos: Optional[dict] = None,
               cvss_vector: Optional[str] = None) -> float:
    """Puntuacion 0-100 de lo que esta amenaza importa A ESTA organizacion.

    Prioridad = gravedad tecnica (CVSS) + explotacion confirmada (KEV) + probabilidad
    (EPSS) + exposicion (tecnologias del inventario y activos reales, con mas peso los de
    produccion y contingencia) + facilidad de explotacion (vector CVSS) + parche
    disponible. ``desglose_relevancia`` devuelve cada componente para explicarlo.

    ``activos`` (opcional) trae el resultado de la aplicabilidad por activo
    ({"afectados": n, "no_afectados": m, "sin_dato": k, "afectados_expuestos": e,
    "parche_disponible": 0/1}): un activo con la version vulnerable confirmada pesa
    mas que cualquier coincidencia de texto, y si todos los activos evaluados ya
    llevan la correccion la relevancia se hunde.

    La severidad tecnica dice lo grave que es en abstracto; esto la combina con
    la exposicion real: criticidad de lo afectado, si esta en internet, cuantos
    sistemas hay y si la version instalada es vulnerable. Es el criterio que
    ordena las alertas, para que lo primero que se lea sea lo que de verdad
    afecta.
    """
    # --- componente tecnica (0-55) ---
    base = _PESO_SEVERIDAD.get(str(severity or "").capitalize(), 10.0)
    if cvss_score is not None:
        try:
            base = max(base, float(cvss_score) * 4.0)
        except (TypeError, ValueError):
            pass
    puntos = min(base, 40.0)

    if in_kev:
        puntos += 15.0            # explotacion confirmada
    if epss is not None:
        try:
            puntos += min(float(epss), 1.0) * 10.0
        except (TypeError, ValueError):
            pass

    # --- componente de exposicion organizativa (0-35) ---
    # Una coincidencia debil (la palabra 'windows' en una noticia de malware,
    # confianza 0,4) no demuestra exposicion: por debajo de min_confianza se
    # trata como simple mencion y no suma. Sin dato de confianza se asume 1.
    # Con ignorar_criticidad_baja, una tecnologia de criticidad baja tampoco
    # demuestra exposicion que importe: se trata como mencion.
    tecs = [t for t in (tecnologias or []) if t
            and float(t.get("confidence") if t.get("confidence") is not None else 1.0) >= float(min_confianza or 0.0)
            and not (ignorar_criticidad_baja and str(t.get("criticality") or "").lower() == "low")]
    if not tecs:
        # Sin correlacion no se puede afirmar exposicion: se deja la tecnica
        # (salvo que la aplicabilidad por activo diga otra cosa)
        puntos = _ajustar_por_activos(puntos, activos)
        puntos += _facilidad_explotacion(cvss_vector)[0] + _parche_disponible(activos)[0]
        return round(max(0.0, min(puntos, 100.0)), 1)

    mejor = 0.0
    hay_afectada = False
    hay_no_afectada = False
    sistemas_total = 0

    for t in tecs:
        criticidad = _PESO_CRITICIDAD.get(str(t.get("criticality") or "medium").lower(), 0.55)
        exposicion = _PESO_EXPOSICION.get(str(t.get("exposure") or "interna").lower(), 0.5)
        veredicto = str(t.get("version_verdict") or "unknown").lower()

        factor = criticidad * exposicion
        if veredicto == "affected":
            factor *= 1.0
            hay_afectada = True
        elif veredicto == "not_affected":
            factor *= 0.15
            hay_no_afectada = True
        else:
            factor *= 0.7          # sin determinar: prudencia, no se descarta

        try:
            sistemas_total += int(t.get("systems_count") or 0)
        except (TypeError, ValueError):
            pass

        mejor = max(mejor, factor)

    puntos += mejor * 30.0

    # Volumen de sistemas: aporta poco, con techo bajo, para no dominar
    if sistemas_total > 0:
        puntos += min(math.log10(sistemas_total + 1) * 3.0, 6.0)

    # Si TODAS las tecnologias estan confirmadas como no afectadas, hundir
    if hay_no_afectada and not hay_afectada and all(
            str(t.get("version_verdict") or "").lower() == "not_affected" for t in tecs):
        puntos *= 0.25

    puntos = _ajustar_por_activos(puntos, activos)
    puntos += _facilidad_explotacion(cvss_vector)[0]
    puntos += _parche_disponible(activos)[0]
    return round(max(0.0, min(puntos, 100.0)), 1)


def _ajustar_por_activos(puntos: float, activos: Optional[dict]) -> float:
    """Aplicabilidad real (OCS): activos con la version vulnerable en produccion o
    contingencia suman 12 puntos por el primero y hasta 28 en escala logaritmica;
    si solo hay afectados en desarrollo, pruebas o soporte, 6 y hasta 14. Si se
    evaluaron activos y todos estan corregidos, la puntuacion se reduce a un tercio.
    Sin dato no cambia nada."""
    ajuste, _ = _puntos_activos(activos)
    if ajuste is None:
        return puntos
    if ajuste == "corregidos":
        return puntos * 0.35
    return puntos + ajuste


def _puntos_activos(activos: Optional[dict]):
    """(puntos | 'corregidos' | None, explicacion)."""
    if not activos:
        return None, "sin evaluar contra los activos"
    try:
        afectados = int(activos.get("afectados") or 0)
        no_afectados = int(activos.get("no_afectados") or 0)
        sin_dato = int(activos.get("sin_dato") or 0)
        expuestos = int(activos.get("afectados_expuestos") or 0)
    except (TypeError, ValueError, AttributeError):
        return None, "sin evaluar contra los activos"
    if expuestos > 0:
        return (min(12.0 + math.log10(expuestos) * 8.0, 28.0),
                f"{expuestos} activo{'s' if expuestos != 1 else ''} de producción o contingencia con la versión vulnerable")
    if afectados > 0:
        return (min(6.0 + math.log10(afectados) * 4.0, 14.0),
                f"{afectados} activo{'s' if afectados != 1 else ''} con la versión vulnerable, ninguno en producción ni contingencia")
    if no_afectados > 0 and sin_dato == 0:
        return "corregidos", f"todos los activos evaluados ({no_afectados}) ya llevan la corrección: se reduce a un tercio"
    return None, "ningún activo evaluado con la versión vulnerable ni corregida"


def _metricas_vector(vector: Optional[str]) -> dict[str, str]:
    if not vector or not isinstance(vector, str):
        return {}
    texto = vector.strip().upper()
    if texto.startswith("CVSS:"):
        texto = texto.split("/", 1)[1] if "/" in texto else ""
    salida: dict[str, str] = {}
    for parte in texto.split("/"):
        if ":" in parte:
            k, _, v = parte.partition(":")
            salida[k.strip()] = v.strip()
    return salida


def _facilidad_explotacion(vector: Optional[str]) -> tuple[float, str]:
    """Hasta 5 puntos segun el vector CVSS: alcanzable por red (+2), complejidad
    baja (+1), sin privilegios (+1) y sin interaccion del usuario (+1)."""
    m = _metricas_vector(vector)
    if not m or "AV" not in m:
        return 0.0, "sin vector CVSS: no se valora la facilidad de explotación"
    puntos = 0.0
    partes = []
    if m.get("AV") == "N":
        puntos += 2.0
        partes.append("alcanzable por red")
    if m.get("AC") == "L":
        puntos += 1.0
        partes.append("complejidad baja")
    if m.get("PR", m.get("AU")) == "N":
        puntos += 1.0
        partes.append("sin privilegios")
    if m.get("UI", "N") == "N":
        puntos += 1.0
        partes.append("sin interacción del usuario")
    return puntos, (", ".join(partes) if partes else "explotación poco accesible según el vector")


def _parche_disponible(activos: Optional[dict]) -> tuple[float, str]:
    """+2 si ya existe una version corregida para los activos afectados: se puede actuar hoy."""
    if activos and activos.get("parche_disponible") and int(activos.get("afectados") or 0) > 0:
        return 2.0, "hay versión corregida publicada: se puede remediar ya"
    return 0.0, "sin dato de parche para los activos afectados"


def desglose_relevancia(*, severity: Optional[str], cvss_score: Optional[float] = None,
                        epss: Optional[float] = None, in_kev: bool = False,
                        tecnologias: Optional[Iterable[dict]] = None, min_confianza: float = 0.0,
                        ignorar_criticidad_baja: bool = False, activos: Optional[dict] = None,
                        cvss_vector: Optional[str] = None) -> list[dict]:
    """Componentes de la prioridad, en el mismo orden en que se aplican, para
    mostrarlos en la ficha: [{"nombre", "puntos", "detalle"}]."""
    filas: list[dict] = []
    base = _PESO_SEVERIDAD.get(str(severity or "").capitalize(), 10.0)
    if cvss_score is not None:
        try:
            base = max(base, float(cvss_score) * 4.0)
        except (TypeError, ValueError):
            pass
    filas.append({"nombre": "Gravedad técnica (CVSS)", "puntos": round(min(base, 40.0), 1),
                  "detalle": (f"CVSS {float(cvss_score):.1f} × 4" if cvss_score is not None
                              else f"severidad {severity or 'sin dato'} sin puntuación oficial")})
    filas.append({"nombre": "Explotación confirmada (KEV)", "puntos": 15.0 if in_kev else 0.0,
                  "detalle": "en el catálogo KEV de CISA" if in_kev else "no consta en KEV"})
    try:
        e = min(float(epss), 1.0) * 10.0 if epss is not None else 0.0
    except (TypeError, ValueError):
        e = 0.0
    filas.append({"nombre": "Probabilidad de explotación (EPSS)", "puntos": round(e, 1),
                  "detalle": (f"EPSS {float(epss) * 100:.1f} %" if epss is not None else "sin dato de EPSS")})
    tecs = [t for t in (tecnologias or []) if t
            and float(t.get("confidence") if t.get("confidence") is not None else 1.0) >= float(min_confianza or 0.0)
            and not (ignorar_criticidad_baja and str(t.get("criticality") or "").lower() == "low")]
    if tecs:
        mejor = 0.0
        sistemas = 0
        for t in tecs:
            factor = (_PESO_CRITICIDAD.get(str(t.get("criticality") or "medium").lower(), 0.55)
                      * _PESO_EXPOSICION.get(str(t.get("exposure") or "interna").lower(), 0.5))
            v = str(t.get("version_verdict") or "unknown").lower()
            factor *= 1.0 if v == "affected" else (0.15 if v == "not_affected" else 0.7)
            mejor = max(mejor, factor)
            try:
                sistemas += int(t.get("systems_count") or 0)
            except (TypeError, ValueError):
                pass
        volumen = min(math.log10(sistemas + 1) * 3.0, 6.0) if sistemas > 0 else 0.0
        filas.append({"nombre": "Exposición por tecnologías del inventario", "puntos": round(mejor * 30.0 + volumen, 1),
                      "detalle": f"{len(tecs)} tecnología{'s' if len(tecs) != 1 else ''} (criticidad, exposición y veredicto de versión)"
                                 + (f"; {sistemas} sistemas" if sistemas else "")})
    else:
        filas.append({"nombre": "Exposición por tecnologías del inventario", "puntos": 0.0,
                      "detalle": "sin correlación con el inventario"})
    puntos_act, detalle_act = _puntos_activos(activos)
    if puntos_act == "corregidos":
        filas.append({"nombre": "Activos reales (OCS Inventory)", "puntos": "×0,35", "detalle": detalle_act})
    else:
        filas.append({"nombre": "Activos reales (OCS Inventory)", "puntos": round(puntos_act or 0.0, 1), "detalle": detalle_act})
    f, d = _facilidad_explotacion(cvss_vector)
    filas.append({"nombre": "Facilidad de explotación", "puntos": f, "detalle": d})
    f, d = _parche_disponible(activos)
    filas.append({"nombre": "Parche disponible", "puntos": f, "detalle": d})
    return filas
