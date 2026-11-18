"""Cifras del apartado Amenazas: cuántas hay y qué cuenta cada número (2026-09-07).

El usuario pidió «cifras o gráficas en el apartado de amenazas, cuántas amenazas en total,
si son amenazas por activo o en total o cómo se determina este número, además saber y poder
ver cantidad de amenazas por servidores y por equipos de cómputo, filtrando por proceso».

Hay tres magnitudes y confundirlas lleva a conclusiones falsas, así que la prueba fija la
semántica de cada una sobre un inventario sembrado a mano:

* REGISTRADAS: filas de `threats`. El catálogo de avisos, incluidos los que no afectan a
  ninguna máquina nuestra. No depende del parque, así que el filtro por proceso NO la cambia.
* CONFIRMADAS: de esas, las confirmadas en al menos un activo.
* VULNERABILIDADES: un CVE en un activo (desde el 2026-09-09; antes eran filas de
  `aplicabilidad`, una por paquete, y un CVE del núcleo se contaba cinco veces en el mismo
  servidor). El mismo CVE en cien activos son cien vulnerabilidades y una sola amenaza; el
  mismo CVE en dos paquetes del mismo activo es UNA vulnerabilidad.

Ampliado el 2026-09-08 con la claridad de la redacción, que el usuario reclamó aparte:
«las amenazas no son claras: en servidores dice 30.827 pero no dice qué son, después dice
485 equipos, pero luego no son servidores», «en la tabla de tipo de equipo necesito una fila
de total», «si son servidores que diga servidores y no equipos» y «en activos me dice que hay
511 servidores y 325 equipos, pero en amenazas veo cifras diferentes». Las pruebas nuevas
fijan, además de la semántica, cómo se escriben las cifras:

* la palabra «equipos» no vale como unidad de máquinas: o «servidores», o «equipos de
  cómputo», o «activos» cuando la cifra mezcla los dos tipos;
* cada cifra de máquinas lleva su denominador («485 de 511 servidores»), y el denominador
  se lee del mismo sitio que la página de Activos y con el mismo recorte que el numerador;
* la tabla por tipo de activo lleva fila de total, con la suma de vulnerabilidades y de
  activos afectados, y las amenazas distintas NO presentadas como suma.
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db, queries
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth, graficos  # noqa: E402

CLAVE = "ClaveSegura#2026"


def _activo(conn, ocs_id, nombre, origen, proceso, entorno="produccion"):
    conn.execute(
        """INSERT INTO activos(ocs_id, nombre, origen, so_familia, presente, proceso,
                               entorno, primera_vez_at, visto_at)
           VALUES(?,?,?,'debian',1,?,?,?,?)""",
        (ocs_id, nombre, origen, proceso, entorno, db.utcnow(), db.utcnow()))
    return conn.execute("SELECT id FROM activos WHERE nombre=?", (nombre,)).fetchone()[0]


def _amenaza(conn, fp, cve, severidad="High", kev=0):
    conn.execute(
        """INSERT INTO threats(fingerprint, cve, title_en, severity, severity_source,
                               first_seen_at, last_seen_at, month, relevance, estado, in_kev)
           VALUES(?,?,?,?,'nvd',?,?,?,60.0,'nueva',?)""",
        (fp, cve, f"Aviso {cve}", severidad, db.utcnow(), db.utcnow(), db.utcnow()[:7], kev))
    return conn.execute("SELECT id FROM threats WHERE fingerprint=?", (fp,)).fetchone()[0]


class TestResumenAmenazas(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "cifras.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            srv1 = _activo(conn, 1, "srv-pila-01", "servidores", "Pila")
            srv2 = _activo(conn, 2, "srv-pila-02", "servidores", "Pila")
            srv3 = _activo(conn, 3, "srv-sin-tag", "servidores", None)
            pc1 = _activo(conn, 4, "pc-ana", "equipos", None)
            # Tres amenazas en el catálogo; solo dos se confirman en algún activo.
            t1 = _amenaza(conn, "fp-1", "CVE-2026-0001", "Critical", kev=1)
            t2 = _amenaza(conn, "fp-2", "CVE-2026-0002", "High")
            _amenaza(conn, "fp-3", "CVE-2026-0003", "Medium")   # no afecta a nadie
            # t1 en los tres servidores y en el equipo: 4 vulnerabilidades, 1 amenaza
            for aid in (srv1, srv2, srv3, pc1):
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor, evaluado_at)
                       VALUES(?,?,'CVE-2026-0001','openssl','1.0','1.2','afectado','osv',?)""",
                    (aid, t1, db.utcnow()))
            # t2 solo en srv-pila-01, con dos paquetes: UNA vulnerabilidad (un CVE en un
            # activo), 1 amenaza y dos filas de paquete
            for paquete in ("curl", "libcurl4"):
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor, evaluado_at)
                       VALUES(?,?,'CVE-2026-0002',?,'7.8','7.9','afectado','osv',?)""",
                    (srv1, t2, paquete, db.utcnow()))
            # una fila «no afectado» no debe contar en ninguna cifra
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES(?,?,'CVE-2026-0002','git','9.9','7.9','no_afectado','osv',?)""",
                (srv2, t2, db.utcnow()))
        cls.conn = db.connect(cls.ruta)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    # ------------------------------------------------------------- semántica
    def test_las_tres_magnitudes_son_distintas_y_correctas(self):
        r = queries.resumen_amenazas(self.conn)
        self.assertEqual(r["registradas"], 3, "el catálogo son las tres amenazas")
        self.assertEqual(r["confirmadas"], 2, "solo dos se confirman en algún activo")
        self.assertEqual(r["sin_confirmar"], 1)
        self.assertEqual(r["vulnerabilidades"], 5,
                         "4 de la primera + 1 de la segunda: sus dos paquetes son el mismo CVE "
                         "en el mismo activo y cuentan una sola vez")
        self.assertEqual(r["activos_afectados"], 4)
        self.assertEqual(r["cve_confirmados"], 2)

    def test_un_veredicto_de_no_afectado_no_cuenta(self):
        r = queries.resumen_amenazas(self.conn)
        self.assertEqual(r["vulnerabilidades"], 5,
                         "la fila «no_afectado» no es una vulnerabilidad")

    def test_una_amenaza_cerrada_deja_de_contar(self):
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE threats SET estado='descartada' WHERE cve='CVE-2026-0002'")
        try:
            r = queries.resumen_amenazas(self.conn)
            self.assertEqual(r["confirmadas"], 1)
            self.assertEqual(r["vulnerabilidades"], 4, "la de curl deja de contar")
            self.assertEqual(r["registradas"], 2, "y sale del catálogo abierto")
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE threats SET estado='nueva' WHERE cve='CVE-2026-0002'")

    # ------------------------------------------------- reparto y filtros
    def test_reparto_por_tipo_de_activo(self):
        r = queries.resumen_amenazas(self.conn)
        por_origen = {o["origen"]: o for o in r["por_origen"]}
        self.assertEqual(por_origen["servidores"]["vulnerabilidades"], 4)
        self.assertEqual(por_origen["servidores"]["activos"], 3)
        self.assertEqual(por_origen["equipos"]["vulnerabilidades"], 1)
        self.assertEqual(por_origen["equipos"]["origen_es"], "Equipos de cómputo")

    def test_reparto_por_proceso_y_grupos_de_los_que_no_tienen(self):
        r = queries.resumen_amenazas(self.conn)
        grupos = {p["proceso"]: p for p in r["por_proceso"]}
        self.assertEqual(grupos["Pila"]["vulnerabilidades"], 3)   # 2 de t1 + 1 de t2 (dos paquetes)
        self.assertEqual(grupos[queries.GRUPO_SERVIDORES_SIN_PROCESO]["vulnerabilidades"], 1)
        self.assertEqual(grupos[queries.GRUPO_EQUIPOS_SIN_PROCESO]["vulnerabilidades"], 1)
        self.assertIn("Mantenimiento", queries.GRUPO_EQUIPOS_SIN_PROCESO)

    def test_el_filtro_por_proceso_acota_el_parque_pero_no_el_catalogo(self):
        """Lo que el usuario necesitaba entender: el catálogo no depende de los equipos."""
        r = queries.resumen_amenazas(self.conn, proceso="Pila")
        self.assertEqual(r["registradas"], 3, "el catálogo no se filtra por proceso")
        self.assertEqual(r["vulnerabilidades"], 3)
        self.assertEqual(r["activos_afectados"], 2)
        self.assertEqual(r["confirmadas"], 2)

    def test_el_filtro_por_tipo_de_equipo(self):
        r = queries.resumen_amenazas(self.conn, origen="equipos")
        self.assertEqual(r["vulnerabilidades"], 1)
        self.assertEqual(r["activos_afectados"], 1)
        r = queries.resumen_amenazas(self.conn, origen="servidores")
        self.assertEqual(r["vulnerabilidades"], 4)

    def test_el_selector_ofrece_los_grupos_con_vulnerabilidades(self):
        procesos = queries.procesos_del_parque(self.conn)
        self.assertIn("Pila", procesos)
        self.assertIn(queries.GRUPO_EQUIPOS_SIN_PROCESO, procesos)
        self.assertIn(queries.GRUPO_SERVIDORES_SIN_PROCESO, procesos)

    # ------------------------------------------------------------- la página
    def _html(self, url: str) -> str:
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        respuesta = cli.get(url)
        self.assertEqual(respuesta.status_code, 200, url)
        html = respuesta.get_data(as_text=True)
        self.assertIsNone(re.search(r"\sstyle\s*=", html), f"style= en {url}")
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", html), f"on*= en {url}")
        return html

    def test_la_pagina_muestra_las_cifras_y_dice_que_cuenta_cada_una(self):
        """Los rótulos cambiaron el 2026-09-08: «Equipos afectados» decía «equipos» de una
        cifra que suma servidores y equipos de cómputo, y el usuario lo leyó como equipos de
        cómputo; ahora es «Activos afectados de N presentes», con la unidad y el denominador.
        «Confirmadas en algún activo» pasó a «Amenazas confirmadas en algún activo» para que
        el rótulo diga de qué es la cifra sin depender del panel de al lado."""
        html = self._html("/amenazas/")
        for texto in ("Cuántas amenazas hay", "Amenazas registradas",
                      "Amenazas confirmadas en algún activo",
                      "Vulnerabilidades confirmadas",
                      "Activos afectados de",
                      "Todos los avisos recolectados",
                      "un CVE en un activo",
                      "cuenta una sola vez",
                      "cien vulnerabilidades y una sola amenaza"):
            self.assertIn(texto, html, texto)
        self.assertNotIn("Equipos afectados", html,
                         "«Equipos afectados» era ambiguo: la cifra suma los dos tipos")

    def test_la_pagina_reparte_por_tipo_de_activo_y_por_proceso(self):
        """Los dos títulos cambiaron el 2026-09-08 a petición del usuario: «tipo de equipo»
        no dice si la fila es de servidores o de equipos de cómputo, y del gráfico de procesos
        pidió literalmente «solo necesito que diga vulnerabilidades por proceso»."""
        html = self._html("/amenazas/")
        self.assertIn("Vulnerabilidades por tipo de activo", html)
        self.assertIn("Vulnerabilidades por proceso", html)
        self.assertNotIn("Vulnerabilidades por proceso de negocio", html)
        self.assertNotIn("Vulnerabilidades por tipo de equipo", html)
        self.assertIn("Equipos de cómputo", html)
        self.assertIn("Servidores", html)

    def test_el_selector_de_proceso_filtra_de_verdad(self):
        completo = self._html("/amenazas/")
        filtrado = self._html("/amenazas/?proceso=Pila")
        def cifras(h):
            return re.findall(r'class="valor fs-22-b">([\d.]+)<', h)
        self.assertNotEqual(cifras(completo), cifras(filtrado))
        # el catálogo no cambia; las vulnerabilidades sí
        self.assertEqual(cifras(completo)[0], cifras(filtrado)[0])
        self.assertNotEqual(cifras(completo)[2], cifras(filtrado)[2])

    def test_un_proceso_inventado_no_rompe_la_pagina(self):
        html = self._html("/amenazas/?proceso=NoExiste&origen=inventado")
        self.assertIn("Cuántas amenazas hay", html)

    # ------------------------------------------- claridad de la redacción (2026-09-08)
    def _bloque(self, url: str = "/amenazas/") -> str:
        """El HTML del bloque «Cuántas amenazas hay», que es el que el usuario criticó."""
        html = self._html(url)
        return html[html.index('id="cuantas-amenazas"'):html.index('id="resultados"')]

    @staticmethod
    def _visible(html: str) -> str:
        """Texto que ve el lector: sin etiquetas, con los espacios normalizados.

        Se quitan las etiquetas para no analizar los enlaces: «?origen=equipos» es una
        clave de la base de datos en una URL, no una palabra que nadie lea.
        """
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))

    @staticmethod
    def _atributos(html: str) -> str:
        """Los textos de atributos que también lee el usuario (rótulos, ayudas, lector de
        pantalla y recorrido guiado)."""
        return " ".join(re.findall(
            r'(?:title|aria-label|data-tour-texto|data-tour-titulo)="([^"]*)"', html))

    def test_la_palabra_equipos_nunca_es_la_unidad_de_las_maquinas(self):
        """La queja de fondo del 2026-09-08: en la fila «Servidores» se leía «485 equipos»
        y el usuario lo entendió como equipos de cómputo. Cada tipo por su nombre.
        """
        bloque = self._bloque()
        for texto in (self._visible(bloque), self._atributos(bloque)):
            sueltas = re.findall(r"\b[Ee]quipos?\b(?!\s+de\s+cómputo)", texto)
            self.assertEqual(sueltas, [], f"«equipos» a secas en: {texto[:400]}")
        # Y en la página ENTERA, glosario incluido. La exclusión que había aquí hasta el
        # 2026-09-08 dejaba fuera «Cómo leer estos datos», y allí seguía habiendo tres
        # frases con la palabra prohibida («un equipo de usuario real», «¿le aplica este
        # CVE a este equipo?», «los equipos con la versión vulnerable»): la página que
        # define los términos daba un tercer nombre a lo que el bloque de arriba llama
        # «equipos de cómputo». Corregidas las tres, el barrido ya no se recorta.
        # Solo el PLURAL en el barrido de la página entera: «equipos» es el que se usa
        # como unidad de un recuento y el que resultó ambiguo. El singular «equipo»
        # aparece también con su otro significado (el equipo humano: «el equipo de
        # seguridad de la información»), que no tiene nada que ver y es correcto.
        pagina = self._html("/amenazas/")
        for texto in (self._visible(pagina), self._atributos(pagina)):
            self.assertEqual(re.findall(r"\b[Ee]quipos\b(?!\s+de\s+cómputo)", texto), [],
                             f"«equipos» a secas en: {texto[:400]}")

    def test_la_fila_y_la_barra_de_servidores_dicen_servidores(self):
        bloque = self._bloque()
        texto = self._visible(bloque)
        self.assertIn("3 de 3 servidores afectados", texto,
                      "la barra de servidores dice servidores, con su denominador")
        self.assertIn("1 de 1 equipo de cómputo afectado", texto,
                      "y la de equipos de cómputo, equipos de cómputo, en singular si es uno")

    def test_cada_cifra_del_bloque_lleva_su_unidad_y_su_denominador(self):
        texto = self._visible(self._bloque())
        self.assertIn("Amenazas registradas", texto)
        self.assertIn("Unidad: amenazas", texto)
        self.assertIn("Vulnerabilidades confirmadas", texto)
        self.assertIn("Activos afectados de 4 presentes", texto)
        self.assertIn("4 activos con inventario presente", texto)
        self.assertIn("3 servidores y 1 equipo de cómputo", texto)
        self.assertIn("3 de 3 servidores y 1 de 1 equipo de cómputo", texto)

    def test_el_bloque_dice_de_donde_salen_los_totales_y_enlaza_a_activos(self):
        """El usuario dijo que las cifras «no concuerdan» con Activos: hay que poder cotejarlo."""
        bloque = self._bloque()
        self.assertIn("página de Activos", self._visible(bloque))
        self.assertIn('href="/activos/"', bloque)

    def test_hay_fila_de_total_marcada_como_total(self):
        """«En la tabla de tipo de equipo necesito una fila de total» (2026-09-08)."""
        bloque = self._bloque()
        self.assertIn("<tfoot>", bloque, "el total va en tfoot, no como una fila más")
        pie = bloque[bloque.index("<tfoot>"):bloque.index("</tfoot>")]
        self.assertIn("Total", self._visible(pie))
        self.assertIn("servidores y equipos de cómputo", self._visible(pie))

    def test_el_total_suma_vulnerabilidades_y_activos_pero_no_amenazas(self):
        """La suma que no se puede hacer: la misma amenaza está en los dos tipos de máquina.

        Aquí la primera amenaza afecta a los tres servidores y al equipo de cómputo, así que
        sumar las amenazas distintas de las dos filas daría 3 donde solo hay 2.
        """
        r = queries.resumen_amenazas(self.conn)
        bloque = self._bloque()
        pie = self._visible(bloque[bloque.index("<tfoot>"):bloque.index("</tfoot>")])
        suma_vulnerabilidades = sum(int(o["vulnerabilidades"]) for o in r["por_origen"])
        suma_activos = sum(int(o["activos"]) for o in r["por_origen"])
        suma_amenazas = sum(int(o["amenazas"]) for o in r["por_origen"])
        self.assertEqual(suma_vulnerabilidades, r["vulnerabilidades"])
        self.assertEqual(suma_activos, r["activos_afectados"])
        self.assertIn(str(suma_vulnerabilidades), pie)
        self.assertIn(f"{suma_activos} de 4 activos", pie)
        self.assertIn(str(r["confirmadas"]), pie, "el total de amenazas es el del resumen")
        self.assertIn("no es la suma de las filas", pie)
        self.assertNotEqual(suma_amenazas, r["confirmadas"])
        self.assertIn(f"sumar las filas daría {suma_amenazas} amenazas",
                      self._visible(bloque),
                      "se explica por qué el total no es la suma, con las dos cifras")

    def test_los_denominadores_son_los_mismos_que_los_de_la_pagina_de_activos(self):
        """511 servidores y 325 equipos de cómputo en producción: el mismo dato, no otro cálculo."""
        from threatintel import ocs
        from webui.vistas.amenazas import _parque_presente

        parque = _parque_presente(self.conn)
        # La vista usa cifras["presentes"], que lo calcula dentro de resumen_amenazas para
        # que el numerador y el denominador no puedan divergir. Las dos cuentan lo mismo.
        presentes = queries.resumen_amenazas(self.conn)["presentes"]
        self.assertEqual(parque, {c: presentes[c] for c in parque})
        resumen_activos = ocs.resumen(self.conn)
        self.assertEqual(parque["servidores"], int(resumen_activos["servidores"]))
        self.assertEqual(parque["equipos"], int(resumen_activos["equipos"]))
        self.assertEqual(parque["total"], int(resumen_activos["total"]))
        texto = self._visible(self._bloque())
        self.assertIn(f"de {parque['servidores']} servidores", texto)
        self.assertIn(f"{parque['total']} activos con inventario presente", texto)

    def test_el_denominador_se_acota_igual_que_las_cifras_filtradas(self):
        """Con el proceso «Pila» puesto, el denominador son los servidores de ese proceso.

        Si el denominador fuera el del parque completo se leería «2 de 3 servidores» en una
        página que solo habla de dos máquinas, que es justo el descuadre que el usuario
        denunció entre Amenazas y Activos.
        """
        from webui.vistas.amenazas import _parque_presente

        parque = _parque_presente(self.conn, proceso="Pila")
        self.assertEqual(parque, {"total": 2, "servidores": 2, "equipos": 0})
        texto = self._visible(self._bloque("/amenazas/?proceso=Pila"))
        self.assertIn("2 de 2 servidores", texto)
        self.assertIn("los activos del proceso «Pila»", texto)
        self.assertNotIn("de 3 servidores", texto)

    def test_la_grafica_de_procesos_dice_de_que_tipo_son_las_maquinas(self):
        """«Si son servidores que diga servidores y no equipos» (2026-09-08)."""
        texto = self._visible(self._bloque())
        self.assertIn("2 servidores afectados", texto, "el proceso Pila son dos servidores")
        self.assertIn("1 equipo de cómputo afectado", texto,
                      "y el grupo de Mantenimiento, un equipo de cómputo")

    def test_las_cifras_de_la_pagina_son_las_de_la_consulta(self):
        """Una sola fuente: si la página las calculase aparte podrían discrepar."""
        html = self._html("/amenazas/")
        r = queries.resumen_amenazas(self.conn)
        pintadas = re.findall(r'class="valor fs-22-b">([\d.]+)<', html)
        self.assertEqual(pintadas[0], f"{r['registradas']:,}".replace(",", "."))
        self.assertEqual(pintadas[1], f"{r['confirmadas']:,}".replace(",", "."))
        self.assertEqual(pintadas[2], f"{r['vulnerabilidades']:,}".replace(",", "."))


class TestCifrasConFiltro(unittest.TestCase):
    """Hallazgos altos de la revisión del 2026-09-08 sobre el bloque de cifras con un
    filtro puesto: la pantalla afirmaba cosas que no eran ciertas."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "filtro.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            # Un proceso de UN SOLO servidor, para la concordancia de número, y un
            # equipo de cómputo en otro proceso, para que el parque tenga los dos tipos.
            solo = _activo(conn, 11, "srv-solo-01", "servidores", "Fcaeldi")
            _activo(conn, 12, "pc-luis", "equipos", "Mantenimiento")
            t1 = _amenaza(conn, "fp-f1", "CVE-2026-1101", "High")
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES(?,?,'CVE-2026-1101','openssl','1.0','1.2','afectado','osv',?)""",
                (solo, t1, db.utcnow()))
            # Dos amenazas más en el catálogo, confirmadas SOLO fuera de ese proceso.
            t2 = _amenaza(conn, "fp-f2", "CVE-2026-1102", "High")
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES((SELECT id FROM activos WHERE nombre='pc-luis'),?,
                          'CVE-2026-1102','firefox','1.0','1.2','afectado','osv',?)""",
                (t2, db.utcnow()))
            _amenaza(conn, "fp-f3", "CVE-2026-1103", "Medium")
            # Un proceso con un servidor y un equipo de cómputo donde SOLO el servidor tiene
            # vulnerabilidades: una sola fila en la tabla por tipo, y parque de dos tipos.
            mixto_srv = _activo(conn, 13, "srv-mixto-01", "servidores", "Mixto")
            _activo(conn, 14, "pc-mixto-01", "equipos", "Mixto")
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES(?,?,'CVE-2026-1101','openssl','1.0','1.2','afectado','osv',?)""",
                (mixto_srv, t1, db.utcnow()))
        cls.conn = db.connect(cls.ruta)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    def _html(self, url):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        respuesta = cli.get(url)
        self.assertEqual(respuesta.status_code, 200, url)
        html = respuesta.get_data(as_text=True)
        self.assertIsNone(re.search(r"\sstyle\s*=", html), f"style= en {url}")
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", html), f"on*= en {url}")
        return html

    def _visible(self, html):
        texto = re.sub(r"<[^>]+>", " ", html)
        return re.sub(r"\s+", " ", texto)

    def test_la_cifra_sin_confirmar_dice_de_que_ambito_habla(self):
        """«6.150 no se han confirmado en ningún activo» era falso con filtro puesto:
        el numerador estaba acotado al proceso y el denominador era el del catálogo
        completo, así que la resta contaba como «sin confirmar» amenazas que sí lo están
        en otras máquinas."""
        r = queries.resumen_amenazas(self.conn, proceso="Fcaeldi")
        self.assertEqual(r["confirmadas"], 1)          # solo la del proceso
        self.assertEqual(r["confirmadas_global"], 2)   # las dos del parque
        self.assertEqual(r["sin_confirmar"], r["registradas"] - 1)
        self.assertEqual(r["sin_confirmar_global"], r["registradas"] - 2)
        texto = self._visible(self._html("/amenazas/?proceso=Fcaeldi"))
        self.assertIn("los activos del proceso «Fcaeldi»", texto)
        self.assertIn(f"en todo el parque {r['sin_confirmar_global']}", texto)

    def test_la_frase_del_ambito_concuerda_en_numero(self):
        """El proceso «Fcaeldi» tiene un solo servidor: «1 activos con inventario
        presente, de los que 1 tienen» era la primera frase que se lee y la que tiene que
        dar confianza."""
        texto = self._visible(self._html("/amenazas/?proceso=Fcaeldi"))
        self.assertIn("1 activo con inventario presente", texto)
        self.assertIn("del que 1 tiene al menos una vulnerabilidad confirmada", texto)
        self.assertIn("Activo afectado de 1 presente", texto)
        for mal in ("1 activos", "de los que 1 tienen", "de 1 presentes"):
            self.assertNotIn(mal, texto)

    def test_con_filtro_no_se_promete_un_cotejo_que_no_cuadra(self):
        """La página de Activos muestra el parque completo sea cual sea el filtro con el
        que se llegue, así que con filtro puesto no se puede prometer que las cifras
        «coinciden con lo que allí se ve»."""
        con = self._visible(self._html("/amenazas/?proceso=Fcaeldi"))
        self.assertIn("acotados a este filtro", con)
        self.assertNotIn("coinciden con lo que allí se ve", con)
        sin = self._visible(self._html("/amenazas/"))
        self.assertIn("coinciden con lo que allí se ve", sin)

    def test_el_enlace_de_activos_afectados_lleva_el_filtro_entero(self):
        """Con «?origen=equipos» se pulsaba la cifra y se aterrizaba en una página que
        decía otra: el enlace perdía el tipo de máquina."""
        html = self._html("/amenazas/?origen=equipos&proceso=Mantenimiento")
        self.assertIn("vista=afectados", html)
        self.assertRegex(html, r'href="[^"]*origen=equipos[^"]*"')
        self.assertRegex(html, r'href="[^"]*proceso=Mantenimiento[^"]*"')

    def test_la_fila_de_total_no_mezcla_el_nombre_de_un_tipo_con_el_total_de_los_dos(self):
        """Con un solo tipo en la tabla porque el otro no tiene vulnerabilidades vivas
        —no porque haya filtro—, la fila decía «485 de 836 servidores», y 836 incluye los
        equipos de cómputo. La clave la decide el filtro, no cuántas filas haya."""
        from webui.vistas.amenazas import _fila_total_origen
        cifras = queries.resumen_amenazas(self.conn, proceso="Mixto")
        # una sola fila en por_origen (solo el servidor tiene vulnerabilidades), sin
        # filtro de tipo y con un parque de DOS tipos: el total tiene que hablar de
        # «activos», no de «servidores», porque el denominador (2) incluye el equipo
        self.assertEqual(len(cifras["por_origen"]), 1)
        # Desde el 2026-09-10 el denominador trae además el reparto por frescura del
        # inventario («sin_reportar» y «con_dato»): las tres cifras de siempre no cambian.
        self.assertEqual({c: cifras["presentes"][c] for c in ("total", "servidores", "equipos")},
                         {"total": 2, "servidores": 1, "equipos": 1})
        total = _fila_total_origen(cifras, cifras["presentes"], "")
        self.assertIn("activo", total["unidad"])
        self.assertNotIn("servidor", total["unidad"])
        self.assertEqual(total["afectados_es"], "1 de 2 activos")
        # si el parque del ámbito es de un solo tipo, se le llama por su nombre aunque
        # no haya filtro de tipo: «1 de 1 servidor», que es exacto
        cifras_f = queries.resumen_amenazas(self.conn, proceso="Fcaeldi")
        total_f = _fila_total_origen(cifras_f, cifras_f["presentes"], "")
        self.assertEqual(total_f["afectados_es"], "1 de 1 servidor")
        # y con el filtro de tipo puesto también
        cifras_srv = queries.resumen_amenazas(self.conn, origen="servidores")
        total_srv = _fila_total_origen(cifras_srv, cifras_srv["presentes"], "servidores")
        self.assertIn("servidor", total_srv["unidad"])
        self.assertEqual(total_srv["presentes"], cifras_srv["presentes"]["servidores"])

    def test_cada_barra_de_proceso_lleva_su_denominador(self):
        """«171 servidores afectados» de un grupo y «33 servidores afectados» de otro no
        se pueden comparar sin el denominador, que es justo lo que se pidió poder hacer."""
        from webui.vistas.amenazas import _nota_proceso
        cifras = queries.resumen_amenazas(self.conn)
        notas = {f["proceso"]: _nota_proceso(f) for f in cifras["por_proceso"]}
        self.assertEqual(notas["Fcaeldi"], "1 de 1 servidor afectado")
        self.assertEqual(notas["Mantenimiento"], "1 de 1 equipo de cómputo afectado")
        for nota in notas.values():
            self.assertIn(" de ", nota, f"sin denominador: {nota}")

    def test_la_nota_de_un_proceso_con_los_dos_tipos_habla_de_maquinas(self):
        """Devolvía «1.234 en servidores · 567 en equipos de cómputo», que son
        VULNERABILIDADES, en la misma columna en la que las notas hermanas cuentan
        máquinas. Dos magnitudes en el mismo sitio sin etiqueta es la ambigüedad que este
        bloque viene a quitar."""
        from webui.vistas.amenazas import _nota_proceso
        fila = {"proceso": "Mixto", "activos": 3, "presentes": 5,
                "activos_de_servidores": 2, "presentes_servidores": 3,
                "activos_de_equipos": 1, "presentes_equipos": 2,
                "de_servidores": 1234, "de_equipos": 567}
        nota = _nota_proceso(fila)
        self.assertEqual(nota, "2 de 3 servidores y 1 de 2 equipos de cómputo afectados")
        self.assertNotIn("1.234", nota)

    def test_una_amenaza_mitigada_confirmada_no_cuenta_como_sin_confirmar(self):
        """Hallazgo BAJO de la revisión de seguridad: «registradas − confirmadas» contaba
        como «no confirmada en ningún activo» a una amenaza mitigada que SÍ lo está,
        porque el catálogo cuenta con dos estados cerrados y las confirmadas con tres."""
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE threats SET estado='mitigada' WHERE cve='CVE-2026-1102'")
        try:
            r = queries.resumen_amenazas(self.conn)
            # registradas incluye la mitigada (no es un estado cerrado); confirmadas no
            self.assertEqual(r["registradas"], 3)
            self.assertEqual(r["confirmadas"], 1)
            # y «sin confirmar» son las que de verdad no están en ningún activo: solo la 1103
            self.assertEqual(r["sin_confirmar"], 1)
            self.assertEqual(r["sin_confirmar_global"], 1)
            rf = queries.resumen_amenazas(self.conn, proceso="Fcaeldi")
            self.assertEqual(rf["sin_confirmar"], 2, "en el proceso no están la 1102 ni la 1103")
            self.assertEqual(rf["sin_confirmar_global"], 1)
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE threats SET estado='nueva' WHERE cve='CVE-2026-1102'")

    def test_el_enlace_a_activos_funciona_con_los_grupos_sin_proceso(self):
        """Hallazgo MEDIO de la revisión de seguridad: la tarjeta decía «33 activos
        afectados» del grupo «Servidores sin proceso asignado» y su enlace aterrizaba en
        una lista de Activos vacía, porque esa página aplicaba el nombre del grupo como
        proceso literal."""
        with db.session(self.ruta) as conn:
            sin = _activo(conn, 21, "srv-sin-proceso-01", "servidores", None)
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES(?,(SELECT id FROM threats WHERE cve='CVE-2026-1101'),
                          'CVE-2026-1101','openssl','1.0','1.2','afectado','osv',?)""",
                (sin, db.utcnow()))
        try:
            grupo = queries.GRUPO_SERVIDORES_SIN_PROCESO
            cifras = queries.resumen_amenazas(self.conn, proceso=grupo)
            self.assertEqual(cifras["activos_afectados"], 1)
            from urllib.parse import quote
            html = self._html(f"/activos/?vista=afectados&proceso={quote(grupo)}")
            self.assertIn("srv-sin-proceso-01", html)
            self.assertNotIn("srv-solo-01", html)
            html = self._html(f"/activos/?vista=afectados&proceso={quote(queries.GRUPO_EQUIPOS_SIN_PROCESO)}")
            self.assertNotIn("srv-sin-proceso-01", html)
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("DELETE FROM aplicabilidad WHERE activo_id=?", (sin,))
                conn.execute("DELETE FROM activos WHERE id=?", (sin,))

    def test_las_bajas_no_cuentan_y_solo_hay_tres_segmentos(self):
        """Regla interna reiterada por el usuario el 2026-09-08: «las amenazas o
        vulnerabilidades bajas no se reportan… solo se reportan tres, críticas, altas y
        medias». Una amenaza Baja confirmada en un activo no entra en ninguna cifra."""
        with db.session(self.ruta) as conn:
            baja = _amenaza(conn, "fp-baja", "CVE-2026-1900", "Low")
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES((SELECT id FROM activos WHERE nombre='srv-solo-01'),?,
                          'CVE-2026-1900','zlib','1.0','1.2','afectado','osv',?)""",
                (baja, db.utcnow()))
        try:
            sin = queries.resumen_amenazas(self.conn)
            con = queries.resumen_amenazas(self.conn, incluir_bajas=True)
            self.assertEqual(con["vulnerabilidades"] - sin["vulnerabilidades"], 1)
            self.assertEqual(con["registradas"] - sin["registradas"], 1)
            self.assertFalse(sin["incluye_bajas"])
            for fila in sin["por_origen"] + sin["por_proceso"]:
                self.assertIn("medias", fila)
                self.assertNotIn("resto", fila)
                self.assertEqual(fila["criticas"] + fila["altas"] + fila["medias"],
                                 fila["vulnerabilidades"], "tres segmentos que suman el total")
            html = self._html("/amenazas/")
            self.assertNotIn("Medias y bajas", html)
            self.assertIn("Medias", html)
            # Desde el 2026-09-10 la pagina tampoco NOMBRA la severidad baja: la unica
            # explicacion que la nombra es el texto de ayuda del ajuste, en Ajustes.
            self.assertNotIn("severidad baja", html.lower())
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("DELETE FROM aplicabilidad WHERE cve='CVE-2026-1900'")
                conn.execute("DELETE FROM threats WHERE cve='CVE-2026-1900'")

    def test_cada_total_de_barra_lleva_su_unidad(self):
        """«Dice 30.827 y ya no dice nada; en equipos dice 15.902 pero no dice de qué»
        (2026-09-08). El total de cada barra escribe la unidad."""
        html = self._html("/amenazas/")
        texto = self._visible(html)
        # el total de cada barra: «N vulnerabilidades · M de P <tipo> afectados»
        self.assertRegex(texto, r"\d[\d.]* vulnerabilidades · \d[\d.]* de \d[\d.]* (servidor|equipo)")
        # y la fila de total de la tabla nombra sus dos magnitudes
        self.assertRegex(texto, r"Total · [^0-9]+\d[\d.]* vulnerabilidades \d[\d.]* amenazas distintas")

    def test_el_estado_de_los_activos_del_semanal_tampoco_cuenta_las_bajas(self):
        """Las cuatro cifras que abren el resumen semanal y el Panel usan el mismo criterio
        que Amenazas: una vulnerabilidad de severidad Baja no cuenta (regla interna)."""
        from threatintel import ocs
        with db.session(self.ruta) as conn:
            baja = _amenaza(conn, "fp-baja-2", "CVE-2026-1901", "Low")
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES((SELECT id FROM activos WHERE nombre='pc-luis'),?,
                          'CVE-2026-1901','zlib','1.0','1.2','afectado','osv',?)""",
                (baja, db.utcnow()))
        try:
            sin = ocs.estado_activos(self.conn, cfg={"ignore_low_severity": True})
            con = ocs.estado_activos(self.conn, cfg={"ignore_low_severity": False})
            self.assertEqual(con["vulnerabilidades"] - sin["vulnerabilidades"], 1)
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("DELETE FROM aplicabilidad WHERE cve='CVE-2026-1901'")
                conn.execute("DELETE FROM threats WHERE cve='CVE-2026-1901'")

    def test_el_recorrido_guiado_no_lleva_cifras_escritas_a_mano(self):
        """«485 de 511 servidores» estaba escrito en la plantilla: en esta base son otras
        cifras, y en cualquier despliegue queda obsoleto en cuanto cambie el inventario."""
        html = self._html("/amenazas/")
        self.assertNotIn("485 de 511 servidores", html)
        self.assertIn("los afectados sobre los presentes de ese tipo", html)


class TestRedaccionDeLasNotas(unittest.TestCase):
    """Las notas de las barras, sin base de datos: son funciones puras.

    Reescritas el 2026-09-08 por la revisión: la nota de cada barra habla SIEMPRE de
    máquinas y SIEMPRE con su denominador (``presentes_servidores`` /
    ``presentes_equipos``, que ahora vienen por grupo desde ``resumen_amenazas``). Antes,
    un proceso con los dos tipos devolvía «1.234 en servidores · 567 en equipos de
    cómputo», que son VULNERABILIDADES, en la misma columna en la que las notas hermanas
    cuentan máquinas: dos magnitudes en el mismo sitio sin etiqueta.
    """

    def test_un_proceso_de_solo_servidores(self):
        from webui.vistas.amenazas import _nota_proceso
        fila = {"de_servidores": 11319, "de_equipos": 0, "activos": 171,
                "activos_de_servidores": 171, "presentes_servidores": 175,
                "activos_de_equipos": 0, "presentes_equipos": 0, "presentes": 175}
        self.assertEqual(_nota_proceso(fila), "171 de 175 servidores afectados")

    def test_un_proceso_de_solo_equipos_de_computo(self):
        from webui.vistas.amenazas import _nota_proceso
        fila = {"de_servidores": 0, "de_equipos": 15902, "activos": 246,
                "activos_de_servidores": 0, "presentes_servidores": 0,
                "activos_de_equipos": 246, "presentes_equipos": 260, "presentes": 260}
        self.assertEqual(_nota_proceso(fila), "246 de 260 equipos de cómputo afectados")

    def test_un_proceso_con_los_dos_tipos_dice_cuantas_maquinas_de_cada_uno(self):
        from webui.vistas.amenazas import _nota_proceso
        fila = {"de_servidores": 1234, "de_equipos": 567, "activos": 40,
                "activos_de_servidores": 30, "presentes_servidores": 33,
                "activos_de_equipos": 10, "presentes_equipos": 12, "presentes": 45}
        nota = _nota_proceso(fila)
        self.assertEqual(nota,
                         "30 de 33 servidores y 10 de 12 equipos de cómputo afectados")
        self.assertNotIn("1.234", nota, "la nota cuenta máquinas, no vulnerabilidades")

    def test_una_sola_maquina_va_en_singular(self):
        from webui.vistas.amenazas import _nota_proceso
        self.assertEqual(
            _nota_proceso({"de_servidores": 4, "de_equipos": 0, "activos": 1,
                           "activos_de_servidores": 1, "presentes_servidores": 1,
                           "activos_de_equipos": 0, "presentes_equipos": 0, "presentes": 1}),
            "1 de 1 servidor afectado")
        self.assertEqual(
            _nota_proceso({"de_servidores": 0, "de_equipos": 4, "activos": 1,
                           "activos_de_servidores": 0, "presentes_servidores": 0,
                           "activos_de_equipos": 1, "presentes_equipos": 1, "presentes": 1}),
            "1 de 1 equipo de cómputo afectado")

    def test_ninguna_nota_usa_la_palabra_equipos_a_secas(self):
        from webui.vistas.amenazas import _nota_origen, _nota_proceso
        filas = [{"de_servidores": 3, "de_equipos": 2, "activos": 4},
                 {"de_servidores": 0, "de_equipos": 2, "activos": 2},
                 {"de_servidores": 3, "de_equipos": 0, "activos": 3}]
        notas = [_nota_proceso(f) for f in filas]
        notas.append(_nota_origen({"afectados_es": "1 de 1 equipo de cómputo", "presentes": 1}))
        for nota in notas:
            self.assertEqual(re.findall(r"\b[Ee]quipos?\b(?!\s+de\s+cómputo)", nota), [], nota)

    def test_el_ambito_nombra_el_recorte_sin_ambiguedad(self):
        from webui.vistas.amenazas import _ambito_es
        self.assertEqual(_ambito_es("", ""), "todos los activos de la organización")
        self.assertEqual(_ambito_es("", "servidores"), "los servidores de toda la organización")
        self.assertEqual(_ambito_es("", "equipos"),
                         "los equipos de cómputo de toda la organización")
        self.assertEqual(_ambito_es("Pila", ""), "los activos del proceso «Pila»")
        self.assertEqual(_ambito_es("Pila", "servidores"), "los servidores del proceso «Pila»")


if __name__ == "__main__":
    unittest.main()


class TestUnCvePorActivo(unittest.TestCase):
    """Unidad de conteo: UN CVE en UN activo (2026-09-09).

    Reclamación del usuario, dos veces: «si hay una vulnerabilidad de kernel que se repite
    que se cuente como una». Medido en producción antes del cambio: 43.135 filas de
    `aplicabilidad` frente a 25.325 pares (activo, CVE), porque un CVE del núcleo toca
    linux-image, linux-headers, linux-modules y linux-tools del mismo servidor y un CVE de
    sssd toca hasta dieciocho paquetes. Aquí un servidor tiene el mismo CVE en CUATRO
    paquetes y un equipo de cómputo lo tiene en UNO: son dos vulnerabilidades, no cinco, en
    todas las capas (consulta, página de Amenazas, estado de los activos, Panel, libro de
    la alerta e informe mensual).
    """

    CVE = "CVE-2026-9001"

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "un_cve_por_activo.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            srv = _activo(conn, 21, "srv-nucleo-01", "servidores", "Pila", entorno="produccion")
            pc = _activo(conn, 22, "pc-carla", "equipos", None, entorno="oficina")
            cls.threat_id = _amenaza(conn, "fp-nucleo", cls.CVE, "Critical", kev=1)
            # El mismo CVE del núcleo en cuatro paquetes binarios del mismo servidor...
            for paquete in ("linux-image-amd64", "linux-headers-amd64",
                            "linux-modules-6.1", "linux-tools-common"):
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor, evaluado_at)
                       VALUES(?,?,?,?,'6.1.0-1','6.1.0-2','afectado','osv',?)""",
                    (srv, cls.threat_id, cls.CVE, paquete, db.utcnow()))
            # ...y en un solo paquete del equipo de cómputo.
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES(?,?,?,'linux-image-generic','6.1.0-1','6.1.0-2','afectado','osv',?)""",
                (pc, cls.threat_id, cls.CVE, db.utcnow()))
        cls.conn = db.connect(cls.ruta)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    def _html(self, url: str) -> str:
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        respuesta = cli.get(url)
        self.assertEqual(respuesta.status_code, 200, url)
        return respuesta.get_data(as_text=True)

    def test_hay_cinco_filas_de_paquete_y_dos_vulnerabilidades(self):
        filas = self.conn.execute("SELECT COUNT(*) FROM aplicabilidad WHERE veredicto='afectado'").fetchone()[0]
        self.assertEqual(filas, 5, "cinco paquetes: la trazabilidad de qué actualizar")
        r = queries.resumen_amenazas(self.conn)
        self.assertEqual(r["vulnerabilidades"], 2, "pero dos vulnerabilidades: un CVE en dos activos")
        self.assertEqual(r["activos_afectados"], 2)
        self.assertEqual(r["cve_confirmados"], 1)
        self.assertEqual(r["confirmadas"], 1)

    def test_por_severidad_por_origen_y_kev_usan_la_misma_unidad(self):
        r = queries.resumen_amenazas(self.conn)
        self.assertEqual(r["vulnerabilidades_kev"], 2, "las dos están en KEV; antes salían 5")
        por_origen = {o["origen"]: o for o in r["por_origen"]}
        self.assertEqual(por_origen["servidores"]["vulnerabilidades"], 1,
                         "cuatro paquetes del mismo servidor son una vulnerabilidad")
        self.assertEqual(por_origen["servidores"]["criticas"], 1)
        self.assertEqual(por_origen["equipos"]["vulnerabilidades"], 1)
        self.assertEqual(por_origen["equipos"]["criticas"], 1)
        for o in por_origen.values():
            self.assertEqual(o["criticas"] + o["altas"] + o["medias"], o["vulnerabilidades"],
                             "los tres segmentos suman el total de la barra")
        self.assertEqual(sum(o["vulnerabilidades"] for o in r["por_origen"]), r["vulnerabilidades"])
        grupos = {p["proceso"]: p for p in r["por_proceso"]}
        self.assertEqual(grupos["Pila"]["vulnerabilidades"], 1)
        self.assertEqual(grupos["Pila"]["de_servidores"], 1)
        self.assertEqual(grupos[queries.GRUPO_EQUIPOS_SIN_PROCESO]["vulnerabilidades"], 1)
        self.assertEqual(grupos[queries.GRUPO_EQUIPOS_SIN_PROCESO]["de_equipos"], 1)

    def test_el_punto_unico_de_verdad(self):
        self.assertEqual(queries.sql_vulnerabilidades(),
                         "COUNT(DISTINCT ap.activo_id || char(31) || ap.cve)")
        self.assertEqual(queries.sql_vulnerabilidades("x", "t.in_kev = 1"),
                         "COUNT(DISTINCT CASE WHEN t.in_kev = 1 THEN x.activo_id || char(31) || x.cve END)")
        self.assertIn(queries.VULNERABILIDAD_DISTINTA, queries.sql_vulnerabilidades())

    def test_la_pagina_de_amenazas_pinta_dos_y_la_fila_total_suma(self):
        html = self._html("/amenazas/")
        bloque = html[html.index('id="cuantas-amenazas"'):html.index('id="resultados"')]
        pintadas = re.findall(r'class="valor fs-22-b">([\d.]+)<', bloque)
        self.assertEqual(pintadas[2], "2", "la métrica «Vulnerabilidades confirmadas»")
        pie = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", bloque[bloque.index("<tfoot>"):bloque.index("</tfoot>")]))
        self.assertIn("2 vulnerabilidades", pie)
        self.assertNotIn("5 vulnerabilidades", pie)
        # La nota de la unidad, donde la cifra aparece por primera vez
        self.assertIn("Una vulnerabilidad es un CVE en un activo", bloque)
        self.assertIn("cuenta una sola vez", bloque)

    def test_estado_de_los_activos_del_semanal(self):
        from threatintel import ocs
        estado = ocs.estado_activos(self.conn, cfg={"ignore_low_severity": True})
        self.assertEqual(estado["vulnerabilidades"], 2)
        self.assertEqual(estado["activos_afectados"], 2)
        self.assertEqual(estado["cve_distintos"], 1)
        self.assertEqual(estado["expuestos_vulnerabilidades"], 1,
                         "solo el servidor está en producción: una vulnerabilidad, no cuatro")
        self.assertEqual(estado["expuestos_activos"], 1)

    def test_el_panel_dice_dos_vulnerabilidades_tambien_acotado(self):
        from webui.vistas.panel import _estado_activos_en_alcance
        acotado = _estado_activos_en_alcance(self.conn, "servidores", cfg={"ignore_low_severity": True})
        self.assertEqual(acotado["vulnerabilidades"], 1)
        self.assertEqual(acotado["expuestos_vulnerabilidades"], 1)
        html = self._html("/")
        self.assertIn('2 <span class="tenue">vulnerabilidades</span>', html)
        self.assertNotIn('5 <span class="tenue">vulnerabilidades</span>', html)
        self.assertIn("cuenta una sola vez", html)

    def test_el_libro_de_la_alerta_cuenta_activos_no_paquetes(self):
        from openpyxl import load_workbook
        from threatintel import libro_alerta
        vista = queries.obtener_amenaza(self.conn, self.threat_id)
        destino = Path(self.dir.name) / "alerta.xlsx"
        ruta = libro_alerta.generar(self.conn, [vista], destino=destino,
                                    cfg={"alert_excel_max_activos": 500},
                                    meta={"url_base": "http://soc.ejemplo.test"})
        self.assertIsNotNone(ruta)
        libro = load_workbook(ruta)
        try:
            hoja = libro[self.CVE]
            texto = "\n".join(str(c.value) for fila in hoja.iter_rows() for c in fila
                              if c.value is not None)
            self.assertIn("2 activos con la versión vulnerable instalada", texto)
            self.assertNotIn("5 activos", texto)
            self.assertEqual(libro["Resumen"].cell(row=2, column=10).value, 2,
                             "la columna de activos afectados del resumen")
        finally:
            libro.close()

    def test_el_informe_mensual_escribe_el_total_y_la_unidad(self):
        from threatintel import aplicabilidad, report
        mes = db.utcnow()[:7]
        cfg = {"translate_engine": "none", "ignore_low_severity": True}
        resumen = aplicabilidad.resumen_informe(self.conn, mes, cfg=cfg)
        self.assertEqual(resumen["vulnerabilidades"], 2)
        self.assertEqual(resumen["vulnerabilidades_kev"], 2)
        self.assertEqual(resumen["activos_afectados"], 2)
        doc = report.construir_documento(self.conn, mes, cfg=cfg)
        parrafos = [p.text for p in doc.paragraphs]
        intro = next(p for p in parrafos if p.startswith("El inventario real cuenta con"))
        self.assertIn("2 activos aparecen afectados, con 2 vulnerabilidades confirmadas", intro)
        self.assertTrue(any("Una vulnerabilidad es un CVE en un activo" in p
                            and "cuenta una sola vez" in p for p in parrafos),
                        "la nota de la unidad acompaña a la cifra")


class TestCoherenciaEntrePaginas(unittest.TestCase):
    """Las mismas cifras en Activos, Amenazas, el Panel, el semanal y las alertas por proceso.

    Revisión de precisión del 2026-09-09: la página de Activos decía «747 con
    vulnerabilidades confirmadas», Amenazas y el Panel decían 746 del mismo parque, y la
    tarjeta de Amenazas enlazaba de una cifra a la otra. La diferencia eran activos cuyos
    únicos CVE son de severidad Baja, que por regla interna no se reporta. Aquí hay tres
    activos: uno con un CVE crítico, uno con un CVE alto y uno cuyo único CVE es Bajo.
    """

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "coherencia.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            uno = _activo(conn, 31, "srv-uno", "servidores", "Pila")
            dos = _activo(conn, 32, "srv-dos", "servidores", "Pila")
            tres = _activo(conn, 33, "srv-tres", "servidores", "Pila")
            criticа = _amenaza(conn, "fp-c", "CVE-2026-8001", "Critical")
            alta = _amenaza(conn, "fp-a", "CVE-2026-8002", "High")
            baja = _amenaza(conn, "fp-b", "CVE-2026-8003", "Low")
            for activo, amenaza, cve in ((uno, criticа, "CVE-2026-8001"),
                                         (dos, alta, "CVE-2026-8002"),
                                         (tres, baja, "CVE-2026-8003")):
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor, evaluado_at)
                       VALUES(?,?,?,'paq','1.0','1.1','afectado','osv',?)""",
                    (activo, amenaza, cve, db.utcnow()))
        cls.conn = db.connect(cls.ruta)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    def _html(self, url: str) -> str:
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        respuesta = cli.get(url)
        self.assertEqual(respuesta.status_code, 200, url)
        return respuesta.get_data(as_text=True)

    def test_las_tres_paginas_cuentan_los_mismos_activos(self):
        from threatintel import ocs
        cfg = {"ignore_low_severity": True}
        self.assertEqual(queries.resumen_amenazas(self.conn)["activos_afectados"], 2)
        self.assertEqual(ocs.estado_activos(self.conn, cfg=cfg)["activos_afectados"], 2)
        self.assertEqual(ocs.resumen(self.conn, cfg=cfg)["con_vulnerabilidades"], 2,
                         "la página de Activos no puede contar el activo que solo tiene una baja")

    def test_con_las_bajas_dentro_las_tres_dicen_tres(self):
        from threatintel import ocs
        cfg = {"ignore_low_severity": False}
        self.assertEqual(queries.resumen_amenazas(self.conn, incluir_bajas=True)["activos_afectados"], 3)
        self.assertEqual(ocs.estado_activos(self.conn, cfg=cfg)["activos_afectados"], 3)
        self.assertEqual(ocs.resumen(self.conn, cfg=cfg)["con_vulnerabilidades"], 3)

    def test_la_vista_rapida_de_activos_lista_lo_que_promete_su_numero(self):
        html = self._html("/activos/")
        self.assertIn("srv-uno", html)
        lista = self._html("/activos/?vista=afectados")
        self.assertIn("srv-uno", lista)
        self.assertIn("srv-dos", lista)
        self.assertNotIn("srv-tres", lista,
                         "el atajo «con vulnerabilidades» no puede traer el activo de solo bajas")

    def test_las_alertas_por_proceso_cuentan_igual_que_amenazas(self):
        from threatintel import alertas_proceso
        procesos = {p["proceso"]: p["con_vulnerabilidades"]
                    for p in alertas_proceso.procesos_disponibles(self.conn)}
        por_proceso = {f["proceso"]: f["activos"]
                       for f in queries.resumen_amenazas(self.conn)["por_proceso"]}
        self.assertEqual(procesos["Pila"], 2)
        self.assertEqual(procesos["Pila"], por_proceso["Pila"])

    def test_la_ficha_del_activo_dice_la_unidad_de_cada_cifra(self):
        """Adaptada el 2026-09-09: la tabla «Amenazas evaluadas para este activo» —una fila
        por CVE y paquete, con los tres veredictos— se retiró porque listaba también lo que
        NO afecta. La ficha cuenta ahora ACTUALIZACIONES (una por cosa que hay que
        actualizar) y dice debajo, con su unidad, cuántas vulnerabilidades y cuántas filas
        de remediación cubren. Lo que no puede volver es llamar «amenazas» a las filas por
        paquete."""
        html = self._html("/activos/1")
        self.assertIn("Actualizaciones pendientes", html)
        self.assertIn("una por cosa que hay que actualizar", html)
        self.assertIn("fila", html)
        self.assertNotIn("amenazas evaluadas ·", html,
                         "la paginación no puede llamar amenazas a las filas por paquete")
        self.assertNotIn("Amenazas evaluadas para este activo", html)
        plantilla = (BASE_DIR / "webui" / "templates" / "_remediaciones_activo.html").read_text(encoding="utf-8")
        self.assertIn("fila{{ 's' if g.filas != 1 }} de remediación en", plantilla,
                      "cada actualización dice cuántas filas de remediación cubre")


class TestPalabrasDelInformeYDelCorreo(unittest.TestCase):
    """«Vulnerabilidad» significa una sola cosa en el informe y en la alerta diaria."""

    def test_el_informe_llama_amenazas_a_los_avisos_del_periodo(self):
        import inspect
        from threatintel import report
        fuente = inspect.getsource(report)
        self.assertIn("amenazas relacionadas con el inventario tecnológico", fuente)
        self.assertNotIn("vulnerabilidades relacionadas con el inventario tecnológico", fuente,
                         "los avisos del catálogo son amenazas, no vulnerabilidades")

    def test_el_informe_escribe_los_numeros_en_formato_espanol(self):
        from threatintel import report
        self.assertEqual(report._numero(22807), "22.807")
        self.assertEqual(report._numero(1), "1")
        self.assertEqual(report._numero(None), "None")

    def test_la_alerta_cuenta_activos_distintos_no_apariciones(self):
        from threatintel import notify
        amenaza = {
            "id": 1, "cve": "CVE-2026-8100", "title_es": "Aviso de prueba", "severity": "High",
            "relevance": 70.0, "tecs_exposicion": [], "activos": {
                "n_afectados": 3, "mas": 0,
                "afectados": [{"id": 7, "nombre": "srv-uno"}, {"id": 7, "nombre": "srv-uno"},
                              {"id": 8, "nombre": "srv-dos"}]}}
        html = notify.render_alert_email([amenaza, dict(amenaza, id=2, cve="CVE-2026-8101",
                                                        fingerprint="otro")],
                                         {"detalle_top": 0})
        self.assertIn("2 activos distintos en total", html)
        self.assertNotIn("6 activos", html, "sumar por amenaza contaba el mismo servidor varias veces")

    def test_quien_tiene_la_base_delante_puede_dar_la_cifra_exacta(self):
        from threatintel import notify
        amenaza = {"id": 1, "cve": "CVE-2026-8102", "title_es": "Aviso", "severity": "High",
                   "relevance": 70.0, "tecs_exposicion": [],
                   "activos": {"n_afectados": 2, "mas": 5,
                               "afectados": [{"id": 7, "nombre": "srv-uno"}]}}
        html = notify.render_alert_email([amenaza], {"detalle_top": 0, "activos_afectados": 41})
        self.assertIn("41 activos distintos en total", html)
        self.assertNotIn("al menos 41", html)
        recortado = notify.render_alert_email([amenaza], {"detalle_top": 0})
        self.assertIn("al menos 1 activo distinto en total", recortado,
                      "con la lista recortada la cifra es un mínimo y se dice")


# ==========================================================================
# Con la severidad baja incluida (revisión de seguridad del 2026-09-09)
# ==========================================================================
class TestSeveridadBajaIncluida(unittest.TestCase):
    """Qué pasa cuando el ajuste «Ignorar la severidad baja» se DESACTIVA.

    Hasta el 2026-09-09 la página de Amenazas pintaba siempre tres segmentos (críticas,
    altas y medias) y afirmaba que «las de severidad baja no se reportan… y no están en
    ninguna cifra de esta página». Con el ajuste desactivado las bajas SÍ entraban en el
    total y en ningún segmento: en la base real, 1.233 vulnerabilidades (278 de equipos de
    cómputo y 955 de servidores) contaban en el total, la barra perdía ese trozo y el
    párrafo seguía diciendo lo contrario. Estas pruebas fijan las dos verdades:

    * con el ajuste activo (lo normal): tres segmentos, su suma es el total y la severidad
      baja no se nombra en ninguna parte de la página;
    * con el ajuste desactivado: cuatro segmentos, su suma sigue siendo el total y el
      texto dice que las bajas cuentan, con cuántas son;
    * una vulnerabilidad cuyos avisos no declaran severidad no desaparece de la barra sin
      decirlo: aparece como «Sin severidad conocida», en los dos estados del ajuste.

    El parque: un servidor del proceso «Pila» y un equipo de cómputo sin proceso, con una
    amenaza crítica, una alta, una media y una baja repartidas entre ellos.
    """

    CLAVES = ("criticas", "altas", "medias", "bajas", "sin_severidad")

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "bajas.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            srv = _activo(conn, 41, "srv-bajas-01", "servidores", "Pila")
            pc = _activo(conn, 42, "pc-bajas-01", "equipos", None)
            critica = _amenaza(conn, "fp-b-c", "CVE-2026-9001", "Critical")
            alta = _amenaza(conn, "fp-b-a", "CVE-2026-9002", "High")
            media = _amenaza(conn, "fp-b-m", "CVE-2026-9003", "Medium")
            baja = _amenaza(conn, "fp-b-b", "CVE-2026-9004", "Low")
            for activo, amenaza, cve in ((srv, critica, "CVE-2026-9001"),
                                         (srv, alta, "CVE-2026-9002"),
                                         (pc, alta, "CVE-2026-9002"),
                                         (pc, media, "CVE-2026-9003"),
                                         (srv, baja, "CVE-2026-9004"),
                                         (pc, baja, "CVE-2026-9004")):
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor, evaluado_at)
                       VALUES(?,?,?,'paq','1.0','1.1','afectado','osv',?)""",
                    (activo, amenaza, cve, db.utcnow()))
        cls.conn = db.connect(cls.ruta)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.dir.cleanup()

    def tearDown(self):
        """El ajuste vuelve siempre a su valor normal: una prueba no puede dejar la base
        con la regla interna desactivada para la siguiente."""
        with db.session(self.ruta) as conn:
            db.set_setting(conn, "ignore_low_severity", True)

    # ------------------------------------------------------------- utilidades
    def _html(self, url: str = "/amenazas/") -> str:
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        respuesta = cli.get(url)
        self.assertEqual(respuesta.status_code, 200, url)
        return respuesta.get_data(as_text=True)

    def _desactivar_el_ajuste(self) -> None:
        with db.session(self.ruta) as conn:
            db.set_setting(conn, "ignore_low_severity", False)

    @staticmethod
    def _bloque(html: str, desde: str, hasta: str | None = None) -> str:
        i = html.index(desde)
        return html[i:html.index(hasta, i)] if hasta else html[i:]

    def _grafico_por_tipo(self, html: str) -> str:
        return self._bloque(html, "Vulnerabilidades por tipo de activo",
                            "Vulnerabilidades por proceso")

    def _grafico_por_proceso(self, html: str) -> str:
        return self._bloque(html, "Vulnerabilidades por proceso", 'id="resultados"')

    @staticmethod
    def _texto(bloque: str) -> str:
        """El texto corrido que lee el operador, con los espacios normalizados: las frases
        de la plantilla llevan saltos de línea y no se pueden buscar tal cual."""
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", bloque)).strip()

    @staticmethod
    def _leyenda(bloque: str) -> list[tuple[str, str]]:
        """[(clave de color, nombre)] de la leyenda de la gráfica, en su orden."""
        leyenda = re.search(r'<ul class="leyenda">(.*?)</ul>', bloque, re.S)
        if not leyenda:
            return []
        return [(clave, nombre.strip()) for clave, nombre in re.findall(
            r'leyenda-punto serie-([a-z0-9-]+)"></span>([^<]*)', leyenda.group(1))]

    @staticmethod
    def _totales_de_barra(bloque: str) -> list[int]:
        """El total que la gráfica escribe a la derecha de cada barra, como número."""
        return [int(n.replace(".", "")) for n in re.findall(
            r'class="etiqueta-valor"[^>]*>([\d.]+) vulnerabilidades', bloque)]

    def _comprobar_suma(self, cifras: dict) -> None:
        """En el total del ámbito y en cada fila del reparto, los segmentos suman el total."""
        self.assertEqual(sum(cifras[c] for c in self.CLAVES), cifras["vulnerabilidades"],
                         "los segmentos del ámbito no suman el total")
        for fila in cifras["por_origen"] + cifras["por_proceso"]:
            self.assertEqual(sum(int(fila[c] or 0) for c in self.CLAVES),
                             fila["vulnerabilidades"],
                             f"los segmentos de «{fila.get('origen') or fila.get('proceso')}» "
                             f"no suman sus vulnerabilidades")

    # --------------------------------------------- con el ajuste activo (normal)
    def test_con_el_ajuste_activo_hay_tres_segmentos_que_suman_el_total(self):
        cifras = queries.resumen_amenazas(self.conn)
        self.assertEqual(cifras["vulnerabilidades"], 4,
                         "crítica y alta del servidor, alta y media del equipo de cómputo")
        self.assertEqual((cifras["criticas"], cifras["altas"], cifras["medias"]), (1, 2, 1))
        self.assertEqual(cifras["bajas"], 0, "las bajas no cuentan con el ajuste activo")
        self.assertEqual(cifras["sin_severidad"], 0)
        self.assertFalse(cifras["incluye_bajas"])
        self._comprobar_suma(cifras)

    def test_con_el_ajuste_activo_la_pagina_no_nombra_la_severidad_baja(self):
        html = self._html()
        for grafico in (self._grafico_por_tipo(html), self._grafico_por_proceso(html)):
            self.assertEqual(self._leyenda(grafico),
                             [("critico", "Críticas"), ("alto", "Altas"), ("medio", "Medias")],
                             "con el ajuste activo la leyenda solo tiene tres segmentos")
            self.assertNotIn("Bajas", grafico)
            self.assertNotIn("Sin severidad conocida", grafico)
        tipo = self._grafico_por_tipo(html)
        texto = self._texto(tipo)
        self.assertIn("partida en tres segmentos", texto)
        self.assertIn("críticas, altas y medias", texto)
        # Y no la nombra en ninguna parte (orden del usuario del 2026-09-10): la pagina
        # dice cuales son las tres severidades que reporta y no menciona la que no cuenta.
        self.assertNotIn("baja", texto.lower())
        self.assertNotIn("severidad baja", self._texto(html).lower())
        # Y el total escrito a la derecha de cada barra es el total de la fila.
        self.assertEqual(sorted(self._totales_de_barra(tipo)), [2, 2])

    # ----------------------------------------- con el ajuste desactivado
    def test_con_el_ajuste_desactivado_hay_cuatro_segmentos_que_suman_el_total(self):
        self._desactivar_el_ajuste()
        cifras = queries.resumen_amenazas(self.conn, incluir_bajas=True)
        self.assertEqual(cifras["vulnerabilidades"], 6, "entran las dos bajas")
        self.assertEqual(cifras["bajas"], 2)
        self.assertTrue(cifras["incluye_bajas"])
        self._comprobar_suma(cifras)
        for fila in cifras["por_origen"]:
            self.assertEqual(fila["bajas"], 1, "cada máquina tiene una vulnerabilidad baja")

    def test_con_el_ajuste_desactivado_la_barra_no_pierde_las_bajas(self):
        """El defecto de fondo: la barra medía críticas + altas + medias mientras el total
        contaba también las bajas, así que el dibujo perdía 1.233 vulnerabilidades de la
        base real sin avisar. Ahora el total de cada barra es la suma de sus segmentos."""
        self._desactivar_el_ajuste()
        html = self._html()
        for grafico in (self._grafico_por_tipo(html), self._grafico_por_proceso(html)):
            self.assertEqual(self._leyenda(grafico),
                             [("critico", "Críticas"), ("alto", "Altas"),
                              ("medio", "Medias"), ("bajo", "Bajas")],
                             "con el ajuste desactivado la leyenda tiene los cuatro segmentos")
        tipo = self._grafico_por_tipo(html)
        self.assertEqual(sorted(self._totales_de_barra(tipo)), [3, 3],
                         "cada barra mide las tres vulnerabilidades de su máquina")
        # Las bajas aparecen en la leyenda con su cifra y su unidad.
        self.assertIn("Bajas <b>2 vulnerabilidades</b>", tipo)

    def test_con_el_ajuste_desactivado_el_texto_dice_la_verdad(self):
        self._desactivar_el_ajuste()
        html = self._html()
        texto = self._texto(self._grafico_por_tipo(html))
        self.assertIn("partida en cuatro segmentos", texto)
        self.assertIn("críticas, altas, medias y bajas", texto)
        self.assertIn("2 de las 6 vulnerabilidades de este ámbito son bajas", texto)
        self.assertNotIn("no se reportan", texto,
                         "con el ajuste desactivado la página no puede decir que no se reportan")
        self.assertNotIn("no están en ninguna cifra de esta página", texto)
        proceso = self._texto(self._grafico_por_proceso(html))
        self.assertIn("los mismos cuatro segmentos de arriba", proceso)
        # El recorrido guiado del panel de cifras cuenta lo mismo que el párrafo.
        recorrido = " ".join(re.findall(r'data-tour-texto="([^"]*)"', html))
        self.assertIn("cuatro segmentos", recorrido)
        self.assertIn("«Ignorar la severidad baja» está desactivado", recorrido)
        self.assertNotIn("no se reportan", recorrido)

    def test_el_catalogo_deja_de_excusarse_con_las_bajas(self):
        """La nota de «Amenazas registradas» dice qué queda fuera SIN nombrar la severidad
        baja (2026-09-10): con el ajuste activo hay algo que no se reporta por su
        severidad, y con el ajuste desactivado la nota no puede afirmarlo."""
        texto = self._texto(self._html())
        self.assertIn("salvo los que no se reportan por su severidad", texto)
        self.assertNotIn("severidad baja", texto.lower())
        self._desactivar_el_ajuste()
        self.assertNotIn("salvo los que no se reportan por su severidad",
                         self._texto(self._html()))

    # --------------------------------- severidad desconocida (NULL en la base)
    def test_una_vulnerabilidad_sin_severidad_no_desaparece_de_la_barra(self):
        """Una vulnerabilidad sin severidad conocida no es una baja: cuenta en el total en
        los dos estados del ajuste, así que tiene su propio segmento en gris («Sin severidad
        conocida») en vez de contarse en el total y en ningún segmento, como ocurría hasta
        el 2026-09-09.

        Cómo se produce: `threats.severity` es NOT NULL, así que una amenaza del catálogo
        siempre tiene severidad; lo que puede faltar es la amenaza. `aplicabilidad.threat_id`
        admite NULL (un veredicto cuya amenaza ya no está en el catálogo), y el propio
        criterio de la consulta lo cuenta desde siempre (`_VIVA_AMENAZA` empieza por
        `t.id IS NULL`): con LEFT JOIN, esa fila llega con `t.severity` a NULL.
        """
        with db.session(self.ruta) as conn:
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES((SELECT id FROM activos WHERE nombre='srv-bajas-01'),NULL,
                          'CVE-2026-9005','paq','1.0','1.1','afectado','manual',?)""",
                (db.utcnow(),))
        try:
            for incluir in (False, True):
                cifras = queries.resumen_amenazas(self.conn, incluir_bajas=incluir)
                self.assertEqual(cifras["sin_severidad"], 1,
                                 f"con incluir_bajas={incluir} la vulnerabilidad sin severidad "
                                 f"sigue contando y se dice en qué segmento está")
                self._comprobar_suma(cifras)
            html = self._html()
            tipo = self._grafico_por_tipo(html)
            self.assertIn(("neutro", "Sin severidad conocida"), self._leyenda(tipo))
            self.assertIn('class="serie-neutro"', tipo, "el segmento gris se dibuja")
            texto = self._texto(tipo)
            self.assertIn("es 1 vulnerabilidad cuyos avisos no traen severidad", texto)
            self.assertIn("partida en cuatro segmentos", texto)
            self.assertNotIn("Bajas", tipo,
                             "el ajuste sigue activo: la severidad baja no se nombra")
            self._desactivar_el_ajuste()
            tipo = self._grafico_por_tipo(self._html())
            self.assertEqual(self._leyenda(tipo),
                             [("critico", "Críticas"), ("alto", "Altas"), ("medio", "Medias"),
                              ("bajo", "Bajas"), ("neutro", "Sin severidad conocida")])
            texto = self._texto(tipo)
            self.assertIn("partida en cinco segmentos", texto)
            self.assertIn("críticas, altas, medias, bajas y sin severidad conocida", texto)
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("DELETE FROM aplicabilidad WHERE cve='CVE-2026-9005'")

    def test_los_dos_caminos_de_sin_severidad_dan_lo_mismo(self):
        """``resumen_amenazas`` resta los cuatro segmentos del total (cuesta cero) y
        ``sql_vulnerabilidades_sin_severidad`` lo cuenta en SQL: tienen que coincidir, con
        y sin bajas y con un aviso sin severidad de por medio."""
        with db.session(self.ruta) as conn:
            for nombre in ("srv-bajas-01", "pc-bajas-01"):
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor, evaluado_at)
                       VALUES((SELECT id FROM activos WHERE nombre=?),NULL,
                              'CVE-2026-9006','paq','1.0','1.1','afectado','manual',?)""",
                    (nombre, db.utcnow()))
        try:
            for incluir in (False, True):
                cifras = queries.resumen_amenazas(self.conn, incluir_bajas=incluir)
                condicion = "" if incluir else f" AND {queries._SIN_BAJAS}"
                en_sql = self.conn.execute(
                    f"""SELECT {queries.sql_vulnerabilidades_sin_severidad()}
                          FROM aplicabilidad ap JOIN activos a ON a.id = ap.activo_id
                          LEFT JOIN threats t ON t.id = ap.threat_id
                         WHERE ap.veredicto = 'afectado' AND a.presente = 1
                           AND {queries._VIVA_AMENAZA}{condicion}""").fetchone()[0]
                self.assertEqual(cifras["sin_severidad"], 2)
                self.assertEqual(cifras["sin_severidad"], en_sql,
                                 f"la resta y el conteo en SQL discrepan con incluir_bajas={incluir}")
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("DELETE FROM aplicabilidad WHERE cve='CVE-2026-9006'")

    # ------------------------------------ coherencia con Alertas por proceso
    def test_procesos_disponibles_cuenta_igual_que_amenazas_en_los_dos_estados(self):
        """«Procesos disponibles» tenía `t.severity <> 'Low'` fijo y no miraba el ajuste: al
        desactivarlo, esa página seguía sin contar las bajas mientras Amenazas sí las
        contaba (revisión de seguridad del 2026-09-09). El parque de esta prueba tiene un
        servidor del proceso «Pila» cuyas vulnerabilidades no son solo bajas, y para que la
        discrepancia se vea hace falta un servidor cuyo ÚNICO CVE sea de severidad baja."""
        from threatintel import alertas_proceso
        with db.session(self.ruta) as conn:
            solo_baja = _activo(conn, 43, "srv-solo-baja", "servidores", "Pila")
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES(?,(SELECT id FROM threats WHERE cve='CVE-2026-9004'),
                          'CVE-2026-9004','paq','1.0','1.1','afectado','osv',?)""",
                (solo_baja, db.utcnow()))
        try:
            # Ajuste activo: el servidor de solo bajas no cuenta en ninguna de las dos.
            disponibles = {p["proceso"]: p["con_vulnerabilidades"]
                           for p in alertas_proceso.procesos_disponibles(self.conn)}
            por_proceso = {f["proceso"]: f["activos"]
                           for f in queries.resumen_amenazas(self.conn)["por_proceso"]}
            self.assertEqual(disponibles["Pila"], 1)
            self.assertEqual(disponibles["Pila"], por_proceso["Pila"])
            # Ajuste desactivado: cuentan los dos servidores en las dos páginas.
            self._desactivar_el_ajuste()
            self.assertFalse(alertas_proceso.incluir_bajas(self.conn) is False,
                             "el ajuste desactivado significa que las bajas cuentan")
            disponibles = {p["proceso"]: p["con_vulnerabilidades"]
                           for p in alertas_proceso.procesos_disponibles(self.conn)}
            por_proceso = {f["proceso"]: f["activos"] for f in queries.resumen_amenazas(
                self.conn, incluir_bajas=True)["por_proceso"]}
            self.assertEqual(disponibles["Pila"], 2)
            self.assertEqual(disponibles["Pila"], por_proceso["Pila"])
            # Y el criterio se puede forzar sin tocar el ajuste (lo usan las pruebas).
            forzado = {p["proceso"]: p["con_vulnerabilidades"] for p in
                       alertas_proceso.procesos_disponibles(self.conn,
                                                            incluir_severidad_baja=False)}
            self.assertEqual(forzado["Pila"], 1)
            self.assertEqual(len(alertas_proceso.listar(self.conn)), len(disponibles))
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("DELETE FROM aplicabilidad WHERE activo_id=?", (solo_baja,))
                conn.execute("DELETE FROM activos WHERE id=?", (solo_baja,))


class TestColorDeLosSegmentos(unittest.TestCase):
    """Los dos segmentos nuevos usan colores que ya existen y se distinguen de los demás.

    Regla del proyecto: los colores tienen significado y no se inventan. «Bajas» va con
    `--bajo` (el azul que ya usa Tendencias cuando esta misma regla está desactivada) y
    «Sin severidad conocida» con `--neutro`, el gris de «sin dato». Aquí se comprueba, en el
    tema claro y en el oscuro, que los cinco rellenos se ven sobre el fondo del panel
    (contraste ≥ 3:1, WCAG 1.4.11 para elementos gráficos) y que los dos nuevos se
    distinguen a simple vista de todos los demás (distancia perceptual dE76 ≥ 25). La rampa
    crítica-alta-media es anterior y deliberadamente próxima (rojos y ámbares), así que su
    par no se mide aquí: la identificación nunca depende solo del color, porque cada
    segmento lleva nombre y cifra en la leyenda, nombre y porcentaje en su descripción
    emergente y la tabla de debajo repite los números.
    """

    ESTILO = (BASE_DIR / "webui" / "static" / "estilo.css").read_text(encoding="utf-8")
    CLAVES_SEGMENTO = ("critico", "alto", "medio", "bajo", "neutro")
    NUEVAS = ("bajo", "neutro")

    @staticmethod
    def _luminancia(color: str) -> float:
        def lineal(c):
            return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
        r, g, b = [lineal(int(color[i:i + 2], 16) / 255) for i in (1, 3, 5)]
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    @classmethod
    def _contraste(cls, a: str, b: str) -> float:
        la, lb = cls._luminancia(a), cls._luminancia(b)
        return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)

    @staticmethod
    def _lab(color: str) -> tuple:
        def lineal(c):
            return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
        r, g, b = [lineal(int(color[i:i + 2], 16) / 255) for i in (1, 3, 5)]
        x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047
        y = 0.2126 * r + 0.7152 * g + 0.0722 * b
        z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883

        def f(v):
            return v ** (1 / 3) if v > 0.008856 else 7.787 * v + 16 / 116
        return 116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))

    @classmethod
    def _distancia(cls, a: str, b: str) -> float:
        return sum((p - q) ** 2 for p, q in zip(cls._lab(a), cls._lab(b))) ** 0.5

    def _temas(self) -> dict[str, tuple[dict, str]]:
        """{tema: ({clave: color}, fondo del panel)} para el claro y el oscuro."""
        pantalla = self.ESTILO[:self.ESTILO.index("@media print")]
        claro = pantalla[:pantalla.index(':root[data-tema="claro"]')]
        oscuro = "\n".join(re.findall(r':root\[data-tema="oscuro"\] \{([^}]*)\}', pantalla))
        salida = {}
        for nombre, bloque in (("claro", claro), ("oscuro", oscuro)):
            colores = {c: re.findall(rf"--{c}: (#[0-9a-f]{{6}})", bloque)[-1]
                       for c in self.CLAVES_SEGMENTO}
            fondo = re.findall(r"--fondo-panel: (#[0-9a-f]{6})", bloque)[-1]
            salida[nombre] = (colores, fondo)
        return salida

    def test_los_cinco_segmentos_tienen_color_y_regla_de_serie(self):
        from webui.vistas import amenazas as vista
        self.assertEqual([c for c, _, _ in vista.SEGMENTOS_BARRA], list(self.CLAVES_SEGMENTO))
        for clave in self.CLAVES_SEGMENTO:
            self.assertIn(clave, graficos.CLAVES)
            self.assertIn(f".serie-{clave} {{", self.ESTILO)
            self.assertIn(f".leyenda-punto.serie-{clave} {{", self.ESTILO)

    def test_contraste_sobre_el_panel_en_los_dos_temas(self):
        for tema, (colores, fondo) in self._temas().items():
            for clave, color in colores.items():
                with self.subTest(tema=tema, clave=clave):
                    self.assertGreaterEqual(round(self._contraste(color, fondo), 2), 3.0)

    def test_los_dos_segmentos_nuevos_se_distinguen_de_los_demas(self):
        for tema, (colores, _) in self._temas().items():
            for nueva in self.NUEVAS:
                for clave, color in colores.items():
                    if clave == nueva:
                        continue
                    with self.subTest(tema=tema, par=f"{nueva}-{clave}"):
                        self.assertGreaterEqual(self._distancia(colores[nueva], color), 25)
