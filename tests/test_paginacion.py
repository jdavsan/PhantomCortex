"""Paginación de los listados largos (2026-09-07).

Petición del usuario: «cuando se muestre información que sea muy extensa se pueda
paginar para que sea mucho mejor de visualizar y no todo en una sola página, por
ejemplo los activos, el apartado de software, en el apartado de remediación, en
correcciones pendientes, en inventario, en fuentes».

Comprueba, para cada listado paginado (activos, software sin clasificar, reglas del
mapa de nombres, tecnologías con activos, inventario de tecnologías, catálogo de
fuentes, remediaciones y correcciones pendientes):

* que con más filas que el tamaño de página solo llegan al navegador las de la
  página pedida, y que las páginas no se solapan ni se dejan filas por el camino;
* que el recuento total es el real y sale de una consulta de recuento, no de contar
  las filas que se pintan;
* que los filtros y el orden se conservan al cambiar de página;
* que una página fuera de rango (cero, negativa, con letras o mayor que la última)
  se atiende con la primera o con la última, nunca con un error;
* que el parcial ``_paginacion.html`` pinta los controles correctos en la primera
  página, en una intermedia y en la última, con ``aria-current`` en la actual y los
  que no llevan a ninguna parte deshabilitados;
* que los números van en formato español y que no hay ``style=`` ni ``on*=``.

La segunda ronda (2026-09-07) anade los hallazgos del revisor: los argumentos
reservados de ``url_for`` en la direccion, la busqueda en vivo que dejaba a la vista
cifras y enlaces de la busqueda anterior, los comodines del ``LIKE``, el tope de filas
que se leen de una vez, el nombre de lo que se lista en Correcciones pendientes y los
detalles de accesibilidad del parcial.

Sin red y con base temporal bajo ``data/``, como el resto de la suite.
"""
from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)

#: El tamano de pagina lo deciden las vistas (el usuario pidio 20 el 2026-09-07). Las
#: pruebas lo leen de ahi y calculan cuantas paginas y cuantas filas esperan, para que
#: cambiarlo no obligue a reescribir treinta comprobaciones.
from webui.vistas.activos import POR_PAGINA as POR_PAGINA
from webui.vistas.activos import SOFTWARE_POR_PAGINA
from webui.vistas.fuentes import POR_PAGINA as POR_PAGINA_FUENTES
from webui.vistas.parches import LIMITE_PAGINA as POR_PAGINA_PARCHES
from webui.vistas.remediaciones import LIMITE_PAGINA as POR_PAGINA_REMEDIACIONES
from webui.vistas.tecnologias import POR_PAGINA as POR_PAGINA_TECNOLOGIAS


def n_paginas(total: int, por_pagina: int = POR_PAGINA) -> int:
    """Paginas que hacen falta para «total» filas (nunca menos de una)."""
    return max(1, -(-total // por_pagina))


def filas_ultima(total: int, por_pagina: int = POR_PAGINA) -> int:
    """Filas de la ultima pagina."""
    return (total % por_pagina) or min(total, por_pagina)


#: Filas de prueba de cada listado, siempre por encima del tamaño de página.
N_ACTIVOS = 120
N_TECNOLOGIAS = 120
N_FUENTES = 120
N_REMEDIACIONES = 1234          # también comprueba el formato español del total
N_PARCHES = 120
N_SIN_CLASIFICAR = 120
N_REGLAS = 120

#: Paginas y ultima pagina de cada listado, con el tamano que use hoy cada vista.
P_ACTIVOS = n_paginas(N_ACTIVOS)
P_TECNOLOGIAS = n_paginas(N_TECNOLOGIAS, POR_PAGINA_TECNOLOGIAS)
P_FUENTES = n_paginas(N_FUENTES, POR_PAGINA_FUENTES)
P_REMEDIACIONES = n_paginas(N_REMEDIACIONES, POR_PAGINA_REMEDIACIONES)
P_PARCHES = n_paginas(N_PARCHES, POR_PAGINA_PARCHES)
P_SIN_CLASIFICAR = n_paginas(N_SIN_CLASIFICAR)
P_REGLAS = n_paginas(N_REGLAS)


class BasePaginacion(unittest.TestCase):
    """Base común: una sola base temporal con datos suficientes para paginar."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "paginacion.db")
        db.init_db(cls.ruta)
        from webui import auth
        ahora = db.utcnow()
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "admin", "AdminSeguro#2026", rol="admin", actor="pruebas")

            # --- tecnologías: 120, la mitad sin versión registrada -----------
            for i in range(1, N_TECNOLOGIAS + 1):
                conn.execute(
                    """INSERT INTO technologies(slug, name, vendor, category, criticality,
                            systems_count, exposure, version_installed, enabled, created_at,
                            updated_at, activos_ocs, versiones_ocs)
                       VALUES(?,?,?,'aplicacion',?,?,'interna',?,1,?,?,?,?)""",
                    (f"tecnologia-{i:03d}", f"Tecnología {i:03d}", "Fabricante",
                     "critical" if i % 4 == 0 else "medium", i,
                     f"1.{i}.0" if i % 2 == 0 else None, ahora, ahora,
                     i, '[{"version": "1.0", "activos": 1}]'))
            cls.tec_ids = [r[0] for r in conn.execute(
                "SELECT id FROM technologies ORDER BY id")]

            # --- fuentes: 120 -------------------------------------------------
            for i in range(1, N_FUENTES + 1):
                conn.execute(
                    """INSERT INTO sources(slug, name, url, kind, category, priority,
                            enabled, timeout_s, created_at, updated_at)
                       VALUES(?,?,?,'rss','news','medium',1,30,?,?)""",
                    (f"fuente-{i:03d}", f"Fuente {i:03d}", f"https://x.invalid/{i}", ahora, ahora))

            # --- activos: 120, la mitad del grupo «beta» ----------------------
            for i in range(1, N_ACTIVOS + 1):
                grupo = "beta" if i % 2 == 0 else "alfa"
                conn.execute(
                    """INSERT INTO activos(origen, ocs_id, nombre, so_nombre, so_version,
                            so_familia, ip, usuario, entorno, proceso, zona, n_software,
                            presente, primera_vez_at, visto_at, ultimo_inventario)
                       VALUES('servidores',?,?,?,?,'debian',?,?,'produccion',?,'interna',?,1,?,?,?)""",
                    (i, f"srv-{grupo}-{i:03d}", "Debian 12", "12", f"10.0.0.{i}",
                     f"usuario{i}", "Proceso Uno" if i % 3 else "Proceso Dos", 3, ahora,
                     ahora, ahora[:10]))
            cls.activo_ids = [r[0] for r in conn.execute("SELECT id FROM activos ORDER BY id")]

            # --- software: 120 nombres sin clasificar y 120 reglas ------------
            primero = cls.activo_ids[0]
            for i in range(1, N_SIN_CLASIFICAR + 1):
                conn.execute(
                    """INSERT INTO activo_software(activo_id, nombre, nombre_norm, version,
                            technology_id) VALUES(?,?,?,?,NULL)""",
                    (primero, f"Programa Suelto {i:03d}", f"programa suelto {i:03d}", "1.0"))
            for i in range(1, N_REGLAS + 1):
                conn.execute(
                    """INSERT INTO tecnologia_ocs(patron, modo, technology_id, origen, created_at)
                       VALUES(?,'exacto',?,'manual',?)""",
                    (f"regla numero {i:03d}", cls.tec_ids[i % len(cls.tec_ids)], ahora))

            # --- amenazas y remediaciones: 1.234 filas ------------------------
            conn.execute(
                """INSERT INTO threats(fingerprint, cve, title_en, severity, severity_source,
                        first_seen_at, last_seen_at, month, relevance, estado)
                   VALUES('fp-paginacion','CVE-2026-0001','Fallo de prueba','High','nvd',?,?,?,50.0,'nueva')""",
                (ahora, ahora, ahora[:7]))
            cls.threat_id = conn.execute(
                "SELECT id FROM threats WHERE fingerprint='fp-paginacion'").fetchone()[0]
            for i in range(N_REMEDIACIONES):
                activo = cls.activo_ids[i % len(cls.activo_ids)]
                conn.execute(
                    """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete,
                            version_vulnerable, version_corregida, motor, estado,
                            detectado_at, comprobado_at)
                       VALUES(?,?,?,?,'1.0','2.0','osv','abierta',?,?)""",
                    (activo, cls.threat_id, f"CVE-2026-{1000 + i}", f"paquete{i:04d}",
                     ahora, ahora))

            # --- correcciones pendientes: 120 filas ---------------------------
            for i in range(1, N_PARCHES + 1):
                conn.execute(
                    """INSERT INTO parches_pendientes(cve, paquete, ecosistema, threat_id,
                            motivo, n_activos, n_activos_expuestos, detectado_at, intentos)
                       VALUES(?,?,?,?,'sin_parche_publicado',?,?,?,1)""",
                    (f"CVE-2026-{2000 + i}", f"pendiente{i:03d}", "Debian:12", cls.threat_id,
                     i, i % 5, ahora))

        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)
        cls.cli = cls.app.test_client()
        cls.cli.post("/login", data={"usuario": "admin", "password": "AdminSeguro#2026"})

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    # ------------------------------------------------------------------ ayudas
    def _html(self, url: str) -> str:
        """HTML de una página, comprobando de paso HTTP 200 y la CSP estricta."""
        respuesta = self.cli.get(url)
        self.assertEqual(respuesta.status_code, 200, url)
        html = respuesta.get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html), f"style= en {url}")
        self.assertIsNone(RE_ON.search(html), f"on*= en {url}")
        return html

    def _zona(self, html: str, ancla: str) -> str:
        """La zona del listado, desde su identificador hasta el final de la página."""
        self.assertIn(ancla, html)
        return html.split(ancla, 1)[1]

    def _filas(self, html: str, ancla: str) -> int:
        """Filas del primer cuerpo de tabla que aparece tras el identificador."""
        cuerpo = self._zona(html, ancla).split("<tbody>", 1)[1].split("</tbody>", 1)[0]
        return cuerpo.count("<tr")

    def _nav(self, html: str, titulo: str) -> str:
        """El bloque <nav> de una paginación concreta, por su etiqueta accesible."""
        patron = r'<nav class="paginacion" aria-label="' + re.escape(titulo) + r'">.*?</nav>'
        encontrado = re.search(patron, html, re.S)
        self.assertIsNotNone(encontrado, f"sin paginación «{titulo}»")
        return encontrado.group(0)

    def _deshabilitados(self, nav: str) -> set:
        """Los controles no disponibles: botones deshabilitados de verdad, no textos."""
        return set(re.findall(r'<button[^>]*\sdisabled[^>]*>([^<]+)</button>', nav))

    def _enlazados(self, nav: str) -> set:
        return set(re.findall(r'<a class="btn paginacion-boton[^"]*"[^>]*>([^<]+)</a>', nav))


class TestParcialDePaginacion(BasePaginacion):
    """El parcial reutilizable: recuento, controles y accesibilidad."""

    TITULO = "Paginación de la lista de activos"

    def test_texto_con_el_total_y_la_pagina_en_formato_espanol(self):
        nav = self._nav(self._html("/activos/"), self.TITULO)
        self.assertIn("120 activos ·", nav)
        self.assertIn(f"página 1 de {P_ACTIVOS}", nav)
        self.assertIn(f"filas 1 a {POR_PAGINA}", nav)
        # Miles con punto, como el resto de la plataforma
        nav = self._nav(self._html("/remediaciones/?estado=todas"),
                        "Paginación de las actualizaciones")
        self.assertIn("1.234 actualizaciones ·", nav)
        self.assertIn(f"página 1 de {P_REMEDIACIONES}", nav)

    def test_primera_pagina_sin_anterior(self):
        nav = self._nav(self._html("/activos/?pagina=1"), self.TITULO)
        self.assertEqual(self._deshabilitados(nav), {"Primera", "Anterior"})
        self.assertIn("Siguiente", self._enlazados(nav))
        self.assertIn("Última", self._enlazados(nav))
        self.assertIn('aria-current="page"', nav)
        self.assertEqual(nav.count('aria-current="page"'), 1)

    def test_pagina_intermedia_con_los_cuatro_controles(self):
        nav = self._nav(self._html("/activos/?pagina=2"), self.TITULO)
        self.assertEqual(self._deshabilitados(nav), set())
        for texto in ("Primera", "Anterior", "Siguiente", "Última"):
            self.assertIn(texto, self._enlazados(nav))
        self.assertEqual(nav.count('aria-current="page"'), 1)
        self.assertIn(f'aria-label="Página 2 de {P_ACTIVOS}"', nav)

    def test_ultima_pagina_sin_siguiente(self):
        nav = self._nav(self._html(f"/activos/?pagina={P_ACTIVOS}"), self.TITULO)
        self.assertEqual(self._deshabilitados(nav), {"Siguiente", "Última"})
        self.assertIn("Primera", self._enlazados(nav))
        self.assertIn("Anterior", self._enlazados(nav))

    def test_la_pagina_actual_no_es_un_enlace(self):
        """La página en la que ya se está no se enlaza a sí misma."""
        nav = self._nav(self._html("/activos/?pagina=2"), self.TITULO)
        actual = re.search(r'<span class="btn primario paginacion-boton paginacion-actual[^>]*>\s*'
                           r'([^<]+?)\s*</span>', nav)
        self.assertIsNotNone(actual)
        self.assertEqual(actual.group(1), "2")

    def test_los_enlaces_vuelven_a_la_zona_del_listado(self):
        """Cambiar de página deja al operador en la tabla, no al principio de la página."""
        nav = self._nav(self._html("/activos/"), self.TITULO)
        self.assertIn("#lista-activos", nav)

    def test_sin_paginacion_cuando_todo_cabe_en_una_pagina(self):
        html = self._html("/activos/?q=srv-beta-002")
        self.assertIn("1 activo ·", html)
        self.assertIn("página 1 de 1", html)
        self.assertNotIn("Siguiente", self._zona(html, 'id="lista-activos"'))


class TestPaginacionDeActivos(BasePaginacion):

    def test_solo_llegan_las_filas_de_la_pagina_pedida(self):
        self.assertEqual(self._filas(self._html("/activos/"), 'id="lista-activos"'), POR_PAGINA)
        self.assertEqual(self._filas(self._html("/activos/?pagina=2"), 'id="lista-activos"'), POR_PAGINA)
        self.assertEqual(self._filas(self._html(f"/activos/?pagina={P_ACTIVOS}"), 'id="lista-activos"'),
                         filas_ultima(N_ACTIVOS))

    def test_las_paginas_no_se_solapan_ni_pierden_filas(self):
        nombres = []
        for pagina in range(1, P_ACTIVOS + 1):
            html = self._html(f"/activos/?orden=nombre&pagina={pagina}")
            nombres += re.findall(r'data-nombre="(srv-[a-z]+-\d+)"', html)
        self.assertEqual(len(nombres), N_ACTIVOS)
        self.assertEqual(len(set(nombres)), N_ACTIVOS)

    def test_el_recuento_total_es_el_real_y_no_el_de_la_pagina(self):
        html = self._html("/activos/")
        self.assertIn("120 activos con estos filtros", html)
        self.assertIn("120 activos ·", html)

    def test_el_filtro_se_conserva_al_cambiar_de_pagina(self):
        html = self._html("/activos/?q=beta&orden=nombre")
        nav = self._nav(html, "Paginación de la lista de activos")
        self.assertIn("60 activos ·", nav)
        self.assertIn("q=beta", nav)
        self.assertIn("orden=nombre", nav)
        # y la segunda página sigue filtrada
        ultima = n_paginas(60)
        segunda = self._html(f"/activos/?q=beta&orden=nombre&pagina={ultima}")
        nombres = re.findall(r'data-nombre="(srv-[a-z]+-\d+)"', segunda)
        self.assertEqual(len(nombres), filas_ultima(60))
        self.assertTrue(all("beta" in n for n in nombres), nombres)
        self.assertNotIn("srv-alfa", self._zona(segunda, 'id="lista-activos"'))

    def test_el_orden_se_conserva_y_lo_aplica_el_servidor(self):
        html = self._html("/activos/?orden=nombre")
        nombres = re.findall(r'data-nombre="(srv-[a-z]+-\d+)"', html)
        self.assertEqual(nombres, sorted(nombres))
        self.assertIn("orden=nombre", self._nav(html, "Paginación de la lista de activos"))

    def test_la_vista_rapida_filtra_en_el_servidor_y_se_conserva(self):
        html = self._html("/activos/?vista=ausentes")
        self.assertIn('name="vista" value="ausentes"', html)
        self.assertIn("0 activos con estos filtros", html)

    def test_pagina_fuera_de_rango_no_da_error(self):
        primera, ultima = f"página 1 de {P_ACTIVOS}", f"página {P_ACTIVOS} de {P_ACTIVOS}"
        for sufijo, esperado in (("pagina=0", primera), ("pagina=-4", primera),
                                 ("pagina=abc", primera), ("pagina=99999", ultima),
                                 ("pagina=", primera)):
            html = self._html(f"/activos/?{sufijo}")
            self.assertIn(esperado, html, sufijo)

    def test_la_exportacion_csv_sigue_completa(self):
        respuesta = self.cli.get("/activos/exportar.csv")
        self.assertEqual(respuesta.status_code, 200)
        lineas = respuesta.get_data(as_text=True).strip().splitlines()
        self.assertEqual(len(lineas), N_ACTIVOS + 1, "cabecera y todas las filas")
        respuesta = self.cli.get("/activos/exportar.csv?q=beta")
        self.assertEqual(len(respuesta.get_data(as_text=True).strip().splitlines()), 61)


class TestPaginacionDeSoftware(BasePaginacion):
    """Los tres listados de la página de Software, cada uno con su número de página."""

    def test_software_sin_clasificar(self):
        html = self._html("/activos/software")
        self.assertEqual(self._filas(html, 'id="sin-clasificar"'), POR_PAGINA)
        nav = self._nav(html, "Paginación del software sin clasificar")
        self.assertIn("120 nombres sin clasificar ·", nav)
        self.assertEqual(self._filas(self._html(f"/activos/software?pagina={P_SIN_CLASIFICAR}"),
                                     'id="sin-clasificar"'), 20)

    def test_reglas_del_mapa_de_nombres(self):
        html = self._html("/activos/software")
        self.assertEqual(self._filas(html, 'id="reglas-del-mapa"'), POR_PAGINA)
        nav = self._nav(html, "Paginación de las reglas del mapa de nombres")
        self.assertIn("120 reglas ·", nav)
        self.assertIn("pagina_reglas=2", nav)
        html = self._html("/activos/software?pagina_reglas=3")
        self.assertEqual(self._filas(html, 'id="reglas-del-mapa"'), 20)

    def test_tecnologias_con_activos(self):
        html = self._html("/activos/software")
        self.assertEqual(self._filas(html, 'id="tecnologias-con-activos"'), POR_PAGINA)
        nav = self._nav(html, "Paginación de las tecnologías con activos")
        self.assertIn("120 tecnologías con activos ·", nav)
        self.assertIn("pagina_tecnologias=2", nav)

    def test_cada_listado_conserva_la_pagina_de_los_otros(self):
        html = self._html("/activos/software?pagina=2&pagina_reglas=3&pagina_tecnologias=2")
        self.assertIn(f"página 2 de {P_SIN_CLASIFICAR}",
                      self._nav(html, "Paginación del software sin clasificar"))
        self.assertIn(f"página 3 de {P_REGLAS}",
                      self._nav(html, "Paginación de las reglas del mapa de nombres"))
        self.assertIn("página 2 de ", self._nav(html, "Paginación de las tecnologías con activos"))
        nav = self._nav(html, "Paginación de las reglas del mapa de nombres")
        self.assertIn("pagina=2", nav)
        self.assertIn("pagina_tecnologias=2", nav)

    def test_el_buscador_se_conserva_entre_paginas(self):
        html = self._html("/activos/software?q=programa+suelto+0")
        nav = self._nav(html, "Paginación del software sin clasificar")
        self.assertIn("q=programa+suelto+0", nav)
        self.assertIn("99 nombres sin clasificar ·", nav)

    def test_pagina_fuera_de_rango_no_da_error(self):
        for sufijo in ("pagina=0", "pagina=99999", "pagina_reglas=abc",
                       "pagina_tecnologias=-2", "pagina=99999&pagina_reglas=0"):
            self._html(f"/activos/software?{sufijo}")


class TestPaginacionDelInventario(BasePaginacion):

    def test_solo_llegan_las_filas_de_la_pagina_pedida(self):
        self.assertEqual(self._filas(self._html("/tecnologias/"), 'id="tabla-tecnologias"'),
                         POR_PAGINA_TECNOLOGIAS)
        self.assertEqual(self._filas(self._html(f"/tecnologias/?pagina={P_TECNOLOGIAS}"),
                                     'id="tabla-tecnologias"'), 20)

    def test_el_pie_de_la_tabla_habla_del_filtro_completo_no_de_la_pagina(self):
        """Con paginación, el pie tiene que hablar de las 120, no de las 20 que se ven.

        Adaptado el 2026-09-15 (auditoría de tableros, punto 4): el pie ya NO suma la
        columna «Sistemas». Sumarla contaba el mismo activo una vez por cada tecnología
        que tiene instalada (22.236 «sistemas» en un parque de 730 máquinas en
        producción) y ni siquiera coincidía con la columna que se ve, que enseña los
        activos de OCS Inventory y no ``systems_count``. En su lugar, el pie enseña los
        activos DISTINTOS del parque que tienen alguna de las tecnologías del filtro; en
        este escenario no hay software instalado, así que son cero.
        """
        html = self._html("/tecnologias/")
        pie = html.split("<tfoot>")[-1]
        self.assertIn("120 tecnologías", pie)
        self.assertIn("60 con versión registrada", pie)
        # la suma de systems_count (1 a 120) ya no se escribe en ninguna parte
        suma_antigua = f"{sum(range(1, N_TECNOLOGIAS + 1)):,}".replace(",", ".")
        self.assertNotIn(suma_antigua, html)
        self.assertIn("Activos distintos del parque", pie)

    def test_el_filtro_se_conserva_entre_paginas(self):
        html = self._html("/tecnologias/?sin_version=1")
        nav = self._nav(html, "Paginación del inventario de tecnologías")
        self.assertIn("60 tecnologías ·", nav)
        self.assertIn("sin_version=1", nav)
        ultima = n_paginas(60, POR_PAGINA_TECNOLOGIAS)
        segunda = self._html(f"/tecnologias/?sin_version=1&pagina={ultima}")
        self.assertEqual(self._filas(segunda, 'id="tabla-tecnologias"'),
                         filas_ultima(60, POR_PAGINA_TECNOLOGIAS))

    def test_pagina_fuera_de_rango_no_da_error(self):
        self.assertIn(f"página 1 de {P_TECNOLOGIAS}", self._html("/tecnologias/?pagina=0"))
        self.assertIn(f"página {P_TECNOLOGIAS} de {P_TECNOLOGIAS}",
                      self._html("/tecnologias/?pagina=77"))

    def test_la_exportacion_csv_sigue_completa(self):
        respuesta = self.cli.get("/tecnologias/exportar.csv")
        self.assertEqual(respuesta.status_code, 200)
        lineas = respuesta.get_data(as_text=True).strip().splitlines()
        self.assertEqual(len(lineas), N_TECNOLOGIAS + 1)


class TestPaginacionDeFuentes(BasePaginacion):

    def test_solo_llegan_las_filas_de_la_pagina_pedida(self):
        self.assertEqual(self._filas(self._html("/fuentes/"), 'id="catalogo-fuentes"'),
                         POR_PAGINA_FUENTES)
        self.assertEqual(self._filas(self._html(f"/fuentes/?pagina={P_FUENTES}"),
                                     'id="catalogo-fuentes"'),
                         filas_ultima(N_FUENTES, POR_PAGINA_FUENTES))

    def test_el_recuento_del_catalogo_cuenta_todas_las_fuentes(self):
        """Los indicadores y el pie siguen hablando de las 120, no de las 50 de la página."""
        html = self._html("/fuentes/")
        self.assertIn("120 fuentes", html.split("<tfoot>")[-1])
        self.assertIn("120 fuentes ·", self._nav(html, "Paginación del catálogo de fuentes"))
        self.assertIn('<div class="valor">120</div>', html)

    def test_pagina_fuera_de_rango_no_da_error(self):
        self.assertIn(f"página 1 de {P_FUENTES}", self._html("/fuentes/?pagina=-1"))
        self.assertIn(f"página {P_FUENTES} de {P_FUENTES}", self._html("/fuentes/?pagina=4000"))


class TestPaginacionDeRemediaciones(BasePaginacion):
    """La dirección por omisión de /remediaciones/ es la vista AGRUPADA, en la que cada
    fila es una actualización (un activo y un paquete) y no una vulnerabilidad.

    El 2026-09-08 estas pruebas exigían el texto «1.234 remediaciones ·» en el pie de esa
    vista, y ese era el motivo por el que el pie seguía diciendo «remediaciones» a veinte
    píxeles de una cabecera que decía «19.284 actualizaciones que cubren 47.526
    remediaciones»: la misma palabra para dos magnitudes distintas, que es la ambigüedad
    de la que se quejó el usuario. Se adaptaron a «actualizaciones» junto con la
    plantilla; el pie de la vista por vulnerabilidad y el de la ficha del activo siguen
    diciendo «remediaciones», que es lo que listan.

    En esta base de pruebas cada remediación tiene un paquete distinto, así que los grupos
    también son 1.234 y las cifras no cambian: lo que cambia es el nombre.
    """

    def test_solo_llegan_las_filas_de_la_pagina_pedida(self):
        html = self._html("/remediaciones/?estado=todas")
        self.assertEqual(self._filas(html, 'id="tabla-remediaciones"'), POR_PAGINA_REMEDIACIONES)
        html = self._html(f"/remediaciones/?estado=todas&pagina={P_REMEDIACIONES}")
        self.assertEqual(self._filas(html, 'id="tabla-remediaciones"'),
                         filas_ultima(N_REMEDIACIONES, POR_PAGINA_REMEDIACIONES))

    def test_las_paginas_no_se_solapan(self):
        primera = set(re.findall(r"CVE-2026-\d+", self._zona(
            self._html("/remediaciones/?estado=todas"), 'id="tabla-remediaciones"')))
        segunda = set(re.findall(r"CVE-2026-\d+", self._zona(
            self._html("/remediaciones/?estado=todas&pagina=2"), 'id="tabla-remediaciones"')))
        self.assertEqual(len(primera & segunda), 0)

    def test_el_total_sale_de_un_recuento_no_de_las_filas(self):
        html = self._html("/remediaciones/?estado=todas")
        self.assertIn("1.234 filas", html)
        self.assertIn("1.234 actualizaciones ·", self._nav(html, "Paginación de las actualizaciones"))

    def test_el_filtro_se_conserva_entre_paginas(self):
        html = self._html("/remediaciones/?estado=todas&q=paquete00")
        nav = self._nav(html, "Paginación de las actualizaciones")
        self.assertIn("100 actualizaciones ·", nav)       # paquete0000 … paquete0099
        self.assertIn("estado=todas", nav)
        self.assertIn("q=paquete00", nav)
        segunda = self._zona(self._html("/remediaciones/?estado=todas&q=paquete00&pagina=2"),
                             'id="tabla-remediaciones"')
        paquetes = re.findall(r"paquete\d{4}", segunda)
        self.assertEqual(len(paquetes), POR_PAGINA_REMEDIACIONES)
        self.assertTrue(all(p.startswith("paquete00") for p in paquetes), paquetes)

    def test_pagina_fuera_de_rango_no_da_error(self):
        self.assertIn(f"página 1 de {P_REMEDIACIONES}",
                      self._html("/remediaciones/?estado=todas&pagina=0"))
        self.assertIn(f"página {P_REMEDIACIONES} de {P_REMEDIACIONES}",
                      self._html("/remediaciones/?estado=todas&pagina=9999"))

    def test_la_exportacion_csv_no_se_pagina(self):
        respuesta = self.cli.get("/remediaciones/exportar.csv?estado=todas")
        self.assertEqual(respuesta.status_code, 200)
        lineas = respuesta.get_data(as_text=True).strip().splitlines()
        self.assertEqual(len(lineas), N_REMEDIACIONES + 1)


class TestPaginacionDeCorreccionesPendientes(BasePaginacion):

    def test_solo_llegan_las_filas_de_la_pagina_pedida(self):
        self.assertEqual(self._filas(self._html("/parches-pendientes/"), 'id="tabla-parches"'),
                         POR_PAGINA_PARCHES)
        self.assertEqual(self._filas(self._html(f"/parches-pendientes/?pagina={P_PARCHES}"),
                                     'id="tabla-parches"'), 20)

    def test_el_total_y_el_numero_de_paginas(self):
        nav = self._nav(self._html("/parches-pendientes/"),
                        "Paginación de las correcciones pendientes")
        self.assertIn("120 correcciones pendientes ·", nav)
        self.assertIn(f"página 1 de {P_PARCHES}", nav)

    def test_el_filtro_se_conserva_entre_paginas(self):
        html = self._html("/parches-pendientes/?q=pendiente0")
        nav = self._nav(html, "Paginación de las correcciones pendientes")
        self.assertIn("q=pendiente0", nav)
        self.assertIn("99 correcciones pendientes ·", nav)

    def test_pagina_fuera_de_rango_no_da_error(self):
        self.assertIn(f"página 1 de {P_PARCHES}", self._html("/parches-pendientes/?pagina=0"))
        self.assertIn(f"página {P_PARCHES} de {P_PARCHES}",
                      self._html("/parches-pendientes/?pagina=800"))


# ==========================================================================
# Segunda ronda: hallazgos del revisor (2026-09-07)
# ==========================================================================
#: Las seis direcciones de los listados paginados, con mas de una pagina cada una.
LISTADOS = ("/activos/", "/activos/software", "/tecnologias/", "/fuentes/",
            "/remediaciones/?estado=todas", "/parches-pendientes/")


class TestArgumentosReservadosDeUrlFor(BasePaginacion):
    """Hallazgo alto: un parametro llamado como un argumento reservado de ``url_for``
    («_anchor», «endpoint», «_method») llegaba dos veces a la llamada y tumbaba los
    seis listados con un error 500. No son filtros: se descartan."""

    def _con(self, url: str, extra: str) -> str:
        return url + ("&" if "?" in url else "?") + extra

    def test_los_seis_listados_aguantan_anchor_endpoint_y_method(self):
        for url in LISTADOS:
            for extra in ("_anchor=x", "endpoint=x", "_method=POST", "values=x",
                          "_scheme=https", "_external=1", "_anchor=x&endpoint=y"):
                with self.subTest(url=url, extra=extra):
                    self._html(self._con(url, extra))

    def test_no_se_cuelan_en_los_enlaces_de_la_paginacion(self):
        nav = self._nav(self._html("/activos/?_anchor=x&endpoint=y&q=beta"),
                        "Paginación de la lista de activos")
        self.assertIn("q=beta", nav)
        self.assertNotIn("endpoint=", nav)
        self.assertNotIn("_anchor=x", nav)          # el ancla la pone el parcial
        self.assertIn("#lista-activos", nav)

    def test_tampoco_en_la_exportacion_de_activos(self):
        """La exportación también expande los argumentos conservados: sin filtrarlos
        el enlace reventaba la página antes de pintarse."""
        html = self._html("/activos/?endpoint=x&q=beta")
        self.assertIn('href="/activos/exportar.csv?q=beta"', html)
        self.assertEqual(self.cli.get("/activos/exportar.csv?endpoint=x").status_code, 200)


class TestBusquedaEnVivoCoherente(BasePaginacion):
    """Hallazgo alto: la búsqueda en vivo sustituye una zona de la página, así que todo
    lo que depende de los filtros tiene que estar DENTRO de esa zona; si no, quedan a
    la vista el recuento, los atajos y la exportación de la búsqueda anterior."""

    def _zona_de(self, html: str, ancla: str) -> str:
        """Solo la zona que sustituye la búsqueda en vivo (hasta el fin del panel)."""
        return self._zona(html, ancla)

    def test_el_formulario_de_filtros_esta_fuera_de_la_zona(self):
        """Si se sustituyera, se perderían los escuchadores que le engancha app.js."""
        html = self._html("/activos/")
        self.assertLess(html.index('data-filtro-vivo="lista-activos"'),
                        html.index('id="lista-activos"'))

    def test_el_recuento_los_atajos_y_la_exportacion_estan_dentro(self):
        html = self._html("/activos/")
        zona = self._zona_de(html, 'id="lista-activos"')
        for texto in ("120 activos con estos filtros", 'data-vista="afectados"',
                      'data-vista="todos"', "/activos/exportar.csv", "Vistas rápidas"):
            self.assertIn(texto, zona, texto)

    def test_los_atajos_conservan_el_texto_buscado(self):
        """Pulsar una vista rápida después de escribir no puede perder la búsqueda."""
        zona = self._zona_de(self._html("/activos/?q=beta"), 'id="lista-activos"')
        self.assertIn('<input type="hidden" name="q" value="beta">', zona)
        self.assertIn("60 activos con estos filtros", zona)
        self.assertIn('href="/activos/exportar.csv?q=beta"', zona)

    def test_el_inventario_no_deja_el_recuento_fuera_de_la_zona(self):
        """En Inventario y en Software el recuento vive en la paginación y en el pie,
        ambos dentro de la zona que se sustituye."""
        html = self._html("/tecnologias/")
        cabecera = (html.split("<h2>Tecnologías monitorizadas</h2>")[1]
                        .split('id="tabla-tecnologias"')[0])
        self.assertNotIn("120 tecnología", cabecera)
        self.assertNotIn("página",
                         cabecera.replace(f"páginas de {POR_PAGINA_TECNOLOGIAS} tecnologías", ""))
        self.assertIn("120 tecnologías ·", self._nav(html, "Paginación del inventario de tecnologías"))
        html = self._html("/activos/software")
        cabecera = (html.split("<h2>Software sin clasificar</h2>")[1]
                        .split('id="sin-clasificar"')[0])
        self.assertNotIn("120 nombre", cabecera)
        self.assertIn("120 nombres sin clasificar ·",
                      self._nav(html, "Paginación del software sin clasificar"))


class TestComodinesDelTextoBuscado(BasePaginacion):
    """Hallazgo medio: sin ``ESCAPE`` el «%» y el «_» del buscador eran comodines, así
    que buscar «%» devolvía la lista completa."""

    def test_activos(self):
        for texto in ("%25", "_", "%25beta%25"):
            with self.subTest(texto=texto):
                html = self._html(f"/activos/?q={texto}")
                self.assertIn("0 activos con estos filtros", html)
                self.assertNotIn("<tr data-id=", self._zona(html, 'id="tabla-activos"'))
        # y el texto literal sí encuentra los activos que lo llevan
        self.assertIn("60 activos con estos filtros", self._html("/activos/?q=beta"))

    def test_la_exportacion_de_activos_tambien(self):
        respuesta = self.cli.get("/activos/exportar.csv?q=%25")
        self.assertEqual(respuesta.status_code, 200)
        lineas = respuesta.get_data(as_text=True).strip().splitlines()
        self.assertEqual(len(lineas), 1, "solo la cabecera")

    def test_inventario_de_tecnologias(self):
        zona = self._zona(self._html("/tecnologias/?q=%25"), 'id="tabla-tecnologias"')
        self.assertIn("Ningún resultado para «%».", zona)
        self.assertNotIn("<tbody>", zona)

    def test_software_sin_clasificar_y_reglas(self):
        html = self._html("/activos/software?q=%25")
        self.assertIn("Ningún nombre sin clasificar contiene «%».", html)
        self.assertIn("Ninguna regla coincide con «%».", html)
        self.assertIn("0 reglas ", html)    # el recuento del panel de reglas


class TestAccesibilidadDelParcial(BasePaginacion):
    """Hallazgos bajos: los controles no disponibles tienen que ser botones
    deshabilitados de verdad, los números de las etiquetas accesibles van en formato
    español, la elipsis se anuncia y el destino del ancla es enfocable."""

    def test_los_no_disponibles_son_botones_deshabilitados(self):
        nav = self._nav(self._html("/activos/"), "Paginación de la lista de activos")
        self.assertNotIn("aria-disabled", nav)
        self.assertEqual(self._deshabilitados(nav), {"Primera", "Anterior"})
        self.assertIn('aria-label="Primera página: ya está en ella"', nav)
        self.assertIn('aria-label="Página anterior: ya está en la primera"', nav)

    def test_la_elipsis_se_anuncia_a_un_lector_de_pantalla(self):
        nav = self._nav(self._html("/remediaciones/?estado=todas&pagina=13"),
                        "Paginación de las actualizaciones")
        self.assertIn('<span aria-hidden="true">…</span>', nav)
        self.assertIn('<span class="oculto-visual">páginas intermedias omitidas</span>', nav)

    def test_los_numeros_de_las_etiquetas_van_en_formato_espanol(self):
        from unittest import mock
        from webui.vistas import remediaciones as vista
        with mock.patch.object(vista, "LIMITE_PAGINA", 1):
            html = self._html("/remediaciones/?estado=todas&pagina=1200")
        nav = self._nav(html, "Paginación de las actualizaciones")
        self.assertIn('aria-label="Página 1.200 de 1.234"', nav)
        self.assertIn('aria-label="Página anterior, la 1.199"', nav)
        self.assertIn('aria-label="Última página, la 1.234"', nav)
        self.assertIn("1.234 actualizaciones ·", nav)

    def test_la_zona_de_destino_del_ancla_es_enfocable(self):
        """Con «tabindex=-1» quien navega con el teclado sigue en la tabla."""
        for url, ancla in (("/activos/", "lista-activos"),
                           ("/tecnologias/", "tabla-tecnologias"),
                           ("/fuentes/", "catalogo-fuentes"),
                           ("/remediaciones/?estado=todas", "tabla-remediaciones"),
                           ("/parches-pendientes/", "tabla-parches"),
                           ("/activos/software", "sin-clasificar")):
            with self.subTest(url=url):
                html = self._html(url)
                self.assertRegex(html, r'id="' + ancla + r'" tabindex="-1"')


class TestTopeDeFilasLeidas(BasePaginacion):
    """Red de seguridad: si ``remediacion.listar`` dejara de aceptar ``desplazamiento``,
    la última página de una lista muy larga se alcanzaría leyendo TODAS las filas
    anteriores (medido por el revisor: +118 MB de memoria). La vista tiene un tope y la
    página lo explica.

    Desde el 2026-09-07 ``threatintel.remediacion.listar`` SÍ acepta ``desplazamiento``
    (lo añadió el coordinador con «LIMIT ? OFFSET ?»), así que en producción esta rama
    no se recorre. Estas pruebas la fuerzan a propósito para que la red siga cubierta:
    sin esto, quitar el parámetro del módulo no rompería ninguna prueba."""

    def test_con_tope_la_lista_se_acota_y_se_explica(self):
        from unittest import mock
        from webui.vistas import remediaciones as vista
        with mock.patch.object(vista, "TOPE_SIN_DESPLAZAMIENTO", 100), \
             mock.patch.object(vista, "_admite_desplazamiento", return_value=False):
            html = self._html("/remediaciones/?estado=todas")
            nav = self._nav(html, "Paginación de las actualizaciones")
            self.assertIn("1.234 actualizaciones ·", nav)      # el total sigue siendo el real
            self.assertIn(f"página 1 de {n_paginas(100, POR_PAGINA_REMEDIACIONES)}", nav)
            self.assertIn("En pantalla se pueden recorrer las primeras", html)
            self.assertIn("100 filas de las 1.234", html)
            self.assertIn("exporte el CSV", html)
            # una página más allá del tope se atiende con la última alcanzable
            alcanzables = n_paginas(100, POR_PAGINA_REMEDIACIONES)
            profunda = self._html("/remediaciones/?estado=todas&pagina=999")
            self.assertIn(f"página {alcanzables} de {alcanzables}", profunda)
            self.assertEqual(self._filas(profunda, 'id="tabla-remediaciones"'),
                             POR_PAGINA_REMEDIACIONES)

    def test_sin_tope_no_hay_aviso_ni_recorte(self):
        """El camino real desde el 2026-09-07: con «desplazamiento» no hay tope ni aviso
        y se pueden recorrer las 25 páginas."""
        html = self._html("/remediaciones/?estado=todas")
        self.assertNotIn("En pantalla se pueden recorrer las primeras", html)
        self.assertIn(f"página 1 de {P_REMEDIACIONES}", html)

    def test_el_modulo_acepta_desplazamiento(self):
        """Si alguien quita el parámetro, la vista vuelve a la rama con tope y la última
        página cuesta cuatro veces más. Esta prueba lo deja escrito."""
        import inspect
        from threatintel import parches, remediacion
        for funcion in (remediacion.listar, parches.listar):
            self.assertIn("desplazamiento", inspect.signature(funcion).parameters,
                          f"{funcion.__module__}.listar debe aceptar «desplazamiento»")

    def test_el_csv_no_se_ve_afectado_por_el_tope(self):
        from unittest import mock
        from webui.vistas import remediaciones as vista
        with mock.patch.object(vista, "TOPE_SIN_DESPLAZAMIENTO", 100):
            respuesta = self.cli.get("/remediaciones/exportar.csv?estado=todas")
        self.assertEqual(len(respuesta.get_data(as_text=True).strip().splitlines()),
                         N_REMEDIACIONES + 1)


class TestNombreDeLoQueSeLista(BasePaginacion):
    """Hallazgo bajo: «120 filas · página 1 de N · filas 1 a N» repetía la palabra
    «filas» con dos significados y no decía qué se estaba listando."""

    def test_correcciones_pendientes(self):
        html = self._html("/parches-pendientes/")
        self.assertIn("120 correcciones pendientes ·",
                      self._nav(html, "Paginación de las correcciones pendientes"))
        self.assertIn("120 correcciones pendientes", html)
        self.assertNotIn("120 filas", html)

    def test_correcciones_ya_encontradas(self):
        html = self._html("/parches-pendientes/?estado=encontradas")
        self.assertIn("0 correcciones encontradas", html)


class TestOrdenTotalDeLaPaginacion(BasePaginacion):
    """Hallazgo bajo: un ORDER BY con empates no define un orden total, así que con
    LIMIT/OFFSET una fila podría salir en dos páginas y otra en ninguna. Los 120
    activos de prueba comparten fecha de inventario."""

    def test_ningun_activo_se_repite_ni_se_pierde_con_fechas_iguales(self):
        vistos = []
        for pagina in range(1, P_ACTIVOS + 1):
            html = self._html(f"/activos/?orden=conexion&pagina={pagina}")
            vistos += re.findall(r'<tr data-id="(\d+)"', self._zona(html, 'id="lista-activos"'))
        self.assertEqual(len(vistos), N_ACTIVOS)
        self.assertEqual(len(set(vistos)), N_ACTIVOS)


class TestOrdenTotalDeLaVistaAgrupada(unittest.TestCase):
    """El orden de la vista agrupada terminaba en ``a.nombre, r.paquete``, y hay activos
    DISTINTOS con el mismo nombre en las dos bases de OCS: 58 pares en producción el
    2026-09-08, con el mismo paquete, la misma severidad, el mismo entorno y la misma
    detección. Con la clave de orden empatada, SQLite podía devolver el mismo grupo en dos
    páginas y perder otro, y nadie lo notaría entre 965 páginas. Ahora el orden termina en
    ``r.activo_id``, que junto al paquete es la clave del grupo y es única.

    Base propia: estas filas alterarían el recuento exacto de activos de las demás pruebas.
    """

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "orden.db")
        db.init_db(self.ruta)
        self.addCleanup(self.dir.cleanup)

    def test_dos_activos_con_el_mismo_nombre_y_paquete_no_se_pisan(self):
        from threatintel import remediacion
        with db.session(self.ruta) as conn:
            ahora = db.utcnow()
            ids = []
            # Dos activos DISTINTOS con el mismo nombre: es lo que ocurre de verdad con
            # las dos bases de OCS (el ocs_id es el que los diferencia, no el nombre).
            for i, (nombre, ocs_id) in enumerate((("GEMELO-01", 101), ("GEMELO-01", 202),
                                                  ("OTRO-02", 303))):
                cur = conn.execute(
                    """INSERT INTO activos(nombre, ip, origen, entorno, presente, so_familia,
                                           ocs_id, primera_vez_at, visto_at)
                       VALUES(?, ?, 'servidores', 'produccion', 1, 'debian', ?, ?, ?)""",
                    (nombre, f"10.0.0.{9 + i}", ocs_id, ahora, ahora))
                ids.append(int(cur.lastrowid))
            for activo_id in ids:
                conn.execute(
                    """INSERT INTO remediaciones(activo_id, cve, paquete, version_vulnerable,
                                                 version_corregida, estado, detectado_at,
                                                 comprobado_at)
                       VALUES(?, 'CVE-2026-99999', 'openssl', '1.0', '2.0', 'abierta',
                              '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')""", (activo_id,))
            vistos = []
            for pagina in range(3):
                grupos = remediacion.listar_actualizaciones(
                    conn, estado="abierta", limite=2, desplazamiento=pagina * 2)
                if not grupos:
                    break
                vistos += [g["clave"] for g in grupos]
        self.assertEqual(len(vistos), 3, "faltan grupos o sobran")
        self.assertEqual(len(vistos), len(set(vistos)), "un grupo se repitió en dos páginas")
        for activo_id in ids:
            self.assertIn(f"{activo_id}-openssl", vistos)


class TestPaginacionDeLaFichaDelActivo(BasePaginacion):
    """La ficha de un activo tenía cuatro listados largos sin paginar: amenazas
    evaluadas (hasta 300 de una vez), remediaciones (100), reglas de configuración que
    no cumple (150) y software instalado. El usuario pidió el 2026-09-07 que también se
    pagine «de a 20». Cada listado lleva su propio parámetro de página para poder
    avanzar en uno sin perder el sitio en los demás.

    Adaptada el 2026-09-09: son TRES listados. La tabla «Amenazas evaluadas para este
    activo» se retiró porque listaba también los veredictos que NO afectan («no me sirve
    que me muestre lo que no me afecta»), y con ella su parámetro ``pagina_cve``; la
    sustituye la tabla de actualizaciones, que no se pagina porque un activo tiene
    decenas, no cientos (36 en el peor caso de producción), y cuando pasa del tope la
    ficha enlaza a Remediación acotada a ese activo, que sí pagina."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Un activo con 60 filas evaluadas y 60 remediaciones propias
        with db.session(cls.ruta) as conn:
            cls.ficha_id = cls.activo_ids[0]
            ahora = conn.execute("SELECT datetime('now')").fetchone()[0].replace(" ", "T") + "Z"
            for i in range(60):
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                            version_instalada, version_corregida, veredicto, motor, evaluado_at)
                       VALUES(?,?,?,?,'1.0','2.0','afectado','osv',?)""",
                    (cls.ficha_id, cls.threat_id, f"CVE-2026-{7000 + i}", f"ficha{i:03d}", ahora))
                conn.execute(
                    """INSERT INTO activo_software(activo_id, nombre, nombre_norm, version)
                       VALUES(?,?,?,'1.0')""",
                    (cls.ficha_id, f"Programa {i:03d}", f"programa {i:03d}"))
                # Remediaciones propias de este activo: las de la base común se
                # reparten entre los 120 y a este le tocan pocas.
                conn.execute(
                    """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete,
                            version_vulnerable, version_corregida, motor, estado,
                            detectado_at, comprobado_at)
                       VALUES(?,?,?,?,'1.0','2.0','osv','abierta',?,?)""",
                    (cls.ficha_id, cls.threat_id, f"CVE-2026-{7000 + i}",
                     f"ficha{i:03d}", ahora, ahora))

    def _ficha(self, sufijo: str = "") -> str:
        return self._html(f"/activos/{self.ficha_id}{sufijo}")

    def _cuerpo(self, html: str, ancla: str) -> str:
        """El <tbody> de ESE listado, acotado: la ficha tiene varias tablas seguidas y
        buscar «desde el identificador hasta el final» mezclaría unas con otras."""
        self.assertIn(ancla, html)
        tras = html.split(ancla, 1)[1]
        self.assertIn("<tbody>", tras, f"el listado «{ancla}» no tiene filas")
        return tras.split("<tbody>", 1)[1].split("</tbody>", 1)[0]

    def test_los_listados_se_paginan_de_a_veinte(self):
        # El software sin clasificar solo se lista con la casilla «todo»: por defecto la
        # ficha muestra únicamente los programas ya clasificados en una tecnología.
        html = self._ficha("?todo=1")
        for ancla, cuantas in (('id="remediaciones-lista"', POR_PAGINA),
                               ('id="tabla-software-activo"', SOFTWARE_POR_PAGINA)):
            with self.subTest(ancla=ancla):
                self.assertEqual(self._cuerpo(html, ancla).count("<tr"), cuantas)
        # La tabla de actualizaciones no se pagina y ya no existe la de veredictos.
        self.assertNotIn('id="cve-evaluados"', html)
        self.assertIn('id="actualizaciones-activo"', html)

    def test_cada_listado_conserva_la_pagina_de_los_otros(self):
        """Lo que el usuario pidió: avanzar en uno sin perder el sitio en los demás."""
        html = self._ficha("?pagina_rem=2&pagina_soft=2&todo=1")
        rem = self._nav(html, "Paginación de las remediaciones del activo")
        soft = self._nav(html, "Paginación del software instalado")
        self.assertIn("página 2 de", rem)
        self.assertIn("página 2 de", soft)
        # y el enlace de cada uno lleva la página del otro
        self.assertIn("pagina_soft=2", rem)
        self.assertIn("pagina_rem=2", soft)

    def test_solo_llegan_las_filas_de_la_pagina_pedida(self):
        primera = re.findall(r"CVE-2026-(\d{4})",
                             self._cuerpo(self._ficha(), 'id="remediaciones-lista"'))
        segunda = re.findall(r"CVE-2026-(\d{4})",
                             self._cuerpo(self._ficha("?pagina_rem=2"), 'id="remediaciones-lista"'))
        self.assertTrue(primera and segunda)
        self.assertFalse(set(primera) & set(segunda), "una fila sale en dos páginas")

    def test_pagina_fuera_de_rango_no_da_error(self):
        for sufijo in ("?pagina_rem=0", "?pagina_rem=-3", "?pagina_rem=abc",
                       "?pagina_rem=99999", "?pagina_soft=99999",
                       "?pagina_scap=99999", "?pagina_rem=",
                       # un parámetro que ya no existe no puede romper la página
                       "?pagina_cve=99999"):
            with self.subTest(sufijo=sufijo):
                self.assertIn("Paginación de las remediaciones del activo",
                              self._ficha(sufijo))

    def test_el_filtro_del_software_se_conserva_y_acota_el_total(self):
        """Al cambiar de página, el filtro escrito tiene que viajar en el enlace."""
        html = self._ficha("?soft=programa&todo=1")
        nav = self._nav(html, "Paginación del software instalado")
        self.assertIn("soft=programa", nav, "el filtro no viaja en los enlaces de página")
        self.assertIn("programas ·", nav)
        self.assertEqual(self._cuerpo(html, 'id="tabla-software-activo"').count("<tr"),
                         SOFTWARE_POR_PAGINA)
        # el total del recuento es el del filtro, y un filtro más estrecho lo reduce
        def total(sufijo):
            texto = self._nav(self._ficha(sufijo), "Paginación del software instalado")
            return int(re.search(r"([\d.]+) programas ·", texto).group(1).replace(".", ""))
        self.assertLess(total("?soft=programa+00&todo=1"), total("?soft=programa&todo=1"))

    def test_el_recuento_es_el_real_y_no_el_de_la_pagina(self):
        nav = self._nav(self._ficha(), "Paginación de las remediaciones del activo")
        self.assertRegex(nav, r"\d+ remediaciones ·")
        self.assertNotIn(f"{POR_PAGINA} remediaciones ·", nav)

    def test_los_modulos_aceptan_desplazamiento(self):
        """Sin «desplazamiento» la ficha volvería a traer las 300 filas de una vez."""
        import inspect
        from threatintel import aplicabilidad, openscap, remediacion
        for funcion in (aplicabilidad.veredictos_de_activo, remediacion.historial_activo,
                        openscap.fallos_activo):
            self.assertIn("desplazamiento", inspect.signature(funcion).parameters,
                          f"{funcion.__module__}.{funcion.__name__}")


if __name__ == "__main__":
    unittest.main()
