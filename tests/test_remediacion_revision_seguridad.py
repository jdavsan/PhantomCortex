"""Hallazgos de la revisión adversaria de seguridad del 2026-09-09 sobre Remediación.

La revisión rechazó el cambio de ese día con ocho hallazgos. Cada prueba de aquí fija uno
para que no vuelva, con la medida que lo justifica:

1. ALTO · denegación de servicio autenticada. «GET /remediaciones/?q=w» devolvía 7,81 MiB
   y «?q=windows» 8,32 MiB, con 1,9 s de proceso, y lo alcanzaba hasta el perfil de solo
   lectura: el límite de veinte acotaba FILAS, no CONTENIDO, y las veinte actualizaciones
   de la página sumaban 17.030 vulnerabilidades (la mayor, 1.358 en un solo equipo
   Windows). Ahora se pintan las primeras ``LIMITE_CVES_GRUPO`` de cada una, la página
   dice cuántas quedan y dónde están, y las cifras y la versión objetivo siguen saliendo
   de TODAS las filas del grupo.
2. MEDIO · un botón que nunca funcionaba. El tope por petición era 1.000 y hay ocho
   actualizaciones por encima (la mayor de 1.358), así que se pintaba «Ya se actualizó:
   comprobar las 1.358» y la petición siempre respondía con el aviso del tope. El tope
   sube a 2.000 y, mientras exista, la fila que lo supere no pinta acciones de grupo: lo
   explica y enlaza donde sí se puede trabajar.
3. MEDIO · el plan en texto venía duplicado: la página decía «40 grupos de remediación» y
   el fichero descargado traía 105 bloques. La fusión se hace ahora dentro de
   ``aplicabilidad.plan_remediacion`` y de ``plan_remediacion_texto``, así que la reciben
   todos los que llaman.
4. MEDIO · una nota de grupo escribía 797 entradas de auditoría (una por fila). Ahora
   queda UNA por acción, con el recuento, el activo y los paquetes, y la misma nota
   repetida sobre el mismo grupo se rechaza.
5. MEDIO · «/remediaciones/<id>/nota» caía con 500 ante un error de base; ahora responde
   como su ruta hermana: registro en el servicio y mensaje neutro conservando el destino.
6. MEDIO · la página calculaba tres veces el mismo resumen (629 ms cada vez): se memoriza
   por (origen, días) durante la petición y se pide sin las partes que no se pintan.
7. BAJO · el respaldo de la fusión era silencioso: si la firma no se puede recalcular, la
   fila lo dice y queda en el diario del servicio.
8. BAJO · una página del historial sin filas se llevaba por delante la tabla de
   actualizaciones de la ficha del activo: los dos paneles son independientes.

Sin red: base temporal bajo ``data/`` y datos insertados a mano (se reutilizan los
ayudantes de ``test_remediacion_agrupada``).
"""
from __future__ import annotations

import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from threatintel import aplicabilidad, db, remediacion
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "tests"))
from webui import auth  # noqa: E402
import test_remediacion_agrupada as base  # noqa: E402

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)
CLAVE = base.CLAVE

#: Cuántas vulnerabilidades se le ponen al grupo grande de las pruebas: más del doble del
#: tope de lo que se pinta, para que el recorte se vea y se pueda contar.
CVES_DEL_GRUPO_GRANDE = 40


def _base_temporal(nombre: str):
    """(directorio temporal, ruta de la base) con el esquema creado."""
    d = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
    ruta = str(Path(d.name) / nombre)
    db.init_db(ruta)
    return d, ruta


def _grupo_grande(conn, activo_id, *, paquete="openssl", n=CVES_DEL_GRUPO_GRANDE):
    """Una actualización con ``n`` vulnerabilidades del mismo paquete, cada una con su
    versión: la MÁS BAJA (que es la última de la cola y la primera en quedar recortada)
    es la más antigua, la crítica y la de explotación activa, para comprobar que las
    cifras del grupo no dependen de lo que se pinta."""
    ids = []
    for i in range(1, n + 1):
        critica = i == 1
        t = base._amenaza(conn, f"CVE-2026-70{i:02d}",
                          severity="Critical" if critica else "Medium",
                          in_kev=1 if critica else 0,
                          titulo=f"Fallo de {paquete} número {i}")
        ids.append(base._remediacion(
            conn, activo_id, t, f"CVE-2026-70{i:02d}", paquete, "3.0.0", f"3.0.{i}",
            detectado_at="2025-01-01T00:00:00Z" if critica else db.utcnow(),
            aviso=f"DSA-60{i:02d}"))
    return ids


# ==========================================================================
# 1. ALTO: el contenido de la página tiene tope y se dice
# ==========================================================================
class TestRecorteDeLoQueSePinta(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir, cls.ruta = _base_temporal("recorte.db")
        with db.session(cls.ruta) as conn:
            cls.srv = base._activo(conn, "srv-openssl-01", ip="10.0.0.21")
            base._software(conn, cls.srv, "openssl", "3.0.0")
            cls.ids = _grupo_grande(conn, cls.srv)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _grupo(self, **kw):
        with db.session(self.ruta) as conn:
            grupos = remediacion.listar_actualizaciones(conn, **kw)
        self.assertEqual(len(grupos), 1)
        return grupos[0]

    def test_el_grupo_pinta_veinticinco_y_cuenta_las_cuarenta(self):
        g = self._grupo()
        self.assertEqual(g["vulnerabilidades"], CVES_DEL_GRUPO_GRANDE,
                         "la cifra es la del grupo entero")
        self.assertEqual(g["pendientes"], CVES_DEL_GRUPO_GRANDE)
        self.assertEqual(g["filas"], CVES_DEL_GRUPO_GRANDE)
        self.assertEqual(g["filas_pendientes"], CVES_DEL_GRUPO_GRANDE)
        self.assertEqual(len(g["remediacion_ids"]), CVES_DEL_GRUPO_GRANDE,
                         "se puede actuar sobre todas, aunque no se pinten todas")
        # lo que se pinta
        self.assertEqual(len(g["cves"]), remediacion.LIMITE_CVES_GRUPO)
        self.assertEqual(g["cves_mostrados"], remediacion.LIMITE_CVES_GRUPO)
        self.assertEqual(g["cves_truncados"],
                         CVES_DEL_GRUPO_GRANDE - remediacion.LIMITE_CVES_GRUPO)
        self.assertTrue(g["truncado"])
        self.assertEqual(g["limite_cves"], remediacion.LIMITE_CVES_GRUPO)
        # la suma de lo mostrado por versión es exactamente lo pintado, y cada entrada
        # sigue diciendo su total real
        self.assertEqual(sum(v["mostrados"] for v in g["versiones"]), len(g["cves"]))
        self.assertEqual([len(v["cves"]) for v in g["versiones"]][:3], [1, 1, 1])
        # la COLA DE VERSIONES tambien se recorta: aqui hay una version por
        # vulnerabilidad, asi que pintarlas todas era otro camino al mismo peso
        self.assertEqual(g["versiones_pedidas"], CVES_DEL_GRUPO_GRANDE)
        self.assertEqual(g["versiones_mostradas"], remediacion.LIMITE_CVES_GRUPO)
        self.assertEqual(g["versiones_truncadas"],
                         CVES_DEL_GRUPO_GRANDE - remediacion.LIMITE_CVES_GRUPO)
        self.assertEqual(len(g["versiones"]), remediacion.LIMITE_CVES_GRUPO)

    def test_las_cifras_que_vienen_de_lo_recortado_no_se_pierden(self):
        """La versión objetivo, la severidad, el KEV y los días de espera salen de TODAS
        las filas: la crítica con explotación activa es justo una de las recortadas."""
        g = self._grupo()
        self.assertEqual(g["version_objetivo"], f"3.0.{CVES_DEL_GRUPO_GRANDE}",
                         "la más alta de las cuarenta, con el comparador de la distribución")
        self.assertEqual(g["versiones_pedidas"], CVES_DEL_GRUPO_GRANDE)
        self.assertEqual(g["severidad"], "Critical", "viene de una vulnerabilidad recortada")
        self.assertTrue(g["in_kev"], "viene de una vulnerabilidad recortada")
        self.assertGreater(g["dias"], 300, "la detección más antigua es la recortada")
        self.assertEqual(g["detectado_at"], "2025-01-01T00:00:00Z")
        # y no está entre las pintadas: es la versión más baja de la cola
        self.assertNotIn("CVE-2026-7001", [c["cve"] for c in g["cves"]])

    def test_los_textos_largos_solo_se_traen_de_lo_que_se_pinta(self):
        """El título de la amenaza y el aviso de la evaluación se piden después, solo
        para las que se pintan: traerlos de las 17.030 filas de una página era el peso."""
        g = self._grupo()
        for c in g["cves"]:
            self.assertTrue(c["titulo"].startswith("Fallo de openssl"), c["cve"])
            self.assertTrue(c["aviso"].startswith("DSA-60"), c["cve"])
            self.assertIn("estado_amenaza_es", c)

    def test_el_recorte_se_puede_subir_para_un_caso_concreto(self):
        g = self._grupo(limite_cves=CVES_DEL_GRUPO_GRANDE)
        self.assertFalse(g["truncado"])
        self.assertEqual(len(g["cves"]), CVES_DEL_GRUPO_GRANDE)
        self.assertEqual(g["cves_truncados"], 0)
        self.assertEqual(g["versiones_truncadas"], 0)
        self.assertEqual(len(g["versiones"]), CVES_DEL_GRUPO_GRANDE)

    def test_un_grupo_pequeno_no_dice_nada_de_recortes(self):
        with db.session(self.ruta) as conn:
            otro = base._activo(conn, "srv-curl-01", ip="10.0.0.22")
            t = base._amenaza(conn, "CVE-2026-7501")
            base._remediacion(conn, otro, t, "CVE-2026-7501", "curl", "7.81.0", "7.82.0")
            g = remediacion.listar_actualizaciones(conn, activo_id=otro)[0]
        self.assertFalse(g["truncado"])
        self.assertEqual(g["cves_truncados"], 0)
        self.assertEqual(g["cves_mostrados"], 1)
        self.assertEqual([v["truncados"] for v in g["versiones"]], [0])
        self.assertEqual(g["versiones_truncadas"], 0)


class TestRecorteEnLaPagina(unittest.TestCase):
    """Lo mismo, en la página: la frase honesta, el enlace y el peso de la respuesta."""

    @classmethod
    def setUpClass(cls):
        cls.dir, cls.ruta = _base_temporal("recorte_pagina.db")
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Lectora Sin Permisos", actor="t")
            auth.crear_usuario(conn, "sistemas@ejemplo.local", CLAVE,
                               rol="admin", nombre="Persona de Sistemas",
                               actor="t")
            cls.srv = base._activo(conn, "srv-openssl-02", ip="10.0.0.23")
            base._software(conn, cls.srv, "openssl", "3.0.0")
            cls.ids = _grupo_grande(conn, cls.srv)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, usuario="lectora@ejemplo.local"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": CLAVE})
        return cli

    def _html(self, cli, url="/remediaciones/"):
        r = cli.get(url)
        self.assertEqual(r.status_code, 200, url)
        html = r.get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html), f"style= en {url}")
        self.assertIsNone(RE_ON.search(html), f"on*= en {url}")
        return html

    def test_la_pagina_dice_cuantas_muestra_y_donde_estan_las_demas(self):
        html = self._html(self._cliente())
        self.assertIn("Se muestran las 25 primeras de 40 vulnerabilidades", html)
        self.assertIn("las otras 15 están en la", html)
        self.assertIn(f'href="/activos/{self.srv}#remediaciones-lista"', html)
        self.assertIn("La versión objetivo se calculó con todas.", html)
        # la cifra de la fila sigue siendo la del grupo entero
        self.assertIn("40 vulnerabilidades", html)

    def test_con_una_sola_fuera_del_recorte_la_frase_concuerda(self):
        """26 vulnerabilidades: se pintan 25 y queda UNA. «las otras 1 están» no es
        español, y esta página la lee gente que no conoce el sistema."""
        with db.session(self.ruta) as conn:
            justo = base._activo(conn, "srv-justo-01", ip="10.0.0.35")
            base._software(conn, justo, "nginx", "1.0.0")
            for i in range(1, 27):
                t = base._amenaza(conn, f"CVE-2026-80{i:02d}")
                base._remediacion(conn, justo, t, f"CVE-2026-80{i:02d}", "nginx",
                                  "1.0.0", f"1.0.{i}")
        html = self._html(self._cliente(), f"/remediaciones/?activo={justo}")
        self.assertIn("Se muestran las 25 primeras de 26 vulnerabilidades; la otra está en la",
                      html)
        self.assertNotIn("las otras 1 están", html)
        # aquí cada vulnerabilidad pide su propia versión, así que lo que se recorta es la
        # última entrada de la cola completa, no parte de una entrada
        self.assertIn("De las 26 versiones que piden los avisos se listan las 25 más altas",
                      html)

    def test_las_vulnerabilidades_recortadas_no_se_pintan(self):
        html = self._html(self._cliente())
        self.assertIn("CVE-2026-7040", html, "la de la versión más alta sí se pinta")
        for cve in ("CVE-2026-7001", "CVE-2026-7010", "CVE-2026-7015"):
            self.assertNotIn(cve, html, f"{cve} quedó fuera del recorte y no debe pintarse")

    def test_la_respuesta_no_crece_con_el_tamano_del_grupo(self):
        """Medida del hallazgo: el peso de la página ya no depende de cuántas
        vulnerabilidades tenga la actualización, porque se pinta un número fijo."""
        cli = self._cliente()
        antes = len(self._html(cli))
        with db.session(self.ruta) as conn:
            otro = base._activo(conn, "srv-openssl-03", ip="10.0.0.24")
            base._software(conn, otro, "openssl", "3.0.0")
            for i in range(200):
                t = base._amenaza(conn, f"CVE-2026-90{i:03d}")
                base._remediacion(conn, otro, t, f"CVE-2026-90{i:03d}", "openssl",
                                  "3.0.0", f"3.1.{i}")
        despues = len(self._html(cli))
        # la fila nueva añade su propia cabecera y sus 25 vulnerabilidades, no 200
        self.assertLess(despues - antes, 40000,
                        f"la página creció {despues - antes} caracteres con 200 "
                        f"vulnerabilidades más: el recorte no está actuando")
        html = self._html(cli)
        self.assertIn("Se muestran las 25 primeras de 200 vulnerabilidades", html)


# ==========================================================================
# 2. MEDIO: el tope de las acciones de grupo
# ==========================================================================
class TestTopeDeLasAccionesDeGrupo(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir, cls.ruta = _base_temporal("tope.db")
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "sistemas@ejemplo.local", CLAVE,
                               rol="admin", nombre="Persona de Sistemas",
                               actor="t")
            cls.srv = base._activo(conn, "srv-tope-01", ip="10.0.0.25")
            base._software(conn, cls.srv, "openssl", "3.0.0")
            cls.ids = _grupo_grande(conn, cls.srv)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "sistemas@ejemplo.local", "password": CLAVE})
        return cli

    def test_el_tope_queda_por_encima_del_maximo_real_medido(self):
        """Medido sobre la base real el 2026-09-09: la actualización mayor tiene 1.358
        filas pendientes y hay ocho por encima de mil. Con el tope en 1.000 el botón de
        esas ocho no podía funcionar nunca."""
        self.assertGreater(remediacion.LIMITE_ACCION_GRUPO, 1358,
                           "el tope tiene que dejar trabajar la actualización mayor de hoy")

    def test_por_encima_del_tope_no_se_pinta_ninguna_accion_de_grupo(self):
        cli = self._cliente()
        with mock.patch.object(remediacion, "LIMITE_ACCION_GRUPO", 10):
            html = cli.get("/remediaciones/").get_data(as_text=True)
        self.assertIn("Demasiadas filas para una sola acción", html)
        self.assertIn("40 filas de remediación pendientes y el tope por petición es 10", html)
        self.assertNotIn("Ya se actualizó: comprobar", html)
        self.assertNotIn("Guardar nota", html)
        self.assertIn(f'href="/activos/{self.srv}#remediaciones-lista"', html)

    def test_por_debajo_del_tope_se_pintan_las_dos_acciones(self):
        html = self._cliente().get("/remediaciones/").get_data(as_text=True)
        self.assertIn("Ya se actualizó: comprobar las 40", html)
        self.assertIn("Guardar nota", html)
        self.assertNotIn("Demasiadas filas para una sola acción", html)

    def test_la_ficha_del_activo_tampoco_pinta_lo_que_no_funciona(self):
        cli = self._cliente()
        with mock.patch.object(remediacion, "LIMITE_ACCION_GRUPO", 10):
            html = cli.get(f"/activos/{self.srv}").get_data(as_text=True)
        self.assertIn("Demasiadas filas para una sola acción", html)
        self.assertIn("use <a href=\"#remediaciones-lista\">el detalle de abajo</a>", html)
        self.assertNotIn("Ya se actualizó: comprobar las 40", html)

    def test_el_modulo_sigue_rechazando_lo_que_pasa_del_tope(self):
        """La cota es del servidor, no de la plantilla: aunque se envíe a mano, no escribe."""
        with db.session(self.ruta) as conn:
            with mock.patch.object(remediacion, "LIMITE_ACCION_GRUPO", 10):
                with self.assertRaises(ValueError) as ctx:
                    remediacion.anotar_grupo(conn, self.ids[0], autor="sistemas",
                                             texto="Nota que no se debe guardar.")
            self.assertIn("el tope por petición es 10", str(ctx.exception))
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM remediacion_notas").fetchone()[0], 0)


# ==========================================================================
# 3. MEDIO: el plan en texto trae los mismos grupos que la página
# ==========================================================================
class TestPlanFusionado(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir, cls.ruta = _base_temporal("plan.db")
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Lectora Sin Permisos", actor="t")
            cls.srv = base._activo(conn, "srv-nucleo-01", ip="10.0.0.26")
            cls.paquetes = ("linux-headers-6.8.0-60-generic", "linux-image-6.8.0-60-generic",
                            "linux-modules-6.8.0-60-generic", "linux-tools-6.8.0-60-generic")
            cls.cves = ("CVE-2026-6001", "CVE-2026-6002", "CVE-2026-6003")
            for paquete in cls.paquetes:
                base._software(conn, cls.srv, paquete, "6.8.0-60.63")
            for cve in cls.cves:
                t = base._amenaza(conn, cve, titulo=f"Fallo del núcleo {cve}")
                for paquete in cls.paquetes:
                    base._remediacion(conn, cls.srv, t, cve, paquete, "6.8.0-60.63",
                                      "6.8.0-60.63.1", aviso=f"USN-{cve[-4:]}")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "lectora@ejemplo.local", "password": CLAVE})
        return cli

    def test_el_plan_sale_fusionado_del_modulo(self):
        with db.session(self.ruta) as conn:
            plan = aplicabilidad.plan_remediacion(conn, activo_id=self.srv)
        self.assertEqual(len(plan["grupos"]), 1, "los tres avisos son una sola orden")
        g = plan["grupos"][0]
        self.assertEqual(g["nombre"], "Núcleo Linux 6.8.0-60-generic")
        self.assertEqual(g["grupos_fusionados"], 3)
        self.assertEqual(sorted(g["cves"]), sorted(self.cves))
        self.assertEqual(len(g["paquetes"]), 4)

    def test_el_fichero_descargado_trae_los_mismos_bloques_que_la_pagina(self):
        """La queja del usuario: la página decía 40 grupos y el fichero traía 105."""
        cli = self._cliente()
        pagina = cli.get(f"/activos/{self.srv}/remediacion").get_data(as_text=True)
        self.assertEqual(pagina.count("Núcleo Linux 6.8.0-60-generic"), 1)
        self.assertIn('<div class="valor">1</div>', pagina)
        r = cli.get(f"/activos/{self.srv}/remediacion?formato=txt")
        self.assertEqual(r.status_code, 200)
        texto = r.get_data(as_text=True)
        self.assertIn("Actualizaciones por aplicar: 1", texto)
        bloques = re.findall(r"^\d+\. ", texto, re.M)
        self.assertEqual(len(bloques), 1, f"el fichero trae {len(bloques)} bloques")
        # el encabezado usa el nombre de la actualización y debajo van sus paquetes
        self.assertIn("1. debian 13 · Núcleo Linux 6.8.0-60-generic", texto)
        self.assertIn("Paquetes (4): linux-headers-6.8.0-60-generic, "
                      "linux-image-6.8.0-60-generic, linux-modules-6.8.0-60-generic, "
                      "linux-tools-6.8.0-60-generic", texto)
        self.assertIn("Vulnerabilidades (3): CVE-2026-6001, CVE-2026-6002, CVE-2026-6003",
                      texto)

    def test_el_numero_de_la_pagina_y_el_del_fichero_coinciden_siempre(self):
        cli = self._cliente()
        with db.session(self.ruta) as conn:
            plan = aplicabilidad.plan_remediacion(conn, activo_id=self.srv)
            texto = aplicabilidad.plan_remediacion_texto(plan, titulo="Plan de prueba")
        pintados = len(remediacion.fusionar_plan(plan["grupos"]))
        self.assertEqual(len(re.findall(r"^\d+\. ", texto, re.M)), pintados)
        self.assertIn(f"Actualizaciones por aplicar: {pintados}", texto)
        html = cli.get(f"/activos/{self.srv}/remediacion").get_data(as_text=True)
        self.assertIn(f'<div class="valor">{pintados}</div>', html)

    def test_fusionar_dos_veces_no_cambia_nada(self):
        with db.session(self.ruta) as conn:
            plan = aplicabilidad.plan_remediacion(conn, activo_id=self.srv)
        una = remediacion.fusionar_plan(plan["grupos"])
        dos = remediacion.fusionar_plan(una)
        self.assertEqual(len(una), len(dos))
        self.assertEqual([g["nombre"] for g in una], [g["nombre"] for g in dos])
        self.assertEqual([g["grupos_fusionados"] for g in una],
                         [g["grupos_fusionados"] for g in dos])


# ==========================================================================
# 4. MEDIO: una sola entrada de auditoría por acción de grupo
# ==========================================================================
class TestAuditoriaDeLasNotasDeGrupo(unittest.TestCase):

    def setUp(self):
        self.dir, self.ruta = _base_temporal("auditoria.db")
        self.addCleanup(self.dir.cleanup)
        self.conn = db.connect(self.ruta)
        self.addCleanup(self.conn.close)
        self.srv = base._activo(self.conn, "srv-sssd-01", ip="10.0.0.27")
        self.paquetes = tuple(f"libsss-{i}" for i in range(1, 19))
        t = base._amenaza(self.conn, "CVE-2026-5001", titulo="Fallo de sssd")
        self.ids = []
        for paquete in self.paquetes:
            base._software(self.conn, self.srv, paquete, "2.6.3-1ubuntu3.8")
            self.ids.append(base._remediacion(self.conn, self.srv, t, "CVE-2026-5001",
                                              paquete, "2.6.3-1ubuntu3.8",
                                              "2.6.3-1ubuntu3.9"))

    def _auditorias(self, accion):
        return self.conn.execute("SELECT * FROM audit_log WHERE action=?", (accion,)).fetchall()

    def test_una_nota_de_grupo_deja_una_sola_entrada_de_auditoria(self):
        r = remediacion.anotar_grupo(self.conn, self.ids[0], autor="sistemas@ejemplo.local",
                                     texto="Programado para la ventana del sábado.",
                                     ip="10.1.1.9")
        self.assertEqual(r["total"], 18)
        # el historial por fila NO se pierde
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM remediacion_notas").fetchone()[0], 18)
        for rid in self.ids:
            self.assertEqual(remediacion.notas(self.conn, rid)[0]["texto"],
                             "Programado para la ventana del sábado.")
        # y la auditoría es UNA sola entrada, con el recuento, el activo y los paquetes
        self.assertEqual(len(self._auditorias("remediacion.nota")), 0)
        filas = self._auditorias("remediacion.nota_grupo")
        self.assertEqual(len(filas), 1)
        detalle = filas[0]["detail"]
        self.assertIn("18 filas de remediación", detalle)
        self.assertIn("srv-sssd-01", detalle)
        self.assertIn("18 paquetes", detalle)
        self.assertIn("libsss-1", detalle)
        self.assertIn("Programado para la ventana del sábado.", detalle)
        self.assertEqual(filas[0]["username"], "sistemas@ejemplo.local")
        self.assertEqual(filas[0]["ip"], "10.1.1.9")
        self.assertEqual(filas[0]["entity_id"], str(self.ids[0]))

    def test_la_misma_nota_repetida_se_rechaza(self):
        remediacion.anotar_grupo(self.conn, self.ids[0], autor="sistemas",
                                 texto="Se aplicará el sábado.")
        with self.assertRaises(ValueError) as ctx:
            remediacion.anotar_grupo(self.conn, self.ids[3], autor="sistemas",
                                     texto="  Se aplicará   el sábado. ")
        self.assertIn("ya está guardada", str(ctx.exception))
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM remediacion_notas").fetchone()[0], 18,
            "el reenvío no multiplica las notas")
        self.assertEqual(len(self._auditorias("remediacion.nota_grupo")), 1)
        # una nota distinta sí se guarda
        remediacion.anotar_grupo(self.conn, self.ids[0], autor="sistemas",
                                 texto="Se movió a la ventana del domingo.")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM remediacion_notas").fetchone()[0], 36)
        self.assertEqual(len(self._auditorias("remediacion.nota_grupo")), 2)

    def test_la_nota_de_una_sola_vulnerabilidad_sigue_auditandose_por_fila(self):
        """El alcance individual no cambia: una fila, una nota, una entrada."""
        remediacion.anotar(self.conn, self.ids[0], autor="sistemas", texto="Solo esta.")
        self.assertEqual(len(self._auditorias("remediacion.nota")), 1)
        self.assertEqual(len(self._auditorias("remediacion.nota_grupo")), 0)


# ==========================================================================
# 5. MEDIO: un error de base no puede acabar en 500
# ==========================================================================
class TestErrorDeBaseEnLasRutas(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir, cls.ruta = _base_temporal("errores.db")
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "sistemas@ejemplo.local", CLAVE,
                               rol="admin", nombre="Persona de Sistemas",
                               actor="t")
            cls.srv = base._activo(conn, "srv-error-01", ip="10.0.0.28")
            t = base._amenaza(conn, "CVE-2026-4001")
            cls.rid = base._remediacion(conn, cls.srv, t, "CVE-2026-4001", "curl",
                                        "7.81.0", "7.82.0")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "sistemas@ejemplo.local", "password": CLAVE})
        return cli

    def _csrf(self, cli):
        html = cli.get("/remediaciones/").get_data(as_text=True)
        encontrado = re.search(r'name="csrf" value="([^"]+)"', html)
        self.assertIsNotNone(encontrado)
        return encontrado.group(1)

    def test_la_nota_con_error_de_base_no_devuelve_500(self):
        cli = self._cliente()
        csrf = self._csrf(cli)
        destino = "/remediaciones/?estado=abierta#tabla-remediaciones"
        for alcance in ("", "grupo"):
            with self.subTest(alcance=alcance or "una sola"):
                objetivo = "anotar_grupo" if alcance == "grupo" else "anotar"
                with mock.patch.object(remediacion, objetivo,
                                       side_effect=sqlite3.OperationalError("database is locked")):
                    r = cli.post(f"/remediaciones/{self.rid}/nota",
                                 data={"csrf": csrf, "texto": "Nota que no se guardará.",
                                       "alcance": alcance, "volver": destino})
                self.assertEqual(r.status_code, 302, "no puede ser un 500")
                self.assertEqual(r.headers["Location"], destino,
                                 "se conserva el destino de vuelta")
                html = cli.get(destino).get_data(as_text=True)
                self.assertIn("No se pudo guardar la nota por un error interno", html)
                self.assertNotIn("database is locked", html,
                                 "el error interno no se le cuenta a nadie")
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM remediacion_notas").fetchone()[0], 0)

    def test_la_comprobacion_con_error_de_base_sigue_igual(self):
        """La ruta hermana ya lo hacía: se comprueba que no se ha perdido."""
        cli = self._cliente()
        csrf = self._csrf(cli)
        with mock.patch.object(remediacion, "comprobar",
                               side_effect=sqlite3.OperationalError("disk I/O error")):
            r = cli.post(f"/remediaciones/{self.rid}/comprobar",
                         data={"csrf": csrf, "volver": "/remediaciones/"})
        self.assertEqual(r.status_code, 302)
        html = cli.get("/remediaciones/").get_data(as_text=True)
        self.assertIn("No se pudo comprobar la remediación por un error interno", html)


# ==========================================================================
# 6. MEDIO: el resumen se calcula una vez por petición
# ==========================================================================
class TestResumenMemorizado(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir, cls.ruta = _base_temporal("resumen.db")
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "sistemas@ejemplo.local", CLAVE,
                               rol="admin", nombre="Persona de Sistemas",
                               actor="t")
            cls.srv = base._activo(conn, "srv-resumen-01", ip="10.0.0.29")
            cls.equipo = base._activo(conn, "eq-resumen-01", origen="equipos",
                                      proceso="", ip="10.0.0.30")
            for activo in (cls.srv, cls.equipo):
                t = base._amenaza(conn, f"CVE-2026-30{activo:02d}")
                base._remediacion(conn, activo, t, f"CVE-2026-30{activo:02d}", "curl",
                                  "7.81.0", "7.82.0")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "sistemas@ejemplo.local", "password": CLAVE})
        return cli

    def _llamadas(self, cli, url):
        real = remediacion.resumen
        registro = []

        def espia(conn, **kw):
            registro.append(kw)
            return real(conn, **kw)

        with mock.patch.object(remediacion, "resumen", side_effect=espia):
            r = cli.get(url)
        self.assertEqual(r.status_code, 200, url)
        return registro

    def test_la_pagina_de_remediacion_calcula_cada_resumen_una_sola_vez(self):
        """Antes: uno completo para las cifras y otro por tipo de máquina dentro del
        bloque «Avance», con el mismo coste cada uno (629 ms medidos)."""
        registro = self._llamadas(self._cliente(), "/remediaciones/")
        claves = [(k.get("origen"), k.get("solo_cifras", False)) for k in registro]
        self.assertEqual(len(claves), len(set(claves)), f"resumen repetido: {claves}")
        self.assertEqual(sorted(claves, key=lambda c: (str(c[0]), c[1])),
                         [(None, False), ("equipos", True), ("servidores", True)])
        # el bloque de avances no pinta ni el reparto por proceso ni la serie semanal
        self.assertEqual(sum(1 for _o, solo in claves if solo), 2)

    def test_la_lista_de_activos_pide_solo_las_cifras_y_una_vez(self):
        registro = self._llamadas(self._cliente(), "/activos/")
        self.assertEqual(len(registro), 1, f"la lista pidió {len(registro)} resúmenes")
        self.assertTrue(registro[0].get("solo_cifras"))

    def test_solo_cifras_no_calcula_lo_que_no_se_pinta_y_no_miente(self):
        with db.session(self.ruta) as conn:
            completo = remediacion.resumen(conn, dias=30)
            cifras = remediacion.resumen(conn, dias=30, solo_cifras=True)
        for clave in ("abiertas", "actualizaciones", "vulnerabilidades_unicas",
                      "cve_distintos", "corregidas_periodo", "activos_con_abiertas",
                      "actualizaciones_con_version", "tiempo_medio_dias", "dias"):
            self.assertEqual(cifras[clave], completo[clave], clave)
        # lo que no se calculó vale None, nunca cero: nadie puede leerlo como «no hay»
        for clave in ("por_proceso", "semanas", "servidores_con_abiertas",
                      "equipos_con_abiertas"):
            self.assertIsNone(cifras[clave], clave)
        self.assertTrue(cifras["solo_cifras"])
        self.assertFalse(completo["solo_cifras"])
        self.assertIsNotNone(completo["por_proceso"])


class TestSerieSemanal(unittest.TestCase):
    """La serie semanal se calcula ahora en dos recorridos de ``remediaciones`` en vez de
    dos por semana (259 ms de los 590 del resumen, medidos sobre la base real; con el
    periodo de 182 días eran 1.467 ms y ahora son 62). Estas pruebas fijan el reparto."""

    def setUp(self):
        self.dir, self.ruta = _base_temporal("serie.db")
        self.addCleanup(self.dir.cleanup)
        self.conn = db.connect(self.ruta)
        self.addCleanup(self.conn.close)
        self.srv = base._activo(self.conn, "srv-serie-01", ip="10.0.0.34")
        self.amenaza = base._amenaza(self.conn, "CVE-2026-3999")

    def _fecha(self, expresion, *modificadores):
        marcas = "".join(", ?" for _ in modificadores)
        return self.conn.execute(f"SELECT date(?{marcas})",
                                 (expresion, *modificadores)).fetchone()[0]

    def _remediacion(self, cve, detectado, *, corregido=None):
        rid = base._remediacion(self.conn, self.srv, self.amenaza, cve, "nginx", "1.0",
                                "1.1", detectado_at=f"{detectado}T10:00:00Z",
                                estado="corregida" if corregido else "abierta")
        if corregido:
            self.conn.execute("UPDATE remediaciones SET corregido_at=? WHERE id=?",
                              (f"{corregido}T10:00:00Z", rid))
        return rid

    def test_cada_fila_cae_en_su_semana_y_ninguna_se_cuenta_dos_veces(self):
        # Mismo cálculo que ``remediacion._serie_semanal`` para el lunes de la semana en
        # curso (corregido el 2026-11-15: "weekday 1", "-7 days" daba el lunes de la
        # semana ANTERIOR cuando «hoy» es justo lunes; ver el docstring de esa función).
        lunes_reciente = self._fecha("now", "-6 days", "weekday 1")
        primer_lunes = self._fecha(lunes_reciente, "-28 days")
        # dos detectadas en la primera semana del periodo (lunes y jueves)
        self._remediacion("CVE-2026-3901", primer_lunes)
        self._remediacion("CVE-2026-3902", self._fecha(primer_lunes, "+3 days"))
        # una en la tercera semana y una en la cuarta, esta ya corregida
        self._remediacion("CVE-2026-3903", self._fecha(primer_lunes, "+14 days"))
        self._remediacion("CVE-2026-3904", self._fecha(primer_lunes, "+21 days"),
                          corregido=self._fecha(lunes_reciente, "+1 days"))
        # y una anterior al periodo, que NO puede aparecer en ninguna semana
        self._remediacion("CVE-2026-3905", self._fecha(primer_lunes, "-1 days"))
        serie = remediacion.resumen(self.conn, dias=35)["semanas"]
        self.assertEqual(len(serie), 5)
        self.assertEqual([s["detectadas"] for s in serie], [2, 0, 1, 1, 0])
        self.assertEqual([s["corregidas"] for s in serie], [0, 0, 0, 0, 1])
        self.assertEqual([s["inicio"] for s in serie][0], primer_lunes)
        self.assertTrue(all(s["etiqueta"] for s in serie))

    def test_sin_nada_en_el_periodo_la_serie_esta_vacia(self):
        lunes_reciente = self._fecha("now", "-6 days", "weekday 1")
        self._remediacion("CVE-2026-3906", self._fecha(lunes_reciente, "-200 days"))
        self.assertEqual(remediacion.resumen(self.conn, dias=35)["semanas"], [])


# ==========================================================================
# 7. BAJO: el respaldo de la fusión es ruidoso
# ==========================================================================
class TestFusionIncompleta(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir, cls.ruta = _base_temporal("fusion.db")
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Lectora Sin Permisos", actor="t")
            cls.srv = base._activo(conn, "srv-fusion-01", ip="10.0.0.31")
            t = base._amenaza(conn, "CVE-2026-2001")
            for paquete in ("linux-image-6.8.0-60-generic", "linux-modules-6.8.0-60-generic"):
                base._software(conn, cls.srv, paquete, "6.8.0-60.63")
                base._remediacion(conn, cls.srv, t, "CVE-2026-2001", paquete,
                                  "6.8.0-60.63", "6.8.0-60.63.1")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_sin_respaldo_la_fusion_es_normal(self):
        with db.session(self.ruta) as conn:
            g = remediacion.listar_actualizaciones(conn, activo_id=self.srv)[0]
        self.assertFalse(g["fusion_incompleta"])
        self.assertEqual(g["n_paquetes"], 2)

    def test_el_respaldo_deja_rastro_en_el_diario_y_marca_la_fila(self):
        with db.session(self.ruta) as conn:
            with mock.patch.object(remediacion, "_paquetes_de_fusiones", return_value={}):
                with self.assertLogs("threatintel.remediacion", level="WARNING") as diario:
                    grupos = remediacion.listar_actualizaciones(conn, activo_id=self.srv)
        self.assertTrue(any("fusión incompleta" in linea for linea in diario.output),
                        diario.output)
        self.assertTrue(all(g["fusion_incompleta"] for g in grupos))
        self.assertTrue(all(g["n_paquetes"] == 1 for g in grupos),
                        "el respaldo muestra un solo paquete, y por eso hay que decirlo")

    def test_la_pagina_dice_que_la_fusion_quedo_incompleta(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "lectora@ejemplo.local", "password": CLAVE})
        with mock.patch.object(remediacion, "_paquetes_de_fusiones", return_value={}):
            with self.assertLogs("threatintel.remediacion", level="WARNING"):
                html = cli.get("/remediaciones/").get_data(as_text=True)
        self.assertIn("Fusión incompleta", html)
        self.assertIn("No se pudo comprobar si esta actualización cubre más paquetes", html)
        self.assertIsNone(RE_STYLE.search(html))
        self.assertIsNone(RE_ON.search(html))


# ==========================================================================
# 8. BAJO: los dos paneles de la ficha del activo son independientes
# ==========================================================================
class TestPanelesIndependientesEnLaFicha(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir, cls.ruta = _base_temporal("paneles.db")
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Lectora Sin Permisos", actor="t")
            cls.srv = base._activo(conn, "srv-paneles-01", ip="10.0.0.32")
            t = base._amenaza(conn, "CVE-2026-1001", titulo="Fallo de curl")
            base._software(conn, cls.srv, "curl", "7.81.0")
            base._remediacion(conn, cls.srv, t, "CVE-2026-1001", "curl", "7.81.0", "7.82.0")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "lectora@ejemplo.local", "password": CLAVE})
        return cli

    def test_los_dos_paneles_se_ven_con_historial(self):
        html = self._cliente().get(f"/activos/{self.srv}").get_data(as_text=True)
        self.assertIn("Actualizaciones pendientes", html)
        self.assertIn("Detalle por vulnerabilidad y paquete", html)

    def test_una_pagina_de_historial_vacia_no_se_lleva_las_actualizaciones(self):
        """Hallazgo BAJO: todo el parcial dependía del historial paginado."""
        from webui.vistas import activos as vista_activos
        cli = self._cliente()
        with mock.patch.object(vista_activos._remediacion, "historial_activo",
                               return_value=[]):
            html = cli.get(f"/activos/{self.srv}").get_data(as_text=True)
        self.assertIn("Actualizaciones pendientes", html,
                      "la tabla de actualizaciones no depende de esa paginación")
        self.assertIn("Actualizar a", html)
        self.assertIn("Detalle por vulnerabilidad y paquete", html)
        self.assertIn("Esta página del historial no tiene filas", html)
        self.assertIsNone(RE_STYLE.search(html))
        self.assertIsNone(RE_ON.search(html))

    def test_sin_ninguna_remediacion_el_panel_lo_dice_y_no_pinta_tabla(self):
        """Adaptado el 2026-09-09: el panel de actualizaciones es ahora la tabla principal
        de la ficha, así que se pinta siempre —con su estado vacío— en vez de desaparecer.
        Lo que no puede haber es una tabla vacía ni el panel del historial."""
        with db.session(self.ruta) as conn:
            limpio = base._activo(conn, "srv-limpio-01", ip="10.0.0.33")
        html = self._cliente().get(f"/activos/{limpio}").get_data(as_text=True)
        self.assertIn("Actualizaciones pendientes", html)
        self.assertIn("No hay ninguna actualización pendiente en este activo", html)
        self.assertNotIn("tabla-actualizaciones-activo", html, "no se pinta una tabla vacía")
        self.assertNotIn("Detalle por vulnerabilidad y paquete", html)


if __name__ == "__main__":
    unittest.main()
