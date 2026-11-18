"""Perfiles segmentados por tipo de máquina y perfil de operador SOC (2026-09-08).

Peticiones del usuario, literales:

* «el apartado de fuentes que se encuentra en el menú debe ir en administración para que
  no todos los roles lo vean»;
* «Se debe de segmentar los roles, uno para redes y otro para mantenimiento donde redes
  solo ve vulnerabilidades de servidores y mantenimiento solo vea vulnerabilidades de
  equipos de cómputo […] y el rol servicios tecnológicos se les dé solo a los jefes del
  proceso donde pueda ver vulnerabilidades de servidores y de equipos al mismo tiempo y
  los avances de cada uno»;
* «Crear el rol de operador soc»;
* «Módulo para crear informes donde solo tenga acceso el rol de operador soc».

Lo que estas pruebas fijan, y por qué:

* El recorte por tipo de máquina se aplica EN EL SERVIDOR, no en el menú: el perfil de
  Redes no ve un equipo de cómputo en ninguna página, ni en una exportación, ni
  manipulando «?origen=» o «?proceso=», ni pidiendo su ficha por identificador (404, la
  misma respuesta que un identificador inventado, para no revelar que existe).
* Las acciones de escritura fuera del alcance se rechazan aunque se conozca el
  identificador y se tenga el permiso genérico de remediar.
* Fuentes es de administración: todos los demás perfiles reciben 403.
* /informes/ solo lo abren la administración y el operador SOC.
* El perfil de solo lectura sigue sin poder escribir nada (tests/test_solo_lectura.py
  barre todas las rutas POST; aquí se comprueba lo nuevo).
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402

CLAVE = "ClaveSegura#2026"

#: Un usuario por perfil. El correo dice el perfil para que los fallos se lean solos.
USUARIOS = {
    "admin": "admin@ejemplo.local",
    "ciberseguridad": "ciberseguridad@ejemplo.local",
    "redes": "redes@ejemplo.local",
    "mantenimiento": "mantenimiento@ejemplo.local",
}

#: Marcadores únicos de cada tipo de máquina: si aparecen en una página que no debería
#: mostrarlos, el recorte ha fallado.
SRV = "SRV-SOLO-REDES"
PC = "PC-SOLO-MANTENIMIENTO"
PAQ_SRV = "paquete-servidor-x"
PAQ_PC = "paquete-computo-y"
CVE_AMBOS, CVE_PC, CVE_SRV = "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"

#: Prefijos de las rutas de administración: 403 para todo perfil que no sea administrador.
ADMINISTRACION = ("/usuarios", "/ajustes", "/credenciales", "/fuentes", "/alertas-proceso",
                  "/sincronizaciones", "/auditoria")


class BaseRoles(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "roles.db")
        db.init_db(cls.ruta)
        ahora = db.utcnow()
        with db.session(cls.ruta) as conn:
            for rol, correo in USUARIOS.items():
                auth.crear_usuario(conn, correo, CLAVE, rol=rol, nombre=f"Persona {rol}", actor="t")
            # Un servidor y un equipo de cómputo, con nombres que no aparecen en ningún
            # otro sitio de la interfaz.
            for ocs_id, nombre, origen, proceso in ((1, SRV, "servidores", "Tesorería"),
                                                    (2, PC, "equipos", None)):
                conn.execute(
                    """INSERT INTO activos(ocs_id, nombre, origen, so_familia, so_nombre, ecosistema,
                                           ip, presente, entorno, proceso, ultimo_inventario,
                                           primera_vez_at, visto_at)
                       VALUES(?,?,?,'ubuntu','Ubuntu','Ubuntu:22.04',?,1,'produccion',?,?,?,?)""",
                    (ocs_id, nombre, origen, f"10.9.9.{ocs_id}", proceso, ahora, ahora, ahora))
            cls.srv_id = conn.execute("SELECT id FROM activos WHERE nombre=?", (SRV,)).fetchone()[0]
            cls.pc_id = conn.execute("SELECT id FROM activos WHERE nombre=?", (PC,)).fetchone()[0]
            for activo_id in (cls.srv_id, cls.pc_id):
                conn.execute("""INSERT INTO activo_software(activo_id, nombre, nombre_norm, version)
                                VALUES(?,'openssl','openssl','1.0')""", (activo_id,))
            # Tres amenazas: una en los dos tipos, una solo en el equipo de cómputo y otra
            # solo en el servidor.
            cls.amenazas = {}
            for n, cve in enumerate((CVE_AMBOS, CVE_PC, CVE_SRV), start=1):
                conn.execute(
                    """INSERT INTO threats(fingerprint, cve, title_en, summary_en, severity,
                           severity_source, cvss_score, in_kev, first_seen_at, last_seen_at,
                           times_seen, month, relevance, estado)
                       VALUES(?,?,?,?,'High','nvd',7.5,0,?,?,1,?,60.0,'nueva')""",
                    (f"fp-{n}", cve, f"Amenaza {cve}", "Resumen de prueba", ahora, ahora, ahora[:7]))
                cls.amenazas[cve] = conn.execute("SELECT id FROM threats WHERE cve=?", (cve,)).fetchone()[0]
            afectaciones = (
                (cls.srv_id, CVE_AMBOS, "openssl", "1.2"),
                (cls.pc_id, CVE_AMBOS, "openssl", "1.2"),
                (cls.pc_id, CVE_PC, PAQ_PC, None),
                (cls.srv_id, CVE_SRV, PAQ_SRV, None),
            )
            for activo_id, cve, paquete, corregida in afectaciones:
                conn.execute(
                    """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada,
                                                 version_corregida, veredicto, motor, evaluado_at)
                       VALUES(?,?,?,?,'1.0',?,'afectado','osv',?)""",
                    (activo_id, cls.amenazas[cve], cve, paquete, corregida, ahora))
                conn.execute(
                    """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete, version_vulnerable,
                                                 version_corregida, motor, estado, detectado_at, comprobado_at)
                       VALUES(?,?,?,?,'1.0',?,'osv','abierta',?,?)""",
                    (activo_id, cls.amenazas[cve], cve, paquete, corregida, ahora, ahora))
            for cve, afectados in ((CVE_AMBOS, 2), (CVE_PC, 1), (CVE_SRV, 1)):
                conn.execute(
                    """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados, no_afectados,
                                                         sin_dato, afectados_expuestos, parche_disponible, detalle)
                       VALUES(?,?,?,0,0,?,1,'{}')""", (cls.amenazas[cve], ahora, afectados, afectados))
            # Correcciones pendientes: una por cada tipo de máquina.
            for cve, paquete in ((CVE_PC, PAQ_PC), (CVE_SRV, PAQ_SRV)):
                conn.execute(
                    """INSERT INTO parches_pendientes(cve, paquete, ecosistema, threat_id, motivo,
                                                      n_activos, n_activos_expuestos, detectado_at)
                       VALUES(?,?,'Ubuntu:22.04',?,'aviso_sin_version',1,1,?)""",
                    (cve, paquete, cls.amenazas[cve], ahora))
            cls.remediaciones = {(r["activo_id"], r["cve"]): r["id"] for r in
                                 conn.execute("SELECT id, activo_id, cve FROM remediaciones")}
            conn.execute("""INSERT INTO sources(name, slug, url, kind, category, enabled, created_at, updated_at)
                            VALUES('Fuente de prueba','prueba','https://example.invalid/rss','rss','vendor',1,?,?)""",
                         (ahora, ahora))
            cls.fuente_id = conn.execute("SELECT id FROM sources WHERE slug='prueba'").fetchone()[0]
            conn.execute("""INSERT INTO technologies(name, slug, category, criticality, exposure, enabled,
                                                     created_at, updated_at)
                            VALUES('OpenSSL','openssl','biblioteca','high','interna',1,?,?)""", (ahora, ahora))
            cls.tec_id = conn.execute("SELECT id FROM technologies WHERE slug='openssl'").fetchone()[0]
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, rol: str):
        cli = self.app.test_client()
        r = cli.post("/login", data={"usuario": USUARIOS[rol], "password": CLAVE})
        self.assertEqual(r.status_code, 302, f"{rol} no pudo entrar")
        return cli

    def _csrf(self, cli, url: str = "/perfil") -> str:
        html = cli.get(url, follow_redirects=True).get_data(as_text=True)
        encontrado = re.search(r'name="csrf" value="([^"]+)"', html)
        self.assertIsNotNone(encontrado, "sin token CSRF: no llegó a entrar")
        return encontrado.group(1)

    def _html(self, cli, url: str, esperado: int = 200) -> str:
        r = cli.get(url)
        self.assertEqual(r.status_code, esperado, f"{url} -> {r.status_code}")
        return r.get_data(as_text=True)

    def _comprobaciones(self, remediacion_id: int) -> int:
        with db.session(self.ruta) as conn:
            return conn.execute("SELECT COUNT(*) FROM remediacion_comprobaciones WHERE remediacion_id=?",
                                (remediacion_id,)).fetchone()[0]

    def _notas(self, remediacion_id: int) -> int:
        with db.session(self.ruta) as conn:
            return conn.execute("SELECT COUNT(*) FROM remediacion_notas WHERE remediacion_id=?",
                                (remediacion_id,)).fetchone()[0]


# ==========================================================================
# Los perfiles y su alcance, escritos en un solo sitio
# ==========================================================================
class TestDefinicionDeLosPerfiles(BaseRoles):

    def test_los_cuatro_perfiles_existen_en_este_orden(self):
        """El orden es el del selector de Usuarios: de más a menos permisos."""
        self.assertEqual(auth.ROLES, ("admin", "ciberseguridad", "redes", "mantenimiento"))
        self.assertEqual(auth.ROL_ES["ciberseguridad"], "Ciberseguridad")
        self.assertEqual(auth.ROL_ES["redes"], "Redes")
        self.assertEqual(auth.ROL_ES["mantenimiento"], "Mantenimiento")
        self.assertEqual(set(auth.ROL_ALCANCE_ES), set(auth.ROLES),
                         "cada perfil tiene su alcance escrito")
        for rol in auth.ROLES:
            self.assertGreater(len(auth.ROL_ALCANCE_ES[rol]), 20, rol)

    def test_el_alcance_dice_lo_que_ve_cada_uno(self):
        self.assertIn("Solo servidores", auth.ROL_ALCANCE_ES["redes"])
        self.assertIn("No ve los equipos de cómputo", auth.ROL_ALCANCE_ES["redes"])
        self.assertIn("Solo equipos de cómputo", auth.ROL_ALCANCE_ES["mantenimiento"])
        self.assertIn("No ve los servidores", auth.ROL_ALCANCE_ES["mantenimiento"])
        self.assertIn("acceso completo", auth.ROL_ALCANCE_ES["ciberseguridad"].lower())

    def test_alcance_origen_por_perfil(self):
        """La función de la que depende todo el recorte: servidores para Redes, equipos
        para Mantenimiento y ninguno para los demás."""
        esperado = {"redes": "servidores", "mantenimiento": "equipos"}
        with self.app.test_request_context():
            from flask import g
            for rol in auth.ROLES:
                g._sesion_fila = {"username": "x", "role": rol, "csrf": "c",
                                  "expires_at": "2999-01-01T00:00:00Z", "mfa_pendiente": 0}
                with self.subTest(rol=rol):
                    self.assertEqual(auth.alcance_origen(), esperado.get(rol))
                    # Ningún parámetro de la dirección amplía el alcance.
                    for pedido in (None, "", "servidores", "equipos", "todos", "x"):
                        if rol in esperado:
                            self.assertEqual(auth.origen_efectivo(pedido), esperado[rol])
                        else:
                            self.assertEqual(auth.origen_efectivo(pedido),
                                             pedido if pedido in ("servidores", "equipos") else None)

    def test_las_listas_de_permiso_son_las_del_diseno(self):
        self.assertEqual(auth.ROLES_INFORMES, ("admin",))
        self.assertEqual(auth.ROLES_OPERACION, ("admin", "ciberseguridad"))
        self.assertEqual(set(auth.ROLES_REMEDIACION), {"admin", "redes", "mantenimiento"})
        self.assertEqual(set(auth.ROLES_AVANCES), {"admin"})


# ==========================================================================
# Matriz de acceso: barrido de TODAS las rutas GET por perfil
# ==========================================================================
class TestMatrizDeAcceso(BaseRoles):

    def _rutas_get(self):
        with self.app.test_request_context():
            reglas = list(self.app.url_map.iter_rules())
        return [r for r in reglas if "GET" in (r.methods or set())
                and r.endpoint != "static" and not r.endpoint.startswith("auth.")
                and r.endpoint not in ("panel.salud_json", "panel.tour_estado")]

    def _url(self, regla, *, activo_id: int) -> str:
        valores = {}
        for nombre in regla.arguments:
            if "activo" in nombre:
                valores[nombre] = activo_id
            elif "source" in nombre or "fuente" in nombre:
                valores[nombre] = self.fuente_id
            elif "tec" in nombre:
                valores[nombre] = self.tec_id
            elif "threat" in nombre:
                valores[nombre] = self.amenazas[CVE_AMBOS]
            elif nombre == "mes":
                valores[nombre] = "2026-09"
            elif regla.endpoint.startswith("colores.") and nombre == "clave":
                valores[nombre] = "viva"
            elif regla.endpoint.startswith("colores.") and nombre == "tema":
                valores[nombre] = "claro"
            else:
                valores[nombre] = 1
        with self.app.test_request_context():
            from flask import url_for
            return url_for(regla.endpoint, **valores)

    def _esperado(self, rol: str, url: str) -> tuple[int, ...]:
        if url == "/ajustes/logo.png":
            # El logo es la imagen de marca (como el favicon): se ve en el login antes
            # de iniciar sesión, así que ningún perfil puede recibir 403. Sin logo
            # subido en esta base de pruebas, responde 404 para todos.
            return (200, 404)
        if any(url.startswith(p) for p in ADMINISTRACION):
            return (200, 302) if rol == "admin" else (403,)
        if url.startswith("/informes"):
            return (200, 302) if rol in auth.ROLES_INFORMES else (403,)
        return (200, 302)

    def test_cada_perfil_recibe_200_o_403_segun_la_matriz(self):
        """Un 403 donde se esperaba página, o una página donde se esperaba 403, es un
        fallo de control de acceso. Los identificadores de activo se eligen dentro del
        alcance de cada perfil (el caso «fuera de alcance» tiene su propia prueba)."""
        for rol in auth.ROLES:
            cli = self._cliente(rol)
            activo = self.pc_id if rol == "mantenimiento" else self.srv_id
            fallos = []
            for regla in self._rutas_get():
                url = self._url(regla, activo_id=activo)
                r = cli.get(url)
                if r.status_code not in self._esperado(rol, url):
                    fallos.append(f"{rol}: GET {url} -> {r.status_code}, "
                                  f"esperado {self._esperado(rol, url)}")
            with self.subTest(rol=rol):
                self.assertEqual(fallos, [])

    def test_fuentes_es_de_administracion(self):
        """«debe ir en administración para que no todos los roles lo vean»: GET y POST."""
        for rol in auth.ROLES:
            cli = self._cliente(rol)
            esperado = 200 if rol == "admin" else 403
            with self.subTest(rol=rol):
                self.assertEqual(cli.get("/fuentes/").status_code, esperado)
                self.assertEqual(cli.get(f"/fuentes/{self.fuente_id}").status_code, esperado)
                if rol != "admin":
                    csrf = self._csrf(cli)
                    for url in (f"/fuentes/{self.fuente_id}/probar", "/fuentes/probar-todas",
                                "/fuentes/nueva", f"/fuentes/{self.fuente_id}/editar",
                                f"/fuentes/{self.fuente_id}/activar", f"/fuentes/{self.fuente_id}/borrar",
                                "/fuentes/sembrar"):
                        self.assertEqual(cli.post(url, data={"csrf": csrf}).status_code, 403, url)

    def test_informes_solo_para_administracion(self):
        for rol in auth.ROLES:
            cli = self._cliente(rol)
            esperado = 200 if rol == "admin" else 403
            with self.subTest(rol=rol):
                self.assertEqual(cli.get("/informes/").status_code, esperado)
                if esperado == 403:
                    csrf = self._csrf(cli)
                    self.assertEqual(cli.post("/informes/2026-09/descargar",
                                              data={"csrf": csrf}).status_code, 403)

    def test_el_403_sigue_siendo_generico(self):
        """El 403 no nombra el perfil necesario, sea cual sea el perfil que lo reciba.

        Revisión de claridad del 2026-09-15: el título pasó de «Acceso inválido», que
        sonaba a culpa de quien lo leía, a «Esta página no está incluida en su perfil».
        Lo que no cambia es lo importante: el texto es SIEMPRE el mismo y nunca dice qué
        cuenta haría falta."""
        textos = set()
        for rol in ("redes", "mantenimiento", "ciberseguridad"):
            html = self._html(self._cliente(rol), "/usuarios/", 403)
            with self.subTest(rol=rol):
                self.assertIn("Esta página no está incluida en su perfil", html)
                self.assertIn("Su cuenta es correcta", html)
                self.assertNotIn("Administrador", html.split("<main")[1])
                textos.add(html.split("<main")[1].split("</main>")[0])
        self.assertEqual(len(textos), 1, "el 403 debe decir lo mismo a todos los perfiles")


# ==========================================================================
# Redes no ve equipos de cómputo; Mantenimiento no ve servidores
# ==========================================================================
class TestAlcancePorTipoDeMaquina(BaseRoles):

    def _paginas(self, propio_id: int, otro_id: int, otro_origen: str, otro_proceso: str):
        t = self.amenazas[CVE_AMBOS]
        return [
            "/", "/activos/", "/activos/exportar.csv",
            f"/activos/?origen={otro_origen}",           # el parámetro no amplía nada
            f"/activos/?proceso={otro_proceso}",
            f"/activos/{propio_id}",
            "/remediaciones/", "/remediaciones/?vista=vulnerabilidad", "/remediaciones/exportar.csv",
            f"/remediaciones/?origen={otro_origen}", f"/remediaciones/?proceso={otro_proceso}",
            f"/remediaciones/?activo={propio_id}",
            "/amenazas/", f"/amenazas/?origen={otro_origen}", f"/amenazas/?proceso={otro_proceso}",
            f"/amenazas/{t}", f"/amenazas/{t}/remediacion", f"/amenazas/{t}/remediacion?formato=txt",
            "/parches-pendientes/", "/parches-pendientes/?estado=encontradas",
        ]

    def _comprobar_recorte(self, rol, propio_id, otro_id, marca_propia, marca_otra,
                           paquete_otro, cve_otro, cve_propio, otro_origen, otro_proceso):
        cli = self._cliente(rol)
        for url in self._paginas(propio_id, otro_id, otro_origen, otro_proceso):
            with self.subTest(rol=rol, url=url):
                html = self._html(cli, url)
                self.assertNotIn(marca_otra, html, f"{rol} ve el activo del otro tipo en {url}")
                if url.startswith("/remediaciones") or url.startswith("/parches"):
                    self.assertNotIn(paquete_otro, html, f"{rol} ve el paquete del otro tipo en {url}")
        # Lo propio sí se ve.
        self.assertIn(marca_propia, self._html(cli, "/activos/"))
        self.assertIn(marca_propia, self._html(cli, "/remediaciones/"))
        self.assertIn(marca_propia, self._html(cli, "/remediaciones/exportar.csv"))
        # El cuadro de activos afectados de la ficha es AJAX (2026-11-16): el nombre ya
        # no vive en el HTML inicial, sino en su propio endpoint paginado, que recorta
        # por el mismo alcance (webui.vistas.amenazas.activos_afectados_json).
        datos_afectados = cli.get(f"/amenazas/activos-afectados/{self.amenazas[CVE_AMBOS]}").get_json()
        nombres_afectados = [a["nombre"] for a in datos_afectados["activos"]]
        self.assertIn(marca_propia, nombres_afectados)
        self.assertNotIn(marca_otra, nombres_afectados)
        parches = self._html(cli, "/parches-pendientes/")
        self.assertIn(cve_propio, parches)
        self.assertNotIn(cve_otro, parches)
        # La ficha del otro tipo no existe para este perfil: 404, como un identificador
        # inventado, sin revelar el nombre.
        for url in (f"/activos/{otro_id}", f"/activos/{otro_id}/vulnerabilidades.json",
                    f"/activos/{otro_id}/exportar.csv", f"/activos/{otro_id}/remediacion",
                    f"/remediaciones/?activo={otro_id}"):
            with self.subTest(rol=rol, url=url):
                r = cli.get(url)
                self.assertEqual(r.status_code, 404, url)
                self.assertNotIn(marca_otra, r.get_data(as_text=True))
        # Y un identificador inventado responde EXACTAMENTE igual (404, mismo cuerpo): sin
        # diferencia que permita enumerar qué identificadores existen del otro tipo
        # (revisión del 2026-09-08).
        inventado = cli.get("/activos/999999")
        ajeno = cli.get(f"/activos/{otro_id}")
        self.assertEqual(inventado.status_code, 404)
        self.assertEqual(inventado.status_code, ajeno.status_code)
        self.assertEqual(inventado.get_data(as_text=True), ajeno.get_data(as_text=True))
        self.assertEqual(cli.get("/remediaciones/?activo=999999").status_code, 404)

    def test_redes_solo_ve_servidores(self):
        self._comprobar_recorte("redes", self.srv_id, self.pc_id, SRV, PC, PAQ_PC, CVE_PC, CVE_SRV,
                                "equipos", "Equipos de cómputo (Mantenimiento)")

    def test_mantenimiento_solo_ve_equipos_de_computo(self):
        self._comprobar_recorte("mantenimiento", self.pc_id, self.srv_id, PC, SRV, PAQ_SRV, CVE_SRV,
                                CVE_PC, "servidores", "Tesorería")

    def test_los_perfiles_sin_recorte_ven_los_dos_tipos(self):
        for rol in ("admin", "ciberseguridad"):
            cli = self._cliente(rol)
            with self.subTest(rol=rol):
                for url in ("/activos/", "/remediaciones/", "/remediaciones/exportar.csv"):
                    html = self._html(cli, url)
                    self.assertIn(SRV, html, url)
                    self.assertIn(PC, html, url)
                # El cuadro de activos afectados de la ficha es AJAX: el nombre vive en
                # su propio endpoint paginado, no en el HTML inicial de la página.
                datos_afectados = cli.get(
                    f"/amenazas/activos-afectados/{self.amenazas[CVE_AMBOS]}").get_json()
                nombres_afectados = [a["nombre"] for a in datos_afectados["activos"]]
                self.assertIn(SRV, nombres_afectados)
                self.assertIn(PC, nombres_afectados)
                parches = self._html(cli, "/parches-pendientes/")
                self.assertIn(CVE_PC, parches)
                self.assertIn(CVE_SRV, parches)

    def test_las_cifras_de_amenazas_se_acotan_al_tipo_para_redes_y_mantenimiento(self):
        """Las cifras del apartado «Cuántas amenazas hay» describen solo el tipo del
        perfil: para Redes, un servidor presente y afectado; el selector de tipo no ofrece
        el otro. Ciberseguridad ve los dos tipos."""
        html = self._html(self._cliente("redes"), "/amenazas/")
        self.assertIn("1 de 1 servidor", html)
        self.assertNotIn(">Equipos de cómputo</option>", html)
        html = self._html(self._cliente("mantenimiento"), "/amenazas/")
        self.assertIn("1 de 1 equipo de cómputo", html)
        self.assertNotIn(">Servidores</option>", html)
        # Ciberseguridad ve los dos tipos sin restricción
        html = self._html(self._cliente("ciberseguridad"), "/amenazas/")
        self.assertIn("2 de 2 activos", html)
        self.assertIn(">Servidores</option>", html)
        self.assertIn(">Equipos de cómputo</option>", html)

    def test_el_panel_acota_las_cifras_de_activos(self):
        # Revisión del 2026-09-08: para un perfil acotado no se dice «0 equipos de cómputo»
        # (es falso: hay, pero no los ve); se dice cuántos activos hay en su alcance y cuál
        # es. Y la concordancia en singular se cuida («1 activo», «1 servidor»).
        redes = self._html(self._cliente("redes"), "/")
        self.assertIn("1 activo (servidores)", redes)
        self.assertNotIn("0 equipos de cómputo", redes)
        mantenimiento = self._html(self._cliente("mantenimiento"), "/")
        self.assertIn("1 activo (equipos de cómputo)", mantenimiento)
        self.assertNotIn("0 servidores", mantenimiento)
        admin = self._html(self._cliente("admin"), "/")
        self.assertIn("2 activos (1 servidor y 1 equipo de cómputo)", admin)

    def test_la_ficha_de_amenaza_acota_el_desglose_por_sistema(self):
        """El desglose por sistema operativo se recalcula con las máquinas del tipo: para
        Redes el sistema Ubuntu tiene 1 activo, no 2."""
        t = self.amenazas[CVE_AMBOS]
        redes = self._html(self._cliente("redes"), f"/amenazas/{t}")
        self.assertIn("1 afectado", redes)
        self.assertNotIn("2 afectados", redes)
        admin = self._html(self._cliente("admin"), f"/amenazas/{t}")
        self.assertIn("2 afectados", admin)


# ==========================================================================
# Escritura: quién puede qué, y dentro de qué alcance
# ==========================================================================
class TestEscrituraPorPerfil(BaseRoles):

    def test_redes_comprueba_y_documenta_solo_servidores(self):
        cli = self._cliente("redes")
        csrf = self._csrf(cli)
        propia = self.remediaciones[(self.srv_id, CVE_SRV)]
        ajena = self.remediaciones[(self.pc_id, CVE_PC)]
        # Las pruebas comparten la base: se cuenta lo que había antes y se mira la diferencia.
        comp_ajena, notas_ajena = self._comprobaciones(ajena), self._notas(ajena)
        comp_propia, notas_propia = self._comprobaciones(propia), self._notas(propia)
        # Fuera de alcance: 404 y nada escrito, aunque conozca el identificador.
        self.assertEqual(cli.post(f"/remediaciones/{ajena}/comprobar", data={"csrf": csrf}).status_code, 404)
        self.assertEqual(cli.post(f"/remediaciones/{ajena}/nota",
                                  data={"csrf": csrf, "texto": "intento fuera de alcance"}).status_code, 404)
        self.assertEqual(cli.post(f"/remediaciones/{ajena}/comprobar",
                                  data={"csrf": csrf, "alcance": "grupo"}).status_code, 404)
        self.assertEqual(self._comprobaciones(ajena), comp_ajena)
        self.assertEqual(self._notas(ajena), notas_ajena)
        # Dentro del alcance: se acepta y queda registrado.
        self.assertEqual(cli.post(f"/remediaciones/{propia}/comprobar", data={"csrf": csrf}).status_code, 302)
        self.assertEqual(cli.post(f"/remediaciones/{propia}/nota",
                                  data={"csrf": csrf, "texto": "Programado para el sábado."}).status_code, 302)
        self.assertEqual(self._comprobaciones(propia), comp_propia + 1)
        self.assertEqual(self._notas(propia), notas_propia + 1)

    def test_mantenimiento_comprueba_y_documenta_solo_equipos_de_computo(self):
        cli = self._cliente("mantenimiento")
        csrf = self._csrf(cli)
        propia = self.remediaciones[(self.pc_id, CVE_PC)]
        ajena = self.remediaciones[(self.srv_id, CVE_SRV)]
        notas_ajena, notas_propia = self._notas(ajena), self._notas(propia)
        self.assertEqual(cli.post(f"/remediaciones/{ajena}/comprobar", data={"csrf": csrf}).status_code, 404)
        self.assertEqual(cli.post(f"/remediaciones/{ajena}/nota",
                                  data={"csrf": csrf, "texto": "intento fuera de alcance"}).status_code, 404)
        self.assertEqual(self._notas(ajena), notas_ajena)
        self.assertEqual(cli.post(f"/remediaciones/{propia}/nota",
                                  data={"csrf": csrf, "texto": "Equipo de cómputo reinstalado."}).status_code, 302)
        self.assertEqual(self._notas(propia), notas_propia + 1)

    def test_ciberseguridad_ve_los_dos_tipos_sin_restricciones(self):
        """Ciberseguridad accede a operación sin segmentación por tipo de máquina."""
        cli = self._cliente("ciberseguridad")
        # Puede ver la ficha de ambos tipos sin 404
        self.assertEqual(cli.get(f"/activos/{self.srv_id}").status_code, 200)
        self.assertEqual(cli.get(f"/activos/{self.pc_id}").status_code, 200)
        # Puede cambiar el estado de amenazas que afecten a ambos tipos
        t = self.amenazas[CVE_AMBOS]
        csrf = self._csrf(cli)
        self.assertEqual(cli.post(f"/amenazas/{t}/estado",
                                  data={"csrf": csrf, "estado": "mitigada"}).status_code, 302)
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT estado FROM threats WHERE id=?", (t,)).fetchone()[0], "mitigada")

    def test_ciberseguridad_no_remedia(self):
        rid = self.remediaciones[(self.srv_id, CVE_AMBOS)]
        cli = self._cliente("ciberseguridad")
        csrf = self._csrf(cli)
        self.assertEqual(cli.post(f"/remediaciones/{rid}/comprobar", data={"csrf": csrf}).status_code, 403)
        self.assertEqual(cli.post(f"/remediaciones/{rid}/nota",
                                  data={"csrf": csrf, "texto": "no debería"}).status_code, 403)

    def test_solo_administracion_y_ciberseguridad_cambian_el_estado_de_una_amenaza(self):
        t = self.amenazas[CVE_SRV]
        for rol in ("redes", "mantenimiento"):
            cli = self._cliente(rol)
            csrf = self._csrf(cli)
            with self.subTest(rol=rol):
                self.assertEqual(cli.post(f"/amenazas/{t}/estado",
                                          data={"csrf": csrf, "estado": "mitigada"}).status_code, 403)
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT estado FROM threats WHERE id=?", (t,)).fetchone()[0], "nueva")
        ciberseguridad = self._cliente("ciberseguridad")
        r = ciberseguridad.post(f"/amenazas/{t}/estado",
                               data={"csrf": self._csrf(ciberseguridad), "estado": "en_analisis", "motivo": "prueba"})
        self.assertEqual(r.status_code, 302)
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute("SELECT estado FROM threats WHERE id=?", (t,)).fetchone()[0],
                             "en_analisis")
            auditado = conn.execute("SELECT username FROM audit_log WHERE action='amenaza.estado' "
                                    "ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(auditado["username"], USUARIOS["ciberseguridad"])

    def test_evaluar_un_cve_contra_un_activo_es_de_operacion(self):
        """«¿Le aplica este CVE?» escribe en la base: administración y ciberseguridad. Se
        envía un identificador mal formado para que la vista responda sin salir a Internet."""
        for rol in ("redes", "mantenimiento"):
            cli = self._cliente(rol)
            with self.subTest(rol=rol):
                self.assertEqual(cli.post(f"/activos/{self.srv_id}/aplica",
                                          data={"csrf": self._csrf(cli), "cve": "malo"}).status_code, 403)
        ciberseguridad = self._cliente("ciberseguridad")
        r = ciberseguridad.post(f"/activos/{self.srv_id}/aplica", data={"csrf": self._csrf(ciberseguridad), "cve": "malo"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("formato CVE-AAAA-NNNN", r.get_data(as_text=True))

    def test_ciberseguridad_no_administra(self):
        cli = self._cliente("ciberseguridad")
        csrf = self._csrf(cli)
        for url in ("/usuarios/crear", "/ajustes/guardar", f"/fuentes/{self.fuente_id}/probar",
                    "/activos/sincronizar", f"/tecnologias/{self.tec_id}/version"):
            with self.subTest(url=url):
                self.assertEqual(cli.post(url, data={"csrf": csrf}).status_code, 403, url)


# ==========================================================================
# Menú y avances
# ==========================================================================
class TestMenuYAvances(BaseRoles):

    def _menu(self, html: str) -> str:
        return html.split('<nav class="nav"')[1].split("</nav>")[0]

    def test_fuentes_solo_en_el_menu_de_administracion(self):
        admin = self._menu(self._html(self._cliente("admin"), "/"))
        self.assertIn('href="/fuentes/"', admin)
        self.assertLess(admin.index("Administración"), admin.index('href="/fuentes/"'),
                        "Fuentes va dentro del grupo Administración")
        for rol in ("ciberseguridad", "redes", "mantenimiento"):
            menu = self._menu(self._html(self._cliente(rol), "/"))
            with self.subTest(rol=rol):
                self.assertNotIn('href="/fuentes/"', menu, f"{rol} recibe un enlace a Fuentes en el menú")
                self.assertNotIn("Administración", menu)
                self.assertNotIn("Fuentes", menu)

    def test_informes_en_el_menu_solo_de_quien_puede_generarlos(self):
        for rol in auth.ROLES:
            menu = self._menu(self._html(self._cliente(rol), "/"))
            with self.subTest(rol=rol):
                if rol == "admin":
                    self.assertIn('href="/informes/"', menu)
                else:
                    self.assertNotIn('href="/informes/"', menu)

    def test_ningun_enlace_del_menu_devuelve_403(self):
        """Cada enlace del menú de cada perfil debe abrirse: un enlace que lleva a
        «Acceso inválido» es un callejón sin salida."""
        for rol in auth.ROLES:
            cli = self._cliente(rol)
            menu = self._menu(self._html(cli, "/"))
            for url in sorted(set(re.findall(r'href="(/[^"]*)"', menu))):
                with self.subTest(rol=rol, url=url):
                    self.assertEqual(cli.get(url).status_code, 200, f"{rol}: {url}")

    def test_la_barra_superior_dice_el_perfil(self):
        self.assertIn("· Redes", self._html(self._cliente("redes"), "/"))
        self.assertIn("· Mantenimiento", self._html(self._cliente("mantenimiento"), "/"))
        self.assertIn("· Ciberseguridad", self._html(self._cliente("ciberseguridad"), "/"))
        # El administrador no muestra el rol en la barra superior (es obvio)

    def test_avance_por_tipo_de_maquina_solo_para_admin(self):
        """El avance por tipo de máquina (servidores y equipos) solo lo ve el administrador."""
        html = self._html(self._cliente("admin"), "/remediaciones/")
        self.assertIn('id="avance-por-tipo"', html)
        bloque = html.split('id="avance-por-tipo"')[1].split("Por proceso de negocio")[0]
        self.assertIn("Servidores", bloque)
        self.assertIn("Equipos de cómputo", bloque)
        self.assertIn("Actualizaciones pendientes", bloque)
        self.assertIn("Vulnerabilidades pendientes", bloque)
        self.assertIn("Días de media hasta corregir", bloque)
        # Adaptado el 2026-09-15 (auditoría de tableros): la columna ya no es un
        # «porcentaje corregido» que dividía un flujo de 30 días entre un stock de
        # hoy, sino el avance de la cola que ya existía al empezar el periodo.
        self.assertIn("Avance del periodo", bloque)
        self.assertNotIn("Porcentaje corregido", bloque)
        # Cada cifra con su unidad y nunca «equipos» a secas.
        self.assertIn("2 <span class=\"pequeno suave\">vulnerabilidades</span>", bloque)
        self.assertIsNone(re.search(r"\bequipos\b(?! de cómputo)", bloque),
                          "«equipos» a secas en el bloque de avances")
        # En este juego de datos todo se detectó hoy: no hay cola anterior, así que
        # no se inventa ningún porcentaje y se dan las dos cifras por separado.
        self.assertIn("Sin porcentaje: no hay cola anterior con la que medirlo", bloque)
        self.assertIn("(movimiento)", bloque)
        self.assertIn("(foto de hoy)", bloque)
        self.assertNotIn(" %</strong>", bloque)
        for rol in ("ciberseguridad", "redes", "mantenimiento"):
            with self.subTest(rol=rol):
                self.assertNotIn('id="avance-por-tipo"',
                                 self._html(self._cliente(rol), "/remediaciones/"))

    def test_el_avance_del_periodo_sale_de_la_cola_que_ya_estaba_pendiente(self):
        """Avance del periodo (reescrita el 2026-09-15, auditoría de tableros).

        Antes esta prueba fijaba «50,0 % corregido: 1 de 2 filas de remediación», donde el
        2 era 1 fila cerrada en 30 días más 1 fila pendiente hoy: un flujo sumado a un
        stock. Ahora se fija el único porcentaje que se puede calcular sin mezclar
        magnitudes: las dos remediaciones del servidor pasan a detectarse hace 60 días (así
        existe una cola anterior al periodo) y se cierra una dentro del periodo, así que el
        avance es 1 de 2 de esa MISMA cola. Los equipos de cómputo no cambian y siguen sin
        cola anterior, luego siguen sin porcentaje.
        """
        rid = self.remediaciones[(self.srv_id, CVE_AMBOS)]
        with db.session(self.ruta) as conn:
            conn.execute("UPDATE remediaciones SET detectado_at=strftime('%Y-%m-%dT%H:%M:%SZ','now','-60 days') "
                         "WHERE activo_id=?", (self.srv_id,))
            conn.execute("UPDATE remediaciones SET estado='corregida', corregido_at=?, version_final='1.2' WHERE id=?",
                         (db.utcnow(), rid))
        try:
            html = self._html(self._cliente("admin"), "/remediaciones/")
            bloque = html.split('id="avance-por-tipo"')[1].split("Por proceso de negocio")[0]
            servidores = bloque.split("Equipos de cómputo")[0]
            self.assertIn("50,0 %", servidores)
            self.assertIn("1 de 2 filas de remediación que ya estaban pendientes el", servidores)
            # El numerador y el denominador son de la misma cohorte: nunca se suma lo
            # corregido del periodo a lo pendiente de hoy.
            self.assertNotIn("de 2 filas de remediación</span></div>", servidores.replace("\n", ""))
            equipos = bloque.split("Equipos de cómputo", 1)[1]
            self.assertIn("Sin porcentaje: no hay cola anterior con la que medirlo", equipos)
        finally:
            with db.session(self.ruta) as conn:
                conn.execute("UPDATE remediaciones SET estado='abierta', corregido_at=NULL, version_final=NULL "
                             "WHERE id=?", (rid,))
                conn.execute("UPDATE remediaciones SET detectado_at=? WHERE activo_id=?",
                             (db.utcnow(), self.srv_id))

    def test_usuarios_ofrece_los_seis_perfiles_con_su_alcance(self):
        html = self._html(self._cliente("admin"), "/usuarios/")
        for rol in auth.ROLES:
            with self.subTest(rol=rol):
                self.assertIn(f'<option value="{rol}"', html)
                self.assertIn(auth.ROL_ALCANCE_ES[rol], html)

    def test_las_plantillas_tocadas_no_llevan_estilo_ni_codigo_en_linea(self):
        for rol in ("ciberseguridad", "redes"):
            for url in ("/", "/remediaciones/", "/activos/", "/amenazas/"):
                html = self._html(self._cliente(rol), url)
                with self.subTest(rol=rol, url=url):
                    self.assertIsNone(re.search(r"\sstyle\s*=", html))
                    self.assertIsNone(re.search(r"\son[a-z]+\s*=", html))


if __name__ == "__main__":
    unittest.main()
