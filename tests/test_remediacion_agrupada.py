"""Deduplicación de remediaciones por actualización y acciones desde /remediaciones/ (2026-09-08).

Dos quejas del usuario el 2026-09-08, las dos cubiertas aquí:

1. «sigo viendo duplicidad en el reporte de vulnerabilidades y fue lo que pedí, si hay una
   vulnerabilidad de kernel que se repite que se cuente como una y se vea como la
   trazabilidad de las versiones a las que se solicita actualizar». Antes lo había
   explicado así (2026-09-07): «una vulnerabilidad de kernel hoy me dice que se debe
   actualizar a la versión 5.4 pero mañana me dice que debo actualizar a la versión 5.6
   porque la 5.4 ya es vulnerable, es decir que se cree como una cola de estas que puedan
   llegar a ser de lo mismo (…) y así evitar duplicados y reprocesos».
2. «No veo tampoco la opción de que servicios tecnológicos pueda documentar sobre una
   vulnerabilidad en un activo»: las dos acciones existían pero solo en la ficha del
   activo, no en la página de Remediación, que es la que ese perfil tiene en su menú.

Lo que estas pruebas fijan y que no se puede perder:
  - La versión objetivo de un grupo es la MÁS ALTA, comparada con el comparador de la
    distribución y NUNCA como texto: «6.12.100-1» es mayor que «6.12.95-1» aunque su texto
    sea menor. Medido en producción el 2026-09-08, el orden de texto elegía la versión
    equivocada en 313 de los 14.870 grupos con versión objetivo.
  - La trazabilidad lista cada CVE con la versión que pedía, de la más alta a la más baja.
  - Los grupos respetan los mismos filtros que el listado por CVE y la paginación de 20.
  - Servicios Tecnológicos ve y puede usar las dos acciones desde /remediaciones/, un
    perfil de solo lectura no las ve ni las puede enviar, y sin csrf no se escribe nada.

Sin red: activos, amenazas, software y remediaciones se insertan a mano en una base
temporal.
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import db, remediacion
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
from webui import auth  # noqa: E402

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)

CLAVE = "ClaveSegura#2026"

#: Las nueve versiones que los avisos del kernel pidieron para un mismo servidor Debian de
#: producción (caso real del 2026-09-08). El orden de texto pondría «6.12.96-1» como la
#: mayor, porque compara carácter a carácter y '9' va después de '1'; la correcta es
#: 6.12.105-1, y quien instalara la 6.12.96-1 se quedaría sin tres correcciones.
VERSIONES_KERNEL_REALES = ("6.12.85-1", "6.12.86-1", "6.12.90-1", "6.12.94-1", "6.12.95-1",
                           "6.12.96-1", "6.12.100-1", "6.12.101-1", "6.12.105-1")


def _activo(conn, nombre, *, familia="debian", origen="servidores", proceso="Pila",
            entorno="produccion", presente=1, ip="10.0.0.1"):
    cur = conn.execute(
        """INSERT INTO activos(origen, ocs_id, nombre, so_familia, so_nombre, ip, entorno,
                               proceso, presente, ultimo_inventario, primera_vez_at, visto_at)
           VALUES(?, (SELECT COALESCE(MAX(ocs_id), 0) + 1 FROM activos), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (origen, nombre, familia, f"{familia} 13", ip, entorno, proceso, presente,
         db.utcnow(), db.utcnow(), db.utcnow()))
    return cur.lastrowid


def _amenaza(conn, cve, *, severity="High", in_kev=0, titulo=None):
    cur = conn.execute(
        """INSERT INTO threats(fingerprint, cve, title_en, title_es, severity, first_seen_at,
                               last_seen_at, month, estado, in_kev)
           VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'nueva', ?)""",
        (f"fp-{cve}", cve, f"{cve} english", titulo, severity, db.utcnow(), db.utcnow(),
         db.utcnow()[:7], in_kev))
    return cur.lastrowid


def _software(conn, activo_id, paquete, version):
    conn.execute("""INSERT OR REPLACE INTO activo_software(activo_id, nombre, nombre_norm, version)
                    VALUES(?,?,?,?)""", (activo_id, paquete, paquete, version))


def _actualizar_software(conn, activo_id, paquete, version):
    """Sustituye la version instalada de un paquete (OCS ve la nueva y solo la nueva).

    No sirve un INSERT OR REPLACE: la clave primaria de ``activo_software`` es
    (activo_id, nombre, version), asi que insertar otra version deja las dos filas y el
    equipo parece tener las dos versiones a la vez.
    """
    conn.execute("DELETE FROM activo_software WHERE activo_id=? AND nombre_norm=?",
                 (activo_id, paquete))
    _software(conn, activo_id, paquete, version)


def _remediacion(conn, activo_id, threat_id, cve, paquete, vulnerable, corregida, *,
                 estado="abierta", detectado_at=None, aviso=None):
    """Una remediación abierta, con su fila de aplicabilidad para que tenga «aviso»."""
    detectado_at = detectado_at or db.utcnow()
    cur = conn.execute(
        """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete, version_vulnerable,
                version_corregida, motor, estado, detectado_at, comprobado_at)
           VALUES(?,?,?,?,?,?,'osv',?,?,?)""",
        (activo_id, threat_id, cve, paquete, vulnerable, corregida, estado, detectado_at,
         db.utcnow()))
    if aviso:
        conn.execute(
            """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada,
                    version_corregida, veredicto, motor, evidencia, aviso, evaluado_at, referencia)
               VALUES(?,?,?,?,?,?,'afectado','osv','prueba',?,?,?)""",
            (activo_id, threat_id, cve, paquete, vulnerable, corregida, aviso,
             detectado_at, f"https://ejemplo/{aviso}"))
    return cur.lastrowid


# ==========================================================================
# 1. La versión objetivo: la más alta, con el comparador de la distribución
# ==========================================================================
class TestVersionObjetivo(unittest.TestCase):
    """Funciones puras: se prueban sin base de datos porque es donde está el riesgo."""

    def test_la_mas_alta_no_es_la_del_orden_de_texto(self):
        """El fallo concreto que hacía elegir mal: '6.12.100-1' < '6.12.95-1' como texto."""
        self.assertLess("6.12.100-1", "6.12.95-1", "como texto, la 100 parece menor")
        self.assertEqual(
            remediacion.version_objetivo("debian", ["6.12.95-1", "6.12.100-1"]),
            "6.12.100-1")
        self.assertEqual(remediacion.version_objetivo("debian", VERSIONES_KERNEL_REALES),
                         "6.12.105-1")
        self.assertEqual(max(VERSIONES_KERNEL_REALES), "6.12.96-1",
                         "el orden de texto elegiría esta, que deja tres fallos sin corregir")

    def test_la_cola_de_versiones_va_de_la_mas_alta_a_la_mas_baja(self):
        cola = remediacion.ordenar_versiones("debian", VERSIONES_KERNEL_REALES)
        self.assertEqual(cola, ["6.12.105-1", "6.12.101-1", "6.12.100-1", "6.12.96-1",
                                "6.12.95-1", "6.12.94-1", "6.12.90-1", "6.12.86-1",
                                "6.12.85-1"])

    def test_cada_familia_usa_su_comparador(self):
        """FreeBSD y Ubuntu no comparan igual: pkg y dpkg. Un solo comparador se equivoca."""
        # pkg: el sufijo «_13» es la revisión, mayor que «_10»
        self.assertEqual(remediacion.version_objetivo("freebsd", ["15.0_10", "15.0_13"]),
                         "15.0_13")
        # dpkg: la época manda sobre el número de versión
        self.assertEqual(remediacion.version_objetivo("ubuntu", ["2:1.0", "9.9"]), "2:1.0")

    def test_sin_versiones_no_hay_objetivo(self):
        for entrada in ([], [None], ["", "  "], [None, ""]):
            self.assertIsNone(remediacion.version_objetivo("debian", entrada), entrada)
            self.assertEqual(remediacion.ordenar_versiones("debian", entrada), [])

    def test_las_repetidas_cuentan_una_vez(self):
        self.assertEqual(
            remediacion.ordenar_versiones("debian", ["1.2", "1.2", " 1.2 ", "1.3"]),
            ["1.3", "1.2"])


# ==========================================================================
# 2. La agrupación sobre la base de datos
# ==========================================================================
class TestAgrupacion(unittest.TestCase):
    """El caso del kernel: veintinueve avisos, una sola actualización."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "agrupada.db")
        db.init_db(self.ruta)
        self.conn = db.connect(self.ruta)
        c = self.conn
        self.srv = _activo(c, "srv-kernel-01", ip="10.0.0.11")
        self.pc = _activo(c, "pc-contable-01", origen="equipos", proceso="", ip="10.0.0.90",
                          entorno="desarrollo")
        _software(c, self.srv, "linux-image-amd64", "6.12.74-2")
        _software(c, self.srv, "curl", "7.81.0")
        _software(c, self.pc, "firefox", "120.0")
        # Tres avisos del kernel con tres versiones objetivo distintas, uno de ellos KEV
        self.kernel = {}
        for cve, version, sev, kev, aviso in (
                ("CVE-2026-0085", "6.12.85-1", "High", 1, "DSA-5001"),
                ("CVE-2026-0095", "6.12.95-1", "Critical", 0, "DSA-5002"),
                ("CVE-2026-0100", "6.12.100-1", "Medium", 0, None)):
            t = _amenaza(c, cve, severity=sev, in_kev=kev, titulo=f"Fallo del núcleo {cve}")
            self.kernel[cve] = _remediacion(
                c, self.srv, t, cve, "linux-image-amd64", "6.12.74-2", version,
                detectado_at="2026-09-01T08:00:00Z" if cve == "CVE-2026-0095" else db.utcnow(),
                aviso=aviso)
        # Un paquete distinto en el mismo servidor: otro grupo. Severidad media y no baja
        # (2026-09-10): la baja no cuenta en nada, asi que una remediacion de severidad
        # baja no saldria en ninguna de estas cifras (ver tests/test_severidad_baja.py).
        t_curl = _amenaza(c, "CVE-2026-0200", severity="Medium")
        self.rem_curl = _remediacion(c, self.srv, t_curl, "CVE-2026-0200", "curl",
                                     "7.81.0", "7.82.0", aviso="DSA-5003")
        # Un grupo en el equipo de cómputo
        t_ff = _amenaza(c, "CVE-2026-0300", severity="High")
        self.rem_ff = _remediacion(c, self.pc, t_ff, "CVE-2026-0300", "firefox",
                                   "120.0", "121.0")

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    def _grupo(self, grupos, paquete):
        for g in grupos:
            if g["paquete"] == paquete:
                return g
        self.fail(f"sin grupo para «{paquete}»: {[g['paquete'] for g in grupos]}")

    def test_tres_avisos_del_kernel_son_una_sola_actualizacion(self):
        self.assertEqual(remediacion.contar(self.conn, estado="abierta"), 5,
                         "cinco vulnerabilidades pendientes")
        self.assertEqual(remediacion.contar_actualizaciones(self.conn), 3,
                         "que son tres actualizaciones: kernel, curl y firefox")
        g = self._grupo(remediacion.listar_actualizaciones(self.conn), "linux-image-amd64")
        self.assertEqual(g["vulnerabilidades"], 3)
        self.assertEqual(g["version_objetivo"], "6.12.100-1",
                         "la más alta; el orden de texto habría elegido 6.12.95-1")
        self.assertEqual(g["version_instalada"], "6.12.74-2")
        self.assertEqual(g["versiones_pedidas"], 3)
        self.assertEqual(g["activo_nombre"], "srv-kernel-01")
        self.assertEqual(g["pendientes"], 3)
        self.assertEqual(sorted(g["remediacion_ids"]), sorted(self.kernel.values()))
        self.assertEqual(sorted(g["remediacion_ids_pendientes"]), sorted(self.kernel.values()))

    def test_la_severidad_y_el_kev_del_grupo_son_los_peores(self):
        g = self._grupo(remediacion.listar_actualizaciones(self.conn), "linux-image-amd64")
        self.assertEqual(g["severidad"], "Critical", "la peor de las tres")
        self.assertTrue(g["in_kev"], "un solo CVE en KEV marca la actualización entera")

    def test_los_dias_de_espera_son_los_de_la_deteccion_mas_antigua(self):
        """El usuario tiene que ver cuánto lleva esperando la más vieja, no la más nueva."""
        g = self._grupo(remediacion.listar_actualizaciones(self.conn), "linux-image-amd64")
        self.assertEqual(g["detectado_at"], "2026-09-01T08:00:00Z")
        self.assertGreaterEqual(g["dias"], 7)

    def test_la_trazabilidad_lista_cada_cve_con_su_version(self):
        """Lo que pidió el usuario: «que se vea la trazabilidad de las versiones a las que
        se solicita actualizar»."""
        g = self._grupo(remediacion.listar_actualizaciones(self.conn), "linux-image-amd64")
        self.assertEqual([v["version"] for v in g["versiones"]],
                         ["6.12.100-1", "6.12.95-1", "6.12.85-1"],
                         "de la más alta a la más baja, no en orden de texto")
        self.assertEqual([v["es_objetivo"] for v in g["versiones"]], [True, False, False])
        self.assertEqual([v["total"] for v in g["versiones"]], [1, 1, 1])
        # cada versión con el CVE que la pedía y su aviso
        pedidos = {c["cve"]: (v["version"], c["aviso"])
                   for v in g["versiones"] for c in v["cves"]}
        self.assertEqual(pedidos["CVE-2026-0085"], ("6.12.85-1", "DSA-5001"))
        self.assertEqual(pedidos["CVE-2026-0095"], ("6.12.95-1", "DSA-5002"))
        self.assertEqual(pedidos["CVE-2026-0100"], ("6.12.100-1", None))
        # la lista plana lleva los mismos CVE, en el mismo orden
        self.assertEqual([c["cve"] for c in g["cves"]],
                         ["CVE-2026-0100", "CVE-2026-0095", "CVE-2026-0085"])
        # y el título traducido de la amenaza, para poder leerla
        self.assertEqual(g["cves"][0]["titulo"], "Fallo del núcleo CVE-2026-0100")

    def test_una_vulnerabilidad_sin_version_conocida_se_lista_aparte(self):
        """No se puede inventar una versión objetivo: si el aviso no la da, se dice."""
        t = _amenaza(self.conn, "CVE-2026-0999", severity="Critical")
        _remediacion(self.conn, self.srv, t, "CVE-2026-0999", "linux-image-amd64",
                     "6.12.74-2", None)
        g = self._grupo(remediacion.listar_actualizaciones(self.conn), "linux-image-amd64")
        self.assertEqual(g["vulnerabilidades"], 4)
        self.assertEqual(g["version_objetivo"], "6.12.100-1", "las conocidas siguen mandando")
        self.assertEqual(g["sin_version_objetivo"], 1)
        self.assertIsNone(g["versiones"][-1]["version"], "las sin versión, al final")
        self.assertEqual([c["cve"] for c in g["versiones"][-1]["cves"]], ["CVE-2026-0999"])

    def test_sin_ninguna_version_conocida_no_hay_objetivo(self):
        t = _amenaza(self.conn, "CVE-2026-0800")
        _remediacion(self.conn, self.pc, t, "CVE-2026-0800", "libreoffice", "7.0", None)
        g = self._grupo(remediacion.listar_actualizaciones(self.conn), "libreoffice")
        self.assertIsNone(g["version_objetivo"])
        self.assertEqual(g["versiones_pedidas"], 0)
        self.assertEqual(g["sin_version_objetivo"], 1)

    def test_los_grupos_respetan_los_filtros(self):
        # por proceso
        grupos = remediacion.listar_actualizaciones(self.conn, proceso="Pila")
        self.assertEqual({g["paquete"] for g in grupos}, {"linux-image-amd64", "curl"})
        self.assertEqual(remediacion.contar_actualizaciones(self.conn, proceso="Pila"), 2)
        # el equipo de cómputo sin proceso cae en su propio grupo, no en «Sin proceso»
        grupos = remediacion.listar_actualizaciones(
            self.conn, proceso=remediacion.GRUPO_EQUIPOS_SIN_PROCESO)
        self.assertEqual([g["paquete"] for g in grupos], ["firefox"])
        # por texto: nombre del activo, IP, CVE o paquete
        self.assertEqual([g["paquete"] for g in remediacion.listar_actualizaciones(
            self.conn, q="linux-image")], ["linux-image-amd64"])
        self.assertEqual([g["paquete"] for g in remediacion.listar_actualizaciones(
            self.conn, q="10.0.0.90")], ["firefox"])
        self.assertEqual(remediacion.contar_actualizaciones(self.conn, q="srv-kernel"), 2)
        # un comodín de LIKE se busca como texto literal, no devuelve todo
        self.assertEqual(remediacion.contar_actualizaciones(self.conn, q="%"), 0)

    def test_un_cve_concreto_no_baja_la_version_objetivo_del_grupo(self):
        """Los filtros deciden QUÉ GRUPOS se muestran, no qué versión hay que instalar.

        Este comportamiento estaba al contrario hasta el 2026-09-08, y esta prueba fijaba
        el error: con «q=CVE-2026-0085» el grupo del núcleo se recortaba a esa fila y la
        página decía «Actualizar a 6.12.85-1» cuando la versión que resuelve ese paquete
        en ese servidor es la más alta del grupo. El buscador invita a buscar por CVE
        («Activo, IP, CVE o paquete»), así que quien ejecutara esa fila instalaba una
        versión que deja el equipo vulnerable: el fallo exacto que la vista agrupada
        existe para evitar. Ahora la versión objetivo y la cola de versiones se calculan
        siempre sobre TODAS las filas de (activo, paquete), y la fila dice cuántas de sus
        vulnerabilidades casan con la búsqueda.
        """
        grupos = remediacion.listar_actualizaciones(self.conn, q="CVE-2026-0085")
        self.assertEqual(len(grupos), 1)
        g = grupos[0]
        # el grupo sigue siendo el grupo entero: su versión objetivo es la más alta
        self.assertEqual(g["version_objetivo"], "6.12.100-1")
        self.assertGreater(g["vulnerabilidades"], 1)
        # y se dice cuánto de él coincide con la búsqueda, para que nadie lea la fila
        # como una actualización de una sola vulnerabilidad
        self.assertEqual(g["coincidencias"], 1)
        # sin filtro no hay nada que aclarar
        sin_filtro = [x for x in remediacion.listar_actualizaciones(self.conn)
                      if x["paquete"] == g["paquete"]][0]
        self.assertIsNone(sin_filtro["coincidencias"])
        self.assertEqual(sin_filtro["version_objetivo"], g["version_objetivo"])
        self.assertEqual(sin_filtro["vulnerabilidades"], g["vulnerabilidades"])

    def test_el_estado_filtra_igual_que_el_listado_por_cve(self):
        self.conn.execute("""UPDATE remediaciones SET estado='corregida', corregido_at=?,
                                 version_final='7.82.0', cerrado_motivo=? WHERE id=?""",
                          (db.utcnow(), remediacion.MOTIVO_CORREGIDA.format(version="7.82.0"),
                           self.rem_curl))
        self.assertEqual(remediacion.contar_actualizaciones(self.conn, estado="abierta"), 2)
        corregidas = remediacion.listar_actualizaciones(self.conn, estado="corregida")
        self.assertEqual([g["paquete"] for g in corregidas], ["curl"])
        self.assertEqual(corregidas[0]["estado"], "corregida")
        self.assertEqual(corregidas[0]["estado_es"], "Corregida")
        self.assertEqual(corregidas[0]["pendientes"], 0)
        self.assertEqual(remediacion.contar_actualizaciones(self.conn, estado=None), 3)

    def test_un_grupo_a_medio_corregir_cuenta_lo_que_queda(self):
        """La versión objetivo se calcula con lo que sigue pendiente: es lo que hay que
        instalar. Lo ya corregido no puede subir el objetivo."""
        self.conn.execute("UPDATE remediaciones SET estado='corregida', corregido_at=? WHERE id=?",
                          (db.utcnow(), self.kernel["CVE-2026-0100"]))
        g = self._grupo(remediacion.listar_actualizaciones(self.conn, estado=None),
                        "linux-image-amd64")
        self.assertEqual((g["pendientes"], g["corregidas"]), (2, 1))
        self.assertEqual(g["estado"], "abierta", "mientras quede algo pendiente, está pendiente")
        self.assertEqual(g["version_objetivo"], "6.12.95-1",
                         "la más alta de las que siguen pendientes")
        self.assertEqual(g["vulnerabilidades"], 3, "la trazabilidad no pierde la corregida")

    def test_el_orden_pone_primero_lo_peor_y_lo_mas_antiguo(self):
        grupos = remediacion.listar_actualizaciones(self.conn)
        self.assertEqual([g["paquete"] for g in grupos],
                         ["linux-image-amd64", "firefox", "curl"],
                         "KEV primero; luego severidad; el equipo de desarrollo (High) "
                         "antes que el servidor con la media")

    def test_la_paginacion_de_veinte_no_parte_ni_repite_grupos(self):
        """El usuario pidió «que en cada uno solo muestre de a 20»."""
        for i in range(25):
            t = _amenaza(self.conn, f"CVE-2026-9{i:03d}")
            _remediacion(self.conn, self.pc, t, f"CVE-2026-9{i:03d}", f"paquete{i:03d}",
                         "1.0", "2.0")
        total = remediacion.contar_actualizaciones(self.conn)
        self.assertEqual(total, 28, "25 paquetes nuevos más los tres grupos anteriores")
        primera = remediacion.listar_actualizaciones(self.conn, limite=20, desplazamiento=0)
        segunda = remediacion.listar_actualizaciones(self.conn, limite=20, desplazamiento=20)
        self.assertEqual(len(primera), 20)
        self.assertEqual(len(segunda), 8)
        claves_1 = {g["clave"] for g in primera}
        claves_2 = {g["clave"] for g in segunda}
        self.assertEqual(len(claves_1), 20, "sin grupos repetidos dentro de la página")
        self.assertEqual(claves_1 & claves_2, set(), "las páginas no se solapan")
        self.assertEqual(len(claves_1 | claves_2), total, "y entre las dos están todos")

    def test_las_notas_y_la_ultima_comprobacion_se_ven_en_el_grupo(self):
        """Requisito 6: que se vea si alguien ya lo intentó y qué respondió el sistema."""
        remediacion.anotar(self.conn, self.kernel["CVE-2026-0085"], autor="sistemas",
                           texto="Programado para la ventana del sábado.")
        remediacion.anotar(self.conn, self.kernel["CVE-2026-0095"], autor="sistemas",
                           texto="Requiere reinicio del servidor.")
        remediacion.comprobar(self.conn, self.kernel["CVE-2026-0095"], solicitante="sistemas")
        g = self._grupo(remediacion.listar_actualizaciones(self.conn), "linux-image-amd64")
        self.assertEqual(g["notas"], 2, "la suma de las notas del grupo")
        self.assertEqual(g["comprobacion_veredicto"], "sigue_vulnerable")
        self.assertIn("Sigue vulnerable", g["comprobacion_veredicto_es"])
        self.assertEqual(g["comprobacion_clave"], "critico")
        self.assertEqual(g["comprobacion_pedida_por"], "sistemas")
        self.assertIsNotNone(g["comprobacion_at"])

    def test_el_resumen_dice_las_dos_magnitudes_por_separado(self):
        res = remediacion.resumen(self.conn, dias=30)
        self.assertEqual(res["abiertas"], 5, "vulnerabilidades pendientes")
        self.assertEqual(res["actualizaciones"], 3, "actualizaciones pendientes")
        self.assertEqual(res["activos_con_abiertas"], 2)
        self.assertEqual(res["servidores_con_abiertas"], 1)
        self.assertEqual(res["equipos_con_abiertas"], 1,
                         "los equipos de cómputo se cuentan aparte de los servidores")


# ==========================================================================
# 3. Acciones sobre toda la actualización
# ==========================================================================
class TestAccionesDeGrupo(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "grupo.db")
        db.init_db(self.ruta)
        self.conn = db.connect(self.ruta)
        self.srv = _activo(self.conn, "srv-kernel-01")
        _software(self.conn, self.srv, "linux-image-amd64", "6.12.74-2")
        self.ids = []
        for cve, version in (("CVE-2026-0085", "6.12.85-1"), ("CVE-2026-0095", "6.12.95-1"),
                             ("CVE-2026-0100", "6.12.100-1")):
            t = _amenaza(self.conn, cve)
            self.ids.append(_remediacion(self.conn, self.srv, t, cve, "linux-image-amd64",
                                         "6.12.74-2", version))
        # otro paquete: no debe verse afectado por las acciones de grupo
        t = _amenaza(self.conn, "CVE-2026-0200")
        self.otro = _remediacion(self.conn, self.srv, t, "CVE-2026-0200", "curl",
                                 "7.81.0", "7.82.0")

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    def _fila(self, rid):
        return dict(self.conn.execute("SELECT * FROM remediaciones WHERE id=?", (rid,)).fetchone())

    def test_comprobar_el_grupo_comprueba_las_tres_y_ninguna_mas(self):
        r = remediacion.comprobar_grupo(self.conn, self.ids[0], solicitante="sistemas")
        self.assertEqual(r["total"], 3)
        self.assertEqual(r["conteo"], {"sigue_vulnerable": 3})
        self.assertEqual(r["veredicto"], "sigue_vulnerable")
        self.assertEqual(r["version_objetivo"], "6.12.100-1")
        self.assertEqual(r["paquete"], "linux-image-amd64")
        self.assertEqual(r["cerradas"], 0, "ninguna se cierra: la versión instalada es anterior")
        for rid in self.ids:
            self.assertEqual(self._fila(rid)["comprobacion_veredicto"], "sigue_vulnerable")
            self.assertEqual(self._fila(rid)["estado"], "abierta")
        self.assertIsNone(self._fila(self.otro)["comprobacion_veredicto"],
                          "el otro paquete no se toca")
        # cada vulnerabilidad deja su propia constancia: la trazabilidad no se pierde
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM remediacion_comprobaciones").fetchone()[0], 3)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='remediacion.comprobar'").fetchone()[0], 3)

    def test_actualizar_de_verdad_cierra_las_tres_de_una_vez(self):
        """Es el sentido de agrupar: una sola actualización resuelve las tres."""
        _actualizar_software(self.conn, self.srv, "linux-image-amd64", "6.12.105-1")
        r = remediacion.comprobar_grupo(self.conn, self.ids[1], solicitante="sistemas")
        self.assertEqual(r["veredicto"], "corregida")
        self.assertEqual(r["conteo"], {"corregida": 3})
        self.assertEqual((r["resueltas"], r["cerradas"]), (3, 3))
        for rid in self.ids:
            fila = self._fila(rid)
            self.assertEqual(fila["estado"], "corregida", rid)
            self.assertEqual(fila["version_final"], "6.12.105-1")
        self.assertEqual(self._fila(self.otro)["estado"], "abierta")

    def test_documentar_el_grupo_guarda_la_misma_nota_en_las_tres(self):
        r = remediacion.anotar_grupo(self.conn, self.ids[2], autor="sistemas",
                                     texto="Programado para la ventana del sábado; requiere reinicio.")
        self.assertEqual(r["total"], 3)
        for rid in self.ids:
            self.assertEqual(self._fila(rid)["notas"], 1, rid)
            self.assertEqual(remediacion.notas(self.conn, rid)[0]["texto"],
                             "Programado para la ventana del sábado; requiere reinicio.")
        self.assertEqual(self._fila(self.otro)["notas"] or 0, 0)

    def test_una_nota_vacia_no_escribe_nada(self):
        with self.assertRaises(ValueError):
            remediacion.anotar_grupo(self.conn, self.ids[0], autor="sistemas", texto="  ")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM remediacion_notas").fetchone()[0], 0)

    def test_una_remediacion_que_no_existe_da_un_error_claro(self):
        for funcion, kwargs in ((remediacion.comprobar_grupo, {"solicitante": "x"}),
                                (remediacion.anotar_grupo, {"autor": "x", "texto": "algo que decir"})):
            with self.subTest(funcion=funcion.__name__):
                with self.assertRaises(ValueError):
                    funcion(self.conn, 99999, **kwargs)

    def test_si_no_queda_nada_pendiente_solo_actua_sobre_la_indicada(self):
        """Documentar algo ya cerrado es legítimo, pero no puede arrastrar al resto."""
        self.conn.execute("UPDATE remediaciones SET estado='corregida', corregido_at=?",
                          (db.utcnow(),))
        r = remediacion.anotar_grupo(self.conn, self.ids[0], autor="sistemas",
                                     texto="Se verificó a mano en la consola.")
        self.assertEqual(r["total"], 1)
        self.assertEqual(self._fila(self.ids[0])["notas"], 1)
        self.assertEqual(self._fila(self.ids[1])["notas"] or 0, 0)


# ==========================================================================
# 4. La página: las dos acciones donde el usuario las buscaba
# ==========================================================================
class TestAccionesEnLaPagina(unittest.TestCase):
    """«No veo tampoco la opción de que servicios tecnológicos pueda documentar sobre una
    vulnerabilidad en un activo» (2026-09-08): estaban solo en la ficha del activo."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "pagina_grupo.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
            auth.crear_usuario(conn, "sistemas@ejemplo.local", CLAVE,
                               rol="admin", nombre="Persona de Sistemas",
                               actor="t")
            auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Lectora Sin Permisos", actor="t")
            cls.srv = _activo(conn, "srv-kernel-01", ip="10.0.0.11")
            _software(conn, cls.srv, "linux-image-amd64", "6.12.74-2")
            cls.ids = {}
            for cve, version, aviso in (("CVE-2026-0085", "6.12.85-1", "DSA-5001"),
                                        ("CVE-2026-0095", "6.12.95-1", "DSA-5002"),
                                        ("CVE-2026-0100", "6.12.100-1", None)):
                t = _amenaza(conn, cve, titulo=f"Fallo del núcleo {cve}")
                cls.ids[cve] = _remediacion(conn, cls.srv, t, cve, "linux-image-amd64",
                                            "6.12.74-2", version, aviso=aviso)
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, usuario):
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

    def _csrf(self, cli, url="/remediaciones/"):
        encontrado = re.search(r'name="csrf" value="([^"]+)"', self._html(cli, url))
        self.assertIsNotNone(encontrado, "sin token csrf en la página")
        return encontrado.group(1)

    def _estado(self, rid):
        with db.session(self.ruta) as conn:
            return dict(conn.execute("SELECT * FROM remediaciones WHERE id=?", (rid,)).fetchone())

    # ---------------------------------------------------------------- lo que se ve
    def test_la_pagina_agrupa_y_muestra_la_trazabilidad_sin_javascript(self):
        html = self._html(self._cliente("lectora@ejemplo.local"))
        zona = html.split('id="tabla-remediaciones"')[1]
        self.assertIn("Actualizaciones pendientes", html)
        self.assertIn("3 filas de remediación", html, "dice de cuántas vulnerabilidades sale")
        self.assertIn("6.12.100-1", zona)
        self.assertIn("Actualizar a", zona)
        self.assertIn("La más alta de las 3 versiones", zona)
        # la trazabilidad se despliega con <details>, no con un script
        self.assertIn("<details>", zona)
        self.assertIn("versión objetivo", zona)
        for cve in self.ids:
            self.assertIn(cve, zona)
        self.assertIn("DSA-5001", zona, "el aviso que pedía cada versión")
        self.assertNotIn("<script>", zona)
        # una sola fila de actualización en la tabla
        self.assertEqual(zona.count('id="rem-'), 1)

    def test_servicios_tecnologicos_ve_las_dos_acciones(self):
        html = self._html(self._cliente("sistemas@ejemplo.local"))
        zona = html.split('id="tabla-remediaciones"')[1]
        self.assertIn("Ya se actualizó: comprobar las 3", zona)
        self.assertIn("Se comprobarán las 3 vulnerabilidades que cubre esta actualización", zona)
        self.assertIn("Documentar", zona)
        self.assertIn('name="alcance" value="grupo"', zona)
        self.assertIn("/comprobar", zona)
        self.assertIn("/nota", zona)
        self.assertIn('name="csrf"', zona)
        # etiqueta visible en el formulario de la nota, no solo un texto de ayuda
        self.assertRegex(zona, r'<label for="nota-actualizacion-\d+">Qué se hizo o qué falta</label>')
        self.assertIn("<textarea", zona)
        # y también en la vista por vulnerabilidad
        porcve = self._html(self._cliente("sistemas@ejemplo.local"),
                            "/remediaciones/?vista=vulnerabilidad")
        zona = porcve.split('id="tabla-remediaciones"')[1]
        self.assertIn("Ya está remediada: comprobar", zona)
        self.assertRegex(zona, r'<label for="nota-\d+">Qué se hizo o qué falta</label>')
        self.assertNotIn('name="alcance" value="grupo"', zona,
                         "por vulnerabilidad se actúa sobre una, no sobre el grupo")

    def test_la_administradora_tambien_las_ve(self):
        zona = self._html(self._cliente("jefa@ejemplo.local")).split('id="tabla-remediaciones"')[1]
        self.assertIn("Ya se actualizó: comprobar las 3", zona)
        self.assertIn("Se comprobarán las 3 vulnerabilidades que cubre esta actualización", zona)
        self.assertIn("Documentar", zona)

    def test_un_perfil_de_solo_lectura_no_las_ve(self):
        for url in ("/remediaciones/", "/remediaciones/?vista=vulnerabilidad"):
            with self.subTest(url=url):
                zona = self._html(self._cliente("lectora@ejemplo.local"),
                                  url).split('id="tabla-remediaciones"')[1]
                self.assertNotIn("comprobar", zona)
                self.assertNotIn("<textarea", zona)
                self.assertNotIn('name="alcance"', zona)

    # ---------------------------------------------------------------- lo que se puede enviar
    def test_servicios_tecnologicos_comprueba_toda_la_actualizacion(self):
        cli = self._cliente("sistemas@ejemplo.local")
        csrf = self._csrf(cli)
        r = cli.post(f"/remediaciones/{self.ids['CVE-2026-0085']}/comprobar",
                     data={"csrf": csrf, "alcance": "grupo",
                           "volver": "/remediaciones/?estado=abierta"},
                     follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("se comprobaron las 3 vulnerabilidades", html,
                      "el mensaje dice que se aplicó al grupo entero")
        self.assertIn("6.12.100-1", html)
        self.assertIn("siguen vulnerables", html)
        for rid in self.ids.values():
            self.assertEqual(self._estado(rid)["comprobacion_veredicto"], "sigue_vulnerable")
            self.assertEqual(self._estado(rid)["estado"], "abierta",
                             "marcarlo no cierra nada: la plataforma decide")

    def test_servicios_tecnologicos_documenta_toda_la_actualizacion(self):
        cli = self._cliente("sistemas@ejemplo.local")
        csrf = self._csrf(cli)
        r = cli.post(f"/remediaciones/{self.ids['CVE-2026-0095']}/nota",
                     data={"csrf": csrf, "alcance": "grupo",
                           "texto": "Programado para la ventana del sábado.",
                           "volver": "/remediaciones/"}, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn("Nota guardada en las 3 vulnerabilidades", r.get_data(as_text=True))
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM remediacion_notas WHERE autor='sistemas@ejemplo.local'"
            ).fetchone()[0], 3)

    def test_una_nota_de_una_sola_vulnerabilidad_no_arrastra_al_grupo(self):
        cli = self._cliente("jefa@ejemplo.local")
        csrf = self._csrf(cli)
        antes = self._estado(self.ids["CVE-2026-0100"])["notas"] or 0
        r = cli.post(f"/remediaciones/{self.ids['CVE-2026-0100']}/nota",
                     data={"csrf": csrf, "texto": "Solo este CVE se mitigó con una regla."},
                     follow_redirects=True)
        self.assertIn("Nota guardada.", r.get_data(as_text=True))
        self.assertEqual(self._estado(self.ids["CVE-2026-0100"])["notas"], antes + 1)

    def test_la_lectora_no_puede_enviar_ninguna_de_las_dos(self):
        cli = self._cliente("lectora@ejemplo.local")
        csrf = self._csrf(cli)
        rid = self.ids["CVE-2026-0085"]
        for url, datos in ((f"/remediaciones/{rid}/comprobar", {"alcance": "grupo"}),
                           (f"/remediaciones/{rid}/nota", {"alcance": "grupo", "texto": "algo"})):
            with self.subTest(url=url):
                self.assertEqual(cli.post(url, data=dict(datos, csrf=csrf)).status_code, 403)

    def test_sin_csrf_no_se_escribe_nada(self):
        cli = self._cliente("sistemas@ejemplo.local")
        rid = self.ids["CVE-2026-0085"]
        for url, datos in ((f"/remediaciones/{rid}/comprobar", {"alcance": "grupo"}),
                           (f"/remediaciones/{rid}/nota", {"alcance": "grupo", "texto": "algo"})):
            with self.subTest(url=url):
                self.assertEqual(cli.post(url, data=datos).status_code, 400)
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM remediacion_notas WHERE texto='algo'").fetchone()[0], 0)

    def test_el_destino_de_vuelta_no_puede_salir_del_sitio(self):
        """El campo «volver» no puede convertirse en un salto a otro dominio."""
        cli = self._cliente("sistemas@ejemplo.local")
        csrf = self._csrf(cli)
        r = cli.post(f"/remediaciones/{self.ids['CVE-2026-0100']}/comprobar",
                     data={"csrf": csrf, "volver": "//evil.example/x"})
        self.assertEqual(r.status_code, 302)
        self.assertNotIn("evil.example", r.headers.get("Location", ""))


# ==========================================================================
# 6. Hallazgos de la revisión adversaria del 2026-09-08
# ==========================================================================
class TestHallazgosDeLaRevision(unittest.TestCase):
    """Cada prueba fija uno de los defectos que la revisión encontró en la primera
    versión de la vista agrupada. Base propia para no depender del orden de las demás."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "revision.db")
        db.init_db(self.ruta)
        self.addCleanup(self.dir.cleanup)

    def test_la_version_instalada_es_la_que_ocs_ve_hoy(self):
        """«Instalada: X» usaba ``version_vulnerable``, que se congela al detectar y no se
        actualiza nunca: 326 filas (164 actualizaciones) de producción mandaban instalar
        una versión que la máquina ya tenía. La versión de verdad está en
        ``activo_software``, que es la que usa ``comprobar``."""
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-kernel-02")
            t = _amenaza(conn, "CVE-2026-0201")
            _remediacion(conn, activo, t, "CVE-2026-0201", "linux-image-amd64",
                         "6.8.0-138.138", "6.8.0-139.139")
            # OCS ya reporta la versión que corrige (el equipo se actualizó solo)
            _software(conn, activo, "linux-image-amd64", "6.8.0-139.139")
            g = remediacion.listar_actualizaciones(conn)[0]
        self.assertEqual(g["version_instalada"], "6.8.0-139.139")
        self.assertTrue(g["version_instalada_es_real"])
        self.assertEqual(g["version_detectada"], "6.8.0-138.138")

    def test_si_ocs_no_reporta_el_paquete_se_dice_que_es_la_de_la_deteccion(self):
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-kernel-03")
            t = _amenaza(conn, "CVE-2026-0202")
            _remediacion(conn, activo, t, "CVE-2026-0202", "openssl", "1.0", "2.0")
            g = remediacion.listar_actualizaciones(conn)[0]
        self.assertEqual(g["version_instalada"], "1.0")
        self.assertFalse(g["version_instalada_es_real"])

    def test_la_version_instalada_con_dos_arquitecturas_es_la_mas_alta(self):
        """``_version_instalada`` elegía por ORDEN DE TEXTO: con dos versiones reales del
        mismo paquete (multiarquitectura, 315 casos en producción) podía comparar contra
        la más baja y decir «sigue vulnerable» un equipo ya corregido."""
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-multiarco-01")
            t = _amenaza(conn, "CVE-2026-0203")
            rid = _remediacion(conn, activo, t, "CVE-2026-0203", "libssl",
                               "6.12.95-1", "6.12.100-1")
            _software(conn, activo, "libssl", "6.12.95-1")
            _software(conn, activo, "libssl", "6.12.100-1")
            res = remediacion.comprobar(conn, rid, solicitante="pruebas")
        self.assertEqual(res["veredicto"], "corregida",
                         "el orden de texto habría elegido 6.12.95-1 y diría lo contrario")

    def test_el_veredicto_del_grupo_es_por_consenso_no_por_recencia(self):
        """La insignia verde «Corregida» aparecía en un grupo con dos de tres
        vulnerabilidades abiertas, porque se pintaba el veredicto de la ÚLTIMA
        comprobación de cualquiera de sus filas."""
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-parcial-01")
            ids = []
            for i, (cve, corrige) in enumerate((("CVE-2026-0301", "3.0"),
                                                ("CVE-2026-0302", "2.0"),
                                                ("CVE-2026-0303", "1.5"))):
                t = _amenaza(conn, cve)
                ids.append(_remediacion(conn, activo, t, cve, "openssl", "1.0", corrige))
            # la máquina está en la 2.0: corrige la tercera y la segunda, no la primera
            _software(conn, activo, "openssl", "2.0")
            for rid in ids:
                remediacion.comprobar(conn, rid, solicitante="pruebas")
            g = [x for x in remediacion.listar_actualizaciones(conn, estado=None)
                 if x["paquete"] == "openssl"][0]
        self.assertEqual(g["comprobacion_veredicto"], "sigue_vulnerable")
        self.assertEqual(g["comprobacion_clave"], "critico")
        self.assertNotIn("Corregida", g["comprobacion_veredicto_es"])
        self.assertEqual(g["comprobacion_comprobadas"], 3)
        self.assertEqual(g["comprobacion_corregidas"], 2)

    def test_los_dias_de_espera_no_son_los_de_una_fila_ya_cerrada(self):
        """``_DIAS`` vale «hasta hoy» para las abiertas y «hasta la corrección» para las
        cerradas, así que un MAX sobre un grupo mixto devolvía el tiempo de vida de una
        fila cerrada: «304 días esperando» cuando lo pendiente se detectó hace tres."""
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-mixto-01")
            t1 = _amenaza(conn, "CVE-2026-0401")
            t2 = _amenaza(conn, "CVE-2026-0402")
            _remediacion(conn, activo, t1, "CVE-2026-0401", "curl", "1.0", "2.0",
                         estado="corregida", detectado_at="2025-01-01T00:00:00Z")
            conn.execute("""UPDATE remediaciones SET corregido_at=?, version_final='2.0'
                             WHERE cve='CVE-2026-0401'""", (db.utcnow(),))
            hace_tres = conn.execute(
                "SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now','-3 days')").fetchone()[0]
            _remediacion(conn, activo, t2, "CVE-2026-0402", "curl", "2.0", "3.0",
                         detectado_at=hace_tres)
            g = [x for x in remediacion.listar_actualizaciones(conn, estado=None)
                 if x["paquete"] == "curl"][0]
        self.assertLessEqual(g["dias"], 4, "los días son los de lo que sigue esperando")
        self.assertGreater(g["dias_totales"], 300, "y el total sigue disponible")
        self.assertEqual(g["detectado_at"], hace_tres)

    def test_un_grupo_ya_corregido_no_dice_dias_esperando(self):
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-cerrado-01")
            t = _amenaza(conn, "CVE-2026-0403")
            _remediacion(conn, activo, t, "CVE-2026-0403", "curl", "1.0", "2.0",
                         estado="corregida")
            conn.execute("UPDATE remediaciones SET corregido_at=?, version_final='2.0'",
                         (db.utcnow(),))
            g = remediacion.listar_actualizaciones(conn, estado=None)[0]
        self.assertIsNone(g["dias"], "no queda nada esperando")
        self.assertIsNotNone(g["dias_totales"])
        self.assertEqual(g["version_final"], "2.0")

    def test_el_mismo_aviso_en_varios_paquetes_del_activo_se_dice(self):
        """La otra mitad de la queja del usuario: el mismo CVE del núcleo aparecía como
        tres «actualizaciones» del mismo servidor (linux-image-amd64 y dos binarios de
        versión) sin nada que dijera que es UN solo aviso.

        Adaptada el 2026-09-09: dos de los tres binarios tienen la misma versión instalada,
        la misma versión objetivo y el mismo CVE, así que ahora SON una sola actualización
        («Núcleo Linux», fusión por origen de paquete). El tercero tiene otra versión
        instalada: queda en su propia fila y las dos filas se señalan como hermanas, con el
        CVE que comparten."""
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-kernel-04")
            t = _amenaza(conn, "CVE-2026-0501")
            for paquete in ("linux-image-amd64", "linux-image-6.12.73-amd64"):
                _remediacion(conn, activo, t, "CVE-2026-0501", paquete, "1.0", "2.0")
            _remediacion(conn, activo, t, "CVE-2026-0501", "linux-image-6.12.74-amd64",
                         "1.1", "2.0")
            grupos = remediacion.listar_actualizaciones(conn)
        self.assertEqual(len(grupos), 2, "una fusión de dos binarios y el tercero aparte")
        fusion = next(g for g in grupos if g["es_fusion"])
        aparte = next(g for g in grupos if not g["es_fusion"])
        self.assertEqual({p["paquete"] for p in fusion["paquetes"]},
                         {"linux-image-amd64", "linux-image-6.12.73-amd64"})
        self.assertEqual(aparte["paquete"], "linux-image-6.12.74-amd64")
        self.assertEqual([(h["paquete"], h["cves"]) for h in fusion["hermanos"]],
                         [("linux-image-6.12.74-amd64", 1)])
        self.assertEqual({h["paquete"] for h in aparte["hermanos"]},
                         {"linux-image-amd64", "linux-image-6.12.73-amd64"})
        self.assertEqual([h["cves"] for h in aparte["hermanos"]], [1, 1])

    def test_la_vulnerabilidad_repetida_se_cuenta_una_vez_en_el_resumen(self):
        """«Si hay una vulnerabilidad de kernel que se repite que se cuente como una»:
        tres filas del mismo CVE en la misma máquina son UNA vulnerabilidad y, desde el
        2026-09-09, también UNA actualización (los tres binarios de sssd salen del mismo
        origen: misma versión instalada, misma objetivo, mismo CVE)."""
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-kernel-05")
            t = _amenaza(conn, "CVE-2026-0601")
            for paquete in ("sssd", "sssd-common", "sssd-ldap"):
                _remediacion(conn, activo, t, "CVE-2026-0601", paquete, "1.0", "2.0")
            r = remediacion.resumen(conn)
        self.assertEqual(r["abiertas"], 3, "tres filas de remediación")
        self.assertEqual(r["actualizaciones"], 1, "una sola actualización: el origen sssd")
        self.assertEqual(r["actualizaciones_con_version"], 1)
        self.assertEqual(r["vulnerabilidades_unicas"], 1, "una sola vulnerabilidad")
        self.assertEqual(r["cve_distintos"], 1)

    def test_el_indicador_separa_lo_que_ya_tiene_version_que_instalar(self):
        """La tarjeta prometía que «instalar la versión más alta resuelve todas sus
        vulnerabilidades», y para 4.414 de los 19.284 grupos de producción no hay nada
        que instalar todavía."""
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-sinversion-01")
            t1 = _amenaza(conn, "CVE-2026-0701")
            t2 = _amenaza(conn, "CVE-2026-0702")
            _remediacion(conn, activo, t1, "CVE-2026-0701", "curl", "1.0", "2.0")
            _remediacion(conn, activo, t2, "CVE-2026-0702", "zlib", "1.0", None)
            r = remediacion.resumen(conn)
        self.assertEqual(r["actualizaciones"], 2)
        self.assertEqual(r["actualizaciones_con_version"], 1)
        self.assertEqual(r["actualizaciones_sin_version"], 1)

    def test_el_resumen_de_la_trazabilidad_cuenta_lo_que_lista(self):
        """El desplegable decía «1 versión solicitada» y al abrirlo había dos elementos,
        porque la entrada «sin versión conocida» se listaba y no se contaba."""
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-cola-01")
            t1 = _amenaza(conn, "CVE-2026-0801")
            t2 = _amenaza(conn, "CVE-2026-0802")
            _remediacion(conn, activo, t1, "CVE-2026-0801", "curl", "1.0", "2.0")
            _remediacion(conn, activo, t2, "CVE-2026-0802", "curl", "1.0", None)
            g = remediacion.listar_actualizaciones(conn)[0]
        self.assertEqual(g["versiones_pedidas"], 1)
        self.assertEqual(g["sin_version_objetivo"], 1)
        self.assertEqual(len(g["versiones"]), g["versiones_pedidas"] + 1,
                         "la lista lleva una entrada más: la de sin versión conocida")


# ==========================================================================
# 7. Revisión de seguridad del 2026-09-08 (hallazgo crítico y medios)
# ==========================================================================
class TestComprobarWindowsYFreeBsd(unittest.TestCase):
    """Hallazgo CRÍTICO: `comprobar` leía «el paquete no está en activo_software» como
    «desinstalado» y cerraba la remediación. Los parches de Windows (motor msrc, paquete
    «windows») y el sistema base de FreeBSD («freebsd», «freebsd-kernel») NUNCA están en
    esa tabla, por diseño: en producción, un solo clic de grupo habría cerrado como
    corregidas 797 vulnerabilidades de un equipo de cómputo sin ninguna prueba, y la
    sincronización no las reabría porque su aplicabilidad está en «sin_dato».
    """

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "windows.db")
        db.init_db(self.ruta)
        self.addCleanup(self.dir.cleanup)

    def _windows(self, conn, build):
        activo = _activo(conn, "pc-win-01", familia="windows", origen="equipos", proceso=None)
        conn.execute("UPDATE activos SET windows_build=?, so_version='10.0.26200' WHERE id=?",
                     (build, activo))
        ids = []
        for i in range(3):
            t = _amenaza(conn, f"CVE-2026-9{i:03d}")
            rid = conn.execute(
                """INSERT INTO remediaciones(activo_id, threat_id, cve, paquete, version_vulnerable,
                        version_corregida, motor, estado, detectado_at, comprobado_at)
                   VALUES(?,?,?,'windows','10.0.26200.8037','10.0.26200.8875','msrc','abierta',?,?)""",
                (activo, t, f"CVE-2026-9{i:03d}", db.utcnow(), db.utcnow())).lastrowid
            ids.append(rid)
        return activo, ids

    def test_windows_sin_kb_reconocida_no_se_cierra_nunca(self):
        with db.session(self.ruta) as conn:
            _activo_id, ids = self._windows(conn, None)
            res = remediacion.comprobar_grupo(conn, ids[0], solicitante="sistemas")
            abiertas = conn.execute(
                "SELECT COUNT(*) FROM remediaciones WHERE estado='abierta'").fetchone()[0]
        self.assertEqual(res["conteo"], {"sin_datos": 3})
        self.assertEqual(res["cerradas"], 0)
        self.assertEqual(abiertas, 3, "ni una sola se cierra sin prueba")
        self.assertIn("boletines de Microsoft", res["resultados"][0]["detalle"])

    def test_windows_se_compara_por_compilacion(self):
        with db.session(self.ruta) as conn:
            _activo_id, ids = self._windows(conn, "10.0.26200.8037")
            r = remediacion.comprobar(conn, ids[0], solicitante="sistemas")
            self.assertEqual(r["veredicto"], "sigue_vulnerable")
            self.assertFalse(r["cerrada"])
            conn.execute("UPDATE activos SET windows_build='10.0.26200.9106'")
            r = remediacion.comprobar(conn, ids[1], solicitante="sistemas")
            self.assertEqual(r["veredicto"], "corregida")
            self.assertTrue(r["cerrada"])
            self.assertIn("compilación", r["detalle"])

    def test_el_sistema_base_de_freebsd_se_compara_con_la_version_del_sistema(self):
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-bsd-01", familia="freebsd")
            conn.execute("UPDATE activos SET so_version='14.4-RELEASE-p6' WHERE id=?", (activo,))
            t = _amenaza(conn, "CVE-2026-9500")
            rid = _remediacion(conn, activo, t, "CVE-2026-9500", "freebsd", "14.4_6", "14.4_9")
            r = remediacion.comprobar(conn, rid, solicitante="sistemas")
            self.assertEqual(r["veredicto"], "sigue_vulnerable", "14.4_6 < 14.4_9")
            self.assertEqual(r["version_instalada"], "14.4_6")
            conn.execute("UPDATE activos SET so_version='14.4-RELEASE-p9' WHERE id=?", (activo,))
            r = remediacion.comprobar(conn, rid, solicitante="sistemas")
            self.assertEqual(r["veredicto"], "corregida")
            # y sin version del sistema, «sin datos», jamas «desinstalado»
            activo2 = _activo(conn, "srv-bsd-02", familia="freebsd", ip="10.0.0.2")
            conn.execute("UPDATE activos SET so_version=NULL WHERE id=?", (activo2,))
            rid2 = _remediacion(conn, activo2, t, "CVE-2026-9500", "freebsd-kernel", "14.4_6", "14.4_9")
            r = remediacion.comprobar(conn, rid2, solicitante="sistemas")
            self.assertEqual(r["veredicto"], "sin_datos")

    def test_un_paquete_de_verdad_desinstalado_sigue_contando_como_corregido(self):
        """La rama «desinstalado» sigue valiendo para los paquetes que SÍ deberían estar
        en activo_software: es la que cubre tests.test_rol_servicios_tecnologicos."""
        with db.session(self.ruta) as conn:
            activo = _activo(conn, "srv-deb-01")
            t = _amenaza(conn, "CVE-2026-9600")
            rid = _remediacion(conn, activo, t, "CVE-2026-9600", "telnetd", "1.0", "2.0")
            r = remediacion.comprobar(conn, rid, solicitante="sistemas")
        self.assertEqual(r["veredicto"], "desinstalado")

    def test_la_version_instalada_de_la_vista_agrupada_tambien_sabe_de_windows_y_freebsd(self):
        with db.session(self.ruta) as conn:
            _activo_id, _ids = self._windows(conn, "10.0.26200.8875")
            bsd = _activo(conn, "srv-bsd-03", familia="freebsd", ip="10.0.0.3")
            conn.execute("UPDATE activos SET so_version='14.4-RELEASE-p6' WHERE id=?", (bsd,))
            t = _amenaza(conn, "CVE-2026-9700")
            _remediacion(conn, bsd, t, "CVE-2026-9700", "freebsd", "14.4_6", "14.4_9")
            grupos = {g["paquete"]: g for g in remediacion.listar_actualizaciones(conn)}
        self.assertEqual(grupos["windows"]["version_instalada"], "10.0.26200.8875")
        self.assertTrue(grupos["windows"]["version_instalada_es_real"])
        self.assertEqual(grupos["freebsd"]["version_instalada"], "14.4_6")


class TestTopeDeLasAccionesDeGrupo(unittest.TestCase):
    """Hallazgo BAJO: una sola petición de grupo escribía tantas filas y asientos de
    auditoría como vulnerabilidades tuviera el grupo, sin cota. Hay tope."""

    def test_por_encima_del_tope_no_se_escribe_nada(self):
        from unittest import mock
        d = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.addCleanup(d.cleanup)
        ruta = str(Path(d.name) / "tope.db")
        db.init_db(ruta)
        with db.session(ruta) as conn:
            activo = _activo(conn, "srv-grande-01")
            ids = []
            for i in range(4):
                t = _amenaza(conn, f"CVE-2026-8{i:03d}")
                ids.append(_remediacion(conn, activo, t, f"CVE-2026-8{i:03d}", "openssl", "1.0", "2.0"))
            with mock.patch.object(remediacion, "LIMITE_ACCION_GRUPO", 3):
                with self.assertRaises(ValueError) as ctx:
                    remediacion.comprobar_grupo(conn, ids[0], solicitante="sistemas")
                with self.assertRaises(ValueError):
                    remediacion.anotar_grupo(conn, ids[0], autor="sistemas", texto="x")
            self.assertIn("tope por petición", str(ctx.exception))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM remediacion_comprobaciones").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM remediacion_notas").fetchone()[0], 0)
            # por debajo del tope funciona igual que siempre
            res = remediacion.comprobar_grupo(conn, ids[0], solicitante="sistemas")
            self.assertEqual(res["total"], 4)


class TestEnlaceAPaquetesHermanos(unittest.TestCase):
    """Hallazgo MEDIO: el enlace a un paquete hermano buscaba su nombre con «q» y llevaba
    a los grupos de TODOS los activos (106 en vez de 1). Ahora acota por activo.

    Adaptada el 2026-09-09: los dos binarios llevan versiones instaladas DISTINTAS («1.0»
    y «1.1»), porque con la misma versión y el mismo CVE ya no son hermanos sino una sola
    actualización fusionada (ver TestFusionPorOrigen)."""

    def test_el_filtro_por_activo_deja_solo_sus_grupos(self):
        d = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.addCleanup(d.cleanup)
        ruta = str(Path(d.name) / "hermanos.db")
        db.init_db(ruta)
        with db.session(ruta) as conn:
            a1 = _activo(conn, "srv-k-01")
            a2 = _activo(conn, "srv-k-02", ip="10.0.0.2")
            t = _amenaza(conn, "CVE-2026-7001")
            for activo in (a1, a2):
                _remediacion(conn, activo, t, "CVE-2026-7001", "linux-image-amd64", "1.0", "2.0")
                _remediacion(conn, activo, t, "CVE-2026-7001", "linux-image-6.12.73-amd64",
                             "1.1", "2.0")
            self.assertEqual(remediacion.contar_actualizaciones(conn, q="linux-image-amd64"), 2)
            self.assertEqual(remediacion.contar_actualizaciones(conn, q="linux-image-amd64",
                                                                activo_id=a1), 1)
            grupos = remediacion.listar_actualizaciones(conn, q="linux-image-amd64", activo_id=a1)
            self.assertEqual([(g["activo_id"], g["paquete"]) for g in grupos],
                             [(a1, "linux-image-amd64")])
            self.assertEqual(remediacion.contar(conn, estado="abierta", activo_id=a2), 2)

    def test_la_pagina_enlaza_los_hermanos_con_el_activo_y_lo_dice(self):
        d = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.addCleanup(d.cleanup)
        ruta = str(Path(d.name) / "hermanos_web.db")
        db.init_db(ruta)
        with db.session(ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin", nombre="Jefa", actor="t")
            a1 = _activo(conn, "srv-k-11")
            t = _amenaza(conn, "CVE-2026-7002")
            _remediacion(conn, a1, t, "CVE-2026-7002", "linux-image-amd64", "1.0", "2.0")
            _remediacion(conn, a1, t, "CVE-2026-7002", "linux-image-6.12.73-amd64", "1.1", "2.0")
        from webui.app import crear_app
        app = crear_app(db_path=ruta, testing=True)
        cli = app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        html = cli.get("/remediaciones/").get_data(as_text=True)
        self.assertRegex(html, rf'href="/remediaciones/\?[^"]*activo={a1}[^"]*q=linux-image')
        acotada = cli.get(f"/remediaciones/?activo={a1}&q=linux-image-amd64").get_data(as_text=True)
        self.assertIn('id="aviso-activo-acotado"', acotada)
        self.assertIn("Solo las actualizaciones del activo", acotada)
        self.assertIn("srv-k-11", acotada)
        self.assertIn("1 actualización ·", acotada)
        # un identificador negativo o no numerico no rompe nada
        self.assertEqual(cli.get("/remediaciones/?activo=-5").status_code, 200)
        self.assertEqual(cli.get("/remediaciones/?activo=abc").status_code, 200)


# ==========================================================================
# 8. Una actualización por ORIGEN de paquete (2026-09-09)
#
# El usuario lo reclamó por segunda vez: en el activo 413 el núcleo salía cinco veces
# (linux-headers, linux-image, linux-modules, linux-tools… de 6.8.0-60.63 a 6.8.0-60.63.1
# con los mismos 32 CVE) y sssd dieciocho. Regla: dentro de un activo, los grupos
# (activo, paquete) con la MISMA versión instalada, la MISMA versión objetivo y el MISMO
# conjunto de CVE pendientes son una sola actualización. Medido en producción: 19.283
# grupos pasan a 8.864 actualizaciones; el núcleo, de 688 a 554.
# ==========================================================================
PAQUETES_NUCLEO = ("linux-headers-6.8.0-60-generic", "linux-image-6.8.0-60-generic",
                   "linux-modules-6.8.0-60-generic", "linux-tools-6.8.0-60-generic")
CVES_NUCLEO = ("CVE-2026-1101", "CVE-2026-1102", "CVE-2026-1103")
PAQUETES_SSSD = ("sssd", "sssd-ad", "sssd-ad-common", "sssd-common", "sssd-ipa", "sssd-krb5",
                 "sssd-krb5-common", "sssd-ldap", "sssd-proxy", "sssd-tools", "libnss-sss",
                 "libpam-sss", "libsss-certmap0", "libsss-idmap0", "libsss-nss-idmap0",
                 "libsss-sudo", "python3-sss", "libipa-hbac0")


class TestNombreActualizacion(unittest.TestCase):
    """Función pura: cómo se llama una fila que junta varios paquetes."""

    def test_nucleo_con_variante_comun(self):
        n = remediacion.nombre_actualizacion(PAQUETES_NUCLEO)
        self.assertEqual(n["nombre"], "Núcleo Linux 6.8.0-60-generic")
        self.assertTrue(n["es_nucleo"])
        self.assertEqual(n["variante"], "6.8.0-60-generic")
        self.assertEqual(n["principal"], "linux-image-6.8.0-60-generic")
        self.assertEqual(n["otros"], 3)

    def test_nucleo_con_modules_extra_y_unsigned(self):
        n = remediacion.nombre_actualizacion(("linux-modules-extra-6.8.0-60-generic",
                                              "linux-image-unsigned-6.8.0-60-generic",
                                              "linux-tools-6.8.0-60"))
        self.assertEqual(n["nombre"], "Núcleo Linux 6.8.0-60-generic",
                         "«6.8.0-60» es prefijo de la variante más larga")

    def test_nucleo_sin_prefijo_comun_usa_la_variante_con_version(self):
        """Adaptada el 2026-09-09 (revisión visual): antes esperaba «Núcleo Linux» a secas.

        Es el caso más frecuente de producción —«linux-image-amd64» conviven con
        «linux-image-6.12.90+deb13.1-amd64» en el mismo activo— y ninguna de las dos
        variantes es prefijo de la otra, así que la regla anterior dejaba la fila sin
        versión: 121 de las 124 filas fusionadas del núcleo se llamaban igual, y 65
        servidores compartían el nombre «Núcleo Linux». Ahora se elige la variante que
        lleva un número de versión, que es la que identifica el núcleo.
        """
        n = remediacion.nombre_actualizacion(("linux-image-amd64", "linux-image-6.12.73+deb13-amd64"))
        self.assertEqual(n["nombre"], "Núcleo Linux 6.12.73+deb13-amd64")
        self.assertEqual(n["variante"], "6.12.73+deb13-amd64")
        self.assertEqual(n["variante_origen"], "paquete")
        self.assertTrue(n["es_nucleo"])

    def test_nucleo_sin_ninguna_version_en_los_nombres_usa_la_instalada(self):
        """«linux-perf» con «linux-tools-common»: ningún nombre lleva la versión (13 casos
        de producción el 2026-09-09). Se usa la versión que OCS Inventory ve instalada y se
        dice de dónde sale, en ``variante_origen``, para que la plantilla lo explique."""
        n = remediacion.nombre_actualizacion(("linux-perf", "linux-tools-common"),
                                             version_instalada="6.12.90-1")
        self.assertEqual(n["nombre"], "Núcleo Linux 6.12.90-1")
        self.assertEqual(n["variante_origen"], "instalada")
        # Sin versión instalada conocida no se inventa nada.
        sin = remediacion.nombre_actualizacion(("linux-perf", "linux-tools-common"))
        self.assertEqual(sin["nombre"], "Núcleo Linux")
        self.assertIsNone(sin["variante_origen"])
        # «amd64» tiene dígitos pero no es una versión: no puede colarse como tal.
        solo_arquitectura = remediacion.nombre_actualizacion(
            ("linux-image-amd64", "linux-headers-amd64"))
        self.assertEqual(solo_arquitectura["nombre"], "Núcleo Linux amd64",
                         "«amd64» es la variante común de los dos, no una versión")
        self.assertEqual(solo_arquitectura["variante_origen"], "paquete")

    def test_paquete_principal_es_el_prefijo_comun_o_el_mas_corto(self):
        self.assertEqual(remediacion.nombre_actualizacion(PAQUETES_SSSD)["nombre"],
                         "sssd y 17 paquetes más")
        self.assertEqual(remediacion.nombre_actualizacion(("libssl3t64", "openssl"))["nombre"],
                         "openssl y 1 paquete más")
        self.assertEqual(remediacion.nombre_actualizacion(("clamav-base", "clamav", "libclamav12",
                                                           "clamav-freshclam"))["principal"], "clamav")

    def test_un_solo_paquete_se_llama_como_el_paquete(self):
        n = remediacion.nombre_actualizacion(["linux-tools-common"])
        self.assertEqual((n["nombre"], n["es_nucleo"], n["otros"]), ("linux-tools-common", False, 0))
        self.assertEqual(remediacion.nombre_actualizacion([])["nombre"], "—")


class TestFusionPorOrigen(unittest.TestCase):
    """El caso del activo 413, reducido: cuatro binarios del núcleo con los mismos tres CVE,
    un linux-tools-common con otra versión, y los dieciocho binarios de sssd."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.addCleanup(self.dir.cleanup)
        self.ruta = str(Path(self.dir.name) / "fusion.db")
        db.init_db(self.ruta)
        self.conn = db.connect(self.ruta)
        self.addCleanup(self.conn.close)
        c = self.conn
        self.srv = _activo(c, "srv-413", ip="10.0.0.13")
        self.amenazas = {cve: _amenaza(c, cve, severity=sev, in_kev=kev)
                         for cve, sev, kev in (("CVE-2026-1101", "High", 0),
                                               ("CVE-2026-1102", "Critical", 1),
                                               ("CVE-2026-1103", "Medium", 0))}
        self.ids_nucleo: dict = {}
        # Se insertan en orden barajado a propósito: la firma no puede depender del orden.
        orden = [(p, cve) for p in PAQUETES_NUCLEO for cve in CVES_NUCLEO]
        orden = orden[::-1][1:] + orden[::-1][:1]
        for paquete, cve in orden:
            _software(c, self.srv, paquete, "6.8.0-60.63")
            self.ids_nucleo[(paquete, cve)] = _remediacion(
                c, self.srv, self.amenazas[cve], cve, paquete, "6.8.0-60.63", "6.8.0-60.63.1",
                aviso=f"USN-{cve[-4:]}")
        # linux-tools-common: otra versión instalada y objetivo, comparte dos de los tres CVE
        _software(c, self.srv, "linux-tools-common", "6.8.0-101.101")
        self.ids_tools = [
            _remediacion(c, self.srv, self.amenazas[cve], cve, "linux-tools-common",
                         "6.8.0-101.101", "6.8.0-139.139")
            for cve in CVES_NUCLEO[:2]]
        # sssd: dieciocho binarios, un CVE
        t_sssd = _amenaza(c, "CVE-2026-1200", severity="High")
        self.ids_sssd = []
        for paquete in PAQUETES_SSSD:
            _software(c, self.srv, paquete, "2.6.3-1ubuntu3.8")
            self.ids_sssd.append(_remediacion(c, self.srv, t_sssd, "CVE-2026-1200", paquete,
                                              "2.6.3-1ubuntu3.8", "2.6.3-1ubuntu3.9"))

    def _por_nombre(self, grupos, nombre):
        for g in grupos:
            if g["nombre"] == nombre:
                return g
        self.fail(f"sin actualización «{nombre}»: {[g['nombre'] for g in grupos]}")

    # ---------------------------------------------------------------- (1) el núcleo es una
    def test_cuatro_binarios_del_nucleo_son_una_actualizacion(self):
        grupos = remediacion.listar_actualizaciones(self.conn)
        self.assertEqual(remediacion.contar(self.conn, estado="abierta"), 12 + 2 + 18,
                         "las filas de remediación no cambian")
        self.assertEqual(remediacion.contar_actualizaciones(self.conn), 3,
                         "núcleo, linux-tools-common y sssd")
        self.assertEqual(len(grupos), 3)
        nucleo = self._por_nombre(grupos, "Núcleo Linux 6.8.0-60-generic")
        self.assertTrue(nucleo["es_fusion"])
        self.assertTrue(nucleo["es_nucleo"])
        self.assertEqual(nucleo["vulnerabilidades"], 3, "tres CVE distintos, no doce")
        self.assertEqual(nucleo["pendientes"], 3)
        self.assertEqual(nucleo["filas"], 12)
        self.assertEqual(nucleo["filas_pendientes"], 12)
        self.assertEqual(nucleo["n_paquetes"], 4)
        self.assertEqual([p["paquete"] for p in nucleo["paquetes"]],
                         ["linux-image-6.8.0-60-generic", "linux-headers-6.8.0-60-generic",
                          "linux-modules-6.8.0-60-generic", "linux-tools-6.8.0-60-generic"],
                         "el principal primero y el resto por nombre")
        for p in nucleo["paquetes"]:
            self.assertEqual(p["version_instalada"], "6.8.0-60.63")
            self.assertTrue(p["version_instalada_es_real"])
            self.assertEqual(p["filas"], 3)
        self.assertEqual(nucleo["version_instalada"], "6.8.0-60.63")
        self.assertEqual(nucleo["version_objetivo"], "6.8.0-60.63.1")
        self.assertFalse(nucleo["instaladas_distintas"])
        self.assertEqual(nucleo["severidad"], "Critical")
        self.assertTrue(nucleo["in_kev"])
        self.assertEqual(sorted(nucleo["remediacion_ids"]), sorted(self.ids_nucleo.values()))
        self.assertEqual(sorted(nucleo["remediacion_ids_pendientes"]),
                         sorted(self.ids_nucleo.values()))
        # la trazabilidad lista cada CVE UNA vez y dice en cuántos paquetes está
        self.assertEqual([c["cve"] for c in nucleo["cves"]],
                         ["CVE-2026-1102", "CVE-2026-1101", "CVE-2026-1103"],
                         "KEV y gravedad primero, dentro de la única versión")
        for c in nucleo["cves"]:
            self.assertEqual(c["n_paquetes"], 4)
            self.assertEqual(len(c["ids"]), 4)
        self.assertEqual(nucleo["versiones_pedidas"], 1)
        self.assertEqual(nucleo["versiones"][0]["total"], 3)
        self.assertEqual(nucleo["clave"], f"{self.srv}-linux-image-6.8.0-60-generic")

    # ---------------------------------------------------------------- (2) el que no cumple
    def test_linux_tools_common_va_aparte_y_es_hermano(self):
        grupos = remediacion.listar_actualizaciones(self.conn)
        tools = self._por_nombre(grupos, "linux-tools-common")
        self.assertFalse(tools["es_fusion"])
        self.assertEqual(tools["paquete"], "linux-tools-common")
        self.assertEqual(tools["vulnerabilidades"], 2)
        self.assertEqual(tools["version_instalada"], "6.8.0-101.101")
        self.assertEqual(tools["version_objetivo"], "6.8.0-139.139")
        nucleo = self._por_nombre(grupos, "Núcleo Linux 6.8.0-60-generic")
        self.assertEqual([(h["paquete"], h["cves"]) for h in nucleo["hermanos"]],
                         [("linux-tools-common", 2)],
                         "comparte dos de los tres CVE pero necesita su propia orden")
        self.assertEqual({(h["paquete"], h["cves"]) for h in tools["hermanos"]},
                         {(p, 2) for p in PAQUETES_NUCLEO})
        # el enlace del hermano (q=paquete, activo=…) lleva a SU fila y a ninguna más
        acotado = remediacion.listar_actualizaciones(self.conn, q="linux-tools-common",
                                                     activo_id=self.srv)
        self.assertEqual([g["paquete"] for g in acotado], ["linux-tools-common"])
        self.assertEqual(remediacion.contar_actualizaciones(self.conn, q="linux-tools-common",
                                                            activo_id=self.srv), 1)

    # ---------------------------------------------------------------- (3) sssd
    def test_dieciocho_binarios_de_sssd_son_una_actualizacion_con_nombre(self):
        grupos = remediacion.listar_actualizaciones(self.conn)
        sssd = self._por_nombre(grupos, "sssd y 17 paquetes más")
        self.assertEqual(sssd["paquete"], "sssd")
        self.assertEqual(sssd["n_paquetes"], 18)
        self.assertEqual(sssd["vulnerabilidades"], 1)
        self.assertEqual(sssd["filas"], 18)
        self.assertEqual(sssd["paquetes"][0]["paquete"], "sssd", "el principal primero")
        self.assertEqual(sorted(sssd["remediacion_ids"]), sorted(self.ids_sssd))
        self.assertEqual(sssd["hermanos"], [], "nadie más pide su CVE")

    # ---------------------------------------------------------------- (4) distinto conjunto
    def test_misma_version_pero_distinto_conjunto_de_cve_no_se_fusiona(self):
        t = _amenaza(self.conn, "CVE-2026-1300")
        # dos paquetes con la misma versión instalada y objetivo; solo uno tiene el CVE extra
        for paquete in ("libpq5", "postgresql-client-16"):
            _remediacion(self.conn, self.srv, t, "CVE-2026-1300", paquete, "16.13", "16.15")
        t2 = _amenaza(self.conn, "CVE-2026-1301")
        _remediacion(self.conn, self.srv, t2, "CVE-2026-1301", "postgresql-client-16", "16.13", "16.15")
        grupos = remediacion.listar_actualizaciones(self.conn)
        nombres = sorted(g["nombre"] for g in grupos)
        self.assertIn("libpq5", nombres)
        self.assertIn("postgresql-client-16", nombres)
        self.assertNotIn("libpq5 y 1 paquete más", nombres)
        self.assertEqual(remediacion.contar_actualizaciones(self.conn), 5)
        # y son hermanos entre sí por el CVE que comparten
        libpq = self._por_nombre(grupos, "libpq5")
        self.assertEqual([(h["paquete"], h["cves"]) for h in libpq["hermanos"]],
                         [("postgresql-client-16", 1)])
        # misma versión objetivo pero distinta versión INSTALADA tampoco se fusiona
        t3 = _amenaza(self.conn, "CVE-2026-1302")
        _remediacion(self.conn, self.srv, t3, "CVE-2026-1302", "bzip2", "1.0.8-5.1", "1.0.8-5.2")
        _remediacion(self.conn, self.srv, t3, "CVE-2026-1302", "libbz2-1.0", "1.0.8-5.0", "1.0.8-5.2")
        self.assertEqual(remediacion.contar_actualizaciones(self.conn), 7)

    # ---------------------------------------------------------------- (5) acciones de grupo
    def test_comprobar_la_fusion_toca_todos_los_identificadores(self):
        r = remediacion.comprobar_grupo(self.conn, self.ids_nucleo[(PAQUETES_NUCLEO[2], CVES_NUCLEO[1])],
                                        solicitante="sistemas")
        self.assertEqual(r["total"], 12, "las doce filas de los cuatro paquetes")
        self.assertEqual(r["cves"], 3)
        self.assertEqual(r["paquetes"], list(PAQUETES_NUCLEO))
        self.assertEqual(r["nombre"], "Núcleo Linux 6.8.0-60-generic")
        self.assertEqual(r["conteo"], {"sigue_vulnerable": 12})
        for rid in self.ids_nucleo.values():
            fila = self.conn.execute("SELECT comprobacion_veredicto FROM remediaciones WHERE id=?",
                                     (rid,)).fetchone()
            self.assertEqual(fila[0], "sigue_vulnerable", rid)
        for rid in self.ids_tools + self.ids_sssd:
            fila = self.conn.execute("SELECT comprobacion_veredicto FROM remediaciones WHERE id=?",
                                     (rid,)).fetchone()
            self.assertIsNone(fila[0], "ni linux-tools-common ni sssd se tocan")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM remediacion_comprobaciones").fetchone()[0], 12)
        # actualizar los cuatro binarios cierra las doce de una vez
        for paquete in PAQUETES_NUCLEO:
            _actualizar_software(self.conn, self.srv, paquete, "6.8.0-60.63.1")
        r = remediacion.comprobar_grupo(self.conn, next(iter(self.ids_nucleo.values())),
                                        solicitante="sistemas")
        self.assertEqual((r["veredicto"], r["cerradas"]), ("corregida", 12))
        self.assertEqual(remediacion.contar_actualizaciones(self.conn), 2)

    def test_documentar_la_fusion_y_el_tope_por_peticion(self):
        from unittest import mock
        r = remediacion.anotar_grupo(self.conn, self.ids_sssd[5], autor="sistemas",
                                     texto="Actualización de sssd programada para el sábado.")
        self.assertEqual(r["total"], 18)
        self.assertEqual(r["nombre"], "sssd y 17 paquetes más")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM remediacion_notas").fetchone()[0], 18)
        # el tope cuenta filas de remediación de la fusión entera y no escribe nada si se pasa
        with mock.patch.object(remediacion, "LIMITE_ACCION_GRUPO", 11):
            with self.assertRaises(ValueError) as ctx:
                remediacion.comprobar_grupo(self.conn, next(iter(self.ids_nucleo.values())),
                                            solicitante="sistemas")
            with self.assertRaises(ValueError):
                remediacion.anotar_grupo(self.conn, next(iter(self.ids_nucleo.values())),
                                         autor="sistemas", texto="x")
        self.assertIn("Núcleo Linux 6.8.0-60-generic", str(ctx.exception))
        self.assertIn("12 filas de remediación", str(ctx.exception))
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM remediacion_comprobaciones").fetchone()[0], 0)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM remediacion_notas").fetchone()[0], 18, "solo las de sssd")
        # con el tope justo, pasa
        with mock.patch.object(remediacion, "LIMITE_ACCION_GRUPO", 12):
            self.assertEqual(remediacion.comprobar_grupo(
                self.conn, next(iter(self.ids_nucleo.values())), solicitante="sistemas")["total"], 12)

    # ---------------------------------------------------------------- (6) indicadores
    def test_los_indicadores_cuentan_fusiones_y_pares_activo_cve(self):
        r = remediacion.resumen(self.conn)
        self.assertEqual(r["actualizaciones"], 3, "núcleo, linux-tools-common y sssd")
        self.assertEqual(r["actualizaciones_con_version"], 3)
        self.assertEqual(r["actualizaciones_sin_version"], 0)
        self.assertEqual(r["vulnerabilidades_unicas"], 4, "tres CVE del núcleo y el de sssd")
        self.assertEqual(r["abiertas"], 32, "filas de remediación")
        self.assertEqual(r["cve_distintos"], 4)
        # el mismo recuento con el alcance por tipo de máquina
        self.assertEqual(remediacion.resumen(self.conn, origen="servidores")["actualizaciones"], 3)
        self.assertEqual(remediacion.resumen(self.conn, origen="equipos")["actualizaciones"], 0)
        # y la página del total coincide con contar_actualizaciones
        pagina = remediacion.pagina_actualizaciones(self.conn, limite=2)
        self.assertEqual(pagina["total"], 3)
        self.assertEqual(len(pagina["grupos"]), 2)
        self.assertEqual(remediacion.pagina_actualizaciones(self.conn, limite=2, desplazamiento=2)["total"], 3)
        self.assertIsNone(remediacion.pagina_actualizaciones(self.conn, limite=2, desplazamiento=40)["total"],
                          "fuera de rango no hay ventana: la vista pide el recuento aparte")
        self.assertEqual(remediacion.pagina_actualizaciones(self.conn, q="nada-de-nada")["total"], 0)

    def test_la_paginacion_no_parte_ni_repite_fusiones(self):
        primera = remediacion.listar_actualizaciones(self.conn, limite=2, desplazamiento=0)
        segunda = remediacion.listar_actualizaciones(self.conn, limite=2, desplazamiento=2)
        claves = [g["clave"] for g in primera + segunda]
        self.assertEqual(len(claves), 3)
        self.assertEqual(len(set(claves)), 3)

    def test_una_fusion_corregida_se_agrupa_igual_en_la_vista_de_todas(self):
        """Con «estado=todas» o «corregida» la firma sale de las filas pendientes si quedan
        y, si no, de todas: la actualización cerrada sigue siendo una sola fila."""
        for paquete in PAQUETES_SSSD:
            _actualizar_software(self.conn, self.srv, paquete, "2.6.3-1ubuntu3.9")
        remediacion.comprobar_grupo(self.conn, self.ids_sssd[0], solicitante="sistemas")
        self.assertEqual(remediacion.contar_actualizaciones(self.conn, estado="abierta"), 2)
        corregidas = remediacion.listar_actualizaciones(self.conn, estado="corregida")
        self.assertEqual([g["nombre"] for g in corregidas], ["sssd y 17 paquetes más"])
        self.assertEqual(corregidas[0]["estado"], "corregida")
        self.assertEqual(corregidas[0]["corregidas"], 1)
        self.assertEqual(corregidas[0]["version_final"], "2.6.3-1ubuntu3.9")
        self.assertEqual(remediacion.contar_actualizaciones(self.conn, estado=None), 3)
        self.assertEqual(len(remediacion.listar_actualizaciones(self.conn, estado=None)), 3)

    def test_la_firma_no_depende_del_orden_de_insercion(self):
        """Dos activos con las mismas filas insertadas en órdenes distintos dan la misma
        fusión (la firma se ordena en SQL; sin ese orden, 3.338 de 19.283 grupos de
        producción salían distintos)."""
        otro = _activo(self.conn, "srv-414", ip="10.0.0.14")
        pares = [(p, cve) for p in PAQUETES_NUCLEO for cve in CVES_NUCLEO]
        import random
        random.Random(7).shuffle(pares)
        for paquete, cve in pares:
            _remediacion(self.conn, otro, self.amenazas[cve], cve, paquete, "6.8.0-60.63", "6.8.0-60.63.1")
        grupos = remediacion.listar_actualizaciones(self.conn, activo_id=otro)
        self.assertEqual([g["nombre"] for g in grupos], ["Núcleo Linux 6.8.0-60-generic"])
        self.assertEqual(grupos[0]["n_paquetes"], 4)

    def test_el_plan_de_remediacion_junta_los_grupos_con_la_misma_orden(self):
        """Adaptada el 2026-09-09: la fusión se hace DENTRO de
        ``aplicabilidad.plan_remediacion``, no en la plantilla, para que la reciban todos
        los que llaman (la página y la descarga en texto, que traía 105 bloques donde la
        página decía 40 grupos). Aquí se comprueba que el plan ya sale fusionado y que
        volver a fusionarlo no cambia nada (la plantilla lo repite tras recortar el plan
        al alcance del perfil)."""
        from threatintel import aplicabilidad
        plan = aplicabilidad.plan_remediacion(self.conn, activo_id=self.srv)
        nucleo = next(g for g in plan["grupos"] if g["nombre"] == "Núcleo Linux 6.8.0-60-generic")
        self.assertEqual(sorted(nucleo["cves"]), sorted(CVES_NUCLEO))
        self.assertEqual(nucleo["grupos_fusionados"], 3,
                         "el núcleo salía una vez por CVE antes de fusionar")
        self.assertTrue(nucleo["es_fusion"])
        otra = remediacion.fusionar_plan(plan["grupos"])
        self.assertEqual(len(otra), len(plan["grupos"]), "fusionar dos veces no cambia nada")
        self.assertEqual([g["nombre"] for g in otra], [g["nombre"] for g in plan["grupos"]])
        self.assertEqual(next(g for g in otra if g["es_fusion"])["grupos_fusionados"], 3,
                         "y no pierde de cuántos avisos sale la orden")
        self.assertEqual(remediacion.fusionar_plan([]), [])


class TestFusionEnLasPaginas(unittest.TestCase):
    """(7) La página de Remediación y la ficha del activo muestran la misma fusión."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / "fusion_web.db")
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "sistemas@ejemplo.local", CLAVE, rol="admin",
                               nombre="Persona de Sistemas", actor="t")
            auth.crear_usuario(conn, "lectora@ejemplo.local", CLAVE, rol="ciberseguridad",
                               nombre="Lectora Sin Permisos", actor="t")
            cls.srv = _activo(conn, "srv-413", ip="10.0.0.13")
            amenazas = {cve: _amenaza(conn, cve, titulo=f"Fallo del núcleo {cve}") for cve in CVES_NUCLEO}
            cls.ids = {}
            for paquete in PAQUETES_NUCLEO:
                _software(conn, cls.srv, paquete, "6.8.0-60.63")
                for cve in CVES_NUCLEO:
                    cls.ids[(paquete, cve)] = _remediacion(
                        conn, cls.srv, amenazas[cve], cve, paquete, "6.8.0-60.63",
                        "6.8.0-60.63.1", aviso=f"USN-{cve[-4:]}")
            _software(conn, cls.srv, "linux-tools-common", "6.8.0-101.101")
            _remediacion(conn, cls.srv, amenazas[CVES_NUCLEO[0]], CVES_NUCLEO[0],
                         "linux-tools-common", "6.8.0-101.101", "6.8.0-139.139")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _cliente(self, usuario="sistemas@ejemplo.local"):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": usuario, "password": CLAVE})
        return cli

    def _html(self, cli, url):
        r = cli.get(url)
        self.assertEqual(r.status_code, 200, url)
        html = r.get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html), f"style= en {url}")
        self.assertIsNone(RE_ON.search(html), f"on*= en {url}")
        self.assertNotIn("<script>", html.split("</head>")[-1])
        return html

    def test_la_pagina_de_remediacion_muestra_una_fila_con_sus_paquetes(self):
        html = self._html(self._cliente(), "/remediaciones/")
        zona = html.split('id="tabla-remediaciones"')[1]
        self.assertEqual(zona.count('id="rem-'), 2, "el núcleo fusionado y linux-tools-common")
        self.assertIn("Núcleo Linux 6.8.0-60-generic", zona)
        self.assertIn("4 paquetes del mismo origen", zona)
        for paquete in PAQUETES_NUCLEO:
            self.assertIn(paquete, zona, "la lista de paquetes es la trazabilidad")
        self.assertIn('<details class="paquetes-fusion">', zona)
        self.assertIn("12 filas de remediación en 4 paquetes", zona)
        self.assertIn("en 4 paquetes", zona)
        self.assertIn("Ya se actualizó: comprobar las 3", zona)
        self.assertIn("en sus 4 paquetes (12 filas de remediación)", zona)
        # el hermano que no cumple la regla, con su enlace acotado al activo
        self.assertIn("linux-tools-common", zona)
        self.assertRegex(zona, rf'href="/remediaciones/\?[^"]*activo={self.srv}[^"]*q=linux-tools-common')
        # los indicadores: 2 actualizaciones, 3 vulnerabilidades (pares activo-CVE), 13 filas
        cabecera = html.split('id="tabla-remediaciones"')[0]
        self.assertIn('<div class="valor">2</div>', cabecera)
        self.assertIn("Actualizaciones pendientes", cabecera)
        self.assertIn("una por activo y origen de paquete", cabecera)
        self.assertIn('<div class="valor">3</div>', cabecera)
        self.assertIn("Vulnerabilidades pendientes", cabecera)
        self.assertIn("13 filas de remediación", html)
        # la vista por vulnerabilidad dice que son filas de trazabilidad
        porcve = self._html(self._cliente(), "/remediaciones/?vista=vulnerabilidad")
        self.assertIn("filas de trazabilidad, no vulnerabilidades distintas", porcve)
        self.assertEqual(porcve.split('id="tabla-remediaciones"')[1].count('id="rem-'), 13)
        # una lectora no ve acciones sobre la fusión
        lectora = self._html(self._cliente("lectora@ejemplo.local"), "/remediaciones/")
        self.assertNotIn('name="alcance"', lectora.split('id="tabla-remediaciones"')[1])

    def test_comprobar_desde_la_pagina_toca_las_doce_filas(self):
        cli = self._cliente()
        html = self._html(cli, "/remediaciones/")
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        rid = self.ids[(PAQUETES_NUCLEO[0], CVES_NUCLEO[0])]
        r = cli.post(f"/remediaciones/{rid}/comprobar",
                     data={"csrf": csrf, "alcance": "grupo", "volver": "/remediaciones/"},
                     follow_redirects=True)
        texto = r.get_data(as_text=True)
        self.assertIn("Núcleo Linux 6.8.0-60-generic", texto)
        self.assertIn("se comprobaron las 3 vulnerabilidades que cubre en sus 4 paquetes "
                      "(12 filas de remediación)", texto)
        with db.session(self.ruta) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM remediaciones WHERE comprobacion_veredicto='sigue_vulnerable'"
            ).fetchone()[0], 12)
            self.assertEqual(conn.execute(
                "SELECT comprobacion_veredicto FROM remediaciones WHERE paquete='linux-tools-common'"
            ).fetchone()[0], None)

    def test_la_ficha_del_activo_muestra_la_misma_fusion(self):
        from flask import url_for
        with self.app.test_request_context():
            url = url_for("activos.detalle", activo_id=self.srv)
        html = self._html(self._cliente(), url)
        self.assertIn('id="actualizaciones-activo"', html)
        zona = html.split('id="actualizaciones-activo"')[1].split('id="remediaciones-activo"')[0]
        # Adaptado el 2026-09-09: la cabecera nombra la unidad con las palabras del
        # usuario («una por cosa que hay que actualizar») y dice las tres magnitudes.
        self.assertIn("2 actualizaciones pendientes en este activo, una por cosa que hay "
                      "que actualizar (activo y origen de paquete)", zona)
        self.assertIn("Núcleo Linux 6.8.0-60-generic", zona)
        self.assertIn("4 paquetes del mismo origen", zona)
        self.assertEqual(zona.count('id="act-'), 2)
        self.assertIn('name="alcance" value="grupo"', zona)
        self.assertIn("linux-tools-common", zona)
        # y debajo sigue el detalle plano, que se presenta como trazabilidad
        detalle = html.split('id="remediaciones-activo"')[1]
        self.assertIn("Detalle por vulnerabilidad y paquete", detalle)
        # Adaptado el 2026-09-09: el panel se presenta como TRAZABILIDAD y remite al
        # recuento de actualizaciones de arriba, para que no se lea como la lista de
        # trabajo (que es la de actualizaciones).
        self.assertIn("Es la TRAZABILIDAD, no la lista de trabajo", detalle)
        self.assertIn('id="rem-', detalle)
        # el recorrido guiado numera los dos paneles sin repetir y en el orden visual
        # (7 las actualizaciones y 8 el detalle, tras retirar la tabla de veredictos).
        pasos = [int(n) for n in re.findall(r'data-tour="(\d+)"', html)]
        self.assertEqual(len(pasos), len(set(pasos)), "números de paso repetidos")
        self.assertEqual(pasos, sorted(pasos), "el recorrido salta hacia atrás")
        self.assertIn(7, pasos)
        self.assertIn(8, pasos)

    def test_el_plan_de_remediacion_del_activo_muestra_un_grupo_del_nucleo(self):
        from flask import url_for
        with self.app.test_request_context():
            url = url_for("activos.remediacion", activo_id=self.srv)
        html = self._html(self._cliente(), url)
        self.assertEqual(html.count("Núcleo Linux 6.8.0-60-generic"), 1,
                         "un solo grupo para los tres CVE del núcleo")
        self.assertIn("4 paquetes del mismo origen: una sola orden los actualiza", html)
        self.assertIn("3 vulnerabilidades", html)
        # linux-tools-common no tiene fila de aplicabilidad en esta base (el plan sale de
        # esa tabla), así que el plan tiene UN grupo: los tres CVE del núcleo, antes tres.
        self.assertIn('<div class="valor">1</div>', html)
        self.assertNotIn("2. debian", html, "no hay un segundo grupo del núcleo")


if __name__ == "__main__":
    unittest.main()
