"""Precisión de la versión instalada frente a la corregida, y desglose por sistema
operativo (2026-09-06).

El usuario pidió tres cosas después de leer la tabla de activos afectados del correo:

1. Que se entienda la comparación. «No se entiende "1.11.1-1build2 →
   1.11.1-1ubuntu0.26.04.2 USN-8486-1"»: la comparación era correcta (el orden de dpkg
   lo confirma), pero el 65 % de las filas comparten la versión de origen y solo cambia
   la revisión del paquete, que es donde las distribuciones aplican el parche.
2. Que se verifique si a todos los sistemas operativos les aplica la misma versión y la
   misma vulnerabilidad. No es así: CVE-2026-15534 se corrige en Ubuntu 22.04 con
   5.34.0-3ubuntu1.8, en Ubuntu 26.04 con 5.40.1-7ubuntu0.1 y en Debian 12 y 13 todavía
   no se corrige.
3. Que todo se sustente con fuentes reales del fabricante, para que el proceso resolutor
   pueda comprobarlo.

La revisión adversaria del 2026-09-06 rechazó la primera versión por tres fallos graves y
cinco menores; estas pruebas cubren los ocho:

1. La fuente oficial se reconocía por SUBCADENA, así que
   «https://malicioso.example/ubuntu.com/aviso» se presentaba como nota de seguridad de
   Ubuntu: ahora se valida el SERVIDOR (``TestFuenteOficialPorServidor``).
2. La explicación de la comparación describía el paquete de la PRIMERA fila del activo:
   ahora va por paquete (``TestPlanPorPaqueteDelActivo``).
3. El resumen por sistema mezclaba paquetes distintos en un «actualizar de X a Y»: ahora el
   plan vive en ``paquetes_detalle`` (``TestPlanPorPaqueteDelSistema``).
4. El motor «version» se sustentaba con la página de la distribución: ahora con la ficha
   del NIST (``TestMotorVersionSeSustentaEnElNist``).
5. El repaso necesitaba que le pasaran el índice de VuXML: ahora lo carga él
   (``TestRepasoCargaVuXML``).
6. Frases que inventaban un cero de nivel de parche o una época
   (``TestSinInventarDatos``).
7. Presentación: identificador de aviso recortado y recorrido guiado en orden
   (``TestPresentacion``).
8. El correo anuncia los ficheros adjuntos y para qué sirve cada libro
   (``TestAdjuntosEnElCorreo``).

Sin red: OSV.dev se simula con un cliente doble o con la caché ``osv_cache``, y cualquier
intento de salir a la red hace fallar la prueba. Base temporal bajo ``data/``.
"""
from __future__ import annotations

import json
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any, Optional

from threatintel import aplicabilidad as ap
from threatintel import db, notify, versiones_distro as vd
from threatintel.paths import BASE_DIR

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)
RE_SCRIPT = re.compile(r"<script(?![^>]*\ssrc=)", re.I)

#: Abreviaturas que no pueden aparecer en nada que lea una persona.
ABREVIATURAS = (">Config<", ">Vuln.<", ">Rel.<", ">Ver.<", ">Vers.<", "N/A", ">SO<", "Corr.")


class Cfg(dict):
    def get(self, clave, defecto=None):
        return super().get(clave, defecto)


def _sin_red(*args, **kwargs):
    raise AssertionError("la prueba ha intentado salir a la red")


# ==========================================================================
# 1. La explicación de la comparación
# ==========================================================================
class TestExplicacionComparacion(unittest.TestCase):
    """``versiones_distro.explicar_comparacion`` en los cuatro casos y con datos raros."""

    def test_ubuntu_misma_version_de_origen(self):
        r = vd.explicar_comparacion("ubuntu", "1.11.1-1build2", "1.11.1-1ubuntu0.26.04.2")
        self.assertTrue(r["misma_origen"])
        self.assertFalse(r["identicas"])
        self.assertEqual(r["origen"], "1.11.1")
        self.assertEqual(r["revision_instalada"], "1build2")
        self.assertEqual(r["revision_corregida"], "1ubuntu0.26.04.2")
        self.assertEqual(r["orden"], -1)             # la instalada es anterior
        self.assertEqual(r["texto"], "Misma versión de origen (1.11.1): la corrección va en la "
                                     "revisión del paquete de Ubuntu, de 1build2 a 1ubuntu0.26.04.2")
        self.assertEqual(r["verificacion"],
                         'dpkg --compare-versions "1.11.1-1build2" lt "1.11.1-1ubuntu0.26.04.2"')

    def test_debian_misma_version_de_origen(self):
        r = vd.explicar_comparacion("debian", "1.10.0-3+b1", "1.10.0-3+deb12u1")
        self.assertTrue(r["misma_origen"])
        self.assertEqual(r["origen"], "1.10.0")
        self.assertIn("paquete de Debian", r["texto"])
        self.assertIn("de 3+b1 a 3+deb12u1", r["texto"])
        self.assertEqual(r["orden"], -1)

    def test_version_de_origen_distinta(self):
        r = vd.explicar_comparacion("debian", "1.10.0-3", "1.11.1-1")
        self.assertFalse(r["misma_origen"])
        self.assertEqual(r["texto"], "De la versión 1.10.0 a la 1.11.1")

    def test_freebsd_nivel_de_parche(self):
        r = vd.explicar_comparacion("freebsd", "1.2.3_1", "1.2.3_4")
        self.assertTrue(r["misma_origen"])
        self.assertEqual((r["origen"], r["revision_instalada"], r["revision_corregida"]),
                         ("1.2.3", "1", "4"))
        self.assertIn("nivel de parche de FreeBSD, del 1 al 4", r["texto"])
        self.assertEqual(r["verificacion"], 'pkg version -t "1.2.3_1" "1.2.3_4"')

    def test_freebsd_sistema_base_sin_nivel_de_parche(self):
        r = vd.explicar_comparacion("freebsd", "14.4", "14.4_9")
        self.assertTrue(r["misma_origen"])
        self.assertIn("sin nivel de parche", r["texto"])

    def test_windows_compilacion(self):
        r = vd.explicar_comparacion("windows", "10.0.26100.4351", "10.0.26100.4770")
        self.assertTrue(r["misma_origen"])
        self.assertEqual(r["origen"], "10.0.26100")
        self.assertIn("actualización acumulativa, del número 4351 al 4770", r["texto"])

    def test_windows_cambia_la_version_del_sistema(self):
        r = vd.explicar_comparacion("windows", "10.0.22631.4890", "10.0.26100.4770")
        self.assertFalse(r["misma_origen"])
        self.assertIn("cambia la versión de Windows", r["texto"])

    def test_epoca_del_paquete(self):
        r = vd.explicar_comparacion("ubuntu", "1:9.6p1-3", "2:9.6p1-1")
        self.assertFalse(r["misma_origen"])
        self.assertIn("época del paquete", r["texto"])

    def test_software_sin_familia(self):
        r = vd.explicar_comparacion(None, "151.0", "152.0.7632")
        self.assertFalse(r["misma_origen"])
        self.assertEqual(r["texto"], "De la versión 151.0 a la 152.0.7632")

    def test_datos_ausentes_no_inventan_nada(self):
        sin_instalada = vd.explicar_comparacion("ubuntu", None, "1.2-3")
        self.assertIn("No se conoce la versión instalada", sin_instalada["texto"])
        self.assertIsNone(sin_instalada["orden"])
        sin_corregida = vd.explicar_comparacion("ubuntu", "1.2-3", "")
        self.assertIn("Todavía no hay versión que corrija", sin_corregida["texto"])
        vacio = vd.explicar_comparacion("ubuntu", None, None)
        self.assertIn("No se conocen ni la versión instalada", vacio["texto"])
        for r in (sin_instalada, sin_corregida, vacio):
            self.assertFalse(r["misma_origen"])

    def test_versiones_identicas(self):
        r = vd.explicar_comparacion("ubuntu", "1.2-3", "1.2-3")
        self.assertTrue(r["identicas"])
        self.assertEqual(r["orden"], 0)
        self.assertIn("la misma cadena", r["texto"])

    def test_version_rara_no_rompe(self):
        r = vd.explicar_comparacion("ubuntu", "sin dato", "?")
        self.assertIsInstance(r["texto"], str)
        self.assertTrue(r["texto"])
        rw = vd.explicar_comparacion("windows", "no es una compilación", "10.0.26100.1")
        self.assertFalse(rw["misma_origen"])
        self.assertIn("De la versión", rw["texto"])

    def test_todas_las_claves_siempre(self):
        claves = {"familia", "distribucion", "instalada", "corregida", "misma_origen", "identicas",
                  "origen", "revision_instalada", "revision_corregida", "orden", "texto",
                  "verificacion"}
        for args in (("ubuntu", "1-1", "1-2"), ("freebsd", None, None), (None, "1", "2"),
                     ("windows", "10.0.1.1", "10.0.1.2")):
            self.assertEqual(set(vd.explicar_comparacion(*args)), claves)

    def test_familia_de_la_comparacion_la_decide_el_motor(self):
        # Chrome instalado en Ubuntu: el motor «version» compara la versión del PROGRAMA,
        # así que explicarlo como «revisión del paquete de Ubuntu» sería falso.
        self.assertIsNone(ap.familia_comparacion("version", "Ubuntu:22.04", "ubuntu"))
        self.assertEqual(ap.familia_comparacion("osv", "Ubuntu:22.04", "ubuntu"), "ubuntu")
        self.assertEqual(ap.familia_comparacion("vuxml", None, "freebsd"), "freebsd")
        self.assertEqual(ap.familia_comparacion("msrc", None, "windows"), "windows")

    def test_explicar_fila_acepta_filas_incompletas(self):
        r = ap.explicar_fila({"motor": "osv", "ecosistema": "Debian:13",
                              "version_instalada": "1.11.1-1", "version_corregida": "1.11.1-1+deb13u1"})
        self.assertTrue(r["misma_origen"])
        self.assertIsInstance(ap.explicar_fila({})["texto"], str)


# ==========================================================================
# 2. Las direcciones oficiales
# ==========================================================================
class TestDireccionesOficiales(unittest.TestCase):
    def test_cada_tipo_de_aviso_tiene_su_direccion(self):
        self.assertEqual(ap.url_aviso("USN-8486-1"),
                         "https://ubuntu.com/security/notices/USN-8486-1")
        self.assertEqual(ap.url_aviso("DSA-5678-1"),
                         "https://security-tracker.debian.org/tracker/DSA-5678-1")
        self.assertEqual(ap.url_aviso("DLA-4773-1"),
                         "https://security-tracker.debian.org/tracker/DLA-4773-1")
        self.assertEqual(ap.url_aviso("ELA-1234-1"),
                         "https://deb.freexian.com/extended-lts/tracker/ELA-1234-1")
        self.assertEqual(ap.url_aviso("FreeBSD-SA-26:33.unbound"),
                         "https://www.freebsd.org/security/advisories/FreeBSD-SA-26:33.unbound.asc")
        self.assertEqual(ap.url_aviso("KB5058405"), "https://support.microsoft.com/help/5058405")

    def test_un_identificador_inventado_no_se_enlaza(self):
        for inventado in ("XYZ-1234-1", "USN", "USN-", "aviso interno", "", None,
                          "javascript:alert(1)", "KB12"):
            self.assertEqual(ap.url_aviso(inventado), "")

    def test_varios_avisos_en_una_celda(self):
        avisos = ap.avisos_con_url("USN-8486-1, USN-8487-1")
        self.assertEqual([a["id"] for a in avisos], ["USN-8486-1", "USN-8487-1"])
        self.assertTrue(all(a["url"].startswith("https://ubuntu.com/security/notices/") for a in avisos))
        self.assertEqual(ap.avisos_con_url(None), [])
        # lo que no se reconoce viaja sin enlace, no se descarta
        sueltos = ap.avisos_con_url("aviso-interno-7")
        self.assertEqual(sueltos[0]["url"], "")

    def test_direccion_canonica_por_familia(self):
        self.assertEqual(ap.referencia_canonica("CVE-2025-15661", ecosistema="Ubuntu:26.04"),
                         "https://ubuntu.com/security/CVE-2025-15661")
        self.assertEqual(ap.referencia_canonica("CVE-2025-15661", ecosistema="Debian:12"),
                         "https://security-tracker.debian.org/tracker/CVE-2025-15661")
        self.assertEqual(ap.referencia_canonica("CVE-2026-1234", familia="windows"),
                         "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1234")
        self.assertEqual(ap.referencia_canonica("CVE-2026-1234"),
                         "https://nvd.nist.gov/vuln/detail/CVE-2026-1234")
        self.assertEqual(ap.referencia_canonica("no es un CVE"), "")

    def test_referencia_del_registro_de_osv(self):
        registro = {"id": "UBUNTU-CVE-2025-15661", "references": [
            {"type": "REPORT", "url": "https://github.com/libssh2/libssh2/pull/1705"},
            {"type": "REPORT", "url": "https://ubuntu.com/security/CVE-2025-15661"},
            {"type": "ADVISORY", "url": "https://ubuntu.com/security/notices/USN-8486-1"}]}
        # gana la nota de seguridad, que es la que dice la versión exacta que corrige
        self.assertEqual(ap.referencia_osv(registro, ecosistema="Ubuntu:26.04"),
                         "https://ubuntu.com/security/notices/USN-8486-1")
        debian = {"id": "DEBIAN-CVE-2025-15661", "references": [
            {"type": "ADVISORY", "url": "https://security-tracker.debian.org/tracker/CVE-2025-15661"}]}
        self.assertEqual(ap.referencia_osv(debian, ecosistema="Debian:12"),
                         "https://security-tracker.debian.org/tracker/CVE-2025-15661")
        # sin ninguna reconocible se construye la canónica; nunca una de terceros
        solo_terceros = {"id": "UBUNTU-CVE-2026-15534",
                         "references": [{"url": "https://github.com/Perl/perl5/commit/54cf.patch"}]}
        self.assertEqual(ap.referencia_osv(solo_terceros, ecosistema="Ubuntu:22.04"),
                         "https://ubuntu.com/security/CVE-2026-15534")
        self.assertEqual(ap.referencia_osv(None, ecosistema="Ubuntu:22.04"), "")

    def test_la_etiqueta_del_enlace_dice_adonde_lleva(self):
        self.assertEqual(ap.etiqueta_referencia("https://ubuntu.com/security/notices/USN-1-1"),
                         "Nota de seguridad de Ubuntu")
        self.assertEqual(ap.etiqueta_referencia("https://security-tracker.debian.org/tracker/CVE-1"),
                         "Rastreador de seguridad de Debian")
        self.assertEqual(ap.etiqueta_referencia("https://nvd.nist.gov/vuln/detail/CVE-1"),
                         "Ficha del CVE en el NIST")
        self.assertEqual(ap.etiqueta_referencia(""), "")

    def test_la_referencia_viaja_en_la_evidencia_y_se_recupera(self):
        evidencia = "libssh2-1t64 1.11.1-1build2 es anterior a la corrección (Ubuntu 26.04)"
        url = "https://ubuntu.com/security/notices/USN-8486-1"
        completa = ap.con_referencia(evidencia, url)
        self.assertTrue(completa.endswith(f"[{ap.MARCA_REFERENCIA} {url}]"))
        self.assertEqual(ap.partir_evidencia(completa), (evidencia, url))
        # idempotente: no se duplica al volver a pasar
        self.assertEqual(ap.con_referencia(completa, url), completa)
        self.assertEqual(ap.partir_evidencia(evidencia), (evidencia, None))
        self.assertEqual(ap.partir_evidencia(None), ("", None))

    def test_el_motivo_de_que_no_haya_correccion_se_escribe_con_palabras(self):
        self.assertEqual(ap.texto_sin_correccion("sin_parche_publicado"),
                         "sin corrección publicada todavía: el fabricante todavía no ha publicado "
                         "la corrección")
        self.assertEqual(ap.texto_sin_correccion(None), "sin corrección publicada todavía")
        for clave, texto in ap.MOTIVO_SIN_PARCHE_ES.items():
            self.assertRegex(texto, r"[áéíóúñ]", f"«{clave}» sin tildes")


# ==========================================================================
# Base común con tres sistemas operativos
# ==========================================================================
class BaseTresSistemas(unittest.TestCase):
    """Un CVE de perl con corrección en dos sistemas y sin corrección en un tercero.

    Es el caso real de CVE-2026-15534 medido sobre la base de producción el 2026-09-06.
    """

    CVE = "CVE-2026-15534"

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.ruta = str(Path(self.dir.name) / "precision.db")
        db.init_db(self.ruta)
        self.conn = db.connect(self.ruta)
        columnas = {r[1] for r in self.conn.execute("PRAGMA table_info(aplicabilidad)")}
        self.assertIn("referencia", columnas,
                      "el esquema v8 tiene que traer aplicabilidad.referencia")
        if "sin_parche_motivo" not in columnas:
            self.conn.execute("ALTER TABLE aplicabilidad ADD COLUMN sin_parche_motivo TEXT")
        self.ahora = db.utcnow()
        self.cfg = Cfg({"applicability_max_osv_per_run": 5, "alert_min_match_confidence": 0.6})
        self._sembrar()

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    def _activo(self, nombre: str, *, ecosistema: Optional[str], familia: str, ciclo: str,
                so_nombre: str, entorno: str, origen: str = "servidores") -> int:
        cur = self.conn.execute(
            """INSERT INTO activos(origen, ocs_id, nombre, so_nombre, so_version, so_familia,
                   so_ciclo, ecosistema, entorno, zona, ip, presente, primera_vez_at, visto_at)
               VALUES(?, (SELECT COALESCE(MAX(ocs_id),0)+1 FROM activos), ?, ?, ?, ?, ?, ?, ?,
                      'interna', '10.0.0.1', 1, ?, ?)""",
            (origen, nombre, so_nombre, ciclo, familia, ciclo, ecosistema, entorno,
             self.ahora, self.ahora))
        return int(cur.lastrowid)

    def _software(self, activo_id: int, nombre: str, version: str) -> None:
        self.conn.execute(
            "INSERT INTO activo_software(activo_id, nombre, nombre_norm, version) VALUES(?,?,?,?)",
            (activo_id, nombre, nombre.lower(), version))

    def _veredicto(self, activo_id: int, paquete: str, *, instalada: str,
                   corregida: Optional[str] = None, motivo: Optional[str] = None,
                   aviso: Optional[str] = None, referencia: Optional[str] = None,
                   motor: str = "osv", veredicto: str = "afectado", cve: Optional[str] = None,
                   formato_antiguo: bool = False) -> None:
        """Un veredicto ya guardado. Con ``formato_antiguo`` la referencia va pegada a la
        evidencia como en las filas anteriores al esquema v8, para comprobar que se siguen
        leyendo; en el formato normal va en la columna ``referencia``."""
        evidencia = (f"{paquete} {instalada} es anterior a la corrección {corregida}"
                     if corregida else f"{paquete} {instalada}: todavía no hay corrección publicada")
        self.conn.execute(
            """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada,
                   version_corregida, veredicto, motor, evidencia, aviso, evaluado_at,
                   sin_parche_motivo, referencia)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (activo_id, self.threat_id, cve or self.CVE, paquete, instalada, corregida, veredicto,
             motor,
             ap.con_referencia(evidencia, referencia) if formato_antiguo else evidencia,
             aviso, self.ahora, motivo,
             None if formato_antiguo else referencia))

    def _sembrar(self):
        cur = self.conn.execute(
            """INSERT INTO threats(fingerprint, cve, title_en, title_es, summary_en, severity,
                   severity_source, first_seen_at, last_seen_at, month, relevance, estado)
               VALUES('fp-perl', ?, 'Perl flaw', 'Fallo en Perl', 'Heap overflow in Perl', 'High',
                      'nvd', ?, ?, ?, 70.0, 'nueva')""",
            (self.CVE, self.ahora, self.ahora, self.ahora[:7]))
        self.threat_id = int(cur.lastrowid)
        self.u22 = self._activo("srv-ubu-22", ecosistema="Ubuntu:22.04", familia="ubuntu",
                                ciclo="22.04", so_nombre="Ubuntu 22.04", entorno="produccion")
        self.u22b = self._activo("pc-ubu-22", ecosistema="Ubuntu:22.04", familia="ubuntu",
                                 ciclo="22.04", so_nombre="Ubuntu 22.04", entorno="pruebas",
                                 origen="equipos")
        self.u26 = self._activo("srv-ubu-26", ecosistema="Ubuntu:26.04", familia="ubuntu",
                                ciclo="26.04", so_nombre="Ubuntu 26.04", entorno="contingencia")
        self.d13 = self._activo("srv-deb-13", ecosistema="Debian:13", familia="debian",
                                ciclo="13", so_nombre="Debian 13", entorno="produccion")
        for activo, version in ((self.u22, "5.34.0-3ubuntu1.5"), (self.u22b, "5.34.0-3ubuntu1.3")):
            for paquete in ("perl", "perl-base", "libperl5.34"):
                self._software(activo, paquete, version)
        for paquete in ("perl", "perl-base", "libperl5.40"):
            self._software(self.u26, paquete, "5.40.1-7build1")
        for paquete in ("perl", "perl-base"):
            self._software(self.d13, paquete, "5.40.1-6")
        self.conn.commit()

    def _registro_ubuntu(self) -> dict:
        def binarios(nombres, version):
            return {"binaries": [{"binary_name": n, "binary_version": version} for n in nombres]}
        return {"id": f"UBUNTU-{self.CVE}", "affected": [
            {"package": {"name": "perl", "ecosystem": "Ubuntu:22.04:LTS"},
             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "5.34.0-3ubuntu1.8"}]}],
             "ecosystem_specific": binarios(("perl", "perl-base", "libperl5.34"), "5.34.0-3ubuntu1.8")},
            {"package": {"name": "perl", "ecosystem": "Ubuntu:26.04:LTS"},
             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "5.40.1-7ubuntu0.1"}]}],
             "ecosystem_specific": binarios(("perl", "perl-base", "libperl5.40"), "5.40.1-7ubuntu0.1")}],
            "references": [{"type": "REPORT", "url": "https://www.cve.org/CVERecord?id=" + self.CVE},
                           {"type": "REPORT", "url": f"https://ubuntu.com/security/{self.CVE}"}],
            "related": ["USN-9001-1"]}

    def _registro_debian(self) -> dict:
        return {"id": f"DEBIAN-{self.CVE}", "affected": [
            {"package": {"name": "perl", "ecosystem": "Debian:13"},
             "ranges": [{"events": [{"introduced": "0"}]}],
             "ecosystem_specific": {"urgency": "not yet assigned"}}],
            "references": [{"type": "ADVISORY",
                            "url": f"https://security-tracker.debian.org/tracker/{self.CVE}"}]}

    def _cachear(self):
        for id_osv, registro in ((f"UBUNTU-{self.CVE}", self._registro_ubuntu()),
                                 (f"DEBIAN-{self.CVE}", self._registro_debian())):
            self.conn.execute(
                "INSERT OR REPLACE INTO osv_cache(id, encontrado, json, consultado_at) VALUES(?,1,?,?)",
                (id_osv, json.dumps(registro, ensure_ascii=False), self.ahora))
        self.conn.commit()

    def _sembrar_veredictos(self, *, con_referencia: bool = True,
                            formato_antiguo: bool = False):
        """Los veredictos ya evaluados, como los guardó la ejecución diaria."""
        usn = "https://ubuntu.com/security/notices/USN-9001-1" if con_referencia else None
        deb = f"https://security-tracker.debian.org/tracker/{self.CVE}" if con_referencia else None
        for paquete in ("perl", "perl-base", "libperl5.34"):
            self._veredicto(self.u22, paquete, instalada="5.34.0-3ubuntu1.5",
                            corregida="5.34.0-3ubuntu1.8", aviso="USN-9001-1", referencia=usn,
                            formato_antiguo=formato_antiguo)
            self._veredicto(self.u22b, paquete, instalada="5.34.0-3ubuntu1.3",
                            corregida="5.34.0-3ubuntu1.8", aviso="USN-9001-1", referencia=usn,
                            formato_antiguo=formato_antiguo)
        for paquete in ("perl", "perl-base", "libperl5.40"):
            self._veredicto(self.u26, paquete, instalada="5.40.1-7build1",
                            corregida="5.40.1-7ubuntu0.1", aviso="USN-9001-1", referencia=usn,
                            formato_antiguo=formato_antiguo)
        for paquete in ("perl", "perl-base"):
            self._veredicto(self.d13, paquete, instalada="5.40.1-6",
                            motivo="aviso_sin_version", referencia=deb,
                            formato_antiguo=formato_antiguo)
        self.conn.execute(
            """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados, no_afectados,
                   sin_dato, afectados_expuestos, parche_disponible, detalle)
               VALUES(?,?,4,0,0,3,1,?)""",
            (self.threat_id, self.ahora,
             json.dumps({"lineas": ["Ubuntu 22.04: 6 instalaciones afectadas"], "errores": []})))
        # La cola de remediación se llena a partir de la evaluación en la misma ejecución
        # diaria (threatintel.remediacion.sincronizar), y desde el 2026-09-09 es de ahí de
        # donde la ficha del activo saca la tabla de actualizaciones: se sincroniza aquí
        # para que la prueba mire lo mismo que produccion.
        from threatintel import remediacion as _rem
        _rem.sincronizar(self.conn)
        self.conn.commit()


# ==========================================================================
# 3. El desglose por sistema operativo
# ==========================================================================
class TestDesglosePorSistema(BaseTresSistemas):
    def test_un_grupo_por_sistema_con_su_propia_version(self):
        self._sembrar_veredictos()
        datos = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)
        sistemas = {s["nombre"]: s for s in datos["sistemas"]}
        self.assertEqual(set(sistemas), {"Ubuntu 22.04", "Ubuntu 26.04", "Debian 13"})
        # el de más activos primero
        self.assertEqual(datos["sistemas"][0]["nombre"], "Ubuntu 22.04")

        u22 = sistemas["Ubuntu 22.04"]
        self.assertEqual((u22["n_activos"], u22["n_expuestos"]), (2, 1))
        self.assertEqual(u22["paquetes"], ["libperl5.34", "perl", "perl-base"])
        self.assertTrue(u22["hay_correccion"])
        # Con tres paquetes NO hay una sola pareja de versiones que represente al sistema
        # (hallazgo 3): el plan vive en paquetes_detalle y las claves agregadas van vacías.
        self.assertFalse(u22["plan_unico"])
        self.assertEqual(u22["n_paquetes"], 3)
        self.assertIsNone(u22["version_instalada"])
        self.assertIsNone(u22["version_corregida"])
        self.assertIsNone(u22["comparacion"])
        self.assertEqual(u22["accion"],
                         "plan por paquete: libperl5.34, actualizar de 5.34.0-3ubuntu1.3 a "
                         "5.34.0-3ubuntu1.8; perl, actualizar de 5.34.0-3ubuntu1.3 a "
                         "5.34.0-3ubuntu1.8; perl-base, actualizar de 5.34.0-3ubuntu1.3 a "
                         "5.34.0-3ubuntu1.8")
        self.assertEqual(u22["referencia"], "https://ubuntu.com/security/notices/USN-9001-1")
        self.assertEqual(u22["referencia_es"], "Nota de seguridad de Ubuntu")
        self.assertEqual([a["id"] for a in u22["avisos"]], ["USN-9001-1"])
        self.assertEqual([d["paquete"] for d in u22["paquetes_detalle"]],
                         ["libperl5.34", "perl", "perl-base"])
        self.assertTrue(all(d["version_corregida"] == "5.34.0-3ubuntu1.8"
                            for d in u22["paquetes_detalle"]))
        # y cada paquete sí lleva su pareja, que existe tal cual en los datos
        for d in u22["paquetes_detalle"]:
            self.assertEqual(d["version_instalada"], "5.34.0-3ubuntu1.3")
            self.assertTrue(d["comparacion"]["misma_origen"])
            self.assertEqual(d["referencia"], "https://ubuntu.com/security/notices/USN-9001-1")

        u26 = sistemas["Ubuntu 26.04"]
        self.assertEqual(u26["versiones_corregidas"], ["5.40.1-7ubuntu0.1"])
        self.assertFalse(u26["plan_unico"])
        self.assertIsNone(u26["version_corregida"])
        self.assertTrue(all(d["version_corregida"] == "5.40.1-7ubuntu0.1"
                            for d in u26["paquetes_detalle"]))
        self.assertEqual((u26["n_activos"], u26["n_expuestos"]), (1, 1))

        d13 = sistemas["Debian 13"]
        self.assertFalse(d13["hay_correccion"])
        self.assertIsNone(d13["version_corregida"])
        self.assertEqual(d13["sin_parche_motivo"], "aviso_sin_version")
        self.assertEqual(d13["sin_parche_motivo_es"],
                         "el aviso de seguridad no indica en qué versión se corrige")
        self.assertIn("sin corrección publicada todavía", d13["accion"])
        self.assertEqual(d13["referencia"],
                         f"https://security-tracker.debian.org/tracker/{self.CVE}")

    def test_ningun_activo_recibe_la_version_de_otro_sistema(self):
        self._sembrar_veredictos()
        datos = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)
        esperado = {"Ubuntu 22.04": "5.34.0-3ubuntu1.8", "Ubuntu 26.04": "5.40.1-7ubuntu0.1",
                    "Debian 13": None}
        for activo in datos["afectados"]:
            for d in activo["paquetes_detalle"]:
                self.assertEqual(d["version_corregida"], esperado[activo["sistema"]],
                                 f"{activo['nombre']}: {d['paquete']} tiene la versión "
                                 f"corregida de otro sistema")
        for sistema in datos["sistemas"]:
            self.assertEqual(len(sistema["versiones_corregidas"]),
                             0 if sistema["nombre"] == "Debian 13" else 1)

    def test_cada_activo_trae_su_explicacion_y_su_fuente(self):
        self._sembrar_veredictos()
        datos = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)
        porNombre = {a["nombre"]: a for a in datos["afectados"]}
        u26 = porNombre["srv-ubu-26"]
        self.assertTrue(u26["comparacion"]["misma_origen"])
        self.assertEqual(u26["comparacion"]["texto"],
                         "Misma versión de origen (5.40.1): la corrección va en la revisión del "
                         "paquete de Ubuntu, de 7build1 a 7ubuntu0.1")
        self.assertEqual(u26["avisos"][0]["url"],
                         "https://ubuntu.com/security/notices/USN-9001-1")
        self.assertEqual(u26["sistema"], "Ubuntu 26.04")
        # la evidencia se lee sin la marca interna de la referencia
        self.assertNotIn(ap.MARCA_REFERENCIA, u26["evidencia"])
        self.assertTrue(u26["referencia"])
        deb = porNombre["srv-deb-13"]
        self.assertIsNone(deb["version_corregida"])
        self.assertIn("sin corrección publicada todavía", deb["sin_parche_texto"])

    def test_sin_evaluar_devuelve_el_desglose_vacio(self):
        datos = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)
        self.assertFalse(datos["evaluada"])
        self.assertEqual(datos["sistemas"], [])

    def test_sistemas_sin_ecosistema_se_agrupan_por_nombre_y_ciclo(self):
        bsd = self._activo("srv-bsd-01", ecosistema=None, familia="freebsd", ciclo="14.4",
                           so_nombre="FreeBSD 14.4", entorno="produccion")
        win = self._activo("pc-win-11", ecosistema=None, familia="windows", ciclo="11-25h2",
                           so_nombre="Windows 11 Pro", entorno="pruebas", origen="equipos")
        self._veredicto(bsd, "unbound", instalada="1.19.0_1", corregida="1.19.0_2", motor="vuxml",
                        aviso="FreeBSD-SA-26:33.unbound")
        self._veredicto(win, "windows 11", instalada="10.0.26100.4351",
                        corregida="10.0.26100.4770", motor="msrc", aviso="KB5058405")
        self._sembrar_veredictos()
        nombres = {s["nombre"]: s for s in
                   ap.activos_de_amenaza(self.conn, self.threat_id, limite=20)["sistemas"]}
        self.assertIn("FreeBSD 14.4", nombres)
        self.assertIn("Windows 11 Pro (25H2)", nombres)
        self.assertIn("nivel de parche de FreeBSD", nombres["FreeBSD 14.4"]["comparacion"]["texto"])
        self.assertEqual(nombres["FreeBSD 14.4"]["referencia"],
                         "https://www.freebsd.org/security/advisories/FreeBSD-SA-26:33.unbound.asc")
        self.assertIn("actualización acumulativa",
                      nombres["Windows 11 Pro (25H2)"]["comparacion"]["texto"])
        self.assertEqual(nombres["Windows 11 Pro (25H2)"]["referencia"],
                         "https://support.microsoft.com/help/5058405")

    def test_varias_versiones_que_corrigen_en_el_mismo_sistema(self):
        """Dos paquetes del mismo sistema con correcciones distintas: se dicen las dos."""
        self._veredicto(self.u22, "perl", instalada="5.34.0-3ubuntu1.5",
                        corregida="5.34.0-3ubuntu1.8")
        self._veredicto(self.u22, "libperl5.34", instalada="5.34.0-3ubuntu1.5",
                        corregida="5.34.0-3ubuntu1.9")
        self.conn.execute(
            """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados, no_afectados,
                   sin_dato, afectados_expuestos, parche_disponible, detalle)
               VALUES(?,?,1,0,0,1,1,'{}')""", (self.threat_id, self.ahora))
        self.conn.commit()
        sistema = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)["sistemas"][0]
        self.assertEqual(sistema["versiones_corregidas"],
                         ["5.34.0-3ubuntu1.8", "5.34.0-3ubuntu1.9"])
        # nunca se elige «la más moderna» como versión del sistema: sería de otro paquete
        self.assertIsNone(sistema["version_corregida"])
        self.assertIsNone(sistema["version_instalada"])
        self.assertFalse(sistema["plan_unico"])
        # con dos versiones distintas no se dice un único «de X a Y»: se dice por paquete
        self.assertEqual(sistema["accion"],
                         "plan por paquete: libperl5.34, actualizar de 5.34.0-3ubuntu1.5 a "
                         "5.34.0-3ubuntu1.9; perl, actualizar de 5.34.0-3ubuntu1.5 a "
                         "5.34.0-3ubuntu1.8")
        detalle = {d["paquete"]: d for d in sistema["paquetes_detalle"]}
        self.assertEqual(detalle["perl"]["version_corregida"], "5.34.0-3ubuntu1.8")
        self.assertEqual(detalle["libperl5.34"]["version_corregida"], "5.34.0-3ubuntu1.9")
        self.assertTrue(detalle["perl"]["comparacion"]["misma_origen"])

    def test_el_sistema_base_de_freebsd_no_se_mezcla_con_los_puertos(self):
        """Caso real (CVE-2026-75803): el mismo servidor tiene el sistema base 14.4_5 y el
        puerto openssl 3.0.16,1. Decir «de 14.4_5 a 3.0.22,1» sería falso."""
        bsd = self._activo("srv-bsd-01", ecosistema=None, familia="freebsd", ciclo="14.4",
                           so_nombre="FreeBSD 14.4", entorno="produccion")
        self._veredicto(bsd, "freebsd", instalada="14.4_5", corregida="14.4_9", motor="vuxml")
        self._veredicto(bsd, "openssl", instalada="3.0.16,1", corregida="3.0.22,1", motor="vuxml")
        self.conn.execute(
            """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados, no_afectados,
                   sin_dato, afectados_expuestos, parche_disponible, detalle)
               VALUES(?,?,1,0,0,1,1,'{}')""", (self.threat_id, self.ahora))
        self.conn.commit()
        sistema = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)["sistemas"][0]
        self.assertEqual(sistema["nombre"], "FreeBSD 14.4")
        self.assertFalse(sistema["plan_unico"])
        self.assertIsNone(sistema["version_instalada"])
        self.assertIsNone(sistema["version_corregida"])
        self.assertNotIn("de 14.4_5 a 3.0.22,1", sistema["accion"])
        self.assertNotIn("de 3.0.16,1 a 14.4_9", sistema["accion"])
        detalle = {d["paquete"]: d for d in sistema["paquetes_detalle"]}
        self.assertEqual(detalle["freebsd"]["version_corregida"], "14.4_9")
        self.assertEqual(detalle["openssl"]["version_corregida"], "3.0.22,1")
        self.assertIn("nivel de parche de FreeBSD", detalle["freebsd"]["comparacion"]["texto"])

    def test_veredictos_del_activo_traen_explicacion_y_enlace(self):
        self._sembrar_veredictos()
        filas = ap.veredictos_de_activo(self.conn, self.u26, limite=10)
        self.assertTrue(filas)
        fila = filas[0]
        self.assertTrue(fila["comparacion"]["misma_origen"])
        self.assertEqual(fila["avisos"][0]["url"],
                         "https://ubuntu.com/security/notices/USN-9001-1")
        self.assertNotIn(ap.MARCA_REFERENCIA, fila["evidencia"])
        self.assertEqual(fila["referencia"], "https://ubuntu.com/security/notices/USN-9001-1")
        self.assertEqual(fila["sistema"], "Ubuntu 26.04")


# ==========================================================================
# 4. La referencia se guarda al evaluar y el repaso la recupera sin red
# ==========================================================================
class ClienteOSVFalso:
    """Doble de ``ClienteOSV``: sirve registros de un diccionario y cuenta consultas."""

    def __init__(self, registros: dict[str, Any], *, max_peticiones: int = 10):
        self.registros = registros
        self.max = max_peticiones
        self.peticiones = 0
        self.consultados: list[str] = []
        self.aciertos_cache = 0

    @property
    def agotado(self) -> bool:
        return self.peticiones >= self.max

    def en_cache(self, id_osv: str) -> bool:
        return id_osv in self.registros

    def registro(self, id_osv: str):
        self.consultados.append(id_osv)
        self.peticiones += 1
        return self.registros.get(id_osv)


class TestReferenciaAlEvaluar(BaseTresSistemas):
    def test_al_evaluar_se_guarda_la_referencia_oficial(self):
        osv = ClienteOSVFalso({f"UBUNTU-{self.CVE}": self._registro_ubuntu(),
                               f"DEBIAN-{self.CVE}": self._registro_debian()})
        amenaza = dict(self.conn.execute("SELECT * FROM threats WHERE id=?", (self.threat_id,)).fetchone())
        resultado = ap.evaluar_amenaza(self.conn, amenaza, cfg=self.cfg, osv=osv)
        self.assertEqual(resultado["afectados"], 4)
        filas = {(r["paquete"], r["version_corregida"]): dict(r) for r in self.conn.execute(
            "SELECT * FROM aplicabilidad WHERE cve=? AND activo_id=?", (self.CVE, self.u22))}
        self.assertTrue(filas)
        for fila in filas.values():
            # v8: la dirección oficial va en su columna y la evidencia queda limpia
            self.assertEqual(fila["referencia"], f"https://ubuntu.com/security/{self.CVE}")
            self.assertNotIn(ap.MARCA_REFERENCIA, fila["evidencia"] or "")
            self.assertEqual(ap.referencia_de_fila(fila), fila["referencia"])
            self.assertEqual(fila["aviso"], "USN-9001-1")
        deb = dict(self.conn.execute(
            "SELECT * FROM aplicabilidad WHERE cve=? AND activo_id=? LIMIT 1",
            (self.CVE, self.d13)).fetchone())
        self.assertEqual(deb["referencia"],
                         f"https://security-tracker.debian.org/tracker/{self.CVE}")
        # cada sistema recibe su propia versión, nunca la de otro
        corregidas = {r["activo_id"]: r["version_corregida"] for r in self.conn.execute(
            "SELECT DISTINCT activo_id, version_corregida FROM aplicabilidad WHERE cve=?", (self.CVE,))}
        self.assertEqual(corregidas[self.u22], "5.34.0-3ubuntu1.8")
        self.assertEqual(corregidas[self.u26], "5.40.1-7ubuntu0.1")
        self.assertIsNone(corregidas[self.d13])

    def test_el_repaso_recupera_la_referencia_de_la_cache_sin_red(self):
        self._sembrar_veredictos(con_referencia=False)
        self._cachear()
        sin_fuente = self.conn.execute(
            "SELECT COUNT(*) FROM aplicabilidad WHERE (referencia IS NULL OR referencia='') "
            "AND evidencia NOT LIKE ?", (f"%[{ap.MARCA_REFERENCIA}%",)).fetchone()[0]
        self.assertEqual(sin_fuente, 11)
        osv = ap.ClienteOSV(self.conn, cfg=self.cfg, fetch=_sin_red)
        stats = ap.repasar_referencias(self.conn, cfg=self.cfg, osv=osv)
        self.assertEqual(stats["peticiones"], 0)        # todo desde la caché
        self.assertGreaterEqual(stats["desde_cache"], 2)
        self.assertEqual(stats["filas"], 11)
        self.assertEqual(stats["sin_referencia"], 0)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM aplicabilidad WHERE referencia IS NULL OR referencia=''"
        ).fetchone()[0], 0)
        ubu = self.conn.execute(
            "SELECT evidencia, aviso, referencia FROM aplicabilidad WHERE activo_id=? LIMIT 1",
            (self.u22,)).fetchone()
        self.assertEqual(ubu["referencia"], f"https://ubuntu.com/security/{self.CVE}")
        self.assertNotIn(ap.MARCA_REFERENCIA, ubu["evidencia"])   # la evidencia queda limpia
        self.assertEqual(ubu["aviso"], "USN-9001-1")     # el aviso también se recupera
        deb = self.conn.execute(
            "SELECT referencia FROM aplicabilidad WHERE activo_id=? LIMIT 1", (self.d13,)).fetchone()
        self.assertEqual(deb["referencia"],
                         f"https://security-tracker.debian.org/tracker/{self.CVE}")
        # segunda pasada: nada que hacer (idempotente)
        self.assertEqual(ap.repasar_referencias(self.conn, cfg=self.cfg, osv=osv)["filas"], 0)

    def test_el_repaso_respeta_el_cupo_de_consultas(self):
        """Sin caché y sin cupo no se sale a la red: esos grupos se aplazan al día siguiente."""
        self._sembrar_veredictos(con_referencia=False)
        osv = ap.ClienteOSV(self.conn, cfg=self.cfg, max_peticiones=0, fetch=_sin_red)
        stats = ap.repasar_referencias(self.conn, cfg=self.cfg, osv=osv, limite_consultas=0)
        self.assertEqual(stats["peticiones"], 0)
        self.assertTrue(stats["cupo_agotado"])
        self.assertEqual(stats["sin_referencia"], 3)     # los tres sistemas quedan pendientes
        self.assertEqual(stats["filas"], 0)              # nada escrito: se reintenta mañana

    def test_el_repaso_no_necesita_osv_para_freebsd_ni_windows(self):
        """Los motores que no son OSV.dev se sustentan con el aviso del fabricante, sin red."""
        bsd = self._activo("srv-bsd-01", ecosistema=None, familia="freebsd", ciclo="14.4",
                           so_nombre="FreeBSD 14.4", entorno="produccion")
        win = self._activo("pc-win-11", ecosistema=None, familia="windows", ciclo="11-25h2",
                           so_nombre="Windows 11 Pro", entorno="pruebas", origen="equipos")
        self._veredicto(bsd, "unbound", instalada="1.19.0_1", corregida="1.19.0_2", motor="vuxml",
                        aviso="FreeBSD-SA-26:33.unbound")
        self._veredicto(win, "windows 11", instalada="10.0.26100.4351",
                        corregida="10.0.26100.4770", motor="msrc", aviso="KB5058405")
        self.conn.commit()
        osv = ap.ClienteOSV(self.conn, cfg=self.cfg, max_peticiones=0, fetch=_sin_red)
        stats = ap.repasar_referencias(self.conn, cfg=self.cfg, osv=osv, limite_consultas=0)
        self.assertEqual((stats["peticiones"], stats["filas"]), (0, 2))
        fuentes = {r["paquete"]: r["referencia"] for r in self.conn.execute(
            "SELECT paquete, referencia FROM aplicabilidad WHERE motor IN ('vuxml','msrc')")}
        self.assertEqual(fuentes["unbound"],
                         "https://www.freebsd.org/security/advisories/FreeBSD-SA-26:33.unbound.asc")
        self.assertEqual(fuentes["windows 11"], "https://support.microsoft.com/help/5058405")

    def test_el_repaso_no_toca_lo_que_ya_esta_sustentado(self):
        self._sembrar_veredictos(con_referencia=True)
        antes = [tuple(r) for r in self.conn.execute(
            "SELECT evidencia, referencia FROM aplicabilidad ORDER BY id")]
        stats = ap.repasar_referencias(self.conn, cfg=self.cfg,
                                       osv=ap.ClienteOSV(self.conn, cfg=self.cfg, fetch=_sin_red))
        self.assertEqual((stats["grupos"], stats["filas"]), (0, 0))
        self.assertEqual([tuple(r) for r in self.conn.execute(
            "SELECT evidencia, referencia FROM aplicabilidad ORDER BY id")], antes)

    def test_el_repaso_respeta_las_filas_antiguas_con_la_marca_en_la_evidencia(self):
        """Compatibilidad: las filas guardadas antes del esquema v8 llevan la dirección
        pegada a la evidencia; ya están sustentadas y el repaso no las toca."""
        self._sembrar_veredictos(con_referencia=True, formato_antiguo=True)
        vacias = self.conn.execute(
            "SELECT COUNT(*) FROM aplicabilidad WHERE referencia IS NULL").fetchone()[0]
        self.assertEqual(vacias, 11)
        stats = ap.repasar_referencias(self.conn, cfg=self.cfg,
                                       osv=ap.ClienteOSV(self.conn, cfg=self.cfg, fetch=_sin_red))
        self.assertEqual((stats["grupos"], stats["filas"]), (0, 0))
        # y se siguen leyendo: la interfaz recupera la fuente de la marca antigua
        datos = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)
        activo = {a["nombre"]: a for a in datos["afectados"]}["srv-ubu-26"]
        self.assertEqual(activo["referencia"],
                         "https://ubuntu.com/security/notices/USN-9001-1")
        for d in activo["paquetes_detalle"]:
            self.assertNotIn(ap.MARCA_REFERENCIA, d["evidencia"])
            self.assertEqual(d["referencia"],
                             "https://ubuntu.com/security/notices/USN-9001-1")


# ==========================================================================
# 5. Cómo se ve: correo y las dos fichas
# ==========================================================================
class TestPresentacion(BaseTresSistemas):
    def _amenaza_para_el_correo(self) -> list[dict]:
        amenazas = [dict(self.conn.execute(
            "SELECT * FROM threats WHERE id=?", (self.threat_id,)).fetchone())]
        for a in amenazas:
            a["technologies"] = []
        ap.adjuntar_activos(self.conn, amenazas, limite=10)
        return amenazas

    def _meta(self, **extra) -> dict:
        meta = {"periodo": self.ahora[:7], "max_detalle": 25, "detalle_top": 3,
                "url_interfaz": "https://interfaz.interna/amenazas/",
                "filtro": {"alertadas": 1, "excluidas": {}, "umbral_relevancia": 50.0,
                           "min_confianza": 0.6, "ignorar_criticidad_baja": True}}
        meta.update(extra)
        return meta

    def test_el_correo_lleva_el_desglose_por_sistema(self):
        self._sembrar_veredictos()
        html = notify.render_alert_email(self._amenaza_para_el_correo(), self._meta())
        self.assertIn("Qué hay que hacer en cada sistema operativo", html)
        # «Equipo» a secas para una máquina desaparece del correo (2026-09-15) y el rótulo
        # dice las dos magnitudes: activos afectados y líneas, una por activo y paquete.
        self.assertIn("Activos con la versión vulnerable instalada", html)
        self.assertNotIn("Equipos con la versión vulnerable instalada", html)
        for texto in ("Ubuntu 22.04", "Ubuntu 26.04", "Debian 13",
                      "5.34.0-3ubuntu1.8", "5.40.1-7ubuntu0.1",
                      "Sin corrección publicada todavía",
                      "el aviso de seguridad no indica en qué versión se corrige".capitalize(),
                      "Misma versión de origen (5.34.0)",
                      "Misma versión de origen (5.40.1)",
                      'href="https://ubuntu.com/security/notices/USN-9001-1"',
                      f'href="https://security-tracker.debian.org/tracker/{self.CVE}"',
                      "Nota de seguridad de Ubuntu", "Rastreador de seguridad de Debian",
                      "en producción o contingencia"):
            self.assertIn(texto, html, f"falta «{texto}» en el correo")
        self.assertIsNone(RE_SCRIPT.search(html))
        for abreviatura in ABREVIATURAS:
            self.assertNotIn(abreviatura, html)

    def test_el_correo_sin_novedades_sigue_intacto(self):
        html = notify.render_alert_email([], self._meta(sin_novedades=True))
        self.assertIn("Sin novedades que requieran acción", html)
        self.assertNotIn("Qué hay que hacer en cada sistema operativo", html)

    def test_el_correo_respeta_el_tope_de_detalle(self):
        self._sembrar_veredictos()
        amenazas = self._amenaza_para_el_correo()
        html = notify.render_alert_email(amenazas, self._meta(detalle_top=0))
        self.assertNotIn("Qué hay que hacer en cada sistema operativo", html)
        html3 = notify.render_alert_email(amenazas, self._meta(detalle_top=3))
        self.assertIn("Qué hay que hacer en cada sistema operativo", html3)

    def _cliente(self):
        from webui import auth
        from webui.app import crear_app
        with db.session(self.ruta) as conn:
            auth.crear_usuario(conn, "analista", "AnalistaSegura#2026", rol="admin", actor="t")
        app = crear_app(db_path=self.ruta, testing=True)
        cli = app.test_client()
        cli.post("/login", data={"usuario": "analista", "password": "AnalistaSegura#2026"})
        return cli

    def test_la_ficha_de_la_amenaza_pinta_el_desglose(self):
        self._sembrar_veredictos()
        html = self._cliente().get(f"/amenazas/{self.threat_id}").get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html))
        self.assertIsNone(RE_ON.search(html))
        self.assertIsNone(RE_SCRIPT.search(html))
        for texto in ("Qué hay que hacer en cada sistema operativo", "Sistema operativo",
                      "En producción o contingencia", "Paquete afectado", "Fuente oficial",
                      "Ubuntu 22.04", "Ubuntu 26.04", "Debian 13",
                      "Actualizar de", "5.34.0-3ubuntu1.8",
                      "Sin corrección publicada todavía",
                      "Misma versión de origen (5.34.0)",
                      'href="https://ubuntu.com/security/notices/USN-9001-1"',
                      "Nota de seguridad de Ubuntu",
                      "Versión instalada más antigua",
                      "dpkg --compare-versions"):
            self.assertIn(texto, html, f"falta «{texto}» en la ficha de la amenaza")
        for abreviatura in ABREVIATURAS:
            self.assertNotIn(abreviatura, html)
        # el recorrido guiado sigue completo y sin números repetidos
        pasos = re.findall(r'data-tour="(\d+)"[^>]*data-tour-titulo="([^"]+)"[^>]*data-tour-texto="([^"]{41,})"',
                           (BASE_DIR / "webui" / "templates" / "amenaza_detalle.html").read_text(encoding="utf-8"))
        numeros = [int(n) for n, _, _ in pasos]
        self.assertEqual(len(numeros), len(set(numeros)))
        self.assertIn("Qué hacer en cada sistema operativo", [t for _, t, _ in pasos])

    def test_la_ficha_del_activo_explica_la_comparacion(self):
        self._sembrar_veredictos()
        html = self._cliente().get(f"/activos/{self.u26}").get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html))
        self.assertIsNone(RE_ON.search(html))
        self.assertIsNone(RE_SCRIPT.search(html))
        # Adaptado el 2026-09-09: la tabla «Amenazas evaluadas para este activo» se
        # retiró porque listaba también lo que NO afecta (petición repetida del usuario).
        # La explicación de la comparación, la orden que la verifica y el aviso con su
        # dirección oficial siguen en la ficha, dentro de la trazabilidad de cada
        # actualización, que es donde está la vulnerabilidad que las pidió.
        for texto in ("Actualizaciones pendientes",
                      "Trazabilidad de las versiones solicitadas",
                      "Misma versión de origen (5.40.1)",
                      'href="https://ubuntu.com/security/notices/USN-9001-1"',
                      "USN-9001-1", "Nota de seguridad de Ubuntu",
                      'dpkg --compare-versions &#34;5.40.1-7build1&#34;'):
            self.assertIn(texto, html, f"falta «{texto}» en la ficha del activo")
        for abreviatura in ABREVIATURAS:
            self.assertNotIn(abreviatura, html)

    def test_el_recorrido_guiado_va_en_el_orden_de_los_paneles(self):
        """Hallazgo 7: el panel nuevo llevaba data-tour="10" y estaba ANTES del panel 9, así
        que el recorrido saltaba hacia atrás."""
        plantilla = (BASE_DIR / "webui" / "templates" / "amenaza_detalle.html").read_text(
            encoding="utf-8")
        numeros = [int(n) for n in re.findall(r'data-tour="(\d+)"', plantilla)]
        self.assertGreaterEqual(len(numeros), 2)
        self.assertEqual(numeros, sorted(numeros),
                         "los pasos del recorrido no siguen el orden de los paneles")
        self.assertEqual(len(numeros), len(set(numeros)), "hay un paso repetido")
        self.assertEqual(numeros, list(range(1, len(numeros) + 1)),
                         "los pasos tienen que ir de 1 a N sin huecos")
        # el panel por sistema va antes que el de activos afectados, y así lo dicen sus números
        por_sistema = plantilla.index('id="por-sistema"')
        afectados = plantilla.index('id="activos-afectados"')
        self.assertLess(por_sistema, afectados)
        paso_sistema = int(re.search(r'id="por-sistema" data-tour="(\d+)"', plantilla).group(1))
        paso_afectados = int(re.search(r'id="activos-afectados" data-tour="(\d+)"',
                                        plantilla).group(1))
        self.assertLess(paso_sistema, paso_afectados)

    def test_el_identificador_de_aviso_se_recorta_al_pintarlo(self):
        """Hallazgo 7: un identificador largo desmontaba la columna de la tabla."""
        largo = "FreeBSD-SA-26:33.openssl-con-un-nombre-larguisimo-de-verdad"
        bsd = self._activo("srv-bsd-largo", ecosistema=None, familia="freebsd", ciclo="14.4",
                           so_nombre="FreeBSD 14.4", entorno="produccion")
        self._veredicto(bsd, "openssl", instalada="3.0.16,1", corregida="3.0.22,1",
                        motor="vuxml", aviso=largo)
        self._sembrar_veredictos()
        cliente = self._cliente()
        html = cliente.get(f"/amenazas/{self.threat_id}").get_data(as_text=True)
        self.assertNotIn(f">{largo}</a>", html)
        self.assertNotIn(f">{largo}</span>", html)
        self.assertIn(largo[:27] + "…", html)
        # y en la ficha del activo, igual
        html_activo = cliente.get(f"/activos/{bsd}").get_data(as_text=True)
        self.assertNotIn(f">{largo}</a>", html_activo)
        self.assertIn(largo[:27] + "…", html_activo)

    def test_la_ficha_del_activo_dice_por_que_no_hay_correccion(self):
        self._sembrar_veredictos()
        html = self._cliente().get(f"/activos/{self.d13}").get_data(as_text=True)
        self.assertIn("sin corrección publicada todavía", html)
        self.assertIn("el aviso de seguridad no indica en qué versión se corrige", html)



# ==========================================================================
# Hallazgo 1 [ALTO]: la fuente oficial se valida por SERVIDOR, no por subcadena
# ==========================================================================
class TestFuenteOficialPorServidor(unittest.TestCase):
    """Antes bastaba con que la dirección CONTUVIERA «ubuntu.com» en cualquier posición.

    Una dirección como «https://malicioso.example/ubuntu.com/aviso» se le presentaba al
    equipo que aplica el parche como «Nota de seguridad de Ubuntu». Ahora se analiza la
    dirección y se compara el nombre de servidor.
    """

    #: Direcciones tramposas que NO se pueden presentar como fuente oficial.
    TRAMPOSAS = (
        ("la ruta contiene el servidor oficial", "https://malicioso.example/ubuntu.com/aviso"),
        ("sufijo del servidor oficial", "https://ubuntu.com.malicioso.example/security/notices/USN-1-1"),
        ("servidor parecido", "https://mi-ubuntu.com/security/notices/USN-1-1"),
        ("subdominio falso de Debian", "https://security-tracker.debian.org.evil.example/tracker/CVE-2025-1"),
        ("credenciales en la dirección", "https://usuario:clave@ubuntu.com/security/notices/USN-1-1"),
        ("puerto que no es el de https", "https://ubuntu.com:8443/security/notices/USN-1-1"),
        ("sin cifrado", "http://ubuntu.com/security/notices/USN-1-1"),
        ("redirección aparente", "https://ubuntu.com/redirect?destino=https://malicioso.example"),
        ("nombre punycode parecido", "https://xn--ubntu-hva.com/security/notices/USN-1-1"),
        ("recorrido de directorios", "https://ubuntu.com/security/notices/../../../malicioso"),
        ("barra invertida antes de arroba", "https://ubuntu.com\\@malicioso.example/security/notices/X"),
        ("esquema ejecutable", "javascript:alert(1)"),
        ("ruta que no es la del aviso", "https://nvd.nist.gov/general/news"),
        ("servidor vacío", "https:///security/notices/USN-1-1"),
    )

    #: Direcciones reales que sí se admiten.
    LEGITIMAS = (
        ("https://ubuntu.com/security/notices/USN-8486-1", "Nota de seguridad de Ubuntu"),
        ("https://UBUNTU.COM/security/notices/USN-8486-1", "Nota de seguridad de Ubuntu"),
        ("https://esm.ubuntu.com/security/notices/USN-8486-1", "Nota de seguridad de Ubuntu"),
        ("https://ubuntu.com/security/CVE-2025-15661", "Ficha del CVE en Ubuntu"),
        ("https://security-tracker.debian.org/tracker/CVE-2025-15661",
         "Rastreador de seguridad de Debian"),
        ("https://deb.freexian.com/extended-lts/tracker/ELA-1234-1",
         "Rastreador del soporte ampliado de Debian"),
        ("https://vuxml.freebsd.org/freebsd/abcd-1234.html", "Entrada de VuXML de FreeBSD"),
        ("https://www.freebsd.org/security/advisories/FreeBSD-SA-26:33.unbound.asc",
         "Aviso de seguridad de FreeBSD"),
        ("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1",
         "Guía de actualizaciones de Microsoft"),
        ("https://support.microsoft.com/help/5058405", "Artículo de soporte de Microsoft"),
        ("https://nvd.nist.gov/vuln/detail/CVE-2026-1", "Ficha del CVE en el NIST"),
    )

    def test_ninguna_direccion_tramposa_pasa_por_oficial(self):
        for motivo, url in self.TRAMPOSAS:
            with self.subTest(motivo=motivo):
                self.assertFalse(ap.es_fuente_oficial(url), f"admitida ({motivo}): {url}")
                self.assertIsNone(ap.peso_fuente_oficial(url))
                self.assertEqual(ap.etiqueta_referencia(url), "",
                                 f"etiquetada como oficial ({motivo}): {url}")

    def test_las_direcciones_reales_se_admiten_con_su_nombre(self):
        for url, etiqueta in self.LEGITIMAS:
            with self.subTest(url=url):
                self.assertTrue(ap.es_fuente_oficial(url), f"rechazada: {url}")
                self.assertEqual(ap.etiqueta_referencia(url), etiqueta)

    def test_el_orden_de_preferencia_se_mantiene(self):
        nota = ap.peso_fuente_oficial("https://ubuntu.com/security/notices/USN-1-1")
        ficha = ap.peso_fuente_oficial("https://ubuntu.com/security/CVE-2025-1")
        nist = ap.peso_fuente_oficial("https://nvd.nist.gov/vuln/detail/CVE-2025-1")
        self.assertLess(nota, ficha)
        self.assertLess(ficha, nist)

    def test_el_registro_de_osv_no_acepta_una_direccion_disfrazada(self):
        registro = {"id": "UBUNTU-CVE-2025-15661", "references": [
            {"type": "ADVISORY", "url": "https://malicioso.example/ubuntu.com/security/notices/USN-1-1"},
            {"type": "REPORT", "url": "https://ubuntu.com.malicioso.example/security/notices/USN-2-1"}]}
        # ninguna es del servidor de Ubuntu: se construye la canónica de la familia
        self.assertEqual(ap.referencia_osv(registro, ecosistema="Ubuntu:26.04",
                                           cve="CVE-2025-15661"),
                         "https://ubuntu.com/security/CVE-2025-15661")

    def test_una_direccion_que_no_se_puede_validar_no_se_presenta_como_fuente(self):
        falsa = "https://malicioso.example/ubuntu.com/aviso"
        # con CVE se cae a la dirección canónica; sin CVE, sin enlace
        self.assertEqual(ap.referencia_segura(falsa, cve="CVE-2025-15661",
                                              ecosistema="Ubuntu:26.04"),
                         "https://ubuntu.com/security/CVE-2025-15661")
        self.assertEqual(ap.referencia_segura(falsa), "")
        self.assertEqual(ap.referencia_segura(None), "")


# ==========================================================================
# Hallazgo 2 [ALTO]: la explicación y las versiones van POR PAQUETE
# ==========================================================================
class TestPlanPorPaqueteDelActivo(BaseTresSistemas):
    """Caso real: un servidor Ubuntu 22.04 con cuatro paquetes de Perl.

    ``perl-modules-5.34`` se quedó en una revisión anterior a la de los otros tres, así que
    la pareja de versiones NO es la misma para los cuatro. Antes se conservaba la versión
    instalada y la corregida de la PRIMERA fila y se usaban para explicar los cuatro
    paquetes: la frase describía un paquete distinto del que se estaba mirando.
    """

    INSTALADAS = {"libperl5.34": "5.34.0-3ubuntu1.5", "perl": "5.34.0-3ubuntu1.5",
                  "perl-base": "5.34.0-3ubuntu1.5", "perl-modules-5.34": "5.34.0-3ubuntu1.3"}
    CORREGIDA = "5.34.0-3ubuntu1.8"
    USN = "https://ubuntu.com/security/notices/USN-9001-1"

    def _sembrar_cuatro_paquetes(self):
        for paquete, instalada in self.INSTALADAS.items():
            self._veredicto(self.u22, paquete, instalada=instalada, corregida=self.CORREGIDA,
                            aviso="USN-9001-1", referencia=self.USN)
        self.conn.execute(
            """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados, no_afectados,
                   sin_dato, afectados_expuestos, parche_disponible, detalle)
               VALUES(?,?,1,0,0,1,1,'{}')""", (self.threat_id, self.ahora))
        self.conn.commit()

    def test_cada_paquete_lleva_su_propia_version_y_su_propia_explicacion(self):
        self._sembrar_cuatro_paquetes()
        activo = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)["afectados"][0]
        self.assertEqual(activo["n_paquetes"], 4)
        self.assertEqual([d["paquete"] for d in activo["paquetes_detalle"]],
                         ["libperl5.34", "perl", "perl-base", "perl-modules-5.34"])
        # los cuatro paquetes NO comparten plan: el activo no tiene una pareja propia
        self.assertFalse(activo["mismo_plan"])
        self.assertIsNone(activo["version_instalada"])
        self.assertIsNone(activo["version_corregida"])
        self.assertIsNone(activo["comparacion"])
        self.assertIn("plan por paquete:", activo["accion"])
        for d in activo["paquetes_detalle"]:
            with self.subTest(paquete=d["paquete"]):
                instalada = self.INSTALADAS[d["paquete"]]
                self.assertEqual(d["version_instalada"], instalada)
                self.assertEqual(d["version_corregida"], self.CORREGIDA)
                revision = instalada.split("-", 1)[1]
                # la frase habla de ESTE paquete, no del primero de la lista
                self.assertIn(f"de {revision} a 3ubuntu1.8", d["comparacion"]["texto"])
                self.assertIn(instalada, d["comparacion"]["verificacion"])
                self.assertEqual(d["accion"], f"actualizar de {instalada} a {self.CORREGIDA}")
                self.assertEqual(d["referencia"], self.USN)
                self.assertEqual(d["referencia_es"], "Nota de seguridad de Ubuntu")
        # el que iba retrasado no hereda la revisión de los otros tres
        modulos = {d["paquete"]: d for d in activo["paquetes_detalle"]}["perl-modules-5.34"]
        self.assertNotIn("3ubuntu1.5", modulos["comparacion"]["texto"])

    def test_un_activo_con_todos_los_paquetes_iguales_si_tiene_una_sola_linea(self):
        for paquete in ("perl", "perl-base"):
            self._veredicto(self.u22, paquete, instalada="5.34.0-3ubuntu1.5",
                            corregida=self.CORREGIDA, aviso="USN-9001-1", referencia=self.USN)
        self.conn.execute(
            """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados, no_afectados,
                   sin_dato, afectados_expuestos, parche_disponible, detalle)
               VALUES(?,?,1,0,0,1,1,'{}')""", (self.threat_id, self.ahora))
        self.conn.commit()
        activo = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)["afectados"][0]
        self.assertTrue(activo["mismo_plan"])
        self.assertEqual(activo["version_instalada"], "5.34.0-3ubuntu1.5")
        self.assertEqual(activo["version_corregida"], self.CORREGIDA)
        self.assertTrue(activo["comparacion"]["misma_origen"])

    def test_el_sistema_tampoco_mezcla_los_cuatro_paquetes(self):
        self._sembrar_cuatro_paquetes()
        sistema = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)["sistemas"][0]
        detalle = {d["paquete"]: d for d in sistema["paquetes_detalle"]}
        self.assertEqual(set(detalle), set(self.INSTALADAS))
        for paquete, instalada in self.INSTALADAS.items():
            self.assertEqual(detalle[paquete]["version_instalada"], instalada)
        self.assertFalse(sistema["plan_unico"])
        self.assertIsNone(sistema["version_instalada"])

    def test_la_ficha_pinta_una_fila_por_paquete(self):
        """El cuadro de activos afectados es AJAX (2026-11-16): el HTML inicial de la
        ficha solo trae el contenedor; una fila por paquete, con su propia versión y su
        propia explicación, vive en su endpoint paginado."""
        self._sembrar_cuatro_paquetes()
        cli = self._cliente_admin()
        html = cli.get(f"/amenazas/{self.threat_id}").get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html))
        self.assertIsNone(RE_ON.search(html))
        self.assertIn('id="grid-cuerpo-activos"', html)

        datos = cli.get(f"/amenazas/activos-afectados/{self.threat_id}").get_json()
        filas = {f["paquete"]: f for f in datos["activos"]}
        self.assertEqual(set(filas), set(self.INSTALADAS))
        for paquete, instalada in self.INSTALADAS.items():
            self.assertIn(f'dpkg --compare-versions "{instalada}"', filas[paquete]["verificacion"])
        # las dos frases distintas conviven: la del paquete retrasado y la de los demás
        self.assertIn("de 3ubuntu1.3 a 3ubuntu1.8", filas["perl-modules-5.34"]["comparacion_texto"])
        for paquete in ("libperl5.34", "perl", "perl-base"):
            self.assertIn("de 3ubuntu1.5 a 3ubuntu1.8", filas[paquete]["comparacion_texto"])
        for abreviatura in ABREVIATURAS:
            self.assertNotIn(abreviatura, html)

    def test_el_correo_pinta_una_fila_por_paquete(self):
        self._sembrar_cuatro_paquetes()
        amenazas = [dict(self.conn.execute(
            "SELECT * FROM threats WHERE id=?", (self.threat_id,)).fetchone())]
        amenazas[0]["technologies"] = []
        ap.adjuntar_activos(self.conn, amenazas, limite=10)
        html = notify.render_alert_email(amenazas, {
            "periodo": self.ahora[:7], "max_detalle": 25, "detalle_top": 3,
            "url_interfaz": "https://interfaz.interna/amenazas/",
            "filtro": {"alertadas": 1, "excluidas": {}, "umbral_relevancia": 50.0,
                       "min_confianza": 0.6, "ignorar_criticidad_baja": True}})
        for paquete in self.INSTALADAS:
            self.assertIn(paquete, html)
        self.assertIn("Una fila por paquete", html)
        self.assertIn("de 3ubuntu1.3 a 3ubuntu1.8", html)
        self.assertIn("de 3ubuntu1.5 a 3ubuntu1.8", html)
        self.assertIsNone(RE_SCRIPT.search(html))

    def _cliente_admin(self):
        from webui import auth
        from webui.app import crear_app
        with db.session(self.ruta) as conn:
            auth.crear_usuario(conn, "analista", "AnalistaSegura#2026", rol="admin", actor="t")
        app = crear_app(db_path=self.ruta, testing=True)
        cli = app.test_client()
        cli.post("/login", data={"usuario": "analista", "password": "AnalistaSegura#2026"})
        return cli


# ==========================================================================
# Hallazgo 3 [ALTO]: el plan del sistema es el de sus paquetes, uno por uno
# ==========================================================================
class TestPlanPorPaqueteDelSistema(BaseTresSistemas):
    def _resumen(self):
        self.conn.execute(
            """INSERT INTO aplicabilidad_amenaza(threat_id, evaluado_at, afectados, no_afectados,
                   sin_dato, afectados_expuestos, parche_disponible, detalle)
               VALUES(?,?,1,0,0,1,1,'{}')""", (self.threat_id, self.ahora))
        self.conn.commit()

    def test_freebsd_da_el_plan_del_sistema_base_y_del_puerto_por_separado(self):
        """CVE-2026-75803: el mismo servidor tiene el sistema base 14.4_5 y openssl 3.0.16,1."""
        bsd = self._activo("srv-bsd-01", ecosistema=None, familia="freebsd", ciclo="14.4",
                           so_nombre="FreeBSD 14.4", entorno="produccion")
        self._veredicto(bsd, "freebsd", instalada="14.4_5", corregida="14.4_9", motor="vuxml",
                        aviso="FreeBSD-SA-26:33.openssl")
        self._veredicto(bsd, "openssl", instalada="3.0.16,1", corregida="3.0.22,1", motor="vuxml",
                        aviso="FreeBSD-SA-26:33.openssl")
        self._resumen()
        datos = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)
        sistema = datos["sistemas"][0]
        detalle = {d["paquete"]: d for d in sistema["paquetes_detalle"]}
        self.assertEqual(detalle["freebsd"]["version_instalada"], "14.4_5")
        self.assertEqual(detalle["freebsd"]["version_corregida"], "14.4_9")
        self.assertEqual(detalle["openssl"]["version_instalada"], "3.0.16,1")
        self.assertEqual(detalle["openssl"]["version_corregida"], "3.0.22,1")
        self.assertEqual(detalle["freebsd"]["accion"], "actualizar de 14.4_5 a 14.4_9")
        self.assertEqual(detalle["openssl"]["accion"], "actualizar de 3.0.16,1 a 3.0.22,1")
        # ninguna frase afirma una pareja que no exista en los datos
        for texto in ("14.4_5 a 3.0.22,1", "3.0.16,1 a 14.4_9", "de 3.0.16,1 a 14.4"):
            self.assertNotIn(texto, sistema["accion"])
            for d in sistema["paquetes_detalle"]:
                self.assertNotIn(texto, d["accion"])
                self.assertNotIn(texto, d["comparacion"]["texto"])
        # el activo tampoco: sus dos paquetes no comparten plan
        activo = datos["afectados"][0]
        self.assertFalse(activo["mismo_plan"])
        self.assertIsNone(activo["version_corregida"])
        self.assertEqual({d["paquete"]: d["version_corregida"] for d in activo["paquetes_detalle"]},
                         {"freebsd": "14.4_9", "openssl": "3.0.22,1"})

    def test_un_sistema_con_un_solo_paquete_si_se_resume_en_una_linea(self):
        bsd = self._activo("srv-bsd-02", ecosistema=None, familia="freebsd", ciclo="14.4",
                           so_nombre="FreeBSD 14.4", entorno="produccion")
        self._veredicto(bsd, "unbound", instalada="1.19.0_1", corregida="1.19.0_2", motor="vuxml")
        self._resumen()
        sistema = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)["sistemas"][0]
        self.assertTrue(sistema["plan_unico"])
        self.assertEqual(sistema["version_instalada"], "1.19.0_1")
        self.assertEqual(sistema["version_corregida"], "1.19.0_2")
        self.assertEqual(sistema["accion"], "actualizar de 1.19.0_1 a 1.19.0_2")
        self.assertIn("nivel de parche de FreeBSD, del 1 al 2", sistema["comparacion"]["texto"])

    def test_un_paquete_con_dos_versiones_corregidas_dice_las_parejas_que_hay(self):
        """El mismo puerto con dos avisos: no se inventa una pareja mezclando la instalada
        más antigua con la corregida más moderna."""
        a1 = self._activo("srv-bsd-03", ecosistema=None, familia="freebsd", ciclo="14.4",
                          so_nombre="FreeBSD 14.4", entorno="produccion")
        a2 = self._activo("srv-bsd-04", ecosistema=None, familia="freebsd", ciclo="14.4",
                          so_nombre="FreeBSD 14.4", entorno="produccion")
        self._veredicto(a1, "openssl", instalada="3.0.16,1", corregida="3.0.18,1", motor="vuxml")
        self._veredicto(a2, "openssl", instalada="3.0.17,1", corregida="3.0.22,1", motor="vuxml")
        self._resumen()
        sistema = ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)["sistemas"][0]
        detalle = sistema["paquetes_detalle"][0]
        self.assertTrue(detalle["varias_corregidas"])
        self.assertIsNone(detalle["version_instalada"])
        self.assertIsNone(detalle["version_corregida"])
        self.assertIsNone(detalle["comparacion"])
        self.assertEqual([(p["instalada"], p["corregida"]) for p in detalle["parejas"]],
                         [("3.0.16,1", "3.0.18,1"), ("3.0.17,1", "3.0.22,1")])
        self.assertEqual(detalle["accion"],
                         "actualizar a la versión que indica el aviso de cada equipo: "
                         "de 3.0.16,1 a 3.0.18,1; de 3.0.17,1 a 3.0.22,1")
        self.assertNotIn("3.0.16,1 a 3.0.22,1", detalle["accion"])

    def test_un_sistema_sin_correccion_lo_dice_una_sola_vez(self):
        self._sembrar_veredictos()
        sistemas = {s["nombre"]: s for s in
                    ap.activos_de_amenaza(self.conn, self.threat_id, limite=10)["sistemas"]}
        d13 = sistemas["Debian 13"]
        self.assertFalse(d13["hay_correccion"])
        self.assertEqual(d13["sin_parche_motivo"], "aviso_sin_version")
        self.assertTrue(all(not d["hay_correccion"] for d in d13["paquetes_detalle"]))


# ==========================================================================
# Hallazgo 4 [MEDIO]: el motor «version» se sustenta en la ficha del NIST
# ==========================================================================
class TestMotorVersionSeSustentaEnElNist(BaseTresSistemas):
    NIST = "https://nvd.nist.gov/vuln/detail/CVE-2026-15534"

    def test_la_funcion_devuelve_siempre_la_ficha_del_nist(self):
        self.assertEqual(ap.referencia_por_motor("version", self.CVE, ecosistema="Ubuntu:22.04",
                                                 familia="ubuntu"), self.NIST)
        # incluso si la fila trae guardada la página de la distribución
        self.assertEqual(ap.referencia_segura(f"https://ubuntu.com/security/{self.CVE}",
                                              cve=self.CVE, ecosistema="Ubuntu:22.04",
                                              familia="ubuntu", motor="version"), self.NIST)
        # los demás motores siguen sustentándose en la distribución
        self.assertEqual(ap.referencia_por_motor("osv", self.CVE, ecosistema="Ubuntu:22.04"),
                         f"https://ubuntu.com/security/{self.CVE}")

    def test_el_repaso_no_le_pone_la_pagina_de_la_distribucion(self):
        self._veredicto(self.u22, "google-chrome-stable", instalada="151.0",
                        corregida="152.0.7632.45", motor="version")
        self.conn.commit()
        osv = ap.ClienteOSV(self.conn, cfg=self.cfg, max_peticiones=0, fetch=_sin_red)
        stats = ap.repasar_referencias(self.conn, cfg=self.cfg, osv=osv, limite_consultas=0)
        self.assertEqual(stats["filas"], 1)
        fila = self.conn.execute(
            "SELECT referencia FROM aplicabilidad WHERE motor='version'").fetchone()
        self.assertEqual(fila["referencia"], self.NIST)

    def test_la_ficha_del_activo_ensena_la_del_nist(self):
        self._veredicto(self.u22, "google-chrome-stable", instalada="151.0",
                        corregida="152.0.7632.45", motor="version",
                        referencia=f"https://ubuntu.com/security/{self.CVE}")
        self.conn.commit()
        fila = [f for f in ap.veredictos_de_activo(self.conn, self.u22, limite=10)
                if f["motor"] == "version"][0]
        self.assertEqual(fila["referencia"], self.NIST)
        self.assertEqual(fila["referencia_es"], "Ficha del CVE en el NIST")
        # y la comparación no se explica como «revisión del paquete de Ubuntu»
        self.assertFalse(fila["comparacion"]["misma_origen"])


# ==========================================================================
# Hallazgo 5 [MEDIO]: el repaso carga el índice de VuXML por sí mismo
# ==========================================================================
XML_VUXML = ('<vuxml><vuln vid="e0ff1234-abcd-11f0-9999-002590c1f29c">'
             '<topic>openssl -- fallo de validación</topic>'
             '<affects><package><name>openssl</name><range><lt>3.0.22,1</lt></range></package>'
             '</affects><references><cvename>CVE-2026-15534</cvename></references>'
             '</vuln></vuxml>')
URL_VUXML_ESPERADA = ("https://vuxml.freebsd.org/freebsd/"
                      "e0ff1234-abcd-11f0-9999-002590c1f29c.html")


class CargadorVuXML:
    """Doble del cargador: cuenta cuántas veces se llama (tiene que ser una sola)."""

    def __init__(self):
        self.llamadas = 0

    def __call__(self):
        self.llamadas += 1
        return ap.IndiceVuXML(XML_VUXML)


class TestRepasoCargaVuXML(BaseTresSistemas):
    def _sembrar_freebsd(self, activos: int = 2):
        for i in range(activos):
            bsd = self._activo(f"srv-bsd-1{i}", ecosistema=None, familia="freebsd", ciclo="14.4",
                               so_nombre="FreeBSD 14.4", entorno="produccion")
            # sin aviso: si el índice no se carga, la referencia sería la genérica del NIST
            self._veredicto(bsd, "openssl", instalada="3.0.16,1", corregida="3.0.22,1",
                            motor="vuxml")
        self.conn.commit()

    def test_el_repaso_lo_carga_solo_cuando_hay_filas_de_freebsd(self):
        self._sembrar_freebsd()
        cargador = CargadorVuXML()
        osv = ap.ClienteOSV(self.conn, cfg=self.cfg, max_peticiones=0, fetch=_sin_red)
        stats = ap.repasar_referencias(self.conn, cfg=self.cfg, osv=osv, limite_consultas=0,
                                       cargar_indice_vuxml=cargador)
        self.assertEqual(cargador.llamadas, 1)           # una sola vez para todos los grupos
        self.assertTrue(stats["vuxml_cargado"])
        fuentes = {r[0] for r in self.conn.execute(
            "SELECT referencia FROM aplicabilidad WHERE motor='vuxml'")}
        self.assertEqual(fuentes, {URL_VUXML_ESPERADA})

    def test_si_se_le_pasa_el_indice_no_lo_vuelve_a_cargar(self):
        self._sembrar_freebsd(activos=1)
        cargador = CargadorVuXML()
        osv = ap.ClienteOSV(self.conn, cfg=self.cfg, max_peticiones=0, fetch=_sin_red)
        ap.repasar_referencias(self.conn, cfg=self.cfg, osv=osv, limite_consultas=0,
                               vuxml=ap.IndiceVuXML(XML_VUXML), cargar_indice_vuxml=cargador)
        self.assertEqual(cargador.llamadas, 0)
        self.assertEqual(self.conn.execute(
            "SELECT referencia FROM aplicabilidad WHERE motor='vuxml'").fetchone()[0],
            URL_VUXML_ESPERADA)

    def test_sin_filas_de_freebsd_no_se_carga_nada(self):
        self._sembrar_veredictos(con_referencia=False)
        self._cachear()
        cargador = CargadorVuXML()
        osv = ap.ClienteOSV(self.conn, cfg=self.cfg, fetch=_sin_red)
        stats = ap.repasar_referencias(self.conn, cfg=self.cfg, osv=osv,
                                       cargar_indice_vuxml=cargador)
        self.assertEqual(cargador.llamadas, 0)
        self.assertFalse(stats["vuxml_cargado"])

    def test_si_vuxml_no_esta_disponible_el_repaso_no_falla(self):
        self._sembrar_freebsd(activos=1)
        osv = ap.ClienteOSV(self.conn, cfg=self.cfg, max_peticiones=0, fetch=_sin_red)

        def cargador_roto():
            raise RuntimeError("sin red y sin caché")

        stats = ap.repasar_referencias(self.conn, cfg=self.cfg, osv=osv, limite_consultas=0,
                                       cargar_indice_vuxml=cargador_roto)
        self.assertFalse(stats["vuxml_cargado"])
        # se sustenta con la ficha del NIST, no se queda sin fuente ni rompe la ejecución
        self.assertEqual(self.conn.execute(
            "SELECT referencia FROM aplicabilidad WHERE motor='vuxml'").fetchone()[0],
            f"https://nvd.nist.gov/vuln/detail/{self.CVE}")


# ==========================================================================
# Hallazgo 6 [BAJO]: ninguna frase inventa un dato que la versión no trae
# ==========================================================================
class TestSinInventarDatos(unittest.TestCase):
    def test_windows_sin_numero_de_actualizacion_no_escribe_un_cero(self):
        r = vd.explicar_comparacion("windows", "10.0.26100", "10.0.26100.4770")
        self.assertTrue(r["misma_origen"])
        self.assertIsNone(r["revision_instalada"])
        self.assertEqual(r["revision_corregida"], "4770")
        self.assertIn(vd.SIN_ACTUALIZACION, r["texto"])
        self.assertNotIn("del número 0", r["texto"])
        self.assertNotIn(" 0 al ", r["texto"])

    def test_freebsd_sin_nivel_de_parche_en_la_corregida(self):
        r = vd.explicar_comparacion("freebsd", "1.19.0_2", "1.19.0")
        self.assertIn(vd.SIN_NIVEL_PARCHE, r["texto"])
        self.assertNotIn("al 0", r["texto"])
        self.assertIsNone(r["revision_corregida"])

    def test_la_epoca_no_se_escribe_si_la_version_no_la_trae(self):
        dpkg = vd.explicar_comparacion("ubuntu", "9.6p1-3", "1:9.6p1-1")
        self.assertIn(vd.SIN_EPOCA, dpkg["texto"])
        self.assertNotIn("0:9.6p1", dpkg["texto"])
        pkg = vd.explicar_comparacion("freebsd", "3.0.16", "3.0.22,1")
        self.assertIn(vd.SIN_EPOCA, pkg["texto"])
        self.assertNotIn("3.0.16,0", pkg["texto"])
        # cuando las dos la traen, se escribe tal cual
        ambas = vd.explicar_comparacion("ubuntu", "1:9.6p1-3", "2:9.6p1-1")
        self.assertIn("1:9.6p1", ambas["texto"])
        self.assertIn("2:9.6p1", ambas["texto"])
        self.assertNotIn(vd.SIN_EPOCA, ambas["texto"])

    def test_las_funciones_de_epoca_distinguen_el_cero_de_la_ausencia(self):
        self.assertTrue(vd.epoca_escrita_dpkg("0:1.2-3"))
        self.assertFalse(vd.epoca_escrita_dpkg("1.2-3"))
        self.assertFalse(vd.epoca_escrita_dpkg(None))
        self.assertTrue(vd.epoca_escrita_pkg("3.0.22,0"))
        self.assertFalse(vd.epoca_escrita_pkg("3.0.22"))

    def test_ninguna_frase_de_las_familias_mete_un_cero_de_la_nada(self):
        casos = (("ubuntu", "1.2-3", "1.2-4"), ("debian", "1.2", "1.2-1"),
                 ("freebsd", "14.4", "14.4_9"), ("freebsd", "1.2.3", "1.2.3_1"),
                 ("windows", "10.0.26100", "10.0.26100.1"),
                 ("windows", "10.0.22631", "10.0.26100"))
        for familia, instalada, corregida in casos:
            with self.subTest(familia=familia, instalada=instalada):
                r = vd.explicar_comparacion(familia, instalada, corregida)
                self.assertNotIn(" 0 ", f" {r['texto']} ".replace(instalada, "").replace(corregida, ""))


# ==========================================================================
# Hallazgo 8: el correo anuncia los ficheros adjuntos
# ==========================================================================
class TestAdjuntosEnElCorreo(BaseTresSistemas):
    def _meta(self, **extra) -> dict:
        meta = {"periodo": self.ahora[:7], "max_detalle": 25, "detalle_top": 3,
                "url_interfaz": "https://interfaz.interna/amenazas/",
                "filtro": {"alertadas": 1, "excluidas": {}, "umbral_relevancia": 50.0,
                           "min_confianza": 0.6, "ignorar_criticidad_baja": True}}
        meta.update(extra)
        return meta

    def _amenazas(self):
        amenazas = [dict(self.conn.execute(
            "SELECT * FROM threats WHERE id=?", (self.threat_id,)).fetchone())]
        amenazas[0]["technologies"] = []
        ap.adjuntar_activos(self.conn, amenazas, limite=10)
        return amenazas

    def test_dice_que_lleva_y_para_que_sirve_cada_libro(self):
        """Revisión de claridad del 2026-09-15: el cuerpo del correo describe cada adjunto
        por lo que es, sin escribir su nombre de fichero. El nombre real lo sigue enseñando
        el gestor de correo junto al clip; la regla del proyecto es que ningún nombre de
        fichero se escriba en la interfaz ni en un correo."""
        self._sembrar_veredictos()
        html = notify.render_alert_email(self._amenazas(), self._meta(
            adjuntos=["alerta_2026-09-06.xlsx", "correcciones_disponibles_2026-09-06.xlsx"]))
        self.assertIn("Ficheros adjuntos a este correo", html)
        self.assertNotIn("alerta_2026-09-06.xlsx", html)
        self.assertNotIn("correcciones_disponibles_2026-09-06.xlsx", html)
        self.assertIn("Hoja de cálculo de las vulnerabilidades de esta alerta", html)
        self.assertIn("Hoja de cálculo de las correcciones que ya se pueden aplicar", html)
        self.assertIsNone(RE_SCRIPT.search(html))
        for abreviatura in ABREVIATURAS:
            self.assertNotIn(abreviatura, html)

    def test_un_solo_libro_solo_anuncia_ese(self):
        self._sembrar_veredictos()
        html = notify.render_alert_email(self._amenazas(),
                                         self._meta(adjuntos=["alerta_2026-09-06.xlsx"]))
        self.assertIn("Hoja de cálculo de las vulnerabilidades de esta alerta", html)
        self.assertNotIn("Hoja de cálculo de las correcciones que ya se pueden aplicar", html)

    def test_sin_adjuntos_no_se_anuncia_nada(self):
        self._sembrar_veredictos()
        for meta in (self._meta(), self._meta(adjuntos=[])):
            html = notify.render_alert_email(self._amenazas(), meta)
            self.assertNotIn("Ficheros adjuntos a este correo", html)


if __name__ == "__main__":
    unittest.main()
