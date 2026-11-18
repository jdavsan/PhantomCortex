"""Una entrada por actualización en la ficha del activo (2026-09-09).

Petición literal del usuario, mirando `/activos/511` (SRV-EJEMPLO-511), donde la tabla
«Amenazas evaluadas para este activo» tenía 182 filas —155 afectadas, 22 no afectadas y 5
sin dato— para 69 vulnerabilidades reales, y entre ellas 29 filas de `linux-tools-common`
con la misma versión instalada (6.8.0-106.106) y siete versiones destino distintas:

  «si una vulnerabilidad se repite se cuente solo como una y en esa misma se deje la
   trazabilidad de las versiones y de la última versión a la que se debe actualizar… que la
   remediación indique sí o sí la última versión a la que se debe actualizar y no una por
   una porque entonces estaría contando 3 vulnerabilidades y no una sola»

  «necesito que se haga ese ajuste para todas las vulnerabilidades que se repitan y las
   futuras que se lleguen a detectar en las fuentes»

  «En amenazas por activo necesito ver solo lo que afecta, no me sirve que me muestre lo
   que no me afecta, no tiene sentido»

Lo que estas pruebas fijan y no se puede perder:

1. Un paquete con tres vulnerabilidades que piden 1.1.0, 1.2.0 y 1.3.0 es UNA fila, con
   versión objetivo 1.3.0 y «3 vulnerabilidades», y la cola de las tres versiones en orden
   descendente con la primera marcada como la que hay que instalar.
2. Dos paquetes distintos con versiones distintas NO se mezclan: son dos filas.
3. En la ficha no aparece ninguna fila de veredicto «no afectado» ni «sin dato»; queda una
   sola línea que dice cuántos se evaluaron y cuántos no le afectan.
4. La cifra grande de la tarjeta y el número de filas de la tabla son el mismo número.
5. El caso de Windows: una sola actualización con muchas versiones destino conserva TODAS
   las versiones de la cola (es la trazabilidad) y acota los CVE de cada una, diciendo
   cuántos no se listan.
6. El plan de remediación del activo da la misma cifra que la ficha y una sola orden por
   paquete, a la última versión.

Sin red: base temporal bajo ``data/`` y datos insertados a mano (se reutilizan los
ayudantes de ``test_remediacion_agrupada``).
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from threatintel import aplicabilidad, db, remediacion
from threatintel.paths import BASE_DIR

sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "tests"))
from webui import auth  # noqa: E402
import test_remediacion_agrupada as base  # noqa: E402

RE_STYLE = re.compile(r"\sstyle\s*=", re.I)
RE_ON = re.compile(r"\son[a-z]+\s*=", re.I)
CLAVE = base.CLAVE

#: Las tres versiones del ejemplo del usuario: «si una vulnerabilidad se repite se cuente
#: solo como una… y no una por una porque entonces estaría contando 3 vulnerabilidades».
VERSIONES_DEL_EJEMPLO = ("1.1.0", "1.2.0", "1.3.0")


def _veredicto(conn, activo_id, threat_id, cve, paquete, instalada, corregida,
               *, veredicto="afectado", aviso=None):
    """Una fila de ``aplicabilidad`` como la que deja la evaluación diaria."""
    conn.execute(
        """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete, version_instalada,
                version_corregida, veredicto, motor, evidencia, aviso, evaluado_at)
           VALUES(?,?,?,?,?,?,?,'osv',?,?,?)""",
        (activo_id, threat_id, cve, paquete, instalada, corregida, veredicto,
         f"{paquete} {instalada} frente a {corregida or 'sin corrección'}", aviso,
         db.utcnow()))


class BaseFicha(unittest.TestCase):
    """Arnés común: una base temporal, un administrador y un cliente autenticado."""

    @classmethod
    def _crear(cls, nombre: str):
        cls.dir = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.dir.name) / nombre)
        db.init_db(cls.ruta)
        with db.session(cls.ruta) as conn:
            auth.crear_usuario(conn, "jefa@ejemplo.local", CLAVE, rol="admin",
                               nombre="Jefa Administradora", actor="t")
        from webui.app import crear_app
        cls.app = crear_app(db_path=cls.ruta, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _html(self, url):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        r = cli.get(url)
        self.assertEqual(r.status_code, 200, url)
        html = r.get_data(as_text=True)
        self.assertIsNone(RE_STYLE.search(html), f"style= en {url}")
        self.assertIsNone(RE_ON.search(html), f"on*= en {url}")
        return html

    def _tabla(self, html):
        """El cuerpo de la tabla de actualizaciones de la ficha."""
        self.assertIn('id="actualizaciones-activo"', html)
        zona = html.split('id="actualizaciones-activo"')[1]
        return zona.split("<tbody>")[1].split("</tbody>")[0]

    def _filas(self, html):
        return self._tabla(html).split("\n          <tr>")[1:]

    @staticmethod
    def _plano(texto):
        return " ".join(re.sub(r"<[^>]+>", " ", texto).split())


# ==========================================================================
# 1. El ejemplo del usuario, literal: tres versiones, una sola entrada
# ==========================================================================
class TestUnaEntradaPorActualizacion(BaseFicha):
    """Un paquete con tres vulnerabilidades que piden tres versiones distintas."""

    @classmethod
    def setUpClass(cls):
        cls._crear("ficha_una_entrada.db")
        with db.session(cls.ruta) as conn:
            cls.srv = base._activo(conn, "srv-ejemplo-01", ip="10.0.0.71")
            base._software(conn, cls.srv, "biblioteca-x", "1.0.0")
            base._software(conn, cls.srv, "otra-biblioteca", "2.0.0")
            # El caso del usuario: tres avisos del MISMO paquete que piden tres versiones.
            for i, version in enumerate(VERSIONES_DEL_EJEMPLO):
                cve = f"CVE-2026-110{i}"
                t = base._amenaza(conn, cve, severity="High")
                base._remediacion(conn, cls.srv, t, cve, "biblioteca-x", "1.0.0", version,
                                  aviso=f"USN-110{i}-1")
            # Un paquete DISTINTO con otra versión: no se puede mezclar con el anterior.
            t = base._amenaza(conn, "CVE-2026-1200", severity="Critical")
            base._remediacion(conn, cls.srv, t, "CVE-2026-1200", "otra-biblioteca",
                              "2.0.0", "2.5.0", aviso="USN-1200-1")
            # Y lo que NO afecta: no puede aparecer en la ficha (es el ejemplo literal del
            # usuario, «busybox-initramfs … ya incluye la corrección»).
            sin_riesgo = base._amenaza(conn, "CVE-2023-42366", severity="Medium")
            _veredicto(conn, cls.srv, sin_riesgo, "CVE-2023-42366", "busybox-initramfs",
                       "1:1.36.1-6ubuntu3.1", "1:1.36.1-6ubuntu3.1", veredicto="no_afectado")
            sin_dato = base._amenaza(conn, "CVE-2026-9999", severity="Medium")
            _veredicto(conn, cls.srv, sin_dato, "CVE-2026-9999", "algo", "1.0", None,
                       veredicto="sin_dato")

    def test_las_tres_vulnerabilidades_son_una_sola_entrada(self):
        html = self._html(f"/activos/{self.srv}")
        filas = self._filas(html)
        self.assertEqual(len(filas), 2,
                         "un paquete con tres versiones pedidas es UNA fila, y el otro "
                         "paquete la suya: nunca una fila por vulnerabilidad")
        biblioteca = next(f for f in filas if "biblioteca-x" in f)
        texto = self._plano(biblioteca)
        self.assertIn("Actualizar a 1.3.0", texto, "la ÚLTIMA versión, no una por una")
        self.assertIn("Instalada: 1.0.0", texto)
        self.assertIn("3 vulnerabilidades", texto)
        self.assertIn("3 filas de remediación en 1 paquete", texto)
        self.assertIn("Es la última de las 3 versiones que piden los avisos", texto)

    def test_la_cola_de_versiones_va_completa_y_de_la_mas_alta_a_la_mas_baja(self):
        html = self._html(f"/activos/{self.srv}")
        biblioteca = next(f for f in self._filas(html) if "biblioteca-x" in f)
        cola = biblioteca.split('class="lista-lineas cola-versiones"')[1]
        versiones = re.findall(r'<li[^>]*>\s*<span class="mono">([^<]+)</span>', cola)
        self.assertEqual(versiones, ["1.3.0", "1.2.0", "1.1.0"],
                         "la cola va de la más alta a la más baja")
        # La primera está marcada como la que hay que instalar, y solo la primera.
        self.assertEqual(cola.count("la que hay que instalar"), 1)
        primera = cola.split("</li>")[0]
        self.assertIn("1.3.0", primera)
        self.assertIn("resuelve las 3 versiones pedidas", self._plano(primera))
        # Y cada versión dice cuántas vulnerabilidades la pidieron, con su unidad.
        self.assertEqual(self._plano(cola).count("pidió esta versión"), 3)

    def test_dos_paquetes_distintos_no_se_mezclan(self):
        html = self._html(f"/activos/{self.srv}")
        filas = self._filas(html)
        otra = next(f for f in filas if "otra-biblioteca" in f)
        texto = self._plano(otra)
        self.assertIn("Actualizar a 2.5.0", texto)
        self.assertIn("1 vulnerabilidad", texto)
        self.assertNotIn("1.3.0", texto, "la versión de otro paquete no puede aparecer aquí")
        biblioteca = next(f for f in filas if "biblioteca-x" in f)
        self.assertNotIn("2.5.0", self._plano(biblioteca))

    def test_la_ficha_no_ensena_lo_que_no_afecta(self):
        """El ejemplo literal del usuario: «CVE-2023-42366 · Media · No afectado ·
        busybox-initramfs … ya incluye la corrección»."""
        html = self._html(f"/activos/{self.srv}")
        self.assertNotIn("busybox-initramfs", html)
        self.assertNotIn("CVE-2023-42366", html)
        self.assertNotIn("CVE-2026-9999", html, "tampoco los «sin dato»")
        self.assertNotIn("No afectado", html)
        self.assertNotIn("Amenazas evaluadas para este activo", html)
        # Ni las tarjetas ni el reparto de veredictos.
        self.assertNotIn("No le afectan", html)
        self.assertNotIn("Reparto de los", html)

    def test_queda_una_linea_con_la_constancia_de_lo_evaluado(self):
        html = self._html(f"/activos/{self.srv}")
        pie = html.split('id="veredictos-evaluados"')[1].split("</div>")[0]
        texto = self._plano(pie)
        # 5 CVE evaluados: 3 + 1 afectados, 1 no afectado y 1 sin dato.
        self.assertIn("Se evaluaron 6 identificadores CVE en este activo", texto)
        self.assertIn("4 le afectan", texto)
        self.assertIn("1 no le afecta", texto)
        self.assertIn("1 no precisa versiones en el aviso", texto)
        self.assertIn("Exportar veredictos (CSV)", texto)

    def test_la_cifra_grande_y_la_tabla_dicen_el_mismo_numero(self):
        html = self._html(f"/activos/{self.srv}")
        tarjeta = html.split('data-tour-titulo="Indicadores del activo"')[1]
        valor = int(re.search(r'<div class="valor">(\d+)</div>', tarjeta).group(1))
        self.assertEqual(valor, len(self._filas(html)),
                         "la cifra grande y las filas de la tabla son la misma cosa")
        self.assertIn("Actualizaciones pendientes", tarjeta)
        # Y debajo, la trazabilidad con su unidad escrita.
        self.assertIn("cubren 4 vulnerabilidades en 2 paquetes", self._plano(tarjeta))
        self.assertIn("4 filas de remediación", self._plano(tarjeta))

    def test_la_exportacion_en_csv_sigue_trayendo_todos_los_veredictos(self):
        cli = self.app.test_client()
        cli.post("/login", data={"usuario": "jefa@ejemplo.local", "password": CLAVE})
        r = cli.get(f"/activos/{self.srv}/exportar.csv")
        self.assertEqual(r.status_code, 200)
        csv = r.get_data(as_text=True)
        self.assertIn("busybox-initramfs", csv, "el CSV sí trae lo que no afecta")
        self.assertIn("CVE-2023-42366", csv)
        self.assertIn("CVE-2026-9999", csv)

    def test_el_plan_del_activo_da_la_misma_cifra_y_una_sola_orden(self):
        """«que la remediación indique sí o sí la última versión»: el plan también."""
        html = self._html(f"/activos/{self.srv}/remediacion")
        self.assertIn("Actualizaciones por aplicar", html)
        valor = re.findall(r'<div class="valor">(\d+)</div>\s*<div class="etiqueta">'
                           r'Actualizaciones por aplicar</div>', html)
        self.assertEqual(valor, ["2"], "una orden por paquete, no una por versión")
        self.assertIn("actualizar a la versión", html)
        self.assertIn("1.3.0", html)
        self.assertIn("3 versiones solicitadas por los avisos", html)

    def test_el_modulo_fusiona_el_plan_por_la_ultima_version(self):
        with db.session(self.ruta) as conn:
            plan = aplicabilidad.plan_remediacion(conn, activo_id=self.srv)
        grupos = plan["grupos"]
        self.assertEqual(len(grupos), 2)
        biblioteca = next(g for g in grupos if "biblioteca-x" in (g.get("paquetes") or []))
        self.assertEqual(biblioteca["corregida"], "1.3.0")
        self.assertEqual(biblioteca["cola_versiones"], ["1.3.0", "1.2.0", "1.1.0"])
        self.assertEqual(biblioteca["versiones_pedidas"], 3)
        self.assertEqual(len(biblioteca["cves"]), 3)
        # Y fusionar dos veces no cambia nada: la plantilla lo repite tras recortar.
        otra_vez = remediacion.fusionar_plan(grupos)
        self.assertEqual([g["corregida"] for g in otra_vez],
                         [g["corregida"] for g in grupos])
        self.assertEqual([g["cola_versiones"] for g in otra_vez],
                         [g["cola_versiones"] for g in grupos])


# ==========================================================================
# 2. El caso de Windows: muchas versiones destino en una sola actualización
# ==========================================================================
class TestMuchasVersionesEnUnaActualizacion(BaseFicha):
    """`windows` con cientos de vulnerabilidades y varias compilaciones destino: la cola de
    versiones NO se recorta (es la trazabilidad) y sí los CVE de cada versión."""

    #: Compilaciones destino, de la más baja a la más alta, con cuántos CVE piden cada una.
    COMPILACIONES = (("10.0.26200.8246", 30), ("10.0.26200.8390", 30),
                     ("10.0.26200.8655", 30), ("10.0.26200.8875", 30),
                     ("10.0.26200.9106", 30), ("10.0.26200.9445", 30))

    @classmethod
    def setUpClass(cls):
        cls._crear("ficha_windows.db")
        with db.session(cls.ruta) as conn:
            cls.pc = base._activo(conn, "pc-windows-01", familia="windows",
                                  origen="equipos", proceso=None, ip="10.1.1.90")
            conn.execute("UPDATE activos SET windows_build='10.0.26200.7000' WHERE id=?",
                         (cls.pc,))
            n = 0
            for compilacion, cuantas in cls.COMPILACIONES:
                for _ in range(cuantas):
                    n += 1
                    cve = f"CVE-2026-{20000 + n}"
                    t = base._amenaza(conn, cve, severity="High")
                    base._remediacion(conn, cls.pc, t, cve, "windows",
                                      "10.0.26200.7000", compilacion)
        cls.total_cves = sum(c for _, c in cls.COMPILACIONES)

    def test_una_sola_fila_con_todas_las_versiones_de_la_cola(self):
        html = self._html(f"/activos/{self.pc}")
        filas = self._filas(html)
        self.assertEqual(len(filas), 1, "un solo paquete, una sola entrada")
        texto = self._plano(filas[0])
        self.assertIn("Actualizar a 10.0.26200.9445", texto, "la compilación más alta")
        self.assertIn(f"{self.total_cves} vulnerabilidades", texto)
        cola = filas[0].split('class="lista-lineas cola-versiones"')[1]
        versiones = re.findall(r'<li[^>]*>\s*<span class="mono">([^<]+)</span>', cola)
        self.assertEqual(versiones, [c for c, _ in reversed(self.COMPILACIONES)],
                         "la cola conserva TODAS las versiones, de la más alta a la más baja")

    def test_los_cve_de_cada_version_se_acotan_y_se_dice_cuantos_faltan(self):
        html = self._html(f"/activos/{self.pc}")
        cola = self._filas(html)[0].split('class="lista-lineas cola-versiones"')[1]
        texto = self._plano(cola)
        tope = remediacion.LIMITE_CVES_POR_VERSION_FICHA
        self.assertIn(f"se muestran {tope}", texto,
                      "cada versión dice cuántas de sus vulnerabilidades se listan")
        self.assertIn("más que piden esta misma versión", texto)
        self.assertIn("el detalle por vulnerabilidad y paquete", texto,
                      "y dónde están todas")
        # Ninguna versión pinta más CVE de los que dice el tope.
        for bloque in cola.split("<li class=\"cola-objetivo\">")[-1:] + cola.split("</li>"):
            enlaces = len(re.findall(r"Remediación número \d+", bloque))
            self.assertLessEqual(enlaces, tope * len(self.COMPILACIONES))

    def test_la_pagina_no_crece_sin_limite(self):
        """El recorte por versión existe para que la ficha no pese megabytes: sin él, el
        equipo de producción con 1.358 vulnerabilidades en 6 compilaciones daba 737,6 KiB
        de HTML frente a los 159,0 KiB de ahora (medido el 2026-09-09)."""
        html = self._html(f"/activos/{self.pc}")
        pintados = len(re.findall(r"Remediación número \d+",
                                  self._filas(html)[0].split('cola-versiones')[1]))
        self.assertLessEqual(pintados, remediacion.LIMITE_CVES_FICHA)
        self.assertLessEqual(
            pintados,
            remediacion.LIMITE_CVES_POR_VERSION_FICHA * len(self.COMPILACIONES))
        self.assertGreater(pintados, 0, "algo se tiene que ver de cada versión")

    def test_la_cifra_grande_sigue_coincidiendo_con_la_tabla(self):
        html = self._html(f"/activos/{self.pc}")
        tarjeta = html.split('data-tour-titulo="Indicadores del activo"')[1]
        valor = int(re.search(r'<div class="valor">(\d+)</div>', tarjeta).group(1))
        self.assertEqual(valor, 1)
        self.assertEqual(valor, len(self._filas(html)))
        # Con UNA sola actualización el verbo va en singular desde el 2026-09-15: decía
        # «1 actualización que cubren 180 vulnerabilidades» (auditoría de tableros).
        self.assertIn(f"cubre {self.total_cves} vulnerabilidades en 1 paquete",
                      self._plano(tarjeta))
        self.assertNotIn("cubren", self._plano(tarjeta))


# ==========================================================================
# 3. La cola de remediación y la evaluación pueden ir desfasadas: se dice
# ==========================================================================
class TestDesfaseConLaEvaluacion(BaseFicha):
    """La tabla sale de la cola de remediación, que se llena en cada sincronización. Si la
    evaluación confirmó algo que aún no está en la cola, la ficha lo dice en vez de dejar
    creer que no hay nada que hacer."""

    @classmethod
    def setUpClass(cls):
        cls._crear("ficha_desfase.db")
        with db.session(cls.ruta) as conn:
            cls.srv = base._activo(conn, "srv-desfase-01", ip="10.0.0.81")
            base._software(conn, cls.srv, "nginx", "1.20.0")
            t = base._amenaza(conn, "CVE-2026-3001", severity="High")
            # Evaluación sí, cola todavía no.
            _veredicto(conn, cls.srv, t, "CVE-2026-3001", "nginx", "1.20.0", "1.20.2")

    def test_lo_confirmado_que_aun_no_esta_en_la_cola_se_dice(self):
        html = self._html(f"/activos/{self.srv}")
        self.assertIn("todavía no está en la cola de remediación", html)
        self.assertIn("No hay ninguna actualización pendiente en este activo", html)
        # Y en cuanto la sincronización pasa, aparece como una actualización.
        with db.session(self.ruta) as conn:
            remediacion.sincronizar(conn)
        html = self._html(f"/activos/{self.srv}")
        self.assertNotIn("todavía no está en la cola de remediación", html)
        self.assertIn("Actualizar a 1.20.2", self._plano(self._tabla(html)))


if __name__ == "__main__":
    unittest.main()
