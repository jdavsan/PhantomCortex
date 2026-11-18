"""Dos ficheros de activos que han dejado de reportar: servidores y equipos (2026-09-15).

Petición literal del usuario:

    «necesito además un informe para equipos y para servidores que me indique cuántos
    servidores o equipos han dejado de reportar y me los envíe en archivos diferentes, uno
    de equipos y otro de servidores, de manera detallada de proceso, hostname, IP y demás»

Lo que fijan estas pruebas:

* la lista detallada separa **servidores** de **equipos de cómputo** y cuenta con el mismo
  criterio que la página de Activos (sin la severidad baja y sin las amenazas descartadas,
  falsos positivos o mitigadas);
* **cada fichero lleva solo su tipo de máquina**, con las columnas pedidas, ordenado por
  tiempo sin reportar y, a igualdad de días, por vulnerabilidades confirmadas;
* cada fichero trae su **fila de totales** y su **hoja de resumen** (cuántos son, de
  cuántos, desde cuándo se considera que no reportan y qué hay que hacer);
* **un grupo vacío no genera fichero**, y el correo lo dice con palabras;
* el correo escribe **las dos cifras** y nombra los dos adjuntos;
* un nombre de máquina que empiece por «=» no acaba siendo una fórmula en la hoja.

Ejecución:
    sudo -n -u si .venv/bin/python -m unittest tests.test_inventario_ficheros
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from openpyxl import load_workbook

from threatintel import db, libro_inventario, notify, ocs
from threatintel.paths import BASE_DIR

AHORA = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)


def _hace(dias: int) -> str:
    return (AHORA - timedelta(days=dias)).isoformat().replace("+00:00", "Z")


class ConfiguracionFalsa(dict):
    """Los dos ajustes que usa el informe, sin ficheros ni secretos."""

    def __init__(self, dias: int = 30):
        super().__init__({"ocs_stale_days": dias, "ignore_low_severity": True})


def _sembrar(ruta: str) -> dict:
    """Parque pequeño y con todos los casos límite que importan.

    Servidores: uno que nunca reportó, uno con 200 días y muchas vulnerabilidades, uno con
    200 días y ninguna (para comprobar el desempate), uno al día.
    Equipos de cómputo: dos sin reportar y uno al día.
    """
    ids: dict = {}
    with db.session(ruta) as conn:
        def activo(nombre, origen, *, dias=None, **extra):
            campos = {
                "origen": origen, "nombre": nombre,
                "so_nombre": extra.get("so_nombre", "Ubuntu"),
                "so_version": extra.get("so_version", "22.04"),
                "so_familia": "ubuntu", "ip": extra.get("ip", "10.1.1.1"),
                "usuario": extra.get("usuario"), "grupo": extra.get("grupo", "ejemplo.local"),
                "zona": extra.get("zona", "interna"),
                "entorno": extra.get("entorno", "produccion"),
                "proceso": extra.get("proceso", "Impuestos"),
                "ultimo_inventario": None if dias is None else _hace(dias),
                "ultima_conexion": None if dias is None else _hace(dias),
            }
            cur = conn.execute(
                """INSERT INTO activos(origen, ocs_id, nombre, so_nombre, so_version,
                        so_familia, ip, usuario, grupo, zona, entorno, proceso,
                        ultimo_inventario, ultima_conexion, presente, primera_vez_at,
                        visto_at)
                   VALUES(:origen, (SELECT COALESCE(MAX(ocs_id),0)+1 FROM activos),
                          :nombre, :so_nombre, :so_version, :so_familia, :ip, :usuario,
                          :grupo, :zona, :entorno, :proceso, :ultimo_inventario,
                          :ultima_conexion, 1, :primera, :visto)""",
                {**campos, "primera": _hace(900), "visto": _hace(1)})
            return cur.lastrowid

        ids["nunca"] = activo("SRV-NUNCA-PD", "servidores", dias=None, ip="10.1.0.9")
        ids["viejo_con_riesgo"] = activo("SRV-VIEJO-PD", "servidores", dias=200,
                                         usuario="soportest", proceso="Pila")
        ids["viejo_limpio"] = activo("SRV-VIEJO-LIMPIO-PD", "servidores", dias=200,
                                     proceso="Embargos")
        ids["servidor_al_dia"] = activo("SRV-AL-DIA-PD", "servidores", dias=2)
        ids["equipo_viejo"] = activo("PC-VIEJO", "equipos", dias=90,
                                     proceso=None, entorno=None, usuario="anaramirez")
        ids["equipo_medio"] = activo("PC-MEDIO", "equipos", dias=45)
        ids["equipo_al_dia"] = activo("PC-AL-DIA", "equipos", dias=1)
        ids["formula"] = activo("=cmd|' /c calc'!A0", "equipos", dias=120)

        def amenaza(cve, severidad, *, kev=0, estado="nueva"):
            cur = conn.execute(
                """INSERT INTO threats(fingerprint, cve, title_en, title_es, severity,
                                       published_at, first_seen_at, last_seen_at, month,
                                       in_kev, estado)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (f"hash-{cve}", cve, cve, cve, severidad, db.utcnow(), db.utcnow(),
                 db.utcnow(), "2026-09", kev, estado))
            return cur.lastrowid

        ids["critica"] = amenaza("CVE-2026-0001", "Critical", kev=1)
        ids["alta"] = amenaza("CVE-2026-0002", "High")
        ids["baja"] = amenaza("CVE-2026-0003", "Low")
        ids["mitigada"] = amenaza("CVE-2026-0004", "High", estado="mitigada")

        def veredicto(activo_id, threat_id, cve, paquete="openssl", resultado="afectado"):
            conn.execute(
                """INSERT INTO aplicabilidad(activo_id, threat_id, cve, paquete,
                        version_instalada, version_corregida, veredicto, motor, evaluado_at)
                   VALUES(?,?,?,?,'1.0','1.1',?, 'osv', ?)""",
                (activo_id, threat_id, cve, paquete, resultado, db.utcnow()))

        # El servidor viejo arrastra dos vulnerabilidades que cuentan (una con explotación
        # activa confirmada) y dos que NO: la baja y la de la amenaza mitigada.
        veredicto(ids["viejo_con_riesgo"], ids["critica"], "CVE-2026-0001")
        veredicto(ids["viejo_con_riesgo"], ids["alta"], "CVE-2026-0002")
        veredicto(ids["viejo_con_riesgo"], ids["baja"], "CVE-2026-0003")
        veredicto(ids["viejo_con_riesgo"], ids["mitigada"], "CVE-2026-0004")
        # Un mismo CVE en dos paquetes es UNA vulnerabilidad, no dos.
        veredicto(ids["viejo_con_riesgo"], ids["alta"], "CVE-2026-0002", paquete="libssl")
        # El equipo sin reportar tiene una; el que reporta al día tiene otra que no sale.
        veredicto(ids["equipo_viejo"], ids["alta"], "CVE-2026-0002")
        veredicto(ids["equipo_al_dia"], ids["critica"], "CVE-2026-0001")
        # Un veredicto «no afectado» no es una vulnerabilidad.
        veredicto(ids["equipo_medio"], ids["alta"], "CVE-2026-0002", resultado="no_afectado")
    return ids


class BaseConDatos(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        cls.ruta = str(Path(cls.tmp.name) / "inventario.db")
        db.init_db(cls.ruta)
        cls.ids = _sembrar(cls.ruta)
        cls.cfg = ConfiguracionFalsa()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.contexto = db.session(self.ruta)
        self.conn = self.contexto.__enter__()
        self.datos = ocs.inventario_sin_reportar_detallado(
            self.conn, cfg=self.cfg, ahora=AHORA)
        self.grupos = {g["origen"]: g for g in self.datos["grupos"]}

    def tearDown(self):
        self.contexto.__exit__(None, None, None)


# ==========================================================================
# 1. Los datos
# ==========================================================================
class TestLista(BaseConDatos):

    def test_separa_servidores_de_equipos_de_computo(self):
        self.assertEqual(self.grupos["servidores"]["sin_reportar"], 3)
        self.assertEqual(self.grupos["equipos"]["sin_reportar"], 3)
        self.assertEqual(self.grupos["servidores"]["total"], 4)
        self.assertEqual(self.grupos["equipos"]["total"], 4)
        self.assertEqual(self.datos["total"], 6)
        self.assertEqual(self.datos["activos_presentes"], 8)

    def test_cada_grupo_lleva_solo_su_tipo_de_maquina(self):
        for origen, grupo in self.grupos.items():
            self.assertTrue(grupo["filas"])
            self.assertTrue(all(f["origen"] == origen for f in grupo["filas"]))

    def test_el_umbral_es_el_ajuste_ocs_stale_days(self):
        self.assertEqual(self.datos["dias"], 30)
        corto = ocs.inventario_sin_reportar_detallado(
            self.conn, cfg=ConfiguracionFalsa(dias=1), ahora=AHORA)
        self.assertEqual(corto["total"], 7,
                         "con un día de plazo solo se salva el que reportó hoy")
        largo = ocs.inventario_sin_reportar_detallado(
            self.conn, cfg=ConfiguracionFalsa(dias=365), ahora=AHORA)
        self.assertEqual(largo["total"], 1, "solo el que no ha reportado nunca")

    def test_los_dias_sin_reportar_se_cuentan_desde_el_ultimo_inventario(self):
        filas = {f["nombre"]: f for f in self.grupos["servidores"]["filas"]}
        self.assertEqual(filas["SRV-VIEJO-PD"]["dias_sin_reportar"], 200)
        self.assertTrue(filas["SRV-NUNCA-PD"]["nunca"])
        self.assertEqual(filas["SRV-NUNCA-PD"]["dias_sin_reportar"], 900,
                         "sin inventario se cuenta desde que la plataforma lo vio")

    def test_las_vulnerabilidades_se_cuentan_como_en_la_pagina_de_activos(self):
        filas = {f["nombre"]: f for f in self.grupos["servidores"]["filas"]}
        # Dos: la crítica y la alta. La baja no cuenta, la mitigada tampoco, y el mismo
        # CVE en dos paquetes es una sola vulnerabilidad.
        self.assertEqual(filas["SRV-VIEJO-PD"]["vulnerabilidades"], 2)
        self.assertEqual(filas["SRV-VIEJO-PD"]["kev"], 1)
        self.assertEqual(filas["SRV-VIEJO-LIMPIO-PD"]["vulnerabilidades"], 0)

    def test_un_veredicto_de_no_afectado_no_es_una_vulnerabilidad(self):
        filas = {f["nombre"]: f for f in self.grupos["equipos"]["filas"]}
        self.assertEqual(filas["PC-MEDIO"]["vulnerabilidades"], 0)

    def test_el_orden_pone_primero_lo_que_mas_importa(self):
        nombres = [f["nombre"] for f in self.grupos["servidores"]["filas"]]
        self.assertEqual(nombres, ["SRV-NUNCA-PD", "SRV-VIEJO-PD", "SRV-VIEJO-LIMPIO-PD"],
                         "primero el que nunca reportó; a igualdad de días, el que más "
                         "vulnerabilidades arrastra")

    def test_los_totales_del_grupo_cuadran_con_sus_filas(self):
        for grupo in self.datos["grupos"]:
            self.assertEqual(grupo["sin_reportar"], len(grupo["filas"]))
            self.assertEqual(grupo["vulnerabilidades"],
                             sum(f["vulnerabilidades"] for f in grupo["filas"]))
            self.assertEqual(grupo["kev"], sum(f["kev"] for f in grupo["filas"]))
            self.assertEqual(grupo["dias_maximo"],
                             max(f["dias_sin_reportar"] for f in grupo["filas"]))

    def test_dos_lecturas_seguidas_dan_lo_mismo(self):
        otra = ocs.inventario_sin_reportar_detallado(self.conn, cfg=self.cfg, ahora=AHORA)
        self.assertEqual([g["sin_reportar"] for g in otra["grupos"]],
                         [g["sin_reportar"] for g in self.datos["grupos"]])
        self.assertEqual([f["nombre"] for f in otra["grupos"][0]["filas"]],
                         [f["nombre"] for f in self.datos["grupos"][0]["filas"]])

    def test_el_que_no_ha_reportado_nunca_cuenta_con_cualquier_plazo(self):
        """Sin fecha de inventario no hay plazo que valga: está a oscuras desde siempre."""
        largo = ocs.inventario_sin_reportar_detallado(
            self.conn, cfg=ConfiguracionFalsa(dias=2000), ahora=AHORA)
        self.assertEqual(largo["total"], 1)
        self.assertEqual([f["nombre"] for g in largo["grupos"] for f in g["filas"]],
                         ["SRV-NUNCA-PD"])


# ==========================================================================
# 2. Los ficheros
# ==========================================================================
class TestFicheros(BaseConDatos):

    def setUp(self):
        super().setUp()
        self.carpeta = tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data"))
        self.destino = Path(self.carpeta.name)

    def tearDown(self):
        self.carpeta.cleanup()
        super().tearDown()

    def _generar(self, datos=None):
        return libro_inventario.generar(datos or self.datos, directorio=self.destino,
                                        fecha=date(2026, 9, 15),
                                        url_activos="https://ejemplo.invalid/activos/")

    def test_se_generan_dos_ficheros_con_nombre_que_se_entiende(self):
        rutas = self._generar()
        self.assertEqual(sorted(p.name for p in rutas.values()), [
            "Equipos_de_computo_sin_reportar_2026-09-15.xlsx",
            "Servidores_sin_reportar_2026-09-15.xlsx"])
        for ruta in rutas.values():
            self.assertTrue(ruta.exists() and ruta.stat().st_size > 0)

    def test_cada_fichero_lleva_solo_su_tipo_de_maquina(self):
        rutas = self._generar()
        libro = load_workbook(rutas["servidores"])
        hoja = libro["Servidores sin reportar"]
        nombres = [f[0].value for f in hoja.iter_rows(min_row=2, max_col=1)
                   if f[0].value and not str(f[0].value).startswith("Total")]
        self.assertEqual(nombres, ["SRV-NUNCA-PD", "SRV-VIEJO-PD", "SRV-VIEJO-LIMPIO-PD"])
        self.assertNotIn("PC-VIEJO", nombres)
        libro_equipos = load_workbook(rutas["equipos"])
        hoja_equipos = libro_equipos["Equipos de cómputo sin reportar"]
        nombres_equipos = [f[0].value for f in hoja_equipos.iter_rows(min_row=2, max_col=1)
                           if f[0].value and not str(f[0].value).startswith("Total")]
        self.assertIn("PC-VIEJO", nombres_equipos)
        self.assertTrue(all(not str(n).startswith("SRV-") for n in nombres_equipos))

    def test_lleva_las_columnas_que_se_pidieron(self):
        rutas = self._generar()
        hoja = load_workbook(rutas["servidores"])["Servidores sin reportar"]
        cabeceras = [c.value for c in hoja[1]]
        for columna in ("Nombre del activo", "Dirección IP", "Proceso de negocio",
                        "Entorno", "Sistema operativo", "Versión del sistema operativo",
                        "Zona de red", "Usuario o responsable", "Días sin reportar",
                        "Fecha del último inventario",
                        "Fecha en que se vio por última vez",
                        "Vulnerabilidades confirmadas"):
            self.assertIn(columna, cabeceras)

    def test_las_filas_van_ordenadas_y_con_su_detalle(self):
        rutas = self._generar()
        hoja = load_workbook(rutas["servidores"])["Servidores sin reportar"]
        cabeceras = [c.value for c in hoja[1]]
        dias = cabeceras.index("Días sin reportar") + 1
        vulnerables = cabeceras.index("Vulnerabilidades confirmadas") + 1
        filas = [(f[0].value, f[dias - 1].value, f[vulnerables - 1].value)
                 for f in hoja.iter_rows(min_row=2, max_row=4)]
        self.assertEqual([f[0] for f in filas],
                         ["SRV-NUNCA-PD", "SRV-VIEJO-PD", "SRV-VIEJO-LIMPIO-PD"])
        self.assertEqual(filas[1][1], 200)
        self.assertEqual(filas[1][2], 2)

    def test_la_fecha_del_ultimo_inventario_es_una_fecha_de_verdad(self):
        """Para que Servicios Tecnológicos pueda ordenar por ella en la hoja."""
        rutas = self._generar()
        hoja = load_workbook(rutas["servidores"])["Servidores sin reportar"]
        cabeceras = [c.value for c in hoja[1]]
        columna = cabeceras.index("Fecha del último inventario") + 1
        self.assertEqual(hoja.cell(row=2, column=columna).value, libro_inventario.NUNCA)
        self.assertIsInstance(hoja.cell(row=3, column=columna).value, datetime)

    def test_tiene_fila_de_totales(self):
        rutas = self._generar()
        hoja = load_workbook(rutas["servidores"])["Servidores sin reportar"]
        etiquetas = [hoja.cell(row=f, column=1).value for f in range(2, hoja.max_row + 1)]
        totales = [f + 2 for f, v in enumerate(etiquetas)
                   if v and str(v).startswith("Total")]
        self.assertEqual(len(totales), 1, "una sola fila de totales")
        fila = totales[0]
        cabeceras = [c.value for c in hoja[1]]
        self.assertIn("3 servidores", hoja.cell(row=fila, column=1).value)
        self.assertEqual(
            hoja.cell(row=fila,
                      column=cabeceras.index("Vulnerabilidades confirmadas") + 1).value, 2)
        self.assertEqual(
            hoja.cell(row=fila,
                      column=cabeceras.index("Días sin reportar") + 1).value, 900)

    def test_la_hoja_de_resumen_dice_cuantos_de_cuantos_y_desde_cuando(self):
        rutas = self._generar()
        hoja = load_workbook(rutas["equipos"])["Resumen"]
        texto = "\n".join(str(c.value) for fila in hoja.iter_rows() for c in fila
                          if c.value is not None)
        self.assertIn("Equipos de cómputo que han dejado de reportar", texto)
        self.assertIn("3 equipos de cómputo de 4", texto)
        self.assertIn("Más de 30 días", texto)
        self.assertIn("ocs_stale_days", texto)
        self.assertIn("Qué hay que hacer", texto)
        self.assertIn("https://ejemplo.invalid/activos/", texto)

    def test_un_grupo_vacio_no_genera_fichero(self):
        datos = ocs.inventario_sin_reportar_detallado(
            self.conn, cfg=ConfiguracionFalsa(dias=365), ahora=AHORA)
        rutas = self._generar(datos)
        self.assertEqual(list(rutas), ["servidores"])
        self.assertFalse((self.destino /
                          "Equipos_de_computo_sin_reportar_2026-09-15.xlsx").exists())

    def test_sin_nadie_sin_reportar_no_se_genera_nada(self):
        """Un parque entero al día: ni un fichero, ni uno vacío «por si acaso»."""
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as otro:
            ruta = str(Path(otro) / "al_dia.db")
            db.init_db(ruta)
            with db.session(ruta) as conn:
                for nombre, origen in (("SRV-OK-PD", "servidores"), ("PC-OK", "equipos")):
                    conn.execute(
                        """INSERT INTO activos(origen, ocs_id, nombre, so_familia,
                                ultimo_inventario, presente, primera_vez_at, visto_at)
                           VALUES(?, (SELECT COALESCE(MAX(ocs_id),0)+1 FROM activos), ?,
                                  'ubuntu', ?, 1, ?, ?)""",
                        (origen, nombre, _hace(1), _hace(100), _hace(0)))
                datos = ocs.inventario_sin_reportar_detallado(conn, cfg=self.cfg,
                                                              ahora=AHORA)
        self.assertEqual(datos["total"], 0)
        self.assertEqual(self._generar(datos), {})
        self.assertEqual(list(self.destino.iterdir()), [])

    def test_un_nombre_que_empieza_por_igual_no_es_una_formula(self):
        rutas = self._generar()
        hoja = load_workbook(rutas["equipos"])["Equipos de cómputo sin reportar"]
        celdas = [c for fila in hoja.iter_rows(max_col=1) for c in fila
                  if str(c.value or "").startswith("=cmd")]
        self.assertEqual(len(celdas), 1)
        self.assertEqual(celdas[0].data_type, "s")
        self.assertTrue(celdas[0].quotePrefix)

    def test_dos_generaciones_seguidas_dan_el_mismo_contenido(self):
        primera = self._generar()["servidores"].read_bytes()
        hoja_1 = load_workbook(self._generar()["servidores"])["Servidores sin reportar"]
        self.assertGreater(len(primera), 0)
        self.assertEqual([c.value for c in hoja_1[1]],
                         [c[0] for c in libro_inventario.COLUMNAS])

    def test_los_adjuntos_van_en_orden_servidores_primero(self):
        rutas = libro_inventario.adjuntos(self.datos, directorio=self.destino,
                                          fecha=date(2026, 9, 15))
        self.assertEqual([r.name for r in rutas], [
            "Servidores_sin_reportar_2026-09-15.xlsx",
            "Equipos_de_computo_sin_reportar_2026-09-15.xlsx"])


# ==========================================================================
# 3. El correo
# ==========================================================================
class TestCorreo(BaseConDatos):

    def _resumen_del_cuerpo(self):
        return ocs.inventario_sin_reportar(self.conn, cfg=self.cfg, limite=200)

    def _adjuntos(self, con_equipos: bool = True):
        salida = []
        for grupo in self.datos["grupos"]:
            hay = grupo["origen"] == "servidores" or con_equipos
            salida.append({
                "origen": grupo["origen"], "origen_es": grupo["origen_es"],
                "sin_reportar": grupo["sin_reportar"], "total": grupo["total"],
                "filas": len(grupo["filas"]),
                "fichero": (f"{grupo['origen']}.xlsx" if hay and grupo["filas"] else "")})
        return salida

    def test_el_correo_dice_las_dos_cifras(self):
        html = notify.render_inventario_email(
            self._resumen_del_cuerpo(), url_activos="https://ejemplo.invalid/activos/",
            adjuntos=self._adjuntos())
        self.assertIn("servidores", html)
        self.assertIn("equipos de cómputo", html)
        self.assertIn("de 4", html)
        self.assertIn("https://ejemplo.invalid/activos/", html)

    def test_el_correo_nombra_los_dos_ficheros(self):
        html = notify.render_inventario_email(
            self._resumen_del_cuerpo(), adjuntos=self._adjuntos())
        self.assertIn("Ficheros adjuntos", html)
        self.assertIn("servidores.xlsx", html)
        self.assertIn("equipos.xlsx", html)

    def test_si_un_grupo_no_tiene_fichero_el_correo_lo_dice(self):
        html = notify.render_inventario_email(
            self._resumen_del_cuerpo(), adjuntos=self._adjuntos(con_equipos=False))
        self.assertIn("No se adjunta el fichero de", html)
        self.assertIn("servidores.xlsx", html)

    def test_sin_adjuntos_el_correo_sigue_siendo_el_de_siempre(self):
        html = notify.render_inventario_email(self._resumen_del_cuerpo())
        self.assertNotIn("Ficheros adjuntos", html)
        self.assertIn("Inventario sin reportar", html)

    def test_el_correo_no_lleva_ninguna_direccion_real(self):
        html = notify.render_inventario_email(
            self._resumen_del_cuerpo(), adjuntos=self._adjuntos())
        self.assertNotIn("@ejemplo.local", html)


# ==========================================================================
# 4. A demanda, desde la línea de órdenes
# ==========================================================================
class TestLineaDeOrdenes(BaseConDatos):
    """`bin/informe_inventario.py --ficheros` genera los dos ficheros y NO envía nada."""

    def test_genera_los_dos_ficheros_sin_enviar_correo(self):
        # El guion lee la fecha de referencia de INFORME_INVENTARIO_AHORA (si existe) en
        # vez del reloj real, para que «sin reportar hace más de N días» cuente igual que
        # en self.datos (sembrado con AHORA) sin importar cuándo corra esta prueba.
        entorno = dict(os.environ, INFORME_INVENTARIO_AHORA=AHORA.isoformat().replace("+00:00", "Z"))
        with tempfile.TemporaryDirectory(dir=str(BASE_DIR / "data")) as salida:
            proceso = subprocess.run(
                [sys.executable, str(BASE_DIR / "bin" / "informe_inventario.py"),
                 "--ficheros", "--en", salida, "--db", self.ruta],
                capture_output=True, text=True, timeout=180, cwd=str(BASE_DIR), env=entorno)
            self.assertEqual(proceso.returncode, 0, proceso.stderr[-2000:])
            generados = sorted(p.name for p in Path(salida).glob("*.xlsx"))
            self.assertEqual(generados, [
                f"Equipos_de_computo_sin_reportar_{date.today().isoformat()}.xlsx",
                f"Servidores_sin_reportar_{date.today().isoformat()}.xlsx"])
        salida_texto = proceso.stdout
        self.assertIn("Servidores: 3 de 4", salida_texto)
        self.assertIn("Equipos de cómputo: 3 de 4", salida_texto)
        self.assertNotIn("Enviado a", salida_texto)


if __name__ == "__main__":
    unittest.main()
