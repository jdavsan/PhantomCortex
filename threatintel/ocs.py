"""Inventario real de activos desde OCS Inventory (solo lectura).

Dos bases de OCS (MariaDB): la de servidores y la de equipos de computo. Las
credenciales viven en ``config/credentials.env`` (``OCS_SERVIDORES_*`` y
``OCS_EQUIPOS_*``); aqui solo se ejecutan SELECT.

Que hace la sincronizacion (``sincronizar``):

1. Lee ``hardware`` (equipos) y ``software`` (programas instalados, esquema
   normalizado de OCS 2.4+) y los vuelca en las tablas ``activos`` y
   ``activo_software`` de SQLite. Un hash por activo detecta cambios (software
   nuevo, version distinta) sin reescribir lo que no cambio.
2. Normaliza el sistema operativo: familia (ubuntu, debian, freebsd, windows...),
   ciclo de vida para endoflife.date («22.04», «12», «14.4», «11-25h2») y
   ecosistema de OSV.dev («Ubuntu:22.04», «Debian:12»).
3. Aplica el mapa de nombres OCS -> tecnologia del inventario (``tecnologia_ocs``):
   «Google Chrome» -> chrome, ``apache2`` -> apache-httpd... Lo no mapeado queda
   visible como «software sin clasificar».
4. Recalcula, en cada tecnologia, cuantos activos la tienen y que versiones
   (``technologies.activos_ocs`` / ``versiones_ocs``), y opcionalmente rellena
   ``systems_count`` y ``version_installed`` (la version mas antigua instalada,
   que es el peor caso).
5. Detecta hallazgos de politica sin CVE: activos que no reportan, software de
   riesgo (TightVNC, DWAgent, Java 7...) y equipos de computo sin agente de
   proteccion. El fin de soporte lo evalua ``aplicabilidad`` con endoflife.date.

Las funciones reciben un «lector» con ``hardware()`` y ``software()`` para que
las pruebas usen datos simulados sin MariaDB.

2026-11-15: la plataforma dejo de depender solo de OCS Inventory. ``conectar()`` y
``LectorOCS`` viven ahora en ``threatintel/inventario/ocs_mysql.py`` (este modulo los
reexporta para no romper a quien ya hacia ``ocs.conectar``/``ocs.LectorOCS``), y
``ORIGENES`` se calcula en cada acceso a partir de
``threatintel.inventario.registro.fuentes_configuradas()`` (lo que declare
``config/inventarios.yml``, o las dos fuentes de OCS de siempre si ese fichero no
existe) en vez de ser un diccionario fijo. El resto de este modulo -- el mapa de
nombres, los hallazgos de politica, el resumen del inventario... -- sigue igual:
todo eso ya era independiente de MariaDB.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
import time
import unicodedata
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator, Optional

from . import db, excepciones
from .inventario import csv_generico, registro
from .inventario.ocs_mysql import LectorOCS, conectar  # noqa: F401 - reexportado (ver nota 2026-11-15)
from .logging_setup import get_logger
from .queries import sql_vulnerabilidades

log = get_logger("ocs")


class _OrigenesConfigurados(Mapping):
    """Sustituye al antiguo ``ORIGENES = {"servidores": "OCS_SERVIDORES", "equipos":
    "OCS_EQUIPOS"}``: se comporta exactamente como ese mismo diccionario (``in``,
    ``len``, ``.items()``, indexacion, iteracion...) pero las claves y los valores se
    leen, en CADA acceso, de ``threatintel.inventario.registro.fuentes_configuradas()``
    -- lo que declare ``config/inventarios.yml``, o las dos fuentes de OCS de siempre
    si ese fichero no existe. Asi, todo el codigo que ya hacia ``ocs.ORIGENES`` --la
    pagina de Sincronizaciones, el filtro de origen de Activos,
    ``bin/sincronizar_ocs.py --origen``, las funciones de este modulo que iteran
    ``ORIGENES``-- se vuelve multi-fuente sin que haya que tocarlo.

    El valor de cada clave es el prefijo de credenciales (``OCS_SERVIDORES``...) para
    las fuentes de tipo ``ocs_mysql``, que es lo unico que el diccionario fijo de antes
    guardaba ahi; las fuentes de otro tipo (``csv``) no tienen prefijo y su valor es
    ``None``.
    """

    def _fuentes(self) -> dict[str, Optional[str]]:
        return {f.nombre: f.prefijo_credenciales for f in registro.fuentes_configuradas()}

    def __getitem__(self, clave: str) -> Optional[str]:
        return self._fuentes()[clave]

    def __iter__(self):
        return iter(self._fuentes())

    def __len__(self) -> int:
        return len(self._fuentes())

    def __repr__(self) -> str:
        return repr(self._fuentes())


#: Nombre de cada fuente de inventario configurada -> su prefijo de credenciales
#: (``None`` si no es de tipo ``ocs_mysql``). Ver ``_OrigenesConfigurados`` arriba.
ORIGENES: Mapping[str, Optional[str]] = _OrigenesConfigurados()
ORIGEN_ES = {"servidores": "Servidor", "equipos": "Equipo de cómputo"}
# Nombre visible de cada tipo de maquina. Unica fuente de verdad del parque: desde el
# 2026-09-08 tiene que coincidir con queries.ORIGEN_AMENAZAS_ES (hay prueba que lo
# exige) porque el usuario veia tres nombres para lo mismo: «equipos de usuario» en
# Activos, «equipos de cómputo» en Amenazas y «equipos» a secas en el Panel.
ORIGEN_PLURAL_ES = {"servidores": "Servidores", "equipos": "Equipos de cómputo"}
FAMILIAS = ("ubuntu", "debian", "freebsd", "windows", "centos", "otro", "desconocido")
FAMILIA_ES = {"ubuntu": "Ubuntu", "debian": "Debian", "freebsd": "FreeBSD", "windows": "Windows",
              "centos": "CentOS", "otro": "Otro sistema", "desconocido": "Sin datos de sistema"}
ZONAS = ("internet", "dmz", "interna")
ZONA_ES = {"internet": "Internet", "dmz": "Perimetral (DMZ)", "interna": "Red interna"}
MODOS_MAPA = ("exacto", "prefijo", "regex")
MODO_MAPA_ES = {"exacto": "Nombre exacto", "prefijo": "Empieza por", "regex": "Expresión regular"}
TIPOS_HALLAZGO = ("fin_soporte", "software_riesgo", "sin_reportar", "sin_edr")
TIPO_HALLAZGO_ES = {
    "fin_soporte": "Sistema fuera de soporte",
    "software_riesgo": "Software de riesgo",
    "sin_reportar": "Sin reportar al inventario",
    "sin_edr": "Sin antivirus Sophos",
    # v14 (2026-09-10): el inventario no trae lo que hace falta para evaluar los parches
    # de Windows de esa maquina. Es la CAUSA de las remediaciones «esperando datos del
    # inventario» y por eso se ensena en la ficha y en la lista de activos: se arregla el
    # agente de OCS y no el sintoma.
    # 2026-09-15 (revision de claridad, punto 6): el rotulo decia «Sin datos suficientes
    # de Windows» y la pagina de Remediacion decia «794 vulnerabilidades ... en 1 activo»
    # sobre el mismo asunto; se leian como dos cifras de lo mismo cuando cuentan cosas
    # distintas (activos con el agente incompleto frente a filas de remediacion en
    # espera). Cada una dice ahora que cuenta.
    "sin_datos_windows": "Sin datos de actualizaciones de Windows",
}
#: Que significa cada hallazgo, para que cualquier lector lo entienda sin contexto.
TIPO_HALLAZGO_EXPLICACION = {
    "fin_soporte": ("El sistema operativo ya no recibe actualizaciones de seguridad de su fabricante: "
                    "cualquier vulnerabilidad nueva quedará sin corregir. Hay que migrarlo o aislarlo."),
    "software_riesgo": ("Hay instalado un programa que la política considera peligroso en un puesto de "
                        "trabajo: acceso remoto no gestionado por TI, Java sin soporte o intercambio de "
                        "ficheros. El detalle indica cuál, su versión y por qué es un riesgo."),
    "sin_reportar": ("El agente de OCS Inventory no ha enviado el inventario en el plazo configurado: no se "
                     "sabe qué tiene instalado hoy ni si sigue encendido. Revisar el agente o dar de baja el equipo."),
    "sin_edr": ("No aparece el antivirus corporativo Sophos entre los programas instalados: el equipo está "
                "sin protección frente a programas maliciosos, o el agente de Sophos está roto o desinstalado."),
    "sin_datos_windows": ("OCS Inventory no informa de ninguna actualización acumulativa de Windows "
                          "reconocida en esta máquina, así que no se puede calcular su compilación y la "
                          "plataforma NO PUEDE afirmar ni negar que le falten parches de seguridad. Sus "
                          "remediaciones de Windows quedan «esperando datos del inventario»: ni cerradas "
                          "ni en la cola de trabajo. Hay que revisar el agente de OCS Inventory de la "
                          "máquina (que informe el historial de actualizaciones instaladas) y comprobar "
                          "que el sistema declarado coincide con el real."),
}
#: Por que cada software de riesgo lo es (prefijo del nombre normalizado -> motivo).
MOTIVO_RIESGO = {
    "tightvnc": "acceso remoto VNC sin cifrado y con contraseñas débiles; es una vía habitual de intrusión",
    "ultravnc": "acceso remoto VNC sin cifrado y con contraseñas débiles; es una vía habitual de intrusión",
    "realvnc": "acceso remoto VNC; si no lo gestiona TI, abre el equipo a terceros",
    "dwagent": "herramienta de acceso remoto desde Internet no gestionada por TI: permite el control total del equipo",
    "teamviewer": "acceso remoto desde Internet no gestionado por TI",
    "anydesk": "acceso remoto desde Internet no gestionado por TI",
    "ammyy": "acceso remoto desde Internet no gestionado por TI, usado con frecuencia en fraudes",
    "java 7": "Java 7 sin soporte desde 2015: vulnerabilidades conocidas sin corrección",
    "java(tm) 7": "Java 7 sin soporte desde 2015: vulnerabilidades conocidas sin corrección",
    "java 6": "Java 6 sin soporte desde 2013: vulnerabilidades conocidas sin corrección",
    "utorrent": "intercambio de ficheros entre pares: fuga de información y descarga de programas maliciosos",
    "bittorrent": "intercambio de ficheros entre pares: fuga de información y descarga de programas maliciosos",
}

#: Entorno del activo. En servidores viene de OCS (campo «Produccion», «Contingencia»…)
#: y, si falta, del sufijo del nombre: -PD, -CT, -DS, -PU, -SP.
ENTORNOS = ("produccion", "contingencia", "desarrollo", "pruebas", "soporte")
ENTORNO_ES = {"produccion": "Producción", "contingencia": "Contingencia", "desarrollo": "Desarrollo",
              "pruebas": "Pruebas de usuario", "soporte": "Soporte y pruebas"}
#: Lo que la organizacion considera expuesto: produccion y contingencia.
ENTORNOS_EXPUESTOS = ("produccion", "contingencia")
#: Los mismos entornos escritos como lista SQL, para las consultas que no pueden pasar
#: parametros (subconsultas de un f-string). Sale de la constante de arriba: nadie los
#: vuelve a escribir a mano.
_EXPUESTOS_SQL = "(" + ",".join("'" + e + "'" for e in ENTORNOS_EXPUESTOS) + ")"
SUFIJO_ENTORNO = {"PD": "produccion", "CT": "contingencia", "DS": "desarrollo", "PU": "pruebas", "SP": "soporte"}
_RE_SUFIJO_ENTORNO = re.compile(r"[-_](PD|CT|DS|PU|SP)$", re.IGNORECASE)
_TAGS_VACIOS = frozenset({"", "na", "n/a", "none", "null", "-", "sin asignar"})

#: Compilaciones de Windows -> ciclo base de endoflife.date (producto «windows»).
CICLOS_WINDOWS = {
    "10.0.28000": "11-26h1", "10.0.26200": "11-25h2", "10.0.26100": "11-24h2",
    "10.0.22631": "11-23h2", "10.0.22621": "11-22h2", "10.0.22000": "11-21h2",
    "10.0.19045": "10-22h2", "10.0.19044": "10-21h2", "10.0.19043": "10-21h1",
    "10.0.19042": "10-20h2", "10.0.19041": "10-2004", "10.0.18363": "10-1909",
    "10.0.18362": "10-1903", "10.0.17763": "10-1809", "10.0.17134": "10-1803",
    "10.0.16299": "10-1709", "10.0.15063": "10-1703", "10.0.14393": "10-1607",
    "10.0.10586": "10-1511", "10.0.10240": "10-1507",
    "6.3.9600": "8.1", "6.2.9200": "8", "6.1.7601": "7-sp1", "6.1.7600": "7",
}
#: Compilaciones de Windows Server -> ciclo de endoflife.date (producto «windows-server»).
CICLOS_WINDOWS_SERVER = {
    "10.0.26100": "2025", "10.0.20348": "2022", "10.0.17763": "2019",
    "10.0.14393": "2016", "6.3.9600": "2012-R2", "6.2.9200": "2012", "6.1.7601": "2008-R2",
}

#: Software que la politica considera de riesgo en un puesto (prefijo del nombre
#: normalizado). Se puede ampliar desde Ajustes (``ocs_risk_software``).
SOFTWARE_RIESGO_BASE = ["tightvnc", "dwagent", "java 7", "java(tm) 7", "java 6", "teamviewer",
                        "anydesk", "ammyy", "ultravnc", "realvnc", "utorrent", "bittorrent"]

#: Reglas iniciales del mapa nombre OCS -> slug de tecnologia. Solo se siembran
#: las que apuntan a una tecnologia existente en el inventario.
MAPA_BASE: list[tuple[str, str, str, Optional[str]]] = [
    # (patron, modo, slug, paquete_fuente)
    ("google chrome", "exacto", "chrome", None),
    ("google-chrome-stable", "exacto", "chrome", None),
    ("google chrome", "prefijo", "chrome", None),
    ("mozilla firefox", "prefijo", "firefox", None),
    ("firefox", "exacto", "firefox", None),
    ("firefox-esr", "exacto", "firefox", None),
    ("microsoft edge", "exacto", "edge", None),
    ("brave", "prefijo", "brave", None),
    ("mozilla thunderbird", "prefijo", "thunderbird", None),
    ("thunderbird", "exacto", "thunderbird", None),
    ("7-zip", "prefijo", "7-zip", None),
    ("p7zip", "prefijo", "7-zip", None),
    ("7zip", "prefijo", "7-zip", None),
    ("winrar", "prefijo", "winrar", None),
    ("notepad++", "prefijo", "notepad-plus-plus", None),
    ("textpad", "prefijo", "textpad", None),
    ("adobe acrobat", "prefijo", "adobe-acrobat", None),
    ("adobe reader", "prefijo", "adobe-acrobat", None),
    ("java(tm)", "prefijo", "java", None),
    ("java se", "prefijo", "java", None),
    ("java auto updater", "exacto", "java", None),
    ("java 8", "prefijo", "java", None),
    ("java 7", "prefijo", "java", None),
    ("java 11", "prefijo", "java", None),
    ("java 17", "prefijo", "java", None),
    ("java 21", "prefijo", "java", None),
    ("openjdk-", "prefijo", "java", None),
    ("openjdk8", "prefijo", "java", None),
    ("openjdk11", "prefijo", "java", None),
    ("openjdk17", "prefijo", "java", None),
    ("openjdk21", "prefijo", "java", None),
    ("default-jre", "prefijo", "java", None),
    ("default-jdk", "prefijo", "java", None),
    ("oracle-java", "prefijo", "java", None),
    ("temurin", "prefijo", "java", None),
    ("libreoffice", "prefijo", "libreoffice", None),
    ("keepass", "prefijo", "keepass", None),
    ("git", "exacto", "git", None),
    ("git version", "prefijo", "git", None),
    ("git-man", "exacto", "git", None),
    ("sophos", "prefijo", "sophos", None),
    ("manictime", "prefijo", "manictime", None),
    ("owncloud", "prefijo", "owncloud", None),
    ("pdf24", "prefijo", "pdf24", None),
    ("subversion", "prefijo", "subversion", None),
    ("apache2", "exacto", "apache-httpd", "apache2"),
    ("apache2-bin", "exacto", "apache-httpd", "apache2"),
    ("apache24", "exacto", "apache-httpd", None),
    ("httpd", "exacto", "apache-httpd", None),
    ("nginx", "exacto", "nginx", "nginx"),
    ("nginx-core", "exacto", "nginx", "nginx"),
    ("nginx-full", "exacto", "nginx", "nginx"),
    ("nginx-light", "exacto", "nginx", "nginx"),
    ("openssl", "exacto", "openssl", "openssl"),
    ("libssl3", "exacto", "openssl", "openssl"),
    ("libssl3t64", "exacto", "openssl", "openssl"),
    ("libssl1.1", "exacto", "openssl", "openssl"),
    ("openssh-server", "exacto", "openssh", "openssh"),
    ("openssh-client", "exacto", "openssh", "openssh"),
    ("openssh-sftp-server", "exacto", "openssh", "openssh"),
    ("openssh-portable", "exacto", "openssh", None),
    ("php", "exacto", "php", None),
    ("php-common", "exacto", "php", None),
    ("php-cli", "exacto", "php", None),
    ("php-fpm", "exacto", "php", None),
    (r"^php\d+\.\d+(-|$)", "regex", "php", None),
    ("php8", "prefijo", "php", None),
    ("php7", "prefijo", "php", None),
    ("libapache2-mod-php", "prefijo", "php", None),
    ("postgresql", "prefijo", "postgresql", None),
    ("mariadb-server", "prefijo", "mariadb", "mariadb"),
    ("mariadb-client", "prefijo", "mariadb", "mariadb"),
    ("mariadb", "prefijo", "mariadb", None),
    ("mysql-server", "prefijo", "mysql", None),
    ("mysql-client", "prefijo", "mysql", None),
    ("mysql", "prefijo", "mysql", None),
    ("mongodb", "prefijo", "mongodb", None),
    ("sqlite3", "exacto", "sqlite", "sqlite3"),
    ("libsqlite3-0", "exacto", "sqlite", "sqlite3"),
    ("libsqlite3-0t64", "exacto", "sqlite", "sqlite3"),
    ("sqlite3", "prefijo", "sqlite", None),
    ("docker.io", "exacto", "docker", "docker.io"),
    ("docker-ce", "exacto", "docker", None),
    ("docker-compose", "prefijo", "docker", None),
    ("containerd", "exacto", "docker", "containerd"),
    ("containerd.io", "exacto", "docker", None),
    ("slapd", "exacto", "openldap", "openldap"),
    ("libldap-2.5-0", "exacto", "openldap", "openldap"),
    ("libldap2", "exacto", "openldap", "openldap"),
    ("openldap", "prefijo", "openldap", None),
    ("samba", "prefijo", "smb", "samba"),
    ("smbclient", "exacto", "smb", "samba"),
    ("libsmbclient", "exacto", "smb", "samba"),
    ("wazuh-agent", "prefijo", "wazuh", None),
    ("wazuh", "prefijo", "wazuh", None),
    ("xrdp", "prefijo", "rdp", None),
    ("proxmox-ve", "prefijo", "proxmox", None),
    ("pve-manager", "prefijo", "proxmox", None),
    ("gitlab", "prefijo", "gitlab", None),
    ("netbeans", "prefijo", "netbeans", None),
    ("eclipse", "prefijo", "eclipse", None),
    ("wordpress", "prefijo", "wordpress", None),
    ("linphone", "prefijo", "linphone", None),
    ("mattermost", "prefijo", "mattermost", None),
    ("crystaldiskinfo", "prefijo", "crystaldiskinfo", None),
    ("linux-image-", "prefijo", "linux", "linux"),
    ("linux-generic", "prefijo", "linux", "linux"),
    ("freebsd-kernel", "exacto", "freebsd", None),
    ("microsoft windows", "prefijo", "windows", None),
]

#: Tecnologias que conviene tener en el inventario porque estan en muchos activos y
#: reciben avisos con frecuencia. Se crean con ``sembrar_tecnologias`` si no existen
#: (criticidad media, red interna); el operador ajusta criticidad y exposicion. Los
#: alias con contexto solo casan cuando el texto habla de una vulnerabilidad.
TECNOLOGIAS_SUGERIDAS: list[dict[str, Any]] = [
    {"slug": "curl", "name": "cURL y libcurl", "vendor": "curl project", "category": "utilidad",
     "aliases": [{"alias": "curl", "contexto": True}, {"alias": "libcurl", "contexto": True}],
     "reglas": [("curl", "exacto", "curl"), ("libcurl", "prefijo", "curl")]},
    {"slug": "sudo", "name": "sudo", "vendor": "Todd Miller", "category": "utilidad",
     "aliases": [{"alias": "sudo", "contexto": True}], "reglas": [("sudo", "exacto", "sudo"), ("sudo-ldap", "exacto", "sudo")]},
    {"slug": "bash", "name": "Bash", "vendor": "GNU", "category": "utilidad",
     "aliases": [{"alias": "bash", "contexto": True}, {"alias": "GNU Bash", "match_mode": "phrase"}], "reglas": [("bash", "exacto", "bash")]},
    {"slug": "python", "name": "Python", "vendor": "Python Software Foundation", "category": "desarrollo",
     "aliases": [{"alias": "cpython"}, {"alias": "python", "contexto": True}],
     "reglas": [("python3", "exacto", "python3-defaults"), (r"^python3\.\d+$", "regex", None), ("python launcher", "prefijo", None),
                ("python", "prefijo", None), ("python3-minimal", "exacto", "python3-defaults")]},
    {"slug": "perl", "name": "Perl", "vendor": "Perl Foundation", "category": "desarrollo",
     "aliases": [{"alias": "perl", "contexto": True}], "reglas": [("perl", "exacto", "perl"), ("perl-base", "exacto", "perl"), ("perl5", "exacto", None)]},
    {"slug": "libxml2", "name": "libxml2", "vendor": "GNOME", "category": "utilidad",
     "aliases": [{"alias": "libxml2"}], "reglas": [("libxml2", "exacto", "libxml2"), ("libxml2", "prefijo", "libxml2")]},
    {"slug": "expat", "name": "Expat (XML)", "vendor": "libexpat", "category": "utilidad",
     "aliases": [{"alias": "expat", "contexto": True}, {"alias": "libexpat"}], "reglas": [("expat", "exacto", "expat"), ("libexpat1", "exacto", "expat"), ("libexpat1t64", "exacto", "expat")]},
    {"slug": "zlib", "name": "zlib", "vendor": "zlib", "category": "utilidad",
     "aliases": [{"alias": "zlib", "contexto": True}], "reglas": [("zlib1g", "exacto", "zlib"), ("zlib", "exacto", None)]},
    {"slug": "libssh2", "name": "libssh2", "vendor": "libssh2", "category": "utilidad",
     "aliases": [{"alias": "libssh2"}], "reglas": [("libssh2-1", "exacto", "libssh2"), ("libssh2-1t64", "exacto", "libssh2"), ("libssh2", "exacto", None)]},
    {"slug": "zabbix", "name": "Zabbix", "vendor": "Zabbix", "category": "monitorizacion",
     "aliases": [{"alias": "zabbix"}], "reglas": [("zabbix", "prefijo", None)]},
    {"slug": "clamav", "name": "ClamAV", "vendor": "Cisco Talos", "category": "seguridad",
     "aliases": [{"alias": "clamav"}], "reglas": [("clamav", "prefijo", "clamav"), ("libclamav", "prefijo", "clamav")]},
    {"slug": "postfix", "name": "Postfix", "vendor": "Wietse Venema", "category": "correo",
     "aliases": [{"alias": "postfix"}], "reglas": [("postfix", "prefijo", "postfix")]},
    {"slug": "rsyslog", "name": "rsyslog", "vendor": "Adiscon", "category": "utilidad",
     "aliases": [{"alias": "rsyslog"}], "reglas": [("rsyslog", "prefijo", "rsyslog")]},
    {"slug": "nagios-nrpe", "name": "Nagios NRPE", "vendor": "Nagios", "category": "monitorizacion",
     "aliases": [{"alias": "nrpe"}, {"alias": "nagios", "contexto": True}], "reglas": [("nagios-nrpe", "prefijo", "nagios-nrpe"), ("nagios-plugins", "prefijo", None)]},
    {"slug": "bareos", "name": "Bareos (copias de seguridad)", "vendor": "Bareos", "category": "utilidad",
     "aliases": [{"alias": "bareos"}], "reglas": [("bareos", "prefijo", "bareos")]},
    {"slug": "cups", "name": "CUPS (impresión)", "vendor": "OpenPrinting", "category": "utilidad",
     "aliases": [{"alias": "cups", "contexto": True}], "reglas": [("cups", "prefijo", "cups"), ("libcups2", "prefijo", "cups")]},
    {"slug": "qemu-kvm", "name": "QEMU / KVM", "vendor": "QEMU", "category": "virtualizacion",
     "aliases": [{"alias": "qemu"}, {"alias": "kvm", "contexto": True}], "reglas": [("qemu", "prefijo", "qemu"), ("pve-qemu", "prefijo", None)]},
    {"slug": "nmap", "name": "Nmap", "vendor": "Nmap Project", "category": "seguridad",
     "aliases": [{"alias": "nmap"}], "reglas": [("nmap", "exacto", None)]},
    {"slug": "openvpn", "name": "OpenVPN", "vendor": "OpenVPN Inc.", "category": "red",
     "aliases": [{"alias": "openvpn"}], "reglas": [("openvpn", "prefijo", "openvpn")]},
    {"slug": "ivanti-secure-access", "name": "Ivanti Secure Access (Pulse Secure)", "vendor": "Ivanti", "category": "red",
     "aliases": [{"alias": "Ivanti Secure Access", "match_mode": "phrase"}, {"alias": "Pulse Secure", "match_mode": "phrase"},
                 {"alias": "Ivanti Connect Secure", "match_mode": "phrase"}],
     "reglas": [("ivanti secure access", "prefijo", None), ("pulse secure", "prefijo", None), ("pulse application launcher", "prefijo", None)]},
    {"slug": "filezilla", "name": "FileZilla", "vendor": "Tim Kosse", "category": "utilidad",
     "aliases": [{"alias": "filezilla"}], "reglas": [("filezilla", "prefijo", None)]},
    {"slug": "microsoft-office", "name": "Microsoft Office", "vendor": "Microsoft", "category": "ofimatica",
     "aliases": [{"alias": "Microsoft Office", "match_mode": "phrase"}, {"alias": "Microsoft 365", "match_mode": "phrase"}, {"alias": "office", "contexto": True}],
     "reglas": [("microsoft office", "prefijo", None), ("microsoft 365", "prefijo", None), ("office 16", "prefijo", None)]},
    {"slug": "microsoft-teams", "name": "Microsoft Teams", "vendor": "Microsoft", "category": "colaboracion",
     "aliases": [{"alias": "Microsoft Teams", "match_mode": "phrase"}, {"alias": "teams", "contexto": True}], "reglas": [("microsoft teams", "prefijo", None), ("teams", "exacto", None)]},
    {"slug": "onedrive", "name": "Microsoft OneDrive", "vendor": "Microsoft", "category": "colaboracion",
     "aliases": [{"alias": "onedrive"}], "reglas": [("microsoft onedrive", "prefijo", None), ("onedrive", "prefijo", None)]},
    {"slug": "vscode", "name": "Visual Studio Code", "vendor": "Microsoft", "category": "desarrollo",
     "aliases": [{"alias": "Visual Studio Code", "match_mode": "phrase"}, {"alias": "vscode"}], "reglas": [("microsoft visual studio code", "prefijo", None), ("code", "exacto", None)]},
    {"slug": "dwagent", "name": "DWAgent (acceso remoto)", "vendor": "DWService", "category": "acceso-remoto",
     "aliases": [{"alias": "dwagent"}, {"alias": "dwservice"}], "reglas": [("dwagent", "prefijo", None)]},
    {"slug": "tightvnc", "name": "TightVNC (acceso remoto)", "vendor": "GlavSoft", "category": "acceso-remoto",
     "aliases": [{"alias": "tightvnc"}, {"alias": "vnc", "contexto": True}], "reglas": [("tightvnc", "prefijo", None)]},
    {"slug": "sophos-endpoint", "name": "Sophos Endpoint", "vendor": "Sophos", "category": "seguridad",
     "aliases": [{"alias": "Sophos Endpoint", "match_mode": "phrase"}, {"alias": "Sophos Intercept X", "match_mode": "phrase"}], "reglas": []},
    {"slug": "remmina", "name": "Remmina (escritorio remoto)", "vendor": "Remmina", "category": "acceso-remoto",
     "aliases": [{"alias": "remmina"}], "reglas": [("remmina", "prefijo", "remmina")]},
    {"slug": "openssh", "name": "OpenSSH", "vendor": "OpenBSD", "category": "red", "aliases": [], "reglas": [("openssh-server", "exacto", "openssh")]},
    {"slug": "snapd", "name": "snapd (paquetes snap)", "vendor": "Canonical", "category": "utilidad",
     "aliases": [{"alias": "snapd"}, {"alias": "snap-confine"}], "reglas": [("snapd", "exacto", "snapd"), ("snap-confine", "exacto", "snapd")]},
    {"slug": "glibc", "name": "glibc (biblioteca C de GNU)", "vendor": "GNU", "category": "utilidad",
     "aliases": [{"alias": "glibc"}, {"alias": "GNU C Library", "match_mode": "phrase"}], "reglas": [("libc6", "exacto", "glibc"), ("libc-bin", "exacto", "glibc")]},
    {"slug": "systemd", "name": "systemd", "vendor": "systemd", "category": "utilidad",
     "aliases": [{"alias": "systemd", "contexto": True}], "reglas": [("systemd", "exacto", "systemd"), ("systemd-", "prefijo", "systemd"), ("libsystemd0", "exacto", "systemd")]},
    {"slug": "gnutls", "name": "GnuTLS", "vendor": "GnuTLS", "category": "criptografia",
     "aliases": [{"alias": "gnutls"}], "reglas": [("libgnutls30", "exacto", "gnutls28"), ("libgnutls30t64", "exacto", "gnutls28"), ("gnutls", "exacto", None)]},
    {"slug": "xz", "name": "XZ Utils", "vendor": "Tukaani", "category": "utilidad",
     "aliases": [{"alias": "xz-utils"}, {"alias": "liblzma"}, {"alias": "xz", "contexto": True}], "reglas": [("xz-utils", "exacto", "xz-utils"), ("liblzma5", "exacto", "xz-utils"), ("xz", "exacto", None)]},
    {"slug": "zstd", "name": "Zstandard", "vendor": "Meta", "category": "utilidad",
     "aliases": [{"alias": "zstd", "contexto": True}], "reglas": [("zstd", "exacto", "libzstd"), ("libzstd1", "exacto", "libzstd")]},
    {"slug": "pcre2", "name": "PCRE2", "vendor": "PCRE", "category": "utilidad",
     "aliases": [{"alias": "pcre2"}, {"alias": "pcre", "contexto": True}], "reglas": [("libpcre2-8-0", "exacto", "pcre2"), ("pcre2", "exacto", None)]},
    {"slug": "dbus", "name": "D-Bus", "vendor": "freedesktop", "category": "utilidad",
     "aliases": [{"alias": "dbus", "contexto": True}, {"alias": "d-bus", "contexto": True}], "reglas": [("dbus", "exacto", "dbus"), ("dbus-daemon", "exacto", "dbus"), ("libdbus-1-3", "exacto", "dbus")]},
    {"slug": "wget", "name": "Wget", "vendor": "GNU", "category": "utilidad",
     "aliases": [{"alias": "wget", "contexto": True}], "reglas": [("wget", "exacto", "wget")]},
    {"slug": "rsync", "name": "rsync", "vendor": "Samba", "category": "utilidad",
     "aliases": [{"alias": "rsync"}], "reglas": [("rsync", "exacto", "rsync")]},
    {"slug": "gnupg", "name": "GnuPG", "vendor": "GnuPG", "category": "criptografia",
     "aliases": [{"alias": "gnupg"}, {"alias": "gpg", "contexto": True}], "reglas": [("gnupg", "prefijo", "gnupg2"), ("gpg", "exacto", "gnupg2"), ("gpg-", "prefijo", "gnupg2")]},
    {"slug": "iptables-nftables", "name": "iptables / nftables (cortafuegos)", "vendor": "netfilter", "category": "red",
     "aliases": [{"alias": "nftables"}, {"alias": "iptables", "contexto": True}], "reglas": [("nftables", "exacto", "nftables"), ("iptables", "exacto", "iptables"), ("ufw", "exacto", "ufw")]},
    {"slug": "microsoft-edge-webview2", "name": "Microsoft Edge WebView2", "vendor": "Microsoft", "category": "navegador",
     "aliases": [{"alias": "WebView2"}], "reglas": [("webview2 runtime", "prefijo", None), ("microsoft edge webview2", "prefijo", None)]},
]


def sembrar_tecnologias(conn: sqlite3.Connection, *, actor: str = "sistema") -> dict[str, int]:
    """Crea las tecnologias sugeridas que falten (con sus alias) y sus reglas de mapa.
    No toca las existentes ni sus alias; idempotente."""
    from . import matching
    creadas = alias_n = reglas_n = 0
    ahora = db.utcnow()
    existentes = {r["slug"]: r["id"] for r in conn.execute("SELECT id, slug FROM technologies")}
    for tec in TECNOLOGIAS_SUGERIDAS:
        tid = existentes.get(tec["slug"])
        if tid is None:
            cur = conn.execute(
                """INSERT INTO technologies(slug, name, vendor, category, criticality, systems_count, exposure, enabled,
                       notes, created_at, updated_at) VALUES(?,?,?,?,'medium',0,'interna',1,?,?,?)""",
                (tec["slug"], tec["name"], tec.get("vendor"), tec.get("category") or "aplicacion",
                 "Creada automáticamente a partir del software presente en los activos (OCS Inventory). "
                 "Ajuste criticidad y exposición.", ahora, ahora))
            tid = cur.lastrowid
            existentes[tec["slug"]] = tid
            creadas += 1
            for a in tec.get("aliases") or []:
                alias = a["alias"].lower()
                modo = a.get("match_mode") or ("phrase" if " " in alias else "word")
                contexto = json.dumps(list(matching.CONTEXTO_VULNERABILIDAD), ensure_ascii=False) if a.get("contexto") else None
                conn.execute("INSERT OR IGNORE INTO tech_aliases(technology_id, alias, match_mode, is_exclusion, context_required) "
                             "VALUES(?,?,?,0,?)", (tid, alias, modo, contexto))
                alias_n += 1
        for patron, modo, fuente in tec.get("reglas") or []:
            cur = conn.execute(
                "INSERT OR IGNORE INTO tecnologia_ocs(patron, modo, technology_id, paquete_fuente, origen, created_at, created_by) "
                "VALUES(?,?,?,?,'semilla',?,?)", (patron.lower() if modo != "regex" else patron, modo, tid, fuente, ahora, actor))
            reglas_n += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    return {"tecnologias": creadas, "alias": alias_n, "reglas": reglas_n}


#: Paquete binario Debian/Ubuntu -> paquete fuente (nombre en OSV.dev) cuando no
#: coinciden. Ubuntu publica ademas la lista de binarios en cada registro OSV;
#: esto cubre sobre todo Debian.
FUENTE_DEBIAN: dict[str, str] = {
    "libssl3": "openssl", "libssl3t64": "openssl", "libssl1.1": "openssl", "libssl-dev": "openssl",
    "libcurl4": "curl", "libcurl4t64": "curl", "libcurl3-gnutls": "curl", "libcurl3t64-gnutls": "curl",
    "openssh-server": "openssh", "openssh-client": "openssh", "openssh-sftp-server": "openssh",
    "apache2-bin": "apache2", "apache2-utils": "apache2", "apache2-data": "apache2",
    "nginx-core": "nginx", "nginx-full": "nginx", "nginx-light": "nginx", "nginx-common": "nginx",
    "libc6": "glibc", "libc-bin": "glibc", "libgnutls30": "gnutls28", "libgnutls30t64": "gnutls28",
    "libexpat1": "expat", "libxml2": "libxml2", "libxslt1.1": "libxslt", "zlib1g": "zlib",
    "libsqlite3-0": "sqlite3", "libglib2.0-0": "glib2.0", "libglib2.0-0t64": "glib2.0",
    "libssh-4": "libssh", "libssh2-1": "libssh2", "libgcrypt20": "libgcrypt20", "libnss3": "nss",
    "libpam0g": "pam", "libpam-modules": "pam", "libsystemd0": "systemd", "libudev1": "systemd",
    "systemd-sysv": "systemd", "libkrb5-3": "krb5", "libgssapi-krb5-2": "krb5",
    "libldap-2.5-0": "openldap", "libldap2": "openldap", "slapd": "openldap",
    "libsasl2-2": "cyrus-sasl2", "libpcre2-8-0": "pcre2", "perl-base": "perl", "libperl5.36": "perl",
    "liblzma5": "xz-utils", "libzstd1": "libzstd", "libbz2-1.0": "bzip2", "libarchive13": "libarchive",
    "libarchive13t64": "libarchive", "libfreetype6": "freetype", "libharfbuzz0b": "harfbuzz",
    "libjpeg62-turbo": "libjpeg-turbo", "libjpeg-turbo8": "libjpeg-turbo", "libwebp7": "libwebp",
    "libgd3": "libgd2", "libmagickcore-6.q16-6": "imagemagick", "libpoppler126": "poppler",
    "poppler-utils": "poppler", "libavahi-common3": "avahi", "avahi-daemon": "avahi",
    "libdbus-1-3": "dbus", "mariadb-server": "mariadb", "mariadb-client": "mariadb",
    "libmariadb3": "mariadb", "redis-server": "redis", "redis-tools": "redis",
    "smbclient": "samba", "libsmbclient": "samba", "libwbclient0": "samba",
    "proftpd-basic": "proftpd-dfsg", "dovecot-core": "dovecot", "dovecot-imapd": "dovecot",
    "libvirt-daemon": "libvirt", "qemu-system-x86": "qemu", "libpq5": "postgresql-16",
    "python3-minimal": "python3-defaults", "libpython3.11-stdlib": "python3.11",
    "libpython3.12-stdlib": "python3.12", "python3.11-minimal": "python3.11",
    "python3.12-minimal": "python3.12", "libtiff6": "tiff", "libtiff5": "tiff",
    "libpng16-16": "libpng1.6", "libpng16-16t64": "libpng1.6", "libcairo2": "cairo",
    "libpixman-1-0": "pixman", "libgtk-3-0": "gtk+3.0", "libgtk-3-0t64": "gtk+3.0",
    "libnghttp2-14": "nghttp2", "libidn2-0": "libidn2", "libpsl5": "libpsl", "libpsl5t64": "libpsl",
    "libtasn1-6": "libtasn1-6", "libp11-kit0": "p11-kit", "libunistring2": "libunistring",
    "libunistring5": "libunistring", "libgmp10": "gmp", "libhogweed6": "nettle", "libnettle8": "nettle",
    "libhogweed6t64": "nettle", "libnettle8t64": "nettle", "libffi8": "libffi", "libcap2": "libcap2",
    "libseccomp2": "libseccomp", "libapparmor1": "apparmor", "libaudit1": "audit",
    "libselinux1": "libselinux", "libsemanage2": "libsemanage", "libmount1": "util-linux",
    "libblkid1": "util-linux", "libuuid1": "util-linux", "libsmartcols1": "util-linux",
    "bsdutils": "util-linux", "mount": "util-linux", "fdisk": "util-linux", "libfdisk1": "util-linux",
    "libncursesw6": "ncurses", "libtinfo6": "ncurses", "ncurses-bin": "ncurses", "ncurses-base": "ncurses",
    "libreadline8": "readline", "libreadline8t64": "readline", "libgpg-error0": "libgpg-error",
    "libgcc-s1": "gcc-12", "libstdc++6": "gcc-12", "libgomp1": "gcc-12",
    "libcups2": "cups", "libcups2t64": "cups", "cups-daemon": "cups", "libgs10": "ghostscript",
    "ghostscript": "ghostscript", "libpython3.10-stdlib": "python3.10", "python3.10-minimal": "python3.10",
    "libxkbcommon0": "libxkbcommon", "libx11-6": "libx11", "libxpm4": "libxpm", "libxext6": "libxext",
    "libpulse0": "pulseaudio", "libvorbis0a": "libvorbis", "libflac12": "flac", "libsndfile1": "libsndfile",
    "libopenjp2-7": "openjpeg2", "libgif7": "giflib", "libexiv2-27": "exiv2",
    "libmagic1": "file", "libmagic1t64": "file", "file": "file",
}

_RE_ARQ = re.compile(r":(amd64|i386|arm64|armhf|all|x86_64|riscv64|ppc64el|s390x)$")
_RE_ESPACIOS = re.compile(r"\s+")
LOTE_SQL = 2000


# --------------------------------------------------------------------------
# Normalizacion
# --------------------------------------------------------------------------
def normalizar_nombre(nombre: Optional[str]) -> str:
    """'libcurl4t64:amd64' -> 'libcurl4t64'; 'Google  Chrome' -> 'google chrome'."""
    n = (nombre or "").strip().lower()
    n = _RE_ARQ.sub("", n)
    return _RE_ESPACIOS.sub(" ", n)


def paquete_fuente(nombre_norm: str, *, reglas: Optional[dict[str, str]] = None) -> list[str]:
    """Candidatos a paquete fuente Debian/Ubuntu para un binario, del mas al
    menos probable: la regla del mapa (si la hay), la tabla FUENTE_DEBIAN, el
    propio nombre y heuristicas (linux-image-* -> linux, php8.2-* -> php8.2)."""
    n = normalizar_nombre(nombre_norm)
    candidatos: list[str] = []
    if reglas and n in reglas and reglas[n]:
        candidatos.append(reglas[n])
    if n in FUENTE_DEBIAN:
        candidatos.append(FUENTE_DEBIAN[n])
    candidatos.append(n)
    if n.startswith("linux-image-") or n.startswith("linux-headers-") or n.startswith("linux-modules-"):
        candidatos.append("linux")
    m = re.match(r"^(php\d+\.\d+)-", n)
    if m:
        candidatos.append(m.group(1))
    m = re.match(r"^(postgresql(?:-client)?-(\d+))$", n)
    if m:
        candidatos.append(f"postgresql-{m.group(2)}")
    if n.startswith("lib") and n.endswith("-dev"):
        candidatos.append(n[3:-4])
    salida: list[str] = []
    for c in candidatos:
        if c and c not in salida:
            salida.append(c)
    return salida


def _version_visible(texto: Optional[str]) -> Optional[str]:
    return (texto or "").strip() or None


def normalizar_entorno(texto: Optional[str]) -> Optional[str]:
    """'Produccion' -> 'produccion'; 'Soporte y Pruebas' -> 'soporte'; 'Pruebas' -> 'pruebas'."""
    t = (texto or "").strip().lower().replace("ó", "o").replace("í", "i")
    if not t or t in _TAGS_VACIOS:
        return None
    if t.startswith("produc"):
        return "produccion"
    if t.startswith("conting"):
        return "contingencia"
    if t.startswith("desarr") or t.startswith("dev"):
        return "desarrollo"
    if "soporte" in t:
        return "soporte"
    if t.startswith("prueba") or t.startswith("test") or t.startswith("qa") or t.startswith("uat"):
        return "pruebas"
    return None


def entorno_de(nombre: Optional[str], cuenta: Optional[dict] = None) -> tuple[Optional[str], str]:
    """(entorno, origen): primero los campos de accountinfo de OCS, despues el sufijo del nombre."""
    for clave, valor in (cuenta or {}).items():
        if str(clave).upper() in ("HARDWARE_ID", "TAG"):
            continue
        e = normalizar_entorno(valor if isinstance(valor, str) else None)
        if e:
            return e, "ocs"
    m = _RE_SUFIJO_ENTORNO.search((nombre or "").strip())
    if m:
        return SUFIJO_ENTORNO[m.group(1).upper()], "nombre"
    return None, "desconocido"


#: Etiquetas de OCS que designan el mismo proceso de negocio con nombres distintos. La clave
#: se compara sin distinguir mayusculas ni espacios de sobra. El usuario indico el 2026-09-06
#: Mapeo de etiquetas OCS a procesos internos. Se amplia desde Ajustes con
#: «ocs_procesos_alias» (una linea por «etiqueta = proceso»).
PROCESOS_ALIAS: dict[str, str] = {
    "administración": "Administración técnica",
    "administracion": "Administración técnica",
    "admin": "Administración técnica",
    # Los nodos de Proxmox son infraestructura de virtualizacion, no un proceso de
    # negocio: los administra el equipo técnico.
    "proxmox": "Administración técnica",
    "pve": "Administración técnica",
}


def _sin_tildes(texto: str) -> str:
    """El texto sin tildes ni diacriticos, para comparar «Tecnologicos» con «Tecnológicos».

    Se usa SOLO para comparar, nunca para escribir: el nombre que se guarda y se ensena
    conserva sus tildes (regla de idioma del proyecto).
    """
    descompuesto = unicodedata.normalize("NFD", str(texto or ""))
    return unicodedata.normalize(
        "NFC", "".join(c for c in descompuesto if not unicodedata.combining(c)))


def _clave_alias(texto: Optional[str]) -> str:
    return " ".join(str(texto or "").split()).lower()


def _clave_proceso(texto: Optional[str]) -> str:
    """Clave de comparacion de un proceso de negocio: sin tildes, sin mayusculas y sin
    espacios de sobra (2026-09-15)."""
    return _sin_tildes(_clave_alias(texto))


def alias_procesos(cfg: Any = None) -> dict[str, str]:
    """Mapa etiqueta de OCS -> proceso de negocio, con lo que anada el ajuste.

    El ajuste ``ocs_procesos_alias`` es una lista de textos «etiqueta = proceso»; lo que se
    escriba ahi tiene prioridad sobre el mapa base, para poder corregir sin tocar el codigo."""
    mapa = dict(PROCESOS_ALIAS)
    crudo = (cfg.get("ocs_procesos_alias") if cfg is not None else None) or []
    if isinstance(crudo, str):
        crudo = [crudo]
    for entrada in crudo:
        etiqueta, _, proceso = str(entrada).partition("=")
        etiqueta, proceso = _clave_alias(etiqueta), " ".join(str(proceso).split())
        if etiqueta and proceso:
            mapa[etiqueta] = proceso[:120]
    return mapa


def procesos_canonicos(cfg: Any = None,
                       alias: Optional[dict[str, str]] = None) -> dict[str, str]:
    """{clave sin tildes ni mayusculas -> nombre canonico} de los procesos de negocio.

    Los nombres canonicos son los DESTINOS del mapa de alias (``PROCESOS_ALIAS`` mas el
    ajuste ``ocs_procesos_alias``): son los unicos que alguien ha escrito a proposito.
    Sirve para que dos etiquetas de OCS Inventory que solo se diferencian en las tildes o
    en las mayusculas («Redes» y «Redes») no se lean
    como dos procesos distintos en los filtros, las tablas y la grafica.
    """
    mapa = alias if alias is not None else alias_procesos(cfg)
    salida: dict[str, str] = {}
    for destino in mapa.values():
        nombre = " ".join(str(destino or "").split())
        if nombre:
            salida.setdefault(_clave_proceso(nombre), nombre)
    return salida


def etiqueta_mal_escrita(etiqueta: Optional[str], proceso: Optional[str]) -> bool:
    """Si la etiqueta de OCS Inventory es el MISMO nombre que el proceso, mal escrito.

    Distingue el caso «Administracion tecnica» (la misma palabra sin tilde, que hay que
    corregir en OCS Inventory) del caso «Proxmox» (un alias legitimo que designa el
    proceso «Administración técnica» con otras palabras y no es ningun error).
    """
    etq, proc = " ".join(str(etiqueta or "").split()), " ".join(str(proceso or "").split())
    if not etq or not proc or etq == proc:
        return False
    return _clave_proceso(etq) == _clave_proceso(proc)


def normalizar_proceso(etiqueta: Optional[str], *, cfg: Any = None,
                       alias: Optional[dict[str, str]] = None) -> Optional[str]:
    """Nombre de proceso de negocio que corresponde a una etiqueta de OCS.

    Es el UNICO sitio donde se decide ese nombre: la sincronizacion, la interfaz, los correos
    y los informes leen ``activos.proceso``, que se rellena aqui. Asi, al agrupar «Jaime
    Torres» y «Admin-JT» en «Redes», el cambio aparece en toda la plataforma.

    Desde el 2026-09-15 la comparacion se hace tambien SIN TILDES Y SIN MAYUSCULAS contra
    los nombres canonicos (``procesos_canonicos``): en produccion habia dos activos con el
    TAG «Redes», sin tilde, que salian como un proceso de negocio aparte
    en los filtros, en las tablas y en la grafica de «Por proceso de negocio». La etiqueta
    original de OCS Inventory no se toca (``activos.etiqueta_ocs``), y la ficha del activo
    avisa de que esta mal escrita para que se corrija en el origen.
    """
    texto = " ".join(str(etiqueta or "").split())
    if not texto:
        return None
    mapa = alias if alias is not None else alias_procesos(cfg)
    directo = mapa.get(_clave_alias(texto))
    if directo:
        return directo[:120]
    canonico = procesos_canonicos(alias=mapa).get(_clave_proceso(texto))
    return (canonico or texto)[:120]


def proceso_de(origen: str, cuenta: Optional[dict], *, cfg: Any = None,
               alias: Optional[dict[str, str]] = None) -> tuple[Optional[str], Optional[str]]:
    """(proceso, etiqueta_ocs): en servidores el TAG de OCS es el proceso de negocio; en
    equipos de computo el TAG es un numero de identificacion y no se usa como proceso."""
    etiqueta = str((cuenta or {}).get("TAG") or "").strip() or None
    if etiqueta is None or etiqueta.lower() in _TAGS_VACIOS:
        return None, etiqueta
    if origen != "servidores" or etiqueta.replace(" ", "").isdigit():
        return None, etiqueta
    return normalizar_proceso(etiqueta, cfg=cfg, alias=alias), etiqueta


#: Lo que el agente UNIX de OCS Inventory escribe en el campo DESCRIPTION: la
#: arquitectura y el tiempo encendido, separados por una barra («x86_64/00-00-17
#: 09:36:09» = arquitectura x86_64 y 17 dias, 9 horas y 36 minutos encendido). No es una
#: descripcion que nadie haya escrito, y en la ficha del activo se leia como ruido
#: (revision de claridad del 2026-09-15): 839 de los 885 activos con descripcion tenian
#: exactamente esta forma, y 881 de 881 tenian la columna «arquitectura» vacia, que es
#: justo el dato que la cadena si trae.
_RE_DESCRIPCION_AGENTE = re.compile(
    r"^\s*(?P<arq>[\w.+-]{2,32})\s*/\s*(?P<anios>\d{1,4})-(?P<meses>\d{1,2})-(?P<dias>\d{1,4})"
    r"\s+(?P<horas>\d{1,3}):(?P<minutos>\d{1,2}):(?P<segundos>\d{1,2})\s*$")


def _tiempo_encendido_es(anios: int, meses: int, dias: int, horas: int, minutos: int) -> str:
    """«1 año, 5 meses y 26 días», «17 días y 9 horas», «7 minutos»: siempre con unidad."""
    partes: list[str] = []
    for valor, singular, plural in ((anios, "año", "años"), (meses, "mes", "meses"),
                                    (dias, "día", "días"), (horas, "hora", "horas"),
                                    (minutos, "minuto", "minutos")):
        if valor:
            partes.append(f"{valor} {singular if valor == 1 else plural}")
    if not partes:
        return "menos de un minuto"
    partes = partes[:2]
    return partes[0] if len(partes) == 1 else f"{partes[0]} y {partes[1]}"


def porcentaje_honesto(parte: Any, total: Any) -> tuple[float, int]:
    """(valor, decimales) de un porcentaje que NO redondea hasta mentir.

    La pagina de Software decia «100,0 % instalaciones clasificadas» al lado de «1 nombre
    sin clasificar»: 813.506 de 813.507 es el 99,999877 %, y redondear a un decimal lo
    convierte en un 100 % que no es cierto (revision de claridad del 2026-09-15, punto
    15). Solo se escribe «100 %» cuando no queda ni una fuera; si el redondeo normal
    llegaria a 100 sin serlo, se TRUNCA a dos decimales («99,99 %»).
    """
    try:
        parte, total = float(parte or 0), float(total or 0)
    except (TypeError, ValueError):
        return 0.0, 0
    if total <= 0:
        return 0.0, 0
    if parte >= total:
        return 100.0, 0
    pct = parte * 100.0 / total
    if round(pct, 1) >= 100.0:
        return int(pct * 100) / 100.0, 2
    return round(pct, 1), 1


def interpretar_descripcion(texto: Optional[str]) -> dict[str, Optional[str]]:
    """Separa la cadena del agente de OCS Inventory en datos con nombre.

    Devuelve ``{"arquitectura", "encendido_es", "descripcion"}``. Cuando el campo
    DESCRIPTION es la cadena del agente UNIX, «descripcion» vale None (no hay ninguna
    descripcion escrita por nadie) y los otros dos traen la arquitectura y el tiempo que
    lleva encendida la maquina. Cuando es cualquier otra cosa se devuelve tal cual como
    «descripcion», sin inventar nada.
    """
    bruto = " ".join(str(texto or "").split())
    if not bruto:
        return {"arquitectura": None, "encendido_es": None, "descripcion": None}
    m = _RE_DESCRIPCION_AGENTE.match(bruto)
    if not m:
        return {"arquitectura": None, "encendido_es": None, "descripcion": bruto}
    anios, meses, dias = int(m.group("anios")), int(m.group("meses")), int(m.group("dias"))
    horas, minutos = int(m.group("horas")), int(m.group("minutos"))
    # Valores imposibles (algun agente informa una fecha en vez de un tiempo): se
    # conserva la arquitectura, que si es fiable, y no se inventa un tiempo encendido.
    sensato = anios <= 50 and meses <= 12 and dias <= 366 and horas <= 24 and minutos <= 59
    return {"arquitectura": m.group("arq"),
            "encendido_es": _tiempo_encendido_es(anios, meses, dias, horas, minutos) if sensato else None,
            "descripcion": None}


def etiqueta_sistema(activo: Any) -> tuple[str, Optional[str]]:
    """(etiqueta del sistema operativo, detalle que anade algo) para la ficha del activo.

    La ficha escribia «Ubuntu 24.04 24.04.4 LTS» en el titulo y «Ubuntu 24.04 24.04.4 LTS
    / Ubuntu 24.04.4 LTS» en la tabla: el mismo sistema tres veces (revision de claridad
    del 2026-09-15). Aqui se compone UNA etiqueta —si el nombre termina en el numero con
    el que empieza la version, ese numero no se repite— y el detalle solo se devuelve
    cuando aporta algo que la etiqueta no dice (el nombre en clave de Debian, por
    ejemplo); «()» y las repeticiones se descartan.
    """
    def _campo(nombre: str) -> str:
        try:
            valor = activo[nombre]
        except (KeyError, IndexError, TypeError):
            valor = getattr(activo, nombre, None)
        return " ".join(str(valor or "").split())

    nombre, version, detalle = _campo("so_nombre"), _campo("so_version"), _campo("so_detalle")
    etiqueta = nombre
    if version:
        partes = nombre.split()
        if partes and version.startswith(partes[-1]) and partes[-1][:1].isdigit():
            etiqueta = " ".join(partes[:-1] + [version])
        elif version not in nombre:
            etiqueta = f"{nombre} {version}".strip()
    etiqueta = etiqueta or nombre or ""
    limpio = detalle.strip("() ")
    if not limpio or limpio == etiqueta or limpio in etiqueta or etiqueta in limpio:
        return etiqueta, None
    return etiqueta, detalle


def motivo_riesgo(nombre_norm: str) -> str:
    n = (nombre_norm or "").lower()
    for prefijo, motivo in MOTIVO_RIESGO.items():
        if n.startswith(prefijo):
            return motivo
    return "programa señalado como de riesgo por la política de la organización"


def normalizar_so(osname: Optional[str], osversion: Optional[str],
                  oscomments: Optional[str] = None) -> dict[str, Any]:
    """Familia, version visible, ciclo (endoflife.date) y ecosistema (OSV.dev).

    Ejemplos reales de OCS:
      ('Ubuntu 24.04', '24.04', 'Ubuntu 24.04.3 LTS') -> ubuntu, 24.04.3 LTS, 24.04, Ubuntu:24.04
      ('Debian GNU/Linux 13.5', '13.5', ...)          -> debian, 13.5, 13, Debian:13
      ('FreeBSD amd64', '14.4-RELEASE-p6', ...)       -> freebsd, 14.4-RELEASE-p6, 14.4, None
      ('Microsoft Windows 11 Pro', '10.0.26200', ...) -> windows, 10.0.26200, 11-25h2, None
    """
    nombre = (osname or "").strip()
    version = (osversion or "").strip()
    detalle = (oscomments or "").strip()
    bajo = nombre.lower()
    out: dict[str, Any] = {"familia": "otro", "version": version or None, "ciclo": None,
                           "ecosistema": None, "nombre_es": nombre or "Sin datos", "edicion": None}
    if not nombre and not version:
        out.update(familia="desconocido", nombre_es="Sin datos de sistema")
        return out

    if "ubuntu" in bajo:
        m = (re.search(r"(\d{2}\.\d{2})", version) or re.search(r"(\d{2}\.\d{2})", nombre)
             or re.search(r"(\d{2}\.\d{2})", detalle))
        ciclo = m.group(1) if m else None
        visible = None
        md = re.search(r"ubuntu\s+(\d{2}\.\d{2}(?:\.\d+)?(?:\s+LTS)?)", detalle, re.I)
        if md:
            visible = md.group(1)
        out.update(familia="ubuntu", ciclo=ciclo, ecosistema=f"Ubuntu:{ciclo}" if ciclo else None,
                   version=visible or version or ciclo,
                   nombre_es=f"Ubuntu {ciclo}" if ciclo else "Ubuntu")
        return out

    if "debian" in bajo:
        m = re.search(r"debian(?:\s+gnu/linux)?\s+(\d+)(?:\.(\d+))?", bajo)
        mayor = m.group(1) if m else None
        visible = version if re.match(r"^\d+(\.\d+)*$", version) else (
            m.group(0).split()[-1] if m else None)
        if not mayor and re.match(r"^\d+", version):
            mayor = version.split(".")[0]
        out.update(familia="debian", ciclo=mayor, ecosistema=f"Debian:{mayor}" if mayor else None,
                   version=visible or version or None,
                   nombre_es=f"Debian {mayor}" if mayor else "Debian")
        return out

    if "freebsd" in bajo:
        m = re.match(r"^(\d+\.\d+)", version)
        ciclo = m.group(1) if m else None
        out.update(familia="freebsd", ciclo=ciclo, version=version or None,
                   nombre_es=f"FreeBSD {ciclo}" if ciclo else "FreeBSD")
        return out

    if "windows" in bajo:
        compilacion = version.split(" ")[0] if version else ""
        if "server" in bajo:
            ciclo = CICLOS_WINDOWS_SERVER.get(compilacion)
            edicion = "server"
        else:
            ciclo = CICLOS_WINDOWS.get(compilacion)
            if "ltsc" in bajo:
                edicion = "e-lts"
            elif "enterprise" in bajo or "education" in bajo:
                edicion = "e"
            else:
                edicion = "w"
        limpio = re.sub(r"^microsoft\s+", "", nombre, flags=re.I)
        out.update(familia="windows", ciclo=ciclo, edicion=edicion, version=version or None,
                   nombre_es=limpio or "Windows")
        return out

    if "centos" in bajo or "red hat" in bajo or "rocky" in bajo or "alma" in bajo:
        m = re.search(r"(\d+)", version) or re.search(r"(\d+)", nombre)
        out.update(familia="centos", ciclo=m.group(1) if m else None, version=version or None,
                   nombre_es=nombre)
        return out

    return out


def _zona_de(ip_texto: Optional[str], redes_internet: Iterable[str], redes_dmz: Iterable[str]) -> str:
    """'10.1.1.21/10.0.0.21' (OCS separa varias IP con '/') -> zona por CIDR."""
    ips: list[ipaddress._BaseAddress] = []
    for trozo in re.split(r"[\s,/;]+", ip_texto or ""):
        try:
            ips.append(ipaddress.ip_address(trozo))
        except ValueError:
            continue
    if not ips:
        return "interna"

    def en(redes: Iterable[str]) -> bool:
        for red in redes or []:
            try:
                r = ipaddress.ip_network(str(red).strip(), strict=False)
            except ValueError:
                continue
            if any(ip in r for ip in ips):
                return True
        return False

    if en(redes_internet):
        return "internet"
    if en(redes_dmz):
        return "dmz"
    return "interna"


def _iso_local(valor: Any) -> Optional[str]:
    """Fecha de OCS (hora local del servidor OCS, sin zona) -> ISO UTC con Z."""
    if valor is None or valor == "":
        return None
    if isinstance(valor, datetime):
        dt = valor
    else:
        try:
            dt = datetime.fromisoformat(str(valor).replace(" ", "T"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.astimezone()          # se asume la zona horaria de esta maquina
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _lista(cfg: Any, clave: str, defecto: list) -> list:
    valor = cfg.get(clave, None) if cfg is not None else None
    if valor is None or valor == "":
        return list(defecto)
    if isinstance(valor, str):
        return [v.strip() for v in re.split(r"[,;\n]+", valor) if v.strip()]
    return [str(v).strip() for v in valor if str(v).strip()]


# --------------------------------------------------------------------------
# Lectura del inventario
#
# ``conectar()`` y ``LectorOCS`` viven en threatintel/inventario/ocs_mysql.py desde el
# 2026-11-15 (import de compatibilidad arriba); el adaptador CSV/JSON generico esta en
# threatintel/inventario/csv_generico.py. Cual se usa para cada fuente lo decide
# ``sincronizar()``, segun el ``tipo`` que declare ``config/inventarios.yml``.
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Sincronizacion
# --------------------------------------------------------------------------
def _hash_activo(so: dict, software: list[tuple[str, str, Optional[str]]]) -> str:
    h = hashlib.sha1()
    h.update(f"{so.get('familia')}|{so.get('version')}|{so.get('ciclo')}".encode("utf-8"))
    for nombre, version, _ in sorted(software):
        h.update(f"\n{nombre}\t{version}".encode("utf-8", "replace"))
    return h.hexdigest()


def _preparar_software(filas: Iterable[tuple[str, Optional[str], Optional[str]]]
                       ) -> list[tuple[str, str, Optional[str]]]:
    salida: dict[tuple[str, str], Optional[str]] = {}
    for nombre, version, fabricante in filas:
        nombre = (nombre or "").strip()
        if not nombre:
            continue
        version = (version or "").strip()
        fabricante = (fabricante or "").strip() or None
        if fabricante and fabricante.lower() in ("unavailable", "n/a", "none", "-"):
            fabricante = None
        salida.setdefault((nombre[:255], version[:120]), fabricante)
    return [(n, v, f) for (n, v), f in salida.items()]


def sincronizar_origen(conn: sqlite3.Connection, origen: str, lector: Any, *,
                       cfg: Any = None, ahora: Optional[str] = None) -> dict[str, Any]:
    """Vuelca un origen de OCS en ``activos`` / ``activo_software``.

    Recorre el software ordenado por equipo (un cursor sin almacenar en memoria)
    y va cerrando activo a activo: un hash por activo decide si hay que
    reescribir su software. Los que ya no estan en OCS quedan con presente=0.
    Devuelve las cifras del sync y las registra en ``sync_ocs``.
    """
    alias_proc = alias_procesos(cfg)   # etiquetas de OCS agrupadas en un mismo proceso
    if origen not in ORIGENES:
        raise ValueError(f"origen desconocido: {origen}")
    ahora = ahora or db.utcnow()
    inicio = time.perf_counter()
    redes_internet = _lista(cfg, "ocs_internet_networks", [])
    redes_dmz = _lista(cfg, "ocs_dmz_networks", [])

    cur = conn.execute("INSERT INTO sync_ocs(origen, started_at, status) VALUES(?,?,'running')",
                       (origen, ahora))
    sync_id = cur.lastrowid
    stats = {"origen": origen, "activos": 0, "software": 0, "nuevos": 0, "cambiados": 0,
             "desaparecidos": 0, "sin_cambios": 0, "error": None, "sync_id": sync_id}

    existentes: dict[int, dict] = {
        int(r["ocs_id"]): {"id": r["id"], "hash": r["hash_software"], "presente": r["presente"]}
        for r in conn.execute("SELECT id, ocs_id, hash_software, presente FROM activos WHERE origen=?",
                              (origen,))}
    vistos: set[int] = set()
    propia_transaccion = not conn.in_transaction
    try:
        hardware = {int(h["ID"]): h for h in lector.hardware()}
        cuentas = lector.accountinfo() if hasattr(lector, "accountinfo") else {}
        if propia_transaccion:
            conn.execute("BEGIN")

        def cerrar(ocs_id: int, filas_software: list) -> None:
            h = hardware.get(ocs_id)
            if h is None:            # software de un equipo que ya no esta en hardware
                return
            vistos.add(ocs_id)
            so = normalizar_so(h.get("OSNAME"), h.get("OSVERSION"), h.get("OSCOMMENTS"))
            software = _preparar_software(filas_software)
            hash_ = _hash_activo(so, software)
            cuenta = cuentas.get(ocs_id) or {}
            entorno, _origen_entorno = entorno_de(h.get("NAME"), cuenta)
            proceso, etiqueta = proceso_de(origen, cuenta, alias=alias_proc)
            campos = {
                "nombre": (h.get("NAME") or f"ocs-{ocs_id}").strip()[:255],
                "entorno": entorno, "proceso": proceso, "etiqueta_ocs": (etiqueta or "")[:120] or None,
                "device_id": h.get("DEVICEID"),
                "so_nombre": so["nombre_es"], "so_version": so["version"],
                "so_detalle": (h.get("OSCOMMENTS") or "").strip()[:255] or None,
                "so_familia": so["familia"], "so_ciclo": so["ciclo"], "ecosistema": so["ecosistema"],
                "ip": (h.get("IPADDR") or "").strip()[:255] or None,
                "usuario": (h.get("USERID") or "").strip()[:120] or None,
                "arquitectura": (h.get("ARCH") or "").strip()[:40] or None,
                "grupo": (h.get("WORKGROUP") or "").strip()[:120] or None,
                "descripcion": (h.get("DESCRIPTION") or "").strip()[:255] or None,
                "ultima_conexion": _iso_local(h.get("LASTCOME")),
                "ultimo_inventario": _iso_local(h.get("LASTDATE")),
                "zona": _zona_de(h.get("IPADDR"), redes_internet, redes_dmz),
                "n_software": len(software),
            }
            previo = existentes.get(ocs_id)
            if previo is None:
                c2 = conn.execute(
                    """INSERT INTO activos(origen, ocs_id, device_id, nombre, so_nombre, so_version,
                           so_detalle, so_familia, so_ciclo, ecosistema, ip, usuario, arquitectura,
                           grupo, descripcion, ultima_conexion, ultimo_inventario, zona, hash_software,
                           n_software, presente, primera_vez_at, visto_at, cambiado_at,
                           entorno, proceso, etiqueta_ocs)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?,?)""",
                    (origen, ocs_id, campos["device_id"], campos["nombre"], campos["so_nombre"],
                     campos["so_version"], campos["so_detalle"], campos["so_familia"], campos["so_ciclo"],
                     campos["ecosistema"], campos["ip"], campos["usuario"], campos["arquitectura"],
                     campos["grupo"], campos["descripcion"], campos["ultima_conexion"],
                     campos["ultimo_inventario"], campos["zona"], hash_, campos["n_software"],
                     ahora, ahora, ahora, campos["entorno"], campos["proceso"], campos["etiqueta_ocs"]))
                activo_id = c2.lastrowid
                stats["nuevos"] += 1
                reescribir = True
            else:
                activo_id = previo["id"]
                reescribir = previo["hash"] != hash_
                conn.execute(
                    """UPDATE activos SET device_id=?, nombre=?, so_nombre=?, so_version=?, so_detalle=?,
                           so_familia=?, so_ciclo=?, ecosistema=?, ip=?, usuario=?, arquitectura=?,
                           grupo=?, descripcion=?, ultima_conexion=?, ultimo_inventario=?, zona=?,
                           hash_software=?, n_software=?, presente=1, visto_at=?,
                           cambiado_at=CASE WHEN ? THEN ? ELSE cambiado_at END,
                           entorno=?, proceso=?, etiqueta_ocs=?
                     WHERE id=?""",
                    (campos["device_id"], campos["nombre"], campos["so_nombre"], campos["so_version"],
                     campos["so_detalle"], campos["so_familia"], campos["so_ciclo"], campos["ecosistema"],
                     campos["ip"], campos["usuario"], campos["arquitectura"], campos["grupo"],
                     campos["descripcion"], campos["ultima_conexion"], campos["ultimo_inventario"],
                     campos["zona"], hash_, campos["n_software"], ahora,
                     1 if reescribir else 0, ahora, campos["entorno"], campos["proceso"],
                     campos["etiqueta_ocs"], activo_id))
                if reescribir:
                    stats["cambiados"] += 1
                else:
                    stats["sin_cambios"] += 1
            if reescribir:
                conn.execute("DELETE FROM activo_software WHERE activo_id=?", (activo_id,))
                conn.executemany(
                    "INSERT OR IGNORE INTO activo_software(activo_id, nombre, nombre_norm, version, fabricante) "
                    "VALUES(?,?,?,?,?)",
                    [(activo_id, n, normalizar_nombre(n), v, f) for n, v, f in software])
            stats["activos"] += 1
            stats["software"] += len(software)

        actual: Optional[int] = None
        acumulado: list = []
        for hw_id, nombre, version, fabricante in lector.software():
            if actual is not None and hw_id != actual:
                cerrar(actual, acumulado)
                acumulado = []
            actual = hw_id
            acumulado.append((nombre, version, fabricante))
        if actual is not None:
            cerrar(actual, acumulado)
        for ocs_id in hardware:
            if ocs_id not in vistos:
                cerrar(ocs_id, [])

        desaparecidos = [d["id"] for oid, d in existentes.items() if oid not in vistos and d["presente"]]
        for lote in range(0, len(desaparecidos), 500):
            ids = desaparecidos[lote:lote + 500]
            conn.execute(f"UPDATE activos SET presente=0 WHERE id IN ({','.join('?' * len(ids))})", ids)
        stats["desaparecidos"] = len(desaparecidos)

        duracion = int((time.perf_counter() - inicio) * 1000)
        conn.execute(
            """UPDATE sync_ocs SET finished_at=?, status='success', activos=?, software=?, nuevos=?,
                   cambiados=?, desaparecidos=?, duracion_ms=? WHERE id=?""",
            (db.utcnow(), stats["activos"], stats["software"], stats["nuevos"], stats["cambiados"],
             stats["desaparecidos"], duracion, sync_id))
        if propia_transaccion:
            conn.execute("COMMIT")
        stats["duracion_ms"] = duracion
        log.info("sincronizacion OCS terminada", extra={k: v for k, v in stats.items() if k != "error"})
        return stats
    except Exception as exc:  # noqa: BLE001
        if propia_transaccion and conn.in_transaction:
            conn.execute("ROLLBACK")
        stats["error"] = f"{type(exc).__name__}: {exc}"
        conn.execute("UPDATE sync_ocs SET finished_at=?, status='failed', error=? WHERE id=?",
                     (db.utcnow(), stats["error"][:1000], sync_id))
        log.error("fallo la sincronizacion OCS", extra={"origen": origen, "error": stats["error"]})
        return stats


def sincronizar(conn: sqlite3.Connection, *, secretos: dict, cfg: Any = None,
                origenes: Optional[Iterable[str]] = None) -> list[dict[str, Any]]:
    """Sincroniza los origenes indicados (por defecto los dos) y despues aplica el
    mapa de nombres, actualiza el inventario y detecta hallazgos."""
    resultados: list[dict[str, Any]] = []
    for origen in (origenes or list(ORIGENES)):
        prefijo = ORIGENES[origen]
        conexion, detalle = conectar(secretos, prefijo)
        if conexion is None:
            conn.execute("INSERT INTO sync_ocs(origen, started_at, finished_at, status, error) "
                         "VALUES(?,?,?,'failed',?)", (origen, db.utcnow(), db.utcnow(), detalle[:1000]))
            resultados.append({"origen": origen, "error": detalle, "activos": 0})
            log.error("no conecta con OCS", extra={"origen": origen, "detalle": detalle})
            continue
        try:
            resultados.append(sincronizar_origen(conn, origen, LectorOCS(conexion), cfg=cfg))
        finally:
            conexion.close()
    if any(not r.get("error") for r in resultados):
        sembrar_mapa(conn)          # reglas base nuevas o retiradas; las manuales no se tocan
        sembrar_tecnologias(conn)   # tecnologias sugeridas por el software presente, si faltan
        aplicar_mapa(conn)
        actualizar_inventario_desde_ocs(conn, cfg=cfg)
        detectar_hallazgos(conn, cfg=cfg)
    return resultados


# --------------------------------------------------------------------------
# Mapa de nombres OCS -> tecnologia
# --------------------------------------------------------------------------
def sembrar_mapa(conn: sqlite3.Connection, *, actor: str = "sistema") -> int:
    """Inserta las reglas base cuyo slug exista en el inventario y retira las reglas
    de semilla que ya no figuran en MAPA_BASE (las manuales no se tocan). Idempotente."""
    slugs = {r["slug"]: r["id"] for r in conn.execute("SELECT id, slug FROM technologies")}
    ahora = db.utcnow()
    creadas = 0
    vigentes = {(patron, modo) for patron, modo, _, _ in MAPA_BASE}
    for tec in TECNOLOGIAS_SUGERIDAS:
        for patron, modo, _ in tec.get("reglas") or []:
            vigentes.add((patron.lower() if modo != "regex" else patron, modo))
    for r in conn.execute("SELECT id, patron, modo FROM tecnologia_ocs WHERE origen='semilla'").fetchall():
        if (r["patron"], r["modo"]) not in vigentes:
            conn.execute("DELETE FROM tecnologia_ocs WHERE id=?", (r["id"],))
    for patron, modo, slug, fuente in MAPA_BASE:
        tid = slugs.get(slug)
        if tid is None:
            continue
        cur = conn.execute(
            "INSERT OR IGNORE INTO tecnologia_ocs(patron, modo, technology_id, paquete_fuente, origen, "
            "created_at, created_by) VALUES(?,?,?,?,'semilla',?,?)",
            (patron, modo, tid, fuente, ahora, actor))
        creadas += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    return creadas


def _reglas(conn: sqlite3.Connection) -> tuple[dict[str, int], list[tuple[str, int]], list[tuple[Any, int]], dict[str, int]]:
    """Reglas compiladas. Las manuales y las del mapa base mandan sobre las automaticas
    (creadas por la clasificacion de respaldo), que solo se aplican si nada mas casa."""
    exactos: dict[str, int] = {}
    prefijos: list[tuple[str, int]] = []
    regexes: list[tuple[Any, int]] = []
    automaticos: dict[str, int] = {}
    for r in conn.execute("SELECT patron, modo, technology_id, origen FROM tecnologia_ocs "
                          "ORDER BY CASE origen WHEN 'manual' THEN 0 WHEN 'semilla' THEN 1 ELSE 2 END, id"):
        patron = (r["patron"] or "").strip().lower() if r["modo"] != "regex" else (r["patron"] or "").strip()
        if not patron:
            continue
        if r["origen"] == "automatico":
            if r["modo"] == "exacto":
                automaticos.setdefault(patron, r["technology_id"])
            continue
        if r["modo"] == "exacto":
            exactos.setdefault(patron, r["technology_id"])
        elif r["modo"] == "prefijo":
            prefijos.append((patron, r["technology_id"]))
        elif r["modo"] == "regex":
            try:
                regexes.append((re.compile(patron, re.IGNORECASE), r["technology_id"]))
            except re.error:
                log.warning("regla regex invalida en tecnologia_ocs", extra={"patron": patron})
    prefijos.sort(key=lambda p: -len(p[0]))
    return exactos, prefijos, regexes, automaticos


def clasificar_nombre(nombre_norm: str, reglas: tuple) -> Optional[int]:
    exactos, prefijos, regexes, automaticos = reglas
    if nombre_norm in exactos:
        return exactos[nombre_norm]
    for patron, tid in prefijos:
        if nombre_norm.startswith(patron):
            return tid
    for rx, tid in regexes:
        if rx.search(nombre_norm):
            return tid
    return automaticos.get(nombre_norm)


def retirar_automaticas(conn: sqlite3.Connection, patron: str, modo: str) -> int:
    """Al crear una regla manual, las automaticas que cubre dejan de tener sentido."""
    patron = (patron or "").strip().lower() if modo != "regex" else (patron or "").strip()
    if not patron:
        return 0
    if modo == "exacto":
        return conn.execute("DELETE FROM tecnologia_ocs WHERE origen='automatico' AND modo='exacto' AND patron=?",
                            (patron,)).rowcount
    if modo == "prefijo":
        return conn.execute("DELETE FROM tecnologia_ocs WHERE origen='automatico' AND modo='exacto' AND patron LIKE ?",
                            (patron.replace("%", "").replace("_", "\\_") + "%",)).rowcount
    try:
        rx = re.compile(patron, re.IGNORECASE)
    except re.error:
        return 0
    ids = [r["id"] for r in conn.execute("SELECT id, patron FROM tecnologia_ocs WHERE origen='automatico' AND modo='exacto'")
           if rx.search(r["patron"] or "")]
    for i in ids:
        conn.execute("DELETE FROM tecnologia_ocs WHERE id=?", (i,))
    return len(ids)


#: Tecnologias de respaldo: clasifican lo que no casa con ninguna regla segun el sistema
#: donde esta instalado. Sin alias (no correlacionan avisos) y sin version en el inventario.
TECNOLOGIAS_RESPALDO: dict[str, dict[str, str]] = {
    "paquetes-debian-ubuntu": {"name": "Paquetes del sistema Debian y Ubuntu", "vendor": "Debian / Canonical",
                               "category": "sistema-operativo",
                               "notes": "Paquetes de la distribución sin regla propia. OSV.dev los evalúa por su nombre de paquete."},
    "puertos-freebsd": {"name": "Puertos y paquetes de FreeBSD", "vendor": "FreeBSD", "category": "sistema-operativo",
                        "notes": "Puertos de FreeBSD sin regla propia. VuXML los evalúa por su nombre de puerto."},
    "paquetes-rpm": {"name": "Paquetes del sistema CentOS y Red Hat", "vendor": "Red Hat", "category": "sistema-operativo",
                     "notes": "Paquetes rpm sin regla propia."},
    "windows-componentes": {"name": "Componentes, controladores y actualizaciones de Windows", "vendor": "Microsoft y fabricantes",
                            "category": "sistema-operativo",
                            "notes": "Actualizaciones KB, entornos de ejecución, controladores y utilidades de fabricante sin interés propio."},
}
#: Programas de Windows que son componente o controlador, no una aplicacion con avisos propios.
_RE_COMPONENTE_WINDOWS = re.compile(
    r"kb\d{6,}|\bdriver\b|controlador|\bruntime\b|redistributable|redistribuible|shared framework|host fx|"
    r"\.net (host|runtime|framework)|hosting bundle|language pack|paquete de idioma|update helper|updater\b|"
    r"^update\b|install application|installer\b|components? installer|setup support|native client|odbc driver|"
    r"ole db driver|vss writer|webview2|edge webview|maintenance service|helper\b|\bsdk\b|manuals?\b|"
    r"error recovery guide|hotfix|firmware|chipset|management engine|icls|\blms\b|wmi provider|"
    r"connected service|supportassist|customer connect|core services|optimizer|health tools|comprobación de estado|"
    r"asistente para la instalación|click-to-run|onedrive setup|realtek|nvidia|intel\(r\)|intel®|amd |amd_|"
    r"\bhp \b|hewlett-packard|kyocera|fujitsu|pfu|paperstream|scanner|scand?all|hplaserjet|\bdell\b|mydell|lenovo|"
    r"asus|armoury|gigabyte|@bios|msi center|promontory|zebra|samsung|status monitor|dot4|bufferchm|docproc|destinations|"
    r"hpdxp|ljdxp|hpgsj|web components|web plugins|localservicecomponents|sólo eliminar|remove only|redeem launcher|"
    r"sql server \d{4} (xevent|sql diagnostics|shared management|dmf|database engine|connection info|common files|batch parser|"
    r"t-sql|setup|rsfx|localdb)|browser for sql server|customer experience|msxml|visual c\+\+|visual studio \d{4} tools",
    re.IGNORECASE)
_RE_FABRICANTE_COMPONENTE = re.compile(
    r"intel|nvidia|realtek|advanced micro devices|\bamd\b|pfu|fujitsu|hewlett|\bhp\b|dell|lenovo|asus|gigabyte|\bmsi\b|"
    r"kyocera|zebra|samsung|epson|canon|brother|logitech|qualcomm|broadcom|synaptics|elan|alps|conexant|waves|dolby|"
    r"emc captiva|knowledgelake|tp-link|sdttelecom|readsoft flexlm", re.IGNORECASE)
_RE_VERSION_EN_NOMBRE = re.compile(r"\s*[-(]?\s*v?\d+(\.\d+){1,3}[^)]*\)?\s*$|\s+\(?(x64|x86|64-bit|32-bit|amd64)[^)]*\)?", re.IGNORECASE)


def _nombre_producto(nombre: str) -> str:
    """'WinSCP 6.3.2' -> 'WinSCP'; 'Notepad++ (64-bit x64)' -> 'Notepad++'; 'PuTTY release 0.83 (64-bit)' -> 'PuTTY release'."""
    n = _RE_VERSION_EN_NOMBRE.sub("", (nombre or "").strip())
    n = re.sub(r"\s+-\s*[a-z]{2}-[a-z]{2}$", "", n, flags=re.IGNORECASE)      # sufijo de idioma «- es-es»
    n = re.sub(r"\s{2,}", " ", n).strip(" -_")
    return n or (nombre or "").strip()


def _slug_de(texto: str) -> str:
    import unicodedata
    base = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()
    base = re.sub(r"[^a-z0-9]+", "-", base.lower()).strip("-")
    return base[:60] or "software"


def _asegurar_tecnologia_respaldo(conn: sqlite3.Connection, slug: str, ahora: str) -> int:
    fila = conn.execute("SELECT id FROM technologies WHERE slug=?", (slug,)).fetchone()
    if fila:
        return fila["id"]
    d = TECNOLOGIAS_RESPALDO[slug]
    cur = conn.execute(
        """INSERT INTO technologies(slug, name, vendor, category, criticality, systems_count, exposure, enabled, notes,
               created_at, updated_at) VALUES(?,?,?,?,'low',0,'interna',1,?,?,?)""",
        (slug, d["name"], d["vendor"], d["category"], d["notes"], ahora, ahora))
    return cur.lastrowid


def clasificar_respaldo(conn: sqlite3.Connection, *, actor: str = "sistema", minimo_windows: int = 1) -> dict[str, int]:
    """Clasifica todo lo que sigue sin tecnologia tras las reglas:

    * paquetes de Debian/Ubuntu, FreeBSD y CentOS -> tecnologia de respaldo de su sistema;
    * en Windows, componentes/controladores/actualizaciones -> «Componentes de Windows»; el
      resto de programas -> una tecnologia propia creada a partir del nombre del producto
      (sin numero de version), con alias exacto para que correlacione avisos que lo nombren.
    Crea reglas de nombre exacto (origen «automatico») para que la asignacion sea trazable
    y editable desde la pagina Software."""
    ahora = db.utcnow()
    resumen = {"respaldo": 0, "componentes_windows": 0, "tecnologias_nuevas": 0, "reglas": 0}
    filas = [dict(r) for r in conn.execute(
        """SELECT s.nombre_norm, MIN(s.nombre) AS nombre, MIN(s.fabricante) AS fabricante,
                  SUM(a.so_familia IN ('ubuntu','debian')) AS deb, SUM(a.so_familia='freebsd') AS bsd,
                  SUM(a.so_familia='centos') AS rpm, SUM(a.so_familia='windows') AS win, COUNT(*) AS total,
                  COUNT(DISTINCT s.activo_id) AS activos
             FROM activo_software s JOIN activos a ON a.id=s.activo_id
            WHERE s.technology_id IS NULL
            GROUP BY s.nombre_norm""")]
    cache: dict[str, int] = {}
    tecs_por_slug = {r["slug"]: r["id"] for r in conn.execute("SELECT id, slug FROM technologies")}

    def regla(patron: str, tid: int) -> None:
        cur = conn.execute(
            "INSERT OR IGNORE INTO tecnologia_ocs(patron, modo, technology_id, paquete_fuente, origen, created_at, created_by) "
            "VALUES(?,'exacto',?,NULL,'automatico',?,?)", (patron, tid, ahora, actor))
        if cur.rowcount and cur.rowcount > 0:
            resumen["reglas"] += 1

    for f in filas:
        n = f["nombre_norm"]
        dominante = max((("deb", f["deb"]), ("bsd", f["bsd"]), ("rpm", f["rpm"]), ("win", f["win"])), key=lambda x: x[1] or 0)[0]
        if dominante == "win":
            fabricante = (f["fabricante"] or "").lower()
            if es_ruido(n) or _RE_COMPONENTE_WINDOWS.search(f["nombre"] or n) or _RE_FABRICANTE_COMPONENTE.search(fabricante) or (
                    "microsoft" in fabricante and not re.search(r"office|365|visio|project|teams|edge|sql server \d{4} \(|onedrive", n)):
                slug = "windows-componentes"
                tid = cache.get(slug) or _asegurar_tecnologia_respaldo(conn, slug, ahora)
                cache[slug] = tid
                resumen["componentes_windows"] += 1
            else:
                producto = _nombre_producto(f["nombre"] or n)
                slug = _slug_de(producto)
                tid = tecs_por_slug.get(slug)
                if tid is None:
                    cur = conn.execute(
                        """INSERT INTO technologies(slug, name, vendor, category, criticality, systems_count, exposure, enabled,
                               notes, created_at, updated_at) VALUES(?,?,?,?,'medium',0,'interna',1,?,?,?)""",
                        (slug, producto[:120], (f["fabricante"] or None), "aplicacion",
                         "Creada automáticamente a partir del software instalado en equipos Windows (OCS Inventory). "
                         "Ajuste criticidad y exposición, o cámbiela por otra tecnología en la página Software.", ahora, ahora))
                    tid = cur.lastrowid
                    tecs_por_slug[slug] = tid
                    conn.execute("INSERT OR IGNORE INTO tech_aliases(technology_id, alias, match_mode, is_exclusion, context_required) "
                                 "VALUES(?,?,?,0,NULL)", (tid, producto.lower(), "phrase" if " " in producto else "word"))
                    resumen["tecnologias_nuevas"] += 1
        else:
            slug = {"deb": "paquetes-debian-ubuntu", "bsd": "puertos-freebsd", "rpm": "paquetes-rpm"}[dominante]
            tid = cache.get(slug) or _asegurar_tecnologia_respaldo(conn, slug, ahora)
            cache[slug] = tid
            resumen["respaldo"] += 1
        regla(n, tid)
        conn.execute("UPDATE activo_software SET technology_id=? WHERE nombre_norm=? AND technology_id IS NULL", (tid, n))
    return resumen


def depurar_automaticas(conn: sqlite3.Connection) -> dict[str, int]:
    """Revisa las tecnologias creadas automaticamente: las que por nombre o fabricante son
    componentes o controladores pasan a «Componentes de Windows» y se eliminan (si no tienen
    amenazas correlacionadas). Idempotente."""
    ahora = db.utcnow()
    movidas = eliminadas = 0
    destino = None
    for t in conn.execute("SELECT id, name, vendor FROM technologies WHERE notes LIKE "
                          "'Creada automáticamente a partir del software instalado en equipos Windows%'").fetchall():
        fabricante = (t["vendor"] or "").lower()
        if not (_RE_COMPONENTE_WINDOWS.search(t["name"]) or _RE_FABRICANTE_COMPONENTE.search(fabricante)):
            continue
        destino = destino or _asegurar_tecnologia_respaldo(conn, "windows-componentes", ahora)
        conn.execute("UPDATE activo_software SET technology_id=? WHERE technology_id=?", (destino, t["id"]))
        conn.execute("UPDATE tecnologia_ocs SET technology_id=? WHERE technology_id=? AND origen='automatico'", (destino, t["id"]))
        movidas += 1
        if conn.execute("SELECT 1 FROM threat_technologies WHERE technology_id=? LIMIT 1", (t["id"],)).fetchone() is None:
            conn.execute("DELETE FROM technologies WHERE id=?", (t["id"],))
            eliminadas += 1
    return {"movidas": movidas, "eliminadas": eliminadas}


def aplicar_mapa(conn: sqlite3.Connection, *, respaldo: bool = True) -> dict[str, int]:
    """Rellena ``activo_software.technology_id`` segun las reglas y, con ``respaldo``,
    clasifica lo que quede con las tecnologias de respaldo. Escribe tambien las filas
    reinsertadas por la sincronizacion (llegan sin tecnologia)."""
    reglas = _reglas(conn)
    nombres = [r["nombre_norm"] for r in conn.execute(
        "SELECT DISTINCT nombre_norm FROM activo_software")]
    mapeados = 0
    cambios = 0
    for n in nombres:
        tid = clasificar_nombre(n, reglas)
        if tid is None:
            cur = conn.execute("UPDATE activo_software SET technology_id=NULL WHERE nombre_norm=? "
                               "AND technology_id IS NOT NULL", (n,))
            if cur.rowcount:
                cambios += 1
            continue
        mapeados += 1
        cur = conn.execute("UPDATE activo_software SET technology_id=? WHERE nombre_norm=? "
                           "AND (technology_id IS NULL OR technology_id<>?)", (tid, n, tid))
        if cur.rowcount:
            cambios += 1
    if respaldo:
        clasificar_respaldo(conn)
        depurar_automaticas(conn)
    instalaciones = conn.execute("SELECT COUNT(*) FROM activo_software").fetchone()[0]
    instal_map = conn.execute(
        "SELECT COUNT(*) FROM activo_software WHERE technology_id IS NOT NULL").fetchone()[0]
    return {"nombres": len(nombres), "nombres_mapeados": mapeados, "cambios": cambios,
            "instalaciones": int(instalaciones or 0), "instalaciones_mapeadas": int(instal_map or 0)}


def reglas_fuente(conn: sqlite3.Connection) -> dict[str, str]:
    """patron exacto -> paquete fuente declarado en el mapa (para OSV)."""
    return {r["patron"]: r["paquete_fuente"] for r in conn.execute(
        "SELECT patron, paquete_fuente FROM tecnologia_ocs WHERE modo='exacto' "
        "AND paquete_fuente IS NOT NULL AND paquete_fuente<>''")}


#: Nombres que nunca son una tecnologia por si mismos (ruido de OCS).
_NOMBRES_GENERICOS = frozenset({"update", "updates", "runtime", "service", "agent", "utility",
                                "tools", "driver", "drivers", "language pack", "help"})

#: Software que no necesita clasificarse: bibliotecas y paquetes del sistema (los evaluan
#: OSV.dev y VuXML por su nombre de paquete), parches de Windows, fuentes, idiomas...
PATRONES_RUIDO = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"^lib[a-z0-9]", r"^python3?-", r"^perl-", r"^ruby-", r"^p5-", r"^py3\d+-", r"^php-(pear|xml|common)$",
    r"^fonts?-", r"^xfonts-", r"^gir1\.2", r"^language-pack", r"^language-support", r"^hunspell-", r"^myspell-",
    r"^xserver-", r"^x11-", r"^gnome-", r"^yaru-", r"^ubuntu-", r"^linux-(firmware|headers|modules|image|tools|libc|generic|base)",
    r"^(update|security update|hotfix|actualizaci[oó]n)( for| de| para)?\b.*\bkb\d{6,}", r"\bkb\d{6,}\b",
    r"^microsoft visual c\+\+", r"^microsoft windows", r"^windows (software development|driver)",
    r"^(office 16|microsoft office [a-z ]*click-to-run|microsoft update health|comprobaci[oó]n de estado)",
    r"^(asistente para la instalaci[oó]n|windows pc health)", r"^ocs ?inventory", r"^ocsinventory",
    r"^(xdg|xkb|xcursor|xbrlapi|xauth|xml-core|xz-utils|zlib1g|zstd|zip|unzip|whiptail|whoopsie|wamerican|util-linux|usb|upower|zenity|yelp)",
    r"^(coreutils|findutils|diffutils|grep|gzip|bzip2|tar|sed|gawk|mawk|hostname|cpio|e2fsprogs|dmidecode|pciutils|pciids|lsof|less|nano|vim|procps|psmisc|init|systemd|udev|dbus|cron|logrotate|rsyslog|bsdutils|mount|passwd|login|base-files|base-passwd|debconf|dpkg|apt|adduser|ca-certificates|keyboard-configuration|console-setup|kbd|locales|tzdata|netbase|iproute2|iputils|net-tools|ifupdown|isc-dhcp|netplan|resolvconf|ethtool|kmod|initramfs|grub|os-prober|efibootmgr|shim|mokutil|plymouth|ucf|sensible-utils|readline-common|ncurses|dash|bash-completion|command-not-found|friendly-recovery|apport|popularity-contest|man-db|manpages|info|install-info|texinfo|groff|bc|dc|file|media-types|mime-support|shared-mime-info|publicsuffix|openssl-provider|gettext|indexinfo|readline|pkg$|lscpu|mpdecimal|brotli|expat|pcre2?$|gettext-runtime)",
))


def es_ruido(nombre_norm: str) -> bool:
    n = (nombre_norm or "").strip().lower()
    return any(p.search(n) for p in PATRONES_RUIDO)


def proponer_mapa(conn: sqlite3.Connection, *, limite: int = 60, minimo_activos: int = 1) -> list[dict]:
    """Software sin clasificar con mas activos y, cuando el nombre coincide con
    una tecnologia o alias del inventario, la propuesta de mapeo."""
    alias: dict[str, tuple[int, str]] = {}
    for r in conn.execute("SELECT id, slug, name FROM technologies WHERE enabled=1"):
        alias.setdefault(r["name"].lower(), (r["id"], r["name"]))
        alias.setdefault(r["slug"].lower().replace("-", " "), (r["id"], r["name"]))
        alias.setdefault(r["slug"].lower(), (r["id"], r["name"]))
    for r in conn.execute(
            """SELECT a.alias, t.id, t.name FROM tech_aliases a JOIN technologies t ON t.id=a.technology_id
                WHERE a.is_exclusion=0 AND a.match_mode IN ('word','phrase') AND t.enabled=1"""):
        a = (r["alias"] or "").lower().strip()
        if len(a) >= 3 and a not in _NOMBRES_GENERICOS:
            alias.setdefault(a, (r["id"], r["name"]))
    largos = sorted((a for a in alias if " " in a or len(a) >= 5), key=len, reverse=True)

    filas = []
    for r in conn.execute(
            """SELECT s.nombre_norm, MIN(s.nombre) AS nombre, COUNT(DISTINCT s.activo_id) AS activos,
                      COUNT(DISTINCT s.version) AS versiones
                 FROM activo_software s JOIN activos a ON a.id=s.activo_id
                WHERE s.technology_id IS NULL AND a.presente=1
                GROUP BY s.nombre_norm
               HAVING activos >= ?
                ORDER BY activos DESC, s.nombre_norm LIMIT ?""", (minimo_activos, limite * 6)):
        n = r["nombre_norm"]
        if es_ruido(n):
            continue
        if len(filas) >= limite:
            break
        sugerencia = alias.get(n)
        if sugerencia is None:
            palabras = set(re.split(r"[^a-z0-9+#.]+", n))
            for a in largos:
                if n.startswith(a + " ") or n.startswith(a + "-") or (a in palabras and " " not in a):
                    sugerencia = alias[a]
                    break
        filas.append({"nombre_norm": n, "nombre": r["nombre"], "activos": int(r["activos"]),
                      "versiones": int(r["versiones"]),
                      "tecnologia_id": sugerencia[0] if sugerencia else None,
                      "tecnologia": sugerencia[1] if sugerencia else None})
    return filas


# --------------------------------------------------------------------------
# Inventario de tecnologias alimentado por OCS
# --------------------------------------------------------------------------
_RE_RELEASE_RPM = re.compile(r"-\d[\w.]*$")
_RE_VERSION_FICTICIA = re.compile(r"snap|transitional|dummy|metapackage", re.I)


def _version_comparable(familia: Optional[str], version: str) -> str:
    """Version «de programa» comparable con un aviso: sin epoca ni revision dpkg
    ('1:9.6p1-3ubuntu13.19' -> '9.6p1'), sin release rpm ('2.4.6-99.el7' -> '2.4.6') y
    sin revision ni epoca de pkg de FreeBSD ('1.30.4_7,3' -> '1.30.4')."""
    from .versiones_distro import dividir_pkg, version_upstream
    if familia in ("debian", "ubuntu"):
        return version_upstream(version)
    if familia == "freebsd":
        return dividir_pkg(version)[1]
    if familia == "centos":
        return _RE_RELEASE_RPM.sub("", version)
    return version


def versiones_de_tecnologia(conn: sqlite3.Connection, tec_id: int, *, limite: int = 12) -> list[dict]:
    """Versiones instaladas de una tecnologia con numero de activos, de la mas
    antigua a la mas nueva (comparacion generica sobre la version «de programa»)."""
    from . import versions
    filas = [dict(r) for r in conn.execute(
        """SELECT s.version, a.so_familia, COUNT(DISTINCT s.activo_id) AS activos
             FROM activo_software s JOIN activos a ON a.id=s.activo_id
            WHERE s.technology_id=? AND a.presente=1
            GROUP BY s.version, a.so_familia""", (tec_id,))]
    agregadas: dict[str, dict] = {}
    for f in filas:
        clave = (f["version"] or "").strip() or "sin versión"
        if _RE_VERSION_FICTICIA.search(clave):
            continue        # paquetes de transicion (firefox 1:1snap1): no son una version real
        entrada = agregadas.setdefault(clave, {"version": clave, "activos": 0,
                                               "comparable": _version_comparable(f["so_familia"], clave)})
        entrada["activos"] += int(f["activos"] or 0)
    lista = list(agregadas.values())

    def clave_orden(e: dict):
        p = versions.parse_version(e["comparable"]) if e["version"] != "sin versión" else None
        return (p is None, p or (), e["version"])

    lista.sort(key=clave_orden)
    return lista[:limite] if limite else lista


def resumen_instalaciones(conn: sqlite3.Connection, tec_id: int) -> dict[str, int]:
    """Cuantas INSTALACIONES tiene una tecnologia, en cuantos ACTIVOS y con cuantas
    versiones distintas.

    Una instalacion es un par (activo, programa, version) de ``activo_software``: el
    mismo activo cuenta tantas veces como versiones tenga instaladas. Por eso la suma de
    la columna de la tabla de versiones de la ficha (56 en Microsoft Windows) NO es el
    numero de activos (50): son pares activo-version. Y ``sin_version`` son las
    instalaciones cuyo programa no declara version, que no aparecen en esa tabla porque
    no hay version que enseñar: 29 en Microsoft Windows, que hasta el 2026-09-15
    desaparecian de la pantalla sin que nada las mencionara (auditoria de tableros,
    punto 2).

    Devuelve {"instalaciones", "activos", "con_version", "sin_version", "versiones"}.
    Con una base sin ``activo_software`` (esquema anterior) devuelve todo a cero en lugar
    de romper la ficha.

    Coste medido sobre produccion (2026-09-15, 996.000 filas): 2 milisegundos en una
    tecnologia normal y 530 en «Componentes, controladores y actualizaciones de Windows»,
    que reune 699.000 instalaciones y 10.903 versiones distintas. Un indice
    (technology_id, activo_id, version) lo dejaria en indice puro; se pide al coordinador
    porque el esquema no se toca desde aqui.
    """
    vacio = {"instalaciones": 0, "activos": 0, "con_version": 0, "sin_version": 0,
             "versiones": 0}
    try:
        fila = conn.execute(
            """SELECT COUNT(*) AS instalaciones,
                      COUNT(DISTINCT s.activo_id) AS activos,
                      SUM(CASE WHEN TRIM(COALESCE(s.version, '')) = '' THEN 1 ELSE 0 END) AS sin_version,
                      COUNT(DISTINCT CASE WHEN TRIM(COALESCE(s.version, '')) <> ''
                                          THEN TRIM(s.version) END) AS versiones
                 FROM activo_software s JOIN activos a ON a.id = s.activo_id
                WHERE s.technology_id = ? AND a.presente = 1""", (int(tec_id),)).fetchone()
    except sqlite3.Error:
        return vacio
    if fila is None:
        return vacio
    instalaciones = int(fila["instalaciones"] or 0)
    sin_version = int(fila["sin_version"] or 0)
    return {"instalaciones": instalaciones, "activos": int(fila["activos"] or 0),
            "con_version": max(instalaciones - sin_version, 0),
            "sin_version": sin_version, "versiones": int(fila["versiones"] or 0)}


def actualizar_inventario_desde_ocs(conn: sqlite3.Connection, *, cfg: Any = None) -> int:
    """Escribe en cada tecnologia cuantos activos la tienen y sus versiones. Con
    ``ocs_update_inventory`` (por defecto activado) tambien rellena
    ``systems_count`` y ``version_installed`` con la version mas antigua instalada
    (el peor caso para la aplicabilidad)."""
    actualizar = True if cfg is None else bool(cfg.get("ocs_update_inventory", True))
    ahora = db.utcnow()
    tocadas = 0
    conteos = {r["technology_id"]: int(r["n"]) for r in conn.execute(
        """SELECT s.technology_id, COUNT(DISTINCT s.activo_id) AS n
             FROM activo_software s JOIN activos a ON a.id=s.activo_id
            WHERE s.technology_id IS NOT NULL AND a.presente=1 GROUP BY s.technology_id""")}
    for r in conn.execute("SELECT id FROM technologies"):
        tid = r["id"]
        n = conteos.get(tid, 0)
        versiones = versiones_de_tecnologia(conn, tid, limite=12) if n else []
        json_v = json.dumps([{"version": v["version"], "activos": v["activos"]} for v in versiones],
                            ensure_ascii=False)
        es_respaldo = conn.execute("SELECT slug FROM technologies WHERE id=?", (tid,)).fetchone()[0] in TECNOLOGIAS_RESPALDO
        if n and actualizar and not es_respaldo:
            minima = next((v["comparable"] for v in versiones if v["version"] != "sin versión"), None)
            conn.execute(
                """UPDATE technologies SET activos_ocs=?, versiones_ocs=?, ocs_actualizado_at=?,
                       systems_count=?, version_installed=COALESCE(?, version_installed), updated_at=?
                 WHERE id=?""", (n, json_v, ahora, n, minima, ahora, tid))
        else:
            conn.execute("UPDATE technologies SET activos_ocs=?, versiones_ocs=?, ocs_actualizado_at=? "
                         "WHERE id=?", (n, json_v, ahora, tid))
        tocadas += 1
    return tocadas


# --------------------------------------------------------------------------
# Hallazgos de politica (sin CVE)
# --------------------------------------------------------------------------
def _umbral_sin_reportar(cfg: Any, ahora: Optional[datetime] = None) -> str:
    dias = int(float((cfg.get("ocs_stale_days", 30) if cfg is not None else 30) or 30))
    base = ahora or datetime.now(timezone.utc)
    return (base - timedelta(days=dias)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def registrar_hallazgos(conn: sqlite3.Connection, tipo: str, actuales: dict[tuple[int, str], str],
                        *, ahora: Optional[str] = None) -> dict[str, int]:
    """Sincroniza ``hallazgos_activos`` de un tipo con el conjunto actual
    {(activo_id, clave): detalle}: los nuevos se abren, los que persisten
    conservan su fecha de deteccion y los que ya no se dan se cierran."""
    ahora = ahora or db.utcnow()
    abiertos = {(r["activo_id"], r["clave"]): r["id"] for r in conn.execute(
        "SELECT id, activo_id, clave FROM hallazgos_activos WHERE tipo=? AND resuelto_at IS NULL", (tipo,))}
    nuevos = 0
    for (activo_id, clave), detalle in actuales.items():
        if (activo_id, clave) in abiertos:
            conn.execute("UPDATE hallazgos_activos SET detalle=? WHERE id=?",
                         (detalle, abiertos[(activo_id, clave)]))
            continue
        conn.execute(
            """INSERT INTO hallazgos_activos(activo_id, tipo, clave, detalle, detectado_at, resuelto_at)
               VALUES(?,?,?,?,?,NULL)
               ON CONFLICT(activo_id, tipo, clave) DO UPDATE SET detalle=excluded.detalle,
                   detectado_at=excluded.detectado_at, resuelto_at=NULL""",
            (activo_id, tipo, clave, detalle, ahora))
        nuevos += 1
    cerrados = 0
    for (activo_id, clave), hid in abiertos.items():
        if (activo_id, clave) not in actuales:
            conn.execute("UPDATE hallazgos_activos SET resuelto_at=? WHERE id=?", (ahora, hid))
            cerrados += 1
    return {"abiertos": len(actuales), "nuevos": nuevos, "cerrados": cerrados}


def detectar_hallazgos(conn: sqlite3.Connection, *, cfg: Any = None,
                       ahora: Optional[datetime] = None) -> dict[str, dict[str, int]]:
    """Sin reportar, software de riesgo y sin agente de proteccion. El fin de
    soporte lo calcula ``aplicabilidad.hallazgos_fin_soporte`` (necesita endoflife.date)."""
    marca = db.utcnow() if ahora is None else ahora.astimezone(timezone.utc).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")
    resultado: dict[str, dict[str, int]] = {}

    # 1. Activos ciegos: presentes en OCS pero sin inventario reciente
    umbral = _umbral_sin_reportar(cfg, ahora)
    dias = int(float((cfg.get("ocs_stale_days", 30) if cfg is not None else 30) or 30))
    actuales: dict[tuple[int, str], str] = {}
    for r in conn.execute(
            "SELECT id, ultimo_inventario FROM activos WHERE presente=1 "
            "AND (ultimo_inventario IS NULL OR ultimo_inventario < ?)", (umbral,)):
        actuales[(r["id"], "inventario")] = (
            f"sin inventario desde {r['ultimo_inventario'][:10]}" if r["ultimo_inventario"]
            else "nunca ha enviado inventario") + f" (más de {dias} días)"
    resultado["sin_reportar"] = registrar_hallazgos(conn, "sin_reportar", actuales, ahora=marca)

    # 2. Software de riesgo (prefijo del nombre normalizado)
    patrones = [p.lower() for p in _lista(cfg, "ocs_risk_software", SOFTWARE_RIESGO_BASE)]
    actuales = {}
    if patrones:
        condiciones = " OR ".join("s.nombre_norm LIKE ?" for _ in patrones)
        for r in conn.execute(
                f"""SELECT DISTINCT s.activo_id, s.nombre_norm, MIN(s.nombre) AS nombre, MIN(s.version) AS version
                      FROM activo_software s JOIN activos a ON a.id=s.activo_id
                     WHERE a.presente=1 AND ({condiciones}) GROUP BY s.activo_id, s.nombre_norm""",
                [p + "%" for p in patrones]):
            actuales[(r["activo_id"], r["nombre_norm"])] = (
                f"{r['nombre']}" + (f" {r['version']}" if r["version"] else "")
                + f": {motivo_riesgo(r['nombre_norm'])}")
    resultado["software_riesgo"] = registrar_hallazgos(conn, "software_riesgo", actuales, ahora=marca)

    # 3. Equipos de computo sin agente de proteccion
    patron_edr = str((cfg.get("ocs_edr_pattern", "sophos") if cfg is not None else "sophos") or "").strip().lower()
    actuales = {}
    if patron_edr:
        for r in conn.execute(
                """SELECT a.id, a.so_familia FROM activos a
                    WHERE a.presente=1 AND a.origen='equipos' AND a.so_familia IN ('windows','ubuntu','debian')
                      AND a.n_software > 0
                      AND NOT EXISTS (SELECT 1 FROM activo_software s
                                       WHERE s.activo_id=a.id AND s.nombre_norm LIKE ?)""",
                (patron_edr + "%",)):
            actuales[(r["id"], patron_edr)] = (f"ningún programa instalado empieza por «{patron_edr}»: "
                                               f"el antivirus corporativo no está o su agente está roto")
    resultado["sin_edr"] = registrar_hallazgos(conn, "sin_edr", actuales, ahora=marca)

    # 4. Windows sin compilacion conocida (v14, 2026-09-10). El motor de parches de
    #    Microsoft (threatintel.msrc) reconoce el producto de la maquina y le pregunta por
    #    cada boletin, pero no puede calcular la compilacion instalada porque OCS no
    #    informa de ninguna actualizacion acumulativa reconocida: el veredicto sale
    #    «sin_dato» para TODOS sus CVE de Windows. En produccion eran 4 equipos de computo
    #    con 2.480 remediaciones que nadie podia hacer. Se registra como hallazgo del
    #    ACTIVO, no como vulnerabilidad, porque lo que hay que arreglar es su agente de
    #    inventario, y es tarea de Redes.
    #
    #    Se exige que EXISTA alguna fila del motor «msrc»: una maquina cuya version de
    #    Windows no tiene boletines (Windows 7, por ejemplo) tampoco tiene compilacion,
    #    pero eso no es un fallo del agente sino un sistema fuera de soporte, que ya tiene
    #    su propio hallazgo.
    actuales = {}
    for r in conn.execute(
            """SELECT a.id, a.so_nombre, a.so_version,
                      COUNT(*) AS sin_dato,
                      COUNT(DISTINCT ap.cve) AS cve
                 FROM activos a JOIN aplicabilidad ap ON ap.activo_id = a.id
                WHERE a.presente=1 AND a.so_familia='windows' AND a.windows_build IS NULL
                  AND ap.motor='msrc' AND ap.veredicto='sin_dato'
                GROUP BY a.id"""):
        cuantas = int(r["cve"] or 0)
        actuales[(r["id"], "compilacion")] = (
            f"{r['so_nombre'] or 'Windows'} {r['so_version'] or ''}".strip()
            + f": OCS no informa de ninguna actualización acumulativa reconocida, así que no "
              f"se puede calcular la compilación instalada y queda"
            + (f" 1 vulnerabilidad de Windows sin poder evaluar" if cuantas == 1
               else f"n {cuantas} vulnerabilidades de Windows sin poder evaluar"))
    resultado["sin_datos_windows"] = registrar_hallazgos(conn, "sin_datos_windows", actuales,
                                                         ahora=marca)
    return resultado


# --------------------------------------------------------------------------
# Consultas de resumen
# --------------------------------------------------------------------------
def ultima_sincronizacion(conn: sqlite3.Connection) -> dict[str, Optional[dict]]:
    salida: dict[str, Optional[dict]] = {}
    for origen in ORIGENES:
        fila = conn.execute("SELECT * FROM sync_ocs WHERE origen=? ORDER BY started_at DESC LIMIT 1",
                            (origen,)).fetchone()
        salida[origen] = dict(fila) if fila else None
    return salida


def resumen(conn: sqlite3.Connection, *, cfg: Any = None, ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Cifras para el panel, la pagina de activos y el informe."""
    umbral = _umbral_sin_reportar(cfg, ahora)
    dias_sin_reportar = int(float((cfg.get("ocs_stale_days", 30) if cfg is not None else 30) or 30))
    fila = conn.execute(
        """SELECT COUNT(*) AS total,
                  SUM(origen='servidores') AS servidores, SUM(origen='equipos') AS equipos,
                  SUM(ultimo_inventario IS NULL OR ultimo_inventario < ?) AS sin_reportar,
                  SUM(so_familia='desconocido') AS sin_so
             FROM activos WHERE presente=1""", (umbral,)).fetchone()
    soft = conn.execute(
        """SELECT COUNT(*) AS instalaciones, SUM(s.technology_id IS NOT NULL) AS mapeadas,
                  COUNT(DISTINCT s.nombre_norm) AS nombres,
                  COUNT(DISTINCT CASE WHEN s.technology_id IS NULL THEN s.nombre_norm END) AS sin_clasificar
             FROM activo_software s JOIN activos a ON a.id=s.activo_id WHERE a.presente=1""").fetchone()
    familias = [dict(r) for r in conn.execute(
        "SELECT so_familia, COUNT(*) AS n FROM activos WHERE presente=1 GROUP BY so_familia ORDER BY n DESC")]
    hallazgos = {r["tipo"]: int(r["n"]) for r in conn.execute(
        """SELECT h.tipo, COUNT(DISTINCT h.activo_id) AS n FROM hallazgos_activos h
             JOIN activos a ON a.id=h.activo_id
            WHERE h.resuelto_at IS NULL AND a.presente=1 GROUP BY h.tipo""")}
    # La severidad Baja no se reporta (ajuste ignore_low_severity): sin este filtro la
    # pagina de Activos decia «747 con vulnerabilidades confirmadas» y Amenazas, el Panel
    # y el resumen semanal decian 746 del mismo parque, con un enlace de una cifra a la
    # otra (revision de precision del 2026-09-09).
    excluir_bajas = bool((cfg or {}).get("ignore_low_severity", True)) if hasattr(cfg or {}, "get") else True
    sin_bajas = " AND (t.severity IS NULL OR t.severity <> 'Low')" if excluir_bajas else ""
    # El riesgo aceptado tampoco cuenta (excepciones con vencimiento, 2026-09-10, tarde).
    # Va en el MISMO sitio que la exclusion de la severidad baja porque significa lo
    # mismo, «este activo no cuenta aqui», y porque esta tarjeta enlaza con las cifras de
    # Amenazas y de Remediacion, que ya lo dejaban fuera: sin esto la pagina de Activos
    # decia una cifra y la de Amenazas otra del mismo parque. Con cero excepciones
    # vigentes el ayudante devuelve cadena vacia y la consulta queda como estaba.
    sin_excepcion = excepciones.y_sin_excepcion(conn, activo="ap.activo_id", cve="ap.cve",
                                                paquete="ap.paquete")
    # «Con vulnerabilidades confirmadas», y aparte los activos que NO REPORTAN
    # (2026-09-10, tarde): los que llevan mas de ``ocs_stale_days`` dias sin enviar
    # inventario tienen su vulnerabilidad calculada sobre datos viejos. Se dan las dos
    # cifras, cada una con su nombre, para que la pagina pueda decir «566 con dato al dia
    # y 30 mas cuyo dato tiene mas de 30 dias» en lugar de un 596 que no distingue.
    fresco = "(a.ultimo_inventario IS NOT NULL AND a.ultimo_inventario >= :umbral)"
    afectados_fila = conn.execute(
        f"""SELECT COUNT(DISTINCT ap.activo_id) AS total,
                   COUNT(DISTINCT CASE WHEN {fresco} THEN ap.activo_id END) AS con_dato,
                   COUNT(DISTINCT CASE WHEN NOT {fresco} THEN ap.activo_id END) AS sin_reportar
              FROM aplicabilidad ap
              JOIN activos a ON a.id=ap.activo_id
              LEFT JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto='afectado' AND a.presente=1
               AND (t.id IS NULL OR t.estado NOT IN ('descartada','falso_positivo','mitigada'))
               {sin_bajas}{sin_excepcion}""", {"umbral": umbral}).fetchone()
    afectados = int(afectados_fila["total"] or 0)
    # «En produccion o contingencia»: la cifra que abre el correo de alerta y el bloque de
    # activos del Panel. Hasta hoy la escribian a mano tres sitios distintos
    # (bin/ejecucion_diaria.py, bin/enviar_prueba.py y webui/vistas/panel.py) y ninguno de
    # los tres dejaba fuera la severidad baja ni el riesgo aceptado, asi que la misma
    # pantalla podia ensenar «597 con vulnerabilidades confirmadas» con un criterio y
    # «208 en produccion o contingencia» con otro. Se calcula aqui, una sola vez y con las
    # mismas dos condiciones que la cifra de arriba (2026-09-10, tarde).
    expuestos_fila = conn.execute(
        f"""SELECT COUNT(DISTINCT ap.activo_id) AS total,
                   COUNT(DISTINCT CASE WHEN {fresco} THEN ap.activo_id END) AS con_dato
              FROM aplicabilidad ap
              JOIN activos a ON a.id=ap.activo_id
              LEFT JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto='afectado' AND a.presente=1
               AND a.entorno IN {_EXPUESTOS_SQL}
               AND (t.id IS NULL OR t.estado NOT IN ('descartada','falso_positivo','mitigada'))
               {sin_bajas}{sin_excepcion}""", {"umbral": umbral}).fetchone()
    expuestos_afectados = int(expuestos_fila["total"] or 0)
    instalaciones = int(soft["instalaciones"] or 0)
    mapeadas = int(soft["mapeadas"] or 0)
    pendientes = sum(1 for (n,) in conn.execute(
        """SELECT DISTINCT s.nombre_norm FROM activo_software s JOIN activos a ON a.id=s.activo_id
            WHERE s.technology_id IS NULL AND a.presente=1""") if not es_ruido(n))
    entornos = {r["entorno"] or "desconocido": int(r["n"]) for r in conn.execute(
        "SELECT entorno, COUNT(*) AS n FROM activos WHERE presente=1 GROUP BY entorno")}
    # La misma pareja de condiciones que la tarjeta grande: hasta hoy este reparto por
    # proceso de negocio contaba la severidad baja y el riesgo aceptado, asi que un
    # proceso podia salir con mas activos afectados que el total de la pagina.
    procesos = [dict(r) for r in conn.execute(
        f"""SELECT a.proceso, COUNT(*) AS activos,
                  SUM(a.entorno IN ('produccion','contingencia')) AS expuestos,
                  (SELECT COUNT(DISTINCT ap.activo_id) FROM aplicabilidad ap JOIN activos b ON b.id=ap.activo_id
                     LEFT JOIN threats t ON t.id=ap.threat_id
                    WHERE b.proceso=a.proceso AND b.presente=1 AND ap.veredicto='afectado'
                      AND (t.id IS NULL OR t.estado NOT IN ('descartada','falso_positivo','mitigada'))
                      {sin_bajas}{sin_excepcion}) AS con_vulnerabilidades,
                  (SELECT COUNT(DISTINCT h.activo_id) FROM hallazgos_activos h JOIN activos b ON b.id=h.activo_id
                    WHERE b.proceso=a.proceso AND b.presente=1 AND h.tipo='fin_soporte' AND h.resuelto_at IS NULL) AS fuera_soporte
             FROM activos a WHERE a.presente=1 AND a.origen='servidores' AND a.proceso IS NOT NULL
            GROUP BY a.proceso ORDER BY activos DESC""")]
    sin_proceso = conn.execute("SELECT COUNT(*) FROM activos WHERE presente=1 AND origen='servidores' "
                               "AND proceso IS NULL").fetchone()[0]
    # El denominador es el inventario ENTERO de tecnologias, sin el filtro «enabled=1»
    # (2026-09-15, revision de claridad, punto 7). Con el filtro, la pagina de Activos
    # decia «164 / 193 tecnologias con activos», la de Software «166 tecnologias con
    # activos» y la de Inventario tecnologico «197 tecnologias»: tres denominadores para
    # lo mismo. Ahora las tres cuentan sobre las 197 del inventario y la pagina de
    # Activos dice cuantas de las instaladas estan desactivadas para el seguimiento.
    tec = conn.execute(
        "SELECT COUNT(*) AS total, SUM(COALESCE(activos_ocs,0) > 0) AS con, "
        "SUM(COALESCE(activos_ocs,0) > 0 AND enabled=0) AS con_desactivadas "
        "FROM technologies").fetchone()
    return {
        "tecnologias_total": int(tec["total"] or 0), "tecnologias_con_activos": int(tec["con"] or 0),
        "tecnologias_con_activos_desactivadas": int(tec["con_desactivadas"] or 0),
        "total": int(fila["total"] or 0), "servidores": int(fila["servidores"] or 0),
        "equipos": int(fila["equipos"] or 0), "sin_reportar": int(fila["sin_reportar"] or 0),
        "sin_so": int(fila["sin_so"] or 0),
        "instalaciones": instalaciones, "instalaciones_mapeadas": mapeadas,
        "pct_mapeado": round(mapeadas * 100.0 / instalaciones, 1) if instalaciones else 0.0,
        # El mismo porcentaje sin el redondeo que miente, con los decimales que hacen
        # falta, y cuantas instalaciones quedan sin clasificar (2026-09-15).
        "pct_mapeado_valor": porcentaje_honesto(mapeadas, instalaciones)[0],
        "pct_mapeado_decimales": porcentaje_honesto(mapeadas, instalaciones)[1],
        "instalaciones_sin_clasificar": max(0, instalaciones - mapeadas),
        "nombres": int(soft["nombres"] or 0), "sin_clasificar": int(soft["sin_clasificar"] or 0),
        "pendientes_clasificar": pendientes, "entornos": entornos, "procesos": procesos,
        "sin_proceso": int(sin_proceso or 0),
        "familias": familias, "hallazgos": hallazgos,
        "con_vulnerabilidades": int(afectados or 0),
        "expuestos_afectados": int(expuestos_afectados or 0),
        # Reparto por frescura del inventario (2026-09-10): las mismas dos cifras
        # calculadas solo sobre los activos que reportan al dia, y cuantos de los
        # afectados tienen el dato viejo. Nunca se calla ninguna de las dos.
        "dias_sin_reportar": dias_sin_reportar,
        "con_vulnerabilidades_con_dato": int(afectados_fila["con_dato"] or 0),
        "sin_reportar_afectados": int(afectados_fila["sin_reportar"] or 0),
        "expuestos_afectados_con_dato": int(expuestos_fila["con_dato"] or 0),
        "presentes_con_dato": max(0, int(fila["total"] or 0) - int(fila["sin_reportar"] or 0)),
        "fuera_soporte": hallazgos.get("fin_soporte", 0),
        "sincronizacion": ultima_sincronizacion(conn),
    }


# --------------------------------------------------------------------------
# Estado de los activos con cifras que dicen QUE cuentan (2026-09-07)
#
# El usuario leia «400 con vulnerabilidades confirmadas» y no podia saber si eran
# 400 activos o 400 vulnerabilidades. Eran activos, pero la etiqueta no lo decia.
# Estas funciones devuelven las dos magnitudes por separado y siempre nombradas:
#   * un ACTIVO afectado es un equipo con al menos una vulnerabilidad confirmada;
#   * una VULNERABILIDAD confirmada es UN CVE en UN activo (2026-09-09). El mismo
#     CVE en cien equipos son cien vulnerabilidades y un solo CVE; el mismo CVE en
#     cinco paquetes del mismo equipo es UNA vulnerabilidad. Antes se contaban filas
#     de `aplicabilidad` (una por paquete) y un CVE del nucleo salia cuatro o cinco
#     veces por servidor. El conteo sale de ``queries.sql_vulnerabilidades``, el
#     unico punto de verdad, para que todas las paginas y correos digan lo mismo.
# --------------------------------------------------------------------------

#: Amenazas que siguen contando: las descartadas, los falsos positivos y las
#: mitigadas no suman en ninguna cifra.
_AMENAZA_VIVA = ("(t.id IS NULL OR t.estado NOT IN "
                 "('descartada','falso_positivo','mitigada'))")

#: Entornos que se consideran expuestos: es donde una vulnerabilidad pesa mas.
_EXPUESTOS = ("produccion", "contingencia")


def estado_activos(conn: sqlite3.Connection, *, cfg: Any = None,
                   ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Cifras del estado de los activos, separando activos de vulnerabilidades.

    Va en el resumen semanal (no en la alerta diaria, que habla de lo detectado hoy).

    Desde el 2026-09-10 (tarde) separa ademas los activos que NO REPORTAN, es decir
    aquellos cuyo ultimo inventario tiene mas dias que el ajuste ``ocs_stale_days`` (30
    por omision; en produccion eran 74 de 717 activos presentes, con 4.043
    vulnerabilidades confirmadas entre 30 de ellos). Sus vulnerabilidades se calculan
    sobre datos viejos: ni afirmarlas ni negarlas es honesto, asi que las cifras se dan
    DOS veces y siempre con su nombre:

    * ``vulnerabilidades``, ``activos_afectados``, ``expuestos_*`` — el parque entero,
      como hasta ahora (nada se oculta y ninguna llamada existente cambia de valor);
    * ``vulnerabilidades_con_dato``, ``activos_afectados_con_dato``,
      ``activos_presentes_con_dato``, ``expuestos_*_con_dato`` — las mismas magnitudes
      calculadas SOLO sobre los activos que reportan al dia. Los que no reportan quedan
      fuera del numerador Y del denominador, que es la unica combinacion coherente: solo
      fuera del numerador equivaldria a afirmar que estan limpios, y dentro de los dos
      equivale a afirmar hechos con datos de hace mas de un mes;
    * ``sin_reportar_activos``, ``sin_reportar_afectados``,
      ``sin_reportar_vulnerabilidades`` — cuantos son y cuanto arrastran, para poder
      decirlo en pantalla con enlace a su lista.

    Mantener el inventario al dia es una tarea de Redes, no una
    vulnerabilidad: su lista y su informe estan en :func:`inventario_sin_reportar`.
    """
    # Regla interna: las bajas no se reportan (ignore_low_severity, activo). Estas cifras
    # abren el resumen semanal y el Panel, asi que usan el mismo criterio que la pagina
    # de Amenazas: una vulnerabilidad de severidad Baja no cuenta (2026-09-08).
    excluir_bajas = bool((cfg or {}).get("ignore_low_severity", True)) if hasattr(cfg or {}, "get") else True
    viva = _AMENAZA_VIVA + (" AND (t.severity IS NULL OR t.severity <> 'Low')" if excluir_bajas else "")
    # El riesgo aceptado tampoco cuenta (2026-09-10, tarde): se pega a la MISMA condicion
    # que deja fuera la severidad baja, asi que entra de una vez en las cuatro consultas
    # de esta funcion (confirmadas, activos expuestos, fin de soporte y vulnerabilidades
    # sin soporte). Estas cifras abren el resumen semanal y el Panel y tienen que decir lo
    # mismo que Amenazas y Remediacion, que ya lo dejaban fuera. Con cero excepciones
    # vigentes la condicion es cadena vacia y las consultas quedan como estaban.
    viva += excepciones.y_sin_excepcion(conn, activo="ap.activo_id", cve="ap.cve",
                                        paquete="ap.paquete")
    # Activos que NO reportan (2026-09-10, tarde). Su ultimo inventario tiene mas dias que
    # el ajuste ``ocs_stale_days`` (30), asi que sus vulnerabilidades se calculan sobre
    # datos viejos: ni afirmarlas ni negarlas es honesto. Se cuentan APARTE, y las cifras
    # «_con_dato» son las mismas magnitudes calculadas SOLO sobre los activos que si
    # reportan al dia, excluyendolos del numerador Y del denominador (ver el apartado
    # correspondiente de docs/INVENTARIO_SIN_REPORTAR_2026-09-10.md): dejarlos en el
    # denominador y fuera del numerador equivaldria a afirmar que estan limpios, y
    # dejarlos en los dos equivale a afirmar hechos con datos de hace mas de un mes.
    umbral = _umbral_sin_reportar(cfg, ahora)
    #: «Dato al dia»: el activo reporto dentro del plazo del ajuste ``ocs_stale_days``.
    #: La fecha va como parametro con nombre (:umbral) y los entornos expuestos como
    #: lista SQL fija (_EXPUESTOS_SQL), para no mezclar marcadores «?» y con nombre.
    fresco = "(a.ultimo_inventario IS NOT NULL AND a.ultimo_inventario >= :umbral)"
    presentes = conn.execute(
        """SELECT COUNT(*) AS total, SUM(origen='servidores') AS servidores,
                  SUM(origen='equipos') AS equipos,
                  SUM(ultimo_inventario IS NULL OR ultimo_inventario < :umbral) AS sin_reportar,
                  SUM(origen='servidores' AND (ultimo_inventario IS NULL
                      OR ultimo_inventario < :umbral)) AS sin_reportar_servidores,
                  SUM(origen='equipos' AND (ultimo_inventario IS NULL
                      OR ultimo_inventario < :umbral)) AS sin_reportar_equipos
             FROM activos WHERE presente=1""", {"umbral": umbral}).fetchone()

    confirmadas = conn.execute(
        f"""SELECT {sql_vulnerabilidades()} AS vulnerabilidades,
                   COUNT(DISTINCT ap.activo_id) AS activos,
                   COUNT(DISTINCT ap.cve) AS cve,
                   {sql_vulnerabilidades(condicion=f"a.entorno IN {_EXPUESTOS_SQL}")}
                       AS vulnerabilidades_expuestas,
                   -- Solo los activos que reportan al dia (2026-09-10)
                   {sql_vulnerabilidades(condicion=fresco)} AS vulnerabilidades_con_dato,
                   COUNT(DISTINCT CASE WHEN {fresco} THEN ap.activo_id END) AS activos_con_dato,
                   {sql_vulnerabilidades(condicion=f"a.entorno IN {_EXPUESTOS_SQL} AND {fresco}")}
                       AS vulnerabilidades_expuestas_con_dato,
                   -- Y los que no: se dicen aparte, nunca se callan
                   {sql_vulnerabilidades(condicion=f"NOT {fresco}")} AS vulnerabilidades_sin_reportar,
                   COUNT(DISTINCT CASE WHEN NOT {fresco} THEN ap.activo_id END)
                       AS activos_sin_reportar
              FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
              LEFT JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto='afectado' AND a.presente=1 AND {viva}""",
        {"umbral": umbral}).fetchone()
    expuestos = conn.execute(
        f"""SELECT COUNT(DISTINCT ap.activo_id) AS activos,
                   COUNT(DISTINCT CASE WHEN {fresco} THEN ap.activo_id END) AS con_dato
              FROM aplicabilidad ap
              JOIN activos a ON a.id=ap.activo_id
              LEFT JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto='afectado' AND a.presente=1
               AND a.entorno IN {_EXPUESTOS_SQL} AND {viva}""",
        {"umbral": umbral}).fetchone()
    activos_expuestos = int(expuestos["activos"] or 0)

    # Fuera de soporte: cuantos equipos y, de ellos, cuantos arrastran ademas
    # vulnerabilidades confirmadas. Un sistema sin soporte y sin vulnerabilidades
    # conocidas es un riesgo futuro; con ellas, es un riesgo de hoy que no se
    # puede corregir actualizando.
    sin_soporte = conn.execute(
        f"""SELECT COUNT(DISTINCT h.activo_id) AS activos,
                   COUNT(DISTINCT CASE WHEN EXISTS (
                        SELECT 1 FROM aplicabilidad ap
                          LEFT JOIN threats t ON t.id=ap.threat_id
                         WHERE ap.activo_id=h.activo_id AND ap.veredicto='afectado'
                           AND {viva})
                     THEN h.activo_id END) AS con_vulnerabilidades
              FROM hallazgos_activos h JOIN activos a ON a.id=h.activo_id
             WHERE h.tipo='fin_soporte' AND h.resuelto_at IS NULL AND a.presente=1"""
    ).fetchone()
    vulns_sin_soporte = conn.execute(
        f"""SELECT {sql_vulnerabilidades()} FROM aplicabilidad ap JOIN activos a ON a.id=ap.activo_id
              LEFT JOIN threats t ON t.id=ap.threat_id
             WHERE ap.veredicto='afectado' AND a.presente=1 AND {viva}
               AND EXISTS (SELECT 1 FROM hallazgos_activos h
                            WHERE h.activo_id=ap.activo_id AND h.tipo='fin_soporte'
                              AND h.resuelto_at IS NULL)""").fetchone()[0]

    total = int(presentes["total"] or 0)
    sin_reportar_activos = int(presentes["sin_reportar"] or 0)
    fuera_activos = int(sin_soporte["activos"] or 0)
    fuera_con = int(sin_soporte["con_vulnerabilidades"] or 0)
    return {
        "activos_presentes": total,
        "servidores": int(presentes["servidores"] or 0),
        "equipos": int(presentes["equipos"] or 0),
        # activos frente a vulnerabilidades: las dos magnitudes, cada una con su nombre
        "activos_afectados": int(confirmadas["activos"] or 0),
        "activos_sin_vulnerabilidades": total - int(confirmadas["activos"] or 0),
        "vulnerabilidades": int(confirmadas["vulnerabilidades"] or 0),
        "cve_distintos": int(confirmadas["cve"] or 0),
        # produccion y contingencia
        "expuestos_activos": int(activos_expuestos or 0),
        "expuestos_vulnerabilidades": int(confirmadas["vulnerabilidades_expuestas"] or 0),
        # fin de soporte
        "fuera_soporte_activos": fuera_activos,
        "fuera_soporte_con_vulnerabilidades": fuera_con,
        "fuera_soporte_sin_vulnerabilidades": max(0, fuera_activos - fuera_con),
        "fuera_soporte_vulnerabilidades": int(vulns_sin_soporte or 0),
        # ------------------------------------------------------------------
        # Activos que NO reportan (2026-09-10). Su dato es viejo: se separan.
        # ------------------------------------------------------------------
        "dias_sin_reportar": int(float((cfg.get("ocs_stale_days", 30) if cfg is not None else 30) or 30)),
        "sin_reportar_activos": sin_reportar_activos,
        "sin_reportar_servidores": int(presentes["sin_reportar_servidores"] or 0),
        "sin_reportar_equipos": int(presentes["sin_reportar_equipos"] or 0),
        "sin_reportar_afectados": int(confirmadas["activos_sin_reportar"] or 0),
        "sin_reportar_vulnerabilidades": int(confirmadas["vulnerabilidades_sin_reportar"] or 0),
        # Las mismas magnitudes SOLO sobre los activos que reportan al dia.
        "activos_presentes_con_dato": max(0, total - sin_reportar_activos),
        "activos_afectados_con_dato": int(confirmadas["activos_con_dato"] or 0),
        "activos_sin_vulnerabilidades_con_dato": max(
            0, total - sin_reportar_activos - int(confirmadas["activos_con_dato"] or 0)),
        "vulnerabilidades_con_dato": int(confirmadas["vulnerabilidades_con_dato"] or 0),
        "expuestos_activos_con_dato": int(expuestos["con_dato"] or 0),
        "expuestos_vulnerabilidades_con_dato": int(confirmadas["vulnerabilidades_expuestas_con_dato"] or 0),
    }


def inventario_sin_reportar(conn: sqlite3.Connection, *, cfg: Any = None,
                            ahora: Optional[datetime] = None,
                            limite: int = 200) -> dict[str, Any]:
    """Activos que llevan demasiado tiempo sin reportar a OCS, por origen.

    Informe propio de Redes: mantener el inventario al dia no es
    una tarea de seguridad, y mezclarlo con la alerta diaria hacia que se leyera
    como un hallazgo de seguridad. Se separa por servidores y equipos de computo
    porque los responsables no son los mismos.
    """
    umbral = _umbral_sin_reportar(cfg, ahora)
    dias = int(float((cfg.get("ocs_stale_days", 30) if cfg else 30) or 30))
    por_origen = {r["origen"]: int(r["n"]) for r in conn.execute(
        """SELECT origen, COUNT(*) AS n FROM activos
            WHERE presente=1 AND (ultimo_inventario IS NULL OR ultimo_inventario < ?)
           GROUP BY origen""", (umbral,))}
    totales = {r["origen"]: int(r["n"]) for r in conn.execute(
        "SELECT origen, COUNT(*) AS n FROM activos WHERE presente=1 GROUP BY origen")}
    # El limite se reparte POR GRUPO, no sobre el conjunto: con un limite bajo y un
    # ORDER BY por origen, «servidores» se quedaba sin ninguna fila porque «equipos» va
    # antes alfabeticamente y se las llevaba todas (2026-09-07).
    por_grupo = max(1, int(limite) // max(1, len(ORIGENES)))
    grupos = []
    recortado = False
    for origen in ORIGENES:
        n = por_origen.get(origen, 0)
        filas = [dict(r) for r in conn.execute(
            """SELECT nombre, origen, ip, so_nombre, proceso, entorno, usuario,
                      ultimo_inventario, visto_at
                 FROM activos
                WHERE presente=1 AND origen=?
                  AND (ultimo_inventario IS NULL OR ultimo_inventario < ?)
                ORDER BY (ultimo_inventario IS NULL) DESC, ultimo_inventario ASC, nombre
                LIMIT ?""", (origen, umbral, por_grupo))]
        for f in filas:
            f["origen_es"] = ORIGEN_ES.get(f["origen"], f["origen"])
            f["nunca"] = not f.get("ultimo_inventario")
        if n > len(filas):
            recortado = True
        grupos.append({
            "origen": origen,
            "origen_es": ORIGEN_PLURAL_ES.get(origen, origen),
            "sin_reportar": n,
            "total": totales.get(origen, 0),
            "pct": round(n * 100.0 / totales[origen], 1) if totales.get(origen) else 0.0,
            "filas": filas,
            "restantes": max(0, n - len(filas)),
        })
    return {
        "dias": dias,
        "total": sum(por_origen.values()),
        "activos_presentes": sum(totales.values()),
        "grupos": grupos,
        "recortado": recortado,
        "limite": int(limite),
        "limite_por_grupo": por_grupo,
    }


#: Dias que se dan por transcurridos cuando un activo NUNCA ha enviado inventario: no se
#: puede restar de una fecha que no existe, asi que se cuenta desde que la plataforma lo
#: vio por primera vez. La hoja de calculo lo escribe con todas sus letras.
_NUNCA = "nunca"


def _dias_desde(referencia: Optional[str], ahora: datetime) -> Optional[int]:
    """Dias enteros transcurridos desde una marca de tiempo ISO, o None si no se puede."""
    if not referencia:
        return None
    texto = str(referencia).strip().replace("Z", "+00:00")
    for intento in (texto, texto[:19], texto[:10]):
        try:
            momento = datetime.fromisoformat(intento)
        except ValueError:
            continue
        if momento.tzinfo is None:
            momento = momento.replace(tzinfo=timezone.utc)
        return max(0, int((ahora - momento).total_seconds() // 86400))
    return None


def inventario_sin_reportar_detallado(conn: sqlite3.Connection, *, cfg: Any = None,
                                      ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Lista COMPLETA de activos que no reportan, por tipo de maquina y con su detalle.

    Peticion del usuario del 2026-09-15: «necesito ademas un informe para equipos y para
    servidores que me indique cuantos servidores o equipos han dejado de reportar y me los
    envie en archivos diferentes, uno de equipos y otro de servidores, de manera detallada
    de proceso, hostname, IP y demas». :func:`inventario_sin_reportar` es lo que va en el
    CUERPO del correo y por eso lleva tope de filas; esto es lo que va en los dos ficheros
    adjuntos, sin tope, con todas las columnas y con las vulnerabilidades confirmadas de
    cada maquina.

    Rendimiento: dos consultas por conjuntos para todo el parque (881 activos, 178.007
    filas de aplicabilidad), nunca una consulta por activo. Las vulnerabilidades se cuentan
    con el MISMO criterio que la pagina de Activos y que :func:`estado_activos`: pares
    (activo, CVE) distintos con veredicto «afectado», sin las amenazas descartadas,
    falsos positivos ni mitigadas, sin la severidad baja y sin el riesgo aceptado.
    """
    momento = ahora or datetime.now(timezone.utc)
    umbral = _umbral_sin_reportar(cfg, momento)
    dias = int(float((cfg.get("ocs_stale_days", 30) if cfg else 30) or 30))

    excluir_bajas = bool((cfg or {}).get("ignore_low_severity", True)) if hasattr(cfg or {}, "get") else True
    viva = _AMENAZA_VIVA + (" AND (t.severity IS NULL OR t.severity <> 'Low')" if excluir_bajas else "")
    viva += excepciones.y_sin_excepcion(conn, activo="ap.activo_id", cve="ap.cve",
                                        paquete="ap.paquete")

    #: Una sola consulta para TODOS los activos que no reportan: el conteo por activo se
    #: resuelve con el indice `idx_aplic_activo`, no con una consulta por fila.
    conteos = {int(r["activo_id"]): r for r in conn.execute(
        f"""SELECT ap.activo_id AS activo_id,
                   COUNT(DISTINCT ap.cve) AS vulnerabilidades,
                   COUNT(DISTINCT CASE WHEN t.in_kev=1 THEN ap.cve END) AS kev
              FROM aplicabilidad ap
              LEFT JOIN threats t ON t.id = ap.threat_id
             WHERE ap.veredicto='afectado' AND {viva}
               AND ap.activo_id IN (SELECT id FROM activos
                                     WHERE presente=1
                                       AND (ultimo_inventario IS NULL
                                            OR ultimo_inventario < :umbral))
             GROUP BY ap.activo_id""", {"umbral": umbral})}

    totales = {r["origen"]: int(r["n"]) for r in conn.execute(
        "SELECT origen, COUNT(*) AS n FROM activos WHERE presente=1 GROUP BY origen")}

    filas_por_origen: dict[str, list[dict[str, Any]]] = {o: [] for o in ORIGENES}
    for fila in conn.execute(
            """SELECT id, origen, ocs_id, nombre, ip, usuario, grupo, descripcion,
                      so_nombre, so_version, so_familia, zona, entorno, proceso,
                      ultima_conexion, ultimo_inventario, visto_at, primera_vez_at
                 FROM activos
                WHERE presente=1 AND (ultimo_inventario IS NULL OR ultimo_inventario < ?)""",
            (umbral,)):
        origen = fila["origen"]
        if origen not in filas_por_origen:
            continue
        conteo = conteos.get(int(fila["id"]))
        nunca = not fila["ultimo_inventario"]
        dias_sin = _dias_desde(fila["ultimo_inventario"] or fila["primera_vez_at"], momento)
        filas_por_origen[origen].append({
            "id": int(fila["id"]),
            "ocs_id": fila["ocs_id"],
            "nombre": fila["nombre"],
            "ip": fila["ip"],
            "usuario": fila["usuario"],
            "grupo": fila["grupo"],
            "descripcion": fila["descripcion"],
            "so_nombre": fila["so_nombre"],
            "so_version": fila["so_version"],
            "so_familia": FAMILIA_ES.get(fila["so_familia"], fila["so_familia"]),
            "zona": fila["zona"],
            "zona_es": ZONA_ES.get(fila["zona"], fila["zona"]),
            "entorno": fila["entorno"],
            "entorno_es": ENTORNO_ES.get(fila["entorno"], fila["entorno"] or ""),
            "proceso": fila["proceso"],
            "origen": origen,
            "origen_es": ORIGEN_ES.get(origen, origen),
            "ultima_conexion": fila["ultima_conexion"],
            "ultimo_inventario": fila["ultimo_inventario"],
            "visto_at": fila["visto_at"],
            "primera_vez_at": fila["primera_vez_at"],
            "nunca": nunca,
            "dias_sin_reportar": dias_sin,
            "vulnerabilidades": int((conteo["vulnerabilidades"] if conteo else 0) or 0),
            "kev": int((conteo["kev"] if conteo else 0) or 0),
        })

    grupos = []
    for origen in ORIGENES:
        # Orden de trabajo: primero los que nunca han reportado, despues los que llevan
        # mas dias y, a igualdad de dias, los que arrastran mas vulnerabilidades
        # confirmadas (estar a oscuras pesa mas cuando ademas hay riesgo conocido).
        filas = sorted(filas_por_origen[origen],
                       key=lambda f: (0 if f["nunca"] else 1,
                                      -(f["dias_sin_reportar"] or 0),
                                      -f["vulnerabilidades"], -f["kev"],
                                      (f["nombre"] or "").lower()))
        total = totales.get(origen, 0)
        grupos.append({
            "origen": origen,
            "origen_es": ORIGEN_PLURAL_ES.get(origen, origen),
            "sin_reportar": len(filas),
            "total": total,
            "pct": round(len(filas) * 100.0 / total, 1) if total else 0.0,
            "vulnerabilidades": sum(f["vulnerabilidades"] for f in filas),
            "kev": sum(f["kev"] for f in filas),
            "nunca": sum(1 for f in filas if f["nunca"]),
            "dias_maximo": max([f["dias_sin_reportar"] or 0 for f in filas] or [0]),
            "filas": filas,
        })
    resultado = {
        "dias": dias,
        "umbral": umbral,
        "generado_at": momento.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "total": sum(g["sin_reportar"] for g in grupos),
        "activos_presentes": sum(totales.values()),
        "grupos": grupos,
    }
    log.info("inventario sin reportar detallado", extra={
        "dias": dias, "total": resultado["total"],
        "activos_presentes": resultado["activos_presentes"],
        **{g["origen"]: g["sin_reportar"] for g in grupos}})
    return resultado


def reaplicar_alias_procesos(conn: sqlite3.Connection, *, cfg: Any = None,
                             actor: str = "sistema") -> dict[str, Any]:
    """Vuelve a aplicar el mapa de alias de procesos a los activos ya guardados.

    Los alias (``PROCESOS_ALIAS`` mas el ajuste ``ocs_procesos_alias``) se aplican al
    leer OCS, asi que un alias nuevo no tendria efecto hasta la sincronizacion siguiente.
    Esta funcion lo aplica en el acto sobre ``activos.proceso``, comparando con la
    etiqueta original que OCS reporto (``etiqueta_ocs``), que es la que no se toca nunca.

    Devuelve {"cambiados": n, "por_alias": {...}} y deja constancia en la auditoria.
    """
    mapa = alias_procesos(cfg)
    if not mapa:
        return {"cambiados": 0, "por_alias": {}}
    por_alias: dict[str, int] = {}
    total = 0
    for clave, destino in mapa.items():
        filas = conn.execute(
            """SELECT id, etiqueta_ocs, proceso FROM activos
                WHERE etiqueta_ocs IS NOT NULL AND lower(trim(etiqueta_ocs)) = ?""",
            (clave,)).fetchall()
        pendientes = [f["id"] for f in filas if (f["proceso"] or "") != destino]
        if not pendientes:
            continue
        conn.executemany("UPDATE activos SET proceso=? WHERE id=?",
                         [(destino, i) for i in pendientes])
        por_alias[f"{clave} -> {destino}"] = len(pendientes)
        total += len(pendientes)
    unificados = unificar_procesos(conn, cfg=cfg, actor=actor)
    total += unificados["cambiados"]
    por_alias.update(unificados["por_grafia"])
    if total:
        db.audit(conn, actor, "ocs.alias_procesos", "activos", None,
                 f"{total} activos reasignados: "
                 + "; ".join(f"{k} ({v})" for k, v in por_alias.items()))
    return {"cambiados": total, "por_alias": por_alias,
            "por_grafia": unificados["por_grafia"]}


def unificar_procesos(conn: sqlite3.Connection, *, cfg: Any = None,
                      actor: str = "sistema") -> dict[str, Any]:
    """Unifica los procesos de negocio que solo se diferencian en tildes o mayusculas.

    ``normalizar_proceso`` lo hace al LEER de OCS Inventory, asi que a partir de la
    siguiente sincronizacion los activos presentes quedan bien; esta funcion lo aplica en
    el acto sobre lo ya guardado, incluidos los activos retirados, que ya no se vuelven a
    leer. Dentro de cada grupo de grafias gana el nombre canonico (el destino de un alias)
    y, si no hay ninguno, la grafia mas frecuente; a igualdad, la que lleva tildes.

    Medido sobre la base real el 2026-09-15: dos activos con el TAG «Servicios
    Tecnologicos» (uno presente y uno retirado) pasan a «Redes», que
    queda con 102 activos en vez de 100, y el filtro de proceso deja de ofrecer dos
    entradas para el mismo proceso.
    """
    canonicos = procesos_canonicos(cfg)
    grupos: dict[str, dict[str, int]] = {}
    for fila in conn.execute(
            "SELECT proceso, COUNT(*) AS n FROM activos "
            "WHERE proceso IS NOT NULL AND TRIM(proceso) <> '' GROUP BY proceso"):
        clave = _clave_proceso(fila["proceso"])
        grupos.setdefault(clave, {})[fila["proceso"]] = int(fila["n"] or 0)
    por_grafia: dict[str, int] = {}
    total = 0
    for clave, grafias in grupos.items():
        destino = canonicos.get(clave)
        if destino is None:
            if len(grafias) < 2:
                continue
            # Sin nombre canonico manda la grafia mas frecuente; a igualdad, la que
            # lleva tildes (es la correcta en espanol y la regla del proyecto).
            destino = sorted(grafias, key=lambda g: (-grafias[g], _sin_tildes(g) == g, g))[0]
        sobran = [g for g in grafias if g != destino]
        if not sobran or (len(grafias) == 1 and destino in grafias):
            continue
        for grafia in sobran:
            cursor = conn.execute("UPDATE activos SET proceso=? WHERE proceso=?",
                                  (destino, grafia))
            if cursor.rowcount:
                por_grafia[f"{grafia} -> {destino}"] = int(cursor.rowcount)
                total += int(cursor.rowcount)
    if total:
        db.audit(conn, actor, "ocs.unificar_procesos", "activos", None,
                 f"{total} activos reagrupados por grafia: "
                 + "; ".join(f"{k} ({v})" for k, v in por_grafia.items()))
    return {"cambiados": total, "por_grafia": por_grafia}
