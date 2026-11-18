# Revisión de seguridad y coherencia del sistema nuevo

**Fecha:** 3 de septiembre de 2026
**Alcance:** el sistema reescrito el 2 y 3 de septiembre — `threatintel/` (19 módulos), `webui/` (Flask, 15 plantillas), `bin/` (10 ejecutables), scripts de backup, cron y servicio systemd
**Método:** cada comprobación se **ejecutó** contra una copia de la base de datos o contra el servicio en marcha. No hay hallazgos por lectura de código sin prueba.

---

## 1. Resumen

| Resultado | Cantidad |
|---|---|
| **Defectos confirmados y corregidos** | 6 |
| Controles verificados como correctos | 9 |
| Riesgos aceptados y documentados | 4 |
| Pruebas de regresión añadidas | 6 (total 51, todas pasan) |

Ninguno de los seis defectos permitía acceso sin autenticación ni fuga de secretos. Dos eran vulnerabilidades web de severidad media en una herramienta interna; los otros cuatro eran incoherencias operativas, dos de ellas graves para la recuperación ante desastre.

---

## 2. Defectos confirmados y corregidos

### 2.1 Redirección abierta en el inicio de sesión — media

**Dónde:** `webui/vistas/sesion.py`, parámetro `siguiente`.

**Prueba:** `POST /login?siguiente=//evil.com/` con credenciales válidas redirigía a `//evil.com/`. La comprobación `startswith("/")` aceptaba el valor porque empieza por barra, pero el navegador interpreta `//host` como URL con esquema relativo, es decir, un dominio externo.

**Impacto real:** un enlace de phishing a la interfaz interna podría, tras el login legítimo, redirigir al operador a un sitio externo. Requiere que la víctima pulse el enlace y se autentique.

**Corrección:** `_destino_seguro()` exige ruta local de una sola barra, sin `\`, sin `://`, sin caracteres de control, y **que coincida con una ruta registrada** en la aplicación. Probado con 12 cargas: todas las externas van a `/`, las locales legítimas se respetan (incluida la cadena de consulta).

### 2.2 XSS por esquema `javascript:` en enlaces de fuente — media

**Dónde:** `webui/templates/amenaza_detalle.html:183`, `href="{{ s.url }}"`.

**Prueba:** se insertó `javascript:alert(document.cookie)` en `threat_sources.url` (el campo que rellena el recolector con datos **de terceros**) y la página `/amenazas/1` lo sirvió intacto en el `href`. El autoescape de Jinja2 escapa caracteres, no valida esquemas.

**Impacto real:** un feed RSS comprometido podría inyectar un enlace que, al pulsarlo el operador, ejecutaría código en el contexto de su sesión. Requiere control sobre una fuente y una acción del operador.

**Corrección:** el filtro `url_segura` ya existía para los correos pero no se había aplicado a la interfaz. Registrado en `webui/filtros.py` y aplicado a todos los `href` con datos dinámicos. Se añadió `rel="noopener noreferrer"` a los enlaces con `target="_blank"`.

### 2.3 Ajuste `log_retention_days` sin efecto — coherencia

**Prueba:** `grep` de la clave en `threatintel/`, `bin/` y `webui/`: **nadie la leía**. El cron borraba logs con un `find -mtime +30` fijo. Cambiar el ajuste en la interfaz no hacía nada — exactamente el defecto que la auditoría reprochó al sistema anterior, donde 46 de 54 variables eran decorativas.

**Corrección:** `health.limpiar_logs()` lee el ajuste; `bin/limpiar.py` lo aplica; el cron de los domingos lo invoca en lugar del `find`. Se añadieron además 7 ajustes que existían pero no se mostraban (`report_max_anexo_items`, `ollama_timeout_s`, `nvd_rate_limit_sleep_s`, `http_user_agent`…). Verificación final: **34 ajustes mostrados, 34 leídos por el código, 0 huérfanos**.

### 2.4 El backup no incluía el sistema nuevo — grave

**Prueba:** `tar -tzf` del backup del 3 de septiembre: contenía `argos_model/`, `config/`, `data/`, `logs/`, `reports/` y `scripts/` con los **10 ficheros del sistema viejo**. `threatintel/`, `webui/`, `bin/` y `tests/`: **ausentes**. Un backup que no habría permitido restaurar nada.

**Causa:** `create_backup.sh` listaba los scripts a mano.

**Corrección:** respalda el árbol completo (`threatintel/`, `webui/`, `bin/`, `tests/`, `docs/`, `obsoleto/`, `requirements.txt`, `README.md`) y la unidad systemd. **Verificado restaurando en un directorio temporal e importando los módulos restaurados.** `restore_backup.sh` actualizado en consecuencia.

### 2.5 Indicador del panel incoherente — coherencia

**Prueba:** el panel decía «52 de 80 fuentes operativas». El denominador eran las 80 registradas (23 desactivadas incluidas) y las 3 API nunca se comprobaban.

**Corrección:** `collector.comprobar_apis()` verifica CISA KEV, NVD y EPSS en cada ejecución; `health.resumen_sistema()` separa feeds de API; el panel dice «55 de 55 fuentes activas operativas» con desglose.

### 2.6 Fechas ISO sin zona horaria se saltaban el filtro — baja

**Prueba:** `2026-08-25T14:00:00` (sin `Z` ni desfase) devolvía `None` en `collector._fecha_entrada()`. Una entrada sin fecha reconocible **se acepta sin pasar por la ventana de 45 días** — el mismo tipo de fuga que tenía `is_current_month()` en el sistema anterior.

**Corrección:** añadidos los formatos sin zona (se asumen UTC), con milisegundos y con `/`.

---

## 3. Controles verificados como correctos

| Control | Prueba ejecutada | Resultado |
|---|---|---|
| **CSRF** | `POST` sin token a las 23 rutas de escritura; token de otra sesión | 23/23 devuelven `400`; token cruzado rechazado |
| **Inyección SQL** | 5 cargas (`' OR '1'='1`, `; DROP TABLE`, `UNION SELECT`…) en búsqueda, filtros e interfaz | Todas tratadas como texto; tablas y recuentos intactos |
| **Fugas de secretos** | Valores reales de `SMTP_PASSWORD`, `BACKUP_PASSPHRASE`, `NIST_NVD_API_KEY`, `OFFSEC_RADAR_TOKEN` buscados en logs, `audit_log`, `settings`, `executions` y en el HTML de 6 páginas | 0 apariciones |
| **Autenticación** | Todas las rutas `GET` sin sesión | Solo `/login` responde 200 |
| **`/salud.json`** | Sin token ni sesión | `403` |
| **Autorización** | Usuario `viewer` contra 3 páginas y 5 acciones de administrador | 8/8 denegadas con `403` |
| **Fijación de sesión** | `iniciar_sesion()` | Llama a `session.clear()` antes de asignar la identidad |
| **Zonas horarias** | 6 formatos de fecha comparados con el límite UTC | Todas quedan en UTC; sin comparaciones mixtas |
| **Falsos negativos de versión** | 16 textos reales de avisos contra `versions.evaluar()` | 15/16 correctos; el único fallo es un **falso positivo** (dirección segura) |
| **Rendimiento del matching** | 5.837 textos reales | 1,08 ms por entrada, lineal; regex compilados una vez (12 ms) |
| **Coherencia de esquema** | 204 sentencias SQL extraídas por AST contra las 16 tablas | 0 discrepancias reales |
| **Permisos** | `sudo -u nobody` contra `credentials.env`, `threat_intel.db`, `data/`, `logs/` | Ninguno legible |
| **Integridad de la base** | `PRAGMA integrity_check` y `foreign_key_check` | `ok`, 0 violaciones |

---

## 4. Riesgos aceptados y documentados

| Riesgo | Situación | Mitigación existente |
|---|---|---|
| **Borrado en cascada** | Eliminar una tecnología pierde sus correlaciones (2.092 en el caso de Windows); eliminar una fuente pierde su procedencia | Las amenazas se conservan. El diálogo de confirmación **ahora informa de la cantidad exacta** que se perderá y sugiere «Desactivar» como alternativa |
| **HTTP sin TLS** | La contraseña de acceso viaja en claro por la LAN | Decisión explícita del responsable. TLS autofirmado disponible bajo demanda |
| **`ufw` inactivo** | El puerto 9090 es alcanzable desde toda la red interna | Autenticación obligatoria, bloqueo tras 5 intentos, sesión de 8 horas |
| **CSP con `'unsafe-inline'`** | Necesario porque las plantillas usan `onclick` en línea para mostrar formularios | Sin JavaScript de terceros; `frame-ancestors 'none'`; `form-action 'self'` |
| **Scripts antiguos en la raíz** | Podrían ejecutarse por costumbre | Sustituidos por avisos que abortan con código 1; originales en `obsoleto/` |

---

## 5. Lo que este documento no cubre

- **Dependencias con CVE conocidos.** No se ha hecho una comprobación fiable contra bases de vulnerabilidades de los 9 paquetes de `requirements.txt`. Se recomienda `pip-audit` con acceso a PyPI.
- **Revisión externa.** Todas las pruebas las ha ejecutado el mismo autor del código. Una segunda revisión independiente encontraría cosas que una autorrevisión no ve.
- **Pruebas de carga.** Un solo usuario administrador; no se ha probado concurrencia de varios operadores en la interfaz.

---

## 6. Método, para reproducir

```bash
# CSRF en todas las rutas POST, XSS en href, redirección, /salud.json
.venv/bin/python -m unittest tests.test_regresiones.TestSeguridadInterfaz -v

# Rendimiento del matching
.venv/bin/python -c "..."   # ver §3, 5.837 textos

# Permisos
sudo -u nobody test -r config/credentials.env && echo FALLO || echo OK

# Backup restaurable
./create_backup.sh && tar -tzf backups/$(ls -t backups | head -1) | grep codigo/threatintel
```

---

*Todas las correcciones están aplicadas y el servicio reiniciado. 51 pruebas pasan.*
