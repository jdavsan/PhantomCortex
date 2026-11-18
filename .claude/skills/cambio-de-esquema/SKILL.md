---
name: cambio-de-esquema
description: "Lista de comprobación para cambiar el esquema de la base SQLite del proyecto Inteligencia de Amenazas (threatintel/db.py): versión, tablas y columnas nuevas también en las sentencias de creación, migración idempotente sin claves duplicadas, copia previa, aplicación en producción y verificación. Úsalo en cualquier cambio de tablas o columnas."
---

# Cambio de esquema (threatintel/db.py)

El esquema vive en la cadena `SCHEMA` (sentencias `CREATE TABLE IF NOT EXISTS` y `CREATE INDEX`)
y las columnas añadidas a tablas ya existentes en el diccionario `_COLUMNAS_NUEVAS`
(`{"tabla": [("columna", "TIPO Y DEFAULT"), ...]}`). `init_db()` primero ejecuta
`migrar_columnas` (ALTER TABLE de lo que falte) y después `SCHEMA`; es idempotente.

## Lista de comprobación
1. **Copia previa** de la base real con la API `backup` de sqlite3 a `backups/threat_intel_pre_<tema>_<fecha>.db`
   (propiedad `si`). Nunca se toca la base real sin copia.
2. **Versión**: subir `SCHEMA_VERSION` y comentar en el esquema la versión y la fecha («v6 (2026-09-05)»).
3. **Tablas nuevas**: añadirlas al final de `SCHEMA` con comentario de propósito por tabla y
   por columna no obvia; índices para las consultas previstas; `UNIQUE` donde la lógica lo exige.
4. **Columnas nuevas en tablas existentes**: DOS sitios obligatorios: (a) la sentencia
   `CREATE TABLE` de esa tabla en `SCHEMA` (para bases nuevas y para las pruebas) y (b)
   `_COLUMNAS_NUEVAS` (para bases existentes). Si la tabla YA tiene entrada en `_COLUMNAS_NUEVAS`,
   ampliar esa lista: una clave repetida en el diccionario hace que Python conserve solo la
   última y la migración se pierda en silencio (ocurrió el 2026-09-05 con `activos`).
5. **Sin romper lo existente**: no renombrar ni borrar columnas usadas; `NOT NULL` solo con
   `DEFAULT`; tipos coherentes con el código que lee (`TEXT` ISO para fechas).
6. **Código**: escrituras con `INSERT … ON CONFLICT … DO UPDATE` cuando hay clave única; nunca
   `INSERT OR REPLACE` en tablas con claves ajenas.
7. **Pruebas**: `db.init_db(ruta_temporal)` en la suite crea el esquema completo; añadir una
   prueba que use las columnas o tablas nuevas. Suite completa en verde.
8. **Producción**: `sudo -n -u si .venv/bin/python -c "from threatintel import db; db.init_db()"` y
   comprobar con `PRAGMA table_info(<tabla>)` y `SELECT value FROM schema_meta WHERE key='version'`.
   Reiniciar el servicio web después.
9. **Documentar**: en `README.md` (estructura de datos, si procede) y en el documento de
   diseño del área, con fecha.

## Comprobación rápida

```bash
sudo -n -u si .venv/bin/python - <<'EOF'
from threatintel import db
claves = list(db._COLUMNAS_NUEVAS)
assert len(claves) == len(set(claves)), "clave duplicada en _COLUMNAS_NUEVAS"
db.init_db(); c = db.connect()
print("versión:", c.execute("SELECT value FROM schema_meta WHERE key='version'").fetchone()[0])
for tabla, cols in db._COLUMNAS_NUEVAS.items():
    reales = {r[1] for r in c.execute(f"PRAGMA table_info({tabla})")}
    faltan = [n for n, _ in cols if n not in reales]
    print(tabla, "faltan:" if faltan else "correcta", faltan or "")
EOF
```
