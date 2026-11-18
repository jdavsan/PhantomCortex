#!/usr/bin/env bash
# Auditoría de seguridad de solo lectura del proyecto y de la instancia web.
# Uso: auditar.sh [BASE_URL]   (por defecto http://127.0.0.1:9090)
set -uo pipefail
PROYECTO=/opt/inteligencia_amenazas
cd "$PROYECTO" || exit 2
BASE="${1:-http://127.0.0.1:9090}"
PY="sudo -n -u si $PROYECTO/.venv/bin/python"
HALLAZGOS=0
falla() { echo "  [HALLAZGO] $*"; HALLAZGOS=$((HALLAZGOS + 1)); }
ok() { echo "  [correcto] $*"; }

echo "== 1. Dependencias (pip-audit) =="
if sudo -n -u si "$PROYECTO/.venv/bin/pip-audit" --progress-spinner off >/tmp/audit_pip.txt 2>&1; then ok "sin vulnerabilidades conocidas"; else falla "pip-audit informa de problemas:"; tail -20 /tmp/audit_pip.txt; fi
rm -f /tmp/audit_pip.txt
sinfijar=$(grep -vE '^\s*(#|$)' requirements.txt | grep -vE '==' || true)
[ -z "$sinfijar" ] && ok "todas las dependencias fijadas con ==" || falla "dependencias sin fijar: $sinfijar"

echo "== 2. Ficheros con secretos =="
for f in config/credentials.env data/threat_intel.db; do
  if [ -e "$f" ]; then
    perm=$(stat -c %a "$f"); prop=$(stat -c %U:%G "$f")
    { [ "$perm" = "600" ] && [ "$prop" = "si:si" ]; } && ok "$f $perm $prop" || falla "$f permisos $perm propietario $prop (esperado 600 si:si)"
  fi
done
# solo las variables que guardan secretos (contraseñas, claves, tokens); servidores y correos no lo son
claves=$(grep -oE '^[A-Z_]*(PASS|KEY|TOKEN|SECRET|CLAVE)[A-Z_]*=' config/credentials.env 2>/dev/null | grep -vE 'API_URL' | tr -d '=' | head -20)
fugas=0
for k in $claves; do
  v=$(grep -E "^$k=" config/credentials.env | cut -d= -f2- | tr -d '"' | head -1)
  [ ${#v} -ge 6 ] && grep -rqF -- "$v" logs/ 2>/dev/null && { falla "valor de $k aparece en logs/"; fugas=1; }
done
[ $fugas -eq 0 ] && ok "ningún valor de credenciales en logs/"

echo "== 3. Cabeceras de la instancia ($BASE) =="
cab=$(curl -s -D - -o /dev/null -m 15 "$BASE/login" 2>/dev/null)
if [ -z "$cab" ]; then falla "sin respuesta de $BASE/login"; else
  csp=$(echo "$cab" | grep -i '^content-security-policy:' || true)
  [ -n "$csp" ] && ok "CSP presente" || falla "sin Content-Security-Policy"
  echo "$csp" | grep -qiE "unsafe-inline|unsafe-eval|\*" && falla "CSP con unsafe-* o comodín: $csp" || ok "CSP sin unsafe-* ni comodines"
  echo "$cab" | grep -qi '^x-frame-options: *deny' && ok "X-Frame-Options: DENY" || falla "X-Frame-Options ausente o distinto de DENY"
  echo "$cab" | grep -qi '^x-content-type-options: *nosniff' && ok "X-Content-Type-Options: nosniff" || falla "X-Content-Type-Options ausente"
  echo "$cab" | grep -qi '^referrer-policy:' && ok "Referrer-Policy presente" || falla "Referrer-Policy ausente"
  echo "$cab" | grep -qi '^set-cookie:.*httponly' && ok "cookie HttpOnly" || echo "  [aviso] la página de acceso no emite cookie de sesión (normal sin autenticar)"
  echo "$BASE" | grep -q '^http://' && echo "  [riesgo aceptado] HTTP sin TLS en la red interna (decisión del usuario)"
fi

echo "== 4. Plantillas web sin código en línea =="
inl=$(grep -nE '\sstyle="|\son[a-z]+="' webui/templates/*.html 2>/dev/null || true)
[ -z "$inl" ] && ok "sin style= ni on*= en plantillas" || { falla "código en línea en plantillas:"; echo "$inl" | head -10; }
# recursos que el navegador cargaría (scripts, hojas, imágenes, fuentes); los enlaces <a href> a NVD o CVE.org son legítimos
ext=$(grep -nE '<(script|img|iframe|source|video|audio)[^>]+src="https?://|<link[^>]+href="https?://|url\(https?://' webui/templates/*.html 2>/dev/null || true)
[ -z "$ext" ] && ok "sin recursos externos cargados por las plantillas" || { falla "recursos externos:"; echo "$ext" | head -5; }

echo "== 5. Pruebas de seguridad de la plataforma =="
salida=$($PY -m unittest tests.test_seguridad_plataforma 2>&1 | tail -3)
echo "$salida" | grep -q "^OK" && ok "tests.test_seguridad_plataforma OK" || { falla "tests.test_seguridad_plataforma falla"; echo "$salida"; }
if [ -f tests/test_segundo_factor.py ]; then
  salida=$($PY -m unittest tests.test_segundo_factor 2>&1 | tail -3)
  echo "$salida" | grep -q "^OK" && ok "tests.test_segundo_factor OK" || { falla "tests.test_segundo_factor falla"; echo "$salida"; }
fi

echo "== 6. Cuentas y sesiones (solo lectura) =="
$PY - <<'EOF'
import sqlite3
c = sqlite3.connect("file:data/threat_intel.db?mode=ro", uri=True); c.row_factory = sqlite3.Row
cols = {r[1] for r in c.execute("PRAGMA table_info(users)")}
extra = ", CASE WHEN totp_activado_at IS NULL THEN 'no' ELSE 'sí' END AS segundo_factor" if "totp_activado_at" in cols else ""
for r in c.execute(f"SELECT username, role, enabled, last_login_at, failed_logins, locked_until{extra} FROM users ORDER BY username"):
    print("  ", dict(r))
n = c.execute("SELECT COUNT(*) FROM web_sessions WHERE expires_at > strftime('%Y-%m-%dT%H:%M:%SZ','now')").fetchone()[0]
print("   sesiones vigentes:", n)
for r in c.execute("SELECT at, username, action, detail FROM audit_log WHERE action LIKE 'login.fallo%' OR action LIKE '%2fa%' ORDER BY id DESC LIMIT 8"):
    print("  ", dict(r))
EOF

echo "== Resultado: $HALLAZGOS hallazgo(s) =="
exit $(( HALLAZGOS > 0 ? 1 : 0 ))
