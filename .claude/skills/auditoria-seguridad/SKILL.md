---
name: auditoria-seguridad
description: "Auditoría de seguridad reproducible del sistema Inteligencia de Amenazas: dependencias (pip-audit), permisos de ficheros con secretos, cabeceras HTTP y CSP de la instancia, plantillas sin código en línea, pruebas de seguridad de la plataforma y estado de cuentas. Úsalo periódicamente y antes de entregar una funcionalidad; produce un informe con hallazgos y severidad."
---

# Auditoría de seguridad

Guion de solo lectura contra el proyecto y la instancia real (solo cabeceras y página de acceso;
nada de fuerza bruta ni carga). Los agentes `revisor-seguridad` y `pentester-interno` lo usan
como punto de partida y profundizan.

```bash
bash .claude/skills/auditoria-seguridad/scripts/auditar.sh
```

## Qué comprueba
1. **Dependencias**: `pip-audit` sobre el entorno virtual (cero vulnerabilidades conocidas) y
   versiones fijadas en `requirements.txt`.
2. **Ficheros con secretos**: `config/credentials.env` y `data/threat_intel.db` con permisos 600
   y propietario `si`; `logs/` sin valores de credenciales (búsqueda de las claves conocidas).
3. **Cabeceras de la instancia**: `Content-Security-Policy` presente y sin `unsafe-inline`,
   `unsafe-eval` ni comodines; `X-Frame-Options: DENY`; `X-Content-Type-Options: nosniff`;
   `Referrer-Policy`; cookie de sesión `HttpOnly` y `SameSite`; `Cache-Control: no-store` en
   páginas con sesión (se comprueba en la suite).
4. **Plantillas**: ninguna con `style=`, `on*=`, `<script>` en línea ni recursos externos
   (correos excluidos).
5. **Pruebas de seguridad de la plataforma**: `tests/test_seguridad_plataforma.py` (todas las
   rutas: sesión, CSRF, rol, cabeceras, XSS, XXE, cargas) y `tests/test_segundo_factor.py`.
6. **Cuentas**: usuarios, rol, estado, último acceso, segundo factor activo (sin contraseñas ni
   secretos), sesiones abiertas.
7. **Registro**: últimas entradas de `audit_log` de accesos fallidos y cambios sensibles.

## Marco
OWASP Top 10 2025 y OWASP API Security Top 10 2023 (el usuario exige estas ediciones). Riesgo
aceptado conocido: la interfaz sirve HTTP sin TLS en la red interna por decisión del usuario;
se anota siempre en el informe hasta que cambie.

## Informe
Hallazgos con severidad (crítico, alto, medio, bajo), evidencia (comando y salida), impacto y
corrección recomendada. Lo que pase se lista también, para que quede constancia de lo
comprobado y la fecha.
