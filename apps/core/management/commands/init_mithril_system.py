import os
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from apps.core.models import UserProfile
from apps.detection.models import SecurityRule

class Command(BaseCommand):
    help = 'Inicializa la cuenta de administrador con cambio obligatorio de contraseña y las reglas de seguridad'

    def handle(self, *args, **options):
        # 1. Crear o verificar usuario root inicial
        admin_username = os.getenv('MITHRIL_INIT_ADMIN_USER', 'admin')
        admin_password = os.getenv('MITHRIL_INIT_ADMIN_PASSWORD', 'MithrilSecurity2026!')
        admin_email = os.getenv('MITHRIL_INIT_ADMIN_EMAIL', 'security@mithril.local')

        user, created = User.objects.get_or_create(username=admin_username, defaults={
            'email': admin_email,
            'is_staff': True,
            'is_superuser': True,
        })

        if created:
            user.set_password(admin_password)
            user.save()
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.must_change_password = True
            profile.has_completed_2fa = False
            profile.save()
            self.stdout.write(self.style.SUCCESS(
                f"✅ Usuario administrador '{admin_username}' creado con cambio obligatorio de contraseña."
            ))
        else:
            self.stdout.write(self.style.NOTICE(f"ℹ️ El usuario administrador '{admin_username}' ya existe."))

        # 2. Reglas universales de detección y heurística para cualquier topología Nginx
        default_rules = [
            {
                'code': 'R-ENV-SCAN',
                'name': 'Escaneo de Archivos Sensibles, Backups y Config (.env / .git / wp-config)',
                'description': 'Intento de acceso a archivos críticos (.env, .git, backups .sql/.bak, phpinfo, wp-config, actuator)',
                'category': 'SCANNER',
                'pattern_regex': r'(\.env|\.git/|\.aws/|\.ssh/|\.docker/|wp-config\.php|phpinfo|\.sql(\.gz|\.bz2|\.zip)?$|\.bak$|\.htaccess|/actuator/env|/server-status)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 55,
            },
            {
                'code': 'R-SQLI-URL',
                'name': 'Inyección SQL (SQLi) en URI o Parámetros',
                'description': 'Patrones SQL maliciosos (UNION SELECT, OR 1=1, SLEEP, BENCHMARK, INFORMATION_SCHEMA, pg_sleep)',
                'category': 'INJECTION',
                'pattern_regex': r'(union\s+(all\s+)?select|or\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1|waitfor\s+delay|benchmark\s*\(|pg_sleep|\bsleep\s*\(\d+|information_schema|extractvalue\s*\(|concat\s*\(.*select)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 55,
            },
            {
                'code': 'R-PATH-TRAVERSAL',
                'name': 'Path Traversal / Inclusión de Archivos Locales (LFI)',
                'description': 'Intento de escapar de la raíz web hacia archivos del sistema (../, /etc/passwd, /proc/self, win.ini)',
                'category': 'TRAVERSAL',
                'pattern_regex': r'(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/|win\.ini|boot\.ini|windows/system32)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 60,
            },
            {
                'code': 'R-XSS-PAYLOAD',
                'name': 'Cross-Site Scripting (XSS) en URL, Query o Headers',
                'description': 'Vectores de inyección de scripts (<script>, javascript:, onerror=, onload=, svg/onload, document.cookie)',
                'category': 'INJECTION',
                'pattern_regex': r'(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*onload|alert\s*\(|document\.cookie|eval\s*\()',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 50,
            },
            {
                'code': 'R-RCE-CMD',
                'name': 'Inyección de Comandos / RCE / Log4Shell / Shellshock',
                'description': 'Intentos de ejecución remota de comandos de sistema, JNDI lookup o bash injection',
                'category': 'INJECTION',
                'pattern_regex': r'(\$\{jndi:|;\s*(cat|ls|whoami|id|wget|curl|bash|sh|nc|python|perl)\b|\|\s*(bash|sh|nc|wget|curl)\b|`(whoami|id|uname)|\(\)\s*\{\s*:;\s*\})',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 80,
            },
            {
                'code': 'R-SSRF-METADATA',
                'name': 'SSRF y Acceso a Metadatos Cloud / Loopback Interno',
                'description': 'Intentos de Server-Side Request Forgery hacia 169.254.169.254, esquemas file://, gopher:// o dict://',
                'category': 'INJECTION',
                'pattern_regex': r'(169\.254\.169\.254|metadata\.google\.internal|file://|gopher://|dict://|ldap://127\.)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 70,
            },
            {
                'code': 'R-BAD-USER-AGENT',
                'name': 'Herramientas Automatizadas de Escaneo y Explotación',
                'description': 'User-Agents asociados a escáneres ofensivos (sqlmap, nikto, nuclei, nmap, masscan, gobuster, wfuzz)',
                'category': 'ANOMALY',
                'pattern_regex': r'(sqlmap|nikto|dirbuster|gobuster|masscan|zgrab|nmap|acunetix|nuclei|wfuzz|ffuf|nessus|openvas|hydra|burpsuite)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 45,
            },
            {
                'code': 'R-SCAN-404-BRUTE',
                'name': 'Heurística de Enumeración de Directorios (Ráfaga 404)',
                'description': 'Acumulación anómala de respuestas 404 Not Found desde una misma IP en corto lapso de tiempo',
                'category': 'SCANNER',
                'pattern_regex': '',
                'threshold_count': 15,
                'threshold_seconds': 60,
                'risk_points': 40,
            },
            {
                'code': 'R-AUTH-BRUTE-401',
                'name': 'Heurística de Fuerza Bruta de Autenticación (401/403)',
                'description': 'Múltiples respuestas 401 Unauthorized o 403 Forbidden en endpoints de acceso o API',
                'category': 'RATE_LIMIT',
                'pattern_regex': r'(login|auth|admin|signin|token|session|api|wp-login|xmlrpc)',
                'threshold_count': 6,
                'threshold_seconds': 60,
                'risk_points': 45,
            },
            {
                'code': 'R-HTTP-FLOOD-DOS',
                'name': 'Heurística Anti-Flood / Ráfaga DoS por IP (Capa 7)',
                'description': 'Volumen excesivo de peticiones HTTP desde una única IP superando el límite por minuto',
                'category': 'RATE_LIMIT',
                'pattern_regex': '',
                'threshold_count': 120,
                'threshold_seconds': 60,
                'risk_points': 60,
            },
        ]

        created_rules_count = 0
        for r_data in default_rules:
            obj, r_created = SecurityRule.objects.get_or_create(code=r_data['code'], defaults=r_data)
            if r_created:
                created_rules_count += 1
            else:
                # Actualizar expresión regular mejorada manteniendo el estado activo/inactivo del operador
                obj.name = r_data['name']
                obj.description = r_data['description']
                obj.pattern_regex = r_data['pattern_regex']
                obj.save(update_fields=['name', 'description', 'pattern_regex'])

        self.stdout.write(self.style.SUCCESS(
            f"✅ Reglas de seguridad configuradas ({created_rules_count} nuevas)."
        ))
