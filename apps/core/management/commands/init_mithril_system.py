import os
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from apps.core.models import UserProfile
from apps.detection.models import SecurityRule
from apps.detection.engine import (
    _probe_own_public_wan_worker,
    get_own_public_wan_ips,
    get_own_internal_infra_ips,
    resolve_geoip,
)
from apps.mitigation.models import IpReputation, BanCandidate

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
                'description': 'Intento de acceso a archivos críticos (.env, .git, backups .sql/.bak, phpinfo, wp-admin, phpmyadmin, actuator)',
                'category': 'SCANNER',
                'pattern_regex': r'(\.env|\.git/|/\.git|\.aws/|\.ssh/|\.docker/|wp-config|wp-login\.php|wp-admin|xmlrpc\.php|phpmyadmin|pma/|myadmin|adminer|phpinfo|\.sql(\.gz|\.bz2|\.zip)?$|\.bak$|\.old$|\.swp$|\.htaccess|/actuator|/server-status|vendor/phpunit|eval-stdin\.php|boaform|cgi-bin|nmaplowercheck|/sdk|/evox/about|/HNAP1|/GponForm|/shell|cmd\.php|cmd\.jsp|owa/auth|autodiscover|/solr/)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 80,
            },
            {
                'code': 'R-SQLI-URL',
                'name': 'Inyección SQL (SQLi) en URI o Parámetros',
                'description': 'Patrones SQL maliciosos (UNION SELECT, OR 1=1, SLEEP, BENCHMARK, INFORMATION_SCHEMA, pg_sleep)',
                'category': 'INJECTION',
                'pattern_regex': r'(union\s+(all\s+)?select|or\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1|waitfor\s+delay|benchmark\s*\(|pg_sleep|\bsleep\s*\(\d+|information_schema|extractvalue\s*\(|concat\s*\(.*select)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 85,
            },
            {
                'code': 'R-PATH-TRAVERSAL',
                'name': 'Path Traversal / Inclusión de Archivos Locales (LFI)',
                'description': 'Intento de escapar de la raíz web hacia archivos del sistema (../, /etc/passwd, /proc/self, win.ini)',
                'category': 'TRAVERSAL',
                'pattern_regex': r'(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/|win\.ini|boot\.ini|windows/system32)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 85,
            },
            {
                'code': 'R-XSS-PAYLOAD',
                'name': 'Cross-Site Scripting (XSS) en URL, Query o Headers',
                'description': 'Vectores de inyección de scripts (<script>, javascript:, onerror=, onload=, svg/onload, document.cookie)',
                'category': 'INJECTION',
                'pattern_regex': r'(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*onload|alert\s*\(|document\.cookie|eval\s*\()',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 80,
            },
            {
                'code': 'R-RCE-CMD',
                'name': 'Inyección de Comandos / RCE / Log4Shell / Shellshock',
                'description': 'Intentos de ejecución remota de comandos de sistema, JNDI lookup o bash injection',
                'category': 'INJECTION',
                'pattern_regex': r'(\$\{jndi:|;\s*(cat|ls|whoami|id|wget|curl|bash|sh|nc|python|perl)\b|\|\s*(bash|sh|nc|wget|curl)\b|`(whoami|id|uname)|\(\)\s*\{\s*:;\s*\})',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 95,
            },
            {
                'code': 'R-SSRF-METADATA',
                'name': 'SSRF y Acceso a Metadatos Cloud / Loopback Interno',
                'description': 'Intentos de Server-Side Request Forgery hacia 169.254.169.254, esquemas file://, gopher:// o dict://',
                'category': 'INJECTION',
                'pattern_regex': r'(169\.254\.169\.254|metadata\.google\.internal|file://|gopher://|dict://|ldap://127\.)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 85,
            },
            {
                'code': 'R-BAD-USER-AGENT',
                'name': 'Herramientas Automatizadas de Escaneo y Explotación',
                'description': 'User-Agents asociados a escáneres ofensivos (sqlmap, nikto, nuclei, nmap, masscan, gobuster, wfuzz)',
                'category': 'ANOMALY',
                'pattern_regex': r'(sqlmap|nikto|dirbuster|gobuster|masscan|zgrab|nmap|acunetix|nuclei|wfuzz|ffuf|nessus|openvas|hydra|burpsuite)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 80,
            },
            {
                'code': 'R-SCAN-404-BRUTE',
                'name': 'Heurística de Enumeración de Directorios (Ráfaga 404)',
                'description': 'Acumulación anómala de respuestas 404 Not Found en rutas distintas desde una misma IP en corto lapso de tiempo',
                'category': 'SCANNER',
                'pattern_regex': '',
                'threshold_count': 10,
                'threshold_seconds': 60,
                'risk_points': 80,
            },
            {
                'code': 'R-AUTH-BRUTE-401',
                'name': 'Heurística de Fuerza Bruta de Autenticación (401/403)',
                'description': 'Múltiples respuestas 401 Unauthorized o 403 Forbidden en endpoints de acceso o API',
                'category': 'RATE_LIMIT',
                'pattern_regex': r'(login|auth|admin|signin|token|session|api|wp-login|xmlrpc)',
                'threshold_count': 3,
                'threshold_seconds': 60,
                'risk_points': 80,
            },
            {
                'code': 'R-XXE-SSTI',
                'name': 'Inyección de Plantillas (SSTI) / Entidades XML Externas (XXE)',
                'description': 'Intentos de Server-Side Template Injection ({{7*7}}, __class__, __subclasses__) o XXE (<!ENTITY, <!DOCTYPE)',
                'category': 'INJECTION',
                'pattern_regex': r'(<!entity\s+|<!doctype\s+[^>]*\[|{{\s*[\w\.\[\]\'\"]*(__class__|__mro__|__subclasses__|__globals__|config|self\.)|{{\s*\d+\s*[\*\+\-]\s*\d+\s*}}|\$\{\s*\d+\s*\*\s*\d+\s*\})',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 90,
            },
            {
                'code': 'R-DIRECT-IP-ACCESS',
                'name': 'Acceso / Escaneo Directo a IP Pública (Evasión de Cloudflare/DNS)',
                'description': 'Peticiones directas a la IP pública del servidor con cabecera Host vacía o IP cruda intentando evadir el WAF/CDN',
                'category': 'SCANNER',
                'pattern_regex': '',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 80,
            },
            {
                'code': 'R-HTTP-FLOOD-DOS',
                'name': 'Heurística Anti-Flood / Ráfaga DoS por IP (Capa 7)',
                'description': 'Volumen excesivo de peticiones HTTP desde una única IP superando el límite por minuto',
                'category': 'RATE_LIMIT',
                'pattern_regex': '',
                'threshold_count': 300,
                'threshold_seconds': 60,
                'risk_points': 80,
            },
        ]

        created_rules_count = 0
        for r_data in default_rules:
            obj, r_created = SecurityRule.objects.get_or_create(code=r_data['code'], defaults=r_data)
            if r_created:
                created_rules_count += 1
            else:
                obj.name = r_data['name']
                obj.description = r_data['description']
                obj.pattern_regex = r_data['pattern_regex']
                if obj.code in ('R-HTTP-FLOOD-DOS', 'R-SCAN-404-BRUTE'):
                    obj.threshold_count = max(obj.threshold_count, r_data['threshold_count'])
                else:
                    obj.threshold_count = min(obj.threshold_count, r_data['threshold_count'])
                obj.risk_points = max(obj.risk_points, r_data['risk_points'])
                obj.save(update_fields=['name', 'description', 'pattern_regex', 'threshold_count', 'risk_points'])

        self.stdout.write(self.style.SUCCESS(
            f"✅ Reglas de seguridad configuradas ({created_rules_count} nuevas)."
        ))

        # 3. Autodescubrir y proteger dinámicamente IPs propias de infraestructura (WAN Propia y Nodos Internos)
        try:
            _probe_own_public_wan_worker()
            own_wan_ips = get_own_public_wan_ips()
            internal_ips = get_own_internal_infra_ips()

            for ip_addr in own_wan_ips:
                geo = resolve_geoip(ip_addr)
                IpReputation.objects.update_or_create(
                    client_ip=ip_addr,
                    defaults={
                        'status': 'WHITELISTED',
                        'current_risk_score': 0,
                        'country_code': str(geo.get('country_code') or '')[:8],
                        'asn': 'OWN_INFRASTRUCTURE',
                    }
                )
                BanCandidate.objects.filter(client_ip=ip_addr, status='PENDING').update(status='DISMISSED')

            for ip_addr in internal_ips:
                IpReputation.objects.update_or_create(
                    client_ip=ip_addr,
                    defaults={
                        'status': 'WHITELISTED',
                        'current_risk_score': 0,
                        'country_code': 'LAN',
                        'asn': 'OWN_INFRASTRUCTURE',
                    }
                )
                BanCandidate.objects.filter(client_ip=ip_addr, status='PENDING').update(status='DISMISSED')

            self.stdout.write(self.style.SUCCESS(
                f"✅ Autodescubrimiento de infraestructura completado (WAN Propia: {len(own_wan_ips)}, Nodos Internos: {len(internal_ips)})."
            ))
        except Exception as exc:
            self.stdout.write(self.style.WARNING(f"⚠️ Aviso en autodescubrimiento de infraestructura: {exc}"))
