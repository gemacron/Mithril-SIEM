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

        # 2. Reglas de detección predeterminadas para Proxies Nginx
        default_rules = [
            {
                'code': 'R-ENV-SCAN',
                'name': 'Escaneo de Variables de Entorno (.env)',
                'description': 'Intento de descarga de archivos sensibles de configuración .env o .git',
                'category': 'SCANNER',
                'pattern_regex': r'(\.env|\.git/|\.aws/|\.ssh/|\.docker/)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 55,
            },
            {
                'code': 'R-SQLI-URL',
                'name': 'Inyección SQL en Parámetros URL',
                'description': 'Patrones SQL maliciosos típicos en query string (UNION SELECT, OR 1=1)',
                'category': 'INJECTION',
                'pattern_regex': r'(union(\s+)select|or(\s+)1=1|waitfor(\s+)delay|benchmark\(|pg_sleep)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 50,
            },
            {
                'code': 'R-PATH-TRAVERSAL',
                'name': 'Path Traversal (Salto de Directorio)',
                'description': 'Intento de escapar de la raíz web hacia el sistema (/etc/passwd, ../../)',
                'category': 'TRAVERSAL',
                'pattern_regex': r'(\.\./|\.\.\\|etc/passwd|win\.ini|windows/system32)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 60,
            },
            {
                'code': 'R-SCAN-404-BRUTE',
                'name': 'Fuerza Bruta / Enumeración de Directorios',
                'description': 'Acumulación anómala de errores 404 en corto lapso de tiempo',
                'category': 'SCANNER',
                'pattern_regex': '',
                'threshold_count': 15,
                'threshold_seconds': 60,
                'risk_points': 40,
            },
            {
                'code': 'R-AUTH-BRUTE-401',
                'name': 'Fuerza Bruta de Autenticación (401/403)',
                'description': 'Múltiples respuestas 401 Unauthorized o 403 Forbidden a endpoints de login',
                'category': 'RATE_LIMIT',
                'pattern_regex': r'(login|auth|admin|signin|token|session)',
                'threshold_count': 6,
                'threshold_seconds': 60,
                'risk_points': 45,
            },
            {
                'code': 'R-BAD-USER-AGENT',
                'name': 'Herramientas Automatizadas de Escaneo',
                'description': 'User-Agents asociados a herramientas ofensivas conocidas (sqlmap, nikto, dirbuster)',
                'category': 'ANOMALY',
                'pattern_regex': r'(sqlmap|nikto|dirbuster|gobuster|masscan|zgrab|nmap|acunetix)',
                'threshold_count': 1,
                'threshold_seconds': 60,
                'risk_points': 40,
            },
        ]

        created_rules_count = 0
        for r_data in default_rules:
            _, r_created = SecurityRule.objects.get_or_create(code=r_data['code'], defaults=r_data)
            if r_created:
                created_rules_count += 1

        self.stdout.write(self.style.SUCCESS(
            f"✅ Reglas de seguridad configuradas ({created_rules_count} nuevas)."
        ))
