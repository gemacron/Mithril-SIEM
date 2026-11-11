from django.db import migrations

def create_direct_ip_rule(apps, schema_editor):
    SecurityRule = apps.get_model('detection', 'SecurityRule')
    SecurityRule.objects.get_or_create(
        code='R-DIRECT-IP-ACCESS',
        defaults={
            'name': 'Acceso Directo por IP Pública (Bypass Cloudflare / Escaneo)',
            'description': 'Detecta y penaliza peticiones que acceden directamente a la dirección IP pública del servidor evadiendo el proxy inverso y CDN de Cloudflare.',
            'category': 'ANOMALY',
            'pattern_regex': '',
            'threshold_count': 1,
            'threshold_seconds': 30,
            'risk_points': 35,
            'is_active': True,
        }
    )

def remove_direct_ip_rule(apps, schema_editor):
    SecurityRule = apps.get_model('detection', 'SecurityRule')
    SecurityRule.objects.filter(code='R-DIRECT-IP-ACCESS').delete()

class Migration(migrations.Migration):
    dependencies = [
        ('detection', '0002_alter_trafficlog_country_code'),
    ]

    operations = [
        migrations.RunPython(create_direct_ip_rule, remove_direct_ip_rule),
    ]
