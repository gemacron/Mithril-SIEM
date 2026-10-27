from django.apps import AppConfig

class MitigationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.mitigation'
    verbose_name = 'Mitigación y Bloqueo de IPs'
