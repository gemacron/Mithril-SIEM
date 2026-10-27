from django.db import models
from apps.nodes.models import ProxyNode

class SecurityRule(models.Model):
    CATEGORY_CHOICES = [
        ('SCANNER', 'Escaneo de Vulnerabilidades y Archivos'),
        ('INJECTION', 'Inyección de Código (SQLi, XSS, RCE)'),
        ('RATE_LIMIT', 'Fuerza Bruta y Ataques de Frecuencia'),
        ('TRAVERSAL', 'Path Traversal / Escape de Raíz'),
        ('ANOMALY', 'Anomalías de User-Agent / Headers'),
    ]

    code = models.CharField(max_length=32, unique=True, help_text="Ej: R-SQLI-001")
    name = models.CharField(max_length=128)
    description = models.TextField(blank=True, default='')
    category = models.CharField(max_length=32, choices=CATEGORY_CHOICES, default='SCANNER')
    pattern_regex = models.TextField(blank=True, default='', help_text="Expresión regular evaluada contra URI o payloads")
    threshold_count = models.IntegerField(default=1, help_text="Ocurrencias necesarias en la ventana de tiempo")
    threshold_seconds = models.IntegerField(default=60, help_text="Ventana de tiempo en segundos")
    risk_points = models.IntegerField(default=30, help_text="Puntos de riesgo sumados a la IP (1-100)")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['code']
        verbose_name = 'Regla de Seguridad'
        verbose_name_plural = 'Reglas de Seguridad'

    def __str__(self):
        return f"[{self.code}] {self.name} (+{self.risk_points} pts)"


class TrafficLog(models.Model):
    node = models.ForeignKey(ProxyNode, on_delete=models.SET_NULL, null=True, blank=True, related_name='logs')
    client_ip = models.GenericIPAddressField(db_index=True)
    http_method = models.CharField(max_length=10)
    uri = models.TextField()
    query_params = models.TextField(blank=True, default='')
    status_code = models.PositiveIntegerField(db_index=True)
    bytes_sent = models.PositiveIntegerField(default=0)
    latency_ms = models.FloatField(default=0.0)
    user_agent = models.TextField(blank=True, default='')
    referer = models.TextField(blank=True, default='')
    country_code = models.CharField(max_length=8, blank=True, default='', db_index=True)
    country_name = models.CharField(max_length=64, blank=True, default='')
    city = models.CharField(max_length=64, blank=True, default='')
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    raw_headers = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['client_ip', 'created_at']),
            models.Index(fields=['node', 'status_code']),
        ]

    def __str__(self):
        return f"{self.created_at} | {self.client_ip} | {self.http_method} {self.uri[:30]} [{self.status_code}]"


class SecurityEvent(models.Model):
    SEVERITY_CHOICES = [
        ('LOW', 'Baja'),
        ('MEDIUM', 'Media'),
        ('HIGH', 'Alta'),
        ('CRITICAL', 'Crítica'),
    ]

    node = models.ForeignKey(ProxyNode, on_delete=models.SET_NULL, null=True, blank=True)
    rule = models.ForeignKey(SecurityRule, on_delete=models.SET_NULL, null=True, blank=True)
    client_ip = models.GenericIPAddressField(db_index=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='MEDIUM')
    matched_payload = models.TextField(blank=True, default='')
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.severity}] {self.client_ip} detonó {self.rule.code if self.rule else 'Heurística'}"
