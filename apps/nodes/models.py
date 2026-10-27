import uuid
import secrets
from django.db import models
from django.utils import timezone

class ProxyNode(models.Model):
    STATUS_CHOICES = [
        ('ONLINE', 'En Línea'),
        ('DEGRADED', 'Degradado / Alto Tráfico'),
        ('OFFLINE', 'Desconectado'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=64, unique=True, help_text="Ej: proxy-edge-us-east-01")
    description = models.TextField(blank=True, default="")
    ip_address = models.GenericIPAddressField(help_text="IP del servidor proxy Nginx")
    location_label = models.CharField(max_length=64, blank=True, default="Datacenter Principal")
    api_key = models.CharField(max_length=64, unique=True, editable=False)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='OFFLINE')
    current_rps = models.IntegerField(default=0, help_text="Peticiones por segundo procesadas")
    total_logs_processed = models.BigIntegerField(default=0)
    last_heartbeat = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = f"mithril_node_{secrets.token_hex(24)}"
        super().save(*args, **kwargs)

    def update_heartbeat(self, rps=0):
        self.last_heartbeat = timezone.now()
        self.current_rps = rps
        self.status = 'ONLINE'
        self.save(update_fields=['last_heartbeat', 'current_rps', 'status'])

    def check_health(self):
        if not self.last_heartbeat:
            return 'OFFLINE'
        diff = (timezone.now() - self.last_heartbeat).total_seconds()
        if diff > 120:
            if self.status != 'OFFLINE':
                self.status = 'OFFLINE'
                self.save(update_fields=['status'])
            return 'OFFLINE'
        return self.status

    class Meta:
        ordering = ['name']
        verbose_name = 'Nodo Proxy'
        verbose_name_plural = 'Nodos Proxy'

    def __str__(self):
        return f"{self.name} ({self.ip_address}) - [{self.status}]"
