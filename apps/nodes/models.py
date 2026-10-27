import uuid
import secrets
from django.db import models
from django.utils import timezone

class ProxyNode(models.Model):
    STATUS_CHOICES = [
        ('ONLINE', 'En Línea'),
        ('DEGRADED', 'Degradado / Alto Tráfico'),
        ('OFFLINE', 'Desconectado'),
        ('MAINTENANCE', 'En Mantenimiento (Pausado)'),
    ]

    BLOCK_METHOD_CHOICES = [
        ('ipset', 'Kernel ipset (Recomendado - Ultra Rápido)'),
        ('nginx_conf', 'Archivo include dinámico de Nginx (deny IP;)'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=64, unique=True, help_text="Ej: proxy-edge-us-east-01")
    description = models.TextField(blank=True, default="")
    ip_address = models.GenericIPAddressField(help_text="IP del servidor proxy Nginx")
    location_label = models.CharField(max_length=64, blank=True, default="Datacenter Principal")
    api_key = models.CharField(max_length=64, unique=True, editable=False)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='OFFLINE')

    # Parámetros de Configuración de Monitorización
    monitoring_enabled = models.BooleanField(default=True, help_text="Activa o pausa la monitorización de este nodo")
    heartbeat_timeout_seconds = models.IntegerField(default=90, help_text="Segundos sin reporte antes de marcar OFFLINE")
    max_rps_alert_threshold = models.IntegerField(default=1000, help_text="Umbral de peticiones/segundo para considerar el nodo saturado")
    syslog_port = models.IntegerField(default=5140, help_text="Puerto UDP/TCP para recibir streaming de logs de este proxy")
    sync_interval_seconds = models.IntegerField(default=15, help_text="Frecuencia en segundos para sincronizar la lista de IPs bloqueadas")
    block_method = models.CharField(max_length=16, choices=BLOCK_METHOD_CHOICES, default='ipset', help_text="Mecanismo de bloqueo local")
    notify_on_degraded = models.BooleanField(default=True, help_text="Enviar alerta por Telegram si el nodo se satura o se desconecta")

    # Métricas y Telemetría del Servidor
    current_rps = models.IntegerField(default=0, help_text="Peticiones por segundo procesadas")
    total_logs_processed = models.BigIntegerField(default=0)
    cpu_usage = models.FloatField(default=0.0, help_text="Porcentaje de uso de CPU reportado")
    memory_usage = models.FloatField(default=0.0, help_text="Porcentaje de uso de RAM reportado")
    active_connections = models.IntegerField(default=0, help_text="Conexiones activas concurrentes en Nginx")
    nginx_version = models.CharField(max_length=32, blank=True, default="")

    last_heartbeat = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = f"mithril_node_{secrets.token_hex(24)}"
        super().save(*args, **kwargs)

    def regenerate_api_key(self):
        self.api_key = f"mithril_node_{secrets.token_hex(24)}"
        self.save(update_fields=['api_key'])
        return self.api_key

    def update_heartbeat(self, rps=0, cpu=0.0, ram=0.0, active_conns=0, nginx_ver=""):
        self.last_heartbeat = timezone.now()
        self.current_rps = rps
        if cpu: self.cpu_usage = cpu
        if ram: self.memory_usage = ram
        if active_conns: self.active_connections = active_conns
        if nginx_ver: self.nginx_version = nginx_ver

        if not self.monitoring_enabled:
            self.status = 'MAINTENANCE'
        elif self.current_rps >= self.max_rps_alert_threshold:
            self.status = 'DEGRADED'
        else:
            self.status = 'ONLINE'

        self.save(update_fields=[
            'last_heartbeat', 'current_rps', 'cpu_usage', 'memory_usage',
            'active_connections', 'nginx_version', 'status'
        ])

    def check_health(self):
        if not self.monitoring_enabled:
            self.status = 'MAINTENANCE'
            return self.status

        if not self.last_heartbeat:
            self.status = 'OFFLINE'
            return self.status

        diff = (timezone.now() - self.last_heartbeat).total_seconds()
        if diff > self.heartbeat_timeout_seconds:
            if self.status != 'OFFLINE':
                self.status = 'OFFLINE'
                self.save(update_fields=['status'])
            return 'OFFLINE'

        if self.current_rps >= self.max_rps_alert_threshold:
            self.status = 'DEGRADED'
            self.save(update_fields=['status'])
            return 'DEGRADED'

        return self.status

    class Meta:
        ordering = ['name']
        verbose_name = 'Nodo Proxy'
        verbose_name_plural = 'Nodos Proxy'

    def __str__(self):
        return f"{self.name} ({self.ip_address}) - [{self.status}]"
