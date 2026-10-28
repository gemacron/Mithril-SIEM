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

    def compute_live_rps(self):
        """Calcula las peticiones por segundo reales basadas en los logs recibidos en los últimos 10s"""
        try:
            window_start = timezone.now() - timezone.timedelta(seconds=10)
            recent_count = self.logs.filter(created_at__gte=window_start).count()
            if recent_count > 0:
                return max(1, round(recent_count / 10))
            return 0
        except Exception:
            return self.current_rps

    def update_heartbeat(self, rps=None, cpu=None, ram=None, active_conns=None, nginx_ver=""):
        self.last_heartbeat = timezone.now()
        computed_rps = self.compute_live_rps()
        if rps is not None and rps > 0:
            self.current_rps = max(rps, computed_rps)
        else:
            self.current_rps = computed_rps

        if cpu is not None and cpu > 0:
            self.cpu_usage = cpu
        if ram is not None and ram > 0:
            self.memory_usage = ram
        if active_conns is not None and active_conns > 0:
            self.active_connections = active_conns
        if nginx_ver:
            self.nginx_version = nginx_ver

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

        now = timezone.now()
        diff = (now - self.last_heartbeat).total_seconds()
        live_rps = self.compute_live_rps()

        if diff > self.heartbeat_timeout_seconds:
            if self.status != 'OFFLINE' or self.current_rps != 0:
                self.status = 'OFFLINE'
                self.current_rps = 0
                self.save(update_fields=['status', 'current_rps'])
            return 'OFFLINE'

        new_status = 'DEGRADED' if live_rps >= self.max_rps_alert_threshold else 'ONLINE'
        if self.status != new_status or self.current_rps != live_rps:
            self.status = new_status
            self.current_rps = live_rps
            self.save(update_fields=['status', 'current_rps'])

        return self.status

    class Meta:
        ordering = ['name']
        verbose_name = 'Nodo Proxy'
        verbose_name_plural = 'Nodos Proxy'

    def __str__(self):
        return f"{self.name} ({self.ip_address}) - [{self.status}]"
