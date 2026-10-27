from django.db import models
from django.contrib.auth.models import User
from apps.nodes.models import ProxyNode

class IpReputation(models.Model):
    STATUS_CHOICES = [
        ('MONITORED', 'Monitoreada / Normal'),
        ('SUSPICIOUS', 'Sospechosa'),
        ('PENDING_BAN', 'Candidata a Bloqueo (Autoban)'),
        ('BANNED', 'Bloqueada Activa'),
        ('WHITELISTED', 'Lista Blanca (Excluida)'),
    ]

    client_ip = models.GenericIPAddressField(primary_key=True)
    current_risk_score = models.SmallIntegerField(default=0)
    total_violations = models.IntegerField(default=0)
    country_code = models.CharField(max_length=4, blank=True, default='')
    asn = models.CharField(max_length=64, blank=True, default='')
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='MONITORED')
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    last_evaluated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-current_risk_score']
        verbose_name = 'Reputación de IP'
        verbose_name_plural = 'Reputaciones de IPs'

    def __str__(self):
        return f"{self.client_ip} | Score: {self.current_risk_score} [{self.status}]"


class BanCandidate(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pendiente de Aprobación'),
        ('APPROVED', 'Bloqueo Aprobado'),
        ('DISMISSED', 'Descartado / Falso Positivo'),
    ]

    client_ip = models.GenericIPAddressField(db_index=True)
    accumulated_score = models.SmallIntegerField(default=80)
    suggested_reason = models.TextField()
    trigger_event = models.ForeignKey('detection.SecurityEvent', on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='PENDING', db_index=True)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Candidato a Bloqueo'
        verbose_name_plural = 'Candidatos a Bloqueo'

    def __str__(self):
        return f"Candidato: {self.client_ip} (Score: {self.accumulated_score}) [{self.status}]"


class ActiveBan(models.Model):
    client_ip = models.GenericIPAddressField(unique=True, db_index=True)
    reason = models.TextField()
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    banned_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True, help_text="NULL indica bloqueo permanente")
    is_active = models.BooleanField(default=True, db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='revoked_bans')

    class Meta:
        ordering = ['-banned_at']
        verbose_name = 'Bloqueo Activo'
        verbose_name_plural = 'Bloqueos Activos'

    def __str__(self):
        return f"BAN: {self.client_ip} ({'Activo' if self.is_active else 'Revocado'})"


class NodeBanSync(models.Model):
    ban = models.ForeignKey(ActiveBan, on_delete=models.CASCADE, related_name='sync_records')
    node = models.ForeignKey(ProxyNode, on_delete=models.CASCADE, related_name='ban_syncs')
    is_synced = models.BooleanField(default=False)
    synced_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True, default='')

    class Meta:
        unique_together = ('ban', 'node')

    def __str__(self):
        return f"Sync {self.ban.client_ip} -> {self.node.name} [{'SYNCED' if self.is_synced else 'PENDING'}]"
