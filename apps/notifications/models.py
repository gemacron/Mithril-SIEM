from django.db import models


SEVERITY_CHOICES = [
    ('LOW', 'Baja'),
    ('MEDIUM', 'Media'),
    ('HIGH', 'Alta'),
    ('CRITICAL', 'Crítica'),
]

RECIPIENT_TYPE_CHOICES = [
    ('USER', 'Persona / Operador'),
    ('GROUP', 'Grupo SOC'),
    ('CHANNEL', 'Canal'),
]

DELIVERY_STATUS_CHOICES = [
    ('PENDING', 'Sin envíos'),
    ('OK', 'Entregado'),
    ('ERROR', 'Error'),
]


class TelegramConfig(models.Model):
    bot_token = models.CharField(
        max_length=128,
        blank=True,
        default='',
        help_text="Token provisto por @BotFather",
    )
    bot_username = models.CharField(
        max_length=64,
        blank=True,
        default='',
        help_text="Usuario del bot detectado automáticamente vía getMe (ej: MithrilAlertBot)",
    )
    chat_id = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text="Chat ID heredado (se migra automáticamente a la lista de destinatarios)",
    )
    is_enabled = models.BooleanField(default=False)
    min_severity = models.CharField(
        max_length=16,
        choices=SEVERITY_CHOICES,
        default='HIGH',
    )
    notify_on_ban_candidate = models.BooleanField(
        default=True,
        help_text="Notificar cuando una IP supera el umbral de Candidato a Bloqueo",
    )
    notify_on_ban_action = models.BooleanField(
        default=True,
        help_text="Notificar cuando un operador aprueba, ejecuta o revoca un bloqueo",
    )
    notify_on_node_offline = models.BooleanField(
        default=True,
        help_text="Notificar si un proxy Nginx deja de emitir heartbeat",
    )
    last_notified_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Configuración de Telegram'
        verbose_name_plural = 'Configuración de Telegram'

    def __str__(self):
        return f"Telegram Bot ({'Activo' if self.is_enabled else 'Inactivo'})"


class TelegramRecipient(models.Model):
    """
    Destinatario individual (persona, grupo SOC o canal) que recibe alertas desde el Bot de Mithril.
    Permite filtros independientes por severidad y tipo de evento, más trazabilidad de entregas.
    """
    name = models.CharField(max_length=80, help_text="Nombre de la persona, grupo o canal")
    chat_id = models.CharField(
        max_length=64,
        unique=True,
        help_text="ID numérico del usuario/grupo (ej: 123456789 o -1001234567890) o @canal",
    )
    message_thread_id = models.CharField(
        max_length=32,
        blank=True,
        default='',
        help_text="Opcional: ID de Topic/Hilo dentro de un Supergrupo con temas",
    )
    recipient_type = models.CharField(
        max_length=16,
        choices=RECIPIENT_TYPE_CHOICES,
        default='USER',
    )
    role_label = models.CharField(
        max_length=64,
        blank=True,
        default='',
        help_text="Etiqueta opcional (ej: Analista SOC, SysAdmin, Guardia)",
    )
    is_active = models.BooleanField(default=True)
    min_severity = models.CharField(
        max_length=16,
        choices=SEVERITY_CHOICES,
        default='HIGH',
    )
    notify_on_ban_candidate = models.BooleanField(default=True)
    notify_on_ban_action = models.BooleanField(default=True)
    notify_on_node_offline = models.BooleanField(default=True)

    last_notified_at = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(
        max_length=16,
        choices=DELIVERY_STATUS_CHOICES,
        default='PENDING',
    )
    last_error = models.TextField(blank=True, default='')
    sent_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-is_active', 'name']
        verbose_name = 'Destinatario de Telegram'
        verbose_name_plural = 'Destinatarios de Telegram'

    def __str__(self):
        state = 'Activo' if self.is_active else 'Pausado'
        return f"{self.name} ({self.chat_id}) [{state}]"
