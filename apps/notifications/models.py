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
    enable_interactive_bot = models.BooleanField(
        default=True,
        help_text="Habilita botones interactivos (Ver Evidencia, Bloquear 24h/7d/Permanente, Descartar) y comandos en Telegram vía Long Polling",
    )
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
    bot_last_poll_at = models.DateTimeField(null=True, blank=True)
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
    Permite filtros independientes por severidad/evento y permisos de acción (bloquear/descartar).
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
    can_manage_bans = models.BooleanField(
        default=True,
        help_text="Permite aprobar bloqueos, revocar bloqueos y descartar candidatos directamente desde Telegram",
    )
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


class TelegramDiscoveredChat(models.Model):
    """
    Almacena chats (personas, grupos o canales) que enviaron /start o interactuaron con el bot,
    alimentado en tiempo real por el listener Long Polling para evitar conflictos 409 en getUpdates.
    """
    chat_id = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=120, blank=True, default='')
    username = models.CharField(max_length=64, blank=True, default='')
    recipient_type = models.CharField(
        max_length=16,
        choices=RECIPIENT_TYPE_CHOICES,
        default='USER',
    )
    thread_id = models.CharField(max_length=32, blank=True, default='')
    last_message = models.CharField(max_length=120, blank=True, default='')
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-last_seen_at']
        verbose_name = 'Chat Detectado en Telegram'
        verbose_name_plural = 'Chats Detectados en Telegram'

    def __str__(self):
        return f"{self.name} ({self.chat_id})"


class TelegramCandidateMessage(models.Model):
    """
    Vincula cada mensaje de alerta enviado a Telegram con su BanCandidate correspondiente
    para sincronizar/actualizar el mensaje y sus botones en TODOS los chats al aprobar o descartar.
    """
    candidate_id = models.BigIntegerField(db_index=True)
    chat_id = models.CharField(max_length=64)
    message_id = models.BigIntegerField()
    rendered_html = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('candidate_id', 'chat_id', 'message_id')
        ordering = ['-id']

    def __str__(self):
        return f"Cand #{self.candidate_id} -> {self.chat_id}:{self.message_id}"
