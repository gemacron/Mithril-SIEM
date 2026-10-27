from django.db import models

class TelegramConfig(models.Model):
    bot_token = models.CharField(max_length=128, blank=True, default='', help_text="Token provisto por @BotFather")
    chat_id = models.CharField(max_length=64, blank=True, default='', help_text="ID del chat, grupo o canal de Telegram")
    is_enabled = models.BooleanField(default=False)
    min_severity = models.CharField(
        max_length=16,
        choices=[('LOW', 'Baja'), ('MEDIUM', 'Media'), ('HIGH', 'Alta'), ('CRITICAL', 'Crítica')],
        default='HIGH'
    )
    notify_on_ban_candidate = models.BooleanField(default=True, help_text="Notificar cuando una IP supera el umbral de Autoban")
    notify_on_node_offline = models.BooleanField(default=True, help_text="Notificar si un proxy Nginx deja de emitir heartbeat")
    last_notified_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Configuración de Telegram'
        verbose_name_plural = 'Configuración de Telegram'

    def __str__(self):
        return f"Telegram Bot ({'Activo' if self.is_enabled else 'Inactivo'})"
