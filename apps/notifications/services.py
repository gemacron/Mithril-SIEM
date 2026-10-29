import os
import threading
import requests
from django.utils import timezone
from .models import TelegramConfig

def _send_telegram_worker(url, payload, config_id=None):
    try:
        resp = requests.post(url, json=payload, timeout=4)
        if resp.status_code == 200 and config_id:
            TelegramConfig.objects.filter(id=config_id).update(last_notified_at=timezone.now())
    except Exception as e:
        print(f"Error enviando alerta Telegram (async): {e}")

def send_telegram_alert(title, message, severity='HIGH'):
    """
    Envía una alerta con formato táctico al canal o chat de Telegram configurado
    de forma asíncrona (no bloqueante) para no detener el análisis ni colgar la UI.
    """
    try:
        config = TelegramConfig.objects.first()
        bot_token = config.bot_token if config else os.getenv('TELEGRAM_BOT_TOKEN')
        chat_id = config.chat_id if config else os.getenv('TELEGRAM_CHAT_ID')
        is_enabled = config.is_enabled if config else (os.getenv('TELEGRAM_ENABLED', 'False').lower() in ('true', '1'))

        if not is_enabled or not bot_token or not chat_id:
            return False

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        full_text = f"🛡️ *[MITHRIL SIEM]*\n*{title}*\n━━━━━━━━━━━━━━━━━━━━━━\n{message}\n━━━━━━━━━━━━━━━━━━━━━━\n⏱️ _{timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}_"

        payload = {
            'chat_id': chat_id,
            'text': full_text,
            'parse_mode': 'Markdown'
        }

        config_id = config.id if config else None
        threading.Thread(
            target=_send_telegram_worker,
            args=(url, payload, config_id),
            daemon=True
        ).start()
        return True
    except Exception as e:
        print(f"Error preparando alerta Telegram: {e}")
        return False

def test_telegram_connection(bot_token, chat_id):
    """
    Prueba de conexión puntual desde el formulario de configuración
    """
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': "🛡️ *Mithril SIEM*: Prueba de conexión exitosa con Telegram Bot.",
        'parse_mode': 'Markdown'
    }
    try:
        resp = requests.post(url, json=payload, timeout=5)
        return resp.status_code == 200, resp.json()
    except Exception as e:
        return False, str(e)
