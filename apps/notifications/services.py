import os
import html
import time
import threading
import requests
from django.db import close_old_connections
from django.db.models import F
from django.utils import timezone
from .models import TelegramConfig, TelegramRecipient


SEVERITY_RANK = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4,
}


def _clean_token(raw_token):
    token = str(raw_token or '').strip().strip('"').strip("'")
    if token.lower().startswith('bot') and ':' in token[3:]:
        token = token[3:]
    return token


def _resolve_bot_token(config=None):
    if config and (config.bot_token or '').strip():
        return _clean_token(config.bot_token)
    return _clean_token(os.getenv('TELEGRAM_BOT_TOKEN', ''))


def _parse_telegram_error(status_code, resp_json=None, raw_text=''):
    desc = ''
    if isinstance(resp_json, dict):
        desc = str(resp_json.get('description') or '').strip()
    if not desc:
        desc = str(raw_text or '').strip()[:220]
    low = desc.lower()

    if status_code == 401 or 'unauthorized' in low:
        return "Bot Token inválido o revocado en @BotFather (HTTP 401)."
    if 'bot was blocked by the user' in low:
        return "El usuario bloqueó al bot en Telegram. Debe desbloquearlo y enviar /start."
    if 'chat not found' in low or "bot can't initiate conversation" in low:
        return "Chat ID no encontrado o la persona todavía no envió /start al bot en Telegram."
    if 'group chat was upgraded to a supergroup' in low:
        migrate_id = ''
        if isinstance(resp_json, dict):
            migrate_id = (resp_json.get('parameters') or {}).get('migrate_to_chat_id', '')
        extra = f" Nuevo Chat ID: {migrate_id}" if migrate_id else ""
        return f"El grupo fue actualizado a Supergrupo.{extra}"
    if 'not enough rights' in low or 'need administrator rights' in low:
        return "El bot no tiene permisos de escritura/administrador en este grupo o canal."
    if status_code == 429:
        return f"Límite temporal de Telegram alcanzado (HTTP 429): {desc}"
    if desc:
        return f"Telegram HTTP {status_code}: {desc}"
    return f"Error HTTP {status_code} al comunicarse con la API de Telegram."


def _format_alert_messages(title, message, severity='HIGH'):
    sev = str(severity or 'HIGH').upper()
    sev_badge = {
        'CRITICAL': '🔴 CRÍTICA',
        'HIGH': '🟠 ALTA',
        'MEDIUM': '🟡 MEDIA',
        'LOW': '🔵 BAJA',
    }.get(sev, sev)
    ts_str = timezone.localtime().strftime('%Y-%m-%d %H:%M:%S %Z')

    safe_title = html.escape(str(title or 'Alerta de Seguridad'))
    safe_msg = html.escape(str(message or ''))
    safe_ts = html.escape(ts_str)

    html_text = (
        f"🛡️ <b>[MITHRIL SIEM]</b> · {sev_badge}\n"
        f"<b>{safe_title}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{safe_msg}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⏱️ <i>{safe_ts}</i>"
    )
    plain_text = (
        f"[MITHRIL SIEM] - {sev}\n"
        f"{title}\n"
        f"----------------------\n"
        f"{message}\n"
        f"----------------------\n"
        f"{ts_str}"
    )
    # Telegram permite hasta 4096 caracteres por mensaje
    if len(html_text) > 4000:
        html_text = html_text[:3980] + "\n… (truncado)"
    if len(plain_text) > 4000:
        plain_text = plain_text[:3980] + "\n... (truncado)"
    return html_text, plain_text


def _post_telegram_message(bot_token, chat_id, html_text, plain_text, thread_id=''):
    """
    Envía un mensaje individual a Telegram usando parse_mode=HTML (inmune a guiones bajos _,
    corchetes [, asteriscos * y payloads SQLi/XSS). Si Telegram devolviera error de parseo
    HTML (400), reintenta automáticamente en texto plano para garantizar la entrega.
    """
    token = _clean_token(bot_token)
    cid = str(chat_id or '').strip()
    if not token or not cid:
        return False, "Falta Bot Token o Chat ID."

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        'chat_id': cid,
        'text': html_text,
        'parse_mode': 'HTML',
        'disable_web_page_preview': True,
    }
    if str(thread_id or '').strip().isdigit():
        payload['message_thread_id'] = int(str(thread_id).strip())

    try:
        resp = requests.post(url, json=payload, timeout=8)
        try:
            data = resp.json()
        except Exception:
            data = None

        if resp.status_code == 200 and (not isinstance(data, dict) or data.get('ok', True)):
            return True, ''

        # Respaldo ante rate-limit corto (429)
        if resp.status_code == 429 and isinstance(data, dict):
            retry_after = int((data.get('parameters') or {}).get('retry_after', 1) or 1)
            if retry_after <= 3:
                time.sleep(retry_after)
                resp2 = requests.post(url, json=payload, timeout=8)
                if resp2.status_code == 200:
                    return True, ''

        # Respaldo automático en texto plano si Telegram rechazó el marcado
        desc_low = str((data or {}).get('description', '') if isinstance(data, dict) else resp.text).lower()
        if resp.status_code == 400 and ('parse entities' in desc_low or 'unsupported start tag' in desc_low):
            plain_payload = {
                'chat_id': cid,
                'text': plain_text,
                'disable_web_page_preview': True,
            }
            if 'message_thread_id' in payload:
                plain_payload['message_thread_id'] = payload['message_thread_id']
            resp_fb = requests.post(url, json=plain_payload, timeout=8)
            if resp_fb.status_code == 200:
                return True, ''
            try:
                data_fb = resp_fb.json()
            except Exception:
                data_fb = None
            return False, _parse_telegram_error(resp_fb.status_code, data_fb, resp_fb.text)

        return False, _parse_telegram_error(resp.status_code, data, resp.text)
    except requests.exceptions.Timeout:
        return False, "Tiempo de espera agotado (timeout) conectando con api.telegram.org. Verifica salida HTTPS (puerto 443)."
    except requests.exceptions.ConnectionError as e:
        return False, f"Sin conexión de red hacia api.telegram.org (DNS/Firewall/HTTPS): {str(e)[:140]}"
    except Exception as e:
        return False, f"Error inesperado enviando a Telegram: {e}"


def ensure_legacy_recipients_migrated(config=None):
    """
    Si el servidor ya tenía un Chat ID configurado en TelegramConfig.chat_id (o TELEGRAM_CHAT_ID en .env)
    y todavía no existen destinatarios en TelegramRecipient, los importa automáticamente.
    """
    try:
        if TelegramRecipient.objects.exists():
            return
        raw_chat = ''
        if config and (config.chat_id or '').strip():
            raw_chat = config.chat_id
        else:
            raw_chat = os.getenv('TELEGRAM_CHAT_ID', '')

        ids = [c.strip() for c in str(raw_chat or '').replace(';', ',').split(',') if c.strip()]
        for idx, cid in enumerate(ids, start=1):
            if TelegramRecipient.objects.filter(chat_id=cid).exists():
                continue
            is_group = cid.startswith('-100') or cid.startswith('-')
            is_channel = cid.startswith('@')
            rtype = 'CHANNEL' if is_channel else ('GROUP' if is_group else 'USER')
            TelegramRecipient.objects.create(
                name='Chat Principal' if idx == 1 else f'Destinatario #{idx}',
                chat_id=cid,
                recipient_type=rtype,
                role_label='Configuración inicial',
                is_active=True,
                min_severity=(config.min_severity if config else 'HIGH') or 'HIGH',
                notify_on_ban_candidate=config.notify_on_ban_candidate if config else True,
                notify_on_ban_action=getattr(config, 'notify_on_ban_action', True) if config else True,
                notify_on_node_offline=config.notify_on_node_offline if config else True,
            )
    except Exception as e:
        print(f"[Mithril Telegram] Error sincronizando destinatarios heredados: {e}")


def get_telegram_bot_info(bot_token):
    """Valida el Bot Token consultando /getMe y devuelve identidad del bot."""
    token = _clean_token(bot_token)
    if not token:
        return False, "No se ha ingresado un Bot Token."
    try:
        resp = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=6)
        data = resp.json() if resp.content else {}
        if resp.status_code == 200 and data.get('ok'):
            return True, data.get('result', {})
        return False, _parse_telegram_error(resp.status_code, data, resp.text)
    except requests.exceptions.Timeout:
        return False, "Timeout al verificar el bot con api.telegram.org."
    except requests.exceptions.ConnectionError as e:
        return False, f"Sin acceso de red a api.telegram.org: {str(e)[:140]}"
    except Exception as e:
        return False, f"Error consultando getMe: {e}"


def discover_telegram_chats(bot_token):
    """
    Consulta /getUpdates del bot para descubrir automáticamente qué personas, grupos o canales
    le enviaron /start o un mensaje recientemente, permitiendo agregarlos en 1 clic sin buscar IDs.
    """
    token = _clean_token(bot_token)
    if not token:
        return False, "Debes guardar o ingresar primero el Bot Token.", []

    try:
        resp = requests.get(
            f"https://api.telegram.org/bot{token}/getUpdates",
            params={'limit': 100, 'timeout': 0},
            timeout=8,
        )
        data = resp.json() if resp.content else {}
        if resp.status_code != 200 or not data.get('ok'):
            return False, _parse_telegram_error(resp.status_code, data, resp.text), []

        chats_map = {}
        for upd in data.get('result', []):
            msg = (
                upd.get('message')
                or upd.get('edited_message')
                or upd.get('channel_post')
                or upd.get('my_chat_member')
                or upd.get('callback_query', {}).get('message')
            )
            if not isinstance(msg, dict):
                continue
            chat = msg.get('chat')
            if not isinstance(chat, dict) or chat.get('id') is None:
                continue

            cid = str(chat['id'])
            ctype_raw = str(chat.get('type', 'private')).lower()
            if ctype_raw in ('group', 'supergroup'):
                rtype = 'GROUP'
                display_name = chat.get('title') or f"Grupo {cid}"
            elif ctype_raw == 'channel':
                rtype = 'CHANNEL'
                display_name = chat.get('title') or f"Canal {cid}"
            else:
                rtype = 'USER'
                first = (chat.get('first_name') or '').strip()
                last = (chat.get('last_name') or '').strip()
                display_name = f"{first} {last}".strip() or chat.get('username') or f"Usuario {cid}"

            username = (chat.get('username') or '').strip()
            sample_text = (msg.get('text') or msg.get('caption') or '').strip()[:60]
            thread_id = str(msg.get('message_thread_id') or '') if msg.get('is_topic_message') else ''

            chats_map[cid] = {
                'chat_id': cid,
                'name': display_name[:80],
                'username': f"@{username}" if username else '',
                'recipient_type': rtype,
                'thread_id': thread_id,
                'sample_text': sample_text,
            }

        existing_ids = set(TelegramRecipient.objects.values_list('chat_id', flat=True))
        results = []
        for item in chats_map.values():
            item['already_added'] = item['chat_id'] in existing_ids
            results.append(item)

        results.sort(key=lambda x: (x['already_added'], x['name'].lower()))
        return True, '', results
    except requests.exceptions.Timeout:
        return False, "Timeout consultando actualizaciones en api.telegram.org.", []
    except requests.exceptions.ConnectionError as e:
        return False, f"Sin acceso de red a api.telegram.org: {str(e)[:140]}", []
    except Exception as e:
        return False, f"Error descubriendo chats: {e}", []


def _matches_recipient_filters(recipient, severity, event_type):
    sev_val = SEVERITY_RANK.get(str(severity or 'HIGH').upper(), 3)
    min_val = SEVERITY_RANK.get(str(recipient.min_severity or 'HIGH').upper(), 3)
    if sev_val < min_val:
        return False

    ev = str(event_type or 'general').lower()
    if ev == 'ban_candidate' and not recipient.notify_on_ban_candidate:
        return False
    if ev == 'ban_action' and not recipient.notify_on_ban_action:
        return False
    if ev == 'node_offline' and not recipient.notify_on_node_offline:
        return False
    return True


def _dispatch_batch_worker(bot_token, targets, html_text, plain_text, config_id=None):
    """
    Hilo dedicado no bloqueante que entrega la alerta a todos los destinatarios seleccionados,
    actualiza métricas individuales (entregado/error/conteo) y registra errores reales en logs.
    """
    close_old_connections()
    any_ok = False
    errors_collected = []
    now_ts = timezone.now()

    try:
        for idx, tgt in enumerate(targets):
            if idx > 0:
                time.sleep(0.05)  # Respetar límite de 30 msg/s de Telegram
            ok, err_msg = _post_telegram_message(
                bot_token=bot_token,
                chat_id=tgt['chat_id'],
                html_text=html_text,
                plain_text=plain_text,
                thread_id=tgt.get('thread_id', ''),
            )
            now_ts = timezone.now()
            if ok:
                any_ok = True
                if tgt.get('recipient_id'):
                    TelegramRecipient.objects.filter(id=tgt['recipient_id']).update(
                        last_status='OK',
                        last_error='',
                        last_notified_at=now_ts,
                        sent_count=F('sent_count') + 1,
                    )
            else:
                err_line = f"{tgt.get('name', tgt['chat_id'])} ({tgt['chat_id']}): {err_msg}"
                errors_collected.append(err_line)
                print(f"[Mithril Telegram] ❌ Fallo entrega a {err_line}", flush=True)
                if tgt.get('recipient_id'):
                    TelegramRecipient.objects.filter(id=tgt['recipient_id']).update(
                        last_status='ERROR',
                        last_error=err_msg[:500],
                    )

        if config_id:
            update_cfg = {}
            if any_ok:
                update_cfg['last_notified_at'] = now_ts
            update_cfg['last_error'] = ' | '.join(errors_collected)[:1000] if errors_collected else ''
            TelegramConfig.objects.filter(id=config_id).update(**update_cfg)
    except Exception as e:
        print(f"[Mithril Telegram] ❌ Error interno en hilo de envío: {e}", flush=True)
    finally:
        close_old_connections()


def send_telegram_alert(title, message, severity='HIGH', event_type='general'):
    """
    Envía una alerta en formato HTML seguro a TODOS los destinatarios activos de Telegram
    (personas, grupos y canales) que cumplan el filtro de severidad y tipo de evento.
    Corre de forma asíncrona (no bloqueante) para jamás frenar el motor de detección ni la UI.
    """
    try:
        config = TelegramConfig.objects.first()
        bot_token = _resolve_bot_token(config)
        if config is not None:
            is_enabled = bool(config.is_enabled)
        else:
            is_enabled = os.getenv('TELEGRAM_ENABLED', 'False').lower() in ('true', '1', 'yes')

        if not is_enabled or not bot_token:
            return False

        # Respetar switches globales del panel si la configuración existe
        ev = str(event_type or 'general').lower()
        if config is not None:
            if ev == 'ban_candidate' and not config.notify_on_ban_candidate:
                return False
            if ev == 'ban_action' and not getattr(config, 'notify_on_ban_action', True):
                return False
            if ev == 'node_offline' and not config.notify_on_node_offline:
                return False

        ensure_legacy_recipients_migrated(config)

        active_recipients = list(TelegramRecipient.objects.filter(is_active=True))
        targets = []
        for rec in active_recipients:
            if _matches_recipient_filters(rec, severity, event_type):
                targets.append({
                    'recipient_id': rec.id,
                    'name': rec.name,
                    'chat_id': rec.chat_id,
                    'thread_id': rec.message_thread_id,
                })

        # Respaldo de compatibilidad si no hay filas en TelegramRecipient pero sí variable de entorno
        if not targets and not active_recipients:
            env_chats = [c.strip() for c in os.getenv('TELEGRAM_CHAT_ID', '').replace(';', ',').split(',') if c.strip()]
            for cid in env_chats:
                targets.append({'recipient_id': None, 'name': cid, 'chat_id': cid, 'thread_id': ''})

        if not targets:
            return False

        html_text, plain_text = _format_alert_messages(title, message, severity=severity)
        config_id = config.id if config else None

        threading.Thread(
            target=_dispatch_batch_worker,
            args=(bot_token, targets, html_text, plain_text, config_id),
            daemon=True,
        ).start()
        return True
    except Exception as e:
        print(f"[Mithril Telegram] ❌ Error preparando alerta Telegram: {e}", flush=True)
        return False


def test_telegram_connection(bot_token, chat_id, thread_id='', recipient_name='', recipient_obj=None, config_obj=None):
    """
    Prueba de conexión síncrona hacia un destinatario puntual usando el mismo formato HTML seguro
    que las alertas reales (incluyendo caracteres especiales como _ y [] para validar escape real).
    """
    title = "Prueba de Conexión — Mithril SIEM"
    target_lbl = f"Destinatario: {recipient_name} ({chat_id})\n" if recipient_name else f"Chat ID: {chat_id}\n"
    msg = (
        f"{target_lbl}"
        f"Estado: Canal operativo y verificado.\n"
        f"Prueba de escape: [R-DANGEROUS-EXT-PROBE] /test_path.php?id=1&mode=check"
    )
    html_text, plain_text = _format_alert_messages(title, msg, severity='HIGH')
    ok, err_msg = _post_telegram_message(bot_token, chat_id, html_text, plain_text, thread_id=thread_id)
    now_ts = timezone.now()

    if recipient_obj is not None:
        if ok:
            TelegramRecipient.objects.filter(id=recipient_obj.id).update(
                last_status='OK',
                last_error='',
                last_notified_at=now_ts,
                sent_count=F('sent_count') + 1,
            )
        else:
            TelegramRecipient.objects.filter(id=recipient_obj.id).update(
                last_status='ERROR',
                last_error=err_msg[:500],
            )

    if config_obj is not None:
        if ok:
            TelegramConfig.objects.filter(id=config_obj.id).update(last_notified_at=now_ts, last_error='')
        else:
            TelegramConfig.objects.filter(id=config_obj.id).update(last_error=f"{recipient_name or chat_id}: {err_msg}"[:1000])

    return ok, ('Mensaje entregado correctamente.' if ok else err_msg)


def test_telegram_broadcast(bot_token, config_obj=None):
    """
    Envía una alerta de prueba síncrona a TODOS los destinatarios activos y devuelve
    el detalle individual de entrega para diagnóstico inmediato.
    """
    recipients = list(TelegramRecipient.objects.filter(is_active=True))
    if not recipients:
        return 0, 0, []

    ok_count = 0
    fail_count = 0
    details = []
    for idx, rec in enumerate(recipients):
        if idx > 0:
            time.sleep(0.05)
        ok, info = test_telegram_connection(
            bot_token=bot_token,
            chat_id=rec.chat_id,
            thread_id=rec.message_thread_id,
            recipient_name=rec.name,
            recipient_obj=rec,
            config_obj=None,
        )
        if ok:
            ok_count += 1
        else:
            fail_count += 1
        details.append({'name': rec.name, 'chat_id': rec.chat_id, 'ok': ok, 'detail': info})

    if config_obj is not None:
        now_ts = timezone.now()
        err_summary = ' | '.join(f"{d['name']}: {d['detail']}" for d in details if not d['ok'])
        upd = {'last_error': err_summary[:1000]}
        if ok_count > 0:
            upd['last_notified_at'] = now_ts
        TelegramConfig.objects.filter(id=config_obj.id).update(**upd)

    return ok_count, fail_count, details
