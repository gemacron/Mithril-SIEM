import os
import html
import time
import threading
import requests
from datetime import timedelta
from django.db import close_old_connections
from django.db.models import F
from django.utils import timezone
from .models import (
    TelegramConfig,
    TelegramRecipient,
    TelegramDiscoveredChat,
    TelegramCandidateMessage,
)


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
    if status_code == 409 or 'terminated by other getupdates' in low:
        return "El Bot Interactivo (Long Polling) ya está escuchando en segundo plano."
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
    if len(html_text) > 4000:
        html_text = html_text[:3980] + "\n… (truncado)"
    if len(plain_text) > 4000:
        plain_text = plain_text[:3980] + "\n... (truncado)"
    return html_text, plain_text


def _post_telegram_message(bot_token, chat_id, html_text, plain_text, thread_id='', reply_markup=None):
    """
    Envía un mensaje individual a Telegram usando parse_mode=HTML (inmune a _, [, * y payloads).
    Soporta botones interactivos (InlineKeyboardMarkup) y fallback automático a texto plano.
    Retorna (ok: bool, err_msg: str, message_id: int | None).
    """
    token = _clean_token(bot_token)
    cid = str(chat_id or '').strip()
    if not token or not cid:
        return False, "Falta Bot Token o Chat ID.", None

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        'chat_id': cid,
        'text': html_text,
        'parse_mode': 'HTML',
        'disable_web_page_preview': True,
    }
    if str(thread_id or '').strip().isdigit():
        payload['message_thread_id'] = int(str(thread_id).strip())
    if reply_markup:
        payload['reply_markup'] = reply_markup

    try:
        resp = requests.post(url, json=payload, timeout=8)
        try:
            data = resp.json()
        except Exception:
            data = None

        if resp.status_code == 200 and (not isinstance(data, dict) or data.get('ok', True)):
            msg_id = (data.get('result') or {}).get('message_id') if isinstance(data, dict) else None
            return True, '', msg_id

        # Respaldo ante rate-limit corto (429)
        if resp.status_code == 429 and isinstance(data, dict):
            retry_after = int((data.get('parameters') or {}).get('retry_after', 1) or 1)
            if retry_after <= 3:
                time.sleep(retry_after)
                resp2 = requests.post(url, json=payload, timeout=8)
                try:
                    data2 = resp2.json()
                except Exception:
                    data2 = None
                if resp2.status_code == 200:
                    msg_id = (data2.get('result') or {}).get('message_id') if isinstance(data2, dict) else None
                    return True, '', msg_id

        # Respaldo automático en texto plano si Telegram rechazó el marcado HTML
        desc_low = str((data or {}).get('description', '') if isinstance(data, dict) else resp.text).lower()
        if resp.status_code == 400 and ('parse entities' in desc_low or 'unsupported start tag' in desc_low):
            plain_payload = {
                'chat_id': cid,
                'text': plain_text,
                'disable_web_page_preview': True,
            }
            if 'message_thread_id' in payload:
                plain_payload['message_thread_id'] = payload['message_thread_id']
            if reply_markup:
                plain_payload['reply_markup'] = reply_markup
            resp_fb = requests.post(url, json=plain_payload, timeout=8)
            try:
                data_fb = resp_fb.json()
            except Exception:
                data_fb = None
            if resp_fb.status_code == 200:
                msg_id = (data_fb.get('result') or {}).get('message_id') if isinstance(data_fb, dict) else None
                return True, '', msg_id
            return False, _parse_telegram_error(resp_fb.status_code, data_fb, resp_fb.text), None

        return False, _parse_telegram_error(resp.status_code, data, resp.text), None
    except requests.exceptions.Timeout:
        return False, "Tiempo de espera agotado (timeout) conectando con api.telegram.org. Verifica salida HTTPS (puerto 443).", None
    except requests.exceptions.ConnectionError as e:
        return False, f"Sin conexión de red hacia api.telegram.org (DNS/Firewall/HTTPS): {str(e)[:140]}", None
    except Exception as e:
        return False, f"Error inesperado enviando a Telegram: {e}", None


def edit_telegram_message(bot_token, chat_id, message_id, html_text, reply_markup=None):
    """Edita texto y botones inline de un mensaje ya enviado en Telegram."""
    token = _clean_token(bot_token)
    if not token or not chat_id or not message_id:
        return False
    url = f"https://api.telegram.org/bot{token}/editMessageText"
    payload = {
        'chat_id': str(chat_id),
        'message_id': int(message_id),
        'text': html_text[:4000],
        'parse_mode': 'HTML',
        'disable_web_page_preview': True,
        'reply_markup': reply_markup if reply_markup is not None else {'inline_keyboard': []},
    }
    try:
        resp = requests.post(url, json=payload, timeout=8)
        if resp.status_code == 200:
            return True
        # Si Telegram responde "message is not modified", considerarlo OK
        if resp.status_code == 400 and 'message is not modified' in resp.text.lower():
            return True
    except Exception:
        pass
    return False


def build_candidate_keyboard(candidate_id, can_manage_bans=True, include_info_btn=True):
    """Construye los botones interactivos (Ver Evidencia, Descartar y Bloquear con duraciones 24h / 7d / Permanente)."""
    rows = []
    if can_manage_bans:
        row1 = []
        if include_info_btn:
            row1.append({'text': '🔎 Ver Evidencia', 'callback_data': f'cand:info:{candidate_id}'})
        row1.append({'text': '🗑️ Descartar', 'callback_data': f'cand:dismiss:{candidate_id}'})
        rows.append(row1)
        rows.append([
            {'text': '🛑 Bloq. 24h', 'callback_data': f'cand:ban:{candidate_id}:24'},
            {'text': '🛑 Bloq. 7d', 'callback_data': f'cand:ban:{candidate_id}:168'},
            {'text': '⛔ Permanente', 'callback_data': f'cand:ban:{candidate_id}:0'},
        ])
    elif include_info_btn:
        rows.append([
            {'text': '🔎 Ver Evidencia', 'callback_data': f'cand:info:{candidate_id}'},
        ])
    return {'inline_keyboard': rows} if rows else None


def build_revoke_keyboard(ban_id):
    return {
        'inline_keyboard': [[
            {'text': '🔓 Revocar Bloqueo', 'callback_data': f'ban:revoke:{ban_id}'},
        ]]
    }


def build_candidate_alert_html(candidate, last_event=None, is_cf=False, cf_node_ip='', country_name='', node_name=''):
    """
    Construye una alerta forense enriquecida en HTML seguro con toda la evidencia necesaria
    para que el operador decida bloquear o descartar directamente desde Telegram.
    """
    ev = last_event or getattr(candidate, 'trigger_event', None)
    ev_details = ev.details if (ev and isinstance(ev.details, dict)) else {}

    eff_score = int(candidate.accumulated_score or 80)
    sev = 'CRITICAL' if eff_score >= 85 else 'HIGH'
    sev_badge = '🔴 CRÍTICA' if sev == 'CRITICAL' else '🟠 ALTA'
    ts_str = timezone.localtime(candidate.created_at or timezone.now()).strftime('%Y-%m-%d %H:%M:%S %Z')

    c_name = country_name or ev_details.get('country_name') or ev_details.get('country_code') or 'Desconocido'
    city = ev_details.get('city') or ''
    geo_label = f"{c_name} · {city}" if (city and city not in ('-', c_name)) else c_name
    n_name = node_name or (ev.node.name if (ev and ev.node) else ev_details.get('node')) or 'N/A'

    rule_code = ev.rule.code if (ev and ev.rule) else 'HEURÍSTICA'
    rule_name = ev.rule.name if (ev and ev.rule) else 'Detección Heurística / Acumulación de Riesgo'
    method = ev_details.get('http_method') or 'GET'
    uri = ev_details.get('uri') or '/'
    query = ev_details.get('query_params') or ev_details.get('query') or ''
    full_uri = f"{uri}?{query}" if query else uri
    status_code = ev_details.get('status_code')
    ua = (ev_details.get('user_agent') or ev_details.get('agent') or '').strip() or '(Sin User-Agent)'
    cf_ray = ev_details.get('cf_ray') or ''
    matched_payload = (ev.matched_payload if ev else '') or candidate.suggested_reason or ''

    lines = [
        f"🛡️ <b>[MITHRIL SIEM]</b> · {sev_badge}",
        f"<b>🚨 Nuevo Candidato a Bloqueo (#{candidate.id})</b>",
        "━━━━━━━━━━━━━━━━━━━━━━",
        f"🌐 <b>IP Atacante:</b> <code>{html.escape(str(candidate.client_ip))}</code>",
        f"📍 <b>Origen:</b> {html.escape(str(geo_label))}",
        f"📡 <b>Proxy:</b> {html.escape(str(n_name))} · <b>Score:</b> <code>{eff_score}/100</code>",
    ]
    if is_cf and cf_node_ip:
        cf_extra = f" · Ray: <code>{html.escape(str(cf_ray))}</code>" if cf_ray else ""
        lines.append(f"☁️ <b>Vía Cloudflare:</b> <code>{html.escape(str(cf_node_ip))}</code>{cf_extra}")

    lines.append(f"🎯 <b>Regla:</b> <code>[{html.escape(str(rule_code))}]</code> {html.escape(str(rule_name)[:90])}")
    status_part = f" → HTTP <code>{html.escape(str(status_code))}</code>" if status_code is not None else ""
    lines.append(f"📥 <b>Petición:</b> <code>{html.escape(str(method))} {html.escape(str(full_uri)[:160])}</code>{status_part}")
    lines.append(f"🧭 <b>User-Agent:</b> <code>{html.escape(str(ua)[:110])}</code>")
    if matched_payload:
        lines.append(f"🔍 <b>Evidencia:</b> <code>{html.escape(str(matched_payload)[:220])}</code>")

    lines.extend([
        "━━━━━━━━━━━━━━━━━━━━━━",
        f"⏱️ <i>{html.escape(ts_str)}</i> · Selecciona una acción abajo:",
    ])
    html_text = "\n".join(lines)
    plain_text = (
        f"[MITHRIL SIEM] Nuevo Candidato #{candidate.id}\n"
        f"IP: {candidate.client_ip} ({geo_label}) | Proxy: {n_name} | Score: {eff_score}/100\n"
        f"Regla: [{rule_code}] {rule_name}\n"
        f"Petición: {method} {full_uri[:160]} ({status_code})\n"
        f"User-Agent: {ua[:110]}\n"
        f"Evidencia: {matched_payload[:220]}"
    )
    return html_text, plain_text, sev


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
                can_manage_bans=True,
                min_severity=(config.min_severity if config else 'HIGH') or 'HIGH',
                notify_on_ban_candidate=config.notify_on_ban_candidate if config else True,
                notify_on_ban_action=getattr(config, 'notify_on_ban_action', True) if config else True,
                notify_on_node_offline=config.notify_on_node_offline if config else True,
            )
    except Exception as e:
        print(f"[Mithril Telegram] Error sincronizando destinatarios heredados: {e}")


def record_discovered_chat_from_update(upd):
    """Extrae metadatos de un update de Telegram y los registra en TelegramDiscoveredChat."""
    msg = (
        upd.get('message')
        or upd.get('edited_message')
        or upd.get('channel_post')
        or upd.get('my_chat_member')
        or (upd.get('callback_query') or {}).get('message')
    )
    if not isinstance(msg, dict):
        return None
    chat = msg.get('chat')
    if not isinstance(chat, dict) or chat.get('id') is None:
        return None

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
    uname_fmt = f"@{username}" if username else ''
    sample_text = (msg.get('text') or msg.get('caption') or '').strip()[:100]
    thread_id = str(msg.get('message_thread_id') or '') if msg.get('is_topic_message') else ''

    try:
        TelegramDiscoveredChat.objects.update_or_create(
            chat_id=cid,
            defaults={
                'name': display_name[:120],
                'username': uname_fmt[:64],
                'recipient_type': rtype,
                'thread_id': thread_id[:32],
                'last_message': sample_text or '/start',
            },
        )
    except Exception:
        pass

    return {
        'chat_id': cid,
        'name': display_name[:80],
        'username': uname_fmt,
        'recipient_type': rtype,
        'thread_id': thread_id,
        'sample_text': sample_text,
    }


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


def is_interactive_poller_alive(config=None):
    cfg = config or TelegramConfig.objects.first()
    if not cfg or not cfg.bot_last_poll_at:
        return False
    return (timezone.now() - cfg.bot_last_poll_at).total_seconds() < 90.0


def discover_telegram_chats(bot_token, config=None):
    """
    Devuelve los chats que interactuaron con el bot.
    Si el listener Long Polling está activo, lee directo desde TelegramDiscoveredChat (cero error 409);
    si el poller está pausado/apagado, consulta /getUpdates y guarda los resultados en BD.
    """
    token = _clean_token(bot_token)
    if not token:
        return False, "Debes guardar o ingresar primero el Bot Token.", []

    poller_alive = is_interactive_poller_alive(config)
    if not poller_alive:
        try:
            resp = requests.get(
                f"https://api.telegram.org/bot{token}/getUpdates",
                params={'limit': 100, 'timeout': 0},
                timeout=8,
            )
            data = resp.json() if resp.content else {}
            if resp.status_code == 200 and data.get('ok'):
                for upd in data.get('result', []):
                    record_discovered_chat_from_update(upd)
            elif resp.status_code != 409:
                # Si no es 409 (poller activo), reportar error solo si tampoco hay descubiertos guardados
                if not TelegramDiscoveredChat.objects.exists():
                    return False, _parse_telegram_error(resp.status_code, data, resp.text), []
        except requests.exceptions.Timeout:
            if not TelegramDiscoveredChat.objects.exists():
                return False, "Timeout consultando actualizaciones en api.telegram.org.", []
        except requests.exceptions.ConnectionError as e:
            if not TelegramDiscoveredChat.objects.exists():
                return False, f"Sin acceso de red a api.telegram.org: {str(e)[:140]}", []
        except Exception as e:
            if not TelegramDiscoveredChat.objects.exists():
                return False, f"Error descubriendo chats: {e}", []

    existing_ids = set(TelegramRecipient.objects.values_list('chat_id', flat=True))
    results = []
    for row in TelegramDiscoveredChat.objects.all()[:50]:
        results.append({
            'chat_id': row.chat_id,
            'name': row.name[:80],
            'username': row.username,
            'recipient_type': row.recipient_type,
            'thread_id': row.thread_id,
            'sample_text': row.last_message,
            'already_added': row.chat_id in existing_ids,
        })
    results.sort(key=lambda x: (x['already_added'], x['name'].lower()))
    return True, '', results


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


def _dispatch_batch_worker(bot_token, targets, html_text, plain_text, config_id=None, candidate_id=None):
    """
    Hilo dedicado no bloqueante que entrega la alerta a todos los destinatarios seleccionados,
    guarda los message_id si es un candidato (para sincronizar botones), actualiza métricas y registra errores.
    """
    close_old_connections()
    any_ok = False
    errors_collected = []
    now_ts = timezone.now()

    try:
        for idx, tgt in enumerate(targets):
            if idx > 0:
                time.sleep(0.05)
            ok, err_msg, msg_id = _post_telegram_message(
                bot_token=bot_token,
                chat_id=tgt['chat_id'],
                html_text=html_text,
                plain_text=plain_text,
                thread_id=tgt.get('thread_id', ''),
                reply_markup=tgt.get('reply_markup'),
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
                if candidate_id and msg_id:
                    try:
                        TelegramCandidateMessage.objects.update_or_create(
                            candidate_id=candidate_id,
                            chat_id=str(tgt['chat_id']),
                            message_id=int(msg_id),
                            defaults={'rendered_html': html_text},
                        )
                    except Exception:
                        pass
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
    que cumplan el filtro de severidad y tipo de evento.
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
                    'reply_markup': None,
                })

        if not targets and not active_recipients:
            env_chats = [c.strip() for c in os.getenv('TELEGRAM_CHAT_ID', '').replace(';', ',').split(',') if c.strip()]
            for cid in env_chats:
                targets.append({'recipient_id': None, 'name': cid, 'chat_id': cid, 'thread_id': '', 'reply_markup': None})

        if not targets:
            return False

        html_text, plain_text = _format_alert_messages(title, message, severity=severity)
        config_id = config.id if config else None

        threading.Thread(
            target=_dispatch_batch_worker,
            args=(bot_token, targets, html_text, plain_text, config_id, None),
            daemon=True,
        ).start()
        return True
    except Exception as e:
        print(f"[Mithril Telegram] ❌ Error preparando alerta Telegram: {e}", flush=True)
        return False


def send_telegram_candidate_alert(candidate, last_event=None, is_cf=False, cf_node_ip='', country_name='', node_name=''):
    """
    Envía una alerta forense enriquecida de Candidato a Bloqueo con botones interactivos
    (Ver Evidencia, Bloquear 24h / 7d / Permanente, Descartar) adaptados al permiso de cada destinatario.
    """
    try:
        config = TelegramConfig.objects.first()
        bot_token = _resolve_bot_token(config)
        if config is not None:
            is_enabled = bool(config.is_enabled)
            if not config.notify_on_ban_candidate:
                return False
            interactive = bool(getattr(config, 'enable_interactive_bot', True))
        else:
            is_enabled = os.getenv('TELEGRAM_ENABLED', 'False').lower() in ('true', '1', 'yes')
            interactive = True

        if not is_enabled or not bot_token:
            return False

        ensure_legacy_recipients_migrated(config)
        html_text, plain_text, sev = build_candidate_alert_html(
            candidate=candidate,
            last_event=last_event,
            is_cf=is_cf,
            cf_node_ip=cf_node_ip,
            country_name=country_name,
            node_name=node_name,
        )

        active_recipients = list(TelegramRecipient.objects.filter(is_active=True))
        targets = []
        for rec in active_recipients:
            if _matches_recipient_filters(rec, sev, 'ban_candidate'):
                markup = None
                if interactive and rec.recipient_type != 'CHANNEL':
                    markup = build_candidate_keyboard(
                        candidate_id=candidate.id,
                        can_manage_bans=bool(getattr(rec, 'can_manage_bans', True)),
                    )
                targets.append({
                    'recipient_id': rec.id,
                    'name': rec.name,
                    'chat_id': rec.chat_id,
                    'thread_id': rec.message_thread_id,
                    'reply_markup': markup,
                })

        if not targets and not active_recipients:
            env_chats = [c.strip() for c in os.getenv('TELEGRAM_CHAT_ID', '').replace(';', ',').split(',') if c.strip()]
            for cid in env_chats:
                markup = build_candidate_keyboard(candidate.id, can_manage_bans=True) if interactive else None
                targets.append({'recipient_id': None, 'name': cid, 'chat_id': cid, 'thread_id': '', 'reply_markup': markup})

        if not targets:
            return False

        config_id = config.id if config else None
        threading.Thread(
            target=_dispatch_batch_worker,
            args=(bot_token, targets, html_text, plain_text, config_id, candidate.id),
            daemon=True,
        ).start()
        return True
    except Exception as e:
        print(f"[Mithril Telegram] ❌ Error enviando candidato interactivo: {e}", flush=True)
        return False


def sync_candidate_telegram_messages(candidate_id, resolution_badge_html, reply_markup=None):
    """
    Actualiza en segundo plano TODOS los mensajes de Telegram asociados a un BanCandidate
    (en chats privados y grupos) cuando alguien lo bloquea o descarta desde Telegram o desde la Web.
    """
    def _sync_worker():
        close_old_connections()
        try:
            config = TelegramConfig.objects.first()
            bot_token = _resolve_bot_token(config)
            if not bot_token:
                return
            msgs = list(TelegramCandidateMessage.objects.filter(candidate_id=candidate_id)[:25])
            ts_str = timezone.localtime().strftime('%H:%M:%S')
            for m in msgs:
                base_html = m.rendered_html or f"<b>Candidato #{candidate_id}</b>"
                # Quitar línea previa de invitación a seleccionar acción si existe
                base_html = base_html.replace(" · Selecciona una acción abajo:", "")
                new_html = f"{base_html}\n\n{resolution_badge_html} <i>({ts_str})</i>"
                edit_telegram_message(
                    bot_token=bot_token,
                    chat_id=m.chat_id,
                    message_id=m.message_id,
                    html_text=new_html,
                    reply_markup=reply_markup,
                )
        except Exception as e:
            print(f"[Mithril Telegram] Error sincronizando mensajes de candidato #{candidate_id}: {e}", flush=True)
        finally:
            close_old_connections()

    threading.Thread(target=_sync_worker, daemon=True).start()


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
        f"Prueba de escape: [R-DANGEROUS-EXT-PROBE] /test_path.php?id=1&mode=check\n"
        f"Comandos disponibles: /pendientes · /bloqueados · /estado · /ayuda"
    )
    html_text, plain_text = _format_alert_messages(title, msg, severity='HIGH')
    ok, err_msg, _ = _post_telegram_message(bot_token, chat_id, html_text, plain_text, thread_id=thread_id)
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
