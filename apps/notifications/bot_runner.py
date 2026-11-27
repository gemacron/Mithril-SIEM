import html
import json
import signal
import time
import requests
from datetime import timedelta
from django.db import close_old_connections
from django.utils import timezone
from apps.nodes.models import ProxyNode
from apps.detection.models import TrafficLog, SecurityEvent
from apps.detection.engine import (
    is_cloudflare_ip,
    is_own_infrastructure_ip,
    extract_log_ip_meta,
    invalidate_reputation_cache,
)
from apps.mitigation.models import BanCandidate, ActiveBan, IpReputation, NodeBanSync
from apps.reports.models import AuditTrail
from .models import TelegramConfig, TelegramRecipient, TelegramCandidateMessage
from .services import (
    _clean_token,
    _resolve_bot_token,
    _post_telegram_message,
    edit_telegram_message,
    build_candidate_alert_html,
    build_candidate_keyboard,
    build_revoke_keyboard,
    record_discovered_chat_from_update,
    sync_candidate_telegram_messages,
)


_STOP_REQUESTED = False


def _signal_handler(signum, frame):
    global _STOP_REQUESTED
    _STOP_REQUESTED = True


def _answer_callback_query(bot_token, callback_query_id, text='', show_alert=False):
    if not bot_token or not callback_query_id:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/answerCallbackQuery",
            json={
                'callback_query_id': str(callback_query_id),
                'text': str(text or '')[:195],
                'show_alert': bool(show_alert),
            },
            timeout=6,
        )
    except Exception:
        pass


def _register_bot_commands(bot_token):
    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/setMyCommands",
            json={
                'commands': [
                    {'command': 'pendientes', 'description': 'Ver candidatos a bloqueo pendientes (con botones)'},
                    {'command': 'bloqueados', 'description': 'Ver IPs bloqueadas activas e intentos repelidos'},
                    {'command': 'estado', 'description': 'Estado en vivo de proxies y alertas SOC'},
                    {'command': 'ayuda', 'description': 'Mostrar guía de comandos del bot'},
                ]
            },
            timeout=8,
        )
    except Exception:
        pass


def _format_actor_label(from_user, recipient_obj=None):
    first = (from_user.get('first_name') or '').strip() if isinstance(from_user, dict) else ''
    last = (from_user.get('last_name') or '').strip() if isinstance(from_user, dict) else ''
    uname = (from_user.get('username') or '').strip() if isinstance(from_user, dict) else ''
    full = f"{first} {last}".strip()
    if full and uname:
        return f"{full} (@{uname})"
    if full:
        return full
    if uname:
        return f"@{uname}"
    if recipient_obj:
        return recipient_obj.name
    return f"ID:{from_user.get('id', '?')}" if isinstance(from_user, dict) else "Operador Telegram"


def _resolve_actor_permissions(from_user, chat_id):
    """
    Determina si quien toca un botón o escribe un comando está registrado y tiene permiso
    para ejecutar bloqueos/descartes (can_manage_bans).
    Soporta tanto chats privados como grupos SOC registrados.
    """
    user_id = str((from_user or {}).get('id') or '').strip()
    chat_str = str(chat_id or '').strip()

    user_rec = TelegramRecipient.objects.filter(chat_id=user_id, is_active=True).first() if user_id else None
    chat_rec = (
        TelegramRecipient.objects.filter(chat_id=chat_str, is_active=True).first()
        if (chat_str and chat_str != user_id)
        else None
    )

    is_known = bool(user_rec or chat_rec)
    can_manage = bool((user_rec and user_rec.can_manage_bans) or (chat_rec and chat_rec.can_manage_bans))
    actor_label = _format_actor_label(from_user, user_rec or chat_rec)
    return is_known, can_manage, actor_label, (user_rec or chat_rec)


def _format_duration_label(hours):
    if hours <= 0:
        return "Permanente"
    if hours == 24:
        return "24 horas"
    if hours == 168:
        return "7 días"
    if hours % 24 == 0:
        return f"{hours // 24} días"
    return f"{hours} horas"


def _build_forensic_dossier_html(candidate):
    """Construye un reporte forense compacto con historial de eventos y últimas peticiones HTTP de la IP."""
    ip_str = candidate.client_ip
    rep = IpReputation.objects.filter(client_ip=ip_str).first()
    events = list(
        SecurityEvent.objects.filter(client_ip=ip_str)
        .select_related('rule', 'node')
        .order_by('-created_at')[:5]
    )
    logs = list(
        TrafficLog.objects.filter(client_ip=ip_str)
        .select_related('node')
        .order_by('-created_at')[:6]
    )

    status_map = {
        'PENDING': '⏳ PENDIENTE DE DECISIÓN',
        'APPROVED': '🛑 BLOQUEADO',
        'DISMISSED': '🗑️ DESCARTADO',
    }
    st_lbl = status_map.get(candidate.status, candidate.status)
    country = (logs[0].country_name or logs[0].country_code) if logs else (rep.country_code if rep else 'Desconocido')
    city = (logs[0].city if logs and logs[0].city and logs[0].city != '-' else '')
    geo_str = f"{country} · {city}" if city and city != country else country

    lines = [
        f"🔎 <b>DOSSIER FORENSE — Candidato #{candidate.id}</b>",
        "━━━━━━━━━━━━━━━━━━━━━━",
        f"🌐 <b>IP:</b> <code>{html.escape(str(ip_str))}</code> ({html.escape(str(geo_str))})",
        f"📊 <b>Score:</b> <code>{candidate.accumulated_score}/100</code> · <b>Infracciones:</b> <code>{rep.total_violations if rep else len(events)}</code>",
        f"📌 <b>Estado:</b> {st_lbl}",
    ]

    if events:
        lines.append("\n<b>🚨 Últimas Reglas Disparadas:</b>")
        for ev in events:
            ts = timezone.localtime(ev.created_at).strftime('%H:%M:%S')
            rcode = ev.rule.code if ev.rule else 'HEURÍSTICA'
            payload = (ev.matched_payload or '')[:110]
            lines.append(f"• <code>{ts}</code> <b>[{html.escape(rcode)}]</b> {html.escape(payload)}")

    if logs:
        lines.append("\n<b>📡 Últimas Peticiones HTTP:</b>")
        for lg in logs:
            ts = timezone.localtime(lg.created_at).strftime('%H:%M:%S')
            q = f"?{lg.query_params}" if lg.query_params else ""
            path = f"{lg.uri}{q}"[:85]
            ua = (lg.user_agent or '').strip()[:36] or '(Sin UA)'
            node_lbl = lg.node.name if lg.node else 'Direct'
            lines.append(
                f"• <code>{ts}</code> [{html.escape(node_lbl)}] <code>{html.escape(lg.http_method)} {lg.status_code} {html.escape(path)}</code> · <i>{html.escape(ua)}</i>"
            )
    else:
        lines.append("\n<i>Sin logs recientes en TrafficLog para esta IP.</i>")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━")
    if candidate.status == 'PENDING':
        lines.append("👇 Puedes bloquear o descartar directamente desde aquí:")
    return "\n".join(lines)


def _handle_callback_query(bot_token, cq):
    cq_id = cq.get('id')
    data = str(cq.get('data') or '').strip()
    from_user = cq.get('from') or {}
    msg = cq.get('message') or {}
    chat = msg.get('chat') or {}
    chat_id = str(chat.get('id') or '')
    message_id = msg.get('message_id')
    thread_id = str(msg.get('message_thread_id') or '') if msg.get('is_topic_message') else ''

    if not data or not chat_id:
        _answer_callback_query(bot_token, cq_id)
        return

    is_known, can_manage, actor_label, _ = _resolve_actor_permissions(from_user, chat_id)
    if not is_known:
        _answer_callback_query(
            bot_token,
            cq_id,
            "⛔ No estás registrado en Mithril SIEM. Pide al administrador agregarte en /notifications/telegram/.",
            show_alert=True,
        )
        return

    parts = data.split(':')

    # 1. VER EVIDENCIA FORENSE
    if len(parts) == 3 and parts[0] == 'cand' and parts[1] == 'info':
        try:
            cand_id = int(parts[2])
        except ValueError:
            _answer_callback_query(bot_token, cq_id, "Candidato inválido.")
            return

        candidate = BanCandidate.objects.select_related('trigger_event', 'trigger_event__rule', 'trigger_event__node').filter(id=cand_id).first()
        if not candidate:
            _answer_callback_query(bot_token, cq_id, "Candidato no encontrado.", show_alert=True)
            return

        dossier_html = _build_forensic_dossier_html(candidate)
        markup = (
            build_candidate_keyboard(candidate.id, can_manage_bans=can_manage, include_info_btn=False)
            if candidate.status == 'PENDING'
            else None
        )
        ok, _, new_msg_id = _post_telegram_message(
            bot_token=bot_token,
            chat_id=chat_id,
            html_text=dossier_html,
            plain_text=f"Dossier Forense Candidato #{candidate.id} - IP {candidate.client_ip}",
            thread_id=thread_id,
            reply_markup=markup,
        )
        if ok and new_msg_id and candidate.status == 'PENDING':
            try:
                TelegramCandidateMessage.objects.update_or_create(
                    candidate_id=candidate.id,
                    chat_id=chat_id,
                    message_id=int(new_msg_id),
                    defaults={'rendered_html': dossier_html},
                )
            except Exception:
                pass
        _answer_callback_query(bot_token, cq_id, "🔎 Evidencia forense enviada.")
        return

    # 2. APROBAR BLOQUEO CON DURACIÓN (24h / 7d / Permanente)
    if len(parts) == 4 and parts[0] == 'cand' and parts[1] == 'ban':
        if not can_manage:
            _answer_callback_query(
                bot_token,
                cq_id,
                "⛔ No tienes permiso para ejecutar bloqueos. Habilita 'Puede Bloquear' en Mithril SIEM.",
                show_alert=True,
            )
            return

        try:
            cand_id = int(parts[2])
            duration_hours = int(parts[3])
            if duration_hours < 0 or duration_hours > 8760:
                duration_hours = 24
        except ValueError:
            _answer_callback_query(bot_token, cq_id, "Parámetros inválidos.")
            return

        candidate = BanCandidate.objects.select_related('trigger_event', 'trigger_event__rule').filter(id=cand_id).first()
        if not candidate:
            _answer_callback_query(bot_token, cq_id, "Candidato no encontrado.", show_alert=True)
            return

        if candidate.status != 'PENDING':
            st_txt = "ya fue bloqueado" if candidate.status == 'APPROVED' else "ya fue descartado"
            _answer_callback_query(bot_token, cq_id, f"ℹ️ Este candidato {st_txt} previamente.", show_alert=True)
            if message_id:
                sync_candidate_telegram_messages(
                    candidate.id,
                    f"ℹ️ <b>Candidato ya procesado ({candidate.status})</b>",
                    reply_markup={'inline_keyboard': []},
                )
            return

        ip_str = candidate.client_ip
        if is_cloudflare_ip(ip_str):
            ev_details = candidate.trigger_event.details if (candidate.trigger_event and isinstance(candidate.trigger_event.details, dict)) else {}
            meta = extract_log_ip_meta(ip_str, ev_details)
            real_ip = meta.get('real_client_ip')
            if real_ip and not is_cloudflare_ip(real_ip):
                ip_str = real_ip
            else:
                _answer_callback_query(
                    bot_token,
                    cq_id,
                    f"🛡️ Protección activa: {ip_str} pertenece a Cloudflare y no puede bloquearse.",
                    show_alert=True,
                )
                return

        if is_own_infrastructure_ip(ip_str):
            _answer_callback_query(
                bot_token,
                cq_id,
                f"🛡️ Protección activa: {ip_str} pertenece a tu propia infraestructura.",
                show_alert=True,
            )
            return

        now_ts = timezone.now()
        expires_at = now_ts + timedelta(hours=duration_hours) if duration_hours > 0 else None
        dur_label = _format_duration_label(duration_hours)
        reason_full = f"{candidate.suggested_reason} [Aprobado vía Telegram por {actor_label}]"

        ban, _ = ActiveBan.objects.update_or_create(
            client_ip=ip_str,
            defaults={
                'reason': reason_full,
                'approved_by': None,
                'banned_at': now_ts,
                'expires_at': expires_at,
                'is_active': True,
                'revoked_at': None,
                'revoked_by': None,
            },
        )

        candidate.status = 'APPROVED'
        candidate.reviewed_by = None
        candidate.reviewed_at = now_ts
        candidate.save(update_fields=['status', 'reviewed_by', 'reviewed_at'])

        IpReputation.objects.filter(client_ip=ip_str).update(status='BANNED')
        invalidate_reputation_cache(ip_str)

        active_nodes = list(ProxyNode.objects.all())
        for node in active_nodes:
            NodeBanSync.objects.update_or_create(
                ban=ban,
                node=node,
                defaults={'is_synced': False},
            )

        AuditTrail.objects.create(
            user=None,
            action='APPROVE_BAN_TELEGRAM',
            target=f"IP: {ip_str}",
            details={
                'candidate_id': candidate.id,
                'duration_hours': duration_hours,
                'duration_label': dur_label,
                'telegram_actor': actor_label,
                'telegram_user_id': str(from_user.get('id', '')),
                'telegram_chat_id': chat_id,
                'reason': candidate.suggested_reason,
            },
        )

        _answer_callback_query(
            bot_token,
            cq_id,
            f"🛑 IP {ip_str} bloqueada ({dur_label}). Sincronizando en {len(active_nodes)} proxy(s).",
        )

        stamp_html = (
            f"✅ <b>BLOQUEADO ({html.escape(dur_label)})</b> por <b>{html.escape(actor_label)}</b> vía Telegram\n"
            f"📡 Orden distribuida a <code>{len(active_nodes)}</code> proxy(s) Nginx."
        )
        # Asegurar que el mensaje clickeado quede registrado aunque no hubiera estado en tabla
        if message_id and not TelegramCandidateMessage.objects.filter(candidate_id=candidate.id, chat_id=chat_id, message_id=int(message_id)).exists():
            TelegramCandidateMessage.objects.create(
                candidate_id=candidate.id,
                chat_id=chat_id,
                message_id=int(message_id),
                rendered_html=html.escape(msg.get('text') or f"Candidato #{candidate.id} ({ip_str})"),
            )
        sync_candidate_telegram_messages(
            candidate_id=candidate.id,
            resolution_badge_html=stamp_html,
            reply_markup=build_revoke_keyboard(ban.id),
        )
        return

    # 3. DESCARTAR CANDIDATO
    if len(parts) == 3 and parts[0] == 'cand' and parts[1] == 'dismiss':
        if not can_manage:
            _answer_callback_query(
                bot_token,
                cq_id,
                "⛔ No tienes permiso para descartar candidatos.",
                show_alert=True,
            )
            return

        try:
            cand_id = int(parts[2])
        except ValueError:
            _answer_callback_query(bot_token, cq_id, "Candidato inválido.")
            return

        candidate = BanCandidate.objects.filter(id=cand_id).first()
        if not candidate:
            _answer_callback_query(bot_token, cq_id, "Candidato no encontrado.", show_alert=True)
            return

        if candidate.status != 'PENDING':
            _answer_callback_query(bot_token, cq_id, f"ℹ️ Este candidato ya estaba en estado {candidate.status}.", show_alert=True)
            sync_candidate_telegram_messages(
                candidate.id,
                f"ℹ️ <b>Candidato ya procesado ({candidate.status})</b>",
                reply_markup={'inline_keyboard': []},
            )
            return

        now_ts = timezone.now()
        candidate.status = 'DISMISSED'
        candidate.reviewed_by = None
        candidate.reviewed_at = now_ts
        candidate.save(update_fields=['status', 'reviewed_by', 'reviewed_at'])

        IpReputation.objects.filter(client_ip=candidate.client_ip).update(current_risk_score=20, status='MONITORED')
        invalidate_reputation_cache(candidate.client_ip)

        AuditTrail.objects.create(
            user=None,
            action='DISMISS_CANDIDATE_TELEGRAM',
            target=f"IP: {candidate.client_ip}",
            details={
                'candidate_id': candidate.id,
                'telegram_actor': actor_label,
                'telegram_user_id': str(from_user.get('id', '')),
                'telegram_chat_id': chat_id,
            },
        )

        _answer_callback_query(bot_token, cq_id, f"🗑️ Candidato {candidate.client_ip} descartado.")

        if message_id and not TelegramCandidateMessage.objects.filter(candidate_id=candidate.id, chat_id=chat_id, message_id=int(message_id)).exists():
            TelegramCandidateMessage.objects.create(
                candidate_id=candidate.id,
                chat_id=chat_id,
                message_id=int(message_id),
                rendered_html=html.escape(msg.get('text') or f"Candidato #{candidate.id} ({candidate.client_ip})"),
            )
        sync_candidate_telegram_messages(
            candidate_id=candidate.id,
            resolution_badge_html=f"🗑️ <b>DESCARTADO</b> por <b>{html.escape(actor_label)}</b> vía Telegram",
            reply_markup={'inline_keyboard': []},
        )
        return

    # 4. REVOCAR BLOQUEO DESDE TELEGRAM
    if len(parts) == 3 and parts[0] == 'ban' and parts[1] == 'revoke':
        if not can_manage:
            _answer_callback_query(bot_token, cq_id, "⛔ No tienes permiso para revocar bloqueos.", show_alert=True)
            return

        try:
            ban_id = int(parts[2])
        except ValueError:
            _answer_callback_query(bot_token, cq_id, "Bloqueo inválido.")
            return

        ban = ActiveBan.objects.filter(id=ban_id).first()
        if not ban:
            _answer_callback_query(bot_token, cq_id, "Bloqueo no encontrado.", show_alert=True)
            return

        if not ban.is_active:
            _answer_callback_query(bot_token, cq_id, f"ℹ️ El bloqueo de {ban.client_ip} ya estaba revocado.", show_alert=True)
            if message_id:
                orig = html.escape(msg.get('text') or f"IP {ban.client_ip}")
                edit_telegram_message(bot_token, chat_id, message_id, f"{orig}\n\n🔓 <i>Ya revocado</i>", {'inline_keyboard': []})
            return

        now_ts = timezone.now()
        ban.is_active = False
        ban.revoked_at = now_ts
        ban.revoked_by = None
        ban.save(update_fields=['is_active', 'revoked_at', 'revoked_by'])

        IpReputation.objects.filter(client_ip=ban.client_ip).update(status='MONITORED', current_risk_score=0)
        invalidate_reputation_cache(ban.client_ip)
        NodeBanSync.objects.filter(ban=ban).update(is_synced=False)

        AuditTrail.objects.create(
            user=None,
            action='REVOKE_BAN_TELEGRAM',
            target=f"IP: {ban.client_ip}",
            details={
                'ban_id': ban.id,
                'telegram_actor': actor_label,
                'telegram_user_id': str(from_user.get('id', '')),
                'telegram_chat_id': chat_id,
            },
        )

        _answer_callback_query(bot_token, cq_id, f"🔓 Bloqueo revocado para {ban.client_ip}.")
        if message_id:
            ts_str = timezone.localtime(now_ts).strftime('%H:%M:%S')
            base_txt = html.escape(msg.get('text') or f"IP {ban.client_ip}")
            edit_telegram_message(
                bot_token,
                chat_id,
                message_id,
                f"{base_txt}\n\n🔓 <b>BLOQUEO REVOCADO</b> por <b>{html.escape(actor_label)}</b> vía Telegram <i>({ts_str})</i>",
                reply_markup={'inline_keyboard': []},
            )
        return

    _answer_callback_query(bot_token, cq_id)


def _handle_command_message(bot_token, msg):
    text = str(msg.get('text') or '').strip()
    if not text.startswith('/'):
        return

    chat = msg.get('chat') or {}
    chat_id = str(chat.get('id') or '')
    if not chat_id:
        return
    from_user = msg.get('from') or {}
    thread_id = str(msg.get('message_thread_id') or '') if msg.get('is_topic_message') else ''

    cmd = text.split()[0].split('@')[0].lower()
    is_known, can_manage, actor_label, _ = _resolve_actor_permissions(from_user, chat_id)

    if cmd == '/start':
        if is_known:
            perm_txt = "🛡️ <b>Autorizado para recibir alertas y ejecutar bloqueos/descartes.</b>" if can_manage else "👁️ <b>Autorizado en modo solo lectura (alertas).</b>"
        else:
            perm_txt = (
                "⏳ <b>Chat detectado y listo para vincular.</b>\n"
                "Pide al administrador de Mithril SIEM que entre a <b>✈️ Telegram → 🔍 Detectar Chats del Bot</b> y haga clic en <b>➕ Agregar</b>."
            )
        reply_html = (
            f"🛡️ <b>Mithril SIEM — Bot de Operaciones SOC</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Hola <b>{html.escape(actor_label)}</b>.\n"
            f"Tu Chat ID es: <code>{html.escape(chat_id)}</code>\n\n"
            f"{perm_txt}\n\n"
            f"Comandos: /pendientes · /bloqueados · /estado · /ayuda"
        )
        _post_telegram_message(bot_token, chat_id, reply_html, reply_html, thread_id=thread_id)
        return

    if not is_known:
        reply_html = (
            f"⛔ <b>Acceso no autorizado</b>\n"
            f"Tu Chat ID (<code>{html.escape(chat_id)}</code>) todavía no está registrado como destinatario activo en Mithril SIEM."
        )
        _post_telegram_message(bot_token, chat_id, reply_html, reply_html, thread_id=thread_id)
        return

    if cmd in ('/ayuda', '/help'):
        perm_lbl = "Operador (puede bloquear/descartar)" if can_manage else "Solo lectura"
        reply_html = (
            f"🛡️ <b>Mithril SIEM — Comandos Disponibles</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"• <code>/pendientes</code> — Ver candidatos a bloqueo pendientes (con evidencia y botones 24h / 7d / Permanente)\n"
            f"• <code>/bloqueados</code> — Ver IPs bloqueadas activas e intentos repelidos por el firewall\n"
            f"• <code>/estado</code> — Salud de los nodos Proxy Nginx, RPS y resumen SOC\n"
            f"• <code>/start</code> — Ver tu Chat ID y estado de permisos\n\n"
            f"👤 Tu nivel: <b>{perm_lbl}</b>"
        )
        _post_telegram_message(bot_token, chat_id, reply_html, reply_html, thread_id=thread_id)
        return

    if cmd == '/pendientes':
        pending = list(
            BanCandidate.objects.filter(status='PENDING')
            .select_related('trigger_event', 'trigger_event__rule', 'trigger_event__node')
            .order_by('-created_at')[:5]
        )
        total_pending = BanCandidate.objects.filter(status='PENDING').count()
        if not pending:
            _post_telegram_message(
                bot_token,
                chat_id,
                "✅ <b>Sin candidatos pendientes.</b> La cola de mitigación está limpia.",
                "Sin candidatos pendientes.",
                thread_id=thread_id,
            )
            return

        if total_pending > len(pending):
            _post_telegram_message(
                bot_token,
                chat_id,
                f"⚠️ Hay <b>{total_pending}</b> candidatos pendientes. Mostrando los <b>{len(pending)}</b> más recientes:",
                f"Hay {total_pending} candidatos pendientes.",
                thread_id=thread_id,
            )

        for cand in pending:
            ev = cand.trigger_event
            ev_details = ev.details if (ev and isinstance(ev.details, dict)) else {}
            html_t, plain_t, _ = build_candidate_alert_html(
                candidate=cand,
                last_event=ev,
                is_cf=bool(ev_details.get('is_cloudflare')),
                cf_node_ip=ev_details.get('cloudflare_ip', ''),
                country_name=ev_details.get('country_name', ''),
                node_name=ev.node.name if (ev and ev.node) else ev_details.get('node', ''),
            )
            markup = build_candidate_keyboard(cand.id, can_manage_bans=can_manage)
            ok, _, msg_id = _post_telegram_message(
                bot_token, chat_id, html_t, plain_t, thread_id=thread_id, reply_markup=markup
            )
            if ok and msg_id:
                try:
                    TelegramCandidateMessage.objects.update_or_create(
                        candidate_id=cand.id,
                        chat_id=chat_id,
                        message_id=int(msg_id),
                        defaults={'rendered_html': html_t},
                    )
                except Exception:
                    pass
            time.sleep(0.06)
        return

    if cmd == '/bloqueados':
        ActiveBan.objects.filter(is_active=True, expires_at__isnull=False, expires_at__lte=timezone.now()).update(is_active=False)
        bans = list(ActiveBan.objects.filter(is_active=True).order_by('-banned_at')[:10])
        total_bans = ActiveBan.objects.filter(is_active=True).count()
        if not bans:
            _post_telegram_message(bot_token, chat_id, "✅ No hay IPs bloqueadas activas actualmente.", "Sin bloqueos activos.", thread_id=thread_id)
            return

        lines = [f"🛑 <b>Bloqueos Activos ({total_bans})</b>", "━━━━━━━━━━━━━━━━━━━━━━"]
        kb_rows = []
        for b in bans:
            exp_lbl = timezone.localtime(b.expires_at).strftime('%d/%m %H:%M') if b.expires_at else "Permanente"
            hits = b.blocked_attempts or 0
            hits_txt = f" · 🛡️ {hits} repelido(s)" if hits > 0 else ""
            lines.append(f"• <code>{html.escape(str(b.client_ip))}</code> ({html.escape(exp_lbl)}){hits_txt}")
            if can_manage and len(kb_rows) < 5:
                kb_rows.append([{'text': f"🔓 Revocar {b.client_ip}", 'callback_data': f"ban:revoke:{b.id}"}])

        markup = {'inline_keyboard': kb_rows} if kb_rows else None
        _post_telegram_message(bot_token, chat_id, "\n".join(lines), "\n".join(lines), thread_id=thread_id, reply_markup=markup)
        return

    if cmd == '/estado':
        nodes = list(ProxyNode.objects.all())
        pending_cnt = BanCandidate.objects.filter(status='PENDING').count()
        active_bans_cnt = ActiveBan.objects.filter(is_active=True).count()
        lines = [
            "📊 <b>Estado General — Mithril SIEM</b>",
            "━━━━━━━━━━━━━━━━━━━━━━",
            f"⚠️ <b>Candidatos pendientes:</b> <code>{pending_cnt}</code>",
            f"🛑 <b>IPs bloqueadas activas:</b> <code>{active_bans_cnt}</code>",
            "",
            "<b>📡 Nodos Proxy Nginx:</b>",
        ]
        if not nodes:
            lines.append("• Sin nodos proxy registrados.")
        else:
            for n in nodes:
                st = n.check_health()
                icon = "🟢" if st == 'ONLINE' else ("🟠" if st == 'DEGRADED' else ("⏸️" if st == 'MAINTENANCE' else "🔴"))
                lines.append(
                    f"• {icon} <b>{html.escape(n.name)}</b> (<code>{html.escape(str(n.ip_address))}</code>) — {st} · {n.current_rps} RPS"
                )
        ts_str = timezone.localtime().strftime('%Y-%m-%d %H:%M:%S %Z')
        lines.extend(["━━━━━━━━━━━━━━━━━━━━━━", f"⏱️ <i>{html.escape(ts_str)}</i>"])
        _post_telegram_message(bot_token, chat_id, "\n".join(lines), "\n".join(lines), thread_id=thread_id)


def run_bot_loop():
    """
    Bucle principal de Long Polling para el Bot Interactivo de Mithril SIEM.
    No requiere puertos entrantes ni HTTPS público; se adapta en caliente cuando cambia el token o el switch.
    """
    global _STOP_REQUESTED
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    print("🤖 [Mithril Telegram Bot] Listener interactivo (Long Polling) iniciado.", flush=True)
    offset = 0
    registered_token = ''
    last_poll_db_write = 0.0

    while not _STOP_REQUESTED:
        close_old_connections()
        try:
            config = TelegramConfig.objects.first()
            bot_token = _resolve_bot_token(config)
            is_enabled = bool(config.is_enabled) if config else False
            interactive = bool(getattr(config, 'enable_interactive_bot', True)) if config else True

            if not bot_token or not is_enabled or not interactive:
                time.sleep(8)
                continue

            if bot_token != registered_token:
                _register_bot_commands(bot_token)
                registered_token = bot_token
                offset = 0

            resp = requests.get(
                f"https://api.telegram.org/bot{bot_token}/getUpdates",
                params={
                    'offset': offset,
                    'timeout': 20,
                    'allowed_updates': json.dumps(['message', 'callback_query', 'my_chat_member']),
                },
                timeout=26,
            )

            now_m = time.monotonic()
            if resp.status_code == 200:
                data = resp.json()
                if config and (now_m - last_poll_db_write) >= 25.0:
                    last_poll_db_write = now_m
                    TelegramConfig.objects.filter(id=config.id).update(bot_last_poll_at=timezone.now())

                if data.get('ok'):
                    for upd in data.get('result', []):
                        upd_id = int(upd.get('update_id', 0))
                        if upd_id >= offset:
                            offset = upd_id + 1
                        try:
                            record_discovered_chat_from_update(upd)
                            if upd.get('callback_query'):
                                _handle_callback_query(bot_token, upd['callback_query'])
                            elif upd.get('message'):
                                _handle_command_message(bot_token, upd['message'])
                        except Exception as e_upd:
                            print(f"[Mithril Telegram Bot] Error procesando update #{upd_id}: {e_upd}", flush=True)
            elif resp.status_code == 409:
                # Otra instancia leyendo getUpdates; esperar suavemente
                time.sleep(10)
            elif resp.status_code == 401:
                print("[Mithril Telegram Bot] Token inválido (401). Esperando actualización en configuración...", flush=True)
                time.sleep(20)
            else:
                time.sleep(5)
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            time.sleep(8)
        except Exception as e:
            print(f"[Mithril Telegram Bot] Error en ciclo Long Polling: {e}", flush=True)
            time.sleep(6)
        finally:
            close_old_connections()

    print("🤖 [Mithril Telegram Bot] Listener detenido ordenadamente.", flush=True)
