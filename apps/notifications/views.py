import os
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from apps.reports.models import AuditTrail
from .models import (
    TelegramConfig,
    TelegramRecipient,
    SEVERITY_CHOICES,
    RECIPIENT_TYPE_CHOICES,
)
from .services import (
    _clean_token,
    _resolve_bot_token,
    ensure_legacy_recipients_migrated,
    get_telegram_bot_info,
    discover_telegram_chats,
    test_telegram_connection,
    test_telegram_broadcast,
)


@login_required
def telegram_settings_view(request):
    config, _ = TelegramConfig.objects.get_or_create(id=1)

    # Si el token vino por .env y el campo en BD está vacío, precargarlo suavemente para mostrarlo listo
    env_token = _clean_token(os.getenv('TELEGRAM_BOT_TOKEN', ''))
    if not (config.bot_token or '').strip() and env_token:
        config.bot_token = env_token
        config.save(update_fields=['bot_token'])

    ensure_legacy_recipients_migrated(config)

    if request.method == 'POST':
        action = request.POST.get('action', '').strip()
        form_token = _clean_token(request.POST.get('bot_token', ''))
        effective_token = form_token or _resolve_bot_token(config)

        if action == 'save':
            prev_token = _clean_token(config.bot_token)
            config.bot_token = form_token
            config.is_enabled = 'is_enabled' in request.POST
            config.min_severity = request.POST.get('min_severity', 'HIGH')
            config.notify_on_ban_candidate = 'notify_on_ban_candidate' in request.POST
            config.notify_on_ban_action = 'notify_on_ban_action' in request.POST
            config.notify_on_node_offline = 'notify_on_node_offline' in request.POST

            # Verificar identidad del bot si cambió el token o aún no se conoce su @username
            if config.bot_token and (config.bot_token != prev_token or not config.bot_username):
                ok_me, info_me = get_telegram_bot_info(config.bot_token)
                if ok_me and isinstance(info_me, dict):
                    config.bot_username = info_me.get('username', '')
                    config.last_error = ''
                else:
                    config.last_error = str(info_me)[:500]
                    messages.warning(request, f"Configuración guardada, pero el Bot Token devolvió un aviso: {info_me}")
            config.save()

            AuditTrail.objects.create(
                user=request.user,
                action='UPDATE_TELEGRAM_CONFIG',
                target='Telegram Bot Global',
                details={
                    'is_enabled': config.is_enabled,
                    'bot_username': config.bot_username,
                    'min_severity': config.min_severity,
                },
                ip_address=request.META.get('REMOTE_ADDR'),
            )
            messages.success(request, '✅ Configuración global de Telegram guardada correctamente.')

        elif action == 'verify_bot':
            if not effective_token:
                messages.error(request, 'Debes ingresar el Bot Token primero.')
            else:
                if form_token and form_token != config.bot_token:
                    config.bot_token = form_token
                ok_me, info_me = get_telegram_bot_info(effective_token)
                if ok_me and isinstance(info_me, dict):
                    uname = info_me.get('username', '')
                    fname = info_me.get('first_name', 'Bot')
                    config.bot_username = uname
                    config.last_error = ''
                    config.save(update_fields=['bot_token', 'bot_username', 'last_error'])
                    messages.success(request, f"✅ Bot verificado correctamente: {fname} (@{uname}).")
                else:
                    config.last_error = str(info_me)[:500]
                    config.save(update_fields=['last_error'])
                    messages.error(request, f"❌ No se pudo verificar el Bot: {info_me}")

        elif action == 'discover_chats':
            if not effective_token:
                messages.error(request, 'Debes configurar el Bot Token antes de detectar chats.')
            else:
                if form_token and form_token != config.bot_token:
                    config.bot_token = form_token
                    config.save(update_fields=['bot_token'])
                if not config.bot_username:
                    ok_me, info_me = get_telegram_bot_info(effective_token)
                    if ok_me and isinstance(info_me, dict) and info_me.get('username'):
                        config.bot_username = info_me['username']
                        config.save(update_fields=['bot_username'])

                ok_d, err_d, chats = discover_telegram_chats(effective_token)
                if not ok_d:
                    config.last_error = err_d[:500]
                    config.save(update_fields=['last_error'])
                    messages.error(request, f"❌ Error detectando chats del bot: {err_d}")
                else:
                    request.session['tg_discovered_chats'] = chats
                    if chats:
                        new_cnt = sum(1 for c in chats if not c['already_added'])
                        messages.success(
                            request,
                            f"🔍 Se detectaron {len(chats)} chat(s) en el bot ({new_cnt} nuevo(s) disponible(s) para agregar en 1 clic).",
                        )
                    else:
                        bot_hint = f"@{config.bot_username}" if config.bot_username else "tu bot"
                        messages.info(
                            request,
                            f"No hay mensajes recientes en {bot_hint}. Pide a cada persona que abra {bot_hint} en Telegram, presione /start y vuelve a hacer clic en 'Detectar Chats'.",
                        )

        elif action == 'add_recipient':
            name = request.POST.get('rec_name', '').strip()
            chat_id = request.POST.get('rec_chat_id', '').strip()
            thread_id = request.POST.get('rec_thread_id', '').strip()
            rtype = request.POST.get('rec_type', 'USER').strip()
            role_label = request.POST.get('rec_role', '').strip()
            min_sev = request.POST.get('rec_min_severity', config.min_severity or 'HIGH').strip()
            on_cand = 'rec_notify_ban_candidate' in request.POST
            on_ban = 'rec_notify_ban_action' in request.POST
            on_off = 'rec_notify_node_offline' in request.POST
            send_test_now = 'rec_send_test_now' in request.POST

            if not chat_id:
                messages.error(request, 'El Chat ID es obligatorio para agregar un destinatario.')
            else:
                if not name:
                    name = f"Destinatario {chat_id}"
                if rtype not in ('USER', 'GROUP', 'CHANNEL'):
                    rtype = 'GROUP' if chat_id.startswith('-') else ('CHANNEL' if chat_id.startswith('@') else 'USER')

                rec, created = TelegramRecipient.objects.update_or_create(
                    chat_id=chat_id,
                    defaults={
                        'name': name[:80],
                        'message_thread_id': thread_id[:32],
                        'recipient_type': rtype,
                        'role_label': role_label[:64],
                        'is_active': True,
                        'min_severity': min_sev if min_sev in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') else 'HIGH',
                        'notify_on_ban_candidate': on_cand,
                        'notify_on_ban_action': on_ban,
                        'notify_on_node_offline': on_off,
                    },
                )

                # Si estaba en la lista de descubiertos en sesión, marcarlo como ya agregado
                disc = request.session.get('tg_discovered_chats')
                if isinstance(disc, list):
                    for item in disc:
                        if item.get('chat_id') == chat_id:
                            item['already_added'] = True
                    request.session['tg_discovered_chats'] = disc

                AuditTrail.objects.create(
                    user=request.user,
                    action='ADD_TELEGRAM_RECIPIENT',
                    target=f"Telegram: {rec.name} ({rec.chat_id})",
                    details={'type': rec.recipient_type, 'role': rec.role_label, 'min_severity': rec.min_severity},
                    ip_address=request.META.get('REMOTE_ADDR'),
                )

                if send_test_now and effective_token:
                    ok_t, detail_t = test_telegram_connection(
                        bot_token=effective_token,
                        chat_id=rec.chat_id,
                        thread_id=rec.message_thread_id,
                        recipient_name=rec.name,
                        recipient_obj=rec,
                        config_obj=config,
                    )
                    if ok_t:
                        messages.success(request, f"✅ Destinatario '{rec.name}' agregado y mensaje de prueba entregado con éxito.")
                    else:
                        messages.warning(request, f"⚠️ Destinatario '{rec.name}' guardado, pero falló la prueba: {detail_t}")
                else:
                    verb = "agregado" if created else "actualizado"
                    messages.success(request, f"✅ Destinatario '{rec.name}' ({rec.chat_id}) {verb} correctamente.")

        elif action == 'edit_recipient':
            rec_id = request.POST.get('recipient_id')
            rec = get_object_or_404(TelegramRecipient, id=rec_id)
            new_name = request.POST.get('rec_name', '').strip()
            new_chat_id = request.POST.get('rec_chat_id', '').strip()
            if not new_name or not new_chat_id:
                messages.error(request, 'El nombre y el Chat ID no pueden quedar vacíos.')
            elif TelegramRecipient.objects.filter(chat_id=new_chat_id).exclude(id=rec.id).exists():
                messages.error(request, f"Ya existe otro destinatario con el Chat ID {new_chat_id}.")
            else:
                rec.name = new_name[:80]
                rec.chat_id = new_chat_id[:64]
                rec.message_thread_id = request.POST.get('rec_thread_id', '').strip()[:32]
                rtype = request.POST.get('rec_type', rec.recipient_type).strip()
                if rtype in ('USER', 'GROUP', 'CHANNEL'):
                    rec.recipient_type = rtype
                rec.role_label = request.POST.get('rec_role', '').strip()[:64]
                min_sev = request.POST.get('rec_min_severity', rec.min_severity).strip()
                if min_sev in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
                    rec.min_severity = min_sev
                rec.notify_on_ban_candidate = 'rec_notify_ban_candidate' in request.POST
                rec.notify_on_ban_action = 'rec_notify_ban_action' in request.POST
                rec.notify_on_node_offline = 'rec_notify_node_offline' in request.POST
                rec.is_active = 'rec_is_active' in request.POST
                rec.save()
                messages.success(request, f"✅ Destinatario '{rec.name}' actualizado.")

        elif action == 'toggle_recipient':
            rec = get_object_or_404(TelegramRecipient, id=request.POST.get('recipient_id'))
            rec.is_active = not rec.is_active
            rec.save(update_fields=['is_active'])
            state_lbl = "activado" if rec.is_active else "pausado"
            messages.info(request, f"Destinatario '{rec.name}' {state_lbl}.")

        elif action == 'delete_recipient':
            rec = get_object_or_404(TelegramRecipient, id=request.POST.get('recipient_id'))
            rec_name = rec.name
            rec_cid = rec.chat_id
            rec.delete()
            AuditTrail.objects.create(
                user=request.user,
                action='DELETE_TELEGRAM_RECIPIENT',
                target=f"Telegram: {rec_name} ({rec_cid})",
                details={},
                ip_address=request.META.get('REMOTE_ADDR'),
            )
            messages.warning(request, f"Destinatario '{rec_name}' ({rec_cid}) eliminado.")

        elif action == 'test_recipient':
            rec = get_object_or_404(TelegramRecipient, id=request.POST.get('recipient_id'))
            if not effective_token:
                messages.error(request, 'Debes configurar el Bot Token antes de enviar pruebas.')
            else:
                ok_t, detail_t = test_telegram_connection(
                    bot_token=effective_token,
                    chat_id=rec.chat_id,
                    thread_id=rec.message_thread_id,
                    recipient_name=rec.name,
                    recipient_obj=rec,
                    config_obj=config,
                )
                if ok_t:
                    messages.success(request, f"✅ Alerta de prueba entregada a '{rec.name}' ({rec.chat_id}).")
                else:
                    messages.error(request, f"❌ Fallo enviando a '{rec.name}' ({rec.chat_id}): {detail_t}")

        elif action in ('test_all', 'test'):
            if not effective_token:
                messages.error(request, 'Debes ingresar el Bot Token para probar las alertas.')
            else:
                if form_token and form_token != config.bot_token:
                    config.bot_token = form_token
                    config.save(update_fields=['bot_token'])
                ok_c, fail_c, details = test_telegram_broadcast(effective_token, config_obj=config)
                if ok_c == 0 and fail_c == 0:
                    messages.warning(request, 'No hay destinatarios activos configurados. Agrega al menos una persona, grupo o canal abajo.')
                elif fail_c == 0:
                    messages.success(request, f"✅ Alerta de prueba entregada con éxito a {ok_c} destinatario(s) activo(s).")
                else:
                    failed_str = "; ".join(f"{d['name']}: {d['detail']}" for d in details if not d['ok'])
                    if ok_c > 0:
                        messages.warning(request, f"⚠️ Entregado a {ok_c}, fallaron {fail_c} → {failed_str}")
                    else:
                        messages.error(request, f"❌ Error al entregar a los {fail_c} destinatario(s): {failed_str}")

        elif action == 'clear_discovered':
            request.session.pop('tg_discovered_chats', None)

        return redirect('notifications:settings')

    recipients = list(TelegramRecipient.objects.all())
    active_count = sum(1 for r in recipients if r.is_active)
    discovered_chats = request.session.get('tg_discovered_chats', [])
    existing_ids = {r.chat_id for r in recipients}
    for item in discovered_chats:
        item['already_added'] = item.get('chat_id') in existing_ids

    return render(request, 'settings/telegram.html', {
        'config': config,
        'recipients': recipients,
        'active_recipients_count': active_count,
        'discovered_chats': discovered_chats,
        'severity_choices': SEVERITY_CHOICES,
        'recipient_type_choices': RECIPIENT_TYPE_CHOICES,
    })
