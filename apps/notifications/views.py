from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import TelegramConfig
from .services import test_telegram_connection

@login_required
def telegram_settings_view(request):
    config, _ = TelegramConfig.objects.get_or_create(id=1)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'save':
            config.bot_token = request.POST.get('bot_token', '').strip()
            config.chat_id = request.POST.get('chat_id', '').strip()
            config.is_enabled = 'is_enabled' in request.POST
            config.min_severity = request.POST.get('min_severity', 'HIGH')
            config.notify_on_ban_candidate = 'notify_on_ban_candidate' in request.POST
            config.notify_on_node_offline = 'notify_on_node_offline' in request.POST
            config.save()
            messages.success(request, 'Configuración de alertas de Telegram actualizada.')

        elif action == 'test':
            token = request.POST.get('bot_token', '').strip() or config.bot_token
            chat = request.POST.get('chat_id', '').strip() or config.chat_id

            if not token or not chat:
                messages.error(request, 'Debes ingresar el Bot Token y el Chat ID para probar la conexión.')
            else:
                success, resp = test_telegram_connection(token, chat)
                if success:
                    messages.success(request, '✅ Mensaje de prueba enviado con éxito a Telegram.')
                else:
                    messages.error(request, f'❌ Error al conectar con Telegram: {resp}')

        return redirect('notifications:settings')

    return render(request, 'settings/telegram.html', {'config': config})
