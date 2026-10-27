import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib import messages
from .models import SecurityRule, TrafficLog, SecurityEvent
from .engine import process_incoming_log
from apps.nodes.models import ProxyNode

@login_required
def rules_list_view(request):
    rules = SecurityRule.objects.all()
    return render(request, 'settings/rules.html', {'rules': rules})

@login_required
def rule_toggle_view(request, rule_id):
    if request.method != 'POST':
        return redirect('detection:rules')

    rule = get_object_or_404(SecurityRule, id=rule_id)
    rule.is_active = not rule.is_active
    rule.save(update_fields=['is_active'])

    status_str = "activada" if rule.is_active else "desactivada"
    messages.info(request, f"Regla '{rule.code}' {status_str}.")
    return redirect('detection:rules')

@csrf_exempt
def api_ingest(request):
    """
    Ingestión de logs de tráfico desde proxies Nginx (Vector / Fluent Bit / Python Agent)
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    node = None
    if auth_header.startswith('Bearer '):
        api_key = auth_header.split(' ')[1].strip()
        node = ProxyNode.objects.filter(api_key=api_key).first()

    try:
        body = json.loads(request.body.decode('utf-8'))
    except Exception as e:
        return JsonResponse({'error': f'Invalid JSON payload: {str(e)}'}, status=400)

    # Si es una lista de logs (batch) o un solo log
    logs_data = body if isinstance(body, list) else [body]
    processed_count = 0

    for item in logs_data:
        try:
            process_incoming_log(item, node=node)
            processed_count += 1
        except Exception as e:
            print(f"Error procesando log individual: {e}")

    if node:
        node.update_heartbeat()

    return JsonResponse({
        'status': 'ok',
        'processed_records': processed_count
    })
