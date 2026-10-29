import re
import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib import messages
from .models import SecurityRule, TrafficLog, SecurityEvent
from .engine import process_incoming_log, invalidate_rules_cache, sync_cloudflare_ips, get_cloudflare_sync_status
from apps.nodes.models import ProxyNode
from apps.reports.models import AuditTrail

@login_required
def rules_list_view(request):
    if request.method == 'POST':
        action = request.POST.get('action', 'create')
        if action == 'sync_cloudflare':
            cf_state = sync_cloudflare_ips(force=True)
            AuditTrail.objects.create(
                user=request.user,
                action='SYNC_CLOUDFLARE_IPS',
                target='Cloudflare Dynamic CIDR API',
                details={
                    'ipv4_count': cf_state['ipv4_count'],
                    'ipv6_count': cf_state['ipv6_count'],
                    'etag': cf_state['etag'],
                    'source': cf_state['source'],
                },
                ip_address=request.META.get('REMOTE_ADDR')
            )
            messages.success(
                request,
                f"Rangos de Cloudflare sincronizados dinámicamente desde {cf_state['source']} "
                f"({cf_state['ipv4_count']} bloques IPv4 + {cf_state['ipv6_count']} bloques IPv6 | ETag: {cf_state['etag']})."
            )
            return redirect('detection:rules')
        elif action == 'create':
            code = request.POST.get('code', '').strip().upper()
            name = request.POST.get('name', '').strip()
            description = request.POST.get('description', '').strip()
            category = request.POST.get('category', 'SCANNER')
            pattern_regex = request.POST.get('pattern_regex', '').strip()
            threshold_count = max(1, int(request.POST.get('threshold_count', 1) or 1))
            threshold_seconds = max(1, int(request.POST.get('threshold_seconds', 60) or 60))
            risk_points = max(1, min(100, int(request.POST.get('risk_points', 40) or 40)))

            if not code or not name:
                messages.error(request, 'El código y el nombre de la regla son obligatorios.')
            else:
                try:
                    if pattern_regex:
                        re.compile(pattern_regex)
                    rule, created = SecurityRule.objects.update_or_create(
                        code=code,
                        defaults={
                            'name': name,
                            'description': description,
                            'category': category,
                            'pattern_regex': pattern_regex,
                            'threshold_count': threshold_count,
                            'threshold_seconds': threshold_seconds,
                            'risk_points': risk_points,
                            'is_active': True,
                        }
                    )
                    AuditTrail.objects.create(
                        user=request.user,
                        action='SAVE_SECURITY_RULE',
                        target=f"Regla: {rule.code}",
                        details={'name': rule.name, 'category': category, 'risk_points': risk_points},
                        ip_address=request.META.get('REMOTE_ADDR')
                    )
                    invalidate_rules_cache()
                    messages.success(request, f"Regla '{rule.code}' guardada y activada exitosamente.")
                except re.error as err:
                    messages.error(request, f"Expresión regular inválida: {err}")
            return redirect('detection:rules')

    rules = SecurityRule.objects.all()
    active_count = rules.filter(is_active=True).count()
    cf_status = get_cloudflare_sync_status()
    return render(request, 'settings/rules.html', {
        'rules': rules,
        'active_count': active_count,
        'categories': SecurityRule.CATEGORY_CHOICES,
        'cf_status': cf_status,
    })

@login_required
def api_cloudflare_ips_status(request):
    """
    Endpoint para consultar o forzar la sincronización dinámica de los rangos CIDR oficiales de Cloudflare
    directamente desde https://api.cloudflare.com/client/v4/ips
    """
    if request.method == 'POST':
        status_data = sync_cloudflare_ips(force=True)
        return JsonResponse({'status': 'synced', **status_data})
    return JsonResponse({'status': 'ok', **get_cloudflare_sync_status()})

@login_required
def rule_toggle_view(request, rule_id):
    if request.method != 'POST':
        return redirect('detection:rules')

    rule = get_object_or_404(SecurityRule, id=rule_id)
    rule.is_active = not rule.is_active
    rule.save(update_fields=['is_active'])
    invalidate_rules_cache()

    AuditTrail.objects.create(
        user=request.user,
        action='TOGGLE_SECURITY_RULE',
        target=f"Regla: {rule.code}",
        details={'is_active': rule.is_active},
        ip_address=request.META.get('REMOTE_ADDR')
    )

    status_str = "activada" if rule.is_active else "desactivada"
    messages.info(request, f"Regla '{rule.code}' {status_str}.")
    return redirect('detection:rules')

@login_required
def rule_delete_view(request, rule_id):
    if request.method == 'POST':
        rule = get_object_or_404(SecurityRule, id=rule_id)
        code = rule.code
        rule.delete()
        invalidate_rules_cache()
        AuditTrail.objects.create(
            user=request.user,
            action='DELETE_SECURITY_RULE',
            target=f"Regla: {code}",
            details={},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        messages.warning(request, f"Regla '{code}' eliminada.")
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

    if not node:
        node_ip = request.META.get('HTTP_X_NODE_IP') or request.META.get('REMOTE_ADDR')
        if node_ip:
            node = ProxyNode.objects.filter(ip_address=node_ip).first()

    try:
        body = json.loads(request.body.decode('utf-8'))
    except Exception as e:
        return JsonResponse({'error': f'Invalid JSON payload: {str(e)}'}, status=400)

    # Si es una lista de logs (batch) o un solo log
    logs_data = body if isinstance(body, list) else [body]
    processed_count = 0

    for item in logs_data:
        try:
            target_node = node
            if not target_node and 'node_ip' in item:
                target_node = ProxyNode.objects.filter(ip_address=item['node_ip']).first()
            process_incoming_log(item, node=target_node)
            processed_count += 1
        except Exception as e:
            print(f"Error procesando log individual: {e}")

    if node:
        node.update_heartbeat()

    return JsonResponse({
        'status': 'ok',
        'processed_records': processed_count
    })
