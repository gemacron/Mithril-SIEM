import re
import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib import messages
from datetime import timedelta
from .models import SecurityRule, TrafficLog, SecurityEvent
from .engine import process_incoming_log, invalidate_rules_cache, sync_cloudflare_ips, get_cloudflare_sync_status, extract_log_ip_meta
from apps.mitigation.models import IpReputation
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

@login_required
def log_inspect_api_view(request, log_id):
    """
    Devuelve la verificación técnica forense de una petición HTTP individual:
    - Estado de seguridad y reglas de detección verificadas
    - Metadatos de la IP del cliente (real y Cloudflare)
    - Reconstrucción de la petición HTTP completa
    """
    log = get_object_or_404(TrafficLog.objects.select_related('node'), id=log_id)
    meta = extract_log_ip_meta(log.client_ip, log.raw_headers)
    reputation = IpReputation.objects.filter(client_ip=log.client_ip).first()

    events = list(SecurityEvent.objects.filter(client_ip=log.client_ip, details__log_id=log.id).select_related('rule'))
    if not events:
        w_start = log.created_at - timedelta(seconds=1)
        w_end = log.created_at + timedelta(seconds=1)
        events = list(SecurityEvent.objects.filter(client_ip=log.client_ip, created_at__gte=w_start, created_at__lte=w_end).select_related('rule'))

    events_data = [{
        'id': ev.id,
        'rule_code': ev.rule.code,
        'rule_name': ev.rule.name,
        'severity': ev.severity,
        'matched_payload': ev.matched_payload,
        'category': ev.rule.get_category_display() if hasattr(ev.rule, 'get_category_display') else ev.rule.category,
    } for ev in events]

    headers = log.raw_headers if isinstance(log.raw_headers, dict) else {}
    connection_ip = headers.get('connection_ip') or log.client_ip
    real_ip = meta['real_client_ip'] or (log.client_ip if not meta['is_cloudflare'] else '')

    full_path = f"{log.uri}?{log.query_params}" if log.query_params else log.uri
    raw_lines = [f"{log.http_method} {full_path} HTTP/1.1"]
    raw_lines.append(f"Host: {headers.get('host', 'servidor')}")
    if headers.get('user_agent') or log.user_agent:
        raw_lines.append(f"User-Agent: {headers.get('user_agent') or log.user_agent}")
    if headers.get('referer') or log.referer:
        raw_lines.append(f"Referer: {headers.get('referer') or log.referer}")
    if meta['is_cloudflare']:
        if meta['cloudflare_ip']:
            raw_lines.append(f"CF-Connecting-IP: {real_ip}")
            raw_lines.append(f"CF-Ray: {headers.get('cf_ray', '-')}")
            raw_lines.append(f"CF-IPCountry: {headers.get('cf_country', headers.get('cf_ipcountry', '-'))}")
    if headers.get('x_forwarded_for'):
        raw_lines.append(f"X-Forwarded-For: {headers.get('x_forwarded_for')}")
    if headers.get('x_real_ip'):
        raw_lines.append(f"X-Real-IP: {headers.get('x_real_ip')}")

    return JsonResponse({
        'status': 'ok',
        'log': {
            'id': log.id,
            'timestamp': log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'node_name': log.node.name if log.node else 'Direct',
            'client_ip': log.client_ip,
            'connection_ip': connection_ip,
            'real_client_ip': real_ip,
            'is_cloudflare': meta['is_cloudflare'],
            'cloudflare_ip': meta['cloudflare_ip'],
            'http_method': log.http_method,
            'uri': log.uri,
            'query_params': log.query_params,
            'status_code': log.status_code,
            'bytes_sent': log.bytes_sent,
            'latency_ms': log.latency_ms,
            'user_agent': log.user_agent,
            'referer': log.referer,
            'country_code': log.country_code,
            'country_name': log.country_name,
            'city': log.city,
            'headers': headers,
            'raw_http': "\n".join(raw_lines),
        },
        'security': {
            'is_threat': len(events_data) > 0 or log.status_code >= 400,
            'risk_score': reputation.current_risk_score if reputation else 0,
            'reputation_status': reputation.status if reputation else 'MONITORED',
            'total_violations': reputation.total_violations if reputation else 0,
            'events': events_data,
        }
    })
