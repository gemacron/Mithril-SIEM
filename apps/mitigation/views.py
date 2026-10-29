import urllib.parse
from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import BanCandidate, ActiveBan, IpReputation, NodeBanSync
from apps.nodes.models import ProxyNode
from apps.detection.models import SecurityEvent, TrafficLog
from apps.reports.models import AuditTrail
from apps.notifications.services import send_telegram_alert

def _build_request_dict(log_obj=None, fallback_details=None, client_ip='', node_name='Direct', created_at_str=''):
    """
    Construye un diccionario forense completo de una petición HTTP (con reconstrucción Raw HTTP)
    a partir de un objeto TrafficLog o de los detalles guardados en SecurityEvent.
    """
    if log_obj:
        method = log_obj.http_method or 'GET'
        uri = log_obj.uri or '/'
        query = log_obj.query_params or ''
        status_code = log_obj.status_code
        bytes_sent = log_obj.bytes_sent
        latency_ms = log_obj.latency_ms
        user_agent = log_obj.user_agent or ''
        referer = log_obj.referer or ''
        country_code = log_obj.country_code or ''
        country_name = log_obj.country_name or ''
        city = log_obj.city or ''
        headers = log_obj.raw_headers if isinstance(log_obj.raw_headers, dict) else {}
        node_str = log_obj.node.name if log_obj.node else node_name
        ts_str = log_obj.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ip_str = log_obj.client_ip
        req_id = log_obj.id
    else:
        d = fallback_details or {}
        method = d.get('http_method', 'GET')
        uri = d.get('uri', '/')
        query = d.get('query_params', d.get('query', ''))
        status_code = d.get('status_code', 200)
        bytes_sent = d.get('bytes_sent', 0)
        latency_ms = d.get('latency_ms', 0.0)
        user_agent = d.get('user_agent', d.get('agent', ''))
        referer = d.get('referer', '')
        country_code = d.get('country_code', '')
        country_name = d.get('country_name', '')
        city = d.get('city', '')
        headers = d.get('headers', {}) if isinstance(d.get('headers'), dict) else {}
        node_str = d.get('node', node_name)
        ts_str = created_at_str
        ip_str = client_ip
        req_id = d.get('log_id', 0)

    full_path = f"{uri}?{query}" if query else uri
    try:
        decoded_once = urllib.parse.unquote_plus(full_path)
        decoded_path = urllib.parse.unquote_plus(decoded_once)
    except Exception:
        decoded_path = full_path

    # Extraer host si URI tiene formato [host]/path
    host_header = headers.get('Host') or headers.get('host') or ''
    request_target = full_path
    if full_path.startswith('[') and ']' in full_path:
        end_bracket = full_path.find(']')
        if not host_header:
            host_header = full_path[1:end_bracket]
        request_target = full_path[end_bracket + 1:] or '/'

    raw_lines = [f"{method} {request_target} HTTP/1.1"]
    if host_header:
        raw_lines.append(f"Host: {host_header}")
    raw_lines.append(f"X-Real-IP: {ip_str}")
    if user_agent:
        raw_lines.append(f"User-Agent: {user_agent}")
    if referer and referer != '-':
        raw_lines.append(f"Referer: {referer}")
    for hk, hv in headers.items():
        if hk.lower() not in ('host', 'user-agent', 'referer', 'x-real-ip'):
            raw_lines.append(f"{hk}: {hv}")

    raw_lines.append("")
    raw_lines.append(f"# --- RESPUESTA NGINX ({node_str}) ---")
    raw_lines.append(f"HTTP/1.1 {status_code} | Bytes: {bytes_sent} | Latencia: {latency_ms} ms")
    if decoded_path != full_path:
        raw_lines.append(f"# --- PAYLOAD DECODIFICADO (ANTI-EVASIÓN) ---")
        raw_lines.append(decoded_path)

    return {
        'id': req_id,
        'timestamp': ts_str,
        'client_ip': ip_str,
        'node': node_str,
        'http_method': method,
        'host': host_header or node_str,
        'uri': uri,
        'query_params': query,
        'full_path': full_path,
        'decoded_path': decoded_path,
        'status_code': status_code,
        'bytes_sent': bytes_sent,
        'latency_ms': latency_ms,
        'user_agent': user_agent or '(Sin User-Agent)',
        'referer': referer or '-',
        'country_code': country_code,
        'country_name': country_name or country_code or 'Desconocido',
        'city': city or '-',
        'headers': headers,
        'raw_http': "\n".join(raw_lines),
    }

@login_required
def candidates_list_view(request):
    candidates = BanCandidate.objects.filter(status='PENDING').select_related('trigger_event', 'trigger_event__rule', 'trigger_event__node')
    return render(request, 'mitigation/candidates.html', {'candidates': candidates})

@login_required
def candidate_inspect_api_view(request, candidate_id):
    """
    Devuelve toda la evidencia forense de un Candidato a Bloqueo:
    - Qué intentó hacer (regla detonada, payload exacto, categoría)
    - Todos los campos de la petición HTTP que disparó la alerta + reconstrucción Raw HTTP
    - Historial de eventos de seguridad disparados por esta IP
    - Últimas 30 peticiones HTTP realizadas por esta IP
    """
    candidate = get_object_or_404(
        BanCandidate.objects.select_related('trigger_event', 'trigger_event__rule', 'trigger_event__node'),
        id=candidate_id
    )
    ip_str = candidate.client_ip
    reputation = IpReputation.objects.filter(client_ip=ip_str).first()

    events_qs = SecurityEvent.objects.filter(client_ip=ip_str).select_related('rule', 'node').order_by('-created_at')[:20]
    logs_qs = TrafficLog.objects.filter(client_ip=ip_str).select_related('node').order_by('-created_at')[:30]

    trigger_ev = candidate.trigger_event or (events_qs[0] if events_qs else None)

    # Buscar el TrafficLog exacto que disparó el evento o el más reciente de esa IP
    primary_log = None
    if trigger_ev and isinstance(trigger_ev.details, dict) and trigger_ev.details.get('log_id'):
        primary_log = TrafficLog.objects.filter(id=trigger_ev.details.get('log_id')).select_related('node').first()
    if not primary_log and logs_qs:
        primary_log = logs_qs[0]

    primary_request = _build_request_dict(
        log_obj=primary_log,
        fallback_details=trigger_ev.details if trigger_ev else {},
        client_ip=ip_str,
        node_name=trigger_ev.node.name if (trigger_ev and trigger_ev.node) else 'Direct',
        created_at_str=trigger_ev.created_at.strftime('%Y-%m-%d %H:%M:%S') if trigger_ev else candidate.created_at.strftime('%Y-%m-%d %H:%M:%S')
    )

    trigger_summary = {
        'rule_code': trigger_ev.rule.code if (trigger_ev and trigger_ev.rule) else 'HEURÍSTICA',
        'rule_name': trigger_ev.rule.name if (trigger_ev and trigger_ev.rule) else 'Detección Heurística / Acumulación de Riesgo',
        'rule_description': trigger_ev.rule.description if (trigger_ev and trigger_ev.rule) else candidate.suggested_reason,
        'rule_category': trigger_ev.rule.get_category_display() if (trigger_ev and trigger_ev.rule) else 'Anomalía de Tráfico',
        'severity': trigger_ev.severity if trigger_ev else 'HIGH',
        'matched_payload': trigger_ev.matched_payload if trigger_ev else candidate.suggested_reason,
        'timestamp': trigger_ev.created_at.strftime('%Y-%m-%d %H:%M:%S') if trigger_ev else candidate.created_at.strftime('%Y-%m-%d %H:%M:%S'),
    }

    events_list = []
    for ev in events_qs:
        ev_details = ev.details if isinstance(ev.details, dict) else {}
        events_list.append({
            'id': ev.id,
            'timestamp': ev.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'rule_code': ev.rule.code if ev.rule else 'HEURISTIC',
            'rule_name': ev.rule.name if ev.rule else 'Heurística',
            'severity': ev.severity,
            'matched_payload': ev.matched_payload,
            'uri': ev_details.get('uri', primary_request['uri']),
            'query_params': ev_details.get('query_params', ev_details.get('query', '')),
            'http_method': ev_details.get('http_method', 'GET'),
            'status_code': ev_details.get('status_code', '-'),
            'user_agent': ev_details.get('user_agent', ev_details.get('agent', '')),
            'node': ev.node.name if ev.node else ev_details.get('node', 'Direct'),
        })

    recent_requests = [_build_request_dict(log_obj=l) for l in logs_qs]
    if not recent_requests:
        recent_requests = [primary_request]

    return JsonResponse({
        'status': 'ok',
        'candidate': {
            'id': candidate.id,
            'client_ip': ip_str,
            'accumulated_score': candidate.accumulated_score,
            'suggested_reason': candidate.suggested_reason,
            'status': candidate.status,
            'created_at': candidate.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'total_violations': reputation.total_violations if reputation else len(events_list),
            'country_code': (reputation.country_code if reputation and reputation.country_code else primary_request['country_code']),
            'country_name': primary_request['country_name'],
            'city': primary_request['city'],
        },
        'trigger': trigger_summary,
        'primary_request': primary_request,
        'security_events': events_list,
        'recent_requests': recent_requests,
    })

@login_required
def approve_candidate_view(request, candidate_id):
    if request.method != 'POST':
        return redirect('mitigation:candidates')

    candidate = get_object_or_404(BanCandidate, id=candidate_id)
    ip_str = candidate.client_ip
    duration_hours = int(request.POST.get('duration_hours', 24))

    expires_at = timezone.now() + timedelta(hours=duration_hours) if duration_hours > 0 else None

    # 1. Crear o reactivar ActiveBan
    ban, created = ActiveBan.objects.update_or_create(
        client_ip=ip_str,
        defaults={
            'reason': candidate.suggested_reason,
            'approved_by': request.user,
            'banned_at': timezone.now(),
            'expires_at': expires_at,
            'is_active': True,
            'revoked_at': None,
            'revoked_by': None,
        }
    )

    # 2. Actualizar Candidato
    candidate.status = 'APPROVED'
    candidate.reviewed_by = request.user
    candidate.reviewed_at = timezone.now()
    candidate.save(update_fields=['status', 'reviewed_by', 'reviewed_at'])

    # 3. Actualizar Reputación de la IP
    IpReputation.objects.filter(client_ip=ip_str).update(status='BANNED')

    # 4. Crear registros de sincronización para cada proxy activo
    active_nodes = ProxyNode.objects.all()
    for node in active_nodes:
        NodeBanSync.objects.update_or_create(
            ban=ban,
            node=node,
            defaults={'is_synced': False}
        )

    # 5. Registrar en auditoría
    AuditTrail.objects.create(
        user=request.user,
        action='APPROVE_BAN',
        target=f"IP: {ip_str}",
        details={
            'candidate_id': candidate.id,
            'duration_hours': duration_hours,
            'reason': candidate.suggested_reason
        },
        ip_address=request.META.get('REMOTE_ADDR')
    )

    # 6. Notificar a Telegram
    send_telegram_alert(
        title="🛑 Bloqueo de IP Aprobado por Operador",
        message=(
            f"IP: {ip_str}\n"
            f"Operador: {request.user.username}\n"
            f"Duración: {'Permanente' if not expires_at else f'{duration_hours} horas'}\n"
            f"Motivo: {candidate.suggested_reason}\n"
            f"Distribuyendo orden de bloqueo a {active_nodes.count()} proxies Nginx..."
        )
    )

    messages.success(request, f"IP {ip_str} bloqueada exitosamente. Se ha ordenado el bloqueo a todos los proxies.")
    return redirect('mitigation:candidates')

@login_required
def dismiss_candidate_view(request, candidate_id):
    if request.method != 'POST':
        return redirect('mitigation:candidates')

    candidate = get_object_or_404(BanCandidate, id=candidate_id)
    candidate.status = 'DISMISSED'
    candidate.reviewed_by = request.user
    candidate.reviewed_at = timezone.now()
    candidate.save(update_fields=['status', 'reviewed_by', 'reviewed_at'])

    # Bajar puntaje de riesgo para no alertar de inmediato
    IpReputation.objects.filter(client_ip=candidate.client_ip).update(current_risk_score=20, status='MONITORED')

    AuditTrail.objects.create(
        user=request.user,
        action='DISMISS_CANDIDATE',
        target=f"IP: {candidate.client_ip}",
        details={'candidate_id': candidate.id},
        ip_address=request.META.get('REMOTE_ADDR')
    )

    messages.info(request, f"Candidato {candidate.client_ip} descartado.")
    return redirect('mitigation:candidates')

@login_required
def active_bans_list_view(request):
    # Expirar automáticamente bloqueos cuyo tiempo haya concluido
    ActiveBan.objects.filter(is_active=True, expires_at__isnull=False, expires_at__lte=timezone.now()).update(is_active=False)
    bans = ActiveBan.objects.filter(is_active=True).select_related('approved_by').prefetch_related('sync_records', 'sync_records__node')
    return render(request, 'mitigation/active_bans.html', {'bans': bans})

@login_required
def revoke_ban_view(request, ban_id):
    if request.method != 'POST':
        return redirect('mitigation:active_bans')

    ban = get_object_or_404(ActiveBan, id=ban_id)
    ban.is_active = False
    ban.revoked_at = timezone.now()
    ban.revoked_by = request.user
    ban.save(update_fields=['is_active', 'revoked_at', 'revoked_by'])

    IpReputation.objects.filter(client_ip=ban.client_ip).update(status='MONITORED', current_risk_score=0)

    # Notificar a los proxies para que remuevan la IP
    NodeBanSync.objects.filter(ban=ban).update(is_synced=False)

    AuditTrail.objects.create(
        user=request.user,
        action='REVOKE_BAN',
        target=f"IP: {ban.client_ip}",
        details={'ban_id': ban.id},
        ip_address=request.META.get('REMOTE_ADDR')
    )

    messages.warning(request, f"Bloqueo para la IP {ban.client_ip} ha sido revocado.")
    return redirect('mitigation:active_bans')

@csrf_exempt
def api_node_sync_bans(request):
    """
    Invocado por el agente de Mithril en cada proxy Nginx para obtener
    la lista de IPs bloqueadas activas que debe aplicar en su iptables/ipset local
    """
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Unauthorized'}, status=401)

    api_key = auth_header.split(' ')[1].strip()
    try:
        node = ProxyNode.objects.get(api_key=api_key)
    except ProxyNode.DoesNotExist:
        return JsonResponse({'error': 'Invalid node API key'}, status=403)

    # Expirar automáticamente bloqueos vencidos antes de enviar la lista al bouncer
    ActiveBan.objects.filter(is_active=True, expires_at__isnull=False, expires_at__lte=timezone.now()).update(is_active=False)
    active_bans = ActiveBan.objects.filter(is_active=True)
    ban_ips = [b.client_ip for b in active_bans]

    # Confirmar sincronización
    NodeBanSync.objects.filter(node=node, ban__in=active_bans).update(
        is_synced=True,
        synced_at=timezone.now()
    )

    return JsonResponse({
        'status': 'ok',
        'node': node.name,
        'count': len(ban_ips),
        'banned_ips': ban_ips
    })
