from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
from apps.nodes.models import ProxyNode
from apps.mitigation.models import BanCandidate, ActiveBan
from apps.detection.models import TrafficLog, SecurityEvent
from apps.detection.engine import is_cloudflare_ip, resolve_geoip, extract_log_ip_meta, get_cloudflare_sync_status

def _enrich_candidate_cf(c):
    ev = c.trigger_event
    ev_details = ev.details if (ev and isinstance(ev.details, dict)) else {}
    meta = extract_log_ip_meta(c.client_ip, ev_details)
    if meta['is_cloudflare'] and not meta['real_client_ip']:
        # Buscar en los últimos logs de esta IP si alguno trajo la IP real en raw_headers
        recent_with_real = (
            TrafficLog.objects.filter(client_ip=c.client_ip)
            .exclude(raw_headers={})
            .order_by('-created_at')[:10]
        )
        for rl in recent_with_real:
            sub_meta = extract_log_ip_meta(rl.client_ip, rl.raw_headers)
            if sub_meta['real_client_ip']:
                meta['real_client_ip'] = sub_meta['real_client_ip']
                break
    c.is_cloudflare = meta['is_cloudflare']
    c.cloudflare_ip = meta['cloudflare_ip']
    c.real_client_ip = meta['real_client_ip']
    return meta

@login_required
def dashboard_view(request):
    nodes = ProxyNode.objects.all()
    for n in nodes:
        n.check_health()

    candidates = list(BanCandidate.objects.filter(status='PENDING').select_related('trigger_event', 'trigger_event__rule')[:5])
    for c in candidates:
        _enrich_candidate_cf(c)
    recent_events = SecurityEvent.objects.select_related('rule', 'node').order_by('-created_at')[:8]

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    since_24h = now - timedelta(hours=24)

    # Expirar bloqueos vencidos automáticamente
    ActiveBan.objects.filter(is_active=True, expires_at__isnull=False, expires_at__lte=now).update(is_active=False)

    recent_logs = list(TrafficLog.objects.select_related('node').order_by('-created_at')[:25])
    recent_ips = {log.client_ip for log in recent_logs}
    threat_ips = set(
        SecurityEvent.objects.filter(client_ip__in=recent_ips, created_at__gte=since_24h)
        .values_list('client_ip', flat=True).distinct()
    ) if recent_ips else set()

    for log in recent_logs:
        log.is_threat = (log.client_ip in threat_ips) or (log.status_code >= 400)
        meta = extract_log_ip_meta(log.client_ip, log.raw_headers)
        log.is_cloudflare = meta['is_cloudflare']
        log.cloudflare_ip = meta['cloudflare_ip']
        log.real_client_ip = meta['real_client_ip']

    total_logs_today = TrafficLog.objects.filter(created_at__gte=today_start).count()
    threats_today = SecurityEvent.objects.filter(created_at__gte=today_start).count()
    online_nodes_count = sum(1 for n in nodes if n.status == 'ONLINE')
    pending_candidates_count = BanCandidate.objects.filter(status='PENDING').count()
    active_bans_count = ActiveBan.objects.filter(is_active=True).count()
    cf_status = get_cloudflare_sync_status()

    context = {
        'nodes': nodes,
        'online_nodes_count': online_nodes_count,
        'candidates': candidates,
        'pending_candidates_count': pending_candidates_count,
        'active_bans_count': active_bans_count,
        'recent_events': recent_events,
        'recent_logs': recent_logs,
        'total_logs_today': total_logs_today,
        'threats_today': threats_today,
        'cf_status': cf_status,
    }
    return render(request, 'dashboard/index.html', context)

@login_required
def api_map_data(request):
    """
    Retorna datos agregados de países y coordenadas de peticiones sospechosas
    para el mapa táctico 2D
    """
    now = timezone.now()
    since = now - timedelta(hours=24)

    # Top países con eventos de seguridad
    country_stats = (
        TrafficLog.objects.filter(created_at__gte=since)
        .exclude(country_code__in=['', 'LAN'])
        .values('country_code', 'country_name')
        .annotate(total=Count('id'))
        .order_by('-total')[:15]
    )

    # Coordenadas recientes de incidentes y tráfico para los puntos del mapa
    raw_points = list(
        TrafficLog.objects.filter(created_at__gte=since)
        .exclude(latitude__isnull=True)
        .values('latitude', 'longitude', 'country_name', 'client_ip', 'status_code', 'raw_headers')
        .order_by('-created_at')[:80]
    )
    point_ips = {p['client_ip'] for p in raw_points}
    threat_ips = set(
        SecurityEvent.objects.filter(client_ip__in=point_ips, created_at__gte=since)
        .values_list('client_ip', flat=True).distinct()
    ) if point_ips else set()
    candidate_ips = set(
        BanCandidate.objects.filter(status='PENDING').values_list('client_ip', flat=True)
    )
    threat_ips.update(candidate_ips)

    recent_points = []
    for p in raw_points:
        # Si un punto histórico quedó con la misma coordenada exacta del nodo base (-34.6037, -58.3816), recalcular su origen para trazar su flecha de trayectoria
        if p['latitude'] is not None and abs(p['latitude'] - (-34.6037)) < 0.01 and abs(p['longitude'] - (-58.3816)) < 0.01:
            re_geo = resolve_geoip(p['client_ip'])
            p['latitude'] = re_geo['latitude']
            p['longitude'] = re_geo['longitude']
            p['country_name'] = re_geo['country_name']
        meta = extract_log_ip_meta(p['client_ip'], p.pop('raw_headers', {}))
        p['is_threat'] = (p['client_ip'] in threat_ips) or (p['status_code'] >= 400)
        p['is_cloudflare'] = meta['is_cloudflare']
        p['cloudflare_ip'] = meta['cloudflare_ip']
        p['real_client_ip'] = meta['real_client_ip']
        recent_points.append(p)

    proxy_nodes = [
        {
            'id': str(n.id),
            'name': n.name,
            'ip': n.ip_address,
            'status': n.status,
            'latitude': -34.6037,
            'longitude': -58.3816
        }
        for n in ProxyNode.objects.all()
    ]

    return JsonResponse({
        'countries': list(country_stats),
        'points': list(recent_points),
        'nodes': proxy_nodes
    })

@login_required
def api_live_stats(request):
    nodes = list(ProxyNode.objects.all())
    for n in nodes:
        n.check_health()

    total_rps = sum(n.current_rps for n in nodes)
    online_count = sum(1 for n in nodes if n.status == 'ONLINE')

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    since_24h = now - timedelta(hours=24)

    ActiveBan.objects.filter(is_active=True, expires_at__isnull=False, expires_at__lte=now).update(is_active=False)

    total_logs_today = TrafficLog.objects.filter(created_at__gte=today_start).count()
    threats_today = SecurityEvent.objects.filter(created_at__gte=today_start).count()
    pending_bans = BanCandidate.objects.filter(status='PENDING').count()
    active_bans = ActiveBan.objects.filter(is_active=True).count()

    recent_logs_qs = list(TrafficLog.objects.select_related('node').order_by('-created_at')[:25])
    recent_ips = {log.client_ip for log in recent_logs_qs}
    threat_ips = set(
        SecurityEvent.objects.filter(client_ip__in=recent_ips, created_at__gte=since_24h)
        .values_list('client_ip', flat=True).distinct()
    ) if recent_ips else set()
    recent_logs_data = []
    for log in recent_logs_qs:
        lat = log.latitude
        lon = log.longitude
        if lat is not None and abs(lat - (-34.6037)) < 0.01 and abs(lon - (-58.3816)) < 0.01:
            re_geo = resolve_geoip(log.client_ip)
            lat, lon = re_geo['latitude'], re_geo['longitude']
        meta = extract_log_ip_meta(log.client_ip, log.raw_headers)
        recent_logs_data.append({
            'id': log.id,
            'timestamp': log.created_at.strftime('%H:%M:%S'),
            'client_ip': log.client_ip,
            'method': log.http_method,
            'uri': log.uri,
            'status_code': log.status_code,
            'country_code': log.country_code,
            'country_name': log.country_name or log.country_code or 'Remoto',
            'latitude': lat,
            'longitude': lon,
            'node': log.node.name if log.node else 'Direct',
            'is_threat': (log.client_ip in threat_ips) or (log.status_code >= 400),
            'is_cloudflare': meta['is_cloudflare'],
            'cloudflare_ip': meta['cloudflare_ip'],
            'real_client_ip': meta['real_client_ip'],
            'user_agent': log.user_agent or '',
        })

    nodes_data = [
        {
            'id': str(n.id),
            'name': n.name,
            'ip': n.ip_address,
            'status': n.status,
            'status_display': n.get_status_display(),
            'rps': n.current_rps,
            'cpu': round(n.cpu_usage, 1),
            'ram': round(n.memory_usage, 1),
            'logs': n.total_logs_processed,
            'last_hb': n.last_heartbeat.strftime('%H:%M:%S') if n.last_heartbeat else 'Nunca'
        }
        for n in nodes
    ]

    candidates_data = []
    for c in BanCandidate.objects.filter(status='PENDING').select_related('trigger_event', 'trigger_event__rule').order_by('-created_at')[:5]:
        ev = c.trigger_event
        ev_details = ev.details if (ev and isinstance(ev.details, dict)) else {}
        c_meta = _enrich_candidate_cf(c)
        candidates_data.append({
            'id': c.id,
            'ip': c.client_ip,
            'score': c.accumulated_score,
            'reason': c.suggested_reason,
            'rule_code': ev.rule.code if (ev and ev.rule) else 'HEURISTIC',
            'payload': ev.matched_payload if ev else '',
            'uri': ev_details.get('uri', ''),
            'is_cloudflare': c_meta['is_cloudflare'],
            'cloudflare_ip': c_meta['cloudflare_ip'],
            'real_client_ip': c_meta['real_client_ip'],
            'detected_at': c.created_at.strftime('%H:%M:%S')
        })

    return JsonResponse({
        'total_rps': total_rps,
        'online_nodes': online_count,
        'total_nodes': len(nodes),
        'total_logs_today': total_logs_today,
        'threats_today': threats_today,
        'pending_bans': pending_bans,
        'active_bans': active_bans,
        'nodes': nodes_data,
        'candidates': candidates_data,
        'recent_logs': recent_logs_data
    })
