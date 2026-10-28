from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
from apps.nodes.models import ProxyNode
from apps.mitigation.models import BanCandidate, ActiveBan
from apps.detection.models import TrafficLog, SecurityEvent

@login_required
def dashboard_view(request):
    nodes = ProxyNode.objects.all()
    for n in nodes:
        n.check_health()

    candidates = BanCandidate.objects.filter(status='PENDING').select_related('trigger_event', 'trigger_event__rule')[:5]
    recent_events = SecurityEvent.objects.select_related('rule', 'node').order_by('-created_at')[:8]

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    since_24h = now - timedelta(hours=24)

    # Expirar bloqueos vencidos automáticamente
    ActiveBan.objects.filter(is_active=True, expires_at__isnull=False, expires_at__lte=now).update(is_active=False)

    threat_ips = set(
        SecurityEvent.objects.filter(created_at__gte=since_24h).values_list('client_ip', flat=True)
    )

    recent_logs = list(TrafficLog.objects.select_related('node').order_by('-created_at')[:25])
    for log in recent_logs:
        log.is_threat = (log.client_ip in threat_ips) or (log.status_code >= 400)

    total_logs_today = TrafficLog.objects.filter(created_at__gte=today_start).count()
    threats_today = SecurityEvent.objects.filter(created_at__gte=today_start).count()
    online_nodes_count = sum(1 for n in nodes if n.status == 'ONLINE')
    pending_candidates_count = BanCandidate.objects.filter(status='PENDING').count()
    active_bans_count = ActiveBan.objects.filter(is_active=True).count()

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
    threat_ips = set(
        SecurityEvent.objects.filter(created_at__gte=since).values_list('client_ip', flat=True)
    )
    raw_points = list(
        TrafficLog.objects.filter(created_at__gte=since)
        .exclude(latitude__isnull=True)
        .values('latitude', 'longitude', 'country_name', 'client_ip', 'status_code')
        .order_by('-created_at')[:80]
    )
    recent_points = []
    for p in raw_points:
        p['is_threat'] = (p['client_ip'] in threat_ips) or (p['status_code'] >= 400)
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

    threat_ips = set(
        SecurityEvent.objects.filter(created_at__gte=since_24h).values_list('client_ip', flat=True)
    )
    recent_logs_qs = TrafficLog.objects.select_related('node').order_by('-created_at')[:25]
    recent_logs_data = [
        {
            'id': log.id,
            'timestamp': log.created_at.strftime('%H:%M:%S'),
            'client_ip': log.client_ip,
            'method': log.http_method,
            'uri': log.uri,
            'status_code': log.status_code,
            'country_code': log.country_code,
            'country_name': log.country_name or log.country_code or 'Remoto',
            'node': log.node.name if log.node else 'Direct',
            'is_threat': (log.client_ip in threat_ips) or (log.status_code >= 400),
        }
        for log in recent_logs_qs
    ]

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

    candidates_data = [
        {
            'id': c.id,
            'ip': c.client_ip,
            'score': c.accumulated_score,
            'reason': c.suggested_reason,
            'detected_at': c.created_at.strftime('%H:%M:%S')
        }
        for c in BanCandidate.objects.filter(status='PENDING').order_by('-created_at')[:5]
    ]

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
