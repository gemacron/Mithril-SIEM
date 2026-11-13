import math
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from apps.nodes.models import ProxyNode
from apps.mitigation.models import BanCandidate, ActiveBan
from apps.detection.models import TrafficLog, SecurityEvent
from apps.detection.engine import (
    is_cloudflare_ip,
    resolve_geoip,
    extract_log_ip_meta,
    get_cloudflare_sync_status,
    is_private_local_ip,
    is_own_public_wan_ip,
    _is_benign_app_sync,
)

def _enrich_candidate_cf(c):
    ev = c.trigger_event
    ev_details = ev.details if (ev and isinstance(ev.details, dict)) else {}
    meta = extract_log_ip_meta(c.client_ip, ev_details)
    if meta['is_cloudflare'] and not meta['real_client_ip']:
        # Buscar en los últimos logs de esta IP si alguno trajo la IP real en raw_headers
        recent_with_real = (
            TrafficLog.objects.filter(client_ip=c.client_ip)
            .exclude(raw_headers={})
            .order_by('-id')[:10]
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
    recent_events = SecurityEvent.objects.select_related('rule', 'node').order_by('-id')[:8]

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    since_24h = now - timedelta(hours=24)

    # Expirar bloqueos vencidos automáticamente
    ActiveBan.objects.filter(is_active=True, expires_at__isnull=False, expires_at__lte=now).update(is_active=False)

    recent_logs = list(
        TrafficLog.objects.select_related('node')
        .exclude(http_method='HTTPS')
        .exclude(user_agent__icontains='Cloudflare-Traffic-Manager')
        .exclude(Q(raw_headers__is_cloudflare=True) & Q(raw_headers__real_client_ip=''))
        .order_by('-id')[:25]
    )
    recent_ips = {log.client_ip for log in recent_logs}
    threat_ips = set(
        SecurityEvent.objects.filter(client_ip__in=recent_ips, created_at__gte=since_24h)
        .values_list('client_ip', flat=True).distinct()
    ) if recent_ips else set()

    def _is_private(ip):
        if not ip:
            return False
        s = str(ip).strip()
        if s.startswith(('127.', '10.', '192.168.', '169.254.')):
            return True
        if s.startswith('172.'):
            parts = s.split('.')
            if len(parts) >= 2 and parts[1].isdigit():
                sec = int(parts[1])
                if 16 <= sec <= 31:
                    return True
        return False

    for log in recent_logs:
        meta = extract_log_ip_meta(log.client_ip, log.raw_headers)
        if not meta['is_cloudflare'] and meta['real_client_ip'] and log.client_ip != meta['real_client_ip']:
            log.client_ip = meta['real_client_ip']
        is_benign = _is_benign_app_sync(log.uri, log.status_code)
        raw_threat = bool(log.raw_headers.get('is_threat')) if isinstance(log.raw_headers, dict) else False
        log.is_threat = (not is_benign) and (raw_threat or (log.status_code >= 400))
        log.is_cloudflare = meta['is_cloudflare']
        log.cloudflare_ip = meta['cloudflare_ip']
        log.connection_ip = meta['cloudflare_ip'] if (meta['is_cloudflare'] and meta['cloudflare_ip']) else log.client_ip
        log.real_client_ip = meta['real_client_ip'] or (log.client_ip if not is_cloudflare_ip(log.client_ip) else '')
        eff_target_ip = log.real_client_ip or log.client_ip
        log.is_own_public_ip = meta.get('is_own_public_ip', False) or is_own_public_wan_ip(eff_target_ip)
        log.is_real_ip_local = _is_private(log.real_client_ip)
        log.is_local_ip = log.is_real_ip_local or (not log.is_cloudflare and _is_private(log.client_ip))
        if log.is_local_ip:
            log.country_code = 'LAN'
            log.country_name = 'Red Interna (LAN)'
        elif log.is_own_public_ip or meta.get('cf_country'):
            re_geo = resolve_geoip(eff_target_ip, cf_country=meta.get('cf_country', ''))
            log.country_code = re_geo['country_code']
            log.country_name = re_geo['country_name']
        log.is_direct_public_ip = meta.get('is_direct_public_ip', (not log.is_cloudflare and not log.is_local_ip and not log.is_own_public_ip and bool(eff_target_ip)))

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

    # Top países con eventos de seguridad y tráfico real
    country_stats = (
        TrafficLog.objects.filter(created_at__gte=since)
        .exclude(country_code__in=['', 'LAN'])
        .exclude(country_code__startswith='CF-')
        .values('country_code', 'country_name')
        .annotate(total=Count('id'))
        .order_by('-total')[:15]
    )

    # Priorizar peticiones con IP real de cliente para que las sondas no desplacen a los clientes reales del mapa
    real_client_points = list(
        TrafficLog.objects.filter(created_at__gte=since)
        .exclude(latitude__isnull=True)
        .exclude(http_method='HTTPS')
        .exclude(user_agent__icontains='Cloudflare-Traffic-Manager')
        .exclude(Q(raw_headers__is_cloudflare=True) & Q(raw_headers__real_client_ip=''))
        .values('id', 'latitude', 'longitude', 'country_name', 'client_ip', 'status_code', 'raw_headers', 'user_agent', 'http_method')
        .order_by('-id')[:70]
    )
    probe_points = list(
        TrafficLog.objects.filter(created_at__gte=since)
        .exclude(latitude__isnull=True)
        .filter(
            Q(http_method='HTTPS')
            | Q(user_agent__icontains='Cloudflare-Traffic-Manager')
            | (Q(raw_headers__is_cloudflare=True) & Q(raw_headers__real_client_ip=''))
        )
        .values('id', 'latitude', 'longitude', 'country_name', 'client_ip', 'status_code', 'raw_headers', 'user_agent', 'http_method')
        .order_by('-id')[:20]
    )
    raw_points = real_client_points + probe_points
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
        meta = extract_log_ip_meta(p['client_ip'], p.pop('raw_headers', {}))
        ua = p.pop('user_agent', '') or ''
        method = p.pop('http_method', '') or ''
        eff_ip = meta['real_client_ip'] if (not meta['is_cloudflare'] and meta['real_client_ip']) else p['client_ip']
        conn_ip = meta['cloudflare_ip'] if (meta['is_cloudflare'] and meta['cloudflare_ip']) else eff_ip
        real_ip_val = meta['real_client_ip'] or (eff_ip if not is_cloudflare_ip(eff_ip) else '')
        target_geo_ip = real_ip_val or conn_ip

        re_geo = resolve_geoip(target_geo_ip, cf_country=meta.get('cf_country', ''))
        p['latitude'] = re_geo['latitude']
        p['longitude'] = re_geo['longitude']
        p['country_name'] = re_geo['country_name']

        p['is_threat'] = (p['client_ip'] in threat_ips) or (real_ip_val in threat_ips) or (p['status_code'] >= 400)
        p['client_ip'] = conn_ip
        p['is_cloudflare'] = meta['is_cloudflare']
        p['cloudflare_ip'] = meta['cloudflare_ip']
        p['real_client_ip'] = real_ip_val
        is_own_pub = meta.get('is_own_public_ip', False) or is_own_public_wan_ip(target_geo_ip)
        p['is_own_public_ip'] = is_own_pub
        p['is_local'] = meta.get('is_local_ip', False) or is_private_local_ip(real_ip_val or (conn_ip if not meta['is_cloudflare'] else ''))
        p['is_direct_public_ip'] = meta.get('is_direct_public_ip', (not p['is_cloudflare'] and not p['is_local'] and not is_own_pub and bool(target_geo_ip)))
        p['is_probe'] = bool(
            (meta['is_cloudflare'] and not real_ip_val)
            or 'Cloudflare-Traffic-Manager' in ua
            or 'TLS SNI' in ua
            or method == 'HTTPS'
        )
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

    recent_logs_qs = list(TrafficLog.objects.select_related('node').order_by('-id')[:25])
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
        eff_ip = meta['real_client_ip'] if (not meta['is_cloudflare'] and meta['real_client_ip']) else log.client_ip
        conn_ip = meta['cloudflare_ip'] if (meta['is_cloudflare'] and meta['cloudflare_ip']) else eff_ip
        real_ip_val = meta['real_client_ip'] or (eff_ip if not is_cloudflare_ip(eff_ip) else '')
        is_loc = meta.get('is_local_ip', False) or is_private_local_ip(eff_ip if not meta['is_cloudflare'] else real_ip_val)
        is_own_pub = meta.get('is_own_public_ip', False) or is_own_public_wan_ip(real_ip_val or eff_ip)
        c_code = 'LAN' if is_loc else log.country_code
        c_name = 'Red Interna (LAN)' if is_loc else (log.country_name or log.country_code or 'Remoto')
        if not is_loc and (is_own_pub or meta.get('cf_country')):
            re_geo = resolve_geoip(real_ip_val or eff_ip, cf_country=meta.get('cf_country', ''))
            c_code = re_geo['country_code']
            c_name = re_geo['country_name']
        is_benign = _is_benign_app_sync(log.uri, log.status_code)
        raw_threat = bool(log.raw_headers.get('is_threat')) if isinstance(log.raw_headers, dict) else False
        recent_logs_data.append({
            'id': log.id,
            'timestamp': log.created_at.strftime('%H:%M:%S'),
            'client_ip': conn_ip,
            'method': log.http_method,
            'uri': log.uri,
            'status_code': log.status_code,
            'country_code': c_code,
            'country_name': c_name,
            'latitude': lat,
            'longitude': lon,
            'node': log.node.name if log.node else 'Direct',
            'is_threat': (not is_benign) and (raw_threat or (log.status_code >= 400)),
            'is_cloudflare': meta['is_cloudflare'],
            'cloudflare_ip': meta['cloudflare_ip'],
            'real_client_ip': real_ip_val,
            'is_local_ip': is_loc,
            'is_own_public_ip': is_own_pub,
            'is_direct_public_ip': meta.get('is_direct_public_ip', (not meta['is_cloudflare'] and not is_loc and not is_own_pub)),
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


@login_required
def api_live_feed_logs(request):
    """
    Endpoint paginado y filtrable que retorna TODAS las peticiones registradas en el día de hoy
    para el panel LIVE FEED del Dashboard.
    """
    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    try:
        page = max(1, int(request.GET.get('page', '1')))
    except ValueError:
        page = 1

    try:
        page_size = int(request.GET.get('page_size', '50'))
        page_size = max(10, min(500, page_size))
    except ValueError:
        page_size = 50

    search_q = request.GET.get('q', '').strip()
    type_filter = request.GET.get('type', 'all').strip().lower()
    method_filter = request.GET.get('method', 'all').strip().upper()
    status_filter = request.GET.get('status', 'all').strip().lower()
    hide_local = request.GET.get('hide_local', '1') == '1'
    hide_probes = request.GET.get('hide_probes', '0') == '1'

    base_qs = TrafficLog.objects.select_related('node').filter(created_at__gte=today_start)
    total_today = base_qs.count()

    qs = base_qs

    # 1. Filtro independiente de IPs Locales Privadas / Balanceador (RFC1918 / Loopback)
    if hide_local:
        qs = (
            qs.exclude(client_ip__startswith='127.')
            .exclude(client_ip__startswith='10.')
            .exclude(client_ip__startswith='192.168.')
            .exclude(client_ip__startswith='169.254.')
            .exclude(country_code='LAN')
            .exclude(raw_headers__is_local_ip=True)
        )

    # 2. Filtro independiente de Sondas de Cloudflare / Handshakes TLS sin IP de cliente final
    if hide_probes:
        qs = (
            qs.exclude(http_method='HTTPS')
            .exclude(user_agent__icontains='Cloudflare-Traffic-Manager')
            .exclude(user_agent__icontains='TLS SNI')
            .exclude(Q(raw_headers__is_cloudflare=True) & Q(raw_headers__real_client_ip=''))
        )

    # 3. Filtro por Método HTTP
    if method_filter and method_filter != 'ALL':
        qs = qs.filter(http_method__iexact=method_filter)

    # 4. Filtro por Código HTTP
    if status_filter and status_filter != 'all':
        if status_filter == '2xx':
            qs = qs.filter(status_code__gte=200, status_code__lt=300)
        elif status_filter == '3xx':
            qs = qs.filter(status_code__gte=300, status_code__lt=400)
        elif status_filter == '4xx':
            qs = qs.filter(status_code__gte=400, status_code__lt=500)
        elif status_filter == '5xx':
            qs = qs.filter(status_code__gte=500)
        elif status_filter.isdigit():
            qs = qs.filter(status_code=int(status_filter))

    # 5. Filtro por Tipo (Amenaza vs Normal)
    if type_filter == 'threat':
        qs = qs.filter(
            (Q(status_code__gte=400) | Q(raw_headers__is_threat=True))
            & ~Q(uri__icontains='/ocs/v2.php/apps/text/public/workspace', status_code=404)
        )
    elif type_filter == 'normal':
        qs = qs.filter(
            (Q(status_code__lt=400) & ~Q(raw_headers__is_threat=True))
            | Q(uri__icontains='/ocs/v2.php/apps/text/public/workspace', status_code=404)
        )

    # 6. Búsqueda por texto (IP, dominio/URI, país, User-Agent, nodo)
    if search_q:
        qs = qs.filter(
            Q(client_ip__icontains=search_q)
            | Q(uri__icontains=search_q)
            | Q(query_params__icontains=search_q)
            | Q(country_name__icontains=search_q)
            | Q(country_code__icontains=search_q)
            | Q(user_agent__icontains=search_q)
            | Q(http_method__icontains=search_q)
            | Q(raw_headers__real_client_ip__icontains=search_q)
            | Q(raw_headers__cloudflare_ip__icontains=search_q)
        )

    total_filtered = qs.count()
    total_pages = max(1, math.ceil(total_filtered / page_size)) if total_filtered > 0 else 1
    if page > total_pages:
        page = total_pages

    offset = (page - 1) * page_size
    page_logs = list(qs.order_by('-id')[offset:offset + page_size])

    logs_data = []
    for log in page_logs:
        meta = extract_log_ip_meta(log.client_ip, log.raw_headers)
        eff_ip = meta['real_client_ip'] if (not meta['is_cloudflare'] and meta['real_client_ip']) else log.client_ip
        conn_ip = meta['cloudflare_ip'] if (meta['is_cloudflare'] and meta['cloudflare_ip']) else eff_ip
        real_ip_val = meta['real_client_ip'] or (eff_ip if not is_cloudflare_ip(eff_ip) else '')
        is_loc = meta.get('is_local_ip', False) or is_private_local_ip(eff_ip if not meta['is_cloudflare'] else real_ip_val)
        is_own_pub = meta.get('is_own_public_ip', False) or is_own_public_wan_ip(real_ip_val or eff_ip)
        c_code = 'LAN' if is_loc else log.country_code
        c_name = 'Red Interna (LAN)' if is_loc else (log.country_name or log.country_code or 'Remoto')
        if not is_loc and (is_own_pub or meta.get('cf_country')):
            re_geo = resolve_geoip(real_ip_val or eff_ip, cf_country=meta.get('cf_country', ''))
            c_code = re_geo['country_code']
            c_name = re_geo['country_name']
        is_benign = _is_benign_app_sync(log.uri, log.status_code)
        raw_threat = bool(log.raw_headers.get('is_threat')) if isinstance(log.raw_headers, dict) else False
        logs_data.append({
            'id': log.id,
            'timestamp': log.created_at.strftime('%H:%M:%S'),
            'client_ip': conn_ip,
            'method': log.http_method,
            'uri': log.uri,
            'status_code': log.status_code,
            'country_code': c_code,
            'country_name': c_name,
            'node': log.node.name if log.node else 'Direct',
            'is_threat': (not is_benign) and (raw_threat or (log.status_code >= 400)),
            'is_cloudflare': meta['is_cloudflare'],
            'cloudflare_ip': meta['cloudflare_ip'],
            'real_client_ip': real_ip_val,
            'is_local_ip': is_loc,
            'is_own_public_ip': is_own_pub,
            'is_direct_public_ip': meta.get('is_direct_public_ip', (not meta['is_cloudflare'] and not is_loc and not is_own_pub)),
            'user_agent': log.user_agent or '',
        })

    return JsonResponse({
        'logs': logs_data,
        'page': page,
        'page_size': page_size,
        'total_filtered': total_filtered,
        'total_today': total_today,
        'total_pages': total_pages,
    })
