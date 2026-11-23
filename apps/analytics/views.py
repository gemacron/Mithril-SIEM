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
    is_own_infrastructure_ip,
    _is_benign_app_sync,
    ensure_ban_candidate_for_ip,
    sync_unbanned_threats_to_candidates,
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

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    since_24h = now - timedelta(hours=24)

    # Expirar bloqueos vencidos automáticamente y sincronizar amenazas con Candidatos a Bloqueo
    ActiveBan.objects.filter(is_active=True, expires_at__isnull=False, expires_at__lte=now).update(is_active=False)
    sync_unbanned_threats_to_candidates()

    candidates = list(BanCandidate.objects.filter(status='PENDING').select_related('trigger_event', 'trigger_event__rule')[:15])
    for c in candidates:
        _enrich_candidate_cf(c)
    recent_events = SecurityEvent.objects.select_related('rule', 'node').order_by('-id')[:8]

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
        log.is_threat = (not is_benign) and raw_threat
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
    Retorna ÚNICAMENTE tráfico activo en tiempo real (ventana móvil de los últimos 90 segundos,
    sin datos históricos) para los mapas tácticos 2D. El historial completo queda reservado para Informes (/reports/).
    """
    now = timezone.now()
    try:
        window_sec = int(request.GET.get('window_sec', '90'))
        window_sec = max(15, min(300, window_sec))
    except ValueError:
        window_sec = 90
    since = now - timedelta(seconds=window_sec)

    sync_unbanned_threats_to_candidates()

    # Top países con actividad en curso (ventana en vivo)
    country_stats = (
        TrafficLog.objects.filter(created_at__gte=since)
        .exclude(country_code__in=['', 'LAN'])
        .exclude(country_code__startswith='CF-')
        .values('country_code', 'country_name')
        .annotate(total=Count('id'))
        .order_by('-total')[:15]
    )

    pending_candidates = list(BanCandidate.objects.filter(status='PENDING'))
    candidate_id_map = {c.client_ip: c.id for c in pending_candidates}
    candidate_ips = set(candidate_id_map.keys())
    active_ban_ips = set(ActiveBan.objects.filter(is_active=True).values_list('client_ip', flat=True))
    dismissed_map = {
        c.client_ip: c.reviewed_at
        for c in BanCandidate.objects.filter(status='DISMISSED', reviewed_at__isnull=False)
    }

    fields_list = (
        'id', 'latitude', 'longitude', 'country_code', 'country_name', 'city',
        'client_ip', 'status_code', 'uri', 'raw_headers', 'user_agent', 'http_method', 'node__name', 'created_at'
    )

    # Priorizar peticiones en curso que hayan disparado una amenaza real + clientes activos actuales
    threat_points = list(
        TrafficLog.objects.filter(created_at__gte=since)
        .exclude(http_method='HTTPS')
        .filter(raw_headers__is_threat=True)
        .values(*fields_list)
        .order_by('-id')[:45]
    )
    real_client_points = list(
        TrafficLog.objects.filter(created_at__gte=since)
        .exclude(latitude__isnull=True)
        .exclude(http_method='HTTPS')
        .exclude(user_agent__icontains='Cloudflare-Traffic-Manager')
        .exclude(country_code__startswith='CF-')
        .exclude(Q(raw_headers__is_cloudflare=True) & Q(raw_headers__real_client_ip=''))
        .values(*fields_list)
        .order_by('-id')[:80]
    )
    py_points = list(
        TrafficLog.objects.filter(created_at__gte=since)
        .exclude(http_method='HTTPS')
        .exclude(country_code__startswith='CF-')
        .filter(
            Q(country_code__in=['PY', 'LAN'])
            | Q(country_name__icontains='Paraguay')
            | Q(raw_headers__cf_country='PY')
            | Q(raw_headers__is_local_ip=True)
            | Q(raw_headers__is_own_public_ip=True)
        )
        .values(*fields_list)
        .order_by('-id')[:45]
    )
    seen_ids = set()
    raw_points = []
    for item in (threat_points + real_client_points + py_points):
        if item['id'] not in seen_ids:
            seen_ids.add(item['id'])
            raw_points.append(item)
    point_ips = {p['client_ip'] for p in raw_points}
    threat_ips = set(
        SecurityEvent.objects.filter(client_ip__in=point_ips, created_at__gte=since)
        .values_list('client_ip', flat=True).distinct()
    ) if point_ips else set()
    threat_ips.update(candidate_ips)
    threat_ips.update(active_ban_ips)

    recent_points = []
    for p in raw_points:
        raw_hdrs = p.pop('raw_headers', {}) or {}
        raw_is_threat = bool(raw_hdrs.get('is_threat')) if isinstance(raw_hdrs, dict) else False
        uri_val = p.pop('uri', '/') or '/'
        created_at_val = p.pop('created_at', None)
        meta = extract_log_ip_meta(p['client_ip'], raw_hdrs)
        ua = p.pop('user_agent', '') or ''
        method = p.pop('http_method', '') or ''
        real_ip_clean = meta.get('real_client_ip') or (p['client_ip'] if not is_cloudflare_ip(p['client_ip']) else '')
        eff_ip = real_ip_clean or p['client_ip']
        conn_ip = meta.get('cloudflare_ip') or (p['client_ip'] if meta.get('is_cloudflare') else eff_ip)
        target_geo_ip = real_ip_clean or conn_ip

        # Jamás graficar IPs de nodos Cloudflare Edge ni sus ubicaciones PoP: solo clientes reales
        if is_cloudflare_ip(target_geo_ip) or (meta['is_cloudflare'] and not real_ip_clean):
            continue

        re_geo = resolve_geoip(target_geo_ip, cf_country=meta.get('cf_country', ''))
        p['latitude'] = re_geo['latitude']
        p['longitude'] = re_geo['longitude']
        p['country_code'] = re_geo['country_code']
        p['country_name'] = re_geo['country_name']
        p['city'] = re_geo.get('city') or p.get('city', '')

        is_own_pub = meta.get('is_own_public_ip', False) or is_own_public_wan_ip(target_geo_ip) or is_own_infrastructure_ip(target_geo_ip)
        is_loc = meta.get('is_local_ip', False) or is_private_local_ip(real_ip_clean or (conn_ip if not meta['is_cloudflare'] else ''))
        is_benign = _is_benign_app_sync(uri_val, p['status_code'])
        is_probe_flag = bool(
            (meta['is_cloudflare'] and not real_ip_clean)
            or 'Cloudflare-Traffic-Manager' in ua
            or 'TLS SNI' in ua
            or method == 'HTTPS'
        )

        # Determinar si es amenaza real (y si fue descartada manualmente como falso positivo después del evento)
        dismissed_ts = dismissed_map.get(target_geo_ip)
        was_dismissed_after = bool(dismissed_ts and created_at_val and dismissed_ts >= created_at_val and target_geo_ip not in candidate_ips and target_geo_ip not in active_ban_ips)

        is_real_threat = (
            not is_own_pub
            and not is_benign
            and not is_probe_flag
            and not was_dismissed_after
            and raw_is_threat
        )

        # Si el punto se marca como amenaza en el mapa y aún no está bloqueado ni en Candidatos, crearlo de inmediato
        if is_real_threat and target_geo_ip not in candidate_id_map and target_geo_ip not in active_ban_ips:
            if not is_cloudflare_ip(target_geo_ip) and not is_own_infrastructure_ip(target_geo_ip):
                cand_obj = ensure_ban_candidate_for_ip(
                    target_ip=target_geo_ip,
                    reason_override=f"Actividad hostil detectada en el Mapa Táctico ({method} {uri_val} -> HTTP {p['status_code']}).",
                    is_cf=meta['is_cloudflare'],
                    cf_node_ip=meta['cloudflare_ip'],
                    country_name=p['country_name'],
                    node_name=p.get('node__name') or 'Direct',
                )
                if cand_obj:
                    candidate_id_map[target_geo_ip] = cand_obj.id
                    candidate_ips.add(target_geo_ip)

        p['is_threat'] = is_real_threat
        p['log_id'] = p['id']
        p['candidate_id'] = candidate_id_map.get(target_geo_ip, 0)
        p['client_ip'] = real_ip_clean or conn_ip
        p['connection_ip'] = conn_ip
        p['is_cloudflare'] = meta['is_cloudflare']
        p['cloudflare_ip'] = meta['cloudflare_ip']
        p['real_client_ip'] = real_ip_clean
        p['is_own_public_ip'] = is_own_pub
        p['is_local'] = is_loc
        p['is_direct_public_ip'] = meta.get('is_direct_public_ip', (not p['is_cloudflare'] and not p['is_local'] and not is_own_pub and bool(target_geo_ip)))
        p['is_probe'] = is_probe_flag
        p['node_name'] = p.pop('node__name', '') or ''
        if p['latitude'] != 0.0 or p['longitude'] != 0.0:
            recent_points.append(p)

    proxy_nodes = []
    for idx, n in enumerate(ProxyNode.objects.all()):
        node_geo = resolve_geoip(n.ip_address) if not is_private_local_ip(n.ip_address) else None
        base_lat = node_geo['latitude'] if (node_geo and node_geo.get('latitude')) else -34.6037
        base_lon = node_geo['longitude'] if (node_geo and node_geo.get('longitude')) else -58.3816
        proxy_nodes.append({
            'id': str(n.id),
            'name': n.name,
            'ip': n.ip_address,
            'status': n.status,
            'latitude': base_lat + (idx * 2.2),
            'longitude': base_lon + (idx * 2.8),
        })

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
    sync_unbanned_threats_to_candidates()

    total_logs_today = TrafficLog.objects.filter(created_at__gte=today_start).count()
    threats_today = SecurityEvent.objects.filter(created_at__gte=today_start).count()
    pending_bans = BanCandidate.objects.filter(status='PENDING').count()
    active_bans = ActiveBan.objects.filter(is_active=True).count()

    recent_logs_qs = list(
        TrafficLog.objects.select_related('node')
        .exclude(http_method='HTTPS')
        .exclude(country_code__startswith='CF-')
        .exclude(user_agent__icontains='Cloudflare-Traffic-Manager')
        .exclude(Q(raw_headers__is_cloudflare=True) & Q(raw_headers__real_client_ip=''))
        .order_by('-id')[:25]
    )
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
        real_ip_clean = meta.get('real_client_ip') or (log.client_ip if not is_cloudflare_ip(log.client_ip) else '')
        if not real_ip_clean and (meta['is_cloudflare'] or is_cloudflare_ip(log.client_ip)):
            continue
        eff_ip = real_ip_clean or log.client_ip
        conn_ip = meta.get('cloudflare_ip') or (log.client_ip if meta.get('is_cloudflare') else eff_ip)
        target_geo_ip = real_ip_clean or conn_ip
        is_loc = meta.get('is_local_ip', False) or is_private_local_ip(real_ip_clean or (conn_ip if not meta['is_cloudflare'] else ''))
        is_own_pub = meta.get('is_own_public_ip', False) or is_own_public_wan_ip(target_geo_ip)
        c_code = 'LAN' if is_loc else log.country_code
        c_name = 'Red Interna (LAN)' if is_loc else (log.country_name or log.country_code or 'Remoto')
        if not is_loc and (is_own_pub or meta.get('cf_country') or real_ip_clean):
            re_geo = resolve_geoip(target_geo_ip, cf_country=meta.get('cf_country', ''))
            c_code = re_geo['country_code']
            c_name = re_geo['country_name']
            if lat is not None and abs(lat - (-34.6037)) < 0.01 and abs(lon - (-58.3816)) < 0.01:
                lat, lon = re_geo['latitude'], re_geo['longitude']
        is_benign = _is_benign_app_sync(log.uri, log.status_code)
        raw_threat = bool(log.raw_headers.get('is_threat')) if isinstance(log.raw_headers, dict) else False
        recent_logs_data.append({
            'id': log.id,
            'timestamp': log.created_at.strftime('%H:%M:%S'),
            'client_ip': eff_ip,
            'connection_ip': conn_ip,
            'method': log.http_method,
            'uri': log.uri,
            'status_code': log.status_code,
            'country_code': c_code,
            'country_name': c_name,
            'latitude': lat,
            'longitude': lon,
            'node': log.node.name if log.node else 'Direct',
            'is_threat': (not is_benign) and (not is_own_pub) and (raw_threat or (target_geo_ip in threat_ips)),
            'is_cloudflare': meta['is_cloudflare'],
            'cloudflare_ip': meta['cloudflare_ip'],
            'real_client_ip': real_ip_clean,
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
    for c in BanCandidate.objects.filter(status='PENDING').select_related('trigger_event', 'trigger_event__rule').order_by('-created_at')[:15]:
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

    # 2. Excluir siempre sondas de Cloudflare / Handshakes TLS sin IP de cliente final
    qs = (
        qs.exclude(http_method='HTTPS')
        .exclude(country_code__startswith='CF-')
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

    # 5. Filtro por Tipo (Amenaza real verificada por el motor vs Tráfico Normal)
    if type_filter == 'threat':
        qs = qs.filter(raw_headers__is_threat=True)
    elif type_filter == 'normal':
        qs = qs.exclude(raw_headers__is_threat=True)

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
            | Q(node__name__icontains=search_q)
            | Q(node__ip_address__icontains=search_q)
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
        real_ip_clean = meta.get('real_client_ip') or (log.client_ip if not is_cloudflare_ip(log.client_ip) else '')
        if not real_ip_clean and (meta['is_cloudflare'] or is_cloudflare_ip(log.client_ip)):
            continue
        eff_ip = real_ip_clean or log.client_ip
        conn_ip = meta.get('cloudflare_ip') or (log.client_ip if meta.get('is_cloudflare') else eff_ip)
        target_geo_ip = real_ip_clean or conn_ip
        is_loc = meta.get('is_local_ip', False) or is_private_local_ip(real_ip_clean or (conn_ip if not meta['is_cloudflare'] else ''))
        is_own_pub = meta.get('is_own_public_ip', False) or is_own_public_wan_ip(target_geo_ip)
        c_code = 'LAN' if is_loc else log.country_code
        c_name = 'Red Interna (LAN)' if is_loc else (log.country_name or log.country_code or 'Remoto')
        if not is_loc and (is_own_pub or meta.get('cf_country') or real_ip_clean):
            re_geo = resolve_geoip(target_geo_ip, cf_country=meta.get('cf_country', ''))
            c_code = re_geo['country_code']
            c_name = re_geo['country_name']
        is_benign = _is_benign_app_sync(log.uri, log.status_code)
        raw_threat = bool(log.raw_headers.get('is_threat')) if isinstance(log.raw_headers, dict) else False
        logs_data.append({
            'id': log.id,
            'timestamp': log.created_at.strftime('%H:%M:%S'),
            'client_ip': eff_ip,
            'connection_ip': conn_ip,
            'method': log.http_method,
            'uri': log.uri,
            'status_code': log.status_code,
            'country_code': c_code,
            'country_name': c_name,
            'node': log.node.name if log.node else 'Direct',
            'is_threat': (not is_benign) and (not is_own_pub) and raw_threat,
            'is_cloudflare': meta['is_cloudflare'],
            'cloudflare_ip': meta['cloudflare_ip'],
            'real_client_ip': real_ip_clean,
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
