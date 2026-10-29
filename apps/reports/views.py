import csv
import json
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from .models import AuditTrail
from apps.detection.models import SecurityEvent, TrafficLog
from apps.detection.engine import extract_log_ip_meta

@login_required
def reports_index_view(request):
    search_ip = request.GET.get('ip', '').strip()
    search_uri = request.GET.get('uri', '').strip()
    search_status = request.GET.get('status', '').strip()
    hide_local = request.GET.get('hide_local', '1') == '1'

    traffic_qs = TrafficLog.objects.select_related('node').all()
    if search_ip:
        traffic_qs = traffic_qs.filter(client_ip__icontains=search_ip)
    elif hide_local:
        traffic_qs = (
            traffic_qs.exclude(client_ip__startswith='192.168.')
            .exclude(client_ip__startswith='10.')
            .exclude(client_ip__startswith='127.')
            .exclude(client_ip__startswith='169.254.')
        )
    if search_uri:
        traffic_qs = traffic_qs.filter(uri__icontains=search_uri)
    if search_status.isdigit():
        traffic_qs = traffic_qs.filter(status_code=int(search_status))

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

    total_traffic_count = traffic_qs.count()
    recent_traffic = list(traffic_qs[:100])
    for log in recent_traffic:
        meta = extract_log_ip_meta(log.client_ip, log.raw_headers)
        log.is_cloudflare = meta['is_cloudflare']
        log.cloudflare_ip = meta['cloudflare_ip']
        log.real_client_ip = meta['real_client_ip']
        log.is_real_ip_local = _is_private(log.real_client_ip)
        log.is_local_ip = log.is_real_ip_local or (not log.is_cloudflare and _is_private(log.client_ip))
    audit_records = AuditTrail.objects.select_related('user')[:50]
    recent_events = list(SecurityEvent.objects.select_related('rule', 'node')[:50])
    for ev in recent_events:
        meta = extract_log_ip_meta(ev.client_ip, ev.details if isinstance(ev.details, dict) else {})
        ev.is_cloudflare = meta['is_cloudflare']
        ev.cloudflare_ip = meta['cloudflare_ip']
        ev.real_client_ip = meta['real_client_ip']

    return render(request, 'reports/index.html', {
        'audit_records': audit_records,
        'recent_events': recent_events,
        'recent_traffic': recent_traffic,
        'total_traffic_count': total_traffic_count,
        'search_ip': search_ip,
        'search_uri': search_uri,
        'search_status': search_status,
        'hide_local': hide_local,
    })

@login_required
def export_csv_view(request):
    data_type = request.GET.get('type', 'audit')
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="mithril_{data_type}_export.csv"'

    writer = csv.writer(response)

    if data_type == 'events':
        writer.writerow(['ID', 'Fecha', 'Severidad', 'IP Atacante', 'Regla', 'Carga Coincidente', 'Nodo'])
        events = SecurityEvent.objects.select_related('rule', 'node').all()[:2000]
        for e in events:
            writer.writerow([
                e.id,
                e.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                e.severity,
                e.client_ip,
                e.rule.name if e.rule else 'Heurística',
                e.matched_payload,
                e.node.name if e.node else 'Direct'
            ])
    elif data_type == 'traffic':
        writer.writerow(['ID', 'Fecha', 'IP Cliente', 'País', 'Método', 'URI', 'Query', 'Código HTTP', 'Bytes', 'Latencia (ms)', 'User-Agent', 'Nodo Proxy'])
        logs = TrafficLog.objects.select_related('node').all()[:5000]
        for l in logs:
            writer.writerow([
                l.id,
                l.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                l.client_ip,
                l.country_name or l.country_code,
                l.http_method,
                l.uri,
                l.query_params,
                l.status_code,
                l.bytes_sent,
                l.latency_ms,
                l.user_agent,
                l.node.name if l.node else 'Direct'
            ])
    else:
        writer.writerow(['ID', 'Fecha', 'Usuario', 'Acción', 'Objetivo', 'Detalles', 'IP Origen'])
        records = AuditTrail.objects.select_related('user').all()[:2000]
        for r in records:
            writer.writerow([
                r.id,
                r.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                r.user.username if r.user else 'Sistema',
                r.action,
                r.target,
                json.dumps(r.details),
                r.ip_address
            ])

    return response

@login_required
def export_json_view(request):
    data_type = request.GET.get('type', 'audit')

    if data_type == 'events':
        events = list(SecurityEvent.objects.select_related('rule', 'node').values(
            'id', 'created_at', 'severity', 'client_ip', 'matched_payload', 'details', 'node__name', 'rule__name'
        )[:1000])
        return JsonResponse({'export_type': 'events', 'records': events})
    else:
        records = list(AuditTrail.objects.select_related('user').values(
            'id', 'created_at', 'user__username', 'action', 'target', 'details', 'ip_address'
        )[:1000])
        return JsonResponse({'export_type': 'audit', 'records': records})
