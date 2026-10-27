import csv
import json
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from .models import AuditTrail
from apps.detection.models import SecurityEvent, TrafficLog

@login_required
def reports_index_view(request):
    audit_records = AuditTrail.objects.select_related('user')[:50]
    recent_events = SecurityEvent.objects.select_related('rule', 'node')[:50]

    return render(request, 'reports/index.html', {
        'audit_records': audit_records,
        'recent_events': recent_events
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
