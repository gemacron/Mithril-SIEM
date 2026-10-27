from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import BanCandidate, ActiveBan, IpReputation, NodeBanSync
from apps.nodes.models import ProxyNode
from apps.reports.models import AuditTrail
from apps.notifications.services import send_telegram_alert

@login_required
def candidates_list_view(request):
    candidates = BanCandidate.objects.filter(status='PENDING').select_related('trigger_event', 'trigger_event__rule')
    return render(request, 'mitigation/candidates.html', {'candidates': candidates})

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
