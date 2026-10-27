def mithril_branding(request):
    pending_count = 0
    active_bans_count = 0
    online_nodes_count = 0

    if request.user.is_authenticated:
        try:
            from apps.mitigation.models import BanCandidate, ActiveBan
            from apps.nodes.models import ProxyNode
            
            pending_count = BanCandidate.objects.filter(status='PENDING').count()
            active_bans_count = ActiveBan.objects.filter(is_active=True).count()
            online_nodes_count = ProxyNode.objects.filter(status='ONLINE').count()
        except Exception:
            pass

    return {
        'MITHRIL_APP_NAME': 'Mithril SIEM',
        'MITHRIL_VERSION': '1.0.0',
        'pending_candidates_count': pending_count,
        'active_bans_count': active_bans_count,
        'online_nodes_count': online_nodes_count,
    }
