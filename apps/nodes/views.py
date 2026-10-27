import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from .models import ProxyNode
from apps.reports.models import AuditTrail

@login_required
def nodes_list_view(request):
    nodes = ProxyNode.objects.all()
    for n in nodes:
        n.check_health()
    host_ip = request.get_host().split(':')[0]
    return render(request, 'nodes/list.html', {'nodes': nodes, 'host_ip': host_ip})

@login_required
def node_create_view(request):
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        ip_address = request.POST.get('ip_address', '').strip()
        location_label = request.POST.get('location_label', '').strip()
        description = request.POST.get('description', '').strip()

        if not name or not ip_address:
            messages.error(request, 'El nombre y la IP del proxy son campos obligatorios.')
        else:
            node = ProxyNode.objects.create(
                name=name,
                ip_address=ip_address,
                location_label=location_label,
                description=description
            )
            AuditTrail.objects.create(
                user=request.user,
                action='CREATE_NODE',
                target=f"Nodo: {node.name}",
                details={'ip': node.ip_address, 'location': node.location_label},
                ip_address=request.META.get('REMOTE_ADDR')
            )
            messages.success(request, f"Servidor proxy '{node.name}' dado de alta exitosamente. Configura su monitorización a continuación.")
            return redirect('nodes:configure', node_id=node.id)

    return render(request, 'nodes/create.html')

@login_required
def node_configure_view(request, node_id):
    """
    Módulo de Configuración Integral de la Monitorización del Servidor Proxy
    """
    node = get_object_or_404(ProxyNode, id=node_id)
    node.check_health()

    if request.method == 'POST':
        action = request.POST.get('action', 'save_config')

        if action == 'regenerate_token':
            old_token = node.api_key
            new_token = node.regenerate_api_key()
            AuditTrail.objects.create(
                user=request.user,
                action='REGENERATE_NODE_KEY',
                target=f"Nodo: {node.name}",
                details={'old_key_prefix': old_token[:12], 'new_key_prefix': new_token[:12]},
                ip_address=request.META.get('REMOTE_ADDR')
            )
            messages.warning(request, f"Token de API para '{node.name}' regenerado. Actualiza la variable NODE_API_KEY en el servidor.")
            return redirect('nodes:configure', node_id=node.id)

        elif action == 'save_config':
            node.location_label = request.POST.get('location_label', '').strip()
            node.description = request.POST.get('description', '').strip()
            node.monitoring_enabled = 'monitoring_enabled' in request.POST
            node.heartbeat_timeout_seconds = int(request.POST.get('heartbeat_timeout_seconds', 90))
            node.max_rps_alert_threshold = int(request.POST.get('max_rps_alert_threshold', 1000))
            node.syslog_port = int(request.POST.get('syslog_port', 5140))
            node.sync_interval_seconds = int(request.POST.get('sync_interval_seconds', 15))
            node.block_method = request.POST.get('block_method', 'ipset')
            node.notify_on_degraded = 'notify_on_degraded' in request.POST
            node.save()

            AuditTrail.objects.create(
                user=request.user,
                action='UPDATE_NODE_CONFIG',
                target=f"Nodo: {node.name}",
                details={
                    'monitoring_enabled': node.monitoring_enabled,
                    'heartbeat_timeout': node.heartbeat_timeout_seconds,
                    'max_rps': node.max_rps_alert_threshold,
                    'block_method': node.block_method
                },
                ip_address=request.META.get('REMOTE_ADDR')
            )
            messages.success(request, f"Parámetros de monitorización para '{node.name}' guardados con éxito.")
            return redirect('nodes:configure', node_id=node.id)

    # Generar comando para levantar agente
    host_ip = request.get_host().split(':')[0]
    generated_systemd_service = f"""[Unit]
Description=Mithril SIEM Bouncer Agent ({node.name})
After=network.target nginx.service

[Service]
Type=simple
User=root
Environment="MITHRIL_URL=http://{host_ip}:9900"
Environment="NODE_API_KEY={node.api_key}"
Environment="SYNC_INTERVAL={node.sync_interval_seconds}"
Environment="BLOCK_METHOD={node.block_method}"
ExecStart=/usr/bin/python3 /opt/mithril/mithril_bouncer.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target"""

    generated_nginx_snippet = f"""# Snippet Nginx para nodo: {node.name}
# Incluir en el bloque server {{ ... }}
include /etc/nginx/conf.d/mithril_blocklist.conf;
access_log syslog:server={host_ip}:{node.syslog_port},facility=local7,tag=nginx mithril_json;"""

    context = {
        'node': node,
        'systemd_service': generated_systemd_service,
        'nginx_snippet': generated_nginx_snippet,
        'host_ip': host_ip,
    }
    return render(request, 'nodes/configure.html', context)

@login_required
def node_delete_view(request, node_id):
    node = get_object_or_404(ProxyNode, id=node_id)
    if request.method == 'POST':
        name = node.name
        AuditTrail.objects.create(
            user=request.user,
            action='DELETE_NODE',
            target=f"Nodo: {name}",
            details={'ip': node.ip_address},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        node.delete()
        messages.success(request, f"Nodo proxy '{name}' revocado y eliminado.")
        return redirect('nodes:list')
    return render(request, 'nodes/delete_confirm.html', {'node': node})

@csrf_exempt
def api_heartbeat(request):
    """
    Endpoint invocado periódicamente por el agente Mithril Bouncer en cada proxy Nginx
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Unauthorized'}, status=401)

    api_key = auth_header.split(' ')[1].strip()
    try:
        node = ProxyNode.objects.get(api_key=api_key)
    except ProxyNode.DoesNotExist:
        return JsonResponse({'error': 'Invalid node API key'}, status=403)

    try:
        data = json.loads(request.body.decode('utf-8'))
        rps = int(data.get('rps', 0))
        cpu = float(data.get('cpu', 0.0))
        ram = float(data.get('ram', 0.0))
        conns = int(data.get('active_connections', 0))
        nginx_ver = str(data.get('nginx_version', ''))
    except Exception:
        rps, cpu, ram, conns, nginx_ver = 0, 0.0, 0.0, 0, ""

    node.update_heartbeat(
        rps=rps,
        cpu=cpu,
        ram=ram,
        active_conns=conns,
        nginx_ver=nginx_ver
    )

    return JsonResponse({
        'status': 'ok',
        'node': node.name,
        'state': node.status,
        'monitoring_enabled': node.monitoring_enabled,
        'sync_interval': node.sync_interval_seconds,
        'block_method': node.block_method
    })
