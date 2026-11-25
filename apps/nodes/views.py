import os
import json
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from .models import ProxyNode
from apps.reports.models import AuditTrail

def download_install_script_view(request):
    """
    Sirve el script agent/install_agent.sh con saltos de línea Unix (LF)
    para que pueda ejecutarse directamente vía:
    curl -sSL http://<IP>:9900/nodes/install.sh | bash -s -- --server ... --key ...
    """
    script_path = os.path.join(settings.BASE_DIR, 'agent', 'install_agent.sh')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read().replace('\r\n', '\n').replace('\r', '\n')
        return HttpResponse(content, content_type='text/plain; charset=utf-8')
    except Exception as e:
        return HttpResponse(f"#!/usr/bin/env bash\necho 'Error cargando install_agent.sh: {e}'\nexit 1\n", content_type='text/plain; charset=utf-8', status=500)

def download_bouncer_script_view(request):
    """
    Sirve el agente Python agent/mithril_bouncer.py con saltos de línea Unix (LF).
    """
    script_path = os.path.join(settings.BASE_DIR, 'agent', 'mithril_bouncer.py')
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read().replace('\r\n', '\n').replace('\r', '\n')
        return HttpResponse(content, content_type='text/plain; charset=utf-8')
    except Exception as e:
        return HttpResponse(f"# Error cargando mithril_bouncer.py: {e}\n", content_type='text/plain; charset=utf-8', status=500)

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
            # Encolar todos los bloqueos activos actuales para este nuevo nodo proxy
            from apps.mitigation.models import ActiveBan, NodeBanSync
            for active_ban in ActiveBan.objects.filter(is_active=True):
                NodeBanSync.objects.get_or_create(ban=active_ban, node=node, defaults={'is_synced': False})

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
            node.block_method = request.POST.get('block_method', 'fail2ban')
            node.notify_on_degraded = 'notify_on_degraded' in request.POST

            raw_lat = request.POST.get('latitude', '').strip()
            raw_lon = request.POST.get('longitude', '').strip()
            if raw_lat and raw_lon:
                try:
                    node.latitude = float(raw_lat.replace(',', '.'))
                    node.longitude = float(raw_lon.replace(',', '.'))
                    node.geo_manual = True
                except ValueError:
                    messages.warning(request, "Coordenadas inválidas; se conservaron las anteriores.")
            else:
                node.latitude = None
                node.longitude = None
                node.geo_manual = False

            node.save()
            try:
                from django.core.cache import cache
                cache.delete('api_map_data_v1_90')
            except Exception:
                pass

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
    generated_one_liner = (
        f'curl -fsSL http://{host_ip}:9900/nodes/install.sh | '
        f'sudo bash -s -- --server "http://{host_ip}:9900" --key "{node.api_key}" --mode {node.block_method}'
    )

    generated_systemd_service = f"""[Unit]
Description=Mithril SIEM Bouncer Agent ({node.name})
After=network-online.target fail2ban.service nginx.service
Wants=network-online.target

[Service]
Type=simple
User=root
Environment="PYTHONUNBUFFERED=1"
Environment="MITHRIL_URL=http://{host_ip}:9900"
Environment="NODE_API_KEY={node.api_key}"
Environment="SYNC_INTERVAL={node.sync_interval_seconds}"
Environment="BLOCK_METHOD={node.block_method}"
Environment="FAIL2BAN_JAIL=mithril-jail"
Environment="NGINX_BLOCK_FILE=/etc/nginx/conf.d/mithril_blocklist.conf"
ExecStart=/usr/bin/python3 /opt/mithril-agent/mithril_bouncer.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target"""

    generated_fail2ban_filter = """# /etc/fail2ban/filter.d/mithril-empty.conf
[Definition]
failregex = ^MITHRIL_MANUAL_BAN <HOST>$
ignoreregex ="""

    generated_fail2ban_action = """# /etc/fail2ban/action.d/mithril-smart.conf
# Mithril SIEM - Smart Hybrid Action v2 (Sin punto y coma para INI parser de Fail2ban)
[Definition]
actionstart = ipset create mithril_f2b hash:ip family inet timeout 0 -exist
              ipset create mithril_f2b6 hash:ip family inet6 timeout 0 -exist 2>/dev/null || true
              iptables -C INPUT -m set --match-set mithril_f2b src -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set mithril_f2b src -j DROP
              ip6tables -C INPUT -m set --match-set mithril_f2b6 src -j DROP 2>/dev/null || ip6tables -I INPUT 1 -m set --match-set mithril_f2b6 src -j DROP 2>/dev/null || true
              iptables -N MITHRIL_REALIP 2>/dev/null || true
              iptables -C INPUT -p tcp -j MITHRIL_REALIP 2>/dev/null || iptables -I INPUT 2 -p tcp -j MITHRIL_REALIP
              iptables -C OUTPUT -p tcp -j MITHRIL_REALIP 2>/dev/null || iptables -I OUTPUT 1 -p tcp -j MITHRIL_REALIP

actionstop  = iptables -D INPUT -p tcp -j MITHRIL_REALIP 2>/dev/null || true
              iptables -D OUTPUT -p tcp -j MITHRIL_REALIP 2>/dev/null || true
              iptables -F MITHRIL_REALIP 2>/dev/null || true
              iptables -X MITHRIL_REALIP 2>/dev/null || true
              iptables -D INPUT -m set --match-set mithril_f2b src -j DROP 2>/dev/null || true
              ip6tables -D INPUT -m set --match-set mithril_f2b6 src -j DROP 2>/dev/null || true
              ipset destroy mithril_f2b 2>/dev/null || true
              ipset destroy mithril_f2b6 2>/dev/null || true

actioncheck = ipset list mithril_f2b >/dev/null 2>&1

actionban   = ipset add mithril_f2b <ip> -exist 2>/dev/null || ipset add mithril_f2b6 <ip> -exist 2>/dev/null || true
              iptables -C MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "CF-Connecting-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || iptables -A MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "CF-Connecting-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || true
              iptables -C MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "X-Real-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || iptables -A MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "X-Real-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || true

actionunban = ipset del mithril_f2b <ip> -exist 2>/dev/null || ipset del mithril_f2b6 <ip> -exist 2>/dev/null || true
              iptables -D MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "CF-Connecting-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || true
              iptables -D MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "X-Real-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || true

[Init]
name = mithril"""

    generated_fail2ban_jail = """# /etc/fail2ban/jail.d/mithril.local
[mithril-jail]
enabled  = true
filter   = mithril-empty
action   = mithril-smart
logpath  = /var/log/mithril-fail2ban.log
bantime  = -1
findtime = 600
maxretry = 1"""

    generated_nginx_snippet = f"""# /etc/nginx/conf.d/mithril_node.conf (Para nodo: {node.name})
# 1. Configuración de Cloudflare Real-IP (para recuperar la IP real del visitante)
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;
real_ip_header CF-Connecting-IP;
real_ip_recursive on;

# 2. Formato JSON enriquecido para Mithril SIEM
log_format mithril_json escape=json '{{'
    '"client_ip":"$remote_addr",'
    '"real_client_ip":"$http_cf_connecting_ip",'
    '"cf_country":"$http_cf_ipcountry",'
    '"cf_ray":"$http_cf_ray",'
    '"x_forwarded_for":"$http_x_forwarded_for",'
    '"time_local":"$time_iso8601",'
    '"http_method":"$request_method",'
    '"uri":"$uri",'
    '"query_params":"$args",'
    '"status_code":$status,'
    '"bytes_sent":$body_bytes_sent,'
    '"latency_ms":$request_time,'
    '"user_agent":"$http_user_agent",'
    '"referer":"$http_referer"'
'}}';

# 3. Envío en tiempo real vía Syslog UDP al SIEM
access_log syslog:server={host_ip}:{node.syslog_port},facility=local7,tag=nginx mithril_json;"""

    context = {
        'node': node,
        'one_liner': generated_one_liner,
        'systemd_service': generated_systemd_service,
        'fail2ban_filter': generated_fail2ban_filter,
        'fail2ban_action': generated_fail2ban_action,
        'fail2ban_jail': generated_fail2ban_jail,
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

    try:
        data = json.loads(request.body.decode('utf-8'))
        rps = int(data.get('rps', 0))
        cpu = float(data.get('cpu', 0.0))
        ram = float(data.get('ram', 0.0))
        conns = int(data.get('active_connections', 0))
        nginx_ver = str(data.get('nginx_version', ''))
        node_ips = data.get('node_ips') if isinstance(data.get('node_ips'), list) else []
        public_ip = str(data.get('public_ip', '') or '').strip()
        hb_lat = float(data['latitude']) if data.get('latitude') not in (None, '') else None
        hb_lon = float(data['longitude']) if data.get('longitude') not in (None, '') else None
        blocked_hits = data.get('blocked_hits') if isinstance(data.get('blocked_hits'), dict) else {}
    except Exception:
        rps, cpu, ram, conns, nginx_ver, node_ips, public_ip, hb_lat, hb_lon, blocked_hits = 0, 0.0, 0.0, 0, "", [], "", None, None, {}

    api_key = auth_header.split(' ', 1)[1].strip().strip('"').strip("'")
    node = ProxyNode.objects.filter(api_key=api_key).first()
    if not node:
        if node_ips:
            node = ProxyNode.objects.filter(ip_address__in=node_ips).first()
        if not node:
            remote_ip = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip() or request.META.get('REMOTE_ADDR', '')
            if remote_ip:
                node = ProxyNode.objects.filter(ip_address=remote_ip).first()
        if not node and ProxyNode.objects.count() == 1:
            node = ProxyNode.objects.first()
        if node and api_key and not ProxyNode.objects.filter(api_key=api_key).exclude(id=node.id).exists():
            node.api_key = api_key
            node.save(update_fields=['api_key'])
    if not node:
        return JsonResponse({'error': 'Invalid node API key'}, status=403)

    if public_ip:
        try:
            from apps.detection.engine import register_own_public_wan_ip, is_private_local_ip
            if not is_private_local_ip(public_ip):
                register_own_public_wan_ip(public_ip)
        except Exception:
            pass

    node.update_heartbeat(
        rps=rps,
        cpu=cpu,
        ram=ram,
        active_conns=conns,
        nginx_ver=nginx_ver,
        public_ip=public_ip or None,
        latitude=hb_lat,
        longitude=hb_lon,
    )

    # Actualizar contadores reales de intentos repelidos por el kernel en este proxy (solo escribe si hubo delta > 0)
    if blocked_hits:
        try:
            from django.utils import timezone as dj_tz
            from apps.mitigation.models import ActiveBan, NodeBanSync
            now_ts = dj_tz.now()
            clean_hits = {}
            for raw_ip, raw_cnt in blocked_hits.items():
                try:
                    cnt_i = int(raw_cnt)
                    ip_s = str(raw_ip).strip()
                    if ip_s and cnt_i > 0:
                        clean_hits[ip_s] = cnt_i
                except (ValueError, TypeError):
                    continue
            if clean_hits:
                active_bans = list(ActiveBan.objects.filter(is_active=True, client_ip__in=list(clean_hits.keys())))
                for ban in active_bans:
                    raw_cnt = clean_hits.get(ban.client_ip, 0)
                    sync_rec, _ = NodeBanSync.objects.get_or_create(
                        ban=ban,
                        node=node,
                        defaults={'is_synced': True, 'synced_at': now_ts}
                    )
                    prev_cnt = sync_rec.last_kernel_counter or 0
                    if raw_cnt == prev_cnt:
                        continue
                    # Si el contador del kernel disminuyó (por reinicio del proxy/firewall), sumar el nuevo valor completo
                    delta = (raw_cnt - prev_cnt) if raw_cnt > prev_cnt else raw_cnt
                    sync_rec.last_kernel_counter = raw_cnt
                    if delta > 0:
                        sync_rec.blocked_hits = (sync_rec.blocked_hits or 0) + delta
                        sync_rec.last_blocked_at = now_ts
                        sync_rec.save(update_fields=['last_kernel_counter', 'blocked_hits', 'last_blocked_at'])
                        ban.blocked_attempts = (ban.blocked_attempts or 0) + delta
                        ban.last_blocked_attempt_at = now_ts
                        ban.save(update_fields=['blocked_attempts', 'last_blocked_attempt_at'])
                    else:
                        sync_rec.save(update_fields=['last_kernel_counter'])
        except Exception:
            pass

    return JsonResponse({
        'status': 'ok',
        'node': node.name,
        'state': node.status,
        'monitoring_enabled': node.monitoring_enabled,
        'sync_interval': node.sync_interval_seconds,
        'block_method': node.block_method
    })
