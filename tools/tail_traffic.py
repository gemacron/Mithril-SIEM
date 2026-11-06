#!/usr/bin/env python3
"""
Mithril SIEM - Monitor de Tráfico en Tiempo Real por Consola (Tail Live Traffic)
Uso:
  podman exec -it mithril-web python tools/tail_traffic.py
  (o con --follow para ver el flujo en vivo continuo)
"""

import os
import sys
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mithril_siem.settings')
django.setup()

from apps.detection.models import TrafficLog
from apps.detection.engine import is_cloudflare_ip, is_private_local_ip

def is_log_local(l):
    hdrs = l.raw_headers if isinstance(l.raw_headers, dict) else {}
    conn_ip = hdrs.get('connection_ip') or l.client_ip
    real_ip = hdrs.get('real_client_ip')
    if is_private_local_ip(conn_ip):
        return True
    if real_ip and is_private_local_ip(real_ip):
        return True
    return False

def format_row(l):
    hdrs = l.raw_headers if isinstance(l.raw_headers, dict) else {}
    conn_ip = hdrs.get('connection_ip') or l.client_ip
    real_ip = hdrs.get('real_client_ip') or '-'
    is_cf = is_cloudflare_ip(conn_ip) or hdrs.get('is_cloudflare', False)
    
    cf_tag = "[CF]" if is_cf else "[DIR]"
    hora = l.created_at.strftime('%H:%M:%S')
    
    # Etiquetar tipo
    ua = l.user_agent or ''
    if 'Cloudflare-Traffic-Manager' in ua:
        real_desc = "Sonda Cloudflare"
    elif l.http_method == 'HTTPS' or 'TLS SNI' in ua:
        real_desc = "Handshake TLS"
    elif real_ip != '-':
        real_desc = f"REAL: {real_ip}"
    else:
        real_desc = "Directo"
        
    return f"{hora} | {cf_tag:<4} Conexión: {conn_ip:<15} | {real_desc:<24} | {l.http_method:<5} {l.status_code} | {l.uri[:38]}"

def main():
    follow = '--follow' in sys.argv or '-f' in sys.argv
    hide_local = '--hide-local' in sys.argv or '--no-local' in sys.argv
    only_local = '--only-local' in sys.argv
    limit = 20
    for arg in sys.argv[1:]:
        if arg.isdigit():
            limit = int(arg)

    filter_desc = "Todas"
    if hide_local:
        filter_desc = "Ocultando IPs Locales / Balanceador"
    elif only_local:
        filter_desc = "Solo IPs Locales / Balanceador"

    print("=" * 85)
    print("🛡️  MITHRIL SIEM - MONITOR DE TRÁFICO EN TIEMPO REAL")
    print(f"   Modo: {'Seguimiento en vivo (--follow)' if follow else f'Últimas {limit} peticiones'} | Filtro: {filter_desc}")
    print("=" * 85)
    print(f"{'HORA':<8} | {'RED':<4} {'IP CONEXIÓN':<24} | {'IP REAL / TIPO':<24} | {'MÉTODO':<5} {'COD'} | {'RUTA / DOMINIO'}")
    print("-" * 85)

    def should_show(l):
        is_loc = is_log_local(l)
        if hide_local and is_loc:
            return False
        if only_local and not is_loc:
            return False
        return True

    # Buscamos suficientes registros para cumplir el limit visible
    fetch_count = limit * 4 if (hide_local or only_local) else limit
    recent_candidates = list(TrafficLog.objects.order_by('-id')[:fetch_count])
    recent = [l for l in recent_candidates if should_show(l)][:limit]
    recent.reverse()
    for l in recent:
        print(format_row(l))

    if not follow:
        print("-" * 85)
        print("💡 Para ver el flujo continuo en vivo ejecuta: python tools/tail_traffic.py -f")
        print("💡 Opciones de filtrado: --hide-local (ocultar IPs privadas) | --only-local (solo IPs privadas)")
        return

    last_id = recent_candidates[0].id if recent_candidates else (TrafficLog.objects.order_by('-id').values_list('id', flat=True).first() or 0)
    print("-" * 85)
    print(f"📡 Escuchando nuevas peticiones entrantes ({filter_desc}) (Ctrl+C para salir)...")
    try:
        while True:
            time.sleep(1.0)
            new_logs = list(TrafficLog.objects.filter(id__gt=last_id).order_by('id')[:50])
            for l in new_logs:
                last_id = l.id
                if should_show(l):
                    print(format_row(l))
    except KeyboardInterrupt:
        print("\nMonitor detenido.")

if __name__ == '__main__':
    main()
