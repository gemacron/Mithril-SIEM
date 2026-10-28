#!/usr/bin/env python3
"""
Mithril LAN Proxy - Forwarder & Ingestion Daemon para Windows
1. TCP 9900: Forwarding bidireccional de 0.0.0.0:9900 -> 127.0.0.1:9900 (Web UI y API)
2. UDP 5140: Syslog Receiver que escucha logs de Nginx en 0.0.0.0:5140, extrae el payload JSON
             y lo ingesta de forma asíncrona en http://127.0.0.1:9900/detection/api/ingest/
"""

import socket
import threading
import json
import re
import urllib.request
import urllib.error
import queue
import time

LOCAL_HOST = "127.0.0.1"
BIND_HOST = "0.0.0.0"
TCP_PORT = 9900
UDP_PORT = 5140
BUFFER_SIZE = 65536
INGEST_URL = f"http://{LOCAL_HOST}:{TCP_PORT}/detection/api/ingest/"

log_queue = queue.Queue(maxsize=10000)

def forward_tcp_stream(src_sock, dst_sock):
    """Reenvía datos bidireccionales entre dos sockets TCP"""
    try:
        while True:
            data = src_sock.recv(BUFFER_SIZE)
            if not data:
                break
            dst_sock.sendall(data)
    except Exception:
        pass
    finally:
        try:
            src_sock.close()
        except Exception:
            pass
        try:
            dst_sock.close()
        except Exception:
            pass

def handle_tcp_client(client_sock, client_addr):
    """Puentea conexiones TCP entrantes al puerto 9900 local de Mithril"""
    try:
        backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_sock.settimeout(5.0)
        backend_sock.connect((LOCAL_HOST, TCP_PORT))
        backend_sock.settimeout(None)
    except Exception as e:
        client_sock.close()
        return

    t1 = threading.Thread(target=forward_tcp_stream, args=(client_sock, backend_sock), daemon=True)
    t2 = threading.Thread(target=forward_tcp_stream, args=(backend_sock, client_sock), daemon=True)
    t1.start()
    t2.start()

def run_tcp_forwarder():
    """Servidor TCP escuchando en 0.0.0.0:9900"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((BIND_HOST, TCP_PORT))
        server.listen(128)
        print(f"🌐 [TCP] Forwarder activo en {BIND_HOST}:{TCP_PORT} -> {LOCAL_HOST}:{TCP_PORT}", flush=True)
    except Exception as e:
        print(f"❌ [TCP] Error enlazando {TCP_PORT}: {e}", flush=True)
        return

    while True:
        try:
            client_sock, client_addr = server.accept()
            t = threading.Thread(target=handle_tcp_client, args=(client_sock, client_addr), daemon=True)
            t.start()
        except Exception as e:
            print(f"⚠️ [TCP] Error aceptando cliente: {e}", flush=True)

def ingest_worker():
    """Consumidor de cola que envía logs a la API de ingestión de Mithril"""
    while True:
        item = log_queue.get()
        try:
            payload_bytes = json.dumps(item).encode('utf-8')
            headers = {
                "Content-Type": "application/json",
                "X-Node-IP": item.get('node_ip', '')
            }
            req = urllib.request.Request(INGEST_URL, data=payload_bytes, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read()
        except Exception:
            pass
        finally:
            log_queue.task_done()

COMBINED_LOG_REGEX = re.compile(
    r'(?P<ip>[0-9a-fA-F\.:]+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"'
)

def parse_nginx_combined_syslog(raw_msg, sender_ip):
    """
    Convierte una línea de access_log en formato clásico 'combined' o 'main' de Nginx
    (como facturaantell-access.log, nube-access.log, pimco-access.log, puercos.log)
    en un evento estructurado para Mithril SIEM.
    """
    m = COMBINED_LOG_REGEX.search(raw_msg)
    if not m:
        return None

    client_ip = m.group('ip').strip()
    req_raw = m.group('request').strip()
    parts = req_raw.split(' ')
    if len(parts) >= 2:
        http_method = parts[0].upper()[:10]
        full_uri = parts[1]
    elif len(parts) == 1 and parts[0]:
        http_method = 'GET'
        full_uri = parts[0]
    else:
        http_method = 'GET'
        full_uri = '/'

    # Ignorar ruido interno de monitoreo local /stub_status desde 127.0.0.1
    if client_ip == '127.0.0.1' and '/stub_status' in full_uri:
        return None

    if '?' in full_uri:
        uri, query_params = full_uri.split('?', 1)
    else:
        uri, query_params = full_uri, ''

    # Extraer etiqueta del sitio si viene en el tag de syslog o prefijo [sitio]
    site_tag = ''
    tag_match = re.search(r'\[site:([a-zA-Z0-9_\-\.]+)\]', raw_msg)
    if tag_match:
        site_tag = tag_match.group(1)
    else:
        syslog_tag = re.search(r'nginx_([a-zA-Z0-9_\-]+):', raw_msg)
        if syslog_tag:
            site_tag = syslog_tag.group(1)

    status_code = int(m.group('status'))
    bytes_str = m.group('bytes')
    bytes_sent = int(bytes_str) if bytes_str.isdigit() else 0
    referer = m.group('referer') if m.group('referer') != '-' else ''
    user_agent = m.group('agent') if m.group('agent') != '-' else ''

    # Si proviene de puercos.log (00-bloqueo-bots.conf), marcar en URI y asegurar detección
    if 'puercos' in site_tag.lower():
        uri = f"[BOT-TRAP] {uri}"
        if status_code < 400:
            status_code = 403
    elif site_tag and not uri.startswith('['):
        uri = f"[{site_tag}] {uri}"

    return {
        'client_ip': client_ip,
        'http_method': http_method,
        'uri': uri,
        'query_params': query_params,
        'status_code': status_code,
        'bytes_sent': bytes_sent,
        'latency_ms': 0.0,
        'user_agent': user_agent,
        'referer': referer or site_tag,
        'node_ip': sender_ip,
        'headers': {'log_type': 'access_combined', 'site': site_tag}
    }

def parse_nginx_error_syslog(raw_msg, sender_ip):
    """
    Convierte una línea de error_log de Nginx recibida por Syslog en un objeto estructurado para Mithril.
    Ejemplo Nginx error_log:
    2026/10/28 11:40:12 [error] 123#123: *45 open() "/var/www/..." failed (...), client: 1.2.3.4, server: x.com, request: "GET /test?a=1 HTTP/1.1", upstream: "...", host: "x.com"
    """
    if "nginx" not in raw_msg.lower() and not re.search(r'\[(emerg|alert|crit|error|warn|notice)\]', raw_msg):
        return None

    client_match = re.search(r'client:\s*([0-9a-fA-F\.:]+)', raw_msg)
    client_ip = client_match.group(1) if client_match else sender_ip

    req_match = re.search(r'request:\s*"([A-Z]+)\s+([^\s"]+)[^"]*"', raw_msg)
    if req_match:
        http_method = req_match.group(1)
        full_uri = req_match.group(2)
        if '?' in full_uri:
            uri, query_params = full_uri.split('?', 1)
        else:
            uri, query_params = full_uri, ''
    else:
        http_method = 'ERR'
        uri = '/nginx-error-log'
        query_params = ''

    level_match = re.search(r'\[(emerg|alert|crit|error|warn|notice)\]', raw_msg)
    level = level_match.group(1).upper() if level_match else 'ERROR'

    # Extraer el mensaje descriptivo principal del error
    msg_match = re.search(r'\[(?:emerg|alert|crit|error|warn|notice)\]\s+\d+#\d+:\s*(?:\*\d+\s+)?([^,]+)', raw_msg)
    err_detail = msg_match.group(1).strip() if msg_match else raw_msg[-120:].strip()

    host_match = re.search(r'host:\s*"([^"]+)"', raw_msg)
    server_match = re.search(r'server:\s*([^,\s]+)', raw_msg)
    vhost = host_match.group(1) if host_match else (server_match.group(1) if server_match else '')

    status_code = 500 if level in ('EMERG', 'ALERT', 'CRIT', 'ERROR') else 400
    if 'No such file or directory' in err_detail or ' is not found' in err_detail:
        status_code = 404
    elif 'access forbidden' in err_detail.lower() or 'permission denied' in err_detail.lower():
        status_code = 403
    elif 'timed out' in err_detail.lower():
        status_code = 504
    elif 'Connection refused' in err_detail or 'no live upstreams' in err_detail:
        status_code = 502

    return {
        'client_ip': client_ip,
        'http_method': http_method,
        'uri': f"[{level}] {uri}" if uri == '/nginx-error-log' else uri,
        'query_params': query_params or err_detail[:160],
        'status_code': status_code,
        'bytes_sent': 0,
        'latency_ms': 0.0,
        'user_agent': f"Nginx ErrorLog ({level}): {err_detail[:100]}",
        'referer': vhost,
        'node_ip': sender_ip,
        'headers': {'log_type': 'error_log', 'level': level, 'vhost': vhost, 'raw_error': err_detail}
    }

def run_udp_syslog_receiver():
    """Servidor UDP escuchando en 0.0.0.0:5140 para Syslog de Nginx (access_log JSON y error_log)"""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server.bind((BIND_HOST, UDP_PORT))
        print(f"📡 [UDP-SYSLOG] Receptor de logs activo en {BIND_HOST}:{UDP_PORT} (Access JSON + Error Log)", flush=True)
    except Exception as e:
        print(f"❌ [UDP-SYSLOG] Error enlazando {UDP_PORT}: {e}", flush=True)
        return

    # Iniciar 4 workers de ingestión concurrente
    for _ in range(4):
        threading.Thread(target=ingest_worker, daemon=True).start()

    while True:
        try:
            data, addr = server.recvfrom(BUFFER_SIZE)
            raw = data.decode('utf-8', errors='ignore')
            
            # 1. Si es un mensaje JSON (mithril_json o json_analytics)
            start_idx = raw.find('{')
            end_idx = raw.rfind('}')
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                json_str = raw[start_idx:end_idx+1]
                try:
                    log_obj = json.loads(json_str)
                    # Normalizar campos por si viene en formato json_analytics u otel_json
                    if 'client_ip' not in log_obj and 'remote_addr' in log_obj:
                        log_obj['client_ip'] = log_obj.get('remote_addr', '')
                    if 'http_method' not in log_obj and 'request_method' in log_obj:
                        log_obj['http_method'] = log_obj.get('request_method', 'GET')
                    if 'uri' not in log_obj and 'request_uri' in log_obj:
                        log_obj['uri'] = log_obj.get('request_uri', '/').split('?')[0]
                    if 'query_params' not in log_obj and 'args' in log_obj:
                        log_obj['query_params'] = log_obj.get('args', '')
                    if 'status_code' not in log_obj and 'status' in log_obj:
                        log_obj['status_code'] = int(log_obj.get('status') or 200)
                    if 'latency_ms' not in log_obj and 'request_time' in log_obj:
                        log_obj['latency_ms'] = float(log_obj.get('request_time') or 0.0)
                    if 'user_agent' not in log_obj and 'http_user_agent' in log_obj:
                        log_obj['user_agent'] = log_obj.get('http_user_agent', '')
                    if 'referer' not in log_obj and 'http_referer' in log_obj:
                        log_obj['referer'] = log_obj.get('http_referer', '')
                    # Ignorar ruido interno de monitoreo local /stub_status desde 127.0.0.1
                    if log_obj.get('client_ip') == '127.0.0.1' and '/stub_status' in str(log_obj.get('uri', '')):
                        continue
                    log_obj['node_ip'] = addr[0]
                    if not log_queue.full():
                        log_queue.put_nowait(log_obj)
                    continue
                except json.JSONDecodeError:
                    pass

            # 2. Si es una línea de access_log en formato combined/main de los sitios (facturaantell, nube, pimco, puercos, etc.)
            comb_obj = parse_nginx_combined_syslog(raw, addr[0])
            if comb_obj:
                if not log_queue.full():
                    log_queue.put_nowait(comb_obj)
                continue

            # 3. Si es un mensaje de texto plano del error_log de Nginx
            err_obj = parse_nginx_error_syslog(raw, addr[0])
            if err_obj and not log_queue.full():
                log_queue.put_nowait(err_obj)
        except Exception:
            pass

def main():
    print("=" * 65)
    print("🛡️  MITHRIL SIEM - LAN PORT FORWARDER & SYSLOG RECEIVER")
    print(f"   IP Escucha : {BIND_HOST}")
    print(f"   Puertos    : TCP {TCP_PORT} (Web/API) | UDP {UDP_PORT} (Syslog Nginx)")
    print("=" * 65, flush=True)

    t_tcp = threading.Thread(target=run_tcp_forwarder, daemon=True)
    t_udp = threading.Thread(target=run_udp_syslog_receiver, daemon=True)

    t_tcp.start()
    t_udp.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDeteniendo forwarder...")

if __name__ == "__main__":
    main()
