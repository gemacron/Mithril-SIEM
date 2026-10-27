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

def run_udp_syslog_receiver():
    """Servidor UDP escuchando en 0.0.0.0:5140 para Syslog de Nginx"""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server.bind((BIND_HOST, UDP_PORT))
        print(f"📡 [UDP-SYSLOG] Receptor de logs activo en {BIND_HOST}:{UDP_PORT}", flush=True)
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
            
            # Los mensajes de syslog tienen formato: <pri>timestamp host tag: {JSON}
            start_idx = raw.find('{')
            end_idx = raw.rfind('}')
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                json_str = raw[start_idx:end_idx+1]
                try:
                    log_obj = json.loads(json_str)
                    log_obj['node_ip'] = addr[0]
                    if not log_queue.full():
                        log_queue.put_nowait(log_obj)
                except json.JSONDecodeError:
                    pass
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
