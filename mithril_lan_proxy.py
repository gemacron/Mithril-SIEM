#!/usr/bin/env python3
"""
Mithril LAN Proxy - Forwarder de Red Local para Mithril SIEM en Windows
Escucha en 0.0.0.0 (todas las interfaces de Windows, ej. 192.168.200.226)
y reenvía el tráfico a 127.0.0.1 (WSL / Contenedores Podman):
- Puerto TCP 9900: Web UI y API REST (Heartbeats y Sync Bans)
- Puerto UDP 5140: Streaming de logs Syslog desde los proxies Nginx
"""

import socket
import threading
import sys

LOCAL_HOST = "127.0.0.1"
BIND_HOST = "0.0.0.0"
TCP_PORT = 9900
UDP_PORT = 5140
BUFFER_SIZE = 65536

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
    """Conecta con el backend local (Daphne/WSL en 127.0.0.1:9900) y puentea la conexión"""
    try:
        backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_sock.settimeout(5.0)
        backend_sock.connect((LOCAL_HOST, TCP_PORT))
        backend_sock.settimeout(None)
    except Exception as e:
        print(f"❌ Error conectando a Mithril local ({LOCAL_HOST}:{TCP_PORT}): {e}", flush=True)
        client_sock.close()
        return

    # Iniciar los dos hilos de streaming
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
        print(f"🌐 [TCP] Escuchando en {BIND_HOST}:{TCP_PORT} -> Redirigiendo a {LOCAL_HOST}:{TCP_PORT}", flush=True)
    except Exception as e:
        print(f"❌ [TCP] No se pudo enlazar puerto {TCP_PORT}: {e}", flush=True)
        return

    while True:
        try:
            client_sock, client_addr = server.accept()
            # print(f"🔗 [TCP] Conexión entrante desde {client_addr[0]}:{client_addr[1]}", flush=True)
            t = threading.Thread(target=handle_tcp_client, args=(client_sock, client_addr), daemon=True)
            t.start()
        except Exception as e:
            print(f"⚠️ [TCP] Error aceptando cliente: {e}", flush=True)

def run_udp_forwarder():
    """Servidor UDP escuchando en 0.0.0.0:5140 (Syslog)"""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server.bind((BIND_HOST, UDP_PORT))
        print(f"📡 [UDP] Escuchando Syslog en {BIND_HOST}:{UDP_PORT} -> Redirigiendo a {LOCAL_HOST}:{UDP_PORT}", flush=True)
    except Exception as e:
        print(f"❌ [UDP] No se pudo enlazar puerto {UDP_PORT}: {e}", flush=True)
        return

    dest = (LOCAL_HOST, UDP_PORT)
    while True:
        try:
            data, addr = server.recvfrom(BUFFER_SIZE)
            server.sendto(data, dest)
        except Exception:
            pass

def main():
    print("=" * 65)
    print("🛡️  MITHRIL SIEM - LAN PORT FORWARDER (WINDOWS)")
    print(f"   IP Externa: 192.168.200.226")
    print(f"   Forwarding: TCP 9900 (API/Web) & UDP 5140 (Syslog)")
    print("=" * 65, flush=True)

    t_tcp = threading.Thread(target=run_tcp_forwarder, daemon=True)
    t_udp = threading.Thread(target=run_udp_forwarder, daemon=True)

    t_tcp.start()
    t_udp.start()

    # Mantener el proceso vivo
    try:
        t_tcp.join()
        t_udp.join()
    except KeyboardInterrupt:
        print("\nSaliendo...")

if __name__ == "__main__":
    main()
