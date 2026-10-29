#!/usr/bin/env python3
"""
Mithril SIEM - Agente Bouncer para Servidores Proxy Nginx
Compatible con: Ubuntu 20.04/22.04/24.04, Debian 11/12, Rocky Linux 8/9, AlmaLinux, RHEL, CentOS.

Funcionalidades:
1. Envia Heartbeat y telemetria (CPU, RAM, version de Nginx, estado) a Mithril SIEM (Puerto 9900).
2. Sincroniza periodicamente la lista de IPs bloqueadas (Blacklist aprobada por el operador).
3. Aplica los bloqueos de forma automatica mediante:
   - ipset / iptables (bloqueo a nivel de kernel/red, ultrarrapido).
   - nginx_conf (archivo dinamico /etc/nginx/conf.d/mithril_blocklist.conf + reload suave).
4. No requiere librerias externas pesadas (soporta urllib nativo con fallback si requests no esta instalado).
"""

import os
import re
import sys
import time
import json
import struct
import socket
import threading
import subprocess
import urllib.request
import urllib.parse
import urllib.error

# Configuracion desde Variables de Entorno (o valores por defecto)
MITHRIL_URL = os.getenv("MITHRIL_URL", "http://127.0.0.1:9900").rstrip("/")
NODE_API_KEY = os.getenv("NODE_API_KEY", "")
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", "15"))  # Segundos
BLOCK_METHOD = os.getenv("BLOCK_METHOD", "ipset")  # 'ipset', 'nginx_conf' o 'monitor'
NGINX_BLOCK_FILE = os.getenv("NGINX_BLOCK_FILE", "/etc/nginx/conf.d/mithril_blocklist.conf")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "5140"))

if not NODE_API_KEY:
    print("❌ [FATAL] La variable de entorno NODE_API_KEY es obligatoria.")
    print("   Obten tu token en el panel de Mithril: Nodos -> Configurar Nodo.")
    sys.exit(1)

def http_request(url, method="GET", data=None):
    """Peticion HTTP ligera utilizando urllib nativo (sin dependencias externas requeridas)"""
    headers = {
        "Authorization": f"Bearer {NODE_API_KEY}",
        "Content-Type": "application/json",
        "User-Agent": "Mithril-Bouncer/1.0"
    }
    encoded_data = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            res_body = response.read().decode("utf-8")
            return response.status, json.loads(res_body) if res_body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return e.code, {"error": body}
    except Exception as e:
        return 0, {"error": str(e)}

def get_ram_usage():
    """Calcula el porcentaje de RAM usada leyendo /proc/meminfo nativo"""
    try:
        with open("/proc/meminfo", "r") as f:
            lines = f.readlines()
        mem = {}
        for line in lines:
            parts = line.split(":")
            if len(parts) == 2:
                mem[parts[0].strip()] = int(parts[1].strip().split()[0])
        total = mem.get("MemTotal", 1)
        avail = mem.get("MemAvailable", mem.get("MemFree", 0))
        used = total - avail
        return round((used / total) * 100, 1)
    except Exception:
        return 0.0

def get_cpu_usage():
    """Calcula estimacion de carga de CPU normalizada por nucleos"""
    try:
        with open("/proc/loadavg", "r") as f:
            load = float(f.read().split()[0])
        cores = os.cpu_count() or 1
        return round(min((load / cores) * 100, 100.0), 1)
    except Exception:
        return 0.0

def get_nginx_version():
    """Detecta la version instalada de Nginx"""
    try:
        res = subprocess.run(["nginx", "-v"], capture_output=True, text=True, check=False)
        out = (res.stderr or res.stdout).strip()
        if "nginx/" in out:
            return out.replace("nginx version: ", "").strip()
        return out or "Nginx (activo)"
    except Exception:
        return "Nginx"

def get_active_connections():
    """Obtiene el numero de conexiones TCP establecidas hacia el proxy de forma universal"""
    try:
        res = subprocess.run(["ss", "-Htan", "state", "established"], capture_output=True, text=True, check=False)
        if res.returncode == 0 and res.stdout:
            lines = [l for l in res.stdout.strip().splitlines() if l.strip()]
            return len(lines)
    except Exception:
        pass
    return 0

def init_firewall():
    """Asegura que el set de ipset y la regla de iptables existan"""
    if BLOCK_METHOD == "ipset":
        try:
            # 1. Crear el ipset si no existe
            subprocess.run(["ipset", "create", "mithril_blacklist", "hash:ip", "-exist"], check=True)
            # 2. Verificar o insertar regla en iptables INPUT
            check = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "mithril_blacklist", "src", "-j", "DROP"],
                                   capture_output=True, check=False)
            if check.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", "mithril_blacklist", "src", "-j", "DROP"], check=True)
                print("🛡️ [FIREWALL] Regla de bloqueo iptables + ipset creada exitosamente.")
            else:
                print("🛡️ [FIREWALL] ipset 'mithril_blacklist' listo y vinculado a iptables.")
        except FileNotFoundError:
            print("⚠️ [AVISO] 'ipset' o 'iptables' no encontrados. Se recomienda instalarlos o usar BLOCK_METHOD=nginx_conf")
        except Exception as e:
            print(f"⚠️ [FIREWALL] Error iniciando ipset: {e}")

def apply_blocklist(banned_ips):
    """Aplica la lista de IPs denegadas en el firewall o archivo de Nginx"""
    if BLOCK_METHOD == "monitor":
        print(f"👁️ [MONITOR-PASIVO] {len(banned_ips)} IPs en lista negra (modo solo lectura, sin tocar firewall ni Nginx).")
        return
    if BLOCK_METHOD == "ipset":
        try:
            # Asegurar que la regla INPUT exista (por si firewalld se recargo en Rocky Linux / RHEL)
            init_firewall()
            # Reemplazo atomico usando un set temporal
            subprocess.run(["ipset", "create", "mithril_temp", "hash:ip", "-exist"], check=True)
            subprocess.run(["ipset", "flush", "mithril_temp"], check=True)
            for ip in banned_ips:
                subprocess.run(["ipset", "add", "mithril_temp", ip, "-exist"], check=True)
            subprocess.run(["ipset", "swap", "mithril_temp", "mithril_blacklist"], check=True)
            subprocess.run(["ipset", "destroy", "mithril_temp"], check=True)
            print(f"✅ [IPSET] {len(banned_ips)} IPs bloqueadas en kernel/firewall.")
        except Exception as e:
            print(f"❌ [IPSET] Error aplicando bloqueo por ipset: {e}")
    else:
        # Metodo configuracion Nginx
        try:
            os.makedirs(os.path.dirname(NGINX_BLOCK_FILE), exist_ok=True)
            content = "# Mithril SIEM - Lista de Bloqueo Dinamica\n"
            for ip in banned_ips:
                content += f"deny {ip};\n"
            
            with open(NGINX_BLOCK_FILE, "w") as f:
                f.write(content)
            
            # Validar sintaxis antes de recargar
            test = subprocess.run(["nginx", "-t"], capture_output=True, text=True, check=False)
            if test.returncode == 0:
                subprocess.run(["nginx", "-s", "reload"], check=False)
                print(f"✅ [NGINX] {len(banned_ips)} IPs sincronizadas en {NGINX_BLOCK_FILE} y Nginx recargado.")
            else:
                print(f"❌ [NGINX] Error en sintaxis de Nginx: {test.stderr}")
        except Exception as e:
            print(f"❌ [NGINX] Error escribiendo lista de bloqueo: {e}")

HTTP_METHODS_BYTES = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")

def extract_tls_sni(payload):
    """Extrae el dominio SNI (Server Name Indication) en memoria de un paquete TLS ClientHello"""
    try:
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        # Saltar Record Header (5) + Handshake Header (4) + Version (2) + Random (32) = 43
        pos = 43
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return ""
        cipher_suites_len = struct.unpack("!H", payload[pos:pos+2])[0]
        pos += 2 + cipher_suites_len
        if pos + 1 > len(payload):
            return ""
        comp_methods_len = payload[pos]
        pos += 1 + comp_methods_len
        if pos + 2 > len(payload):
            return ""
        extensions_len = struct.unpack("!H", payload[pos:pos+2])[0]
        pos += 2
        end_ext = min(len(payload), pos + extensions_len)
        while pos + 4 <= end_ext:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos+4])
            pos += 4
            if ext_type == 0x0000 and pos + 5 <= end_ext:  # server_name extension
                name_len = struct.unpack("!H", payload[pos+3:pos+5])[0]
                if pos + 5 + name_len <= end_ext:
                    return payload[pos+5:pos+5+name_len].decode("ascii", errors="ignore")
                break
            pos += ext_len
    except Exception:
        pass
    return ""

def kernel_network_mirror_worker():
    """
    Espejo de Red en Memoria del Kernel (AF_PACKET Zero-File-Read Mirror):
    - NO lee ningún archivo de /var/log/nginx/ ni de /etc/nginx/ (cero I/O de disco).
    - Captura en memoria RAM todas las peticiones HTTP entrantes y balanceadas (proxy_pass)
      así como las conexiones TLS (SNI) sin importar cómo esté configurado Nginx.
    """
    if not hasattr(socket, "AF_PACKET"):
        return

    parsed = urllib.parse.urlparse(MITHRIL_URL)
    target_host = parsed.hostname or "127.0.0.1"
    target_port = parsed.port or 9900
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_sock.settimeout(0.5)
    except Exception as e:
        print(f"⚠️ [KERNEL-MIRROR] No se pudo abrir AF_PACKET ({e}).")
        return

    print(f"⚡ [KERNEL-MIRROR] Espejo en memoria RAM activo (Cero lectura de archivos) -> UDP {target_host}:{SYSLOG_PORT}")

    pending_http = {}  # (src_ip, src_port, dst_ip, dst_port) -> dict
    recent_client_activity = {}  # client_ip -> timestamp
    last_external_edge = {"ip": "", "ts": 0.0}
    last_flush = time.time()

    def flush_expired_pending(now_ts):
        for k, req_item in list(pending_http.items()):
            if now_ts - req_item["ts"] >= 0.8:
                pending_http.pop(k, None)
                event_json = json.dumps({
                    "client_ip": req_item["client_ip"],
                    "real_client_ip": req_item.get("real_client_ip", ""),
                    "cloudflare_ip": req_item.get("cloudflare_ip", ""),
                    "http_method": req_item["http_method"],
                    "uri": req_item["uri"],
                    "query_params": req_item["query_params"],
                    "status_code": 200,
                    "bytes_sent": 0,
                    "latency_ms": round(max(0.0, now_ts - req_item["ts"]), 4),
                    "user_agent": req_item["user_agent"],
                    "referer": req_item["referer"],
                    "headers": req_item.get("headers", {}),
                })
                msg = f"<190>nginx: {event_json}".encode("utf-8", errors="ignore")
                udp_sock.sendto(msg[:60000], (target_host, SYSLOG_PORT))

    while True:
        try:
            try:
                raw_packet, addr = raw_sock.recvfrom(65535)
            except socket.timeout:
                now_ts = time.time()
                flush_expired_pending(now_ts)
                last_flush = now_ts
                continue

            now = time.time()
            if now - last_flush >= 0.5:
                flush_expired_pending(now)
                last_flush = now
            # En loopback (lo), Linux entrega cada paquete dos veces (entrada y salida PACKET_OUTGOING=4)
            if addr and len(addr) >= 3 and addr[0] == "lo" and addr[2] == 4:
                continue

            if len(raw_packet) < 34:
                continue

            eth_proto = struct.unpack("!H", raw_packet[12:14])[0]
            eth_offset = 14
            if eth_proto == 0x8100:  # 802.1Q VLAN
                if len(raw_packet) < 38:
                    continue
                eth_proto = struct.unpack("!H", raw_packet[16:18])[0]
                eth_offset = 18

            if eth_proto != 0x0800:  # Solo IPv4
                continue

            ver_ihl = raw_packet[eth_offset]
            ihl = (ver_ihl & 0x0F) * 4
            if raw_packet[eth_offset + 9] != 6:  # Solo TCP
                continue

            ip_end = eth_offset + ihl
            if len(raw_packet) < ip_end + 20:
                continue

            src_ip = socket.inet_ntoa(raw_packet[eth_offset + 12 : eth_offset + 16])
            dst_ip = socket.inet_ntoa(raw_packet[eth_offset + 16 : eth_offset + 20])
            src_port, dst_port = struct.unpack("!HH", raw_packet[ip_end : ip_end + 4])

            # Ignorar tráfico propio hacia Mithril SIEM o SSH
            if src_port in (22, SYSLOG_PORT, target_port) or dst_port in (22, SYSLOG_PORT, target_port):
                continue

            tcp_header_len = ((raw_packet[ip_end + 12] >> 4) & 0x0F) * 4
            payload_start = ip_end + tcp_header_len
            if payload_start >= len(raw_packet):
                continue

            payload = raw_packet[payload_start:]
            if len(payload) < 8:
                continue

            # 1. Petición HTTP en memoria (entrante directa o desencriptada por Nginx hacia upstream)
            if payload.startswith(HTTP_METHODS_BYTES):
                head_End = payload.find(b"\r\n\r\n")
                header_bytes = payload[:head_End] if head_End != -1 else payload[:2048]
                header_text = header_bytes.decode("latin-1", errors="ignore")
                lines = header_text.split("\r\n")
                if not lines:
                    continue

                req_parts = lines[0].split(" ")
                if len(req_parts) < 2:
                    continue
                method = req_parts[0].upper()[:10]
                full_uri = req_parts[1]

                headers_map = {}
                for hline in lines[1:]:
                    if ":" in hline:
                        k, v = hline.split(":", 1)
                        headers_map[k.strip().lower()] = v.strip()

                # Extraer tanto la IP Real del Cliente como la IP del nodo de Cloudflare (si aplica)
                cf_connecting_ip = headers_map.get("cf-connecting-ip") or headers_map.get("true-client-ip") or ""
                xff_raw = headers_map.get("x-forwarded-for", "")
                xff_parts = [p.strip() for p in xff_raw.split(",") if p.strip()]
                x_real_ip = headers_map.get("x-real-ip", "").strip()
                cf_ray = headers_map.get("cf-ray", "").strip()
                cf_country = headers_map.get("cf-ipcountry", "").strip()

                real_ip = (
                    cf_connecting_ip
                    or (xff_parts[0] if xff_parts else "")
                    or x_real_ip
                    or src_ip
                )

                # Identificar la IP de borde (nodo Cloudflare o conexión entrante externa)
                edge_ip = src_ip
                if src_ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")):
                    if len(xff_parts) >= 2:
                        edge_ip = xff_parts[-1]
                    elif (now - last_external_edge["ts"]) <= 2.0 and last_external_edge["ip"]:
                        edge_ip = last_external_edge["ip"]
                else:
                    last_external_edge["ip"] = src_ip
                    last_external_edge["ts"] = now

                # Ignorar peticiones desde este mismo servidor cuando Nginx ya recibió el paquete directo
                if real_ip in ("127.0.0.1", "::1") and any(p in full_uri for p in ("/stub_status", "/nginx_status", "/metrics")):
                    continue

                host_hdr = headers_map.get("host", "")
                if "?" in full_uri:
                    uri, query_params = full_uri.split("?", 1)
                else:
                    uri, query_params = full_uri, ""

                display_uri = f"[{host_hdr}] {uri}" if host_hdr and not uri.startswith("[") else uri
                recent_client_activity[real_ip] = now
                recent_client_activity[edge_ip] = now

                req_headers_info = {
                    "host": host_hdr,
                    "cf_connecting_ip": cf_connecting_ip,
                    "x_forwarded_for": xff_raw,
                    "x_real_ip": x_real_ip,
                    "cf_ray": cf_ray,
                    "cf_ipcountry": cf_country,
                    "edge_ip": edge_ip,
                    "raw_src_ip": src_ip,
                }

                pending_http[(src_ip, src_port, dst_ip, dst_port)] = {
                    "ts": now,
                    "client_ip": edge_ip if (cf_ray or cf_connecting_ip) else real_ip,
                    "real_client_ip": real_ip if real_ip != edge_ip else cf_connecting_ip,
                    "cloudflare_ip": edge_ip if (cf_ray or cf_connecting_ip) else "",
                    "http_method": method,
                    "uri": display_uri,
                    "query_params": query_params,
                    "user_agent": headers_map.get("user-agent", ""),
                    "referer": headers_map.get("referer", host_hdr),
                    "headers": req_headers_info,
                }

            # 2. Respuesta HTTP en memoria (empareja el código de estado 200/404/500/403 con la petición)
            elif payload.startswith((b"HTTP/1.1 ", b"HTTP/1.0 ")):
                req_key = (dst_ip, dst_port, src_ip, src_port)
                req_item = pending_http.pop(req_key, None)
                if req_item:
                    first_line = payload[:64].decode("latin-1", errors="ignore").split("\r\n")[0]
                    parts = first_line.split(" ")
                    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 200
                    latency = round(max(0.0, now - req_item["ts"]), 4)
                    event_json = json.dumps({
                        "client_ip": req_item["client_ip"],
                        "real_client_ip": req_item.get("real_client_ip", ""),
                        "cloudflare_ip": req_item.get("cloudflare_ip", ""),
                        "http_method": req_item["http_method"],
                        "uri": req_item["uri"],
                        "query_params": req_item["query_params"],
                        "status_code": status_code,
                        "bytes_sent": len(payload),
                        "latency_ms": latency,
                        "user_agent": req_item["user_agent"],
                        "referer": req_item["referer"],
                        "headers": req_item.get("headers", {}),
                    })
                    msg = f"<190>nginx: {event_json}".encode("utf-8", errors="ignore")
                    udp_sock.sendto(msg[:60000], (target_host, SYSLOG_PORT))

            # 3. Handshake TLS ClientHello en puerto 443 (para sitios HTTPS estáticos o sin proxy_pass HTTP)
            elif dst_port == 443 and payload[0] == 0x16:
                if not src_ip.startswith(("127.", "10.", "192.168.")):
                    last_external_edge["ip"] = src_ip
                    last_external_edge["ts"] = now
                sni = extract_tls_sni(payload)
                if sni and (now - recent_client_activity.get(src_ip, 0)) > 2.0:
                    recent_client_activity[src_ip] = now
                    event_json = json.dumps({
                        "client_ip": src_ip,
                        "http_method": "HTTPS",
                        "uri": f"[{sni}] /",
                        "query_params": "",
                        "status_code": 200,
                        "bytes_sent": len(payload),
                        "latency_ms": 0.0,
                        "user_agent": f"TLS SNI ({sni})",
                        "referer": sni,
                    })
                    msg = f"<190>nginx: {event_json}".encode("utf-8", errors="ignore")
                    udp_sock.sendto(msg[:60000], (target_host, SYSLOG_PORT))

        except Exception:
            pass

def main():
    print("=" * 60)
    print("🛡️  MITHRIL BOUNCER AGENT - INICIADO")
    print(f"   SIEM Destino   : {MITHRIL_URL}")
    print(f"   Metodo Bloqueo : {BLOCK_METHOD}")
    print(f"   Intervalo Sync : {SYNC_INTERVAL} segundos")
    print("=" * 60)

    init_firewall()
    t_mirror = threading.Thread(target=kernel_network_mirror_worker, daemon=True)
    t_mirror.start()
    last_banned_count = -1

    while True:
        cpu = get_cpu_usage()
        ram = get_ram_usage()
        nginx_ver = get_nginx_version()
        active_conns = get_active_connections()

        # 1. Enviar Heartbeat y Telemetria al SIEM
        hb_data = {
            "status": "ok",
            "cpu": cpu,
            "ram": ram,
            "nginx_version": nginx_ver,
            "active_connections": active_conns,
            "rps": 0
        }
        status_code, resp = http_request(f"{MITHRIL_URL}/nodes/api/heartbeat/", method="POST", data=hb_data)
        if status_code != 200:
            print(f"⚠️ [HEARTBEAT] Respuesta inesperada del SIEM ({status_code}): {resp.get('error', '')}")

        # 2. Sincronizar Bans Aprobados por el Operador
        status_code, sync_resp = http_request(f"{MITHRIL_URL}/mitigation/api/sync-bans/", method="GET")
        if status_code == 200:
            banned_ips = sync_resp.get("banned_ips", [])
            # Solo reaplicar si hubo cambios en la lista para no saturar I/O
            if len(banned_ips) != last_banned_count or last_banned_count == -1:
                apply_blocklist(banned_ips)
                last_banned_count = len(banned_ips)
        else:
            print(f"⚠️ [SYNC-BANS] Error sincronizando lista de bans ({status_code})")

        time.sleep(SYNC_INTERVAL)

if __name__ == "__main__":
    main()
