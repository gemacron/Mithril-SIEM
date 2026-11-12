#!/usr/bin/env python3
"""
Mithril SIEM - Agente Bouncer para Servidores Proxy Nginx
Compatible con: Ubuntu 20.04/22.04/24.04, Debian 11/12, Rocky Linux 8/9, AlmaLinux, RHEL, CentOS.

Funcionalidades:
1. Envia Heartbeat y telemetria (CPU, RAM, version de Nginx, estado) a Mithril SIEM (Puerto 9900).
2. Sincroniza periodicamente la lista de IPs bloqueadas (Blacklist aprobada por el operador).
3. Aplica los bloqueos de forma automatica mediante:
   - fail2ban (Recomendado): Delega el bloqueo a Fail2ban (`fail2ban-client set mithril-jail banip <IP>`) con Smart Hybrid Action (Kernel ipset + Cloudflare Edge API opcional, sin tocar ni recargar Nginx).
   - ipset / iptables (bloqueo directo a nivel de kernel/red, ultrarrapido, sin tocar Nginx).
   - nginx_conf (archivo dinamico /etc/nginx/conf.d/mithril_blocklist.conf + reload suave).
   - monitor (modo pasivo 100% observacion, cero bloqueos).
4. No requiere librerias externas pesadas (soporta urllib nativo).
"""

import os
import re
import sys
import time
import json
import struct
import socket
import ipaddress
import threading
import subprocess
import urllib.request
import urllib.parse
import urllib.error

# Configuracion desde Variables de Entorno (o valores por defecto)
MITHRIL_URL = os.getenv("MITHRIL_URL", "http://127.0.0.1:9900").rstrip("/")
NODE_API_KEY = os.getenv("NODE_API_KEY", "")
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", "15"))  # Segundos
BLOCK_METHOD = os.getenv("BLOCK_METHOD", "fail2ban")  # 'fail2ban', 'ipset', 'nginx_conf' o 'monitor'
FAIL2BAN_JAIL = os.getenv("FAIL2BAN_JAIL", "mithril-jail")
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

_F2B_MEM_BANS = set()

FAIL2BAN_FILTER_CONTENT = """# Mithril SIEM - Filtro base para mithril-jail
[Definition]
failregex = ^MITHRIL_MANUAL_BAN <HOST>$
ignoreregex =
"""

FAIL2BAN_ACTION_CONTENT = """# Mithril SIEM - Smart Hybrid Action (Universal: Kernel ipset + Cloudflare Edge API opcional)
[Definition]
actionstart = ipset create mithril_f2b hash:ip timeout 0 -exist
              iptables -C INPUT -m set --match-set mithril_f2b src -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set mithril_f2b src -j DROP

actionstop  = iptables -D INPUT -m set --match-set mithril_f2b src -j DROP 2>/dev/null || true
              ipset destroy mithril_f2b 2>/dev/null || true

actioncheck = ipset list mithril_f2b >/dev/null 2>&1

actionban   = ipset add mithril_f2b <ip> -exist
              if [ -f /etc/mithril/cloudflare.env ]; then . /etc/mithril/cloudflare.env; if [ -n "$CF_API_TOKEN" ] && [ -n "$CF_ZONE_ID" ]; then curl -fsSL -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/access_rules/rules" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{\\"mode\\":\\"block\\",\\"configuration\\":{\\"target\\":\\"ip\\",\\"value\\":\\"<ip>\\"},\\"notes\\":\\"Mithril-SIEM-Fail2ban\\"}" >/dev/null 2>&1 || true; fi; fi

actionunban = ipset del mithril_f2b <ip> -exist
              if [ -f /etc/mithril/cloudflare.env ]; then . /etc/mithril/cloudflare.env; if [ -n "$CF_API_TOKEN" ] && [ -n "$CF_ZONE_ID" ]; then RULE_ID=$(curl -fsSL -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/access_rules/rules?configuration.target=ip&configuration.value=<ip>" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" 2>/dev/null | grep -o '"id":"[^"]*"' | head -n1 | cut -d'"' -f4); if [ -n "$RULE_ID" ]; then curl -fsSL -X DELETE "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/access_rules/rules/$RULE_ID" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" >/dev/null 2>&1 || true; fi; fi; fi

[Init]
name = mithril
"""

FAIL2BAN_JAIL_CONTENT = f"""# Mithril SIEM - Jail dedicado controlado por Mithril Bouncer
[{FAIL2BAN_JAIL}]
enabled  = true
filter   = mithril-empty
action   = mithril-smart
logpath  = /var/log/mithril-fail2ban.log
bantime  = -1
findtime = 600
maxretry = 1
"""

def init_fail2ban():
    """Verifica que Fail2ban y el jail 'mithril-jail' esten activos; los provisiona si existen los binarios."""
    try:
        chk = subprocess.run(["fail2ban-client", "status", FAIL2BAN_JAIL], capture_output=True, text=True, check=False)
        if chk.returncode == 0:
            return True

        # Si fail2ban-client existe pero el jail aun no fue cargado, autoprovisionar archivos
        os.makedirs("/etc/fail2ban/filter.d", exist_ok=True)
        os.makedirs("/etc/fail2ban/action.d", exist_ok=True)
        os.makedirs("/etc/fail2ban/jail.d", exist_ok=True)
        if not os.path.exists("/var/log/mithril-fail2ban.log"):
            with open("/var/log/mithril-fail2ban.log", "a") as f:
                f.write("")
        if not os.path.exists("/etc/fail2ban/filter.d/mithril-empty.conf"):
            with open("/etc/fail2ban/filter.d/mithril-empty.conf", "w") as f:
                f.write(FAIL2BAN_FILTER_CONTENT)
        if not os.path.exists("/etc/fail2ban/action.d/mithril-smart.conf"):
            with open("/etc/fail2ban/action.d/mithril-smart.conf", "w") as f:
                f.write(FAIL2BAN_ACTION_CONTENT)
        if not os.path.exists("/etc/fail2ban/jail.d/mithril.local"):
            with open("/etc/fail2ban/jail.d/mithril.local", "w") as f:
                f.write(FAIL2BAN_JAIL_CONTENT)

        subprocess.run(["systemctl", "enable", "--now", "fail2ban"], capture_output=True, check=False)
        subprocess.run(["fail2ban-client", "reload"], capture_output=True, text=True, check=False)
        chk2 = subprocess.run(["fail2ban-client", "status", FAIL2BAN_JAIL], capture_output=True, text=True, check=False)
        if chk2.returncode == 0:
            print(f"🛡️ [FAIL2BAN] Jail '{FAIL2BAN_JAIL}' (Smart Hybrid Action) activo y listo.")
            return True
        return False
    except FileNotFoundError:
        return False
    except Exception as e:
        print(f"⚠️ [FAIL2BAN] Aviso verificando Fail2ban: {e}")
        return False

def get_fail2ban_banned_ips():
    """Obtiene el conjunto de IPs actualmente bloqueadas en el jail de Fail2ban."""
    try:
        res = subprocess.run(["fail2ban-client", "get", FAIL2BAN_JAIL, "banip"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            out = res.stdout.strip()
            if not out:
                return set()
            return {tok.strip() for tok in out.split() if tok.strip()}

        # Fallback para versiones anteriores de fail2ban-client
        st = subprocess.run(["fail2ban-client", "status", FAIL2BAN_JAIL], capture_output=True, text=True, check=False)
        if st.returncode == 0 and "Banned IP list:" in st.stdout:
            after = st.stdout.split("Banned IP list:", 1)[1].splitlines()[0]
            return {tok.strip() for tok in after.split() if tok.strip()}
    except Exception:
        pass
    return set(_F2B_MEM_BANS)

def init_firewall():
    """Inicializa el motor de bloqueo configurado (fail2ban o ipset)"""
    if BLOCK_METHOD == "monitor":
        print("👁️ [MODO MONITOR] Mitigación pasiva activa (cero cambios en firewall).")
        return

    if BLOCK_METHOD == "fail2ban":
        if init_fail2ban():
            print(f"🛡️ [FAIL2BAN] Motor de bloqueo '{FAIL2BAN_JAIL}' vinculado a Mithril SIEM (sin tocar Nginx).")
            return
        print("⚠️ [AVISO] 'fail2ban-client' no detectado o inactivo; activando respaldo directo en Kernel (ipset).")

    if BLOCK_METHOD in ("ipset", "fail2ban"):
        try:
            subprocess.run(["ipset", "create", "mithril_blacklist", "hash:ip", "-exist"], check=True)
            check = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "mithril_blacklist", "src", "-j", "DROP"],
                                   capture_output=True, check=False)
            if check.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", "mithril_blacklist", "src", "-j", "DROP"], check=True)
                print("🛡️ [FIREWALL] Regla de bloqueo iptables + ipset creada exitosamente.")
            else:
                print("🛡️ [FIREWALL] ipset 'mithril_blacklist' listo y vinculado a iptables.")
        except FileNotFoundError:
            print("⚠️ [AVISO] 'ipset' o 'iptables' no encontrados. Instala fail2ban e ipset.")
        except Exception as e:
            print(f"⚠️ [FIREWALL] Error iniciando ipset: {e}")

def apply_blocklist(banned_ips):
    """
    Sincroniza la lista de IPs denegadas aprobadas por el operador en Mithril SIEM.
    - Protege siempre contra bloqueo accidental de nodos de Cloudflare o IPs internas.
    - Con BLOCK_METHOD='fail2ban' (por defecto): delega a Fail2ban ('mithril-jail') sin tocar Nginx.
    - Con BLOCK_METHOD='ipset': aplica en kernel ipset sin tocar Nginx.
    - Con BLOCK_METHOD='nginx_conf': escribe archivo de Nginx y recarga suavemente.
    """
    # Filtro de inmunidad absoluta para rangos de Cloudflare e IPs de red local/loopback
    safe_ips = []
    for raw_ip in banned_ips:
        ip = str(raw_ip).strip()
        if not ip:
            continue
        if is_cf_ip(ip) or is_local_balancer_ip(ip):
            print(f"🛡️ [INMUNIDAD] Ignorando IP protegida (Cloudflare/Local): {ip}")
            continue
        safe_ips.append(ip)

    if BLOCK_METHOD == "monitor":
        print(f"👁️ [MONITOR-PASIVO] {len(safe_ips)} IPs en lista negra (modo solo lectura, sin tocar firewall ni Nginx).")
        return

    # 1. MODO RECOMENDADO: Fail2ban Smart Hybrid Action (Universal con o sin Cloudflare, sin tocar Nginx)
    if BLOCK_METHOD == "fail2ban":
        if init_fail2ban():
            current_f2b = get_fail2ban_banned_ips()
            target_set = set(safe_ips)
            to_ban = sorted(target_set - current_f2b)
            to_unban = sorted(current_f2b - target_set)

            for ip in to_ban:
                res = subprocess.run(["fail2ban-client", "set", FAIL2BAN_JAIL, "banip", ip], capture_output=True, text=True, check=False)
                if res.returncode == 0:
                    _F2B_MEM_BANS.add(ip)
                    print(f"🔒 [FAIL2BAN] IP {ip} bloqueada en jail '{FAIL2BAN_JAIL}'.")
                else:
                    print(f"⚠️ [FAIL2BAN] Error bloqueando {ip}: {res.stderr.strip() or res.stdout.strip()}")

            for ip in to_unban:
                res = subprocess.run(["fail2ban-client", "set", FAIL2BAN_JAIL, "unbanip", ip], capture_output=True, text=True, check=False)
                if res.returncode == 0:
                    _F2B_MEM_BANS.discard(ip)
                    print(f"🔓 [FAIL2BAN] IP {ip} desbloqueada de jail '{FAIL2BAN_JAIL}'.")

            print(f"✅ [FAIL2BAN] Sincronización activa: {len(target_set)} IPs bloqueadas en '{FAIL2BAN_JAIL}' (Cero cambios en Nginx).")
            return
        else:
            print("⚠️ [FAIL2BAN] Servicio Fail2ban no disponible localmente; aplicando respaldo en Kernel ipset.")

    # 2. Bloqueo directo en Kernel / Firewall con ipset (sin tocar Nginx)
    if BLOCK_METHOD in ("ipset", "fail2ban"):
        try:
            init_firewall()
            subprocess.run(["ipset", "create", "mithril_temp", "hash:ip", "-exist"], check=True)
            subprocess.run(["ipset", "flush", "mithril_temp"], check=True)
            for ip in safe_ips:
                subprocess.run(["ipset", "add", "mithril_temp", ip, "-exist"], check=True)
            subprocess.run(["ipset", "swap", "mithril_temp", "mithril_blacklist"], check=True)
            subprocess.run(["ipset", "destroy", "mithril_temp"], check=True)
            print(f"✅ [IPSET] {len(safe_ips)} IPs bloqueadas en kernel/firewall (Cero cambios en Nginx).")
        except Exception as e:
            print(f"⚠️ [IPSET] Error aplicando bloqueo por ipset: {e}")
        return

    # 3. Modo legacy: Bloqueo en archivo de Nginx (solo si se selecciona explícitamente BLOCK_METHOD=nginx_conf)
    if BLOCK_METHOD == "nginx_conf":
        try:
            os.makedirs(os.path.dirname(NGINX_BLOCK_FILE), exist_ok=True)
            content = "# Mithril SIEM - Lista de Bloqueo Dinamica\n"
            for ip in safe_ips:
                content += f"deny {ip};\n"

            with open(NGINX_BLOCK_FILE, "w") as f:
                f.write(content)

            test = subprocess.run(["nginx", "-t"], capture_output=True, text=True, check=False)
            if test.returncode == 0:
                subprocess.run(["nginx", "-s", "reload"], check=False)
                print(f"✅ [NGINX] {len(safe_ips)} IPs sincronizadas en {NGINX_BLOCK_FILE} y Nginx recargado.")
            else:
                print(f"❌ [NGINX] Error en sintaxis de Nginx: {test.stderr}")
        except Exception as e:
            print(f"⚠️ [NGINX] Error escribiendo lista de bloqueo en Nginx: {e}")

HTTP_METHODS_BYTES = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")

_CF_NETS = [
    ipaddress.ip_network(c) for c in (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    )
]
_CF_CACHE = {}

def is_cf_ip(ip_s):
    if not ip_s:
        return False
    if ip_s in _CF_CACHE:
        return _CF_CACHE[ip_s]
    try:
        ip_obj = ipaddress.ip_address(ip_s.strip())
        res = any(ip_obj in net for net in _CF_NETS)
    except Exception:
        res = False
    if len(_CF_CACHE) > 2000:
        _CF_CACHE.clear()
    _CF_CACHE[ip_s] = res
    return res

def is_local_balancer_ip(ip_s):
    return ip_s.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."))

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
                header_bytes = payload[:head_End] if head_End != -1 else payload[:16384]
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

                # Extraer todas las cabeceras posibles donde Cloudflare o Nginx colocan la IP real y la IP del nodo
                cf_connecting_ip = (
                    headers_map.get("cf-connecting-ip")
                    or headers_map.get("true-client-ip")
                    or headers_map.get("x-cluster-client-ip")
                    or ""
                ).strip()
                xff_raw = headers_map.get("x-forwarded-for", "")
                xff_parts = [p.strip() for p in xff_raw.split(",") if p.strip()]
                x_real_ip = headers_map.get("x-real-ip", "").strip()
                cf_ray = headers_map.get("cf-ray", "").strip()
                cf_country = headers_map.get("cf-ipcountry", "").strip()

                # Separar con precisión matemática cuál IP es el nodo Cloudflare y cuál es la IP Real del Cliente
                cf_node_ip = ""
                real_origin_ip = ""
                for cand in [cf_connecting_ip, *xff_parts, x_real_ip, src_ip]:
                    if not cand:
                        continue
                    if is_cf_ip(cand):
                        if not cf_node_ip:
                            cf_node_ip = cand
                    elif not is_local_balancer_ip(cand):
                        if not real_origin_ip:
                            real_origin_ip = cand

                if not cf_node_ip and (now - last_external_edge["ts"]) <= 2.5 and is_cf_ip(last_external_edge["ip"]):
                    cf_node_ip = last_external_edge["ip"]

                is_via_cloudflare = bool(cf_node_ip or is_cf_ip(src_ip) or cf_ray or cf_country)

                # Si NO vino de Cloudflare y tampoco hubo IP pública externa (tráfico directo por LAN),
                # registrar la IP local del equipo emisor de la red interna
                if not is_via_cloudflare and not real_origin_ip:
                    for cand in [cf_connecting_ip, *xff_parts, x_real_ip, src_ip]:
                        if cand and cand not in ("127.0.0.1", "::1") and not is_cf_ip(cand):
                            real_origin_ip = cand
                            break

                edge_ip = cf_node_ip or (src_ip if is_cf_ip(src_ip) else (xff_parts[-1] if xff_parts else src_ip))
                real_ip = real_origin_ip or (cf_connecting_ip if not is_local_balancer_ip(cf_connecting_ip) else "")

                if not is_local_balancer_ip(src_ip):
                    last_external_edge["ip"] = src_ip
                    last_external_edge["ts"] = now

                # Ignorar peticiones desde este mismo servidor cuando Nginx ya recibió el paquete directo
                if (real_ip or edge_ip) in ("127.0.0.1", "::1") and any(p in full_uri for p in ("/stub_status", "/nginx_status", "/metrics")):
                    continue

                host_hdr = headers_map.get("host", "")
                if "?" in full_uri:
                    uri, query_params = full_uri.split("?", 1)
                else:
                    uri, query_params = full_uri, ""

                display_uri = f"[{host_hdr}] {uri}" if host_hdr and not uri.startswith("[") else uri
                primary_ip = cf_node_ip or edge_ip or real_ip or src_ip
                recent_client_activity[primary_ip] = now
                if real_ip:
                    recent_client_activity[real_ip] = now

                req_headers_info = {
                    "host": host_hdr,
                    "cf_connecting_ip": cf_connecting_ip,
                    "x_forwarded_for": xff_raw,
                    "x_real_ip": x_real_ip,
                    "cf_ray": cf_ray,
                    "cf_ipcountry": cf_country,
                    "cloudflare_ip": cf_node_ip,
                    "real_client_ip": real_ip if real_ip != primary_ip else "",
                    "edge_ip": edge_ip,
                    "raw_src_ip": src_ip,
                }

                pending_http[(src_ip, src_port, dst_ip, dst_port)] = {
                    "ts": now,
                    "client_ip": primary_ip,
                    "real_client_ip": real_ip if real_ip != primary_ip else "",
                    "cloudflare_ip": cf_node_ip,
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
                if not is_local_balancer_ip(src_ip):
                    last_external_edge["ip"] = src_ip
                    last_external_edge["ts"] = now
                sni = extract_tls_sni(payload)
                if sni and (now - recent_client_activity.get(src_ip, 0)) > 2.5:
                    recent_client_activity[src_ip] = now
                    event_json = json.dumps({
                        "client_ip": src_ip,
                        "real_client_ip": "",
                        "cloudflare_ip": src_ip if is_cf_ip(src_ip) else "",
                        "http_method": "HTTPS",
                        "uri": f"[{sni}] /",
                        "query_params": "",
                        "status_code": 200,
                        "bytes_sent": len(payload),
                        "latency_ms": 0.0,
                        "user_agent": f"TLS SNI ({sni})",
                        "referer": sni,
                        "headers": {
                            "host": sni,
                            "cloudflare_ip": src_ip if is_cf_ip(src_ip) else "",
                            "real_client_ip": "",
                        }
                    })
                    msg = f"<190>nginx: {event_json}".encode("utf-8", errors="ignore")
                    udp_sock.sendto(msg[:60000], (target_host, SYSLOG_PORT))

        except Exception:
            pass

def main():
    global BLOCK_METHOD, SYNC_INTERVAL
    print("=" * 60)
    print("🛡️  MITHRIL BOUNCER AGENT v2.1 - INICIADO")
    print(f"   SIEM Destino   : {MITHRIL_URL}")
    print(f"   Metodo Bloqueo : {BLOCK_METHOD} (Jail: {FAIL2BAN_JAIL})")
    print(f"   Intervalo Sync : {SYNC_INTERVAL} segundos")
    print("=" * 60)

    init_firewall()
    t_mirror = threading.Thread(target=kernel_network_mirror_worker, daemon=True)
    t_mirror.start()
    last_banned_set = None

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
        if status_code == 200:
            remote_method = resp.get("block_method")
            if remote_method and remote_method != BLOCK_METHOD and BLOCK_METHOD != "monitor":
                print(f"🔄 [CONFIG] Método de bloqueo actualizado desde Mithril SIEM: {BLOCK_METHOD} -> {remote_method}")
                BLOCK_METHOD = remote_method
                last_banned_set = None
        else:
            print(f"⚠️ [HEARTBEAT] Respuesta inesperada del SIEM ({status_code}): {resp.get('error', '')}")

        # 2. Sincronizar Bans Aprobados por el Operador
        status_code, sync_resp = http_request(f"{MITHRIL_URL}/mitigation/api/sync-bans/", method="GET")
        if status_code == 200:
            banned_ips = sync_resp.get("banned_ips", [])
            current_set = set(banned_ips)
            # Reaplicar si cambio el conjunto de IPs o es la primera sincronizacion
            if last_banned_set is None or current_set != last_banned_set:
                apply_blocklist(banned_ips)
                last_banned_set = current_set
        else:
            print(f"⚠️ [SYNC-BANS] Error sincronizando lista de bans ({status_code})")

        time.sleep(SYNC_INTERVAL)

if __name__ == "__main__":
    main()
