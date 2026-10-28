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
import glob
import time
import json
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
NGINX_LOG_DIR = os.getenv("NGINX_LOG_DIR", "/var/log/nginx")
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

def discover_nginx_log_files():
    """
    Descubre dinamicamente todos los archivos de log activos en cualquier configuracion de Nginx:
    1. Analiza las directivas access_log y error_log declaradas en /etc/nginx/
    2. Escanea /var/log/nginx/*.log como respaldo universal
    """
    discovered = set()

    # 1. Buscar en /var/log/nginx/*.log (y subdirectorios de primer nivel)
    if os.path.isdir(NGINX_LOG_DIR):
        for pattern in ("*.log", "*/*.log"):
            for p in glob.glob(os.path.join(NGINX_LOG_DIR, pattern)):
                if os.path.isfile(p):
                    discovered.add(os.path.abspath(p))

    # 2. Descubrir rutas personalizadas declaradas en archivos .conf de /etc/nginx
    nginx_etc = "/etc/nginx"
    log_directive_re = re.compile(r'^\s*(?:access_log|error_log)\s+([^\s;]+)', re.MULTILINE)
    if os.path.isdir(nginx_etc):
        for root_dir, _, files in os.walk(nginx_etc):
            for fname in files:
                if not fname.endswith(".conf"):
                    continue
                fpath = os.path.join(root_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as cf:
                        content = cf.read()
                    for match in log_directive_re.finditer(content):
                        raw_path = match.group(1).strip('"\'')
                        if raw_path in ("off", "/dev/null") or raw_path.startswith("syslog:"):
                            continue
                        if not os.path.isabs(raw_path):
                            raw_path = os.path.join("/var/log/nginx", raw_path)
                        if os.path.isfile(raw_path):
                            discovered.add(os.path.abspath(raw_path))
                except Exception:
                    pass

    return discovered

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

def tail_nginx_logs_worker():
    """
    Recolector universal de logs en tiempo real (100% Read-Only):
    Descubre automaticamente cualquier archivo access_log y error_log de Nginx
    en el servidor (sin importar como este estructurado /etc/nginx/) y transmite
    las nuevas entradas por UDP al SIEM sin tocar ni recargar Nginx.
    """
    parsed = urllib.parse.urlparse(MITHRIL_URL)
    target_host = parsed.hostname or "127.0.0.1"
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    open_files = {}  # path -> (file_obj, inode, source_tag)
    last_discovery = 0

    print(f"📡 [LOG-STREAMER] Auto-descubrimiento universal de logs Nginx activo -> UDP {target_host}:{SYSLOG_PORT}")

    while True:
        try:
            now = time.time()
            # Re-escanear archivos de log cada 10 segundos para detectar nuevos vhosts o rotaciones
            if now - last_discovery >= 10:
                last_discovery = now
                for path in discover_nginx_log_files():
                    fname = os.path.basename(path)
                    # Ignorar archivos rotados historicos (.gz, -YYYYMMDD)
                    if fname.endswith(".gz") or re.search(r'-\d{8}$', fname):
                        continue
                    try:
                        st = os.stat(path)
                        if st.st_size == 0 and path not in open_files:
                            continue
                        source_tag = re.sub(r'([-_.]?(access|error))?\.log$', '', fname, flags=re.IGNORECASE) or "nginx"
                        if path not in open_files:
                            f = open(path, "r", encoding="utf-8", errors="ignore")
                            f.seek(0, os.SEEK_END)  # Posicionarse al final para leer solo trafico en vivo
                            open_files[path] = (f, st.st_ino, source_tag)
                        else:
                            f, old_ino, source_tag = open_files[path]
                            if st.st_ino != old_ino or st.st_size < f.tell():
                                try:
                                    f.close()
                                except Exception:
                                    pass
                                f = open(path, "r", encoding="utf-8", errors="ignore")
                                open_files[path] = (f, st.st_ino, source_tag)
                    except Exception:
                        pass

            for path, (f, ino, source_tag) in list(open_files.items()):
                try:
                    lines_read = 0
                    while lines_read < 250:
                        line = f.readline()
                        if not line:
                            break
                        lines_read += 1
                        line_str = line.strip()
                        if not line_str:
                            continue
                        payload = f"<190>nginx: [vhost:{source_tag}] {line_str}".encode("utf-8", errors="ignore")
                        udp_sock.sendto(payload[:60000], (target_host, SYSLOG_PORT))
                except Exception:
                    pass
        except Exception:
            pass

        time.sleep(0.4)

def main():
    print("=" * 60)
    print("🛡️  MITHRIL BOUNCER AGENT - INICIADO")
    print(f"   SIEM Destino   : {MITHRIL_URL}")
    print(f"   Metodo Bloqueo : {BLOCK_METHOD}")
    print(f"   Intervalo Sync : {SYNC_INTERVAL} segundos")
    print("=" * 60)

    init_firewall()
    t_logs = threading.Thread(target=tail_nginx_logs_worker, daemon=True)
    t_logs.start()
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
