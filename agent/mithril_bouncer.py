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
import sys
import time
import json
import subprocess
import urllib.request
import urllib.error

# Configuracion desde Variables de Entorno (o valores por defecto)
MITHRIL_URL = os.getenv("MITHRIL_URL", "http://127.0.0.1:9900").rstrip("/")
NODE_API_KEY = os.getenv("NODE_API_KEY", "")
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", "15"))  # Segundos
BLOCK_METHOD = os.getenv("BLOCK_METHOD", "ipset")  # 'ipset' o 'nginx_conf'
NGINX_BLOCK_FILE = os.getenv("NGINX_BLOCK_FILE", "/etc/nginx/conf.d/mithril_blocklist.conf")

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
    if BLOCK_METHOD == "ipset":
        try:
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

def main():
    print("=" * 60)
    print("🛡️  MITHRIL BOUNCER AGENT - INICIADO")
    print(f"   SIEM Destino   : {MITHRIL_URL}")
    print(f"   Metodo Bloqueo : {BLOCK_METHOD}")
    print(f"   Intervalo Sync : {SYNC_INTERVAL} segundos")
    print("=" * 60)

    init_firewall()
    last_banned_count = -1

    while True:
        cpu = get_cpu_usage()
        ram = get_ram_usage()
        nginx_ver = get_nginx_version()

        # 1. Enviar Heartbeat y Telemetria al SIEM
        hb_data = {
            "status": "ok",
            "cpu": cpu,
            "ram": ram,
            "nginx_version": nginx_ver,
            "active_connections": 0,
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
