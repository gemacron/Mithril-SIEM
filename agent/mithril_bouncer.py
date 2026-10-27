#!/usr/bin/env python3
"""
Mithril Bouncer - Agente para Servidores Proxy Nginx
Este script se ejecuta en cada nodo proxy.
1. Envía heartbeats periódicos a Mithril SIEM reportando salud y tráfico.
2. Sincroniza la lista de IPs bloqueadas aprobadas por el operador.
3. Aplica los bloqueos en el firewall del sistema (ipset / nftables / iptables)
   o genera un include dinámico de Nginx (deny <ip>;).
"""

import os
import sys
import time
import subprocess
import requests

MITHRIL_URL = os.getenv("MITHRIL_URL", "http://127.0.0.1:9900")
NODE_API_KEY = os.getenv("NODE_API_KEY", "")
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", "15"))  # Segundos
BLOCK_METHOD = os.getenv("BLOCK_METHOD", "nginx_conf")  # 'ipset' o 'nginx_conf'
NGINX_BLOCK_FILE = os.getenv("NGINX_BLOCK_FILE", "/etc/nginx/conf.d/mithril_blocklist.conf")

if not NODE_API_KEY:
    print("❌ ERROR: Debes definir la variable de entorno NODE_API_KEY con el token de este nodo.")
    sys.exit(1)

headers = {
    "Authorization": f"Bearer {NODE_API_KEY}",
    "Content-Type": "application/json"
}

def init_ipset():
    if BLOCK_METHOD == "ipset":
        try:
            subprocess.run(["ipset", "create", "mithril_blacklist", "hash:ip", "-exist"], check=True)
            print("🛡️ ipset 'mithril_blacklist' listo.")
        except Exception as e:
            print(f"Advertencia iniciando ipset: {e}")

def apply_blocklist(banned_ips):
    if BLOCK_METHOD == "ipset":
        try:
            # Reemplazo atómico de ipset
            subprocess.run(["ipset", "create", "mithril_temp", "hash:ip", "-exist"], check=True)
            for ip in banned_ips:
                subprocess.run(["ipset", "add", "mithril_temp", ip, "-exist"], check=True)
            subprocess.run(["ipset", "swap", "mithril_temp", "mithril_blacklist"], check=True)
            subprocess.run(["ipset", "destroy", "mithril_temp"], check=True)
            print(f"✅ Sincronizadas {len(banned_ips)} IPs en ipset.")
        except Exception as e:
            print(f"Error aplicando ipset: {e}")
    else:
        # Método archivo de configuración de Nginx
        try:
            os.makedirs(os.path.dirname(NGINX_BLOCK_FILE), exist_ok=True)
            with open(NGINX_BLOCK_FILE, "w") as f:
                f.write("# Mithril SIEM - Lista de Bloqueo Dinámica\n")
                for ip in banned_ips:
                    f.write(f"deny {ip};\n")
            # Recarga suave de Nginx sin desconexiones
            subprocess.run(["nginx", "-s", "reload"], check=False)
            print(f"✅ Sincronizadas {len(banned_ips)} IPs en {NGINX_BLOCK_FILE} y Nginx recargado.")
        except Exception as e:
            print(f"Error aplicando archivo Nginx: {e}")

def main():
    print("==========================================")
    print("🛡️ INICIANDO MITHRIL BOUNCER AGENT")
    print(f"Conectando con SIEM: {MITHRIL_URL}")
    print("==========================================")
    init_ipset()

    while True:
        # 1. Enviar Heartbeat
        try:
            hb_resp = requests.post(
                f"{MITHRIL_URL}/nodes/api/heartbeat/",
                headers=headers,
                json={"status": "ok", "rps": 0},
                timeout=5
            )
        except Exception as e:
            print(f"⚠️ Error enviando heartbeat a Mithril: {e}")

        # 2. Sincronizar Bans Aprobados
        try:
            sync_resp = requests.get(
                f"{MITHRIL_URL}/mitigation/api/sync-bans/",
                headers=headers,
                timeout=5
            )
            if sync_resp.status_code == 200:
                data = sync_resp.json()
                banned_ips = data.get("banned_ips", [])
                apply_blocklist(banned_ips)
            else:
                print(f"Respuesta inesperada al sincronizar bans: {sync_resp.status_code}")
        except Exception as e:
            print(f"⚠️ Error consultando lista de bans: {e}")

        time.sleep(SYNC_INTERVAL)

if __name__ == "__main__":
    main()
