#!/usr/bin/env bash
# ====================================================================
# Mithril SIEM - Script de Instalación Automatizado del Agente Bouncer
# Compatible con: Ubuntu, Debian, Rocky Linux, AlmaLinux, RHEL, CentOS
# ====================================================================

set -e

# Colores para la salida
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}   🛡️  MITHRIL SIEM - INSTALADOR DE AGENTE BOUNCER   ${NC}"
echo -e "${CYAN}====================================================${NC}"

# 1. Comprobar permisos de root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Error: Este script debe ejecutarse como root (usa sudo).${NC}"
    exit 1
fi

# 2. Argumentos por flags (--server, --key, --mode, --interval) o posicionales ($1 $2 $3 $4)
MITHRIL_URL=""
NODE_API_KEY=""
BLOCK_METHOD="fail2ban"
SYNC_INTERVAL="15"

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server|-s)
            MITHRIL_URL="$2"
            shift 2
            ;;
        --key|-k)
            NODE_API_KEY="$2"
            shift 2
            ;;
        --mode|-m)
            BLOCK_METHOD="$2"
            shift 2
            ;;
        --interval|-i)
            SYNC_INTERVAL="$2"
            shift 2
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ -z "$MITHRIL_URL" ] && [ ${#POSITIONAL[@]} -ge 1 ]; then
    MITHRIL_URL="${POSITIONAL[0]}"
fi
if [ -z "$NODE_API_KEY" ] && [ ${#POSITIONAL[@]} -ge 2 ]; then
    NODE_API_KEY="${POSITIONAL[1]}"
fi
if [ "$BLOCK_METHOD" = "fail2ban" ] && [ ${#POSITIONAL[@]} -ge 3 ]; then
    BLOCK_METHOD="${POSITIONAL[2]}"
fi
if [ "$SYNC_INTERVAL" = "15" ] && [ ${#POSITIONAL[@]} -ge 4 ]; then
    SYNC_INTERVAL="${POSITIONAL[3]}"
fi

if [ -z "$MITHRIL_URL" ]; then
    echo -e -n "${YELLOW}Ingresa la URL de Mithril SIEM (ej. http://192.168.1.100:9900): ${NC}"
    read -r MITHRIL_URL
fi

if [ -z "$NODE_API_KEY" ]; then
    echo -e -n "${YELLOW}Ingresa el Token de API del Nodo (NODE_API_KEY): ${NC}"
    read -r NODE_API_KEY
fi

if [ -z "$NODE_API_KEY" ]; then
    echo -e "${RED}❌ Error: El Token de API del Nodo es obligatorio.${NC}"
    exit 1
fi

# Limpiar trailing slash de URL
MITHRIL_URL="${MITHRIL_URL%/}"

# 3. Detección de la Distribución Linux
echo -e "\n${CYAN}🔍 [1/6] Detectando sistema operativo...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_LIKE=${ID_LIKE:-$ID}
    echo -e "${GREEN}   Sistema detectado: $NAME ($VERSION_ID)${NC}"
else
    echo -e "${RED}❌ No se pudo determinar la distribución Linux.${NC}"
    exit 1
fi

# 4. Instalación de paquetes necesarios (incluyendo fail2ban e ipset)
echo -e "\n${CYAN}📦 [2/6] Instalando dependencias (Python 3, fail2ban, ipset, iptables, curl)...${NC}"
case "$OS_ID" in
    ubuntu|debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq python3 fail2ban ipset iptables curl
        ;;
    rocky|almalinux|rhel|centos|fedora)
        dnf install -y -q epel-release 2>/dev/null || true
        dnf install -y -q python3 fail2ban ipset iptables iptables-nft curl policycoreutils-python-utils
        if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
            echo -e "${CYAN}   Configurando permisos SELinux para Nginx y Syslog UDP (5140)...${NC}"
            setsebool -P httpd_can_network_connect 1 2>/dev/null || true
            setsebool -P nis_enabled 1 2>/dev/null || true
            semanage port -a -t syslogd_port_t -p udp 5140 2>/dev/null || semanage port -m -t syslogd_port_t -p udp 5140 2>/dev/null || true
        fi
        ;;
    *)
        echo -e "${YELLOW}   Distribución no estándar detectada ($OS_ID). Intentando gestores conocidos...${NC}"
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y -q epel-release 2>/dev/null || true
            dnf install -y -q python3 fail2ban ipset iptables curl
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq && apt-get install -y -qq python3 fail2ban ipset iptables curl
        else
            echo -e "${RED}❌ No se encontró apt-get ni dnf.${NC}"
            exit 1
        fi
        ;;
esac

# 5. Configuración de Fail2ban Smart Hybrid Action (Universal con o sin Cloudflare, sin tocar Nginx)
echo -e "\n${CYAN}🛡️  [3/6] Configurando Fail2ban Smart Hybrid Action (mithril-jail)...${NC}"
mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/action.d /etc/fail2ban/jail.d /etc/mithril
touch /var/log/mithril-fail2ban.log

cat <<'EOF' > /etc/fail2ban/filter.d/mithril-empty.conf
# Mithril SIEM - Filtro base para mithril-jail
[Definition]
failregex = ^MITHRIL_MANUAL_BAN <HOST>$
ignoreregex =
EOF

cat <<'EOF' > /etc/fail2ban/action.d/mithril-smart.conf
# Mithril SIEM - Smart Hybrid Action (Universal: Kernel ipset L3 + Kernel L7 Real-IP Header Match + Cloudflare API opcional)
[Definition]
actionstart = ipset create mithril_f2b hash:ip timeout 0 -exist
              ipset create mithril_f2b6 hash:ip family inet6 timeout 0 -exist 2>/dev/null || true
              iptables -C INPUT -m set --match-set mithril_f2b src -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set mithril_f2b src -j DROP
              ip6tables -C INPUT -m set --match-set mithril_f2b6 src -j DROP 2>/dev/null || ip6tables -I INPUT 1 -m set --match-set mithril_f2b6 src -j DROP 2>/dev/null || true
              iptables -N MITHRIL_REALIP 2>/dev/null || true
              iptables -C INPUT -p tcp -m multiport --dports 80,443,8080,8443 -j MITHRIL_REALIP 2>/dev/null || iptables -I INPUT 2 -p tcp -m multiport --dports 80,443,8080,8443 -j MITHRIL_REALIP 2>/dev/null || true

actionstop  = iptables -D INPUT -m set --match-set mithril_f2b src -j DROP 2>/dev/null || true
              ip6tables -D INPUT -m set --match-set mithril_f2b6 src -j DROP 2>/dev/null || true
              iptables -D INPUT -p tcp -m multiport --dports 80,443,8080,8443 -j MITHRIL_REALIP 2>/dev/null || true
              iptables -F MITHRIL_REALIP 2>/dev/null || true
              iptables -X MITHRIL_REALIP 2>/dev/null || true
              ipset destroy mithril_f2b 2>/dev/null || true
              ipset destroy mithril_f2b6 2>/dev/null || true

actioncheck = ipset list mithril_f2b >/dev/null 2>&1

actionban   = if echo "<ip>" | grep -q ":"; then ipset add mithril_f2b6 <ip> -exist 2>/dev/null || true; else ipset add mithril_f2b <ip> -exist 2>/dev/null || true; fi
              iptables -C MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "CF-Connecting-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || iptables -A MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "CF-Connecting-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || true
              iptables -C MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "X-Real-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || iptables -A MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "X-Real-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || true
              if [ -f /etc/mithril/cloudflare.env ]; then . /etc/mithril/cloudflare.env; if [ -n "$CF_API_TOKEN" ] && [ -n "$CF_ZONE_ID" ]; then curl -fsSL -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/access_rules/rules" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{\"mode\":\"block\",\"configuration\":{\"target\":\"ip\",\"value\":\"<ip>\"},\"notes\":\"Mithril-SIEM-Fail2ban\"}" >/dev/null 2>&1 || true; fi; fi

actionunban = if echo "<ip>" | grep -q ":"; then ipset del mithril_f2b6 <ip> -exist 2>/dev/null || true; else ipset del mithril_f2b <ip> -exist 2>/dev/null || true; fi
              iptables -D MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "CF-Connecting-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || true
              iptables -D MITHRIL_REALIP -p tcp -m string --algo bm --icase --string "X-Real-IP: <ip>" -j REJECT --reject-with tcp-reset 2>/dev/null || true
              if [ -f /etc/mithril/cloudflare.env ]; then . /etc/mithril/cloudflare.env; if [ -n "$CF_API_TOKEN" ] && [ -n "$CF_ZONE_ID" ]; then RULE_ID=$(curl -fsSL -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/access_rules/rules?configuration.target=ip&configuration.value=<ip>" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" 2>/dev/null | grep -o '"id":"[^"]*"' | head -n1 | cut -d'"' -f4); if [ -n "$RULE_ID" ]; then curl -fsSL -X DELETE "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/access_rules/rules/$RULE_ID" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" >/dev/null 2>&1 || true; fi; fi; fi

[Init]
name = mithril
EOF

cat <<'EOF' > /etc/fail2ban/jail.d/mithril.local
# Mithril SIEM - Jail dedicado controlado por Mithril Bouncer
[mithril-jail]
enabled  = true
filter   = mithril-empty
action   = mithril-smart
logpath  = /var/log/mithril-fail2ban.log
bantime  = -1
findtime = 600
maxretry = 1
EOF

if [ ! -f /etc/mithril/cloudflare.env.example ]; then
    cat <<'EOF' > /etc/mithril/cloudflare.env.example
# (Opcional) Si este servidor está detrás de Cloudflare, renombra este archivo a
# /etc/mithril/cloudflare.env y coloca tus credenciales para que Fail2ban bloquee
# también en el borde de Cloudflare además del Kernel Linux:
CF_API_TOKEN="tu_token_cloudflare_firewall_access_rules"
CF_ZONE_ID="tu_zone_id_cloudflare"
EOF
fi

systemctl enable --now fail2ban 2>/dev/null || true
systemctl restart fail2ban 2>/dev/null || fail2ban-client reload 2>/dev/null || true

# 6. Despliegue de los archivos del agente
echo -e "\n${CYAN}📂 [4/6] Instalando archivos del agente en /opt/mithril-agent...${NC}"
mkdir -p /opt/mithril-agent
mkdir -p /etc/nginx/conf.d

# Descargar la última versión de mithril_bouncer.py directamente desde el servidor Mithril SIEM (o repositorio local/GitHub)
echo -e "${CYAN}   Descargando agente mithril_bouncer.py desde $MITHRIL_URL...${NC}"
if curl -fsSL "$MITHRIL_URL/nodes/mithril_bouncer.py" -o /opt/mithril-agent/mithril_bouncer.py 2>/dev/null && grep -q "Mithril" /opt/mithril-agent/mithril_bouncer.py; then
    echo -e "${GREEN}   Agente descargado exitosamente desde el servidor Mithril SIEM.${NC}"
elif [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/mithril_bouncer.py" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cp "$SCRIPT_DIR/mithril_bouncer.py" /opt/mithril-agent/mithril_bouncer.py
    echo -e "${GREEN}   Agente copiado desde el directorio local.${NC}"
else
    echo -e "${YELLOW}   Descargando mithril_bouncer.py desde GitHub...${NC}"
    curl -fsSL "https://raw.githubusercontent.com/gemacron/Mithril-SIEM/main/agent/mithril_bouncer.py" -o /opt/mithril-agent/mithril_bouncer.py
fi

sed -i 's/\r$//' /opt/mithril-agent/mithril_bouncer.py 2>/dev/null || true
chmod +x /opt/mithril-agent/mithril_bouncer.py

# 7. Creación y Configuración del Servicio Systemd
echo -e "\n${CYAN}⚙️  [5/6] Configurando servicio persistente Systemd (mithril-bouncer.service)...${NC}"
cat <<EOF > /etc/systemd/system/mithril-bouncer.service
[Unit]
Description=Mithril SIEM Bouncer Agent
After=network-online.target fail2ban.service nginx.service
Wants=network-online.target

[Service]
Type=simple
User=root
Environment="MITHRIL_URL=$MITHRIL_URL"
Environment="NODE_API_KEY=$NODE_API_KEY"
Environment="BLOCK_METHOD=$BLOCK_METHOD"
Environment="FAIL2BAN_JAIL=mithril-jail"
Environment="SYNC_INTERVAL=$SYNC_INTERVAL"
Environment="NGINX_BLOCK_FILE=/etc/nginx/conf.d/mithril_blocklist.conf"
ExecStart=/usr/bin/python3 /opt/mithril-agent/mithril_bouncer.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 8. Activar e Iniciar el Servicio
echo -e "\n${CYAN}🚀 [6/6] Activando e iniciando el servicio...${NC}"
systemctl daemon-reload
systemctl enable --now mithril-bouncer.service

# Comprobar estado
sleep 2
if systemctl is-active --quiet mithril-bouncer.service; then
    echo -e "${GREEN}✅ ¡Agente Mithril Bouncer + Fail2ban Smart Action instalado y ejecutándose exitosamente!${NC}"
else
    echo -e "${YELLOW}⚠️ El servicio fue creado pero reporta advertencias. Revisa con: journalctl -u mithril-bouncer -e${NC}"
fi

echo -e "\n${CYAN}====================================================${NC}"
echo -e "${GREEN}   CONFIGURACIÓN FINALIZADA CON ÉXITO${NC}"
echo -e "${CYAN}====================================================${NC}"
echo -e "Comandos útiles para administrar el agente y Fail2ban:"
echo -e " • Estado del agente       : ${YELLOW}systemctl status mithril-bouncer${NC}"
echo -e " • Registros en vivo       : ${YELLOW}journalctl -u mithril-bouncer -f${NC}"
echo -e " • Estado Jail Fail2ban    : ${YELLOW}fail2ban-client status mithril-jail${NC}"
echo -e " • Ver IPs bloqueadas (F2B): ${YELLOW}fail2ban-client get mithril-jail banip${NC}"
echo -e " • Ver IPs en Kernel ipset : ${YELLOW}ipset list mithril_f2b${NC}"
echo -e " • (Opcional Cloudflare)   : Edita ${YELLOW}/etc/mithril/cloudflare.env${NC} con CF_API_TOKEN y CF_ZONE_ID"
echo -e " • Nota sobre Nginx        : ${GREEN}No requiere modificar ni recargar ningún archivo de Nginx.${NC}"
