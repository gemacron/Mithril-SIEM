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

# 2. Argumentos opcionales o interactivos
MITHRIL_URL="${1:-}"
NODE_API_KEY="${2:-}"
BLOCK_METHOD="${3:-ipset}"
SYNC_INTERVAL="${4:-15}"

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
echo -e "\n${CYAN}🔍 [1/5] Detectando sistema operativo...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_LIKE=${ID_LIKE:-$ID}
    echo -e "${GREEN}   Sistema detectado: $NAME ($VERSION_ID)${NC}"
else
    echo -e "${RED}❌ No se pudo determinar la distribución Linux.${NC}"
    exit 1
fi

# 4. Instalación de paquetes necesarios
echo -e "\n${CYAN}📦 [2/5] Instalando dependencias (Python 3, ipset, iptables, curl)...${NC}"
case "$OS_ID" in
    ubuntu|debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq python3 ipset iptables curl
        ;;
    rocky|almalinux|rhel|centos|fedora)
        dnf install -y -q python3 ipset iptables iptables-nft curl policycoreutils-python-utils
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
            dnf install -y -q python3 ipset iptables curl
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq && apt-get install -y -qq python3 ipset iptables curl
        else
            echo -e "${RED}❌ No se encontró apt-get ni dnf.${NC}"
            exit 1
        fi
        ;;
esac

# 5. Despliegue de los archivos del agente
echo -e "\n${CYAN}📂 [3/5] Instalando archivos del agente en /opt/mithril-agent...${NC}"
mkdir -p /opt/mithril-agent
mkdir -p /etc/nginx/conf.d

# Si el script se ejecuta dentro del repositorio clonado, copiar directamente
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/mithril_bouncer.py" ]; then
    cp "$SCRIPT_DIR/mithril_bouncer.py" /opt/mithril-agent/mithril_bouncer.py
else
    echo -e "${YELLOW}   Descargando mithril_bouncer.py desde el repositorio...${NC}"
    curl -sSL "https://raw.githubusercontent.com/gemacron/Mithril-SIEM/main/agent/mithril_bouncer.py" -o /opt/mithril-agent/mithril_bouncer.py
fi

chmod +x /opt/mithril-agent/mithril_bouncer.py

# Crear archivo inicial de lista negra de Nginx vacío para evitar errores de sintaxis
if [ ! -f /etc/nginx/conf.d/mithril_blocklist.conf ]; then
    echo "# Mithril SIEM - Bloqueo Dinámico Inicial" > /etc/nginx/conf.d/mithril_blocklist.conf
fi

# 6. Creación y Configuración del Servicio Systemd
echo -e "\n${CYAN}⚙️  [4/5] Configurando servicio persistente Systemd (mithril-bouncer.service)...${NC}"
cat <<EOF > /etc/systemd/system/mithril-bouncer.service
[Unit]
Description=Mithril SIEM Bouncer Agent
After=network.target nginx.service

[Service]
Type=simple
User=root
Environment="MITHRIL_URL=$MITHRIL_URL"
Environment="NODE_API_KEY=$NODE_API_KEY"
Environment="BLOCK_METHOD=$BLOCK_METHOD"
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

# 7. Activar e Iniciar el Servicio
echo -e "\n${CYAN}🚀 [5/5] Activando e iniciando el servicio...${NC}"
systemctl daemon-reload
systemctl enable --now mithril-bouncer.service

# Comprobar estado
sleep 2
if systemctl is-active --quiet mithril-bouncer.service; then
    echo -e "${GREEN}✅ ¡Agente Mithril Bouncer instalado y ejecutándose exitosamente!${NC}"
else
    echo -e "${YELLOW}⚠️ El servicio fue creado pero reporta advertencias. Revisa con: journalctl -u mithril-bouncer -e${NC}"
fi

echo -e "\n${CYAN}====================================================${NC}"
echo -e "${GREEN}   CONFIGURACIÓN FINALIZADA CON ÉXITO${NC}"
echo -e "${CYAN}====================================================${NC}"
echo -e "Comandos útiles para administrar el agente:"
echo -e " • Ver estado del servicio : ${YELLOW}systemctl status mithril-bouncer${NC}"
echo -e " • Ver registros en vivo   : ${YELLOW}journalctl -u mithril-bouncer -f${NC}"
echo -e " • Reiniciar agente        : ${YELLOW}systemctl restart mithril-bouncer${NC}"
echo -e " • Ver IPs bloqueadas      : ${YELLOW}ipset list mithril_blacklist${NC}  (o cat /etc/nginx/conf.d/mithril_blocklist.conf)"
echo -e ""
echo -e "Siguiente paso en Nginx: Añade 'include /etc/nginx/conf.d/mithril_blocklist.conf;' en tu bloque server { ... }"
