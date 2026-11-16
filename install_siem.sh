#!/usr/bin/env bash
# ====================================================================
# Mithril SIEM - Instalador Rápido del Servidor Central (Podman)
# Compatible con: Rocky Linux, AlmaLinux, RHEL, CentOS, Ubuntu, Debian
# ====================================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}   🛡️  MITHRIL SIEM - DESPLIEGUE AUTOMÁTICO         ${NC}"
echo -e "${CYAN}====================================================${NC}"

# 1. Instalar podman y podman-compose si no existen
if ! command -v podman >/dev/null 2>&1 || ! command -v podman-compose >/dev/null 2>&1; then
    echo -e "\n${CYAN}📦 [1/4] Instalando Podman y podman-compose...${NC}"
    if command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y epel-release 2>/dev/null || true
        sudo dnf install -y podman podman-compose
    elif command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq
        sudo apt-get install -y podman podman-compose
    fi
else
    echo -e "\n${GREEN}✅ [1/4] Podman y podman-compose ya están instalados.${NC}"
fi

# 2. Preparar archivo .env y permisos de ejecución
echo -e "\n${CYAN}⚙️  [2/4] Preparando configuración (.env) y permisos...${NC}"
if [ ! -f .env ]; then
    cp .env.example .env
fi
sed -i 's/\r$//' entrypoint.sh 2>/dev/null || true
chmod +x entrypoint.sh

# 3. Abrir puertos 9900/tcp (Panel/API) y 5140/udp (Syslog) en el Firewall
echo -e "\n${CYAN}🔥 [3/4] Abriendo puertos 9900/tcp y 5140/udp en el firewall...${NC}"
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    sudo firewall-cmd --add-port=9900/tcp --add-port=5140/udp --permanent >/dev/null 2>&1 || true
    sudo firewall-cmd --reload >/dev/null 2>&1 || true
    echo -e "${GREEN}   Puertos habilitados en firewalld.${NC}"
elif command -v ufw >/dev/null 2>&1; then
    sudo ufw allow 9900/tcp >/dev/null 2>&1 || true
    sudo ufw allow 5140/udp >/dev/null 2>&1 || true
    echo -e "${GREEN}   Puertos habilitados en UFW.${NC}"
fi

# 4. Construir y levantar los contenedores
echo -e "\n${CYAN}🚀 [4/4] Construyendo y levantando contenedores Mithril SIEM...${NC}"
podman-compose up -d --build

HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
HOST_IP=${HOST_IP:-localhost}

echo -e "\n${GREEN}====================================================${NC}"
echo -e "${GREEN}✅ ¡MITHRIL SIEM DESPLEGADO Y ACTIVO!${NC}"
echo -e "   🌐 Panel Web : http://${HOST_IP}:9900"
echo -e "   👤 Usuario   : admin"
echo -e "   🔑 Clave     : MithrilSecurity2026!"
echo -e "${GREEN}====================================================${NC}"
