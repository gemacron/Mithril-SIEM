# 🛡️ Mithril Bouncer Agent

Este directorio contiene el agente ligero en Python 3 para los servidores proxy Nginx que se conectan a **Mithril SIEM** (puertos `9900/tcp` y `5140/udp`).

## Instalación en 1 Línea (en el Servidor Proxy)
```bash
curl -fsSL http://<IP_MITHRIL>:9900/nodes/install.sh | sudo bash -s -- --server http://<IP_MITHRIL>:9900 --key "<NODE_API_KEY>" --mode fail2ban
```

## Actualización Rápida del Agente
```bash
sudo curl -fsSL http://<IP_MITHRIL>:9900/nodes/mithril_bouncer.py -o /opt/mithril-agent/mithril_bouncer.py
sudo systemctl restart mithril-bouncer
```

## Archivos

- **`install_agent.sh`**: Instalador automático desatendido compatible con **Rocky Linux / AlmaLinux / RHEL / CentOS** y **Ubuntu / Debian**. Configura Fail2ban (`mithril-jail` + `mithril-smart`) y el servicio `systemd` (`mithril-bouncer.service`).
- **`mithril_bouncer.py`**: Agente con espejo de red 100% en memoria RAM (`AF_PACKET` IPv4/IPv6 + inspección sanitizada de cuerpos `POST`/`PUT`/`PATCH`, cero lectura de disco), envío de telemetría (CPU, RAM, versión de Nginx) y sincronización de bloqueos/desbloqueos con **Fail2ban + Kernel `ipset`** (**cero cambios y cero reloads en Nginx**).

Para la guía completa de verificación y comandos, consulta:
👉 **[Guía Rápida de Conexión de Proxies (`docs/PROXY_SETUP_GUIDE.md`)](../docs/PROXY_SETUP_GUIDE.md)**
