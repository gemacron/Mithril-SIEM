# 🛡️ Mithril Bouncer Agent

Este directorio contiene el agente para los servidores proxy Nginx que interactúan con **Mithril SIEM** en el puerto 9900.

## Archivos

- **`install_agent.sh`**: Script de instalación desatendida y automática compatible con **Ubuntu/Debian** y **Rocky Linux/RHEL**. Configura el servicio persistente `systemd` (`mithril-bouncer.service`).
- **`mithril_bouncer.py`**: Script del agente en Python 3 nativo. Envía métricas (CPU, RAM, Nginx) y sincroniza la lista de bloqueo (`ipset` o `nginx_conf`).
- **`nginx_syslog_sample.conf`**: Configuración de ejemplo para Nginx con formato JSON y streaming de Syslog por UDP.

Para la guía de instalación detallada paso a paso, consulta:
👉 **[Guía de Conexión de Proxies (docs/PROXY_SETUP_GUIDE.md)](../docs/PROXY_SETUP_GUIDE.md)**
