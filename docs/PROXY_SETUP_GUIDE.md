# 🛡️ Guía Rápida de Conexión de Proxies Nginx a Mithril SIEM

Esta guía explica cómo conectar cualquier servidor proxy inverso **Nginx** (**Rocky Linux, AlmaLinux, RHEL, CentOS, Ubuntu o Debian**) a **Mithril SIEM** en menos de 1 minuto y **sin tocar ni recargar Nginx**.

---

## 🏛️ Flujo de Comunicación (100% en RAM + Fail2ban)

```
┌────────────────────────────────────────────────────────┐
│                   Mithril SIEM Core                    │
│  • Panel Web & API : http://<IP_MITHRIL>:9900          │
│  • Syslog Ingestion: udp://<IP_MITHRIL>:5140           │
└───────────────────────────▲────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
  [Heartbeat + Sincronización]      [Espejo de Red en RAM]
  Puerto 9900 (HTTP/REST)           Puerto 5140 (UDP)
              │                           │
┌─────────────┴───────────────────────────┴──────────────┐
│        Servidor Proxy (Rocky Linux / Ubuntu)           │
│                                                        │
│  1. mithril-bouncer.service (Servicio systemd)         │
│     • Captura HTTP IPv4/IPv6 + body POST/PUT en RAM    │
│     • Envía telemetría (CPU, RAM, Nginx versión)       │
│     • Autenticado estrictamente con NODE_API_KEY       │
│     • Sincroniza bloqueos aprobados con Fail2ban       │
│                                                        │
│  2. Fail2ban + Kernel ipset (mithril-jail)             │
│     • Bloquea IPs en Kernel (mithril_f2b / iptables)   │
│     • Cero cambios y cero reloads en Nginx             │
└────────────────────────────────────────────────────────┘
```

---

## Paso 1: Dar de Alta el Servidor Proxy en Mithril SIEM

1. Ingresa al panel web de Mithril SIEM: `http://<IP_MITHRIL>:9900`.
2. Ve a **Nodos Proxy** (`/nodes/`) y haz clic en **`+ Alta Proxy`** (`/nodes/create/`).
3. Completa los datos básicos:
   - **Nombre:** Ej. `Proxy-Principal` o `proxy-edge-01`.
   - **Dirección IP:** IP de tu servidor proxy (ej. `<IP_DEL_PROXY>`).
   - **Método de Mitigación:** `Fail2ban + Smart Action (Recomendado - Universal sin tocar Nginx)`.
4. Al guardar, Mithril te mostrará en pantalla el **Comando de Instalación Automática en 1 Línea** con tu `NODE_API_KEY`.

---

## Paso 2: Instalar el Agente en 1 Solo Comando

En la terminal de tu servidor proxy Nginx, ejecuta el comando que te entregó Mithril:

```bash
curl -fsSL http://<IP_MITHRIL>:9900/nodes/install.sh | sudo bash -s -- --server http://<IP_MITHRIL>:9900 --key "<TU_NODE_API_KEY>" --mode fail2ban
```

### ¿Qué realiza este comando automáticamente?
1. Detecta tu distribución Linux (`dnf` o `apt-get`) e instala `python3`, `fail2ban`, `ipset`, `iptables` y `curl`.
2. Configura permisos SELinux en Rocky Linux / RHEL si aplica.
3. Crea y activa el jail `mithril-jail` con la acción `mithril-smart` (`Smart Hybrid Action v2`) en Fail2ban.
4. Descarga `/opt/mithril-agent/mithril_bouncer.py` desde tu servidor Mithril SIEM.
5. Crea e inicia el servicio persistente `mithril-bouncer.service` en `systemd`.
6. **No modifica ni recarga Nginx en ningún momento.**

---

## Paso 3: Verificación y Comandos Útiles en el Servidor Proxy

### 1. Ver el log en tiempo real del agente
```bash
sudo journalctl -u mithril-bouncer -n 20 -f
```
Salida esperada:
```text
🛡️  MITHRIL BOUNCER AGENT v2.1 - INICIADO
   SIEM Destino   : http://<IP_MITHRIL>:9900
   Metodo Bloqueo : fail2ban (Jail: mithril-jail)
   Intervalo Sync : 15 segundos
🛡️ [FAIL2BAN] Jail 'mithril-jail' (Smart Hybrid Action v2) activo y listo.
✅ [FAIL2BAN] Sincronización activa: 0 IPs bloqueadas en 'mithril-jail' e ipset (Cero cambios en Nginx).
```

### 2. Ver qué IPs están bloqueadas en Fail2ban y en el Kernel (`ipset`)
```bash
# Estado del jail en Fail2ban:
sudo fail2ban-client status mithril-jail

# Lista de IPs cargadas en el conjunto del Kernel (IPv4 / IPv6):
sudo ipset list mithril_f2b
sudo ipset list mithril_f2b6
```

### 3. Ver cuántos intentos/paquetes ha bloqueado el Firewall (`pkts`)
```bash
sudo iptables -L INPUT -n -v | grep mithril_f2b
sudo iptables -L MITHRIL_REALIP -n -v
```

### 4. Actualizar el Agente en un Proxy ya Instalado (sin tocar Nginx)
```bash
sudo curl -fsSL "http://<IP_MITHRIL>:9900/nodes/mithril_bouncer.py" -o /opt/mithril-agent/mithril_bouncer.py
sudo systemctl restart mithril-bouncer
```

### 5. Cambiar la IP del Servidor Mithril (si mudas el SIEM de servidor)
```bash
sudo sed -i 's|^Environment="MITHRIL_URL=.*|Environment="MITHRIL_URL=http://<NUEVA_IP_MITHRIL>:9900"|' /etc/systemd/system/mithril-bouncer.service
sudo curl -fsSL "http://<NUEVA_IP_MITHRIL>:9900/nodes/mithril_bouncer.py" -o /opt/mithril-agent/mithril_bouncer.py
sudo systemctl daemon-reload && sudo systemctl restart mithril-bouncer
```
