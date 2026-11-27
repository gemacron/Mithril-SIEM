# 🛡️ Mithril SIEM `v2.1.0`

<div align="center">
  <img src="static/img/mithril-logo.jpg" alt="Mithril SIEM" width="160" style="border-radius: 16px; border: 2px solid #00e5ff; box-shadow: 0 0 20px rgba(0,229,255,0.4);" />
  <h3>Plataforma Táctica SIEM de Detección Heurística, Telemetría en Memoria y Mitigación Universal con Fail2ban</h3>
  <p>Entorno Web SOC en Modo Oscuro • Espejo de Red 100% en RAM (Cero I/O en Disco) • Fail2ban Smart Hybrid Action (Sin tocar Nginx) • Mapa 2D Interactivo • Integración Podman</p>

  [![Version](https://img.shields.io/badge/Version-2.1.0-00e5ff)](#)
  [![Fail2ban](https://img.shields.io/badge/Fail2ban-Smart_Hybrid_Action-10b981)](#instalación-y-configuración-de-fail2ban-en-el-agente)
  [![Podman](https://img.shields.io/badge/Podman-Ready-892CA0?logo=podman&logoColor=white)](#despliegue-con-podman)
  [![Linux](https://img.shields.io/badge/Linux-Rocky_%7C_RHEL_%7C_Debian_%7C_Ubuntu-FCC624?logo=linux&logoColor=black)](#conexión-de-servidores-proxy-nginx)
  [![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](#)
  [![Django](https://img.shields.io/badge/Django-5.0-092E20?logo=django&logoColor=white)](#)
  [![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](#)
  [![2FA](https://img.shields.io/badge/2FA-Google_Authenticator-4285F4?logo=google&logoColor=white)](#)
  [![Telegram](https://img.shields.io/badge/Telegram-Alerts-26A5E4?logo=telegram&logoColor=white)](#)
</div>

---

## 📖 Descripción General

**Mithril SIEM** es un sistema de gestión de eventos e información de seguridad (SIEM/SOAR) y detección de intrusiones (WAF/IDS) diseñado específicamente para balanceadores de carga y servidores proxy inversos **Nginx** en entornos críticos de producción.

A diferencia de los analizadores tradicionales basados en lectura de archivos de log en disco (que generan contención de I/O, bloqueos de descriptores en rotaciones o pierden tráfico cuando distintos `VirtualHosts` sobrescriben la directiva `access_log`), **Mithril SIEM** opera con una arquitectura **100% en memoria RAM (Zero-Disk-Read)** que captura la totalidad del tráfico HTTP/HTTPS entrante sin leer ni abrir ningún archivo de `/var/log/nginx/` ni `/etc/nginx/`.

---

## ✨ Características Principales

- **⚡ Espejo de Red 100% en Memoria RAM (`AF_PACKET` Kernel Mirror + Syslog):**
  - **Cero lectura de archivos en disco:** El agente (`agent/mithril_bouncer.py`) no lee ni toca `/var/log/nginx/` ni `/etc/nginx/`, garantizando riesgo cero de I/O en servidores de producción.
  - **Inspección IPv4 + IPv6 de Tráfico Entrante, `proxy_pass` Interno y Cuerpos HTTP:** Captura en RAM todas las peticiones HTTP entrantes y las peticiones desencriptadas por Nginx hacia los *upstreams* internos (`proxy_pass`), extrayendo la IP real del cliente (`CF-Connecting-IP` / `X-Real-IP` / `X-Forwarded-For`), el dominio (`Host`), método HTTP (incluyendo `CONNECT`, `TRACE`, `PROPFIND`, etc.), `URI`, `query_params`, `User-Agent`, `Referer` y un fragmento sanitizado del cuerpo `POST`/`PUT`/`PATCH` (hasta 2 KB, censurando contraseñas/tokens automáticamente).
  - **Emparejamiento de Respuestas y Buffers Anti-Pérdida (4 MB):** Correlaciona en RAM las respuestas HTTP (`HTTP/1.x <status>`) para obtener el código de estado real (`200`, `401`, `403`, `404`, `500`, etc.) y la latencia en milisegundos, utilizando buffers de red ampliados (4 MB) para evitar pérdidas durante ráfagas.
  - **Receptor Syslog Universal Multi-Formato (`mithril_lan_proxy.py`):** Recibe flujos UDP en el puerto `5140` con **autenticación estricta por `NODE_API_KEY`** (rechaza con `403` cualquier nodo no registrado o deshabilitado) y deduplicación inteligente en ventana de 1.5 segundos.
- **🧠 Motor de Detección Agnóstico a la Aplicación (`apps/detection/engine.py`):**
  - **Normalización Profunda de Payloads:** Decodificación automática de doble capa URL (`unquote_plus` para detectar `%27`, `%20`, `%252e%252e%252f`, `%3cscript%3e`) y limpieza de comentarios SQL ofuscados (`/**/`).
  - **Heurística Universal sin Rutas Hardcodeadas:** Evalúa cada petición de forma individual (`is_threat` exacto por petición) y analiza patrones reales de ataque agnósticos a cualquier aplicación web (`401`/`403` Auth Brute Force, `404` en **rutas base distintas** para enumeración de directorios, y `DoS` HTTP Flood en Capa 7).
  - **Gestor Visual de Reglas en la Web UI (`/detection/rules/`):** Creación, edición, activación/desactivación y eliminación de reglas Regex y heurísticas en caliente desde el navegador.
- **🎮 Centro de Operaciones de Seguridad (SOC) y Mapas Tácticos 2D:**
  - Feed en vivo persistente sincronizado con PostgreSQL (`TrafficLog` + `SecurityEvent`) y cálculo de **RPS en tiempo real** por nodo.
  - Visualización interactiva en Canvas 2D (Mapa Mundial + Mapa Táctico con zoom hasta `120x`) con geolocalización offline automática (`GeoLite2-City.mmdb`) y vectores de ataque clicables.
- **🔍 Explorador Forense de Tráfico HTTP (`/reports/`):**
  - Búsqueda histórica sobre el 100% de las peticiones HTTP/HTTPS registradas (`TrafficLog`) filtrando por IP de origen, URI/Host o código de respuesta HTTP, más auditoría de incidentes y exportación directa a **CSV** (`?type=traffic` y `?type=events`).
- **🛡️ Mitigación Universal con Fail2ban Smart Hybrid Action (`fail2ban`), Kernel (`ipset`) o Modo Monitor (`monitor`):**
  - **Fail2ban Smart Hybrid Action (`--mode fail2ban`, por defecto):** Cuando el operador aprueba un bloqueo en Mithril, el agente delega el bloqueo a Fail2ban (`fail2ban-client set mithril-jail banip <IP>`). La acción híbrida `mithril-smart` bloquea automáticamente en el Kernel de Linux (`ipset`/`iptables`) para servidores sin Cloudflare o ataques directos a la IP pública, y si detecta credenciales en `/etc/mithril/cloudflare.env`, bloquea simultáneamente la IP real del atacante en el borde de Cloudflare. **Nunca modifica ni recarga archivos de Nginx.**
  - **Inmunidad Absoluta de Nodos Cloudflare y Detección de Evasión Directa (`🎯 DIRECTO A IP`):** Distingue el tráfico proxificado (`☁️ CF Edge`) del tráfico que golpea directamente la IP pública del servidor saltándose Cloudflare (`R-DIRECT-IP-ACCESS`), y garantiza que ningún rango de Cloudflare pueda ser bloqueado jamás.
  - **Modo Monitor Pasivo (`--mode monitor`):** Monitoreo 100% pasivo que registra todo el tráfico y alertas sin ejecutar ningún comando sobre el firewall del servidor.
  - **Autoban Human-in-the-Loop:** Cola de decisión para que el operador apruebe o descarte bloqueos sugeridos en un clic.
- **🔐 Seguridad Blindada y Alertas en Tiempo Real:**
  - Cambio obligatorio de contraseña en el primer inicio de sesión y **2FA TOTP** compatible con Google Authenticator / Authy.
  - Alertas instantáneas enriquecidas vía **Telegram**.

---

## 🏛️ Arquitectura del Sistema

```
┌────────────────────────────────────────────────────────────────────────┐
│              SERVIDORES PROXY / BALANCEADORES NGINX                    │
│  - Espejo de Red en RAM (Kernel AF_PACKET: HTTP + proxy_pass + TLS SNI)│
│  - Emisión nativa por red (syslog:server=IP:5140)                      │
│  * Cero lectura ni modificación de /var/log/nginx/ o /etc/nginx/       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Streaming UDP 5140 / HTTP API 9900)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│           RECEPTOR UNIVERSAL & MOTOR DE DETECCIÓN MITHRIL              │
│  - Parser Multi-Formato + Deduplicación en ventana móvil (1.5s)        │
│  - Normalización Anti-Evasión (Doble URL-Decode + Strip /**/)          │
│  - Evaluación de 11 Reglas Universales + Detección Directo a IP        │
│  - Inmunidad garantizada para todos los rangos CIDR de Cloudflare      │
└──────────────────┬──────────────────────────────────┬──────────────────┘
                   │                                  │
    (Persistencia TrafficLog & Event)       (Streaming WebSocket / UI)
                   ▼                                  ▼
┌──────────────────────────────────┐ ┌───────────────────────────────────┐
│       POSTGRESQL 16 & REDIS      │ │        MITHRIL CORE (WEB UI)      │
│  - Tráfico Forense + Incidentes  │ │  - Dashboard SOC & Mapa 2D        │
│  - Cálculo de RPS en Tiempo Real │ │  - Editor Visual de Reglas        │
└──────────────────────────────────┘ │  - Explorador Forense & Cola SOAR │
                                     └─────────────────┬─────────────────┘
                                                       │ Orden de Bloqueo (Clic Operador)
                                                       ▼
                                     ┌───────────────────────────────────┐
                                     │   MITHRIL BOUNCER + FAIL2BAN      │
                                     │  fail2ban-client set mithril-jail │
                                     │  ├─ Capa 1: Kernel ipset/iptables │
                                     │  └─ Capa 2: Cloudflare API (Opt.) │
                                     │  * Cero recargas en Nginx         │
                                     └───────────────────────────────────┘
```

---

## 🧠 Reglas de Detección y Heurística Preconfiguradas

Al iniciar el contenedor `mithril-web`, el sistema configura automáticamente 13 reglas universales que pueden personalizarse o ampliarse desde **`http://<IP_MITHRIL>:9900/detection/rules/`**:

| Código | Nombre de la Regla / Heurística | Severidad | Umbral por Defecto | Acción |
| :--- | :--- | :---: | :---: | :---: |
| `R-ENV-SCAN` | Escaneo de Archivos Sensibles (`.env`, `.git`, `.aws`, `wp-config`, `.sql`, `.bak`) | `CRITICAL` | 1 hit / 60s | Candidato Bloqueo |
| `R-DANGEROUS-EXT-PROBE` | Sondeo de Extensiones Peligrosas / Webshells (`.php`, `.aspx`, `.jsp`, `.cgi`, `.zip` con `403`/`404` o sin UA) | `CRITICAL` | 1 hit / 60s | Candidato Bloqueo |
| `R-SQLI-URL` | Inyección SQL Universal (`UNION SELECT`, `SLEEP()`, `BENCHMARK()`, `OR 1=1`) | `CRITICAL` | 1 hit / 60s | Candidato Bloqueo |
| `R-PATH-TRAVERSAL` | Escalada de Directorios / LFI (`../`, `/etc/passwd`, `proc/self`, `win.ini`) | `CRITICAL` | 1 hit / 60s | Candidato Bloqueo |
| `R-XSS-PAYLOAD` | Cross-Site Scripting (`<script>`, `javascript:`, `onerror=`, `onload=`, `<svg>`) | `CRITICAL` | 1 hit / 60s | Candidato Bloqueo |
| `R-RCE-CMD` | Ejecución Remota de Comandos / Log4Shell / Shellshock (`${jndi:...}`, `wget`, `bash`) | `CRITICAL` | 1 hit / 60s | Candidato Bloqueo |
| `R-SSRF-METADATA` | Server-Side Request Forgery (`169.254.169.254`, `metadata.google.internal`, `file://`) | `CRITICAL` | 1 hit / 60s | Candidato Bloqueo |
| `R-XXE-SSTI` | Inyección de Plantillas (SSTI) / Entidades XML Externas (`<!ENTITY`, `{{7*7}}`, `__class__`) | `CRITICAL` | 1 hit / 60s | Candidato Bloqueo |
| `R-BAD-USER-AGENT` | Escáneres de Vulnerabilidades (`sqlmap`, `nikto`, `nuclei`, `nmap`, `gobuster`, `ffuf`) | `CRITICAL` | 1 hit / 60s | Candidato Bloqueo |
| `R-SCAN-404-BRUTE` | Heurística de Enumeración de Directorios (`404 Not Found` en rutas distintas) | `HIGH` | 40 rutas distintas / 60s | Candidato Bloqueo |
| `R-AUTH-BRUTE-401` | Heurística de Fuerza Bruta de Autenticación (`401`/`403` repetidos en logins/tokens) | `HIGH` | 15 hits / 60s | Candidato Bloqueo |
| `R-HTTP-FLOOD-DOS` | Heurística de Inundación HTTP / Denegación de Servicio (DoS Capa 7) | `CRITICAL` | 300 reqs / 60s | Candidato Bloqueo |
| `R-DIRECT-IP-ACCESS` | Acceso Directo a IP Pública (Host IP cruda o vacío evadiendo Cloudflare/DNS) | `HIGH` | 1 hit / 60s | Candidato Bloqueo |

---

## 🚀 Despliegue Rápido en Servidor Linux (Podman)

Mithril está preparado para desplegarse en segundos sobre **Rocky Linux, AlmaLinux, RHEL, CentOS, Ubuntu o Debian** utilizando **Podman Compose**.

### Opción 1: Despliegue Automático en 1 Comando (Recomendado)
Clona el repositorio y ejecuta el instalador automático `install_siem.sh` (instala `podman-compose`, configura `.env`, abre los puertos `9900/tcp` y `5140/udp` en el firewall y levanta todos los contenedores):

```bash
git clone https://github.com/gemacron/Mithril-SIEM.git
cd Mithril-SIEM
bash install_siem.sh
```

---

### Opción 2: Despliegue Manual Paso a Paso

#### 1. Instalar Podman y `podman-compose`
```bash
# En Rocky Linux / AlmaLinux / RHEL / CentOS:
sudo dnf install -y epel-release
sudo dnf install -y podman podman-compose git

# En Ubuntu / Debian:
sudo apt-get update && sudo apt-get install -y podman podman-compose git
```

#### 2. Clonar y Levantar el Proyecto
```bash
git clone https://github.com/gemacron/Mithril-SIEM.git
cd Mithril-SIEM
cp -n .env.example .env
chmod +x entrypoint.sh
podman-compose up -d --build
```

#### 3. Abrir Puertos en el Firewall del Servidor SIEM
```bash
# En Rocky Linux / RHEL (firewalld):
sudo firewall-cmd --add-port=9900/tcp --add-port=5140/udp --permanent
sudo firewall-cmd --reload

# En Ubuntu / Debian (UFW):
sudo ufw allow 9900/tcp && sudo ufw allow 5140/udp
```

El sistema levanta automáticamente los 5 contenedores (incluyendo el receptor Syslog UDP `5140` integrado dentro de `mithril-web`):
- **`mithril-db`**: PostgreSQL 16 con volumen persistente (`5432/tcp`).
- **`mithril-redis`**: Redis 7 en memoria (`6379/tcp`).
- **`mithril-web`**: Panel Web SOC + API REST (`9900/tcp`) + Receptor Syslog Universal (`5140/udp`).
- **`mithril-worker`**: Celery Worker para procesamiento asíncrono de telemetría y heurísticas.
- **`mithril-beat`**: Celery Beat para tareas programadas y expiración de bloqueos.

> *(Nota para entornos Windows / WSL2 de desarrollo: ejecuta `python mithril_lan_proxy.py` en el host Windows para puentear la interfaz LAN hacia la máquina virtual de Podman).*

---

## 🔑 Primer Inicio de Sesión (Setup Inicial)

1. Ingresa a la interfaz web en tu navegador:
   ```text
   http://IP_DEL_SERVIDOR_MITHRIL:9900
   ```
2. Utiliza las credenciales iniciales definidas en `.env` (por defecto `admin` / `MithrilSecurity2026!`).
3. El sistema te guiará por el **Asistente de Seguridad Inicial**:
   - Configuración de nueva contraseña robusta.
   - Enrolamiento **2FA TOTP** mediante código QR compatible con **Google Authenticator** / Authy.
   - Generación de **5 códigos de emergencia de respaldo**.

---

## 📡 Conexión de Servidores Proxy Nginx (1 Comando - Cero Cambios en Nginx)

### Paso 1: Dar de alta el nodo en Mithril
1. En el menú superior de Mithril, ve a **Nodos Proxy (`/nodes/`)** y haz clic en **+ Alta Proxy**.
2. Asigna un nombre identificativo (ej: `Proxy-Principal`) y la dirección IP de tu servidor proxy (ej: `<IP_DEL_PROXY>`).
3. Al guardarlo, Mithril te mostrará en pantalla el **Comando de Instalación de 1 Línea** con tu `NODE_API_KEY` ya incluido.

### Paso 2: Ejecutar el Instalador de 1 Línea en el Servidor Proxy
Copia y pega el comando en la terminal de tu servidor proxy Nginx:

#### Opción A — Modo Activo Universal con Fail2ban (Recomendado - Sin tocar Nginx)
```bash
curl -fsSL http://IP_DE_MITHRIL:9900/nodes/install.sh | sudo bash -s -- --server http://IP_DE_MITHRIL:9900 --key "TU_API_KEY" --mode fail2ban
```

#### Opción B — Modo Monitor Pasivo (Solo Observación - Cero Bloqueos)
```bash
curl -fsSL http://IP_DE_MITHRIL:9900/nodes/install.sh | sudo bash -s -- --server http://IP_DE_MITHRIL:9900 --key "TU_API_KEY" --mode monitor
```

> **¿Qué hace este comando automáticamente en segundos?**
> 1. Instala `fail2ban`, `ipset` e `iptables` según tu distribución Linux.
> 2. Configura `mithril-jail` y la acción `mithril-smart` (`Smart Hybrid Action v2`) en Fail2ban.
> 3. Descarga `/opt/mithril-agent/mithril_bouncer.py` y activa el servicio `mithril-bouncer.service`.
> 4. **No modifica ni recarga ningún archivo de Nginx.**

---

## 🔍 Comandos de Verificación Rápida en el Servidor Proxy

Una vez instalado el agente en tu servidor proxy, puedes verificar su funcionamiento con:

```bash
# 1. Ver el log en vivo del agente Mithril Bouncer:
sudo journalctl -u mithril-bouncer -n 20 -f

# 2. Ver las IPs bloqueadas actualmente en Fail2ban:
sudo fail2ban-client status mithril-jail

# 3. Ver las IPs cargadas en la tabla ipset del Kernel:
sudo ipset list mithril_f2b

# 4. Ver el contador de paquetes/intentos bloqueados en tiempo real:
sudo iptables -L INPUT -n -v | grep mithril_f2b
sudo iptables -L MITHRIL_REALIP -n -v
```

### Actualizar el Agente o Cambiar la IP del Servidor Mithril
Para actualizar el agente en un proxy ya instalado (sin tocar Nginx):
```bash
sudo curl -fsSL "http://<IP_MITHRIL>:9900/nodes/mithril_bouncer.py" -o /opt/mithril-agent/mithril_bouncer.py
sudo systemctl restart mithril-bouncer
```

Si mudas Mithril SIEM a una nueva IP (`<NUEVA_IP_MITHRIL>`), ejecuta en tu servidor proxy:
```bash
sudo sed -i 's|^Environment="MITHRIL_URL=.*|Environment="MITHRIL_URL=http://<NUEVA_IP_MITHRIL>:9900"|' /etc/systemd/system/mithril-bouncer.service
sudo curl -fsSL "http://<NUEVA_IP_MITHRIL>:9900/nodes/mithril_bouncer.py" -o /opt/mithril-agent/mithril_bouncer.py
sudo systemctl daemon-reload && sudo systemctl restart mithril-bouncer
```

---

## ✈️ Configuración de Alertas por Telegram

1. Crea un bot en Telegram con **@BotFather** y obtén tu `API Token`.
2. Obtén el `Chat ID` de tu usuario o canal del SOC.
3. En la interfaz web de Mithril, dirígete a **Telegram** en el menú lateral.
4. Ingresa las credenciales, activa los tipos de alertas deseadas y pulsa **Enviar Alerta de Prueba**.

---

## 📂 Estructura del Proyecto

```text
Mithril/
├── agent/
│   ├── mithril_bouncer.py     # Agente con espejo de red en RAM (AF_PACKET) + ipset/monitor
│   └── install_agent.sh       # Instalador universal (Debian/Ubuntu & Rocky/RHEL/SELinux)
├── apps/
│   ├── analytics/             # Dashboard en vivo, métricas y sincronización con PostgreSQL
│   ├── core/                  # Inicialización del sistema y comando init_mithril_system
│   ├── detection/             # Motor de detección Regex + Heurísticas y CRUD visual de reglas
│   ├── mitigation/            # Gestión de IPs bloqueadas (BlockedIP) y listas blancas
│   ├── nodes/                 # Gestión de nodos agentes, heartbeats y cálculo de RPS real
│   ├── notifications/         # Integración de alertas en tiempo real con Telegram
│   └── reports/               # Explorador forense de tráfico HTTP y exportación CSV/JSON
├── templates/                 # Interfaz web táctica (Dashboard, Reglas, Nodos, Reportes)
├── mithril_lan_proxy.py       # Proxy TCP (9900) y Receptor Syslog Universal UDP (5140)
├── docker-compose.yml         # Orquestación de contenedores (Podman / Docker)
└── Containerfile              # Definición de imagen de producción de Mithril SIEM
```

---

## 📜 Licencia

Desarrollado bajo licencia MIT. Software libre para uso, auditoría y distribución.
