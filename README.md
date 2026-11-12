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
  - **Inspección de Tráfico Entrante y `proxy_pass` Interno:** Captura en RAM todas las peticiones HTTP entrantes y las peticiones desencriptadas por Nginx hacia los *upstreams* internos (`proxy_pass`), extrayendo la IP real del cliente (`X-Real-IP` / `X-Forwarded-For`), el dominio (`Host`), método HTTP, `URI`, `query_params`, `User-Agent` y `Referer`.
  - **Emparejamiento de Respuestas y TLS SNI:** Correlaciona en RAM las respuestas HTTP (`HTTP/1.x <status>`) para obtener el código de estado real (`200`, `401`, `403`, `404`, `500`, etc.) y la latencia en milisegundos, además de extraer el **SNI (`Server Name Indication`)** del handshake TLS `ClientHello` en conexiones HTTPS (`443`).
  - **Receptor Syslog Universal Multi-Formato (`mithril_lan_proxy.py`):** Recibe flujos UDP en el puerto `5140` compatibles con cualquier formato de log (`mithril_json`, `json_analytics`, `otel_json`, `combined`/`main` estándar y `error_log` en texto plano) con **deduplicación inteligente en ventana de 1.5 segundos**.
- **🧠 Motor de Detección y Heurística Anti-Evasión (`apps/detection/engine.py`):**
  - **Normalización Profunda de Payloads:** Decodificación automática de doble capa URL (`unquote_plus` para detectar `%27`, `%20`, `%252e%252e%252f`, `%3cscript%3e`) y limpieza de comentarios SQL ofuscados (`/**/`).
  - **Heurística Genérica por Umbral y Ventana de Tiempo:** Evalúa frecuencia de impactos (`threshold_count`) dentro de ventanas móviles (`threshold_seconds`) tanto para expresiones regulares como para anomalías de estado HTTP (`401`/`403` Auth Brute Force, `404` Directory Scanning y `DoS` HTTP Flood en Capa 7).
  - **Gestor Visual de Reglas en la Web UI (`/detection/rules/`):** Creación, edición, activación/desactivación y eliminación de reglas Regex y heurísticas en caliente desde el navegador.
- **🎮 Centro de Operaciones de Seguridad (SOC) y Mapa Táctico 2D:**
  - Feed en vivo persistente sincronizado con PostgreSQL (`TrafficLog` + `SecurityEvent`) y cálculo de **RPS en tiempo real** por nodo.
  - Visualización mundial interactiva en Canvas 2D con geolocalización de tráfico y vectores de ataque.
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

Al iniciar el contenedor `mithril-web`, el sistema configura automáticamente 11 reglas universales que pueden personalizarse o ampliarse desde **`http://localhost:9900/detection/rules/`**:

| Código | Nombre de la Regla / Heurística | Severidad | Umbral por Defecto | Acción |
| :--- | :--- | :---: | :---: | :---: |
| `R-ENV-SCAN` | Escaneo de Archivos Sensibles (`.env`, `.git`, `.aws`, `wp-config`, `.sql`, `.bak`) | `CRITICAL` | 1 hit / 60s | Bloqueo IP |
| `R-SQLI-URL` | Inyección SQL Universal (`UNION SELECT`, `SLEEP()`, `BENCHMARK()`, `OR 1=1`) | `CRITICAL` | 1 hit / 60s | Bloqueo IP |
| `R-PATH-TRAVERSAL` | Escalada de Directorios / LFI (`../`, `/etc/passwd`, `php://`, `proc/self`) | `HIGH` | 1 hit / 60s | Bloqueo IP |
| `R-XSS-PAYLOAD` | Cross-Site Scripting (`<script>`, `javascript:`, `onerror=`, `onload=`, `<svg>`) | `MEDIUM` | 1 hit / 60s | Alerta |
| `R-RCE-CMD` | Ejecución Remota de Comandos / Log4Shell (`${jndi:...}`, `cmd=`, `/bin/sh`, `wget`) | `CRITICAL` | 1 hit / 60s | Bloqueo IP |
| `R-SSRF-METADATA` | Server-Side Request Forgery (`169.254.169.254`, `metadata.google.internal`, `127.0.0.1`) | `CRITICAL` | 1 hit / 60s | Bloqueo IP |
| `R-BAD-USER-AGENT` | Escáneres de Vulnerabilidades (`sqlmap`, `nikto`, `nuclei`, `nmap`, `gobuster`, `ffuf`) | `HIGH` | 1 hit / 60s | Bloqueo IP |
| `R-SCAN-404-BRUTE` | Heurística de Descubrimiento de Rutas (`404 Not Found` masivos) | `MEDIUM` | 15 hits / 60s | Bloqueo IP |
| `R-AUTH-BRUTE-401` | Heurística de Fuerza Bruta de Autenticación (`401`/`403` masivos en logins/APIs) | `HIGH` | 10 hits / 60s | Bloqueo IP |
| `R-HTTP-FLOOD-DOS` | Heurística de Inundación HTTP / Denegación de Servicio (DoS Capa 7) | `CRITICAL` | 120 hits / 10s | Bloqueo IP |
| `R-DIRECT-IP-ACCESS` | Acceso Directo a IP Pública (Evasión de Proxy Cloudflare `🎯 DIRECTO A IP`) | `MEDIUM` | 1 hit / 60s | Alerta (+35 pts) |

---

## 🚀 Despliegue con Podman

Mithril está empaquetado para correr mediante **Podman Compose** (o Docker Compose).

### 1. Clonar el Repositorio
```bash
git clone https://github.com/gemacron/Mithril-SIEM.git
cd Mithril-SIEM
```

### 2. Configurar Variables de Entorno
Copia la plantilla si aún no tienes un archivo `.env`:
```bash
cp .env.example .env
```

### 3. Levantar los Contenedores
```bash
podman compose up -d --build
```
*(O `docker compose up -d --build` si utilizas Docker).*

El comando inicializará automáticamente:
- **`mithril-db`**: PostgreSQL 16 con volumen persistente (`5432/tcp`).
- **`mithril-redis`**: Redis 7 en memoria (`6379/tcp`).
- **`mithril-web`**: Servidor Django + Daphne en el puerto `9900`.
- **`mithril-worker`**: Celery Worker para procesamiento asíncrono de telemetría y heurísticas.
- **`mithril-beat`**: Celery Beat para tareas programadas y expiración de bloqueos.

### 4. Iniciar el Proxy LAN y Receptor Syslog Universal
Para recibir telemetría UDP (`5140`) y peticiones HTTP de los agentes (`9900`) desde cualquier servidor en la red LAN:
```bash
python mithril_lan_proxy.py
```

---

## 🔑 Primer Inicio de Sesión (Setup Inicial)

1. Ingresa a la interfaz web en tu navegador:
   ```text
   http://localhost:9900
   ```
2. Utiliza las credenciales iniciales definidas en `.env` (por defecto `admin` / `MithrilSecurity2026!`).
3. El sistema te guiará por el **Asistente de Seguridad Inicial**:
   - Configuración de nueva contraseña robusta.
   - Enrolamiento **2FA TOTP** mediante código QR compatible con **Google Authenticator** / Authy.
   - Generación de **5 códigos de emergencia de respaldo**.

---

## 📡 Conexión de Servidores Proxy Nginx (Rocky Linux / RHEL / Debian / Ubuntu)

### Paso 1: Dar de alta el nodo en Mithril
1. En el menú superior de Mithril, ve a **Nodos Proxy (`/nodes/`)** y haz clic en **+ Alta de Nuevo Proxy**.
2. Asigna un nombre (ej: `servbalancer150`) y su dirección IP.
3. Copia el **Token de Conexión (`API_KEY`)** generado para ese nodo.

### Paso 2: Instalación Automática en 1 Comando (Incluye Fail2ban Smart Action)
Ejecuta en tu servidor Linux el instalador automático provisto por Mithril:

#### Opción A — Modo Activo Universal con Fail2ban (Recomendado - Sin tocar Nginx)
```bash
curl -sSL http://IP_DE_MITHRIL:9900/nodes/install.sh | sudo bash -s -- --server http://IP_DE_MITHRIL:9900 --key "TU_API_KEY" --mode fail2ban
```

#### Opción B — Modo Monitor Pasivo (Cero cambios en Firewall)
```bash
curl -sSL http://IP_DE_MITHRIL:9900/nodes/install.sh | sudo bash -s -- --server http://IP_DE_MITHRIL:9900 --key "TU_API_KEY" --mode monitor
```

---

## 🛡️ Instalación y Configuración de Fail2ban en el Agente (Paso a Paso)

Si deseas instalar o auditar manualmente la integración de **Fail2ban** en cualquier servidor proxy (con o sin Cloudflare), sigue estos pasos:

### 1. Instalar Fail2ban e `ipset`
```bash
# En Ubuntu / Debian:
sudo apt-get update && sudo apt-get install -y fail2ban ipset iptables curl

# En Rocky Linux / AlmaLinux / RHEL:
sudo dnf install -y epel-release && sudo dnf install -y fail2ban ipset iptables iptables-nft curl
```

### 2. Crear el Filtro Base y el Archivo de Control
```bash
sudo mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/action.d /etc/fail2ban/jail.d /etc/mithril
sudo touch /var/log/mithril-fail2ban.log

sudo tee /etc/fail2ban/filter.d/mithril-empty.conf > /dev/null <<'EOF'
[Definition]
failregex = ^MITHRIL_MANUAL_BAN <HOST>$
ignoreregex =
EOF
```

### 3. Crear la Acción Híbrida Universal (`/etc/fail2ban/action.d/mithril-smart.conf`)
Esta acción bloquea siempre en el Kernel de Linux (`ipset`/`iptables`) para proteger cualquier plataforma sin Cloudflare y frenar ataques directos a la IP pública, y si existe `/etc/mithril/cloudflare.env`, bloquea también en el borde de Cloudflare vía API:

```bash
sudo tee /etc/fail2ban/action.d/mithril-smart.conf > /dev/null <<'EOF'
[Definition]
actionstart = ipset create mithril_f2b hash:ip timeout 0 -exist
              iptables -C INPUT -m set --match-set mithril_f2b src -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set mithril_f2b src -j DROP

actionstop  = iptables -D INPUT -m set --match-set mithril_f2b src -j DROP 2>/dev/null || true
              ipset destroy mithril_f2b 2>/dev/null || true

actioncheck = ipset list mithril_f2b >/dev/null 2>&1

actionban   = ipset add mithril_f2b <ip> -exist
              if [ -f /etc/mithril/cloudflare.env ]; then . /etc/mithril/cloudflare.env; if [ -n "$CF_API_TOKEN" ] && [ -n "$CF_ZONE_ID" ]; then curl -fsSL -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/access_rules/rules" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{\"mode\":\"block\",\"configuration\":{\"target\":\"ip\",\"value\":\"<ip>\"},\"notes\":\"Mithril-SIEM-Fail2ban\"}" >/dev/null 2>&1 || true; fi; fi

actionunban = ipset del mithril_f2b <ip> -exist
              if [ -f /etc/mithril/cloudflare.env ]; then . /etc/mithril/cloudflare.env; if [ -n "$CF_API_TOKEN" ] && [ -n "$CF_ZONE_ID" ]; then RULE_ID=$(curl -fsSL -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/access_rules/rules?configuration.target=ip&configuration.value=<ip>" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" 2>/dev/null | grep -o '"id":"[^"]*"' | head -n1 | cut -d'"' -f4); if [ -n "$RULE_ID" ]; then curl -fsSL -X DELETE "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/access_rules/rules/$RULE_ID" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" >/dev/null 2>&1 || true; fi; fi; fi

[Init]
name = mithril
EOF
```

### 4. Crear el Jail Dedicado (`/etc/fail2ban/jail.d/mithril.local`) y Reiniciar Fail2ban
```bash
sudo tee /etc/fail2ban/jail.d/mithril.local > /dev/null <<'EOF'
[mithril-jail]
enabled  = true
filter   = mithril-empty
action   = mithril-smart
logpath  = /var/log/mithril-fail2ban.log
bantime  = -1
findtime = 600
maxretry = 1
EOF

sudo systemctl enable --now fail2ban
sudo fail2ban-client reload
sudo fail2ban-client status mithril-jail
```

### 5. (Opcional) Activar Bloqueo en el Borde de Cloudflare
Si tu dominio pasa por Cloudflare, crea el archivo `/etc/mithril/cloudflare.env` para que Fail2ban bloquee también en el Edge de Cloudflare sin tocar Nginx:
```bash
sudo tee /etc/mithril/cloudflare.env > /dev/null <<'EOF'
CF_API_TOKEN="TU_CLOUDFLARE_API_TOKEN"
CF_ZONE_ID="TU_CLOUDFLARE_ZONE_ID"
EOF
sudo chmod 600 /etc/mithril/cloudflare.env
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
