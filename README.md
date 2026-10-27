# 🛡️ Mithril SIEM

<div align="center">
  <img src="static/img/mithril-logo.jpg" alt="Mithril SIEM" width="160" style="border-radius: 16px; border: 2px solid #00e5ff; box-shadow: 0 0 20px rgba(0,229,255,0.4);" />
  <h3>Plataforma Táctica SIEM de Detección y Mitigación de Amenazas para Proxies Nginx</h3>
  <p>Entorno Web SOC en Modo Oscuro • Mapa 2D Interactivo • Autoban Asistido por Humano • Integración Podman</p>

  [![Podman](https://img.shields.io/badge/Podman-Ready-892CA0?logo=podman&logoColor=white)](#despliegue-con-podman)
  [![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](#)
  [![Django](https://img.shields.io/badge/Django-5.0-092E20?logo=django&logoColor=white)](#)
  [![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](#)
  [![2FA](https://img.shields.io/badge/2FA-Google_Authenticator-4285F4?logo=google&logoColor=white)](#)
  [![Telegram](https://img.shields.io/badge/Telegram-Alerts-26A5E4?logo=telegram&logoColor=white)](#)
</div>

---

## 📖 Descripción General

**Mithril SIEM** es un sistema de gestión de eventos e información de seguridad diseñado específicamente para infraestructuras web protegidas por servidores proxy inversos **Nginx**. 

A diferencia de los analizadores tradicionales de archivos de log en disco (lentos, reactivos y con alto costo de I/O), **Mithril** procesa eventos normalizados en tiempo real mediante streaming directo (Syslog / JSON), enriquece los datos geográficamente en microsegundos, evalúa reglas heurísticas y centraliza la toma de decisiones de bloqueo para un número ilimitado de servidores proxy.

---

## ✨ Características Principales

- **🎮 Centro de Operaciones de Seguridad (SOC) en Modo Oscuro:** Interfaz táctica de alto contraste diseñada para salas de control (War Room) y monitores de seguridad.
- **🗺️ Mapa Táctico 2D Mundial en Tiempo Real:** Visualización interactiva ultraligera en Canvas que ilumina coordenadas de tráfico y pulsos de ataque balístico sin dependencias de APIs de terceros (100% autónomo).
- **⚠️ Autoban en Modo Simulación (Human-in-the-Loop):** El motor calcula continuamente el puntaje de riesgo de cada IP. Cuando una IP supera el umbral (80/100), entra a una **cola de decisión** con toda la evidencia para que el operador apruebe el bloqueo en un clic o lo descarte.
- **📡 Escalado Indefinido de Proxies Nginx:** Alta dinámica de servidores proxy con tokens únicos y monitor de salud (heartbeat).
- **🛡️ Mithril Bouncer (Mitigación Instantánea):** Agente ultraligero que corre en cada proxy Nginx y aplica los bloqueos aprobados en el kernel/firewall (`ipset` / `nftables`) o mediante listas dinámicas de Nginx sin reiniciar el servicio.
- **🔐 Seguridad Blindada en el Acceso:**
  - **Primer login forzado:** Obliga al cambio de la contraseña genérica de despliegue antes de habilitar el acceso al panel.
  - **2FA TOTP Obligatorio:** Enrolamiento con código QR compatible con **Google Authenticator**, Authy y claves de recuperación de emergencia.
  - **Anti-Fuerza Bruta y Auditoría:** Registro de cada intento de inicio de sesión con IP y User-Agent.
- **✈️ Alertas en Tiempo Real por Telegram:** Notificación instantánea con formato enriquecido a grupos o canales del SOC ante candidatos a bloqueo o caídas de proxies.
- **📜 Auditoría Forense y Exportación:** Historial completo inmutable de acciones de operadores e incidentes con exportación en formatos **CSV** y **JSON**.

---

## 🏛️ Arquitectura del Sistema

```
┌────────────────────────────────────────────────────────┐
│                   CAPA DE PROXIES NGINX                │
│   [ Proxy Nginx 01 ]    [ Proxy Nginx 02 ]   [ ...0N ] │
│   (Emisión JSON Syslog) (Emisión JSON Syslog)          │
└───────────────────────────┬────────────────────────────┘
                            │ (Streaming en tiempo real)
                            ▼
┌────────────────────────────────────────────────────────┐
│                INGESTIÓN & CELERY WORKERS              │
│  - Normalización y Enriquecimiento GeoIP local         │
│  - Evaluación de Reglas Heurísticas (OWASP / Scanners) │
│  - Correlación de Anomalías y Cálculo de Riesgo        │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
 (Guarda Logs e Incidentes)     (Emite evento WebSocket)
               ▼                          ▼
┌──────────────────────────────┐ ┌───────────────────────┐
│     POSTGRESQL 16 & REDIS    │ │   MITHRIL CORE (WEB)  │
│  - Particionamiento por día  │ │  - Dashboard SOC 2D   │
│  - Índices BRIN ultrarrápidos│ │  - Cola de Aprobación │
└──────────────────────────────┘ └───────────┬───────────┘
                                             │ Orden de Bloqueo Aprobada
                                             ▼
                                ┌────────────────────────┐
                                │   MITHRIL BOUNCER      │
                                │  (Aplica ipset / Nginx │
                                │   en cada servidor)    │
                                └────────────────────────┘
```

---

## 🚀 Despliegue con Podman

Mithril está empaquetado para correr de forma nativa y rootless mediante **Podman Compose**.

### 1. Clonar el Repositorio
```bash
git clone https://github.com/gemacron/Mithril-SIEM.git
cd Mithril-SIEM
```

### 2. Configurar Variables de Entorno
Copia la plantilla y ajusta las contraseñas deseadas:
```bash
cp .env.example .env
```

### 3. Levantar los Contenedores
```bash
podman compose up -d --build
```
*(O `docker compose up -d --build` si utilizas Docker).*

El comando inicializará automáticamente:
- **`mithril-db`**: PostgreSQL 16 con volumen persistente.
- **`mithril-redis`**: Redis 7 en memoria.
- **`mithril-web`**: Servidor Django + Daphne (WebSockets) en el puerto `9900`.
- **`mithril-worker`**: Celery Worker para procesamiento en segundo plano.
- **`mithril-beat`**: Tareas periódicas y chequeo de salud de proxies.

---

## 🔑 Primer Inicio de Sesión (Setup Inicial)

1. Ingresa a la interfaz web en tu navegador:
   ```
   http://localhost:9900
   ```
2. Utiliza las credenciales genéricas iniciales definidas en `.env`:
   - **Usuario:** `admin`
   - **Contraseña:** `MithrilSecurity2026!`
3. El sistema interceptará el acceso y te guiará por el **Asistente de Seguridad Inicial**:
   - Ingresa tu nueva contraseña fuerte (mínimo 12 caracteres).
   - Escanea el código QR con tu aplicación **Google Authenticator**.
   - Ingresa el token de 6 dígitos para validar la sincronización.
   - Guarda los **5 códigos de emergencia de respaldo** proporcionados.

---

## 📡 Conexión de Servidores Proxy Nginx

### Paso 1: Dar de alta el proxy en Mithril
1. En el menú superior de Mithril, ve a **Nodos Proxy** y haz clic en **+ Alta de Nuevo Proxy**.
2. Asigna un nombre (ej: `proxy-edge-01`) y su IP.
3. El sistema generará un **Token de Conexión** único (ej: `mithril_node_9a8b...`) y podrás acceder a su pantalla **⚙️ Configurar** para ajustar umbrales de RPS, timeouts y descargar el servicio systemd.

### Paso 2: Ejecutar el Agente Mithril Bouncer en el Proxy
En cada máquina donde corre Nginx, ejecuta el agente:
```bash
export MITHRIL_URL="http://IP_DE_MITHRIL:9900"
export NODE_API_KEY="mithril_node_TU_TOKEN_GENERADO"
python3 agent/mithril_bouncer.py
```

### Paso 3: Configurar Nginx para emisión JSON
Agrega al bloque `http` o `server` de tu configuración Nginx el formato definido en `agent/nginx_syslog_sample.conf`:
```nginx
include /etc/nginx/conf.d/mithril_blocklist.conf;
access_log syslog:server=IP_DE_MITHRIL:5140,facility=local7,tag=nginx mithril_json;
```

---

## ✈️ Configuración de Alertas por Telegram

1. Crea un bot en Telegram con **@BotFather** y obtén tu `API Token`.
2. Obtén el `Chat ID` de tu usuario o canal de seguridad.
3. En la interfaz web de Mithril, dirígete a **Telegram** en la barra superior.
4. Ingresa las credenciales, activa los tipos de alertas deseadas y pulsa **Enviar Alerta de Prueba**.

---

## 📜 Licencia

Desarrollado bajo licencia MIT. Software libre para uso, auditoría y distribución.
