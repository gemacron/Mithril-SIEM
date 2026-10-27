# 🛡️ Guía de Conexión de Proxies Nginx a Mithril SIEM (Puerto 9900)

Esta guía explica paso a paso cómo conectar cualquier servidor proxy inverso **Nginx** que ejecute **Ubuntu** (20.04/22.04/24.04), **Debian** (11/12), **Rocky Linux** (8/9) o **AlmaLinux/RHEL/CentOS** a la plataforma central **Mithril SIEM**.

---

## 🏛️ Flujo de Comunicación

```
┌────────────────────────────────────────────────────────┐
│                   Mithril SIEM Core                    │
│  • Panel Web & API : http://<IP_MITHRIL>:9900          │
│  • Syslog Ingestion: udp://<IP_MITHRIL>:5140           │
└───────────────────────────▲────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
  [Heartbeat + Sincronización]      [Logs JSON Syslog]
  Puerto 9900 (HTTP/REST)           Puerto 5140 (UDP)
              │                           │
┌─────────────┴───────────────────────────┴──────────────┐
│        Servidor Proxy (Ubuntu / Rocky Linux)           │
│                                                        │
│  1. mithril-bouncer.service (Servicio systemd)         │
│     • Envía telemetría (CPU, RAM, Nginx versión)       │
│     • Descarga lista negra aprobada                    │
│     • Aplica bloqueos en kernel (ipset / iptables)     │
│                                                        │
│  2. Nginx Web Server                                   │
│     • Emite logs en formato JSON estructurado          │
│     • Incluye lista de bloqueo dinámico                │
└────────────────────────────────────────────────────────┘
```

---

## Paso 1: Registrar el Servidor Proxy en Mithril SIEM

1. Ingresa a la interfaz web de Mithril SIEM: `http://<IP_MITHRIL>:9900`.
2. En el menú superior, haz clic en **Nodos Proxy** (`/nodes/`).
3. Haz clic en el botón **+ Registrar Servidor Proxy** (`/nodes/create/`).
4. Completa el formulario:
   - **Nombre:** Identificador del nodo (ej. `proxy-edge-01`, `dmz-nginx-rocky`).
   - **Dirección IP:** IP pública o de red interna del servidor proxy (ej. `192.168.1.50`).
   - **Etiqueta de Ubicación:** ej. `Datacenter Principal`, `AWS us-east-1`.
   - **Descripción:** Notas operativas sobre los dominios que balancea.
5. Haz clic en **Registrar Servidor Proxy**. Serás redirigido a la pantalla de **Configuración del Nodo**.
6. **Copia el Token de API del Nodo (`NODE_API_KEY`)**. Este token autentica al agente contra Mithril.

---

## Paso 2: Instalación del Agente Bouncer en el Servidor Proxy

Conéctate por SSH a tu servidor proxy (**Ubuntu** o **Rocky Linux**) como usuario con privilegios `sudo` o `root`.

### Opción 1: Instalación Rápida con Git (Recomendada)

Ejecuta los siguientes comandos:

```bash
# 1. Clonar el repositorio oficial
git clone https://github.com/gemacron/Mithril-SIEM.git /tmp/Mithril-SIEM

# 2. Ejecutar el instalador universal
sudo bash /tmp/Mithril-SIEM/agent/install_agent.sh
```

El script detectará automáticamente tu distribución (**Ubuntu/Debian** o **Rocky Linux/RHEL**) y te solicitará dos parámetros:
* **URL de Mithril SIEM:** `http://<IP_MITHRIL>:9900`
* **Token del Nodo (NODE_API_KEY):** El token obtenido en el Paso 1.

---

### Opción 2: Instalación No Interactiva (Scripts Automatizados / Ansible / Terraform)

```bash
git clone https://github.com/gemacron/Mithril-SIEM.git /tmp/Mithril-SIEM

sudo bash /tmp/Mithril-SIEM/agent/install_agent.sh \
  "http://<IP_MITHRIL>:9900" \
  "<TU_NODE_API_KEY>" \
  "ipset" \
  "15"
```

> **¿Qué realiza `install_agent.sh` internamente?**
> 1. Detecta el gestor de paquetes del sistema (`apt-get` o `dnf`).
> 2. Instala dependencias del sistema: `python3`, `ipset`, `iptables`, `curl`.
> 3. Instala el agente optimizado en `/opt/mithril-agent/mithril_bouncer.py` (sin librerías de terceros obligatorias).
> 4. Genera la unidad persistente `/etc/systemd/system/mithril-bouncer.service`.
> 5. Habilita e inicia el servicio automáticamente con `systemctl enable --now mithril-bouncer.service`.

---

## Paso 3: Configurar Nginx para Envío de Logs y Bloqueo

### 3.1. Agregar el Formato JSON Estructurado

Abre el archivo principal de configuración de Nginx:
```bash
sudo nano /etc/nginx/nginx.conf
```

Dentro del bloque `http { ... }`, añade la siguiente directiva `log_format`:

```nginx
http {
    # ... otras directivas existentes ...

    # Formato JSON estructurado para Mithril SIEM
    log_format mithril_json escape=json '{'
        '"client_ip":"$remote_addr",'
        '"time_local":"$time_iso8601",'
        '"http_method":"$request_method",'
        '"uri":"$uri",'
        '"query_params":"$args",'
        '"status_code":$status,'
        '"bytes_sent":$body_bytes_sent,'
        '"latency_ms":$request_time,'
        '"user_agent":"$http_user_agent",'
        '"referer":"$http_referer"'
    '}';
}
```

---

### 3.2. Configurar el VirtualHost de tu Aplicación o Dominio

Edita el archivo de configuración de tu sitio:
* **Ubuntu / Debian:** `/etc/nginx/sites-available/default` (o `/etc/nginx/conf.d/mi_sitio.conf`)
* **Rocky Linux / RHEL:** `/etc/nginx/conf.d/mi_sitio.conf`

```nginx
server {
    listen 80;
    server_name tu-dominio.com;

    # 1. Inclusión de la lista de bloqueo dinámico generada por Mithril Bouncer
    include /etc/nginx/conf.d/mithril_blocklist.conf;

    # 2. Envío en tiempo real por Syslog UDP directo al servidor Mithril (Puerto 5140)
    # Reemplaza <IP_MITHRIL> por la IP de tu servidor Mithril SIEM
    access_log syslog:server=<IP_MITHRIL>:5140,facility=local7,tag=nginx mithril_json;

    # Log de errores estándar
    error_log /var/log/nginx/error.log warn;

    location / {
        proxy_pass http://127.0.0.1:8080; # Backend o servidor de aplicaciones
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

### 3.3. Validar y Recargar Nginx

```bash
# Comprobar sintaxis sin interrumpir tráfico
sudo nginx -t

# Recarga en caliente (cero tiempo de inactividad)
sudo systemctl reload nginx
```

---

## Paso 4: Verificación y Comandos de Administración

### 1. Comprobar el Estado del Servicio en el Proxy
```bash
sudo systemctl status mithril-bouncer
```
Debe indicar `active (running)`.

### 2. Monitorear los Registros del Agente en Vivo
```bash
sudo journalctl -u mithril-bouncer -f
```
Salida esperada:
```text
🛡️  MITHRIL BOUNCER AGENT - INICIADO
   SIEM Destino   : http://192.168.1.100:9900
   Metodo Bloqueo : ipset
   Intervalo Sync : 15 segundos
🛡️ [FIREWALL] ipset 'mithril_blacklist' listo y vinculado a iptables.
✅ [IPSET] 0 IPs bloqueadas en kernel/firewall.
```

### 3. Consultar la Lista de IPs Bloqueadas en el Firewall
* **Si usas `ipset` (bloqueo a nivel de kernel/red):**
  ```bash
  sudo ipset list mithril_blacklist
  ```
* **Si usas `nginx_conf`:**
  ```bash
  cat /etc/nginx/conf.d/mithril_blocklist.conf
  ```

### 4. Verificar en el Panel Web de Mithril SIEM
1. Entra a `http://<IP_MITHRIL>:9900/nodes/`.
2. El servidor proxy mostrará una insignia verde **`ONLINE`**.
3. Se reportará en tiempo real:
   * **CPU:** Porcentaje de carga normalizada.
   * **RAM:** Porcentaje de memoria en uso.
   * **Nginx:** Versión instalada en el proxy.
   * **Última Señal:** Hace pocos segundos.

---

## 🔧 Resolución de Problemas Frecuentes

| Síntoma | Causa Probable | Solución |
| :--- | :--- | :--- |
| **Error `Unauthorized` (401/403) en logs** | `NODE_API_KEY` incorrecto o nodo eliminado | Revisa la variable en `/etc/systemd/system/mithril-bouncer.service` y ejecuta `systemctl daemon-reload && systemctl restart mithril-bouncer`. |
| **No llegan logs al Mapa 2D de Mithril** | Bloqueo en firewall UDP del puerto 5140 | En el servidor Mithril, abre el puerto: `sudo ufw allow 5140/udp` (Ubuntu) o `sudo firewall-cmd --add-port=5140/udp --permanent && sudo firewall-cmd --reload` (Rocky Linux). |
| **`nginx: [emerg] open() "/etc/nginx/conf.d/mithril_blocklist.conf" failed`** | Archivo inicial no creado | Ejecuta: `sudo touch /etc/nginx/conf.d/mithril_blocklist.conf && sudo systemctl reload nginx`. |
| **SELinux bloquea conexiones salientes en Rocky Linux** | Política estricta de red en SELinux | Ejecuta: `sudo setsebool -P httpd_can_network_connect 1`. |
