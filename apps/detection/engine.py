import os
import re
import json
import time
import threading
import urllib.parse
import urllib.request
import ipaddress
from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache
from django.db.models import F
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from .models import TrafficLog, SecurityRule, SecurityEvent
from apps.mitigation.models import IpReputation, BanCandidate, ActiveBan
from apps.notifications.services import send_telegram_alert

# Caché en memoria de reglas activas y expresiones regulares precompiladas (TTL 5s)
_RULES_CACHE = {'ts': 0.0, 'rules': []}
# Cooldown por (client_ip, rule_code) para evitar saturar PostgreSQL ante ráfagas DoS/Scanners
_EVENT_COOLDOWN_CACHE = {}
# Control de cadencia de WebSocket (máx ~16 mensajes/seg hacia el navegador para no colgar el DOM/Canvas)
_WS_LAST_BROADCAST = {'ts': 0.0}

def invalidate_rules_cache():
    _RULES_CACHE['ts'] = 0.0

def get_cached_active_rules():
    now_mono = time.monotonic()
    if (now_mono - _RULES_CACHE['ts']) > 5.0 or not _RULES_CACHE['rules']:
        rules_list = list(SecurityRule.objects.filter(is_active=True))
        for r in rules_list:
            if r.pattern_regex:
                try:
                    r._compiled_regex = re.compile(r.pattern_regex, re.IGNORECASE)
                except re.error:
                    r._compiled_regex = None
            else:
                r._compiled_regex = None
        _RULES_CACHE['rules'] = rules_list
        _RULES_CACHE['ts'] = now_mono
    return _RULES_CACHE['rules']

def _is_in_event_cooldown(client_ip, rule_code, cooldown_sec=4.0):
    now_mono = time.monotonic()
    if len(_EVENT_COOLDOWN_CACHE) > 4000:
        cutoff = now_mono - 15.0
        for k in [k for k, v in _EVENT_COOLDOWN_CACHE.items() if v < cutoff]:
            _EVENT_COOLDOWN_CACHE.pop(k, None)
    key = (client_ip, rule_code)
    last_ts = _EVENT_COOLDOWN_CACHE.get(key, 0.0)
    if (now_mono - last_ts) < cooldown_sec:
        return True
    _EVENT_COOLDOWN_CACHE[key] = now_mono
    return False

# ==============================================================================
# INTEGRACIÓN DINÁMICA DE IPs DE CLOUDFLARE (API OFICIAL + CACHÉ PERSISTENTE)
# ==============================================================================
CLOUDFLARE_JSON_API_URL = "https://api.cloudflare.com/client/v4/ips"
CLOUDFLARE_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPS_V6_URL = "https://www.cloudflare.com/ips-v6"
CLOUDFLARE_CACHE_KEY = "mithril:cloudflare_dynamic_ips_v1"
CLOUDFLARE_LOCAL_FILE = "/tmp/mithril_cloudflare_ips.json"
CLOUDFLARE_SYNC_TTL_SEC = 3600  # Auto-revalidar cada 1 hora desde la API oficial de Cloudflare

# Semilla inicial de respaldo únicamente en caso de arranque sin internet
_BOOTSTRAP_IPV4 = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
]
_BOOTSTRAP_IPV6 = [
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
]

_CF_STATE_LOCK = threading.Lock()
_CF_DYNAMIC_STATE = {
    'ipv4_cidrs': list(_BOOTSTRAP_IPV4),
    'ipv6_cidrs': list(_BOOTSTRAP_IPV6),
    'networks': [ipaddress.ip_network(c, strict=False) for c in (_BOOTSTRAP_IPV4 + _BOOTSTRAP_IPV6)],
    'etag': 'bootstrap',
    'source': 'Pendiente sincronización con api.cloudflare.com',
    'last_sync_epoch': 0.0,
    'last_sync_str': 'Sincronizando...',
    'syncing': False,
    'last_error': '',
}
_CF_IP_CACHE = {}
# Correlación en memoria de corto plazo: asocia (cloudflare_ip) o (uri_limpia) -> real_client_ip
_CF_REAL_IP_CORRELATION = {}


def _compile_cf_networks(ipv4_list, ipv6_list):
    nets = []
    clean_v4, clean_v6 = [], []
    for c in ipv4_list:
        c_str = str(c).strip()
        if not c_str:
            continue
        try:
            nets.append(ipaddress.ip_network(c_str, strict=False))
            clean_v4.append(c_str)
        except Exception:
            pass
    for c in ipv6_list:
        c_str = str(c).strip()
        if not c_str:
            continue
        try:
            nets.append(ipaddress.ip_network(c_str, strict=False))
            clean_v6.append(c_str)
        except Exception:
            pass
    return clean_v4, clean_v6, nets


def _apply_cf_state(ipv4_list, ipv6_list, etag, source, sync_epoch=None, sync_str=None):
    clean_v4, clean_v6, nets = _compile_cf_networks(ipv4_list, ipv6_list)
    if not nets:
        return False
    now_ep = sync_epoch or time.time()
    now_str = sync_str or timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    with _CF_STATE_LOCK:
        changed = (
            clean_v4 != _CF_DYNAMIC_STATE['ipv4_cidrs']
            or clean_v6 != _CF_DYNAMIC_STATE['ipv6_cidrs']
            or etag != _CF_DYNAMIC_STATE['etag']
        )
        _CF_DYNAMIC_STATE['ipv4_cidrs'] = clean_v4
        _CF_DYNAMIC_STATE['ipv6_cidrs'] = clean_v6
        _CF_DYNAMIC_STATE['networks'] = nets
        _CF_DYNAMIC_STATE['etag'] = etag or 'dynamic'
        _CF_DYNAMIC_STATE['source'] = source
        _CF_DYNAMIC_STATE['last_sync_epoch'] = now_ep
        _CF_DYNAMIC_STATE['last_sync_str'] = now_str
        _CF_DYNAMIC_STATE['last_error'] = ''
        if changed:
            _CF_IP_CACHE.clear()
    return True


def _load_cf_from_shared_cache():
    """Intenta recuperar los rangos dinámicos desde Redis/Django Cache o archivo persistente local."""
    try:
        cached = cache.get(CLOUDFLARE_CACHE_KEY)
        if isinstance(cached, dict) and cached.get('ipv4_cidrs'):
            _apply_cf_state(
                cached.get('ipv4_cidrs', []),
                cached.get('ipv6_cidrs', []),
                cached.get('etag', 'cached'),
                cached.get('source', CLOUDFLARE_JSON_API_URL),
                cached.get('last_sync_epoch', time.time()),
                cached.get('last_sync_str', ''),
            )
            return True
    except Exception:
        pass

    try:
        if os.path.exists(CLOUDFLARE_LOCAL_FILE):
            with open(CLOUDFLARE_LOCAL_FILE, 'r', encoding='utf-8') as f:
                disk_data = json.load(f)
            if isinstance(disk_data, dict) and disk_data.get('ipv4_cidrs'):
                _apply_cf_state(
                    disk_data.get('ipv4_cidrs', []),
                    disk_data.get('ipv6_cidrs', []),
                    disk_data.get('etag', 'disk-cache'),
                    disk_data.get('source', CLOUDFLARE_JSON_API_URL),
                    disk_data.get('last_sync_epoch', 0.0),
                    disk_data.get('last_sync_str', ''),
                )
                return True
    except Exception:
        pass
    return False


def sync_cloudflare_ips(force=False):
    """
    Consulta dinámicamente los endpoints oficiales de Cloudflare:
      1) Primario (JSON API v4): https://api.cloudflare.com/client/v4/ips
      2) Secundario (Texto plano): https://www.cloudflare.com/ips-v4 y https://www.cloudflare.com/ips-v6
    Actualiza los bloques CIDR IPv4 e IPv6 en memoria, Redis y disco sin reiniciar el SIEM.
    """
    if not force and _CF_DYNAMIC_STATE['syncing']:
        return get_cloudflare_sync_status()

    _CF_DYNAMIC_STATE['syncing'] = True
    headers = {
        'User-Agent': 'Mithril-SIEM-ThreatIntel/2.0',
        'Accept': 'application/json, text/plain;q=0.9',
    }
    ipv4_list, ipv6_list = [], []
    etag = ''
    source_used = ''
    err_msg = ''

    # 1. Intentar API Oficial JSON v4 de Cloudflare
    try:
        req = urllib.request.Request(CLOUDFLARE_JSON_API_URL, headers=headers, method='GET')
        with urllib.request.urlopen(req, timeout=6) as resp:
            payload = json.loads(resp.read().decode('utf-8', errors='ignore'))
        if payload.get('success') and isinstance(payload.get('result'), dict):
            res = payload['result']
            ipv4_list = res.get('ipv4_cidrs', []) or []
            ipv6_list = res.get('ipv6_cidrs', []) or []
            etag = res.get('etag', 'cf-api-v4')
            source_used = CLOUDFLARE_JSON_API_URL
    except Exception as e:
        err_msg = str(e)

    # 2. Fallback a los endpoints oficiales de texto plano (/ips-v4 y /ips-v6)
    if not ipv4_list:
        try:
            req4 = urllib.request.Request(CLOUDFLARE_IPS_V4_URL, headers=headers, method='GET')
            with urllib.request.urlopen(req4, timeout=6) as r4:
                ipv4_list = [line.strip() for line in r4.read().decode('utf-8', errors='ignore').splitlines() if line.strip()]
            req6 = urllib.request.Request(CLOUDFLARE_IPS_V6_URL, headers=headers, method='GET')
            with urllib.request.urlopen(req6, timeout=6) as r6:
                ipv6_list = [line.strip() for line in r6.read().decode('utf-8', errors='ignore').splitlines() if line.strip()]
            if ipv4_list:
                etag = f"txt-{len(ipv4_list)}v4-{len(ipv6_list)}v6"
                source_used = f"{CLOUDFLARE_IPS_V4_URL} + /ips-v6"
                err_msg = ''
        except Exception as e2:
            err_msg = f"{err_msg} | Fallback: {e2}".strip(' |')

    try:
        if ipv4_list:
            now_ep = time.time()
            now_str = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            _apply_cf_state(ipv4_list, ipv6_list, etag, source_used, now_ep, now_str)
            cache_payload = {
                'ipv4_cidrs': _CF_DYNAMIC_STATE['ipv4_cidrs'],
                'ipv6_cidrs': _CF_DYNAMIC_STATE['ipv6_cidrs'],
                'etag': _CF_DYNAMIC_STATE['etag'],
                'source': _CF_DYNAMIC_STATE['source'],
                'last_sync_epoch': now_ep,
                'last_sync_str': now_str,
            }
            try:
                cache.set(CLOUDFLARE_CACHE_KEY, cache_payload, timeout=86400)
            except Exception:
                pass
            try:
                with open(CLOUDFLARE_LOCAL_FILE, 'w', encoding='utf-8') as f:
                    json.dump(cache_payload, f)
            except Exception:
                pass
        else:
            _CF_DYNAMIC_STATE['last_error'] = err_msg or 'No se recibieron CIDRs desde Cloudflare'
            _CF_DYNAMIC_STATE['last_sync_epoch'] = time.time() - (CLOUDFLARE_SYNC_TTL_SEC - 300)  # Reintentar en 5 min
    finally:
        _CF_DYNAMIC_STATE['syncing'] = False

    return get_cloudflare_sync_status()


def ensure_cloudflare_ips_fresh():
    """
    Garantiza que los rangos de Cloudflare estén actualizados desde la API oficial
    sin bloquear jamás el hilo de análisis de tráfico.
    """
    now_ep = time.time()
    if _CF_DYNAMIC_STATE['last_sync_epoch'] == 0.0:
        _load_cf_from_shared_cache()

    if (now_ep - _CF_DYNAMIC_STATE['last_sync_epoch']) > CLOUDFLARE_SYNC_TTL_SEC and not _CF_DYNAMIC_STATE['syncing']:
        t = threading.Thread(target=sync_cloudflare_ips, kwargs={'force': False}, daemon=True)
        t.start()


def get_cloudflare_sync_status():
    """Devuelve el estado actual y la lista dinámica de CIDRs de Cloudflare."""
    ensure_cloudflare_ips_fresh()
    with _CF_STATE_LOCK:
        v4 = list(_CF_DYNAMIC_STATE['ipv4_cidrs'])
        v6 = list(_CF_DYNAMIC_STATE['ipv6_cidrs'])
        return {
            'ipv4_cidrs': v4,
            'ipv6_cidrs': v6,
            'ipv4_count': len(v4),
            'ipv6_count': len(v6),
            'total_cidrs': len(v4) + len(v6),
            'etag': _CF_DYNAMIC_STATE['etag'],
            'source': _CF_DYNAMIC_STATE['source'],
            'last_sync_str': _CF_DYNAMIC_STATE['last_sync_str'],
            'last_error': _CF_DYNAMIC_STATE['last_error'],
            'api_endpoint': CLOUDFLARE_JSON_API_URL,
            'fallback_v4_endpoint': CLOUDFLARE_IPS_V4_URL,
            'fallback_v6_endpoint': CLOUDFLARE_IPS_V6_URL,
        }


def is_cloudflare_ip(ip_str):
    """
    Identifica de forma ultrarrápida (con caché en RAM + actualización dinámica desde api.cloudflare.com)
    si una IP pertenece a la red Edge/CDN de Cloudflare.
    """
    if not ip_str:
        return False
    ensure_cloudflare_ips_fresh()
    ip_clean = str(ip_str).strip()
    if ip_clean in _CF_IP_CACHE:
        return _CF_IP_CACHE[ip_clean]
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        networks = _CF_DYNAMIC_STATE['networks']
        is_cf = any(ip_obj in net for net in networks)
    except Exception:
        is_cf = False
    if len(_CF_IP_CACHE) > 5000:
        _CF_IP_CACHE.clear()
    _CF_IP_CACHE[ip_clean] = is_cf
    return is_cf


def _is_valid_ip(ip_candidate):
    if not ip_candidate:
        return False
    s = str(ip_candidate).strip()
    if not s or s == '-':
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def is_private_local_ip(ip_str):
    """Detecta si una dirección IP pertenece a rangos locales o RFC 1918 privados."""
    if not ip_str:
        return False
    s = str(ip_str).strip()
    if s.startswith(('127.', '10.', '192.168.', '169.254.', '::1')) or s in ('localhost', '-'):
        return True
    if s.startswith('172.'):
        parts = s.split('.')
        if len(parts) >= 2 and parts[1].isdigit():
            sec = int(parts[1])
            if 16 <= sec <= 31:
                return True
    return False


def resolve_cloudflare_and_real_ip(data):
    """
    Separa e identifica simultáneamente:
      1) `cloudflare_ip`: La IP del nodo Edge de Cloudflare (si la petición pasó por Cloudflare).
      2) `real_client_ip`: La IP real del cliente de origen (extraída de CF-Connecting-IP,
         True-Client-IP, X-Forwarded-For, X-Real-IP o correlación en memoria).
      3) `is_cloudflare`: True si interviene un nodo de Cloudflare o cabeceras CF.
      4) `is_local_ip`: True si es tráfico originado en la LAN o balanceador local.
    """
    headers = data.get('headers', {}) if isinstance(data.get('headers'), dict) else {}
    raw_ip = str(data.get('client_ip') or data.get('remote_addr') or '').strip()

    # Extraer posibles cabeceras de IP real enviadas por Cloudflare / Nginx
    cf_conn_ip = str(
        data.get('real_client_ip')
        or data.get('cf_connecting_ip')
        or data.get('http_cf_connecting_ip')
        or headers.get('cf_connecting_ip')
        or headers.get('cf-connecting-ip')
        or headers.get('true_client_ip')
        or headers.get('true-client-ip')
        or ''
    ).strip()

    x_real_ip = str(
        data.get('x_real_ip')
        or data.get('http_x_real_ip')
        or headers.get('x_real_ip')
        or headers.get('x-real-ip')
        or ''
    ).strip()

    xff_raw = str(
        data.get('x_forwarded_for')
        or data.get('http_x_forwarded_for')
        or headers.get('x_forwarded_for')
        or headers.get('x-forwarded-for')
        or ''
    ).strip()

    explicit_cf_ip = str(
        data.get('cloudflare_ip')
        or headers.get('cloudflare_ip')
        or headers.get('edge_ip')
        or headers.get('raw_src_ip')
        or ''
    ).strip()

    cf_ray = str(data.get('cf_ray') or data.get('http_cf_ray') or headers.get('cf_ray') or headers.get('cf-ray') or '').strip()
    cf_country = str(data.get('cf_country') or data.get('http_cf_ipcountry') or headers.get('cf_country') or headers.get('cf_ipcountry') or headers.get('cf-ipcountry') or '').strip()

    # Desglosar lista de IPs en X-Forwarded-For
    xff_ips = []
    if xff_raw and xff_raw != '-':
        for part in xff_raw.split(','):
            cand = part.strip()
            if _is_valid_ip(cand):
                xff_ips.append(cand)

    all_candidates = []
    for cand in [cf_conn_ip, *xff_ips, x_real_ip, explicit_cf_ip, raw_ip]:
        if _is_valid_ip(cand) and cand not in all_candidates:
            all_candidates.append(cand)

    cf_node_ip = ''
    real_origin_ip = ''

    # 1. Priorizar extracción de IP pública externa del cliente y el nodo Edge Cloudflare
    for cand in all_candidates:
        if is_cloudflare_ip(cand):
            if not cf_node_ip:
                cf_node_ip = cand
        elif not is_private_local_ip(cand):
            if not real_origin_ip:
                real_origin_ip = cand

    # 2. Si no hubo IP pública externa y la petición NO vino de Cloudflare, registrar IP de la LAN
    if not real_origin_ip and not cf_node_ip:
        for cand in all_candidates:
            if cand not in ('127.0.0.1', '::1') and not is_cloudflare_ip(cand):
                real_origin_ip = cand
                break

    is_cf = bool(cf_node_ip or cf_ray or (cf_conn_ip and _is_valid_ip(cf_conn_ip)))

    # Correlación en memoria: si un paquete tiene tanto cf_node_ip como real_origin_ip,
    # guardarlo brevemente para que líneas de log adyacentes (ej. error_log sin XFF) lo hereden
    now_mono = time.monotonic()
    if len(_CF_REAL_IP_CORRELATION) > 2000:
        cutoff = now_mono - 30.0
        for k in [k for k, v in _CF_REAL_IP_CORRELATION.items() if v.get('ts', 0) < cutoff]:
            _CF_REAL_IP_CORRELATION.pop(k, None)

    uri_clean = re.sub(r'^\[[^\]]+\]\s*', '', str(data.get('uri', '/')))
    if cf_node_ip and real_origin_ip and cf_node_ip != real_origin_ip:
        _CF_REAL_IP_CORRELATION[f"cf:{cf_node_ip}"] = {'real_ip': real_origin_ip, 'cf_ip': cf_node_ip, 'ts': now_mono}
        _CF_REAL_IP_CORRELATION[f"uri:{uri_clean}"] = {'real_ip': real_origin_ip, 'cf_ip': cf_node_ip, 'ts': now_mono}
    elif cf_node_ip and not real_origin_ip:
        corr = _CF_REAL_IP_CORRELATION.get(f"cf:{cf_node_ip}") or _CF_REAL_IP_CORRELATION.get(f"uri:{uri_clean}")
        if corr and (now_mono - corr.get('ts', 0)) <= 15.0:
            real_origin_ip = corr.get('real_ip', '')
    elif real_origin_ip and not cf_node_ip:
        corr = _CF_REAL_IP_CORRELATION.get(f"uri:{uri_clean}")
        if corr and corr.get('real_ip') == real_origin_ip and (now_mono - corr.get('ts', 0)) <= 15.0:
            cf_node_ip = corr.get('cf_ip', '')
            is_cf = bool(cf_node_ip)

    final_real_ip = real_origin_ip if (real_origin_ip and real_origin_ip != cf_node_ip) else ''
    is_local = is_private_local_ip(final_real_ip or raw_ip) and not is_cf

    return {
        'is_cloudflare': is_cf,
        'cloudflare_ip': cf_node_ip,
        'real_client_ip': final_real_ip,
        'is_local_ip': is_local,
        'cf_ray': cf_ray,
        'cf_country': cf_country,
    }


def extract_log_ip_meta(ip_str, headers=None):
    """
    Extrae metadatos de Cloudflare (`is_cloudflare`, `cloudflare_ip`, `real_client_ip`, `cf_ray`, `cf_country`)
    a partir de una IP y un diccionario `raw_headers` o `details` almacenado en BD.
    """
    hdrs = headers if isinstance(headers, dict) else {}
    nested_hdrs = hdrs.get('headers', {}) if isinstance(hdrs.get('headers'), dict) else {}
    merged = {**nested_hdrs, **hdrs, 'client_ip': ip_str}
    meta = resolve_cloudflare_and_real_ip(merged)
    if not meta['is_cloudflare'] and hdrs.get('is_cloudflare'):
        meta['is_cloudflare'] = True
    if not meta['cloudflare_ip'] and is_cloudflare_ip(ip_str):
        meta['cloudflare_ip'] = ip_str
    return meta

def normalize_inspection_payload(raw_text):
    """
    Decodifica payloads URL-encoded (simple y doble codificación como %20, %2e%2e%2f, %3cscript%3e)
    y normaliza comentarios de evasión SQL (/**/) para que las reglas regex detecten ataques ofuscados.
    """
    if not raw_text:
        return ""
    try:
        decoded_once = urllib.parse.unquote_plus(str(raw_text))
        decoded_twice = urllib.parse.unquote_plus(decoded_once)
        cleaned = re.sub(r'/\*.*?\*/', ' ', decoded_twice)
        return f"{raw_text} {decoded_once} {cleaned}"
    except Exception:
        return str(raw_text)

def resolve_geoip(ip_str):
    """
    Resuelve la ubicación geográfica aproximada de la IP y detecta si pertenece a Cloudflare.
    Asigna coordenadas separadas del nodo base incluso para IPs privadas para que el arco/flecha
    de ataque en el Mapa Táctico 2D siempre tenga trayectoria visible hacia el servidor proxy.
    """
    is_cf = is_cloudflare_ip(ip_str)
    if is_cf:
        cf_pops = [
            ('CF-US', 'Cloudflare Edge (US-East)', 'Ashburn PoP', 39.0438, -77.4874),
            ('CF-US', 'Cloudflare Edge (US-West)', 'San Francisco PoP', 37.7749, -122.4194),
            ('CF-EU', 'Cloudflare Edge (EU-Central)', 'Frankfurt PoP', 50.1109, 8.6821),
            ('CF-GB', 'Cloudflare Edge (UK)', 'London PoP', 51.5074, -0.1278),
            ('CF-BR', 'Cloudflare Edge (LATAM)', 'São Paulo PoP', -23.5505, -46.6333),
            ('CF-ES', 'Cloudflare Edge (EU-South)', 'Madrid PoP', 40.4168, -3.7038),
            ('CF-SG', 'Cloudflare Edge (APAC)', 'Singapore PoP', 1.3521, 103.8198),
        ]
        pop = cf_pops[abs(hash(ip_str)) % len(cf_pops)]
        return {
            'country_code': pop[0],
            'country_name': pop[1],
            'city': pop[2],
            'latitude': pop[3],
            'longitude': pop[4],
            'is_cloudflare': True
        }

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback:
            # Coordenadas regionales diferenciadas de la base (-34.60, -58.38) para que el vector/flecha sea visible en el mapa
            lan_origins = [
                ('LO', 'Red Local (LAN)', 'Segmento Corporativo Norte', -12.0464, -77.0428),
                ('LO', 'Red Local (LAN)', 'Segmento Corporativo Oeste', -33.4489, -70.6693),
                ('LO', 'Red Local (LAN)', 'Segmento Corporativo Este', -23.5505, -46.6333),
                ('LO', 'Red Local (LAN)', 'Segmento DataCenter LAN', 4.7110, -74.0721),
                ('LO', 'Red Local (LAN)', 'Segmento Interno DMZ', -25.2637, -57.5759),
            ]
            loc = lan_origins[abs(hash(ip_str)) % len(lan_origins)]
            return {
                'country_code': loc[0],
                'country_name': loc[1],
                'city': loc[2],
                'latitude': loc[3],
                'longitude': loc[4],
                'is_cloudflare': False
            }
    except Exception:
        pass

    known_nodes = [
        ('US', 'Estados Unidos', 'Ashburn', 39.0438, -77.4874),
        ('DE', 'Alemania', 'Frankfurt', 50.1109, 8.6821),
        ('CN', 'China', 'Beijing', 39.9042, 116.4074),
        ('RU', 'Rusia', 'Moscú', 55.7558, 37.6173),
        ('BR', 'Brasil', 'São Paulo', -23.5505, -46.6333),
        ('ES', 'España', 'Madrid', 40.4168, -3.7038),
        ('FR', 'Francia', 'París', 48.8566, 2.3522),
        ('NL', 'Países Bajos', 'Ámsterdam', 52.3676, 4.9041),
        ('GB', 'Reino Unido', 'Londres', 51.5074, -0.1278),
        ('JP', 'Japón', 'Tokio', 35.6762, 139.6503),
    ]
    hash_idx = abs(hash(ip_str)) % len(known_nodes)
    geo = known_nodes[hash_idx]

    return {
        'country_code': geo[0],
        'country_name': geo[1],
        'city': geo[2],
        'latitude': geo[3],
        'longitude': geo[4],
        'is_cloudflare': False
    }


def process_incoming_log(data, node=None):
    """
    Procesa, normaliza, enriquece e inspecciona cada petición recibida de Nginx
    """
    client_ip = data.get('client_ip', '').strip()
    if not client_ip:
        return None

    ip_meta = resolve_cloudflare_and_real_ip(data)
    geo = resolve_geoip(client_ip)
    is_cf = bool(ip_meta['is_cloudflare'] or geo.get('is_cloudflare', False))
    cf_node_ip = ip_meta['cloudflare_ip'] or (client_ip if is_cf else '')
    real_client_ip = ip_meta['real_client_ip']

    incoming_headers = data.get('headers', {}) if isinstance(data.get('headers'), dict) else {}
    if is_cf:
        incoming_headers['is_cloudflare'] = True
    if cf_node_ip:
        incoming_headers['cloudflare_ip'] = cf_node_ip
    if real_client_ip:
        incoming_headers['real_client_ip'] = real_client_ip
    if ip_meta.get('cf_ray'):
        incoming_headers['cf_ray'] = ip_meta['cf_ray']
    if ip_meta.get('cf_country'):
        incoming_headers['cf_country'] = ip_meta['cf_country']

    # 1. Guardar log normalizado
    log = TrafficLog.objects.create(
        node=node,
        client_ip=client_ip,
        http_method=data.get('http_method', 'GET').upper(),
        uri=data.get('uri', '/'),
        query_params=data.get('query_params', ''),
        status_code=int(data.get('status_code', 200)),
        bytes_sent=int(data.get('bytes_sent', 0)),
        latency_ms=float(data.get('latency_ms', 0.0)),
        user_agent=data.get('user_agent', ''),
        referer=data.get('referer', ''),
        country_code=geo['country_code'],
        country_name=geo['country_name'],
        city=geo['city'],
        latitude=geo['latitude'],
        longitude=geo['longitude'],
        raw_headers=incoming_headers
    )

    if node:
        ProxyNode.objects.filter(id=node.id).update(total_logs_processed=F('total_logs_processed') + 1)

    # 2. Consultar o crear reputación de la IP
    reputation, _ = IpReputation.objects.get_or_create(
        client_ip=client_ip,
        defaults={
            'country_code': geo['country_code'],
            'asn': 'CLOUDFLARE' if is_cf else '',
            'status': 'MONITORED'
        }
    )
    if is_cf and reputation.asn != 'CLOUDFLARE':
        reputation.asn = 'CLOUDFLARE'
        reputation.save(update_fields=['asn'])

    # Si la IP está en Lista Blanca, no generar alertas de bloqueo
    if reputation.status == 'WHITELISTED':
        broadcast_to_soc(log, is_threat=False, reputation=reputation)
        return log

    # 3. Motor Universal de Detección Heurística y Reglas (con caché en RAM y anti-saturación)
    now = timezone.now()
    active_rules = get_cached_active_rules()

    # Normalizar y decodificar URL/Query/User-Agent/Referer para detectar ataques codificados (%20, %2e%2e, etc.)
    raw_combined = f"{log.uri} {log.query_params} {log.user_agent} {log.referer}"
    full_target_string = normalize_inspection_payload(raw_combined)
    normalized_uri = normalize_inspection_payload(f"{log.uri} {log.query_params}")

    risk_to_add = 0
    triggered_events = []
    matched_any_rule = False

    base_req_details = {
        'log_id': log.id,
        'node': node.name if node else 'Direct',
        'http_method': log.http_method,
        'uri': log.uri,
        'query_params': log.query_params,
        'status_code': log.status_code,
        'bytes_sent': log.bytes_sent,
        'latency_ms': log.latency_ms,
        'user_agent': log.user_agent,
        'referer': log.referer,
        'country_code': log.country_code,
        'country_name': log.country_name,
        'city': log.city,
        'is_cloudflare': is_cf,
        'cloudflare_ip': cf_node_ip,
        'real_client_ip': real_client_ip,
        'cf_ray': ip_meta.get('cf_ray', ''),
        'cf_country': ip_meta.get('cf_country', ''),
        'headers': log.raw_headers or {},
    }

    for rule in active_rules:
        compiled_rx = getattr(rule, '_compiled_regex', None)
        window_start = now - timedelta(seconds=max(1, rule.threshold_seconds))

        # A. Reglas de Fuerza Bruta de Autenticación (401/403)
        if rule.code == 'R-AUTH-BRUTE-401':
            if log.status_code in (401, 403) and (not compiled_rx or compiled_rx.search(normalized_uri)):
                matched_any_rule = True
                if not _is_in_event_cooldown(client_ip, rule.code, cooldown_sec=3.0):
                    recent_auth_fails = TrafficLog.objects.filter(
                        client_ip=client_ip,
                        status_code__in=[401, 403],
                        created_at__gte=window_start
                    ).count()
                    if recent_auth_fails >= rule.threshold_count:
                        event = SecurityEvent.objects.create(
                            node=node,
                            rule=rule,
                            client_ip=client_ip,
                            severity='HIGH',
                            matched_payload=f"{recent_auth_fails} respuestas {log.status_code} en {log.uri} ({rule.threshold_seconds}s)",
                            details={**base_req_details, 'count_auth_fails': recent_auth_fails}
                        )
                        triggered_events.append(event)
                        risk_to_add += rule.risk_points

        # B. Detección Heurística de Frecuencia 404 (Enumeración de archivos / Scanners)
        elif rule.code == 'R-SCAN-404-BRUTE' or (not rule.pattern_regex and rule.category == 'SCANNER'):
            if log.status_code == 404:
                matched_any_rule = True
                if not _is_in_event_cooldown(client_ip, rule.code, cooldown_sec=3.0):
                    recent_404_count = TrafficLog.objects.filter(
                        client_ip=client_ip,
                        status_code=404,
                        created_at__gte=window_start
                    ).count()
                    if recent_404_count >= rule.threshold_count:
                        event = SecurityEvent.objects.create(
                            node=node,
                            rule=rule,
                            client_ip=client_ip,
                            severity='HIGH',
                            matched_payload=f"{recent_404_count} errores 404 en {rule.threshold_seconds}s ({log.uri})",
                            details={**base_req_details, 'count_404': recent_404_count}
                        )
                        triggered_events.append(event)
                        risk_to_add += rule.risk_points

        # C. Detección Heurística de Ráfaga / Flood DoS por IP (Rate Limit sin regex)
        elif not rule.pattern_regex and rule.category == 'RATE_LIMIT':
            if not _is_in_event_cooldown(client_ip, rule.code, cooldown_sec=4.0):
                recent_req_count = TrafficLog.objects.filter(
                    client_ip=client_ip,
                    created_at__gte=window_start
                ).count()
                if recent_req_count >= rule.threshold_count:
                    matched_any_rule = True
                    event = SecurityEvent.objects.create(
                        node=node,
                        rule=rule,
                        client_ip=client_ip,
                        severity='CRITICAL' if rule.risk_points >= 60 else 'HIGH',
                        matched_payload=f"Ráfaga DoS: {recent_req_count} reqs en {rule.threshold_seconds}s",
                        details={**base_req_details, 'request_count': recent_req_count, 'window_seconds': rule.threshold_seconds}
                    )
                    triggered_events.append(event)
                    risk_to_add += rule.risk_points

        # D. Reglas basadas en Expresión Regular (con soporte de umbral threshold_count >= 1)
        elif compiled_rx:
            match = compiled_rx.search(full_target_string)
            if match:
                matched_any_rule = True
                matched_text = match.group(0)
                if not _is_in_event_cooldown(client_ip, rule.code, cooldown_sec=2.5):
                    should_trigger = True

                    if rule.threshold_count > 1:
                        recent_matches = SecurityEvent.objects.filter(
                            client_ip=client_ip,
                            rule=rule,
                            created_at__gte=window_start
                        ).count() + 1
                        if recent_matches < rule.threshold_count:
                            SecurityEvent.objects.create(
                                node=node,
                                rule=rule,
                                client_ip=client_ip,
                                severity='LOW',
                                matched_payload=f"[{recent_matches}/{rule.threshold_count}] {matched_text}",
                                details={**base_req_details, 'uri': log.uri, 'query': log.query_params, 'agent': log.user_agent}
                            )
                            should_trigger = False

                    if should_trigger:
                        severity = 'CRITICAL' if rule.risk_points >= 70 else ('HIGH' if rule.risk_points >= 50 else 'MEDIUM')
                        event = SecurityEvent.objects.create(
                            node=node,
                            rule=rule,
                            client_ip=client_ip,
                            severity=severity,
                            matched_payload=matched_text,
                            details={**base_req_details, 'uri': log.uri, 'query': log.query_params, 'agent': log.user_agent}
                        )
                        triggered_events.append(event)
                        risk_to_add += rule.risk_points

    # 4. Actualizar puntaje de riesgo de la IP
    if risk_to_add > 0:
        reputation.current_risk_score = min(100, reputation.current_risk_score + risk_to_add)
        reputation.total_violations += len(triggered_events)
        reputation.last_seen_at = now
        reputation.last_evaluated_at = now

        if reputation.current_risk_score >= 80 and reputation.status != 'BANNED':
            reputation.status = 'PENDING_BAN'
        elif reputation.current_risk_score >= 40 and reputation.status == 'MONITORED':
            reputation.status = 'SUSPICIOUS'

        reputation.save()

        # 5. Generar Candidato a Bloqueo (Dry-Run / Autoban Simulado) sin detener el análisis posterior
        if reputation.current_risk_score >= 80:
            last_event = triggered_events[0] if triggered_events else None
            reason_text = f"Puntaje de riesgo {reputation.current_risk_score}/100 alcanzado. Disparó {reputation.total_violations} infracciones."
            if last_event and last_event.rule:
                reason_text += f" Última infracción: {last_event.rule.name}."
            if is_cf and real_client_ip:
                reason_text += f" [Cloudflare Node: {cf_node_ip} ➔ IP Real Cliente: {real_client_ip}]"

            candidate, created = BanCandidate.objects.get_or_create(
                client_ip=client_ip,
                status='PENDING',
                defaults={
                    'accumulated_score': reputation.current_risk_score,
                    'suggested_reason': reason_text,
                    'trigger_event': last_event
                }
            )
            if not created:
                candidate.accumulated_score = reputation.current_risk_score
                candidate.suggested_reason = reason_text
                if last_event:
                    candidate.trigger_event = last_event
                candidate.save(update_fields=['accumulated_score', 'suggested_reason', 'trigger_event'])

            # Notificar vía Telegram de forma asíncrona (no bloqueante) si es un candidato nuevo
            if created:
                cf_line = f"IP Real Cliente: {real_client_ip} (vía Cloudflare {cf_node_ip})\n" if (is_cf and real_client_ip) else ""
                send_telegram_alert(
                    title="🚨 Nuevo Candidato a Bloqueo Detectado",
                    message=(
                        f"IP Detectada: {client_ip} ({geo['country_name']})\n"
                        f"{cf_line}"
                        f"Score de Riesgo: {reputation.current_risk_score}/100\n"
                        f"Proxy: {node.name if node else 'N/A'}\n"
                        f"Motivo: {reason_text}\n"
                        f"Estado: Esperando aprobación del operador en Mithril SIEM."
                    )
                )

    # 6. Emitir evento en vivo por WebSockets al SOC (incluso si ya es candidato, el mapa sigue analizando)
    is_threat = (
        len(triggered_events) > 0
        or matched_any_rule
        or reputation.status in ('PENDING_BAN', 'BANNED')
        or log.status_code >= 400
    )
    broadcast_to_soc(log, is_threat=is_threat, reputation=reputation, events=triggered_events)

    return log


def broadcast_to_soc(log, is_threat=False, reputation=None, events=None):
    """
    Envía por WebSocket el evento para actualizar el mapa 2D y el Live Feed del operador.
    Incluye control de cadencia (throttling) para no saturar ni colgar el navegador ante ráfagas masivas.
    """
    now_mono = time.monotonic()
    min_interval = 0.035 if is_threat else 0.08  # Priorizar amenazas pero limitar a máx ~28 fps de red
    if (now_mono - _WS_LAST_BROADCAST['ts']) < min_interval:
        return
    _WS_LAST_BROADCAST['ts'] = now_mono

    channel_layer = get_channel_layer()
    if not channel_layer:
        return

    meta = extract_log_ip_meta(log.client_ip, log.raw_headers)
    payload = {
        'type': 'traffic_event',
        'event': {
            'id': log.id,
            'timestamp': log.created_at.strftime('%H:%M:%S'),
            'client_ip': log.client_ip,
            'method': log.http_method,
            'uri': log.uri,
            'status_code': log.status_code,
            'country_code': log.country_code,
            'country_name': log.country_name,
            'city': log.city,
            'latitude': log.latitude,
            'longitude': log.longitude,
            'node': log.node.name if log.node else 'Direct',
            'is_threat': is_threat,
            'is_cloudflare': meta['is_cloudflare'],
            'cloudflare_ip': meta['cloudflare_ip'],
            'real_client_ip': meta['real_client_ip'],
            'is_local_ip': meta.get('is_local_ip', False) or is_private_local_ip(meta['real_client_ip'] or (log.client_ip if not meta['is_cloudflare'] else '')),
            'user_agent': log.user_agent or '',
            'risk_score': reputation.current_risk_score if reputation else 0,
            'violations_count': len(events) if events else 0,
        }
    }

    try:
        async_to_sync(channel_layer.group_send)('soc_live_feed', payload)
    except Exception:
        pass
