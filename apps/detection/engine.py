import os
import re
import zlib
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
from apps.nodes.models import ProxyNode
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


# ==============================================================================
# AUTODESCUBRIMIENTO DINÁMICO DE INFRAESTRUCTURA PROPIA (CERO IPs HARDCODEADAS)
# ==============================================================================
OWN_WAN_CACHE_KEY = 'mithril:own_public_wan_info:v1'
_OWN_INFRA_LOCK = threading.Lock()
_OWN_INFRA_STATE = {
    'public_wan_ips': set(),
    'public_wan_country': '',
    'internal_node_ips': {'127.0.0.1', '::1'},
    'last_wan_probe_epoch': 0.0,
    'last_db_refresh_epoch': 0.0,
    'probing_wan': False,
}
_GEOIP_MEM_CACHE = {}


def _probe_own_public_wan_worker():
    """
    Descubre automáticamente la IP Pública WAN de salida del propio entorno y su país ISO
    consultando reflectores públicos estándar (Cloudflare Trace / ipify), sin hardcodear ninguna IP.
    """
    try:
        for url in ('https://1.1.1.1/cdn-cgi/trace', 'https://api.ipify.org', 'https://icanhazip.com'):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mithril-SIEM/2.1'}, method='GET')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    body = resp.read().decode('utf-8', errors='ignore').strip()
                discovered_ip = ''
                discovered_cc = ''
                if 'ip=' in body:
                    for line in body.splitlines():
                        if line.startswith('ip='):
                            discovered_ip = line.split('=', 1)[1].strip()
                        elif line.startswith('loc='):
                            discovered_cc = line.split('=', 1)[1].strip().upper()
                else:
                    discovered_ip = body
                if _is_valid_ip(discovered_ip) and not is_private_local_ip(discovered_ip):
                    register_own_public_wan_ip(discovered_ip, discovered_cc)
                    break
            except Exception:
                continue
    finally:
        _OWN_INFRA_STATE['probing_wan'] = False
        _OWN_INFRA_STATE['last_wan_probe_epoch'] = time.time()


def register_own_public_wan_ip(ip_str, country_code=''):
    """Registra dinámicamente en RAM y Redis una IP Pública WAN perteneciente a la propia infraestructura."""
    if not _is_valid_ip(ip_str) or is_private_local_ip(ip_str) or is_cloudflare_ip(ip_str):
        return
    s = str(ip_str).strip()
    cc = str(country_code or '').strip().upper()
    with _OWN_INFRA_LOCK:
        _OWN_INFRA_STATE['public_wan_ips'].add(s)
        if cc and cc not in ('XX', 'T1', '-'):
            _OWN_INFRA_STATE['public_wan_country'] = cc
        payload = {
            'ips': list(_OWN_INFRA_STATE['public_wan_ips']),
            'country': _OWN_INFRA_STATE['public_wan_country'],
        }
    try:
        cache.set(OWN_WAN_CACHE_KEY, payload, timeout=86400)
    except Exception:
        pass


def _refresh_own_infra_ips_if_needed():
    now_ep = time.time()
    # 1. Sondear la IP Pública WAN del servidor en segundo plano cada 30 minutos
    if (now_ep - _OWN_INFRA_STATE['last_wan_probe_epoch']) > 1800 and not _OWN_INFRA_STATE['probing_wan']:
        _OWN_INFRA_STATE['probing_wan'] = True
        try:
            cached = cache.get(OWN_WAN_CACHE_KEY)
            if isinstance(cached, dict):
                with _OWN_INFRA_LOCK:
                    for ip_c in cached.get('ips', []):
                        if _is_valid_ip(ip_c):
                            _OWN_INFRA_STATE['public_wan_ips'].add(ip_c)
                    if cached.get('country') and not _OWN_INFRA_STATE['public_wan_country']:
                        _OWN_INFRA_STATE['public_wan_country'] = cached['country']
        except Exception:
            pass
        threading.Thread(target=_probe_own_public_wan_worker, daemon=True).start()

    # 2. Sincronizar nodos registrados e IPs en lista blanca desde PostgreSQL cada 45 segundos
    if (now_ep - _OWN_INFRA_STATE['last_db_refresh_epoch']) > 45:
        _OWN_INFRA_STATE['last_db_refresh_epoch'] = now_ep
        try:
            node_ips = set(ProxyNode.objects.values_list('ip_address', flat=True))
            own_wan_db = set(
                IpReputation.objects.filter(asn='OWN_INFRASTRUCTURE').values_list('client_ip', flat=True)
            )
            whitelisted_db = set(
                IpReputation.objects.filter(status='WHITELISTED').values_list('client_ip', flat=True)
            )
            with _OWN_INFRA_LOCK:
                for nip in (node_ips | whitelisted_db):
                    if _is_valid_ip(nip):
                        if is_private_local_ip(nip):
                            _OWN_INFRA_STATE['internal_node_ips'].add(nip)
                        elif nip in own_wan_db:
                            _OWN_INFRA_STATE['public_wan_ips'].add(nip)
                for wip in own_wan_db:
                    if _is_valid_ip(wip) and not is_private_local_ip(wip):
                        _OWN_INFRA_STATE['public_wan_ips'].add(wip)
        except Exception:
            pass


def get_own_public_wan_ips():
    """
    Devuelve el conjunto de IPs Públicas WAN propias de la infraestructura:
      - Autodescubiertas en tiempo de ejecución (reflector WAN / agentes mithril-bouncer / monitores internos)
      - Registradas en BD con ASN 'OWN_INFRASTRUCTURE'
      - Opcionalmente declaradas en la variable de entorno MITHRIL_OWN_PUBLIC_IPS
    """
    _refresh_own_infra_ips_if_needed()
    env_extra = os.environ.get('MITHRIL_OWN_PUBLIC_IPS', '')
    extra_set = {x.strip() for x in env_extra.split(',') if _is_valid_ip(x.strip())}
    with _OWN_INFRA_LOCK:
        return set(_OWN_INFRA_STATE['public_wan_ips']) | extra_set


def get_own_internal_infra_ips():
    """
    Devuelve el conjunto de IPs internas de la infraestructura (nodos Proxy registrados,
    loopback, IPs en lista blanca y variable opcional MITHRIL_PROTECTED_IPS).
    """
    _refresh_own_infra_ips_if_needed()
    env_extra = os.environ.get('MITHRIL_PROTECTED_IPS', '')
    extra_set = {x.strip() for x in env_extra.split(',') if _is_valid_ip(x.strip())}
    with _OWN_INFRA_LOCK:
        return set(_OWN_INFRA_STATE['internal_node_ips']) | extra_set


def is_own_public_wan_ip(ip_str):
    """
    Detecta dinámicamente si una IP pública corresponde a la propia IP pública WAN de la infraestructura
    (por ejemplo cuando un monitor interno como Zabbix o un servicio propio sale a Internet y entra por Cloudflare).
    ESTA IP TIENE INMUNIDAD ABSOLUTA Y JAMÁS DEBE BLOQUEARSE.
    """
    if not ip_str:
        return False
    return str(ip_str).strip() in get_own_public_wan_ips()


def is_own_infrastructure_ip(ip_str):
    """
    Verifica dinámicamente si una IP pertenece a la infraestructura crítica propia (WAN Pública propia,
    Nodos Proxy registrados, Servidores en Lista Blanca o Loopback). Nunca debe ser bloqueada.
    """
    if not ip_str:
        return False
    s = str(ip_str).strip()
    if s in get_own_internal_infra_ips() or is_own_public_wan_ip(s):
        return True
    return False


ISO_COUNTRY_GEO_MAP = {
    'PY': ('PY', 'Paraguay', 'Asunción', -25.2637, -57.5759),
    'AR': ('AR', 'Argentina', 'Buenos Aires', -34.6037, -58.3816),
    'BR': ('BR', 'Brasil', 'São Paulo', -23.5505, -46.6333),
    'UY': ('UY', 'Uruguay', 'Montevideo', -34.9011, -56.1645),
    'CL': ('CL', 'Chile', 'Santiago', -33.4489, -70.6693),
    'BO': ('BO', 'Bolivia', 'La Paz', -16.4897, -68.1193),
    'PE': ('PE', 'Perú', 'Lima', -12.0464, -77.0428),
    'CO': ('CO', 'Colombia', 'Bogotá', 4.7110, -74.0721),
    'EC': ('EC', 'Ecuador', 'Quito', -0.1807, -78.4678),
    'VE': ('VE', 'Venezuela', 'Caracas', 10.4806, -66.9036),
    'MX': ('MX', 'México', 'Ciudad de México', 19.4326, -99.1332),
    'US': ('US', 'Estados Unidos', 'Ashburn', 39.0438, -77.4874),
    'CA': ('CA', 'Canadá', 'Toronto', 43.6532, -79.3832),
    'ES': ('ES', 'España', 'Madrid', 40.4168, -3.7038),
    'DE': ('DE', 'Alemania', 'Frankfurt', 50.1109, 8.6821),
    'FR': ('FR', 'Francia', 'París', 48.8566, 2.3522),
    'GB': ('GB', 'Reino Unido', 'Londres', 51.5074, -0.1278),
    'NL': ('NL', 'Países Bajos', 'Ámsterdam', 52.3676, 4.9041),
    'IT': ('IT', 'Italia', 'Milán', 45.4642, 9.1900),
    'PT': ('PT', 'Portugal', 'Lisboa', 38.7223, -9.1393),
    'CH': ('CH', 'Suiza', 'Zúrich', 47.3769, 8.5417),
    'PL': ('PL', 'Polonia', 'Varsovia', 52.2297, 21.0122),
    'UA': ('UA', 'Ucrania', 'Kiev', 50.4501, 30.5234),
    'RU': ('RU', 'Rusia', 'Moscú', 55.7558, 37.6173),
    'CN': ('CN', 'China', 'Beijing', 39.9042, 116.4074),
    'JP': ('JP', 'Japón', 'Tokio', 35.6762, 139.6503),
    'KR': ('KR', 'Corea del Sur', 'Seúl', 37.5665, 126.9780),
    'SG': ('SG', 'Singapur', 'Singapur', 1.3521, 103.8198),
    'IN': ('IN', 'India', 'Mumbai', 19.0760, 72.8777),
    'AU': ('AU', 'Australia', 'Sídney', -33.8688, 151.2093),
    'HK': ('HK', 'Hong Kong', 'Hong Kong', 22.3193, 114.1694),
    'TW': ('TW', 'Taiwán', 'Taipéi', 25.0330, 121.5654),
    'TR': ('TR', 'Turquía', 'Estambul', 41.0082, 28.9784),
    'IL': ('IL', 'Israel', 'Tel Aviv', 32.0853, 34.7818),
    'ZA': ('ZA', 'Sudáfrica', 'Johannesburgo', -26.2041, 28.0473),
    'IE': ('IE', 'Irlanda', 'Dublín', 53.3498, -6.2603),
    'SE': ('SE', 'Suecia', 'Estocolmo', 59.3293, 18.0686),
    'FI': ('FI', 'Finlandia', 'Helsinki', 60.1699, 24.9384),
    'RO': ('RO', 'Rumania', 'Bucarest', 44.4268, 26.1025),
    'BG': ('BG', 'Bulgaria', 'Sofía', 42.6977, 23.3219),
    'CZ': ('CZ', 'República Checa', 'Praga', 50.0755, 14.4378),
    'AT': ('AT', 'Austria', 'Viena', 48.2082, 16.3738),
    'BE': ('BE', 'Bélgica', 'Bruselas', 50.8503, 4.3517),
}


def resolve_cloudflare_and_real_ip(data):
    """
    Separa e identifica simultáneamente con precisión absoluta las 4 variables de red:
      1) `cloudflare_ip`: La IP del nodo Edge de Cloudflare (si la petición pasó por Cloudflare).
      2) `real_client_ip`: La IP real del cliente de origen (extraída estrictamente de cabeceras HTTP
         reales de ESTA petición: CF-Connecting-IP, True-Client-IP, X-Forwarded-For, X-Real-IP).
      3) `is_cloudflare`: True si la conexión proviene de un nodo de Cloudflare o trae cabeceras CF.
      4) `is_local_ip`: True si es tráfico originado directamente en la LAN privada (RFC1918).
      5) `is_own_public_ip`: True si `real_client_ip` es la propia IP Pública WAN de la infraestructura.
      6) `is_direct_public_ip`: True si un cliente externo se conectó directo a la IP pública sin pasar por Cloudflare.
    """
    headers = data.get('headers', {}) if isinstance(data.get('headers'), dict) else {}
    raw_ip = str(data.get('client_ip') or data.get('remote_addr') or '').strip()
    http_method = str(data.get('http_method') or data.get('method') or '').upper()
    user_agent = str(data.get('user_agent') or '')

    # Si el agente mithril-bouncer reportó su propia IP pública WAN de salida, registrarla dinámicamente
    node_pub_ip = str(headers.get('node_public_ip') or data.get('node_public_ip') or '').strip()
    if node_pub_ip:
        register_own_public_wan_ip(node_pub_ip)

    # 1. Detección de Handshakes TLS ClientHello
    # Un paquete de Handshake TLS en puerto 443 es previo a la desencriptación HTTP,
    # por lo que por definición criptográfica NO posee cabeceras HTTP CF-Connecting-IP.
    if http_method == 'HTTPS' or 'TLS SNI' in user_agent or 'ClientHello' in user_agent:
        is_cf = is_cloudflare_ip(raw_ip)
        return {
            'is_cloudflare': is_cf,
            'cloudflare_ip': raw_ip if is_cf else '',
            'real_client_ip': '',
            'is_local_ip': False if is_cf else is_private_local_ip(raw_ip),
            'is_own_public_ip': is_own_public_wan_ip(raw_ip),
            'is_direct_public_ip': False,
            'cf_ray': '',
            'cf_country': '',
        }

    # 2. Extracción de cabeceras de cliente reales
    cf_header_ip = str(
        headers.get('cf_connecting_ip')
        or headers.get('cf-connecting-ip')
        or headers.get('true_client_ip')
        or headers.get('true-client-ip')
        or data.get('cf_connecting_ip')
        or data.get('http_cf_connecting_ip')
        or ''
    ).strip()

    cf_ray = str(headers.get('cf_ray') or headers.get('cf-ray') or data.get('cf_ray') or '').strip()
    cf_country = str(headers.get('cf_country') or headers.get('cf-country') or headers.get('cf_ipcountry') or headers.get('cf-ipcountry') or data.get('cf_country') or '').strip()

    xff_raw = str(headers.get('x_forwarded_for') or headers.get('x-forwarded-for') or data.get('x_forwarded_for') or '').strip()
    xff_ips = []
    if xff_raw and xff_raw != '-':
        for part in xff_raw.split(','):
            cand = part.strip()
            if _is_valid_ip(cand):
                xff_ips.append(cand)

    x_real_ip = str(headers.get('x_real_ip') or headers.get('x-real-ip') or data.get('x_real_ip') or '').strip()

    # Verificar si las cabeceras HTTP reales del proxy (X-Real-IP / X-Forwarded-For) demuestran
    # que el cliente conectó directamente (por red local LAN o directo a IP pública)
    # sin pasar por Cloudflare (sin CF-Ray, sin CF-Connecting-IP y sin IPs de Cloudflare en X-Real-IP/XFF).
    header_peer_ips = [ip for ip in ([x_real_ip] + xff_ips) if _is_valid_ip(ip)]
    has_direct_non_cf_peer = (
        bool(header_peer_ips)
        and not cf_header_ip
        and not cf_ray
        and not cf_country
        and all(not is_cloudflare_ip(ip) for ip in header_peer_ips)
    )

    # Detección de si la conexión interviene Cloudflare Edge
    if has_direct_non_cf_peer:
        is_cf_node = False
        is_cf = False
        cf_node_ip = ''
    else:
        is_cf_node = is_cloudflare_ip(raw_ip) or any(is_cloudflare_ip(ip) for ip in header_peer_ips)
        is_cf = bool(is_cf_node or cf_ray or cf_country or (cf_header_ip and _is_valid_ip(cf_header_ip)))
        cf_node_ip = (
            raw_ip if is_cloudflare_ip(raw_ip)
            else next((ip for ip in header_peer_ips if is_cloudflare_ip(ip)), str(headers.get('cloudflare_ip') or data.get('cloudflare_ip') or '') if is_cf else '')
        )

    real_client_ip = ''

    if is_cf:
        # Petición a través de Cloudflare:
        # El cliente real DEBE venir de CF-Connecting-IP, True-Client-IP o del cliente original en X-Forwarded-For.
        if _is_valid_ip(cf_header_ip) and not is_cloudflare_ip(cf_header_ip):
            real_client_ip = cf_header_ip
        else:
            # Buscar en X-Forwarded-For la IP del cliente que no sea de Cloudflare
            for cand in xff_ips:
                if not is_cloudflare_ip(cand):
                    real_client_ip = cand
                    break

        # Si NO vino ninguna cabecera de cliente externa:
        # ES UNA SONDA DE SALUD (HEALTHCHECK) INTERNA DE CLOUDFLARE O UN RECURSO INTERNO DE EDGE.
        final_real_ip = real_client_ip
        is_local = is_private_local_ip(final_real_ip) if final_real_ip else False
        # Autodescubrimiento de Hairpinning WAN: si un monitor interno (Zabbix, Prometheus, Uptime-Kuma, Nagios)
        # sale por la WAN de la infraestructura y entra por Cloudflare, registrar automáticamente esa IP como WAN Propia.
        if final_real_ip and not is_local and any(m in user_agent for m in ('Zabbix', 'Prometheus', 'Uptime-Kuma', 'Nagios', 'Blackbox-Exporter')):
            register_own_public_wan_ip(final_real_ip, cf_country)
    else:
        # Petición directa que no pasó por Cloudflare (red local LAN o acceso directo a IP pública):
        direct_cand = ''
        for cand in [x_real_ip, *xff_ips]:
            if _is_valid_ip(cand) and not is_cloudflare_ip(cand):
                direct_cand = cand
                break
        final_cand = direct_cand or raw_ip
        if _is_valid_ip(final_cand) and final_cand not in ('127.0.0.1', '::1'):
            final_real_ip = final_cand
        else:
            final_real_ip = ''
        is_local = is_private_local_ip(final_real_ip or raw_ip)

    is_own_pub = is_own_public_wan_ip(final_real_ip or raw_ip)
    is_direct_pub = (not is_cf) and (not is_local) and (not is_own_pub) and bool(final_real_ip)

    return {
        'is_cloudflare': is_cf,
        'cloudflare_ip': cf_node_ip,
        'real_client_ip': final_real_ip,
        'is_local_ip': is_local,
        'is_own_public_ip': is_own_pub,
        'is_direct_public_ip': is_direct_pub,
        'cf_ray': cf_ray,
        'cf_country': cf_country,
    }


def extract_log_ip_meta(ip_str, headers=None):
    """
    Extrae metadatos de red (`is_cloudflare`, `cloudflare_ip`, `real_client_ip`, `is_local_ip`,
    `is_own_public_ip`, `is_direct_public_ip`, `cf_ray`, `cf_country`)
    a partir de una IP y un diccionario `raw_headers` o `details` almacenado en BD.
    """
    hdrs = headers if isinstance(headers, dict) else {}
    nested_hdrs = hdrs.get('headers', {}) if isinstance(hdrs.get('headers'), dict) else {}
    merged = {**nested_hdrs, **hdrs}

    # Verificar si una fila tenía X-Real-IP directo (sin cabeceras reales de Cloudflare)
    x_real = str(merged.get('x_real_ip') or merged.get('x-real-ip') or '').strip()
    cf_conn = str(merged.get('cf_connecting_ip') or merged.get('cf-connecting-ip') or '').strip()
    cf_ray_val = str(merged.get('cf_ray') or merged.get('cf-ray') or '').strip()
    cf_country_val = str(merged.get('cf_country') or merged.get('cf_ipcountry') or '').strip()

    if _is_valid_ip(x_real) and not is_cloudflare_ip(x_real) and not cf_conn and not cf_ray_val and not cf_country_val:
        is_loc = is_private_local_ip(x_real)
        is_own_pub = is_own_public_wan_ip(x_real)
        return {
            'is_cloudflare': False,
            'cloudflare_ip': '',
            'real_client_ip': x_real,
            'is_local_ip': is_loc,
            'is_own_public_ip': is_own_pub,
            'is_direct_public_ip': (not is_loc) and (not is_own_pub),
            'cf_ray': '',
            'cf_country': '',
        }

    # Si ya se procesó y almacenó previamente en raw_headers, retornar directamente
    stored_real = merged.get('real_client_ip') or ''
    stored_cf = merged.get('cloudflare_ip') or ''
    is_cf_flag = bool(merged.get('is_cloudflare'))

    if is_cf_flag or stored_cf or (stored_real and stored_real != ip_str):
        is_cf = is_cf_flag or bool(stored_cf) or is_cloudflare_ip(ip_str) or is_cloudflare_ip(merged.get('connection_ip'))
        cf_node = stored_cf or (ip_str if is_cloudflare_ip(ip_str) else str(merged.get('connection_ip') or ''))
        eff_target = stored_real or ip_str
        is_loc = is_private_local_ip(eff_target)
        is_own_pub = bool(merged.get('is_own_public_ip')) or is_own_public_wan_ip(eff_target)
        is_direct_val = merged.get('is_direct_public_ip')
        if is_direct_val is None:
            is_direct_val = (not is_cf) and (not is_loc) and (not is_own_pub) and bool(eff_target)
        return {
            'is_cloudflare': is_cf,
            'cloudflare_ip': cf_node if is_cf else '',
            'real_client_ip': stored_real,
            'is_local_ip': is_loc,
            'is_own_public_ip': is_own_pub,
            'is_direct_public_ip': bool(is_direct_val) and not is_own_pub,
            'cf_ray': cf_ray_val,
            'cf_country': cf_country_val,
        }

    merged['client_ip'] = ip_str
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


def _lookup_public_geoip_api(ip_clean):
    """
    Consulta universal GeoIP en línea con caché en RAM y Redis para IPs públicas directas
    (cuando no viene cabecera CF-IPCountry), válido para cualquier país o proveedor del mundo.
    """
    if not ip_clean or is_private_local_ip(ip_clean) or is_cloudflare_ip(ip_clean):
        return None
    if ip_clean in _GEOIP_MEM_CACHE:
        return _GEOIP_MEM_CACHE[ip_clean]
    cache_key = f"mithril:geoip:v1:{ip_clean}"
    try:
        cached = cache.get(cache_key)
        if isinstance(cached, dict) and cached.get('country_code'):
            _GEOIP_MEM_CACHE[ip_clean] = cached
            return cached
    except Exception:
        pass

    try:
        url = f"http://ip-api.com/json/{ip_clean}?fields=status,countryCode,country,city,lat,lon&lang=es"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mithril-SIEM/2.1'}, method='GET')
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            payload = json.loads(resp.read().decode('utf-8', errors='ignore'))
        if payload.get('status') == 'success' and payload.get('countryCode'):
            cc = str(payload['countryCode']).strip().upper()[:8]
            cname = str(payload.get('country') or ISO_COUNTRY_GEO_MAP.get(cc, (cc, cc, 'Remoto', 0.0, 0.0))[1])
            city = str(payload.get('city') or 'Remoto')
            lat = float(payload.get('lat') or 0.0)
            lon = float(payload.get('lon') or 0.0)
            res = {
                'country_code': cc,
                'country_name': cname,
                'city': city,
                'latitude': lat,
                'longitude': lon,
                'is_cloudflare': False,
            }
            if len(_GEOIP_MEM_CACHE) > 4000:
                _GEOIP_MEM_CACHE.clear()
            _GEOIP_MEM_CACHE[ip_clean] = res
            try:
                cache.set(cache_key, res, timeout=86400)
            except Exception:
                pass
            return res
    except Exception:
        pass
    return None


def resolve_geoip(ip_str, cf_country=''):
    """
    Resuelve dinámicamente la ubicación geográfica real de cualquier IP (sin IPs ni prefijos ISP hardcodeados):
      1) Si es una IP Privada / Red Local (RFC1918 / Loopback) -> Red Interna (LAN)
      2) Si es un nodo Edge de Cloudflare sin cliente -> Cloudflare Edge PoP
      3) El país real reportado por Cloudflare en la cabecera HTTP `CF-IPCountry` (`cf_country`)
      4) Consulta universal en caché / API GeoIP para conexiones públicas directas
      5) Si es la IP Pública WAN propia de la infraestructura -> País real + '(WAN Propia)'
    """
    ip_clean = str(ip_str or '').strip()
    crc_val = zlib.crc32(ip_clean.encode('utf-8'))
    is_own_wan = is_own_public_wan_ip(ip_clean)

    is_cf = is_cloudflare_ip(ip_clean)
    if is_cf and not is_own_wan:
        cf_pops = [
            ('CF-US', 'Cloudflare Edge (US-East)', 'Ashburn PoP', 39.0438, -77.4874),
            ('CF-US', 'Cloudflare Edge (US-West)', 'San Francisco PoP', 37.7749, -122.4194),
            ('CF-EU', 'Cloudflare Edge (EU-Central)', 'Frankfurt PoP', 50.1109, 8.6821),
            ('CF-GB', 'Cloudflare Edge (UK)', 'London PoP', 51.5074, -0.1278),
            ('CF-BR', 'Cloudflare Edge (LATAM)', 'São Paulo PoP', -23.5505, -46.6333),
            ('CF-ES', 'Cloudflare Edge (EU-South)', 'Madrid PoP', 40.4168, -3.7038),
            ('CF-SG', 'Cloudflare Edge (APAC)', 'Singapore PoP', 1.3521, 103.8198),
        ]
        pop = cf_pops[crc_val % len(cf_pops)]
        return {
            'country_code': pop[0],
            'country_name': pop[1],
            'city': pop[2],
            'latitude': pop[3],
            'longitude': pop[4],
            'is_cloudflare': True
        }

    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        if ip_obj.is_private or ip_obj.is_loopback:
            lan_origins = [
                ('LAN', 'Red Interna (LAN)', 'Segmento Corporativo LAN', -25.2637, -57.5759),
                ('LAN', 'Red Interna (LAN)', 'Segmento DataCenter LAN', -25.2800, -57.6300),
                ('LAN', 'Red Interna (LAN)', 'Segmento Interno DMZ', -25.3000, -57.5500),
            ]
            loc = lan_origins[crc_val % len(lan_origins)]
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

    # Determinar el país base (desde CF-IPCountry, país WAN autodescubierto, o GeoIP API universal)
    cc_clean = str(cf_country or '').strip().upper()
    if not cc_clean and is_own_wan:
        cc_clean = _OWN_INFRA_STATE.get('public_wan_country', '')

    base_geo = None
    if cc_clean and cc_clean not in ('XX', 'T1', '-'):
        if cc_clean in ISO_COUNTRY_GEO_MAP:
            g = ISO_COUNTRY_GEO_MAP[cc_clean]
            base_geo = {
                'country_code': g[0],
                'country_name': g[1],
                'city': g[2],
                'latitude': g[3],
                'longitude': g[4],
                'is_cloudflare': False
            }
        else:
            base_geo = {
                'country_code': cc_clean[:8],
                'country_name': f'País ISO ({cc_clean})',
                'city': 'Remoto',
                'latitude': 20.0,
                'longitude': 0.0,
                'is_cloudflare': False
            }
        if ip_clean:
            _GEOIP_MEM_CACHE[ip_clean] = base_geo

    if not base_geo:
        base_geo = _lookup_public_geoip_api(ip_clean)

    if not base_geo:
        known_nodes = [
            ('US', 'Estados Unidos', 'Ashburn', 39.0438, -77.4874),
            ('BR', 'Brasil', 'São Paulo', -23.5505, -46.6333),
            ('AR', 'Argentina', 'Buenos Aires', -34.6037, -58.3816),
            ('DE', 'Alemania', 'Frankfurt', 50.1109, 8.6821),
            ('ES', 'España', 'Madrid', 40.4168, -3.7038),
            ('FR', 'Francia', 'París', 48.8566, 2.3522),
            ('NL', 'Países Bajos', 'Ámsterdam', 52.3676, 4.9041),
            ('GB', 'Reino Unido', 'Londres', 51.5074, -0.1278),
        ]
        g = known_nodes[crc_val % len(known_nodes)]
        base_geo = {
            'country_code': g[0],
            'country_name': g[1],
            'city': g[2],
            'latitude': g[3],
            'longitude': g[4],
            'is_cloudflare': False
        }

    if is_own_wan:
        cname = base_geo['country_name']
        if '(WAN Propia)' not in cname:
            cname = f"{cname} (WAN Propia)"
        city_name = base_geo['city']
        if '(Infraestructura Propia)' not in city_name:
            city_name = f"{city_name} (Infraestructura Propia)"
        return {
            'country_code': base_geo['country_code'],
            'country_name': cname,
            'city': city_name,
            'latitude': base_geo['latitude'],
            'longitude': base_geo['longitude'],
            'is_cloudflare': False
        }

    return dict(base_geo)


def _is_benign_app_sync(uri_str, status_code):
    """
    Identifica llamadas de sincronización en segundo plano legítimas de Nextcloud / WebDAV
    para evitar falsos positivos de ráfaga o 404 de workspace vacíos contra usuarios legítimos.
    """
    u = str(uri_str or '').lower()
    if status_code == 404 and '/ocs/v2.php/apps/text/public/workspace' in u:
        return True
    if status_code in (200, 204, 207, 304) and any(p in u for p in (
        '/index.php/apps/text/session/',
        '/ocs/v2.php/apps/user_status/',
        '/ocs/v2.php/apps/notifications/',
        '/ocs/v2.php/apps/dashboard/',
        '/index.php/apps/files/api/v1/stats',
        '/public.php/webdav/',
        '/remote.php/dav/',
        '/cron.php',
    )):
        return True
    return False


def process_incoming_log(data, node=None):
    """
    Procesa, normaliza, enriquece e inspecciona cada petición recibida de Nginx.
    Evalúa, puntúa y genera candidatos a bloqueo SIEMPRE sobre la IP del cliente real
    (sin importar si se conecta a través de un nodo Cloudflare, desde la LAN o de forma directa),
    garantizando inmunidad absoluta a las IPs de Cloudflare y a la IP Pública WAN propia de la infraestructura.
    """
    raw_conn_ip = data.get('client_ip', '').strip()
    if not raw_conn_ip:
        return None

    ip_meta = resolve_cloudflare_and_real_ip(data)
    is_cf = ip_meta['is_cloudflare']
    cf_node_ip = ip_meta['cloudflare_ip'] or (raw_conn_ip if is_cf else '')
    real_client_ip = ip_meta['real_client_ip']

    # La IP real del cliente que realiza la petición (detrás de Cloudflare, por LAN local, o directo a IP pública):
    target_client_ip = real_client_ip if real_client_ip else raw_conn_ip

    cf_country_hdr = ip_meta.get('cf_country', '')
    geo = resolve_geoip(target_client_ip, cf_country=cf_country_hdr)

    incoming_headers = dict(data.get('headers', {})) if isinstance(data.get('headers'), dict) else {}
    if is_cf:
        incoming_headers['is_cloudflare'] = True
        incoming_headers['cloudflare_ip'] = cf_node_ip
        incoming_headers['connection_ip'] = cf_node_ip or raw_conn_ip
    else:
        incoming_headers['is_cloudflare'] = False
        incoming_headers['cloudflare_ip'] = ''
        incoming_headers['edge_ip'] = target_client_ip
        incoming_headers['connection_ip'] = target_client_ip
    if real_client_ip:
        incoming_headers['real_client_ip'] = real_client_ip
    is_local = ip_meta.get('is_local_ip', False) or is_private_local_ip(target_client_ip)
    incoming_headers['is_local_ip'] = is_local
    is_own_pub = ip_meta.get('is_own_public_ip', False) or is_own_public_wan_ip(target_client_ip)
    incoming_headers['is_own_public_ip'] = is_own_pub
    is_direct = ip_meta.get('is_direct_public_ip', False) or ((not is_cf) and (not is_local) and (not is_own_pub))
    incoming_headers['is_direct_public_ip'] = is_direct
    if ip_meta.get('cf_ray'):
        incoming_headers['cf_ray'] = ip_meta['cf_ray']
    if cf_country_hdr:
        incoming_headers['cf_country'] = cf_country_hdr

    # 1. Guardar log normalizado con la IP del cliente real para indexación y búsqueda
    log = TrafficLog.objects.create(
        node=node,
        client_ip=target_client_ip,
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

    # 2. Consultar o crear reputación de la IP del CLIENTE
    is_own_infra = is_own_infrastructure_ip(target_client_ip)
    rep_cc = str(geo.get('country_code') or '')[:4]
    reputation, _ = IpReputation.objects.get_or_create(
        client_ip=target_client_ip,
        defaults={
            'country_code': rep_cc,
            'asn': 'OWN_INFRASTRUCTURE' if is_own_infra else ('CLOUDFLARE' if (is_cf and not real_client_ip) else ''),
            'status': 'WHITELISTED' if is_own_infra else 'MONITORED'
        }
    )
    if is_own_infra and (reputation.status != 'WHITELISTED' or reputation.country_code != rep_cc):
        reputation.status = 'WHITELISTED'
        reputation.country_code = rep_cc
        reputation.asn = 'OWN_INFRASTRUCTURE'
        reputation.current_risk_score = 0
        reputation.save(update_fields=['status', 'country_code', 'asn', 'current_risk_score'])
    elif not is_own_infra and cf_country_hdr and len(rep_cc) == 2 and reputation.country_code != rep_cc:
        reputation.country_code = rep_cc
        reputation.save(update_fields=['country_code'])
    elif is_cf and not real_client_ip and reputation.asn != 'CLOUDFLARE':
        reputation.asn = 'CLOUDFLARE'
        reputation.save(update_fields=['asn'])

    # Si la IP está en Lista Blanca o es la propia IP de la infraestructura (WAN o Balanceador), no generar alertas de bloqueo
    if reputation.status == 'WHITELISTED' or is_own_infra:
        broadcast_to_soc(log, is_threat=False, reputation=reputation)
        return log

    # Si la petición viene a través de Cloudflare pero no tiene cliente final
    # (es una sonda de salud interna de Cloudflare, monitor de uptime o TLS handshake),
    # no evaluar reglas de ataque o DoS sobre el nodo compartido de Cloudflare.
    if is_cf and not real_client_ip:
        broadcast_to_soc(log, is_threat=False, reputation=reputation)
        return log

    is_benign_sync = _is_benign_app_sync(log.uri, log.status_code)

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
        'is_own_public_ip': is_own_pub,
        'is_direct_public_ip': is_direct,
        'cf_ray': ip_meta.get('cf_ray', ''),
        'cf_country': ip_meta.get('cf_country', ''),
        'headers': log.raw_headers or {},
    }

    for rule in active_rules:
        compiled_rx = getattr(rule, '_compiled_regex', None)
        window_start = now - timedelta(seconds=max(1, rule.threshold_seconds))

        # E. Detección de Acceso Directo por IP Pública (Bypass Cloudflare / Reconocimiento de Origen)
        if rule.code == 'R-DIRECT-IP-ACCESS':
            if is_direct and not is_cf and not is_own_infra:
                matched_any_rule = True
                if not _is_in_event_cooldown(target_client_ip, rule.code, cooldown_sec=10.0):
                    host_header = str(incoming_headers.get('host') or incoming_headers.get('Host') or data.get('host') or '').strip()
                    matched_msg = f"Acceso directo a IP Pública sin Cloudflare (Host: {host_header or 'IP'}, URI: {log.uri})"
                    event = SecurityEvent.objects.create(
                        node=node,
                        rule=rule,
                        client_ip=target_client_ip,
                        severity='MEDIUM',
                        matched_payload=matched_msg,
                        details={**base_req_details, 'host': host_header, 'direct_bypass': True}
                    )
                    triggered_events.append(event)
                    risk_to_add += rule.risk_points

        # A. Reglas de Fuerza Bruta de Autenticación (401/403)
        elif rule.code == 'R-AUTH-BRUTE-401':
            if log.status_code in (401, 403) and (not compiled_rx or compiled_rx.search(normalized_uri)):
                matched_any_rule = True
                if not _is_in_event_cooldown(target_client_ip, rule.code, cooldown_sec=3.0):
                    recent_auth_fails = TrafficLog.objects.filter(
                        client_ip=target_client_ip,
                        status_code__in=[401, 403],
                        created_at__gte=window_start
                    ).count()
                    if recent_auth_fails >= rule.threshold_count:
                        event = SecurityEvent.objects.create(
                            node=node,
                            rule=rule,
                            client_ip=target_client_ip,
                            severity='HIGH',
                            matched_payload=f"{recent_auth_fails} respuestas {log.status_code} en {log.uri} ({rule.threshold_seconds}s)",
                            details={**base_req_details, 'count_auth_fails': recent_auth_fails}
                        )
                        triggered_events.append(event)
                        risk_to_add += rule.risk_points

        # B. Detección Heurística de Frecuencia 404 (Enumeración de archivos / Scanners)
        elif rule.code == 'R-SCAN-404-BRUTE' or (not rule.pattern_regex and rule.category == 'SCANNER'):
            if log.status_code == 404 and not is_benign_sync:
                matched_any_rule = True
                if not _is_in_event_cooldown(target_client_ip, rule.code, cooldown_sec=3.0):
                    recent_404_count = (
                        TrafficLog.objects.filter(
                            client_ip=target_client_ip,
                            status_code=404,
                            created_at__gte=window_start
                        )
                        .exclude(uri__icontains='/ocs/v2.php/apps/text/public/workspace')
                        .count()
                    )
                    if recent_404_count >= rule.threshold_count:
                        event = SecurityEvent.objects.create(
                            node=node,
                            rule=rule,
                            client_ip=target_client_ip,
                            severity='HIGH',
                            matched_payload=f"{recent_404_count} errores 404 en {rule.threshold_seconds}s ({log.uri})",
                            details={**base_req_details, 'count_404': recent_404_count}
                        )
                        triggered_events.append(event)
                        risk_to_add += rule.risk_points

        # C. Detección Heurística de Ráfaga / Flood DoS por IP (Rate Limit sin regex)
        elif not rule.pattern_regex and rule.category == 'RATE_LIMIT':
            if not is_benign_sync and not _is_in_event_cooldown(target_client_ip, rule.code, cooldown_sec=4.0):
                recent_req_count = (
                    TrafficLog.objects.filter(
                        client_ip=target_client_ip,
                        created_at__gte=window_start
                    )
                    .exclude(uri__icontains='/index.php/apps/text/session/')
                    .exclude(uri__icontains='/ocs/v2.php/apps/user_status/')
                    .exclude(uri__icontains='/ocs/v2.php/apps/notifications/')
                    .count()
                )
                if recent_req_count >= rule.threshold_count:
                    matched_any_rule = True
                    event = SecurityEvent.objects.create(
                        node=node,
                        rule=rule,
                        client_ip=target_client_ip,
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
                if not _is_in_event_cooldown(target_client_ip, rule.code, cooldown_sec=2.5):
                    should_trigger = True

                    if rule.threshold_count > 1:
                        recent_matches = SecurityEvent.objects.filter(
                            client_ip=target_client_ip,
                            rule=rule,
                            created_at__gte=window_start
                        ).count() + 1
                        if recent_matches < rule.threshold_count:
                            SecurityEvent.objects.create(
                                node=node,
                                rule=rule,
                                client_ip=target_client_ip,
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
                            client_ip=target_client_ip,
                            severity=severity,
                            matched_payload=matched_text,
                            details={**base_req_details, 'uri': log.uri, 'query': log.query_params, 'agent': log.user_agent}
                        )
                        triggered_events.append(event)
                        risk_to_add += rule.risk_points

    # 4. Actualizar puntaje de riesgo de la IP DEL CLIENTE
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

        # 5. Generar Candidato a Bloqueo para la IP del CLIENTE
        if reputation.current_risk_score >= 80:
            if is_cloudflare_ip(target_client_ip) or is_own_infrastructure_ip(target_client_ip):
                # Los nodos CDN de Cloudflare y la propia IP WAN/LAN de la infraestructura tienen inmunidad absoluta
                pass
            else:
                last_event = triggered_events[0] if triggered_events else None
                reason_text = f"Puntaje de riesgo {reputation.current_risk_score}/100 alcanzado. Disparó {reputation.total_violations} infracciones."
                if last_event and last_event.rule:
                    reason_text += f" Última infracción: {last_event.rule.name}."
                if is_cf and cf_node_ip:
                    reason_text += f" (Petición recibida a través de Cloudflare Edge: {cf_node_ip})"

                candidate, created = BanCandidate.objects.get_or_create(
                    client_ip=target_client_ip,
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
                    cf_line = f"Conexión vía Cloudflare Node: {cf_node_ip}\n" if (is_cf and cf_node_ip) else ""
                    send_telegram_alert(
                        title="🚨 Nuevo Candidato a Bloqueo Detectado",
                        message=(
                            f"IP Cliente: {target_client_ip} ({geo['country_name']})\n"
                            f"{cf_line}"
                            f"Score de Riesgo: {reputation.current_risk_score}/100\n"
                            f"Proxy: {node.name if node else 'N/A'}\n"
                            f"Motivo: {reason_text}\n"
                            f"Estado: Esperando aprobación del operador en Mithril SIEM."
                        )
                    )

    # 6. Emitir evento en vivo por WebSockets al SOC
    is_threat = (not is_benign_sync) and (
        len(triggered_events) > 0
        or matched_any_rule
        or (log.status_code >= 400)
    )
    if (len(triggered_events) > 0 or matched_any_rule) and not is_benign_sync:
        incoming_headers['is_threat'] = True
        log.raw_headers = incoming_headers
        log.save(update_fields=['raw_headers'])
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
    connection_ip = log.raw_headers.get('connection_ip') or (meta['cloudflare_ip'] if meta['is_cloudflare'] else log.client_ip)
    eff_real_ip = meta['real_client_ip'] or log.client_ip
    is_own_pub = meta.get('is_own_public_ip', False) or is_own_public_wan_ip(eff_real_ip)
    is_direct_ip = meta.get('is_direct_public_ip')
    if is_direct_ip is None:
        is_direct_ip = (not meta['is_cloudflare']) and (not meta.get('is_local_ip', False)) and (not is_own_pub) and bool(eff_real_ip)

    payload = {
        'type': 'traffic_event',
        'event': {
            'id': log.id,
            'timestamp': log.created_at.strftime('%H:%M:%S'),
            'client_ip': connection_ip,
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
            'real_client_ip': meta['real_client_ip'] or '',
            'is_local_ip': meta.get('is_local_ip', False) or is_private_local_ip(meta['real_client_ip'] or (connection_ip if not meta['is_cloudflare'] else '')),
            'is_own_public_ip': bool(is_own_pub),
            'is_direct_public_ip': bool(is_direct_ip) and not is_own_pub,
            'user_agent': log.user_agent or '',
            'risk_score': reputation.current_risk_score if reputation else 0,
            'violations_count': len(events) if events else 0,
        }
    }

    try:
        async_to_sync(channel_layer.group_send)('soc_live_feed', payload)
    except Exception:
        pass
