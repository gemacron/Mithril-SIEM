import re
import time
import urllib.parse
import ipaddress
from datetime import timedelta
from django.utils import timezone
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
        # Reemplazar comentarios SQL inline /**/ usados para evadir UNION/**/SELECT
        cleaned = re.sub(r'/\*.*?\*/', ' ', decoded_twice)
        return f"{raw_text} {decoded_once} {cleaned}"
    except Exception:
        return str(raw_text)

def resolve_geoip(ip_str):
    """
    Resuelve la ubicación geográfica aproximada de la IP.
    En un entorno de producción puede leer de MaxMind GeoLite2-City.mmdb.
    Aquí provee resolución ultra-rápida y determinista de prueba con coordenadas.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback:
            return {
                'country_code': 'LO',
                'country_name': 'Red Local',
                'city': 'SOC Base Local',
                'latitude': -34.6037,
                'longitude': -58.3816
            }
    except Exception:
        pass

    # Tabla hash rápida de muestra para pruebas y visualización en el mapa 2D
    # (En producción esto enlaza con GeoLite2-City.mmdb)
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
        'longitude': geo[4]
    }


def process_incoming_log(data, node=None):
    """
    Procesa, normaliza, enriquece e inspecciona cada petición recibida de Nginx
    """
    client_ip = data.get('client_ip', '').strip()
    if not client_ip:
        return None

    geo = resolve_geoip(client_ip)

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
        raw_headers=data.get('headers', {})
    )

    if node:
        ProxyNode.objects.filter(id=node.id).update(total_logs_processed=F('total_logs_processed') + 1)

    # 2. Consultar o crear reputación de la IP
    reputation, _ = IpReputation.objects.get_or_create(
        client_ip=client_ip,
        defaults={
            'country_code': geo['country_code'],
            'status': 'MONITORED'
        }
    )

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
                send_telegram_alert(
                    title="🚨 Nuevo Candidato a Bloqueo Detectado",
                    message=(
                        f"IP: {client_ip} ({geo['country_name']})\n"
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
            'risk_score': reputation.current_risk_score if reputation else 0,
            'violations_count': len(events) if events else 0,
        }
    }

    try:
        async_to_sync(channel_layer.group_send)('soc_live_feed', payload)
    except Exception:
        pass
