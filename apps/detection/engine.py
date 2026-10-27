import re
import ipaddress
from datetime import timedelta
from django.utils import timezone
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from .models import TrafficLog, SecurityRule, SecurityEvent
from apps.mitigation.models import IpReputation, BanCandidate, ActiveBan
from apps.notifications.services import send_telegram_alert

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
        node.total_logs_processed += 1
        node.save(update_fields=['total_logs_processed'])

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

    # 3. Motor de Detección Heurística y Reglas
    now = timezone.now()
    active_rules = SecurityRule.objects.filter(is_active=True)
    full_target_string = f"{log.uri} {log.query_params} {log.user_agent}"

    risk_to_add = 0
    triggered_events = []

    for rule in active_rules:
        # A. Coincidencia por Regex
        if rule.pattern_regex:
            match = re.search(rule.pattern_regex, full_target_string, re.IGNORECASE)
            if match:
                severity = 'HIGH' if rule.risk_points >= 50 else 'MEDIUM'
                event = SecurityEvent.objects.create(
                    node=node,
                    rule=rule,
                    client_ip=client_ip,
                    severity=severity,
                    matched_payload=match.group(0),
                    details={'uri': log.uri, 'query': log.query_params, 'agent': log.user_agent}
                )
                triggered_events.append(event)
                risk_to_add += rule.risk_points

        # B. Detección de Frecuencia 404 (Enumeración / Scanners)
        elif rule.code == 'R-SCAN-404-BRUTE' and log.status_code == 404:
            window_start = now - timedelta(seconds=rule.threshold_seconds)
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
                    matched_payload=f"{recent_404_count} errores 404 en {rule.threshold_seconds}s",
                    details={'count_404': recent_404_count}
                )
                triggered_events.append(event)
                risk_to_add += rule.risk_points

    # 4. Actualizar puntaje de riesgo de la IP
    if risk_to_add > 0:
        reputation.current_risk_score = min(100, reputation.current_risk_score + risk_to_add)
        reputation.total_violations += len(triggered_events)
        reputation.last_seen_at = now
        reputation.last_evaluated_at = now

        if reputation.current_risk_score >= 80:
            reputation.status = 'PENDING_BAN'
        elif reputation.current_risk_score >= 40:
            reputation.status = 'SUSPICIOUS'

        reputation.save()

        # 5. Generar Candidato a Bloqueo (Dry-Run / Autoban Simulado)
        if reputation.current_risk_score >= 80:
            last_event = triggered_events[0] if triggered_events else None
            reason_text = f"Puntaje de riesgo {reputation.current_risk_score}/100 alcanzado. Disparó {len(triggered_events)} reglas."
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
                candidate.save(update_fields=['accumulated_score', 'suggested_reason'])

            # Notificar vía Telegram si es un candidato nuevo
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

    # 6. Emitir evento en vivo por WebSockets al SOC
    is_threat = len(triggered_events) > 0
    broadcast_to_soc(log, is_threat=is_threat, reputation=reputation, events=triggered_events)

    return log


def broadcast_to_soc(log, is_threat=False, reputation=None, events=None):
    """
    Envía por WebSocket el evento para actualizar el mapa 2D y el Live Feed del operador
    """
    channel_layer = get_channel_layer()
    if not channel_layer:
        return

    payload = {
        'type': 'traffic_event',
        'event': {
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

    async_to_sync(channel_layer.group_send)('soc_live_feed', payload)
