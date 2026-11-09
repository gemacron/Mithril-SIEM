#!/usr/bin/env python3
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mithril_siem.settings')
django.setup()

from apps.detection.models import TrafficLog
from django.db.models import Count
from datetime import timedelta
from django.utils import timezone

now = timezone.now()
total = TrafficLog.objects.count()
last_24h = TrafficLog.objects.filter(created_at__gte=now - timedelta(hours=24)).count()

print(f"Total registros históricos: {total}")
print(f"Registros últimas 24 horas: {last_24h}")

print("\n--- TOP USER-AGENTS (Últimas 24h) ---")
for item in TrafficLog.objects.filter(created_at__gte=now - timedelta(hours=24)).values('user_agent').annotate(c=Count('id')).order_by('-c')[:10]:
    print(f"[{item['c']:>6}] {repr(item['user_agent'][:90])}")

print("\n--- TOP VHOST / URI (Últimas 24h) ---")
for item in TrafficLog.objects.filter(created_at__gte=now - timedelta(hours=24)).values('uri').annotate(c=Count('id')).order_by('-c')[:10]:
    print(f"[{item['c']:>6}] {repr(item['uri'][:90])}")

print("\n--- EJEMPLOS CON 'real_client_ip' REGISTRADA (Últimas 24h) ---")
with_real = TrafficLog.objects.filter(
    created_at__gte=now - timedelta(hours=24)
).exclude(raw_headers__real_client_ip__isnull=True).exclude(raw_headers__real_client_ip='')[:10]

if not with_real.exists():
    print("Ninguno en las últimas 24h. Buscando en todo el historial...")
    with_real = TrafficLog.objects.exclude(raw_headers__real_client_ip__isnull=True).exclude(raw_headers__real_client_ip='').order_by('-id')[:10]

for l in with_real:
    hdrs = l.raw_headers if isinstance(l.raw_headers, dict) else {}
    real_ip = hdrs.get('real_client_ip')
    conn_ip = hdrs.get('connection_ip') or l.client_ip
    print(f"ID {l.id} | Fecha {l.created_at} | Conexión: {conn_ip} | Real: {real_ip} | Método: {l.http_method} | URI: {l.uri} | UA: {l.user_agent[:40]}")

print("\n--- ÚLTIMAS 5 PETICIONES CRUDAS CON HEADERS ---")
for l in TrafficLog.objects.order_by('-id')[:5]:
    print(f"ID {l.id} | Método: {l.http_method} | URI: {l.uri} | UA: {l.user_agent} | Headers: {l.raw_headers}")

