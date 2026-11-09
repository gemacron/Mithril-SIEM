import os, sys, django
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mithril_siem.settings')
django.setup()

from apps.detection.models import TrafficLog
from django.utils import timezone
from datetime import timedelta
from apps.detection.engine import is_private_local_ip

now = timezone.now()
qs = TrafficLog.objects.filter(
    created_at__gte=now - timedelta(hours=3)
).exclude(raw_headers__real_client_ip__isnull=True).exclude(raw_headers__real_client_ip='').order_by('-id')

print(f"Total peticiones con IP real en las últimas 3 horas: {qs.count()}")
count_non_bot = 0
for l in qs:
    hdrs = l.raw_headers or {}
    real_ip = hdrs.get('real_client_ip')
    if is_private_local_ip(real_ip):
        continue
    ua = l.user_agent or ''
    is_bot = 'UptimeRobot' in ua or 'bot' in ua.lower() or 'spider' in ua.lower()
    tag = "[BOT]" if is_bot else "[USUARIO REAL]"
    hora = l.created_at.strftime("%H:%M:%S")
    print(f"{hora} | {tag:<14} | Real: {real_ip:<15} | Host: {hdrs.get('host', '-'):<22} | {l.http_method:<4} | {l.uri[:30]:<30} | UA: {ua[:40]}")
    count_non_bot += 1
    if count_non_bot >= 25:
        break

