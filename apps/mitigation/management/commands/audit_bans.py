from django.core.management.base import BaseCommand
from apps.mitigation.models import BanCandidate, ActiveBan, IpReputation
from apps.detection.engine import is_cloudflare_ip, is_private_local_ip

class Command(BaseCommand):
    help = 'Audita el estado de los candidatos a bloqueo y bloqueos activos'

    def handle(self, *args, **options):
        candidates = list(BanCandidate.objects.all().order_by('-created_at'))
        self.stdout.write(f"=== CANDIDATOS A BLOQUEO (Total: {len(candidates)}) ===")
        for c in candidates:
            is_cf = is_cloudflare_ip(c.client_ip)
            is_loc = is_private_local_ip(c.client_ip)
            tag = " [ALERTA: ES CLOUDFLARE]" if is_cf else (" [LAN LOCAL]" if is_loc else " [IP CLIENTE VALIDA]")
            self.stdout.write(f"ID {c.id:3d} | IP: {c.client_ip:15s} | Score: {c.accumulated_score:3d} | Status: {c.status:9s}{tag}")
            self.stdout.write(f"       Motivo: {c.suggested_reason[:100]}")

        active_bans = list(ActiveBan.objects.all().order_by('-banned_at'))
        self.stdout.write(f"\n=== BLOQUEOS (Total: {len(active_bans)}) ===")
        for b in active_bans:
            is_cf = is_cloudflare_ip(b.client_ip)
            is_loc = is_private_local_ip(b.client_ip)
            tag = " [ALERTA: ES CLOUDFLARE]" if is_cf else (" [LAN LOCAL]" if is_loc else " [IP CLIENTE VALIDA]")
            status_str = "ACTIVO" if b.is_active else "REVOCADO"
            self.stdout.write(f"ID {b.id:3d} | IP: {b.client_ip:15s} | Estado: {status_str:8s} | Expira: {str(b.expires_at)[:19]}{tag}")
