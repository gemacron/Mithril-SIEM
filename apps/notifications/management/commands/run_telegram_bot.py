from django.core.management.base import BaseCommand
from apps.notifications.bot_runner import run_bot_loop


class Command(BaseCommand):
    help = "Inicia el listener interactivo Long Polling del Bot de Telegram de Mithril SIEM (botones de bloqueo y comandos)."

    def handle(self, *args, **options):
        run_bot_loop()
