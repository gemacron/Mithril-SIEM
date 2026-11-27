from django.db import migrations, models


def migrate_legacy_chat_ids(apps, schema_editor):
    TelegramConfig = apps.get_model('notifications', 'TelegramConfig')
    TelegramRecipient = apps.get_model('notifications', 'TelegramRecipient')

    config = TelegramConfig.objects.first()
    if not config or not config.chat_id:
        return

    raw_ids = [c.strip() for c in str(config.chat_id).replace(';', ',').split(',') if c.strip()]
    for idx, cid in enumerate(raw_ids, start=1):
        if TelegramRecipient.objects.filter(chat_id=cid).exists():
            continue
        is_group = cid.startswith('-100') or cid.startswith('-')
        is_channel = cid.startswith('@')
        rtype = 'CHANNEL' if is_channel else ('GROUP' if is_group else 'USER')
        label = 'Chat Principal' if idx == 1 else f'Destinatario #{idx}'
        TelegramRecipient.objects.create(
            name=label,
            chat_id=cid,
            recipient_type=rtype,
            role_label='Migrado automáticamente',
            is_active=True,
            min_severity=config.min_severity or 'HIGH',
            notify_on_ban_candidate=config.notify_on_ban_candidate,
            notify_on_ban_action=True,
            notify_on_node_offline=config.notify_on_node_offline,
        )


class Migration(migrations.Migration):

    dependencies = [
        ('notifications', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='telegramconfig',
            name='bot_username',
            field=models.CharField(
                blank=True,
                default='',
                help_text='Usuario del bot detectado automáticamente vía getMe (ej: MithrilAlertBot)',
                max_length=64,
            ),
        ),
        migrations.AddField(
            model_name='telegramconfig',
            name='last_error',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='telegramconfig',
            name='notify_on_ban_action',
            field=models.BooleanField(
                default=True,
                help_text='Notificar cuando un operador aprueba, ejecuta o revoca un bloqueo',
            ),
        ),
        migrations.AlterField(
            model_name='telegramconfig',
            name='chat_id',
            field=models.CharField(
                blank=True,
                default='',
                help_text='Chat ID heredado (se migra automáticamente a la lista de destinatarios)',
                max_length=255,
            ),
        ),
        migrations.AlterField(
            model_name='telegramconfig',
            name='notify_on_ban_candidate',
            field=models.BooleanField(
                default=True,
                help_text='Notificar cuando una IP supera el umbral de Candidato a Bloqueo',
            ),
        ),
        migrations.CreateModel(
            name='TelegramRecipient',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='Nombre de la persona, grupo o canal', max_length=80)),
                (
                    'chat_id',
                    models.CharField(
                        help_text='ID numérico del usuario/grupo (ej: 123456789 o -1001234567890) o @canal',
                        max_length=64,
                        unique=True,
                    ),
                ),
                (
                    'message_thread_id',
                    models.CharField(
                        blank=True,
                        default='',
                        help_text='Opcional: ID de Topic/Hilo dentro de un Supergrupo con temas',
                        max_length=32,
                    ),
                ),
                (
                    'recipient_type',
                    models.CharField(
                        choices=[('USER', 'Persona / Operador'), ('GROUP', 'Grupo SOC'), ('CHANNEL', 'Canal')],
                        default='USER',
                        max_length=16,
                    ),
                ),
                (
                    'role_label',
                    models.CharField(
                        blank=True,
                        default='',
                        help_text='Etiqueta opcional (ej: Analista SOC, SysAdmin, Guardia)',
                        max_length=64,
                    ),
                ),
                ('is_active', models.BooleanField(default=True)),
                (
                    'min_severity',
                    models.CharField(
                        choices=[('LOW', 'Baja'), ('MEDIUM', 'Media'), ('HIGH', 'Alta'), ('CRITICAL', 'Crítica')],
                        default='HIGH',
                        max_length=16,
                    ),
                ),
                ('notify_on_ban_candidate', models.BooleanField(default=True)),
                ('notify_on_ban_action', models.BooleanField(default=True)),
                ('notify_on_node_offline', models.BooleanField(default=True)),
                ('last_notified_at', models.DateTimeField(blank=True, null=True)),
                (
                    'last_status',
                    models.CharField(
                        choices=[('PENDING', 'Sin envíos'), ('OK', 'Entregado'), ('ERROR', 'Error')],
                        default='PENDING',
                        max_length=16,
                    ),
                ),
                ('last_error', models.TextField(blank=True, default='')),
                ('sent_count', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Destinatario de Telegram',
                'verbose_name_plural': 'Destinatarios de Telegram',
                'ordering': ['-is_active', 'name'],
            },
        ),
        migrations.RunPython(migrate_legacy_chat_ids, migrations.RunPython.noop),
    ]
