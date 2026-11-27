from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('notifications', '0002_telegram_multi_recipients'),
    ]

    operations = [
        migrations.AddField(
            model_name='telegramconfig',
            name='bot_last_poll_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='telegramconfig',
            name='enable_interactive_bot',
            field=models.BooleanField(
                default=True,
                help_text='Habilita botones interactivos (Ver Evidencia, Bloquear 24h/7d/Permanente, Descartar) y comandos en Telegram vía Long Polling',
            ),
        ),
        migrations.AddField(
            model_name='telegramrecipient',
            name='can_manage_bans',
            field=models.BooleanField(
                default=True,
                help_text='Permite aprobar bloqueos, revocar bloqueos y descartar candidatos directamente desde Telegram',
            ),
        ),
        migrations.CreateModel(
            name='TelegramDiscoveredChat',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('chat_id', models.CharField(max_length=64, unique=True)),
                ('name', models.CharField(blank=True, default='', max_length=120)),
                ('username', models.CharField(blank=True, default='', max_length=64)),
                (
                    'recipient_type',
                    models.CharField(
                        choices=[('USER', 'Persona / Operador'), ('GROUP', 'Grupo SOC'), ('CHANNEL', 'Canal')],
                        default='USER',
                        max_length=16,
                    ),
                ),
                ('thread_id', models.CharField(blank=True, default='', max_length=32)),
                ('last_message', models.CharField(blank=True, default='', max_length=120)),
                ('last_seen_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Chat Detectado en Telegram',
                'verbose_name_plural': 'Chats Detectados en Telegram',
                'ordering': ['-last_seen_at'],
            },
        ),
        migrations.CreateModel(
            name='TelegramCandidateMessage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('candidate_id', models.BigIntegerField(db_index=True)),
                ('chat_id', models.CharField(max_length=64)),
                ('message_id', models.BigIntegerField()),
                ('rendered_html', models.TextField(blank=True, default='')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-id'],
                'unique_together': {('candidate_id', 'chat_id', 'message_id')},
            },
        ),
    ]
