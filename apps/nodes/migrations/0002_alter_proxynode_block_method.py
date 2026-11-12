from django.db import migrations, models


def set_default_fail2ban(apps, schema_editor):
    ProxyNode = apps.get_model('nodes', 'ProxyNode')
    ProxyNode.objects.filter(block_method='ipset').update(block_method='fail2ban')


class Migration(migrations.Migration):

    dependencies = [
        ('nodes', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='proxynode',
            name='block_method',
            field=models.CharField(
                choices=[
                    ('fail2ban', 'Fail2ban + Smart Action (Recomendado - Universal sin tocar Nginx)'),
                    ('ipset', 'Kernel ipset (Directo - Firewall de Red)'),
                    ('nginx_conf', 'Archivo include dinámico de Nginx (deny IP;)'),
                    ('monitor', 'Modo Monitor Pasivo (Solo Observación - Cero Bloqueos)'),
                ],
                default='fail2ban',
                help_text='Mecanismo de bloqueo local',
                max_length=16,
            ),
        ),
        migrations.RunPython(set_default_fail2ban, migrations.RunPython.noop),
    ]

