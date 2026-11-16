#!/bin/bash
set -e

echo "=========================================="
echo "🛡️  MITHRIL SIEM - INICIALIZANDO ENTORNO"
echo "=========================================="

# Esperar a PostgreSQL
if [ -n "$DB_HOST" ]; then
    echo "Esperando conexión a PostgreSQL en $DB_HOST:$DB_PORT..."
    while ! nc -z "$DB_HOST" "$DB_PORT"; do
      sleep 1
    done
    echo "✅ Conexión con PostgreSQL establecida."
fi

# Esperar a Redis
if [ -n "$REDIS_HOST" ]; then
    echo "Esperando conexión a Redis en $REDIS_HOST:$REDIS_PORT..."
    while ! nc -z "$REDIS_HOST" "$REDIS_PORT"; do
      sleep 1
    done
    echo "✅ Conexión con Redis establecida."
fi

# Crear y aplicar migraciones
echo "Generando migraciones para aplicaciones Mithril..."
python manage.py makemigrations core nodes detection mitigation notifications reports --noinput

echo "Aplicando migraciones de base de datos..."
python manage.py migrate --noinput

# Sembrar reglas de seguridad iniciales y usuario root con cambio obligatorio
echo "Inicializando reglas de seguridad y cuenta root..."
python manage.py init_mithril_system

# Recolectar archivos estáticos
echo "Recolectando estáticos..."
python manage.py collectstatic --noinput

echo "=========================================="
echo "🚀 MITHRIL SIEM LISTO. ARRANCANDO SERVIDOR."
echo "=========================================="

# Si es el contenedor web (daphne), iniciar también el receptor Syslog UDP en el puerto 5140 en segundo plano
if [ "$1" = "daphne" ] && [ -f "/app/mithril_lan_proxy.py" ]; then
    echo "📡 Iniciando receptor Syslog UDP (puerto 5140) en segundo plano..."
    python /app/mithril_lan_proxy.py --syslog-only &
fi

exec "$@"
