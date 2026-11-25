import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv('SECRET_KEY', 'mithril_default_secret_dev_key_2026')
DEBUG = os.getenv('DEBUG', 'True').lower() in ('true', '1', 'yes')

_raw_hosts = [h.strip() for h in os.getenv('ALLOWED_HOSTS', '*').split(',') if h.strip()]
ALLOWED_HOSTS = _raw_hosts if '*' in _raw_hosts else (_raw_hosts + ['*'])

# Application definition
INSTALLED_APPS = [
    'daphne',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third party
    'channels',
    
    # Mithril SIEM Apps
    'apps.core',
    'apps.nodes',
    'apps.detection',
    'apps.mitigation',
    'apps.notifications',
    'apps.analytics',
    'apps.reports',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
    # Mithril Security Interceptor: Forces initial password change and 2FA
    'apps.core.middleware.ForcePasswordChangeMiddleware',
]

ROOT_URLCONF = 'mithril_siem.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'apps.core.context_processors.mithril_branding',
            ],
        },
    },
]

WSGI_APPLICATION = 'mithril_siem.wsgi.application'
ASGI_APPLICATION = 'mithril_siem.asgi.application'

# Database Configuration (PostgreSQL with SQLite fallback for local test without DB running)
DB_HOST = os.getenv('DB_HOST', '')
if DB_HOST:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('DB_NAME', 'mithril_siem'),
            'USER': os.getenv('DB_USER', 'mithril_user'),
            'PASSWORD': os.getenv('DB_PASSWORD', 'mithril_secure_pg_pass_2026'),
            'HOST': DB_HOST,
            'PORT': os.getenv('DB_PORT', '5432'),
            'CONN_MAX_AGE': 60,
            'CONN_HEALTH_CHECKS': True,
            'OPTIONS': {
                'options': '-c statement_timeout=15000',
            },
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12},
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'es-es'

def _detect_server_timezone():
    """
    Detecta automáticamente la zona horaria IANA real del servidor donde corre Mithril SIEM
    (sin hardcodear ningún país ni ciudad). Soporta:
      1. Variable de entorno TIME_ZONE o TZ (si se configura en .env).
      2. Archivo /etc/timezone (Debian/Ubuntu).
      3. Enlace simbólico /etc/localtime -> .../zoneinfo/<Area/Ciudad> (Rocky/RHEL/Ubuntu).
      4. Archivo binario TZif montado en /etc/localtime (Podman/Docker bind-mount), buscando coincidencia exacta en zoneinfo.
      5. Respaldo por desplazamiento local del SO (Etc/GMT±N) o UTC.
    """
    import time as _time
    from zoneinfo import ZoneInfo

    def _valid_tz(name):
        if not name:
            return ''
        cand = str(name).strip().lstrip(':')
        try:
            ZoneInfo(cand)
            return cand
        except Exception:
            return ''

    # 1. Variable de entorno explícita
    for env_key in ('TIME_ZONE', 'TZ'):
        v = _valid_tz(os.getenv(env_key, ''))
        if v:
            return v

    # 2. /etc/timezone (Debian/Ubuntu)
    if os.path.isfile('/etc/timezone'):
        try:
            with open('/etc/timezone', 'r', encoding='utf-8') as f:
                v = _valid_tz(f.read().strip())
                if v:
                    return v
        except Exception:
            pass

    # 3. Symlink /etc/localtime -> .../zoneinfo/<Zona>
    if os.path.exists('/etc/localtime'):
        try:
            real_p = os.path.realpath('/etc/localtime')
            if 'zoneinfo/' in real_p:
                v = _valid_tz(real_p.split('zoneinfo/', 1)[1])
                if v:
                    return v
        except Exception:
            pass

        # 4. Bind-mount plano /etc/localtime en Podman/Docker: comparar bytes con /usr/share/zoneinfo o tzdata
        try:
            with open('/etc/localtime', 'rb') as f:
                local_bytes = f.read()
            if local_bytes:
                zone_roots = ['/usr/share/zoneinfo']
                try:
                    import tzdata
                    zone_roots.append(os.path.join(os.path.dirname(tzdata.__file__), 'zoneinfo'))
                except Exception:
                    pass
                fallback_match = ''
                for zroot in zone_roots:
                    if not os.path.isdir(zroot):
                        continue
                    for dirpath, dirnames, filenames in os.walk(zroot):
                        dirnames[:] = [d for d in dirnames if d not in ('posix', 'right', 'Etc')]
                        for fname in filenames:
                            fpath = os.path.join(dirpath, fname)
                            try:
                                if os.path.getsize(fpath) != len(local_bytes):
                                    continue
                                with open(fpath, 'rb') as zf:
                                    if zf.read() == local_bytes:
                                        rel = os.path.relpath(fpath, zroot).replace('\\', '/')
                                        v = _valid_tz(rel)
                                        if v:
                                            if '/' in v:
                                                return v
                                            if not fallback_match:
                                                fallback_match = v
                            except Exception:
                                continue
                if fallback_match:
                    return fallback_match
        except Exception:
            pass

    # 5. Respaldo usando el desplazamiento UTC real del sistema operativo (signo invertido en POSIX Etc/GMT)
    try:
        offset_sec = _time.localtime().tm_gmtoff
        if offset_sec % 3600 == 0 and offset_sec != 0:
            hours = int(offset_sec // 3600)
            etc_name = f"Etc/GMT{-hours:+d}"
            v = _valid_tz(etc_name)
            if v:
                return v
    except Exception:
        pass

    return 'UTC'

TIME_ZONE = _detect_server_timezone()
USE_I18N = True
USE_TZ = True

# Static & Media
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LOGIN_URL = '/auth/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/auth/login/'

# Channels & Redis Layer
REDIS_HOST = os.getenv('REDIS_HOST', '')
REDIS_PORT = os.getenv('REDIS_PORT', '6379')

if REDIS_HOST:
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {
                "hosts": [(REDIS_HOST, int(REDIS_PORT))],
            },
        },
    }
    CELERY_BROKER_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"
    CELERY_RESULT_BACKEND = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"
else:
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels.layers.InMemoryChannelLayer"
        }
    }
    CELERY_BROKER_URL = "redis://127.0.0.1:6379/0"
    CELERY_RESULT_BACKEND = "redis://127.0.0.1:6379/0"

CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

# Mithril SIEM Parameters
MITHRIL_BAN_CANDIDATE_THRESHOLD = int(os.getenv('MITHRIL_BAN_CANDIDATE_THRESHOLD', 80))
MITHRIL_ANOMALY_WINDOW_SECONDS = int(os.getenv('MITHRIL_ANOMALY_WINDOW_SECONDS', 600))
MITHRIL_DEFAULT_BAN_HOURS = int(os.getenv('MITHRIL_DEFAULT_BAN_HOURS', 24))
