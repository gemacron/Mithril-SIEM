from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('apps.core.urls', namespace='core')),
    path('', include('apps.analytics.urls', namespace='analytics')),
    path('nodes/', include('apps.nodes.urls', namespace='nodes')),
    path('mitigation/', include('apps.mitigation.urls', namespace='mitigation')),
    path('detection/', include('apps.detection.urls', namespace='detection')),
    path('notifications/', include('apps.notifications.urls', namespace='notifications')),
    path('reports/', include('apps.reports.urls', namespace='reports')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
