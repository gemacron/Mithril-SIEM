from django.urls import path
from . import views

app_name = 'analytics'

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('api/map-data/', views.api_map_data, name='api_map_data'),
    path('api/live-stats/', views.api_live_stats, name='api_live_stats'),
]
