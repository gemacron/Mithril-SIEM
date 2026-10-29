from django.urls import path
from . import views

app_name = 'detection'

urlpatterns = [
    path('rules/', views.rules_list_view, name='rules'),
    path('rules/<int:rule_id>/toggle/', views.rule_toggle_view, name='rule_toggle'),
    path('rules/<int:rule_id>/delete/', views.rule_delete_view, name='rule_delete'),
    path('api/ingest/', views.api_ingest, name='api_ingest'),
    path('api/cloudflare-ips/', views.api_cloudflare_ips_status, name='api_cloudflare_ips'),
]
