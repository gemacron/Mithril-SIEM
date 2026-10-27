from django.urls import path
from . import views

app_name = 'detection'

urlpatterns = [
    path('rules/', views.rules_list_view, name='rules'),
    path('rules/<int:rule_id>/toggle/', views.rule_toggle_view, name='rule_toggle'),
    path('api/ingest/', views.api_ingest, name='api_ingest'),
]
