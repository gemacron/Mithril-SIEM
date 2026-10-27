from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('', views.reports_index_view, name='index'),
    path('export/csv/', views.export_csv_view, name='export_csv'),
    path('export/json/', views.export_json_view, name='export_json'),
]
