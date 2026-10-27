from django.urls import path
from . import views

app_name = 'notifications'

urlpatterns = [
    path('telegram/', views.telegram_settings_view, name='settings'),
]
