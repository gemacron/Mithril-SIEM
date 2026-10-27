from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('verify-2fa/', views.verify_2fa_view, name='verify_2fa'),
    path('first-run/', views.first_run_setup_view, name='first_run_setup'),
]
