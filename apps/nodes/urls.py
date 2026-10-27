from django.urls import path
from . import views

app_name = 'nodes'

urlpatterns = [
    path('', views.nodes_list_view, name='list'),
    path('create/', views.node_create_view, name='create'),
    path('<uuid:node_id>/configure/', views.node_configure_view, name='configure'),
    path('<uuid:node_id>/delete/', views.node_delete_view, name='delete'),
    path('api/heartbeat/', views.api_heartbeat, name='api_heartbeat'),
]
