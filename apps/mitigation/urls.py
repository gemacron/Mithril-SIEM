from django.urls import path
from . import views

app_name = 'mitigation'

urlpatterns = [
    path('candidates/', views.candidates_list_view, name='candidates'),
    path('candidates/<int:candidate_id>/approve/', views.approve_candidate_view, name='approve_candidate'),
    path('candidates/<int:candidate_id>/dismiss/', views.dismiss_candidate_view, name='dismiss_candidate'),
    path('active-bans/', views.active_bans_list_view, name='active_bans'),
    path('active-bans/<int:ban_id>/revoke/', views.revoke_ban_view, name='revoke_ban'),
    path('api/sync-bans/', views.api_node_sync_bans, name='api_node_sync_bans'),
]
