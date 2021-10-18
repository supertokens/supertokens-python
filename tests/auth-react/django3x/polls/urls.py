from django.urls import path

from . import views

urlpatterns = [
    path('ping', views.ping, name='ping'),
    path('sessionInfo', views.session_info, name='sessionInfo'),
    path('token', views.token, name='token')
]
