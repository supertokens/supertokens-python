from django.urls import path

from . import views

urlpatterns = [
    path("sessioninfo", views.get_session_info),
]
