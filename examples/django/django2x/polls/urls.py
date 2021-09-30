from django.urls import path

from tests.frontendIntegration.django2x.polls import views

urlpatterns = [
    path('create', views.create, name='create'),
    path('user', views.user, name='user')
]


