from django.urls import path

from . import views

urlpatterns = [  # type: ignore
    path('ping', views.ping, name='ping'),
    path('sessionInfo', views.session_info, name='sessionInfo'),
    path('token', views.token, name='token'),
    path('test/setFlow', views.test_set_flow, name='setFlow'),
    path('test/getDevice', views.test_get_device, name='getDevice'),
    path('test/featureFlags', views.test_feature_flags, name='featureFlags'),
    path('beforeeach', views.before_each, name='beforeeach')
]
