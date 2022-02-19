from django.urls import path

from tests.frontendIntegration.django3x.polls import views

urlpatterns = [  # type: ignore
    path('index.html', views.send_file, name='index.html'),  # type: ignore
    path('login', views.login, name='login'),  # type: ignore
    path('beforeeach', views.before_each, name='beforeeach'),  # type: ignore
    path('testUserConfig', views.test_config, name='testUserConfig'),  # type: ignore
    path(
        'multipleInterceptors',
        views.multiple_interceptors,  # type: ignore
        name='multipleInterceptors'),
    path('', views.get_info, name='/'),  # type: ignore
    path('update-jwt', views.update_jwt, name='update_jwt'),  # type: ignore
    path('testing', views.testing, name='testing'),  # type: ignore
    path('logout', views.logout, name='logout'),  # type: ignore
    path('revokeAll', views.revoke_all, name='revokeAll'),  # type: ignore
    path('refresh', views.refresh, name='refresh'),  # type: ignore
    path(
        'refreshAttemptedTime',
        views.refresh_attempted_time,  # type: ignore
        name='refreshAttemptedTime'),
    path('auth/session/refresh', views.refresh, name='refresh'),  # type: ignore
    path('setAntiCsrf', views.set_anti_csrf, name='setAntiCsrf'),
    path('setEnableJWT', views.set_enable_jwt, name='setEnableJWT'),
    path('featureFlags', views.feature_flags, name='featureFlags'),
    path(
        'reinitialiseBackendConfig',
        views.reinitialize,  # type: ignore
        name='reinitialiseBackendConfig'),
    path(
        'refreshCalledTime',
        views.refresh_called_time,  # type: ignore
        name='refreshCalledTime'),
    path(
        'getSessionCalledTime',
        views.get_session_called_time,  # type: ignore
        name='getSessionCalledTime'),
    path('ping', views.ping, name='ping'),  # type: ignore
    path('testHeader', views.test_header, name='testHeader'),  # type: ignore
    path('checkDeviceInfo', views.check_device_info, name='checkDeviceInfo'),  # type: ignore
    path('check-rid', views.check_rid, name='check-rid'),  # type: ignore
    path('checkAllowCredentials',
         views.check_allow_credentials,  # type: ignore
         name='checkAllowCredentials'),
    path('testError', views.test_error, name='testError'),  # type: ignore
]
