from django.conf.urls.static import static  # type: ignore
from django.urls import path

from . import views

urlpatterns = [  # type: ignore
    path("index.html", views.send_file, name="index.html"),  # type: ignore
    path("login", views.login, name="login"),  # type: ignore
    path("login-2.18", views.login_218, name="login_218"),  # type: ignore
    path(
        "test/setup/st",
        views.setup_st,  # type: ignore
        name="setup_st",
    ),
    path("beforeeach", views.before_each, name="beforeeach"),  # type: ignore
    path("after", views.after, name="after"),  # type: ignore
    path("testUserConfig", views.test_config, name="testUserConfig"),  # type: ignore
    path(
        "multipleInterceptors",
        views.multiple_interceptors,  # type: ignore
        name="multipleInterceptors",
    ),
    path("", views.get_info, name="/"),  # type: ignore
    path(
        "check-rid-no-session",
        views.check_rid_no_session,  # type: ignore
        name="check-rid-no-session",
    ),  # type: ignore
    path("update-jwt", views.update_jwt, name="update_jwt"),  # type: ignore
    path(
        "update-jwt-with-handle",
        views.update_jwt_with_handle,  # type: ignore
        name="update_jwt_with_handle",
    ),
    path(
        "session-claims-error",
        views.session_claim_error_api,  # type: ignore
        name="session_claim_error_api",
    ),
    path("403-without-body", views.without_body_403, name="without_body_403"),  # type: ignore
    path("testing", views.testing, name="testing"),  # type: ignore
    path("logout", views.logout, name="logout"),  # type: ignore
    path("revokeAll", views.revoke_all, name="revokeAll"),  # type: ignore
    path("refresh", views.refresh, name="refresh"),  # type: ignore
    path(
        "refreshAttemptedTime",
        views.refresh_attempted_time,  # type: ignore
        name="refreshAttemptedTime",
    ),
    path("auth/session/refresh", views.refresh, name="refresh"),  # type: ignore
    path("featureFlags", views.feature_flags, name="featureFlags"),  # type: ignore
    path(
        "reinitialiseBackendConfig",
        views.reinitialize,  # type: ignore
        name="reinitialiseBackendConfig",
    ),
    path(
        "refreshCalledTime",
        views.refresh_called_time,  # type: ignore
        name="refreshCalledTime",
    ),
    path(
        "getSessionCalledTime",
        views.get_session_called_time,  # type: ignore
        name="getSessionCalledTime",
    ),
    path("ping", views.ping, name="ping"),  # type: ignore
    path("testHeader", views.test_header, name="testHeader"),  # type: ignore
    path("checkDeviceInfo", views.check_device_info, name="checkDeviceInfo"),  # type: ignore
    path("check-rid", views.check_rid, name="check-rid"),  # type: ignore
    path(
        "checkAllowCredentials",
        views.check_allow_credentials,  # type: ignore
        name="checkAllowCredentials",
    ),
    path("testError", views.test_error, name="testError"),  # type: ignore
] + static("angular/", document_root="templates/angular/")
