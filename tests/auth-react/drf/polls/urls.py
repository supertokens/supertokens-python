import os

from django.urls import path

from . import views

urlpatterns = [  # type: ignore
    path("ping", views.ping, name="ping"),  # type: ignore
    path("sessionInfo", views.session_info, name="sessionInfo"),  # type: ignore
    path("token", views.token, name="token"),  # type: ignore
    path("test/setFlow", views.test_set_flow, name="setFlow"),  # type: ignore
    path("test/getDevice", views.test_get_device, name="getDevice"),  # type: ignore
    path("test/featureFlags", views.test_feature_flags, name="featureFlags"),  # type: ignore
    path("beforeeach", views.before_each, name="beforeeach"),  # type: ignore
]

mode = os.environ.get("APP_MODE", "asgi")

if mode == "asgi":
    urlpatterns += [
        path("unverifyEmail", views.unverify_email_api, name="unverifyEmail"),  # type: ignore
        path("setRole", views.set_role_api, name="setRole"),  # type: ignore
        path("checkRole", views.check_role_api, name="checkRole"),  # type: ignore
        path("deleteUser", views.delete_user, name="deleteUser"),  # type: ignore
    ]
else:
    urlpatterns += [
        path("unverifyEmail", views.sync_unverify_email_api, name="unverifyEmail"),  # type: ignore
        path("setRole", views.sync_set_role_api, name="setRole"),  # type: ignore
        path("checkRole", views.sync_check_role_api, name="checkRole"),  # type: ignore
        path("deleteUser", views.sync_delete_user, name="deleteUser"),  # type: ignore
    ]
