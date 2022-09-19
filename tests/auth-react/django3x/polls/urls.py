import os

from django.urls import path

from . import views

urlpatterns = [  # type: ignore
    path("ping", views.ping, name="ping"),
    path("sessionInfo", views.session_info, name="sessionInfo"),
    path("token", views.token, name="token"),
    path("test/setFlow", views.test_set_flow, name="setFlow"),
    path("test/getDevice", views.test_get_device, name="getDevice"),
    path("test/featureFlags", views.test_feature_flags, name="featureFlags"),
    path("beforeeach", views.before_each, name="beforeeach"),
]

mode = os.environ.get("APP_MODE", "asgi")

if mode == "asgi":
    urlpatterns += [
        path("unverifyEmail", views.unverify_email_api, name="unverifyEmail"),  # type: ignore
        path("setRole", views.set_role_api, name="setRole"),  # type: ignore
        path("checkRole", views.check_role_api, name="checkRole"),  # type: ignore
    ]
else:
    urlpatterns += [
        path("unverifyEmail", views.sync_unverify_email_api, name="unverifyEmail"),
        path("setRole", views.sync_set_role_api, name="setRole"),
        path("checkRole", views.sync_check_role_api, name="checkRole"),
    ]
