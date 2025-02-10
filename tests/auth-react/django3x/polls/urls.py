import os

from django.urls import path

from . import views

urlpatterns = [  # type: ignore
    path("ping", views.ping, name="ping"),
    path("sessionInfo", views.session_info, name="sessionInfo"),
    path("token", views.token, name="token"),
    path("changeEmail", views.change_email, name="changeEmail"),  # type: ignore
    path("setupTenant", views.setup_tenant, name="setupTenant"),  # type: ignore
    path("removeTenant", views.remove_tenant, name="removeTenant"),  # type: ignore
    path(
        "removeUserFromTenant",
        views.remove_user_from_tenant,  # type: ignore
        name="removeUserFromTenant",
    ),  # type: ignore
    path("addUserToTenant", views.add_user_to_tenant, name="addUserToTenant"),  # type: ignore
    path("test/setFlow", views.test_set_flow, name="setFlow"),  # type: ignore
    path(
        "test/setAccountLinkingConfig",
        views.test_set_account_linking_config,  # type: ignore
        name="setAccountLinkingConfig",
    ),  # type: ignore
    path("setMFAInfo", views.set_mfa_info, name="setMfaInfo"),  # type: ignore
    path(
        "addRequiredFactor",
        views.add_required_factor,  # type: ignore
        name="addRequiredFactor",
    ),  # type: ignore
    path(
        "test/setEnabledRecipes",
        views.test_set_enabled_recipes,  # type: ignore
        name="setEnabledRecipes",
    ),
    path("test/getTOTPCode", views.test_get_totp_code, name="getTotpCode"),  # type: ignore
    path(
        "test/create-oauth2-client",
        views.test_create_oauth2_client,
        name="createOAuth2Client",
    ),  # type: ignore
    path("test/getDevice", views.test_get_device, name="getDevice"),  # type: ignore
    path("test/featureFlags", views.test_feature_flags, name="featureFlags"),  # type: ignore
    path("beforeeach", views.before_each, name="beforeeach"),  # type: ignore
]

mode = os.environ.get("APP_MODE", "asgi")

if mode == "asgi":
    urlpatterns += [  # type: ignore
        path("unverifyEmail", views.unverify_email_api, name="unverifyEmail"),  # type: ignore
        path("setRole", views.set_role_api, name="setRole"),  # type: ignore
        path("checkRole", views.check_role_api, name="checkRole"),  # type: ignore
        path("deleteUser", views.delete_user, name="deleteUser"),  # type: ignore
    ]
else:
    urlpatterns += [  # type: ignore
        path("unverifyEmail", views.sync_unverify_email_api, name="unverifyEmail"),
        path("setRole", views.sync_set_role_api, name="setRole"),
        path("checkRole", views.sync_check_role_api, name="checkRole"),
        path("deleteUser", views.sync_delete_user, name="deleteUser"),
    ]
