# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import json
import os
from typing import Any, Dict, List

from django.http import HttpRequest, HttpResponse, JsonResponse
from mysite.store import get_codes, get_url_with_token
from mysite.utils import custom_init
from supertokens_python import convert_to_recipe_user_id
from supertokens_python.asyncio import get_user
from supertokens_python.auth_utils import LinkingToSessionUserFailedError
from supertokens_python.recipe.emailpassword.asyncio import update_email_or_password
from supertokens_python.recipe.emailpassword.interfaces import (
    EmailAlreadyExistsError,
    UnknownUserIdError,
    UpdateEmailOrPasswordEmailChangeNotAllowedError,
    UpdateEmailOrPasswordOkResult,
)
from supertokens_python.recipe.emailverification import EmailVerificationClaim
from supertokens_python.recipe.multifactorauth.asyncio import (
    add_to_required_secondary_factors_for_user,
)
from supertokens_python.recipe.multitenancy.asyncio import (
    associate_user_to_tenant,
    create_or_update_tenant,
    create_or_update_third_party_config,
    delete_tenant,
    disassociate_user_from_tenant,
)
from supertokens_python.recipe.multitenancy.interfaces import (
    AssociateUserToTenantEmailAlreadyExistsError,
    AssociateUserToTenantOkResult,
    AssociateUserToTenantPhoneNumberAlreadyExistsError,
    AssociateUserToTenantThirdPartyUserAlreadyExistsError,
    AssociateUserToTenantUnknownUserIdError,
    TenantConfigCreateOrUpdate,
)
from supertokens_python.recipe.oauth2provider.interfaces import CreateOAuth2ClientInput
from supertokens_python.recipe.oauth2provider.syncio import create_oauth2_client
from supertokens_python.recipe.passwordless.asyncio import update_user
from supertokens_python.recipe.passwordless.interfaces import (
    EmailChangeNotAllowedError,
    UpdateUserEmailAlreadyExistsError,
    UpdateUserOkResult,
    UpdateUserPhoneNumberAlreadyExistsError,
    UpdateUserUnknownUserIdError,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.interfaces import SessionClaimValidator
from supertokens_python.recipe.thirdparty import ProviderConfig
from supertokens_python.recipe.thirdparty.asyncio import manually_create_or_update_user
from supertokens_python.recipe.thirdparty.interfaces import (
    ManuallyCreateOrUpdateUserOkResult,
    SignInUpNotAllowed,
)
from supertokens_python.recipe.userroles import PermissionClaim, UserRoleClaim
from supertokens_python.types import AccountInfo, RecipeUserId

mode = os.environ.get("APP_MODE", "asgi")


async def override_global_claim_validators(
    gv: List[SessionClaimValidator],
    _session: SessionContainer,
    user_context: Dict[str, Any],
):
    validators = gv.copy()
    req = user_context["_default"]["request"]
    body = await req.json()

    if body.get("role"):
        info = body["role"]
        validator = getattr(UserRoleClaim.validators, info["validator"])
        validators.append(validator(*info["args"]))

    if body.get("permission"):
        info = body["permission"]
        validator = getattr(PermissionClaim.validators, info["validator"])
        validators.append(validator(*info["args"]))

    return validators


if mode == "asgi":
    from supertokens_python.recipe.emailverification.asyncio import unverify_email
    from supertokens_python.recipe.session.framework.django.asyncio import (
        verify_session,
    )
    from supertokens_python.recipe.userroles.asyncio import (
        add_role_to_user,
        create_new_role_or_add_permissions,
    )

    @verify_session()
    async def session_info(request: HttpRequest):  # type: ignore
        session_: SessionContainer = request.supertokens  # type: ignore
        return JsonResponse(
            {
                "sessionHandle": session_.get_handle(),  # type: ignore
                "userId": session_.get_user_id(),  # type: ignore
                "jwtPayload": session_.get_access_token_payload(),  # type: ignore
                "sessionDataFromDatabase": await session_.get_session_data_from_database(),  # type: ignore
            }
        )

    @verify_session()
    async def set_role_api(request: HttpRequest):
        session_: SessionContainer = request.supertokens  # type: ignore
        body = json.loads(request.body)
        await create_new_role_or_add_permissions(body["role"], body["permissions"])
        await add_role_to_user("public", session_.get_user_id(), body["role"])  # type: ignore
        await session_.fetch_and_set_claim(UserRoleClaim)  # type: ignore
        await session_.fetch_and_set_claim(PermissionClaim)  # type: ignore
        return JsonResponse({"status": "OK"})

    @verify_session()
    async def unverify_email_api(request: HttpRequest):
        session_: SessionContainer = request.supertokens  # type: ignore
        await unverify_email(session_.get_recipe_user_id())  # type: ignore
        await session_.fetch_and_set_claim(EmailVerificationClaim)  # type: ignore
        return JsonResponse({"status": "OK"})

    @verify_session(override_global_claim_validators=override_global_claim_validators)
    async def check_role_api():  # type: ignore
        return JsonResponse({"status": "OK"})

    async def delete_user(request: HttpRequest):
        from supertokens_python.asyncio import delete_user, list_users_by_account_info

        body = json.loads(request.body)
        user = await list_users_by_account_info(
            "public", AccountInfo(email=body["email"])
        )
        if len(user) == 0:
            raise Exception("Should not come here")
        await delete_user(user[0].id)
        return JsonResponse({"status": "OK"})

else:
    from supertokens_python.recipe.emailverification.syncio import (
        unverify_email as sync_unverify_email,
    )
    from supertokens_python.recipe.session.framework.django.syncio import verify_session
    from supertokens_python.recipe.userroles.syncio import (
        add_role_to_user as sync_add_role_to_user,
    )
    from supertokens_python.recipe.userroles.syncio import (
        create_new_role_or_add_permissions as sync_create_new_role_or_add_permissions,
    )

    @verify_session()
    def session_info(request: HttpRequest):
        session_: SessionContainer = request.supertokens  # type: ignore
        return JsonResponse(
            {
                "sessionHandle": session_.get_handle(),  # type: ignore
                "userId": session_.get_user_id(),  # type: ignore
                "accessTokenPayload": session_.get_access_token_payload(),  # type: ignore
                "sessionDataFromDatabase": session_.sync_get_session_data_from_database(),  # type: ignore
            }
        )

    @verify_session()
    def sync_set_role_api(request: HttpRequest):
        session_: SessionContainer = request.supertokens  # type: ignore
        body = json.loads(request.body)
        sync_create_new_role_or_add_permissions(body["role"], body["permissions"])
        sync_add_role_to_user("public", session_.get_user_id(), body["role"])  # type: ignore
        session_.sync_fetch_and_set_claim(UserRoleClaim)  # type: ignore
        session_.sync_fetch_and_set_claim(PermissionClaim)  # type: ignore
        return JsonResponse({"status": "OK"})

    @verify_session()
    def sync_unverify_email_api(request: HttpRequest):
        session_: SessionContainer = request.supertokens  # type: ignore
        sync_unverify_email(session_.get_recipe_user_id())  # type: ignore
        session_.sync_fetch_and_set_claim(EmailVerificationClaim)  # type: ignore
        return JsonResponse({"status": "OK"})

    def sync_delete_user(request: HttpRequest):
        from supertokens_python.syncio import delete_user, list_users_by_account_info

        body = json.loads(request.body)
        user = list_users_by_account_info("public", AccountInfo(email=body["email"]))
        if len(user) == 0:
            raise Exception("Should not come here")
        delete_user(user[0].id)
        return JsonResponse({"status": "OK"})

    @verify_session(override_global_claim_validators=override_global_claim_validators)
    def sync_check_role_api():
        return JsonResponse({"status": "OK"})


def ping(request: HttpRequest):
    return HttpResponse("success")


def token(request: HttpRequest):
    latest_url_with_token = get_url_with_token()
    return JsonResponse({"latestURLWithToken": latest_url_with_token})


def test_get_device(request: HttpRequest):
    pre_auth_session_id = request.GET.get("preAuthSessionId", None)
    if pre_auth_session_id is None:
        return HttpResponse("")
    codes = get_codes(pre_auth_session_id)
    return JsonResponse({"preAuthSessionId": pre_auth_session_id, "codes": codes})


async def change_email(request: HttpRequest):
    body = json.loads(request.body)
    if body is None:
        raise Exception("Should never come here")

    if body["rid"] == "emailpassword":
        resp = await update_email_or_password(
            recipe_user_id=convert_to_recipe_user_id(body["recipeUserId"]),
            email=body["email"],
            tenant_id_for_password_policy=body["tenantId"],
        )
        if isinstance(resp, UpdateEmailOrPasswordOkResult):
            return JsonResponse({"status": "OK"})
        if isinstance(resp, EmailAlreadyExistsError):
            return JsonResponse({"status": "EMAIL_ALREADY_EXISTS_ERROR"})
        if isinstance(resp, UnknownUserIdError):
            return JsonResponse({"status": "UNKNOWN_USER_ID_ERROR"})
        if isinstance(resp, UpdateEmailOrPasswordEmailChangeNotAllowedError):
            return JsonResponse(
                {"status": "EMAIL_CHANGE_NOT_ALLOWED_ERROR", "reason": resp.reason}
            )
        return JsonResponse(resp.to_json())
    elif body["rid"] == "thirdparty":
        user = await get_user(user_id=body["recipeUserId"])
        assert user is not None
        login_method = next(
            lm
            for lm in user.login_methods
            if lm.recipe_user_id.get_as_string() == body["recipeUserId"]
        )
        assert login_method is not None
        assert login_method.third_party is not None
        resp = await manually_create_or_update_user(
            tenant_id=body["tenantId"],
            third_party_id=login_method.third_party.id,
            third_party_user_id=login_method.third_party.user_id,
            email=body["email"],
            is_verified=False,
        )
        if isinstance(resp, ManuallyCreateOrUpdateUserOkResult):
            return JsonResponse(
                {"status": "OK", "createdNewRecipeUser": resp.created_new_recipe_user}
            )
        if isinstance(resp, LinkingToSessionUserFailedError):
            raise Exception("Should not come here")
        if isinstance(resp, SignInUpNotAllowed):
            return JsonResponse(
                {"status": "SIGN_IN_UP_NOT_ALLOWED", "reason": resp.reason}
            )
        return JsonResponse(
            {"status": "EMAIL_CHANGE_NOT_ALLOWED_ERROR", "reason": resp.reason}
        )
    elif body["rid"] == "passwordless":
        resp = await update_user(
            recipe_user_id=convert_to_recipe_user_id(body["recipeUserId"]),
            email=body.get("email"),
            phone_number=body.get("phoneNumber"),
        )

        if isinstance(resp, UpdateUserOkResult):
            return JsonResponse({"status": "OK"})
        if isinstance(resp, UpdateUserUnknownUserIdError):
            return JsonResponse({"status": "UNKNOWN_USER_ID_ERROR"})
        if isinstance(resp, UpdateUserEmailAlreadyExistsError):
            return JsonResponse({"status": "EMAIL_ALREADY_EXISTS_ERROR"})
        if isinstance(resp, UpdateUserPhoneNumberAlreadyExistsError):
            return JsonResponse({"status": "PHONE_NUMBER_ALREADY_EXISTS_ERROR"})
        if isinstance(resp, EmailChangeNotAllowedError):
            return JsonResponse(
                {"status": "EMAIL_CHANGE_NOT_ALLOWED_ERROR", "reason": resp.reason}
            )
        return JsonResponse(
            {
                "status": "PHONE_NUMBER_CHANGE_NOT_ALLOWED_ERROR",
                "reason": resp.reason,
            }
        )

    raise Exception("Should not come here")


async def setup_tenant(request: HttpRequest):
    body = json.loads(request.body)
    if body is None:
        raise Exception("Should never come here")
    tenant_id = body["tenantId"]
    login_methods = body["loginMethods"]
    core_config = body.get("coreConfig", {})

    first_factors: List[str] = []
    if login_methods.get("emailPassword", {}).get("enabled") == True:
        first_factors.append("emailpassword")
    if login_methods.get("thirdParty", {}).get("enabled") == True:
        first_factors.append("thirdparty")
    if login_methods.get("passwordless", {}).get("enabled") == True:
        first_factors.extend(["otp-phone", "otp-email", "link-phone", "link-email"])

    core_resp = await create_or_update_tenant(
        tenant_id,
        config=TenantConfigCreateOrUpdate(
            first_factors=first_factors,
            core_config=core_config,
        ),
    )

    if login_methods.get("thirdParty", {}).get("providers") is not None:
        for provider in login_methods["thirdParty"]["providers"]:
            await create_or_update_third_party_config(
                tenant_id,
                config=ProviderConfig.from_json(provider),
            )

    return JsonResponse({"status": "OK", "createdNew": core_resp.created_new})


async def add_user_to_tenant(request: HttpRequest):
    body = json.loads(request.body)
    if body is None:
        raise Exception("Should never come here")
    tenant_id = body["tenantId"]
    recipe_user_id = body["recipeUserId"]

    core_resp = await associate_user_to_tenant(tenant_id, RecipeUserId(recipe_user_id))

    if isinstance(core_resp, AssociateUserToTenantOkResult):
        return JsonResponse(
            {"status": "OK", "wasAlreadyAssociated": core_resp.was_already_associated}
        )
    elif isinstance(core_resp, AssociateUserToTenantUnknownUserIdError):
        return JsonResponse({"status": "UNKNOWN_USER_ID_ERROR"})
    elif isinstance(core_resp, AssociateUserToTenantEmailAlreadyExistsError):
        return JsonResponse({"status": "EMAIL_ALREADY_EXISTS_ERROR"})
    elif isinstance(core_resp, AssociateUserToTenantPhoneNumberAlreadyExistsError):
        return JsonResponse({"status": "PHONE_NUMBER_ALREADY_EXISTS_ERROR"})
    elif isinstance(core_resp, AssociateUserToTenantThirdPartyUserAlreadyExistsError):
        return JsonResponse({"status": "THIRD_PARTY_USER_ALREADY_EXISTS_ERROR"})
    return JsonResponse(
        {"status": "ASSOCIATION_NOT_ALLOWED_ERROR", "reason": core_resp.reason}
    )


async def remove_user_from_tenant(request: HttpRequest):
    body = json.loads(request.body)
    if body is None:
        raise Exception("Should never come here")
    tenant_id = body["tenantId"]
    recipe_user_id = body["recipeUserId"]

    core_resp = await disassociate_user_from_tenant(
        tenant_id, RecipeUserId(recipe_user_id)
    )

    return JsonResponse({"status": "OK", "wasAssociated": core_resp.was_associated})


async def remove_tenant(request: HttpRequest):
    body = json.loads(request.body)
    if body is None:
        raise Exception("Should never come here")
    tenant_id = body["tenantId"]

    core_resp = await delete_tenant(tenant_id)

    return JsonResponse({"status": "OK", "didExist": core_resp.did_exist})


async def test_set_flow(request: HttpRequest):
    body = json.loads(request.body)
    import mysite.store

    mysite.store.contact_method = body["contactMethod"]
    mysite.store.flow_type = body["flowType"]
    custom_init()
    return HttpResponse("")


async def test_set_account_linking_config(request: HttpRequest):
    import mysite.store

    body = json.loads(request.body)
    if body is None:
        raise Exception("Invalid request body")
    mysite.store.accountlinking_config = body
    custom_init()
    return HttpResponse("")


async def set_mfa_info(request: HttpRequest):
    import mysite.store

    body = json.loads(request.body)
    if body is None:
        return JsonResponse({"error": "Invalid request body"}, status_code=400)
    mysite.store.mfa_info = body
    return JsonResponse({"status": "OK"})


@verify_session()
async def add_required_factor(request: HttpRequest):
    session_: SessionContainer = request.supertokens  # type: ignore
    body = json.loads(request.body)
    if body is None or "factorId" not in body:
        return JsonResponse({"error": "Invalid request body"}, status_code=400)

    await add_to_required_secondary_factors_for_user(
        session_.get_user_id(),  # type: ignore
        body["factorId"],
    )

    return JsonResponse({"status": "OK"})


def test_set_enabled_recipes(request: HttpRequest):
    import mysite.store

    body = json.loads(request.body)
    if body is None:
        raise Exception("Invalid request body")
    mysite.store.enabled_recipes = body.get("enabledRecipes")
    mysite.store.enabled_providers = body.get("enabledProviders")
    custom_init()
    return HttpResponse("")


def test_get_totp_code(request: HttpRequest):
    from pyotp import TOTP

    body = json.loads(request.body)
    if body is None or "secret" not in body:
        return JsonResponse({"error": "Invalid request body"}, status_code=400)

    secret = body["secret"]
    totp = TOTP(secret, digits=6, interval=1)
    code = totp.now()

    return JsonResponse({"totp": code})


def test_create_oauth2_client(request: HttpRequest):
    body = json.loads(request.body)
    if body is None:
        raise Exception("Invalid request body")
    client = create_oauth2_client(CreateOAuth2ClientInput.from_json(body))
    return JsonResponse(client.to_json())


def before_each(request: HttpRequest):
    import mysite.store

    mysite.store.contact_method = "EMAIL_OR_PHONE"
    mysite.store.flow_type = "USER_INPUT_CODE_AND_MAGIC_LINK"
    mysite.store.latest_url_with_token = ""
    mysite.store.code_store = dict()
    mysite.store.accountlinking_config = {}
    mysite.store.enabled_providers = None
    mysite.store.enabled_recipes = None
    mysite.store.mfa_info = {}
    custom_init()
    return HttpResponse("")


def test_feature_flags(request: HttpRequest):
    return JsonResponse(
        {
            "available": [
                "passwordless",
                "thirdpartypasswordless",
                "generalerror",
                "userroles",
                "multitenancy",
                "multitenancyManagementEndpoints",
                "accountlinking",
                "mfa",
                "recipeConfig",
                "accountlinking-fixes",
                "oauth2",
            ]
        }
    )
