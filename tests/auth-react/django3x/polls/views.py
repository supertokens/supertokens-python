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
from typing import List, Dict, Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from mysite.store import get_codes, get_url_with_token
from mysite.utils import custom_init

from supertokens_python.recipe.emailverification import EmailVerificationClaim
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.interfaces import SessionClaimValidator
from supertokens_python.recipe.userroles import UserRoleClaim, PermissionClaim

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
    from supertokens_python.recipe.session.framework.django.asyncio import (
        verify_session,
    )
    from supertokens_python.recipe.userroles.asyncio import (
        create_new_role_or_add_permissions,
        add_role_to_user,
    )
    from supertokens_python.recipe.emailverification.asyncio import unverify_email

    @verify_session()
    async def session_info(request: HttpRequest):  # type: ignore
        session_: SessionContainer = request.supertokens  # type: ignore
        return JsonResponse(
            {
                "sessionHandle": session_.get_handle(),
                "userId": session_.get_user_id(),
                "jwtPayload": session_.get_access_token_payload(),
                "sessionDataFromDatabase": await session_.get_session_data_from_database(),
            }
        )

    @verify_session()
    async def set_role_api(request: HttpRequest):
        session_: SessionContainer = request.supertokens  # type: ignore
        body = json.loads(request.body)
        await create_new_role_or_add_permissions(body["role"], body["permissions"])
        await add_role_to_user(session_.get_user_id(), body["role"])
        await session_.fetch_and_set_claim(UserRoleClaim)
        await session_.fetch_and_set_claim(PermissionClaim)
        return JsonResponse({"status": "OK"})

    @verify_session()
    async def unverify_email_api(request: HttpRequest):
        session_: SessionContainer = request.supertokens  # type: ignore
        await unverify_email(session_.get_user_id())
        await session_.fetch_and_set_claim(EmailVerificationClaim)
        return JsonResponse({"status": "OK"})

    @verify_session(override_global_claim_validators=override_global_claim_validators)
    async def check_role_api():  # type: ignore
        return JsonResponse({"status": "OK"})

else:
    from supertokens_python.recipe.session.framework.django.syncio import verify_session
    from supertokens_python.recipe.userroles.syncio import (
        create_new_role_or_add_permissions as sync_create_new_role_or_add_permissions,
        add_role_to_user as sync_add_role_to_user,
    )
    from supertokens_python.recipe.emailverification.syncio import (
        unverify_email as sync_unverify_email,
    )

    @verify_session()
    def session_info(request: HttpRequest):
        session_: SessionContainer = request.supertokens  # type: ignore
        return JsonResponse(
            {
                "sessionHandle": session_.get_handle(),
                "userId": session_.get_user_id(),
                "accessTokenPayload": session_.get_access_token_payload(),
                "sessionDataFromDatabase": session_.sync_get_session_data_from_database(),
            }
        )

    @verify_session()
    def sync_set_role_api(request: HttpRequest):
        session_: SessionContainer = request.supertokens  # type: ignore
        body = json.loads(request.body)
        sync_create_new_role_or_add_permissions(body["role"], body["permissions"])
        sync_add_role_to_user(session_.get_user_id(), body["role"])
        session_.sync_fetch_and_set_claim(UserRoleClaim)
        session_.sync_fetch_and_set_claim(PermissionClaim)
        return JsonResponse({"status": "OK"})

    @verify_session()
    def sync_unverify_email_api(request: HttpRequest):
        session_: SessionContainer = request.supertokens  # type: ignore
        sync_unverify_email(session_.get_user_id())
        session_.sync_fetch_and_set_claim(EmailVerificationClaim)
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


def test_set_flow(request: HttpRequest):
    body = json.loads(request.body)
    contact_method = body["contactMethod"]
    flow_type = body["flowType"]
    custom_init(contact_method=contact_method, flow_type=flow_type)
    return HttpResponse("")


def before_each(request: HttpRequest):
    setattr(settings, "CODE_STORE", dict())
    return HttpResponse("")


def test_feature_flags(request: HttpRequest):
    return JsonResponse(
        {
            "available": [
                "passwordless",
                "thirdpartypasswordless",
                "generalerror",
                "userroles",
            ]
        }
    )
