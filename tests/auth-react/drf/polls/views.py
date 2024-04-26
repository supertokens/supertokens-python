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
import os
from typing import List, Dict, Any

from django.conf import settings
from rest_framework import status  # type: ignore
from rest_framework.decorators import api_view, renderer_classes  # type: ignore
from rest_framework.renderers import JSONRenderer, StaticHTMLRenderer  # type: ignore
from rest_framework.request import Request  # type: ignore
from rest_framework.response import Response  # type: ignore
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
    from adrf.decorators import api_view  # type: ignore

    from supertokens_python.recipe.session.framework.django.asyncio import (
        verify_session,
    )
    from supertokens_python.recipe.userroles.asyncio import (
        create_new_role_or_add_permissions,
        add_role_to_user,
    )
    from supertokens_python.recipe.emailverification.asyncio import unverify_email

    @api_view(["GET"])
    @renderer_classes([JSONRenderer])  # type: ignore
    @verify_session()
    async def session_info(request: Request):  # type: ignore
        session_: SessionContainer = request.supertokens  # type: ignore
        return Response(
            {
                "sessionHandle": session_.get_handle(),
                "userId": session_.get_user_id(),
                "jwtPayload": session_.get_access_token_payload(),
                "sessionDataFromDatabase": await session_.get_session_data_from_database(),
            }
        )  # type: ignore

    @api_view(["GET"])
    @renderer_classes([JSONRenderer])  # type: ignore
    @verify_session()
    async def set_role_api(request: Request):  # type: ignore
        session_: SessionContainer = request.supertokens  # type: ignore
        body = request.data  # type: ignore

        await create_new_role_or_add_permissions(body["role"], body["permissions"])  # type: ignore
        await add_role_to_user("public", session_.get_user_id(), body["role"])  # type: ignore
        await session_.fetch_and_set_claim(UserRoleClaim)
        await session_.fetch_and_set_claim(PermissionClaim)
        return Response({"status": "OK"})  # type: ignore

    @api_view(["GET"])
    @renderer_classes([JSONRenderer])  # type: ignore
    @verify_session()
    async def unverify_email_api(request: Request):  # type: ignore
        session_: SessionContainer = request.supertokens  # type: ignore
        await unverify_email(session_.get_user_id())
        await session_.fetch_and_set_claim(EmailVerificationClaim)
        return Response({"status": "OK"})  # type: ignore

    @api_view(["GET"])
    @renderer_classes([JSONRenderer])  # type: ignore
    @verify_session(override_global_claim_validators=override_global_claim_validators)
    async def check_role_api():  # type: ignore
        return Response({"status": "OK"})  # type: ignore

    @api_view(["POST"])
    @renderer_classes([JSONRenderer])  # type: ignore
    async def delete_user(request: Request):  # type: ignore
        from supertokens_python.recipe.emailpassword.asyncio import get_user_by_email
        from supertokens_python.asyncio import delete_user

        body = request.data  # type: ignore
        user = await get_user_by_email("public", body["email"])  # type: ignore
        if user is None:
            raise Exception("Should not come here")
        await delete_user(user.user_id)
        return Response({"status": "OK"})  # type: ignore

else:
    from supertokens_python.recipe.session.framework.django.syncio import verify_session
    from supertokens_python.recipe.userroles.syncio import (
        create_new_role_or_add_permissions as sync_create_new_role_or_add_permissions,
        add_role_to_user as sync_add_role_to_user,
    )
    from supertokens_python.recipe.emailverification.syncio import (
        unverify_email as sync_unverify_email,
    )

    @api_view(["GET"])
    @renderer_classes([JSONRenderer])  # type: ignore
    @verify_session()
    def session_info(request: Request):  # type: ignore
        session_: SessionContainer = request.supertokens  # type: ignore
        return Response(
            {
                "sessionHandle": session_.get_handle(),
                "userId": session_.get_user_id(),
                "accessTokenPayload": session_.get_access_token_payload(),
                "sessionDataFromDatabase": session_.sync_get_session_data_from_database(),
            }
        )  # type: ignore

    @api_view(["GET"])
    @renderer_classes([JSONRenderer])  # type: ignore
    @verify_session()
    def sync_set_role_api(request: Request):  # type: ignore
        session_: SessionContainer = request.supertokens  # type: ignore
        body = request.data  # type: ignore
        sync_create_new_role_or_add_permissions(body["role"], body["permissions"])  # type: ignore
        sync_add_role_to_user("public", session_.get_user_id(), body["role"])  # type: ignore
        session_.sync_fetch_and_set_claim(UserRoleClaim)
        session_.sync_fetch_and_set_claim(PermissionClaim)
        return Response({"status": "OK"})  # type: ignore

    @api_view(["GET"])
    @renderer_classes([JSONRenderer])  # type: ignore
    @verify_session()
    def sync_unverify_email_api(request: Request):  # type: ignore
        session_: SessionContainer = request.supertokens  # type: ignore
        sync_unverify_email(session_.get_user_id())
        session_.sync_fetch_and_set_claim(EmailVerificationClaim)
        return Response({"status": "OK"})  # type: ignore

    @api_view(["GET"])
    @renderer_classes([JSONRenderer])  # type: ignore
    def sync_delete_user(request: Request):  # type: ignore
        from supertokens_python.recipe.emailpassword.syncio import get_user_by_email
        from supertokens_python.syncio import delete_user

        body = request.data  # type: ignore
        user = get_user_by_email("public", body["email"])  # type: ignore
        if user is None:
            raise Exception("Should not come here")
        delete_user(user.user_id)
        return Response({"status": "OK"})  # type: ignore

    @api_view(["GET"])
    @renderer_classes([JSONRenderer])  # type: ignore
    @verify_session(override_global_claim_validators=override_global_claim_validators)
    def sync_check_role_api():  # type: ignore
        return Response({"status": "OK"})  # type: ignore


@api_view(["GET"])
@renderer_classes([StaticHTMLRenderer])  # type: ignore
def ping(request: Request):  # type: ignore
    return Response("success")  # type: ignore


@api_view(["GET"])
@renderer_classes([JSONRenderer])  # type: ignore
def token(request: Request):  # type: ignore
    latest_url_with_token = get_url_with_token()
    return Response({"latestURLWithToken": latest_url_with_token})  # type: ignore


@api_view(["GET"])
@renderer_classes([JSONRenderer])  # type: ignore
def test_get_device(request: Request):  # type: ignore
    pre_auth_session_id = request.GET.get("preAuthSessionId", None)  # type: ignore
    if pre_auth_session_id is None:
        return Response("")  # type: ignore
    codes = get_codes(pre_auth_session_id)  # type: ignore
    return Response({"preAuthSessionId": pre_auth_session_id, "codes": codes})  # type: ignore


@api_view(["POST"])
@renderer_classes([JSONRenderer])  # type: ignore
def test_set_flow(request: Request):  # type: ignore
    body = request.data  # type: ignore
    contact_method = body["contactMethod"]  # type: ignore
    flow_type = body["flowType"]  # type: ignore
    custom_init(contact_method=contact_method, flow_type=flow_type)  # type: ignore
    return Response("")  # type: ignore


@api_view(["GET", "POST"])
@renderer_classes([JSONRenderer])  # type: ignore
def before_each(request: Request):  # type: ignore
    setattr(settings, "CODE_STORE", dict())
    return Response("")  # type: ignore


@api_view(["GET"])
@renderer_classes([JSONRenderer])  # type: ignore
def test_feature_flags(request: Request):  # type: ignore
    return Response(
        {
            "available": [
                "passwordless",
                "thirdpartypasswordless",
                "generalerror",
                "userroles",
            ]
        }
    )  # type: ignore
