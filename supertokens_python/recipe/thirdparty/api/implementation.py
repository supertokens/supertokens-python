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
from __future__ import annotations
from base64 import b64decode
import json

from typing import TYPE_CHECKING, Any, Dict, Optional, Union
from urllib.parse import parse_qs, urlencode, urlparse

from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.emailverification.interfaces import (
    CreateEmailVerificationTokenOkResult,
)
from supertokens_python.recipe.session.asyncio import create_new_session
from supertokens_python.recipe.thirdparty.interfaces import (
    APIInterface,
    AuthorisationUrlGetOkResult,
    SignInUpPostNoEmailGivenByProviderResponse,
    SignInUpPostOkResult,
)
from supertokens_python.recipe.thirdparty.provider import RedirectUriInfo
from supertokens_python.recipe.thirdparty.types import UserInfoEmail

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdparty.interfaces import APIOptions
    from supertokens_python.recipe.thirdparty.provider import Provider

from supertokens_python.types import GeneralErrorResponse


class APIImplementation(APIInterface):
    async def authorisation_url_get(
        self,
        provider: Provider,
        redirect_uri_on_provider_dashboard: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[AuthorisationUrlGetOkResult, GeneralErrorResponse]:
        authorisation_url_info = await provider.get_authorisation_redirect_url(
            redirect_uri_on_provider_dashboard=redirect_uri_on_provider_dashboard,
            user_context=user_context,
        )

        return AuthorisationUrlGetOkResult(
            url_with_query_params=authorisation_url_info.url_with_query_params,
            pkce_code_verifier=authorisation_url_info.pkce_code_verifier,
        )

    async def sign_in_up_post(
        self,
        provider: Provider,
        redirect_uri_info: Optional[RedirectUriInfo],
        oauth_tokens: Optional[Dict[str, Any]],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignInUpPostOkResult,
        SignInUpPostNoEmailGivenByProviderResponse,
        GeneralErrorResponse,
    ]:
        oauth_tokens_to_use: Dict[str, Any] = {}

        if redirect_uri_info is not None:
            oauth_tokens_to_use = await provider.exchange_auth_code_for_oauth_tokens(
                redirect_uri_info=redirect_uri_info,
                user_context=user_context,
            )
        else:
            oauth_tokens_to_use = oauth_tokens  # type: ignore

        user_info = await provider.get_user_info(
            oauth_tokens=oauth_tokens_to_use,
            user_context=user_context,
        )

        if user_info.email is None and provider.config.require_email is False:
            # We don't expect to get an email from this provider.
            # So we generate a fake one
            if provider.config.generate_fake_email is not None:
                user_info.email = UserInfoEmail(
                    email=await provider.config.generate_fake_email(
                        user_info.third_party_user_id, tenant_id, user_context
                    ),
                    is_verified=True,
                )

        email = user_info.email.id if user_info.email is not None else None
        email_verified = (
            user_info.email.is_verified if user_info.email is not None else None
        )
        if email is None:
            return SignInUpPostNoEmailGivenByProviderResponse()

        signinup_response = await api_options.recipe_implementation.sign_in_up(
            third_party_id=provider.id,
            third_party_user_id=user_info.third_party_user_id,
            email=email,
            oauth_tokens=oauth_tokens_to_use,
            raw_user_info_from_provider=user_info.raw_user_info_from_provider,
            tenant_id=tenant_id,
            user_context=user_context,
        )

        if email_verified:
            ev_instance = EmailVerificationRecipe.get_instance_optional()
            if ev_instance is not None:
                token_response = await ev_instance.recipe_implementation.create_email_verification_token(
                    tenant_id=tenant_id,
                    user_id=signinup_response.user.user_id,
                    email=signinup_response.user.email,
                    user_context=user_context,
                )

                if isinstance(token_response, CreateEmailVerificationTokenOkResult):
                    await ev_instance.recipe_implementation.verify_email_using_token(
                        token=token_response.token,
                        tenant_id=tenant_id,
                        user_context=user_context,
                    )

        user = signinup_response.user
        session = await create_new_session(
            request=api_options.request,
            tenant_id=tenant_id,
            user_id=user.user_id,
            user_context=user_context,
        )

        return SignInUpPostOkResult(
            created_new_user=signinup_response.created_new_user,
            user=user,
            session=session,
            oauth_tokens=oauth_tokens_to_use,
            raw_user_info_from_provider=user_info.raw_user_info_from_provider,
        )

    async def apple_redirect_handler_post(
        self,
        form_post_info: Dict[str, Any],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ):
        state_in_b64: str = form_post_info["state"]
        state = b64decode(state_in_b64).decode("utf-8")
        state_obj = json.loads(state)
        redirect_uri: str = state_obj["frontendRedirectURI"]

        url_obj = urlparse(redirect_uri)
        qparams = parse_qs(url_obj.query)
        for k, v in form_post_info.items():
            qparams[k] = [v]

        redirect_uri = url_obj._replace(query=urlencode(qparams, doseq=True)).geturl()

        api_options.response.set_header("Location", redirect_uri)
        api_options.response.set_status_code(303)
        api_options.response.set_html_content("")
