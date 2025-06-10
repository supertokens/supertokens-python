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

import json
from base64 import b64decode
from typing import TYPE_CHECKING, Any, Dict, Optional, Union
from urllib.parse import parse_qs, urlencode, urlparse

from supertokens_python.recipe.accountlinking.types import AccountInfoWithRecipeId
from supertokens_python.recipe.emailverification import EmailVerificationRecipe
from supertokens_python.recipe.emailverification.asyncio import is_email_verified
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.thirdparty.interfaces import (
    APIInterface,
    AuthorisationUrlGetOkResult,
    SignInUpNotAllowed,
    SignInUpOkResult,
    SignInUpPostNoEmailGivenByProviderResponse,
    SignInUpPostOkResult,
)
from supertokens_python.recipe.thirdparty.provider import RedirectUriInfo
from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo, UserInfoEmail

if TYPE_CHECKING:
    from supertokens_python.recipe.thirdparty.interfaces import APIOptions
    from supertokens_python.recipe.thirdparty.provider import Provider

from supertokens_python.types.response import GeneralErrorResponse


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
        session: Optional[SessionContainer],
        should_try_linking_with_session_user: Union[bool, None],
        tenant_id: str,
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[
        SignInUpPostOkResult,
        SignInUpPostNoEmailGivenByProviderResponse,
        SignInUpNotAllowed,
        GeneralErrorResponse,
    ]:
        from supertokens_python.auth_utils import (
            OkResponse,
            PostAuthChecksOkResponse,
            SignInNotAllowedResponse,
            SignUpNotAllowedResponse,
            get_authenticating_user_and_add_to_current_tenant_if_required,
            post_auth_checks,
            pre_auth_checks,
        )

        error_code_map = {
            "SIGN_UP_NOT_ALLOWED": "Cannot sign in / up due to security reasons. Please try a different login method or contact support. (ERR_CODE_006)",
            "SIGN_IN_NOT_ALLOWED": "Cannot sign in / up due to security reasons. Please try a different login method or contact support. (ERR_CODE_004)",
            "LINKING_TO_SESSION_USER_FAILED": {
                "EMAIL_VERIFICATION_REQUIRED": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_020)",
                "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_021)",
                "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_022)",
                "SESSION_USER_ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR": "Cannot sign in / up due to security reasons. Please contact support. (ERR_CODE_023)",
            },
        }

        oauth_tokens_to_use: Dict[str, Any] = {}

        if redirect_uri_info is not None:
            oauth_tokens_to_use = await provider.exchange_auth_code_for_oauth_tokens(
                redirect_uri_info=redirect_uri_info,
                user_context=user_context,
            )
        elif oauth_tokens is not None:
            oauth_tokens_to_use = oauth_tokens
        else:
            raise Exception("should never come here")

        user_info = await provider.get_user_info(
            oauth_tokens=oauth_tokens_to_use,
            user_context=user_context,
        )

        if user_info.email is None and provider.config.require_email is False:
            # We don't expect to get an email from this provider.
            # So we generate a fake one
            assert provider.config.generate_fake_email is not None
            user_info.email = UserInfoEmail(
                email=await provider.config.generate_fake_email(
                    tenant_id, user_info.third_party_user_id, user_context
                ),
                is_verified=True,
            )

        email_info = user_info.email
        if email_info is None:
            return SignInUpPostNoEmailGivenByProviderResponse()

        recipe_id = "thirdparty"

        async def check_credentials_on_tenant(_: str):
            # We essentially did this above when calling exchange_auth_code_for_oauth_tokens
            return True

        authenticating_user = (
            await get_authenticating_user_and_add_to_current_tenant_if_required(
                third_party=ThirdPartyInfo(
                    third_party_user_id=user_info.third_party_user_id,
                    third_party_id=provider.id,
                ),
                email=None,
                phone_number=None,
                recipe_id=recipe_id,
                user_context=user_context,
                session=session,
                tenant_id=tenant_id,
                check_credentials_on_tenant=check_credentials_on_tenant,
            )
        )

        is_sign_up = authenticating_user is None
        if authenticating_user is not None:
            # This is a sign in. So before we proceed, we need to check if an email change
            # is allowed since the email could have changed from the social provider's side.
            # We do this check here and not in the recipe function cause we want to keep the
            # recipe function checks to a minimum so that the dev has complete control of
            # what they can do.

            # The is_email_change_allowed and pre_auth_checks functions take an is_verified boolean.
            # Now, even though we already have that from the input, that's just what the provider says.
            # If the provider says that the email is NOT verified, it could have been that the email
            # is verified on the user's account via supertokens on a previous sign in / up.
            # So we just check that as well before calling is_email_change_allowed

            assert authenticating_user.login_method is not None
            recipe_user_id = authenticating_user.login_method.recipe_user_id

            if (
                not email_info.is_verified
                and EmailVerificationRecipe.get_instance_optional() is not None
            ):
                email_info.is_verified = await is_email_verified(
                    recipe_user_id,
                    email_info.id,
                    user_context,
                )

        pre_auth_checks_result = await pre_auth_checks(
            authenticating_account_info=AccountInfoWithRecipeId(
                recipe_id=recipe_id,
                email=email_info.id,
                third_party=ThirdPartyInfo(
                    third_party_user_id=user_info.third_party_user_id,
                    third_party_id=provider.id,
                ),
            ),
            authenticating_user=(
                authenticating_user.user if authenticating_user else None
            ),
            factor_ids=["thirdparty"],
            is_sign_up=is_sign_up,
            is_verified=email_info.is_verified,
            sign_in_verifies_login_method=email_info.is_verified,
            skip_session_user_update_in_core=False,
            tenant_id=tenant_id,
            user_context=user_context,
            session=session,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if not isinstance(pre_auth_checks_result, OkResponse):
            if isinstance(pre_auth_checks_result, SignUpNotAllowedResponse):
                reason = error_code_map["SIGN_UP_NOT_ALLOWED"]
                assert isinstance(reason, str)
                return SignInUpNotAllowed(reason)
            if isinstance(pre_auth_checks_result, SignInNotAllowedResponse):
                reason = error_code_map["SIGN_IN_NOT_ALLOWED"]
                assert isinstance(reason, str)
                return SignInUpNotAllowed(reason)

            reason_dict = error_code_map["LINKING_TO_SESSION_USER_FAILED"]
            assert isinstance(reason_dict, Dict)
            reason = reason_dict[pre_auth_checks_result.reason]
            return SignInUpNotAllowed(reason=reason)

        signinup_response = await api_options.recipe_implementation.sign_in_up(
            third_party_id=provider.id,
            third_party_user_id=user_info.third_party_user_id,
            email=email_info.id,
            is_verified=email_info.is_verified,
            oauth_tokens=oauth_tokens_to_use,
            raw_user_info_from_provider=user_info.raw_user_info_from_provider,
            session=session,
            tenant_id=tenant_id,
            user_context=user_context,
            should_try_linking_with_session_user=should_try_linking_with_session_user,
        )

        if isinstance(signinup_response, SignInUpNotAllowed):
            return signinup_response

        if not isinstance(signinup_response, SignInUpOkResult):
            reason_dict = error_code_map["LINKING_TO_SESSION_USER_FAILED"]
            assert isinstance(reason_dict, Dict)
            reason = reason_dict[signinup_response.reason]
            return SignInUpNotAllowed(reason=reason)

        post_auth_checks_result = await post_auth_checks(
            factor_id="thirdparty",
            is_sign_up=is_sign_up,
            authenticated_user=signinup_response.user,
            recipe_user_id=signinup_response.recipe_user_id,
            request=api_options.request,
            tenant_id=tenant_id,
            user_context=user_context,
            session=session,
        )

        if not isinstance(post_auth_checks_result, PostAuthChecksOkResponse):
            reason = error_code_map["SIGN_IN_NOT_ALLOWED"]
            assert isinstance(reason, str)
            return SignInUpNotAllowed(reason)

        return SignInUpPostOkResult(
            created_new_recipe_user=signinup_response.created_new_recipe_user,
            user=post_auth_checks_result.user,
            session=post_auth_checks_result.session,
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
