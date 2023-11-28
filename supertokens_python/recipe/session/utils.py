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
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Union
from urllib.parse import urlparse

from typing_extensions import Literal

from supertokens_python.exceptions import raise_general_exception
from supertokens_python.framework import BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.utils import (
    is_an_ip_address,
    resolve,
    send_non_200_response,
    send_non_200_response_with_message,
)

from ...types import MaybeAwaitable
from .constants import AUTH_MODE_HEADER_KEY, SESSION_REFRESH
from .exceptions import ClaimValidationError

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest
    from supertokens_python.supertokens import AppInfo
    from supertokens_python.recipe.openid import (
        InputOverrideConfig as OpenIdInputOverrideConfig,
    )

    from .interfaces import (
        APIInterface,
        RecipeInterface,
        SessionContainer,
        SessionClaimValidator,
    )
    from .recipe import SessionRecipe

from supertokens_python.logger import log_debug_message


def normalise_session_scope(session_scope: str) -> str:
    def helper(scope: str) -> str:
        scope = scope.strip()

        if scope.startswith("."):
            scope = scope[1:]

        if (not scope.startswith("https://")) and (not scope.startswith("http://")):
            scope = "http://" + scope

        try:
            url_obj = urlparse(scope)
            if url_obj.hostname is None:
                raise Exception("Should not come here")
            scope = url_obj.hostname

            if scope.startswith("."):
                scope = scope[1:]

            return scope
        except Exception:
            raise_general_exception("Please provide a valid sessionScope")

    no_dot_normalised = helper(session_scope)
    if no_dot_normalised == "localhost" or is_an_ip_address(no_dot_normalised):
        return no_dot_normalised

    if no_dot_normalised[0] == ".":
        return no_dot_normalised[1:]

    return no_dot_normalised


def normalise_same_site(same_site: str) -> Literal["strict", "lax", "none"]:
    same_site = same_site.strip()
    same_site = same_site.lower()
    allowed_values = {"strict", "lax", "none"}
    if same_site not in allowed_values:
        raise Exception('cookie same site must be one of "strict", "lax", or "none"')
    return same_site  # type: ignore


def get_url_scheme(url: str) -> str:
    url_obj = urlparse(url)
    return url_obj.scheme


class ErrorHandlers:
    def __init__(
        self,
        on_token_theft_detected: Callable[
            [BaseRequest, str, str, BaseResponse],
            Union[BaseResponse, Awaitable[BaseResponse]],
        ],
        on_try_refresh_token: Callable[
            [BaseRequest, str, BaseResponse],
            Union[BaseResponse, Awaitable[BaseResponse]],
        ],
        on_unauthorised: Callable[
            [BaseRequest, str, BaseResponse],
            Union[BaseResponse, Awaitable[BaseResponse]],
        ],
        on_invalid_claim: Callable[
            [BaseRequest, List[ClaimValidationError], BaseResponse],
            Union[BaseResponse, Awaitable[BaseResponse]],
        ],
    ):
        self.__on_token_theft_detected = on_token_theft_detected
        self.__on_try_refresh_token = on_try_refresh_token
        self.__on_unauthorised = on_unauthorised
        self.__on_invalid_claim = on_invalid_claim

    async def on_token_theft_detected(
        self,
        request: BaseRequest,
        session_handle: str,
        user_id: str,
        response: BaseResponse,
    ) -> BaseResponse:
        return await resolve(
            self.__on_token_theft_detected(request, session_handle, user_id, response)
        )

    async def on_try_refresh_token(
        self, request: BaseRequest, message: str, response: BaseResponse
    ):
        result = await resolve(self.__on_try_refresh_token(request, message, response))
        return result

    async def on_unauthorised(
        self,
        request: BaseRequest,
        message: str,
        response: BaseResponse,
    ):
        return await resolve(self.__on_unauthorised(request, message, response))

    async def on_invalid_claim(
        self,
        recipe: SessionRecipe,
        request: BaseRequest,
        claim_validation_errors: List[ClaimValidationError],
        response: BaseResponse,
    ):
        _ = recipe
        result = await resolve(
            self.__on_invalid_claim(request, claim_validation_errors, response)
        )
        return result


class InputErrorHandlers(ErrorHandlers):
    def __init__(
        self,
        on_token_theft_detected: Union[
            None,
            Callable[
                [BaseRequest, str, str, BaseResponse],
                Union[BaseResponse, Awaitable[BaseResponse]],
            ],
        ] = None,
        on_unauthorised: Union[
            Callable[
                [BaseRequest, str, BaseResponse],
                Union[BaseResponse, Awaitable[BaseResponse]],
            ],
            None,
        ] = None,
        on_invalid_claim: Union[
            Callable[
                [BaseRequest, List[ClaimValidationError], BaseResponse],
                Union[BaseResponse, Awaitable[BaseResponse]],
            ],
            None,
        ] = None,
    ):
        if on_token_theft_detected is None:
            on_token_theft_detected = default_token_theft_detected_callback
        if on_unauthorised is None:
            on_unauthorised = default_unauthorised_callback
        if on_invalid_claim is None:
            on_invalid_claim = default_invalid_claim_callback
        super().__init__(
            on_token_theft_detected,
            default_try_refresh_token_callback,
            on_unauthorised,
            on_invalid_claim,
        )


async def default_unauthorised_callback(
    _: BaseRequest, __: str, response: BaseResponse
) -> BaseResponse:
    from .recipe import SessionRecipe

    return send_non_200_response_with_message(
        "unauthorised",
        SessionRecipe.get_instance().config.session_expired_status_code,
        response,
    )


async def default_try_refresh_token_callback(
    _: BaseRequest, __: str, response: BaseResponse
) -> BaseResponse:
    from .recipe import SessionRecipe

    return send_non_200_response_with_message(
        "try refresh token",
        SessionRecipe.get_instance().config.session_expired_status_code,
        response,
    )


async def default_token_theft_detected_callback(
    _: BaseRequest, session_handle: str, __: str, response: BaseResponse
) -> BaseResponse:
    from .recipe import SessionRecipe

    await SessionRecipe.get_instance().recipe_implementation.revoke_session(
        session_handle, {}
    )
    return send_non_200_response_with_message(
        "token theft detected",
        SessionRecipe.get_instance().config.session_expired_status_code,
        response,
    )


async def default_invalid_claim_callback(
    _: BaseRequest,
    claim_validation_errors: List[ClaimValidationError],
    response: BaseResponse,
) -> BaseResponse:
    from .recipe import SessionRecipe

    return send_non_200_response(
        {
            "message": "invalid claim",
            "claimValidationErrors": [err.to_json() for err in claim_validation_errors],
        },
        SessionRecipe.get_instance().config.invalid_claim_status_code,
        response,
    )


def get_auth_mode_from_header(request: BaseRequest) -> Optional[str]:
    auth_mode = request.get_header(AUTH_MODE_HEADER_KEY)
    if auth_mode is None:
        return None
    return auth_mode.lower()


def get_token_transfer_method_default(
    req: BaseRequest,
    for_create_new_session: bool,
    user_context: Dict[str, Any],
):
    _ = user_context

    # We allow fallback (checking headers then cookies) by default when validating
    if not for_create_new_session:
        return "any"

    auth_mode = get_auth_mode_from_header(req)
    if auth_mode in ("header", "cookie"):
        return auth_mode

    return "any"


class InputOverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
        openid_feature: Union[OpenIdInputOverrideConfig, None] = None,
    ):
        self.functions = functions
        self.apis = apis
        self.openid_feature = openid_feature


class OverrideConfig:
    def __init__(
        self,
        functions: Union[Callable[[RecipeInterface], RecipeInterface], None] = None,
        apis: Union[Callable[[APIInterface], APIInterface], None] = None,
    ):
        self.functions = functions
        self.apis = apis


TokenType = Literal["access", "refresh"]
TokenTransferMethod = Literal["cookie", "header"]


class SessionConfig:
    def __init__(
        self,
        refresh_token_path: NormalisedURLPath,
        cookie_domain: Union[None, str],
        get_cookie_same_site: Callable[
            [Optional[BaseRequest], Dict[str, Any]],
            Literal["lax", "strict", "none"],
        ],
        cookie_secure: bool,
        session_expired_status_code: int,
        error_handlers: ErrorHandlers,
        anti_csrf_function_or_string: Union[
            Callable[
                [Optional[BaseRequest], Dict[str, Any]],
                Literal["VIA_CUSTOM_HEADER", "NONE"],
            ],
            Literal["VIA_CUSTOM_HEADER", "NONE", "VIA_TOKEN"],
        ],
        get_token_transfer_method: Callable[
            [BaseRequest, bool, Dict[str, Any]],
            Union[TokenTransferMethod, Literal["any"]],
        ],
        override: OverrideConfig,
        framework: str,
        mode: str,
        invalid_claim_status_code: int,
        use_dynamic_access_token_signing_key: bool,
        expose_access_token_to_frontend_in_cookie_based_auth: bool,
    ):
        self.session_expired_status_code = session_expired_status_code
        self.invalid_claim_status_code = invalid_claim_status_code
        self.use_dynamic_access_token_signing_key = use_dynamic_access_token_signing_key
        self.expose_access_token_to_frontend_in_cookie_based_auth = (
            expose_access_token_to_frontend_in_cookie_based_auth
        )

        self.refresh_token_path = refresh_token_path
        self.cookie_domain = cookie_domain
        self.get_cookie_same_site = get_cookie_same_site
        self.cookie_secure = cookie_secure
        self.error_handlers = error_handlers
        self.anti_csrf_function_or_string = anti_csrf_function_or_string
        self.get_token_transfer_method = get_token_transfer_method
        self.override = override
        self.framework = framework
        self.mode = mode


def validate_and_normalise_user_input(
    app_info: AppInfo,
    cookie_domain: Union[str, None] = None,
    cookie_secure: Union[bool, None] = None,
    cookie_same_site: Union[Literal["lax", "strict", "none"], None] = None,
    session_expired_status_code: Union[int, None] = None,
    anti_csrf: Union[Literal["VIA_TOKEN", "VIA_CUSTOM_HEADER", "NONE"], None] = None,
    get_token_transfer_method: Union[
        Callable[
            [BaseRequest, bool, Dict[str, Any]],
            Union[TokenTransferMethod, Literal["any"]],
        ],
        None,
    ] = None,
    error_handlers: Union[ErrorHandlers, None] = None,
    override: Union[InputOverrideConfig, None] = None,
    invalid_claim_status_code: Union[int, None] = None,
    use_dynamic_access_token_signing_key: Union[bool, None] = None,
    expose_access_token_to_frontend_in_cookie_based_auth: Union[bool, None] = None,
):
    _ = cookie_same_site  # we have this otherwise pylint complains that cookie_same_site is unused, but it is being used in the get_cookie_same_site function.
    if anti_csrf not in {"VIA_TOKEN", "VIA_CUSTOM_HEADER", "NONE", None}:
        raise ValueError(
            "anti_csrf must be one of VIA_TOKEN, VIA_CUSTOM_HEADER, NONE or None"
        )

    if error_handlers is not None and not isinstance(error_handlers, ErrorHandlers):  # type: ignore
        raise ValueError("error_handlers must be an instance of ErrorHandlers or None")

    if override is not None and not isinstance(override, InputOverrideConfig):  # type: ignore
        raise ValueError("override must be an instance of InputOverrideConfig or None")

    cookie_domain = (
        normalise_session_scope(cookie_domain) if cookie_domain is not None else None
    )

    cookie_secure = (
        cookie_secure
        if cookie_secure is not None
        else app_info.api_domain.get_as_string_dangerous().startswith("https")
    )

    session_expired_status_code = (
        session_expired_status_code if session_expired_status_code is not None else 401
    )

    invalid_claim_status_code = (
        invalid_claim_status_code if invalid_claim_status_code is not None else 403
    )

    if session_expired_status_code == invalid_claim_status_code:
        raise Exception(
            "session_expired_status_code and invalid_claim_status_code cannot be the same "
            f"({invalid_claim_status_code})"
        )

    if get_token_transfer_method is None:
        get_token_transfer_method = get_token_transfer_method_default

    if error_handlers is None:
        error_handlers = InputErrorHandlers()

    if override is None:
        override = InputOverrideConfig()

    if use_dynamic_access_token_signing_key is None:
        use_dynamic_access_token_signing_key = True

    if expose_access_token_to_frontend_in_cookie_based_auth is None:
        expose_access_token_to_frontend_in_cookie_based_auth = False

    if cookie_same_site is not None:
        # this is just so that we check that the user has provided the right
        # values, since normalise_same_site throws an error if the user
        # as provided an empty string.
        _ = normalise_same_site(cookie_same_site)

    def get_cookie_same_site(
        request: Optional[BaseRequest], user_context: Dict[str, Any]
    ) -> Literal["lax", "strict", "none"]:
        nonlocal cookie_same_site
        if cookie_same_site is not None:
            return normalise_same_site(cookie_same_site)
        top_level_api_domain = app_info.top_level_api_domain
        top_level_website_domain = app_info.get_top_level_website_domain(
            request, user_context
        )

        api_domain_scheme = get_url_scheme(
            app_info.api_domain.get_as_string_dangerous()
        )
        website_domain_scheme = get_url_scheme(
            app_info.get_origin(request, user_context).get_as_string_dangerous()
        )
        if (top_level_api_domain != top_level_website_domain) or (
            api_domain_scheme != website_domain_scheme
        ):
            cookie_same_site = "none"
        else:
            cookie_same_site = "lax"
        return cookie_same_site

    def anti_csrf_function(
        request: Optional[BaseRequest], user_context: Dict[str, Any]
    ) -> Literal["NONE", "VIA_CUSTOM_HEADER"]:
        same_site = get_cookie_same_site(request, user_context)
        if same_site == "none":
            return "VIA_CUSTOM_HEADER"
        return "NONE"

    anti_csrf_function_or_string: Union[
        Callable[
            [Optional[BaseRequest], Dict[str, Any]],
            Literal["VIA_CUSTOM_HEADER", "NONE"],
        ],
        Literal["VIA_CUSTOM_HEADER", "NONE", "VIA_TOKEN"],
    ] = anti_csrf_function
    if anti_csrf is not None:
        anti_csrf_function_or_string = anti_csrf

    return SessionConfig(
        app_info.api_base_path.append(NormalisedURLPath(SESSION_REFRESH)),
        cookie_domain,
        get_cookie_same_site,
        cookie_secure,
        session_expired_status_code,
        error_handlers,
        anti_csrf_function_or_string,
        get_token_transfer_method,
        OverrideConfig(override.functions, override.apis),
        app_info.framework,
        app_info.mode,
        invalid_claim_status_code,
        use_dynamic_access_token_signing_key,
        expose_access_token_to_frontend_in_cookie_based_auth,
    )


async def get_required_claim_validators(
    session: SessionContainer,
    override_global_claim_validators: Optional[
        Callable[
            [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ],
    user_context: Dict[str, Any],
) -> List[SessionClaimValidator]:
    from .recipe import SessionRecipe

    claim_validators_added_by_other_recipes = (
        SessionRecipe.get_instance().get_claim_validators_added_by_other_recipes()
    )
    global_claim_validators = await resolve(
        SessionRecipe.get_instance().recipe_implementation.get_global_claim_validators(
            session.get_tenant_id(),
            session.get_user_id(),
            claim_validators_added_by_other_recipes,
            user_context,
        )
    )

    if override_global_claim_validators is not None:
        return await resolve(
            override_global_claim_validators(
                global_claim_validators, session, user_context
            )
        )

    return global_claim_validators


async def validate_claims_in_payload(
    claim_validators: List[SessionClaimValidator],
    new_access_token_payload: Dict[str, Any],
    user_context: Dict[str, Any],
):
    validation_errors: List[ClaimValidationError] = []
    for validator in claim_validators:
        claim_validation_res = await validator.validate(
            new_access_token_payload, user_context
        )
        log_debug_message(
            "validate_claims_in_payload %s validate res %s",
            validator.id,
            json.dumps(claim_validation_res.__dict__),
        )
        if not claim_validation_res.is_valid:
            validation_errors.append(
                ClaimValidationError(validator.id, claim_validation_res.reason)
            )

    return validation_errors
