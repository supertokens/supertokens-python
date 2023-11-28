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

from typing import Any, Callable, Dict, List, Optional, Union, TYPE_CHECKING

from supertokens_python.logger import log_debug_message
from supertokens_python.recipe.session.access_token import (
    validate_access_token_structure,
)
from supertokens_python.recipe.session.constants import available_token_transfer_methods
from supertokens_python.recipe.session.cookie_and_header import (
    clear_session_mutator,
    get_anti_csrf_header,
    get_token,
    set_cookie_response_mutator,
)
from supertokens_python.recipe.session.exceptions import (
    raise_try_refresh_token_exception,
    raise_unauthorised_exception,
)
from supertokens_python.recipe.session.interfaces import (
    RecipeInterface as SessionRecipeInterface,
)
from supertokens_python.recipe.session.interfaces import (
    SessionClaimValidator,
    SessionContainer,
)
from supertokens_python.recipe.session.exceptions import (
    SuperTokensSessionError,
    TokenTheftError,
    UnauthorisedError,
)
from supertokens_python.recipe.session.jwt import (
    ParsedJWTInfo,
    parse_jwt_without_signature_verification,
)
from supertokens_python.recipe.session.utils import (
    SessionConfig,
    TokenTransferMethod,
    get_required_claim_validators,
)
from supertokens_python.types import MaybeAwaitable
from supertokens_python.utils import (
    FRAMEWORKS,
    get_rid_from_header,
    is_an_ip_address,
    normalise_http_method,
    set_request_in_user_context_if_not_defined,
)
from supertokens_python.supertokens import Supertokens
from .constants import protected_props

if TYPE_CHECKING:
    from supertokens_python.recipe.session.recipe import SessionRecipe
    from supertokens_python.supertokens import AppInfo
    from .interfaces import ResponseMutator

LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME = "sIdRefreshToken"


async def get_session_from_request(
    request: Any,
    config: SessionConfig,
    recipe_interface_impl: SessionRecipeInterface,
    session_required: Optional[bool] = None,
    anti_csrf_check: Optional[bool] = None,
    check_database: Optional[bool] = None,
    override_global_claim_validators: Optional[
        Callable[
            [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> Optional[SessionContainer]:
    log_debug_message("getSession: Started")

    if not hasattr(request, "wrapper_used") or not request.wrapper_used:
        request = FRAMEWORKS[
            Supertokens.get_instance().app_info.framework
        ].wrap_request(request)

    log_debug_message("getSession: Wrapping done")

    user_context = set_request_in_user_context_if_not_defined(user_context, request)

    # This token isn't handled by getToken to limit the scope of this legacy/migration code
    if request.get_cookie(LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME) is not None:
        log_debug_message(
            "getSession: Throwing TRY_REFRESH_TOKEN because the request is using a legacy session"
        )
        # This could create a spike on refresh calls during the update of the backend SDK
        return raise_try_refresh_token_exception(
            "using legacy session, please call the refresh API"
        )

    session_optional = not session_required
    log_debug_message("getSession: optional validation: %s", session_optional)

    access_tokens: Dict[TokenTransferMethod, ParsedJWTInfo] = {}

    # We check all token transfer methods for available access tokens
    for transfer_method in available_token_transfer_methods:
        token_string = get_token(request, "access", transfer_method)

        if token_string is not None:
            try:
                info = parse_jwt_without_signature_verification(token_string)
                validate_access_token_structure(info.payload, info.version)
                log_debug_message(
                    "getSession: got access token from %s", transfer_method
                )
                access_tokens[transfer_method] = info
            except Exception:
                log_debug_message(
                    "getSession: ignoring token in %s, because it doesn't match our access token structure",
                    transfer_method,
                )

    allowed_transfer_method = config.get_token_transfer_method(
        request, False, user_context
    )
    request_transfer_method: Optional[TokenTransferMethod] = None
    request_access_token: Union[ParsedJWTInfo, None] = None

    if (allowed_transfer_method in ("any", "header")) and access_tokens.get(
        "header"
    ) is not None:
        log_debug_message("getSession: using header transfer method")
        request_transfer_method = "header"
        request_access_token = access_tokens["header"]
    elif (allowed_transfer_method in ("any", "cookie")) and access_tokens.get(
        "cookie"
    ) is not None:
        log_debug_message("getSession: using cookie transfer method")
        request_transfer_method = "cookie"
        request_access_token = access_tokens["cookie"]

    anti_csrf_token = get_anti_csrf_header(request)
    do_anti_csrf_check = anti_csrf_check

    if do_anti_csrf_check is None:
        do_anti_csrf_check = normalise_http_method(request.method()) != "get"
    if request_transfer_method == "header":
        do_anti_csrf_check = False
    if request_access_token is None:
        do_anti_csrf_check = False

    if callable(config.anti_csrf_function_or_string):
        anti_csrf = config.anti_csrf_function_or_string(request, user_context)
    else:
        anti_csrf = config.anti_csrf_function_or_string

    if do_anti_csrf_check and anti_csrf == "VIA_CUSTOM_HEADER":
        if anti_csrf == "VIA_CUSTOM_HEADER":
            if get_rid_from_header(request) is None:
                log_debug_message(
                    "getSession: Returning TRY_REFRESH_TOKEN because custom header (rid) was not passed"
                )
                raise_try_refresh_token_exception(
                    "anti-csrf check failed. Please pass 'rid: \"session\"' header in the request, or set doAntiCsrfCheck to false for this API"
                )

            log_debug_message("getSession: VIA_CUSTOM_HEADER anti-csrf check passed")
            do_anti_csrf_check = False

    log_debug_message("getSession: Value of antiCsrfToken is: %s", do_anti_csrf_check)

    session = await recipe_interface_impl.get_session(
        access_token=request_access_token.raw_token_string
        if request_access_token is not None
        else None,
        anti_csrf_token=anti_csrf_token,
        anti_csrf_check=do_anti_csrf_check,
        session_required=session_required,
        check_database=check_database,
        override_global_claim_validators=override_global_claim_validators,
        user_context=user_context,
    )

    if session is not None:
        claim_validators = await get_required_claim_validators(
            session, override_global_claim_validators, user_context
        )
        await session.assert_claims(claim_validators, user_context)

        # request_transfer_method can only be None here if the user overriddes get_session
        # to load the session by a custom method in that (very niche) case they also need to
        # override how the session is attached to the response.
        # In that scenario the transferMethod passed to attachToRequestResponse likely doesn't
        # matter, still, we follow the general fallback logic

        if request_transfer_method is not None:
            final_transfer_method = request_transfer_method
        elif allowed_transfer_method != "any":
            final_transfer_method = allowed_transfer_method
        else:
            final_transfer_method = "header"

        await session.attach_to_request_response(
            request, final_transfer_method, user_context
        )

    return session


async def create_new_session_in_request(
    request: Any,
    user_context: Dict[str, Any],
    recipe_instance: SessionRecipe,
    access_token_payload: Dict[str, Any],
    user_id: str,
    config: SessionConfig,
    app_info: AppInfo,
    session_data_in_database: Dict[str, Any],
    tenant_id: str,
) -> SessionContainer:
    log_debug_message("createNewSession: Started")

    if not hasattr(request, "wrapper_used") or not request.wrapper_used:
        request = FRAMEWORKS[
            Supertokens.get_instance().app_info.framework
        ].wrap_request(request)

    log_debug_message("createNewSession: Wrapping done")
    user_context = set_request_in_user_context_if_not_defined(user_context, request)

    claims_added_by_other_recipes = recipe_instance.get_claims_added_by_other_recipes()
    app_info = recipe_instance.app_info
    issuer = (
        app_info.api_domain.get_as_string_dangerous()
        + app_info.api_base_path.get_as_string_dangerous()
    )

    final_access_token_payload = {**access_token_payload, "iss": issuer}

    for prop in protected_props:
        if prop in final_access_token_payload:
            del final_access_token_payload[prop]

    for claim in claims_added_by_other_recipes:
        update = await claim.build(user_id, tenant_id, user_context)
        final_access_token_payload = {**final_access_token_payload, **update}

    log_debug_message("createNewSession: Access token payload built")

    output_transfer_method = config.get_token_transfer_method(
        request, True, user_context
    )
    if output_transfer_method == "any":
        output_transfer_method = "header"
    log_debug_message(
        "createNewSession: using transfer method %s", output_transfer_method
    )

    if (
        output_transfer_method == "cookie"
        and config.get_cookie_same_site(request, user_context) == "none"
        and not config.cookie_secure
        and not (
            (
                app_info.top_level_api_domain == "localhost"
                or is_an_ip_address(app_info.top_level_api_domain)
            )
            and (
                app_info.get_top_level_website_domain(request, user_context)
                == "localhost"
                or is_an_ip_address(
                    app_info.get_top_level_website_domain(request, user_context)
                )
            )
        )
    ):
        # We can allow insecure cookie when both website & API domain are localhost or an IP
        # When either of them is a different domain, API domain needs to have https and a secure cookie to work
        raise Exception(
            "Since your API and website domain are different, for sessions to work, please use https on your apiDomain and don't set cookieSecure to false."
        )

    disable_anti_csrf = output_transfer_method == "header"
    session = await recipe_instance.recipe_implementation.create_new_session(
        user_id,
        final_access_token_payload,
        session_data_in_database,
        disable_anti_csrf,
        tenant_id,
        user_context=user_context,
    )

    log_debug_message("createNewSession: Session created in core built")

    for transfer_method in available_token_transfer_methods:
        if (
            transfer_method != output_transfer_method
            and get_token(request, "access", transfer_method) is not None
        ):
            session.response_mutators.append(
                clear_session_mutator(config, transfer_method, request)
            )

    log_debug_message("createNewSession: Cleared old tokens")

    await session.attach_to_request_response(
        request, output_transfer_method, user_context
    )
    log_debug_message("createNewSession: Attached new tokens to res")

    return session


# In all cases: if sIdRefreshToken token exists (so it's a legacy session) we clear it.
# Check http://localhost:3002/docs/contribute/decisions/session/0008 for further details and a table of expected behaviours


async def refresh_session_in_request(
    request: Any,
    user_context: Dict[str, Any],
    config: SessionConfig,
    recipe_interface_impl: SessionRecipeInterface,
) -> SessionContainer:
    log_debug_message("refreshSession: Started")

    response_mutators: List[ResponseMutator] = []

    if not hasattr(request, "wrapper_used") or not request.wrapper_used:
        request = FRAMEWORKS[
            Supertokens.get_instance().app_info.framework
        ].wrap_request(request)

    log_debug_message("refreshSession: Wrapping done")
    user_context = set_request_in_user_context_if_not_defined(user_context, request)

    refresh_tokens: Dict[TokenTransferMethod, Optional[str]] = {}

    for transfer_method in available_token_transfer_methods:
        refresh_tokens[transfer_method] = get_token(request, "refresh", transfer_method)
        if refresh_tokens[transfer_method] is not None:
            log_debug_message(
                "refreshSession: got refresh token from %s", transfer_method
            )

    allowed_transfer_method = config.get_token_transfer_method(
        request, False, user_context
    )
    log_debug_message(
        "refreshSession: getTokenTransferMethod returned: %s",
        allowed_transfer_method,
    )

    request_transfer_method: TokenTransferMethod
    refresh_token: Optional[str]

    if (allowed_transfer_method in ("any", "header")) and (
        refresh_tokens.get("header")
    ):
        log_debug_message("refreshSession: using header transfer method")
        request_transfer_method = "header"
        refresh_token = refresh_tokens["header"]
    elif (allowed_transfer_method in ("any", "cookie")) and (
        refresh_tokens.get("cookie")
    ):
        log_debug_message("refreshSession: using cookie transfer method")
        request_transfer_method = "cookie"
        refresh_token = refresh_tokens["cookie"]
    else:
        # This token isn't handled by getToken/setToken to limit the scope of this legacy/migration code
        if request.get_cookie(LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME) is not None:
            log_debug_message(
                "refreshSession: cleared legacy id refresh token because refresh token was not found"
            )
            response_mutators.append(
                set_cookie_response_mutator(
                    config,
                    LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME,
                    "",
                    0,
                    "access_token_path",
                    request,
                )
            )

        log_debug_message(
            "refreshSession: UNAUTHORISED because refresh_token in request is None"
        )
        return raise_unauthorised_exception(
            "Refresh token not found. Are you sending the refresh token in the request?",
            clear_tokens=False,
            response_mutators=response_mutators,
        )

    assert refresh_token is not None

    disable_anti_csrf = request_transfer_method == "header"
    anti_csrf_token = get_anti_csrf_header(request)

    anti_csrf = config.anti_csrf_function_or_string
    if callable(anti_csrf):
        anti_csrf = anti_csrf(request, user_context)

    if anti_csrf == "VIA_CUSTOM_HEADER" and not disable_anti_csrf:
        if get_rid_from_header(request) is None:
            log_debug_message(
                "refreshSession: Returning UNAUTHORISED because anti-csrf token is undefined"
            )
            # see https://github.com/supertokens/supertokens-node/issues/141
            raise_unauthorised_exception(
                "anti-csrf check failed. Please pass 'rid: \"session\"' header in the request.",
                clear_tokens=False,
            )
        disable_anti_csrf = True

    session: Optional[SessionContainer] = None
    try:
        session = await recipe_interface_impl.refresh_session(
            refresh_token, anti_csrf_token, disable_anti_csrf, user_context
        )
    except SuperTokensSessionError as e:
        if isinstance(e, TokenTheftError) or (
            isinstance(e, UnauthorisedError) and getattr(e, "clear_tokens") is True
        ):
            # We clear the LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME here because we want to limit the scope of
            # this legacy/migration code so the token clearing functions in the error handlers do not.
            if request.get_cookie(LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME) is not None:
                log_debug_message(
                    "refreshSession: cleared legacy id refresh token because refresh token was not found"
                )
                response_mutators.append(
                    set_cookie_response_mutator(
                        config,
                        LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME,
                        "",
                        0,
                        "access_token_path",
                        request,
                    )
                )

        e.response_mutators.extend(response_mutators)
        raise e

    log_debug_message(
        "refreshSession: Attaching refreshed session info as %s",
        request_transfer_method,
    )

    # We clear the tokens in all token transfer methods we are not going to overwrite:
    for transfer_method in available_token_transfer_methods:
        if (
            transfer_method != request_transfer_method
            and refresh_tokens[transfer_method] is not None
        ):
            response_mutators.append(
                clear_session_mutator(config, transfer_method, request)
            )

    await session.attach_to_request_response(
        request, request_transfer_method, user_context
    )
    log_debug_message("refreshSession: Success!")

    # This token isn't handled by getToken/setToken to limit the scope of this legacy/migration code
    if request.get_cookie(LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME) is not None:
        log_debug_message(
            "refreshSession: cleared legacy id refresh token after successful refresh"
        )
        response_mutators.append(
            set_cookie_response_mutator(
                config,
                LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME,
                "",
                0,
                "access_token_path",
                request,
            )
        )

    session.response_mutators.extend(response_mutators)
    return session
