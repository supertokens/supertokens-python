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
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

from supertokens_python.recipe.openid.interfaces import (
    GetOpenIdDiscoveryConfigurationResult,
)
from supertokens_python.recipe.session.interfaces import (
    ClaimsValidationResult,
    GetClaimValueOkResult,
    JSONObject,
    SessionClaim,
    SessionClaimValidator,
    SessionContainer,
    SessionDoesNotExistError,
    SessionInformationResult,
)
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.types import MaybeAwaitable
from supertokens_python.utils import FRAMEWORKS, resolve

from ...jwt.interfaces import (
    CreateJwtOkResult,
    CreateJwtResultUnsupportedAlgorithm,
    GetJWKSResult,
)
from ..session_request_functions import (
    create_new_session_in_request,
    get_session_from_request,
    refresh_session_in_request,
)
from ..constants import protected_props
from ..utils import get_required_claim_validators

from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID

_T = TypeVar("_T")


async def create_new_session(
    request: Any,
    tenant_id: str,
    user_id: str,
    access_token_payload: Union[Dict[str, Any], None] = None,
    session_data_in_database: Union[Dict[str, Any], None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> SessionContainer:
    if user_context is None:
        user_context = {}
    if session_data_in_database is None:
        session_data_in_database = {}
    if access_token_payload is None:
        access_token_payload = {}

    recipe_instance = SessionRecipe.get_instance()
    config = recipe_instance.config
    app_info = recipe_instance.app_info

    return await create_new_session_in_request(
        request,
        user_context,
        recipe_instance,
        access_token_payload,
        user_id,
        config,
        app_info,
        session_data_in_database,
        tenant_id,
    )


async def create_new_session_without_request_response(
    tenant_id: str,
    user_id: str,
    access_token_payload: Union[Dict[str, Any], None] = None,
    session_data_in_database: Union[Dict[str, Any], None] = None,
    disable_anti_csrf: bool = False,
    user_context: Union[None, Dict[str, Any]] = None,
) -> SessionContainer:
    if user_context is None:
        user_context = {}
    if session_data_in_database is None:
        session_data_in_database = {}
    if access_token_payload is None:
        access_token_payload = {}

    claims_added_by_other_recipes = (
        SessionRecipe.get_instance().get_claims_added_by_other_recipes()
    )
    app_info = SessionRecipe.get_instance().app_info
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

    return await SessionRecipe.get_instance().recipe_implementation.create_new_session(
        user_id,
        final_access_token_payload,
        session_data_in_database,
        disable_anti_csrf,
        tenant_id,
        user_context=user_context,
    )


async def validate_claims_for_session_handle(
    session_handle: str,
    override_global_claim_validators: Optional[
        Callable[
            [
                List[SessionClaimValidator],
                SessionInformationResult,
                Dict[str, Any],
            ],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[SessionDoesNotExistError, ClaimsValidationResult]:
    if user_context is None:
        user_context = {}

    recipe_impl = SessionRecipe.get_instance().recipe_implementation
    session_info = await recipe_impl.get_session_information(
        session_handle, user_context
    )

    if session_info is None:
        return SessionDoesNotExistError()

    claim_validators_added_by_other_recipes = (
        SessionRecipe.get_instance().get_claim_validators_added_by_other_recipes()
    )
    global_claim_validators = await resolve(
        recipe_impl.get_global_claim_validators(
            session_info.tenant_id,
            session_info.user_id,
            claim_validators_added_by_other_recipes,
            user_context,
        )
    )

    if override_global_claim_validators is not None:
        claim_validators = await resolve(
            override_global_claim_validators(
                global_claim_validators, session_info, user_context
            )
        )
    else:
        claim_validators = global_claim_validators

    claim_validation_res = await recipe_impl.validate_claims(
        session_info.user_id,
        session_info.custom_claims_in_access_token_payload,
        claim_validators,
        user_context,
    )

    if claim_validation_res.access_token_payload_update is not None:
        updated = await recipe_impl.merge_into_access_token_payload(
            session_handle,
            claim_validation_res.access_token_payload_update,
            user_context,
        )
        if not updated:
            return SessionDoesNotExistError()

    return ClaimsValidationResult(claim_validation_res.invalid_claims)


async def validate_claims_in_jwt_payload(
    tenant_id: str,
    user_id: str,
    jwt_payload: JSONObject,
    override_global_claim_validators: Optional[
        Callable[
            [
                List[SessionClaimValidator],
                str,
                Dict[str, Any],
            ],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}

    recipe_impl = SessionRecipe.get_instance().recipe_implementation

    claim_validators_added_by_other_recipes = (
        SessionRecipe.get_instance().get_claim_validators_added_by_other_recipes()
    )
    global_claim_validators = await resolve(
        recipe_impl.get_global_claim_validators(
            tenant_id,
            user_id,
            claim_validators_added_by_other_recipes,
            user_context,
        )
    )

    if override_global_claim_validators is not None:
        claim_validators = await resolve(
            override_global_claim_validators(
                global_claim_validators, user_id, user_context
            )
        )
    else:
        claim_validators = global_claim_validators

    return await recipe_impl.validate_claims_in_jwt_payload(
        user_id, jwt_payload, claim_validators, user_context
    )


async def fetch_and_set_claim(
    session_handle: str,
    claim: SessionClaim[Any],
    user_context: Union[None, Dict[str, Any]] = None,
) -> bool:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.fetch_and_set_claim(
        session_handle, claim, user_context
    )


async def get_claim_value(
    session_handle: str,
    claim: SessionClaim[_T],
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[SessionDoesNotExistError, GetClaimValueOkResult[_T]]:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.get_claim_value(
        session_handle, claim, user_context
    )


async def set_claim_value(
    session_handle: str,
    claim: SessionClaim[_T],
    value: _T,
    user_context: Union[None, Dict[str, Any]] = None,
) -> bool:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.set_claim_value(
        session_handle, claim, value, user_context
    )


async def remove_claim(
    session_handle: str,
    claim: SessionClaim[Any],
    user_context: Union[None, Dict[str, Any]] = None,
) -> bool:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.remove_claim(
        session_handle, claim, user_context
    )


async def get_session(
    request: Any,
    session_required: Optional[bool] = None,
    anti_csrf_check: Optional[bool] = None,
    check_database: Optional[bool] = None,
    override_global_claim_validators: Optional[
        Callable[
            [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[SessionContainer, None]:
    if user_context is None:
        user_context = {}

    if session_required is None:
        session_required = True

    recipe_instance = SessionRecipe.get_instance()
    recipe_interface_impl = recipe_instance.recipe_implementation
    config = recipe_instance.config

    return await get_session_from_request(
        request,
        config,
        recipe_interface_impl,
        session_required=session_required,
        anti_csrf_check=anti_csrf_check,
        check_database=check_database,
        override_global_claim_validators=override_global_claim_validators,
        user_context=user_context,
    )


async def get_session_without_request_response(
    access_token: str,
    anti_csrf_token: Optional[str] = None,
    anti_csrf_check: Optional[bool] = None,
    session_required: Optional[bool] = None,
    check_database: Optional[bool] = None,
    override_global_claim_validators: Optional[
        Callable[
            [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Optional[SessionContainer]:
    """Tries to validate an access token and build a Session object from it.

    Notes about anti-csrf checking:
    - if the `antiCsrf` is set to VIA_HEADER in the Session recipe config you have to handle anti-csrf checking before calling this function and set antiCsrfCheck to false in the options.
    - you can disable anti-csrf checks by setting antiCsrf to NONE in the Session recipe config. We only recommend this if you are always getting the access-token from the Authorization header.
    - if the antiCsrf check fails the returned status will be TRY_REFRESH_TOKEN_ERROR

    Args:
    - access_token: The access token extracted from the authorization header or cookies
    - anti_csrf_token: The anti-csrf token extracted from the authorization header or cookies. Can be undefined if antiCsrfCheck is false
    - anti_csrf_check: If true, anti-csrf checking will be done. If false, it will be skipped. Default behaviour is to check.
    - session_required: If true, throws an error if the session does not exist. Default is True.
    - check_database: If true, the session will be checked in the database. If false, it will be skipped. Default behaviour is to skip.
    - override_global_claim_validators: Alter the
    - user_context: user context

    Results:
    - OK: The session was successfully validated, including claim validation
    - CLAIM_VALIDATION_ERROR: While the access token is valid, one or more claim validators have failed. Our frontend SDKs expect a 403 response the contents matching the value returned from this function.
    - TRY_REFRESH_TOKEN_ERROR: This means, that the access token structure was valid, but it didn't pass validation for some reason and the user should call the refresh API.
        You can send a 401 response to trigger this behaviour if you are using our frontend SDKs
    - UNAUTHORISED: This means that the access token likely doesn't belong to a SuperTokens session. If this is unexpected, it's best handled by sending a 401 response.
    """
    if user_context is None:
        user_context = {}

    if session_required is None:
        session_required = True

    recipe_interface_impl = SessionRecipe.get_instance().recipe_implementation

    session = await recipe_interface_impl.get_session(
        access_token,
        anti_csrf_token,
        anti_csrf_check,
        session_required,
        check_database,
        override_global_claim_validators,
        user_context,
    )

    if session is not None:
        claim_validators = await get_required_claim_validators(
            session, override_global_claim_validators, user_context
        )
        await session.assert_claims(claim_validators, user_context)

    return session


async def refresh_session(
    request: Any,
    user_context: Union[None, Dict[str, Any]] = None,
) -> SessionContainer:
    if user_context is None:
        user_context = {}

    if not hasattr(request, "wrapper_used") or not request.wrapper_used:
        request = FRAMEWORKS[
            SessionRecipe.get_instance().app_info.framework
        ].wrap_request(request)

    recipe_instance = SessionRecipe.get_instance()
    config = recipe_instance.config
    recipe_interface_impl = recipe_instance.recipe_implementation

    return await refresh_session_in_request(
        request,
        user_context,
        config,
        recipe_interface_impl,
    )


async def refresh_session_without_request_response(
    refresh_token: str,
    disable_anti_csrf: bool = False,
    anti_csrf_token: Optional[str] = None,
    user_context: Optional[Dict[str, Any]] = None,
) -> SessionContainer:
    if user_context is None:
        user_context = {}

    return await SessionRecipe.get_instance().recipe_implementation.refresh_session(
        refresh_token, anti_csrf_token, disable_anti_csrf, user_context
    )


async def revoke_session(
    session_handle: str, user_context: Union[None, Dict[str, Any]] = None
) -> bool:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.revoke_session(
        session_handle, user_context
    )


async def revoke_all_sessions_for_user(
    user_id: str,
    tenant_id: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> List[str]:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.revoke_all_sessions_for_user(
        user_id, tenant_id or DEFAULT_TENANT_ID, tenant_id is None, user_context
    )


async def get_all_session_handles_for_user(
    user_id: str,
    tenant_id: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> List[str]:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.get_all_session_handles_for_user(
        user_id, tenant_id or DEFAULT_TENANT_ID, tenant_id is None, user_context
    )


async def revoke_multiple_sessions(
    session_handles: List[str], user_context: Union[None, Dict[str, Any]] = None
) -> List[str]:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.revoke_multiple_sessions(
        session_handles, user_context
    )


async def get_session_information(
    session_handle: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[SessionInformationResult, None]:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.get_session_information(
        session_handle, user_context
    )


async def update_session_data_in_database(
    session_handle: str,
    new_session_data: Dict[str, Any],
    user_context: Union[None, Dict[str, Any]] = None,
) -> bool:
    if user_context is None:
        user_context = {}
    return await SessionRecipe.get_instance().recipe_implementation.update_session_data_in_database(
        session_handle, new_session_data, user_context
    )


async def merge_into_access_token_payload(
    session_handle: str,
    new_access_token_payload: Dict[str, Any],
    user_context: Union[None, Dict[str, Any]] = None,
) -> bool:
    if user_context is None:
        user_context = {}

    return await SessionRecipe.get_instance().recipe_implementation.merge_into_access_token_payload(
        session_handle, new_access_token_payload, user_context
    )


async def create_jwt(
    payload: Dict[str, Any],
    validity_seconds: Optional[int] = None,
    use_static_signing_key: Optional[bool] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[CreateJwtOkResult, CreateJwtResultUnsupportedAlgorithm]:
    if user_context is None:
        user_context = {}
    openid_recipe = SessionRecipe.get_instance().openid_recipe

    return await openid_recipe.recipe_implementation.create_jwt(
        payload, validity_seconds, use_static_signing_key, user_context
    )


async def get_jwks(user_context: Union[None, Dict[str, Any]] = None) -> GetJWKSResult:
    if user_context is None:
        user_context = {}
    openid_recipe = SessionRecipe.get_instance().openid_recipe
    return await openid_recipe.recipe_implementation.get_jwks(user_context)


async def get_open_id_discovery_configuration(
    user_context: Union[None, Dict[str, Any]] = None
) -> GetOpenIdDiscoveryConfigurationResult:
    if user_context is None:
        user_context = {}
    openid_recipe = SessionRecipe.get_instance().openid_recipe

    return (
        await openid_recipe.recipe_implementation.get_open_id_discovery_configuration(
            user_context
        )
    )
