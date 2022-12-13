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

from typing import Any, Dict, List, Union, Callable, Optional, TypeVar

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.recipe.openid.interfaces import (
    GetOpenIdDiscoveryConfigurationResult,
)
from supertokens_python.types import MaybeAwaitable

from ...jwt.interfaces import (
    CreateJwtOkResult,
    CreateJwtResultUnsupportedAlgorithm,
    GetJWKSResult,
)
from ..interfaces import (
    RegenerateAccessTokenOkResult,
    SessionContainer,
    SessionInformationResult,
    SessionClaimValidator,
    SessionClaim,
    JSONObject,
    ClaimsValidationResult,
    SessionDoesNotExistError,
    GetClaimValueOkResult,
)


def create_new_session(
    request: Any,
    user_id: str,
    access_token_payload: Union[Dict[str, Any], None] = None,
    session_data: Union[Dict[str, Any], None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> SessionContainer:
    from supertokens_python.recipe.session.asyncio import (
        create_new_session as async_create_new_session,
    )

    return sync(
        async_create_new_session(
            request,
            user_id,
            access_token_payload,
            session_data,
            user_context=user_context,
        )
    )


def get_session(
    request: Any,
    anti_csrf_check: Union[bool, None] = None,
    session_required: bool = True,
    override_global_claim_validators: Optional[
        Callable[
            [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[SessionContainer, None]:
    from supertokens_python.recipe.session.asyncio import (
        get_session as async_get_session,
    )

    return sync(
        async_get_session(
            request,
            anti_csrf_check,
            session_required,
            override_global_claim_validators,
            user_context,
        )
    )


def refresh_session(
    request: Any, user_context: Union[None, Dict[str, Any]] = None
) -> SessionContainer:
    from supertokens_python.recipe.session.asyncio import (
        refresh_session as async_refresh_session,
    )

    return sync(async_refresh_session(request, user_context))


def revoke_session(
    session_handle: str, user_context: Union[None, Dict[str, Any]] = None
) -> bool:
    from supertokens_python.recipe.session.asyncio import (
        revoke_session as async_revoke_session,
    )

    return sync(async_revoke_session(session_handle, user_context))


def revoke_all_sessions_for_user(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[str]:
    from supertokens_python.recipe.session.asyncio import (
        revoke_all_sessions_for_user as async_revoke_all_sessions_for_user,
    )

    return sync(async_revoke_all_sessions_for_user(user_id, user_context))


def get_all_session_handles_for_user(
    user_id: str, user_context: Union[None, Dict[str, Any]] = None
) -> List[str]:
    from supertokens_python.recipe.session.asyncio import (
        get_all_session_handles_for_user as async_get_all_session_handles_for_user,
    )

    return sync(async_get_all_session_handles_for_user(user_id, user_context))


def revoke_multiple_sessions(
    session_handles: List[str], user_context: Union[None, Dict[str, Any]] = None
) -> List[str]:
    from supertokens_python.recipe.session.asyncio import (
        revoke_multiple_sessions as async_revoke_multiple_sessions,
    )

    return sync(async_revoke_multiple_sessions(session_handles, user_context))


def get_session_information(
    session_handle: str, user_context: Union[None, Dict[str, Any]] = None
) -> Union[SessionInformationResult, None]:
    from supertokens_python.recipe.session.asyncio import (
        get_session_information as async_get_session_information,
    )

    return sync(async_get_session_information(session_handle, user_context))


def update_session_data(
    session_handle: str,
    new_session_data: Dict[str, Any],
    user_context: Union[None, Dict[str, Any]] = None,
) -> bool:
    from supertokens_python.recipe.session.asyncio import (
        update_session_data as async_update_session_data,
    )

    return sync(
        async_update_session_data(session_handle, new_session_data, user_context)
    )


def update_access_token_payload(
    session_handle: str,
    new_access_token_payload: Dict[str, Any],
    user_context: Union[None, Dict[str, Any]] = None,
) -> bool:
    from supertokens_python.recipe.session.asyncio import (
        update_access_token_payload as async_update_access_token_payload,
    )

    return sync(
        async_update_access_token_payload(
            session_handle, new_access_token_payload, user_context
        )
    )


def merge_into_access_token_payload(
    session_handle: str,
    new_access_token_payload: Dict[str, Any],
    user_context: Union[None, Dict[str, Any]] = None,
) -> bool:
    from supertokens_python.recipe.session.asyncio import (
        merge_into_access_token_payload as async_merge_into_access_token_payload,
    )

    return sync(
        async_merge_into_access_token_payload(
            session_handle, new_access_token_payload, user_context
        )
    )


def create_jwt(
    payload: Dict[str, Any],
    validity_seconds: Union[None, int] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[CreateJwtOkResult, CreateJwtResultUnsupportedAlgorithm]:
    from supertokens_python.recipe.session.asyncio import create_jwt as async_create_jwt

    return sync(async_create_jwt(payload, validity_seconds, user_context))


def get_jwks(user_context: Union[None, Dict[str, Any]] = None) -> GetJWKSResult:
    from supertokens_python.recipe.session.asyncio import get_jwks as async_get_jwks

    return sync(async_get_jwks(user_context))


def get_open_id_discovery_configuration(
    user_context: Union[None, Dict[str, Any]] = None
) -> GetOpenIdDiscoveryConfigurationResult:
    from supertokens_python.recipe.session.asyncio import (
        get_open_id_discovery_configuration as async_get_open_id_discovery_configuration,
    )

    return sync(async_get_open_id_discovery_configuration(user_context))


def regenerate_access_token(
    access_token: str,
    new_access_token_payload: Union[Dict[str, Any], None] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[RegenerateAccessTokenOkResult, None]:
    from supertokens_python.recipe.session.asyncio import (
        regenerate_access_token as async_regenerate_access_token,
    )

    return sync(
        async_regenerate_access_token(
            access_token, new_access_token_payload, user_context
        )
    )


_T = TypeVar("_T")


def fetch_and_set_claim(
    session_handle: str,
    claim: SessionClaim[Any],
    user_context: Union[None, Dict[str, Any]] = None,
) -> bool:
    from supertokens_python.recipe.session.asyncio import (
        fetch_and_set_claim as async_fetch_and_set_claim,
    )

    return sync(async_fetch_and_set_claim(session_handle, claim, user_context))


def set_claim_value(
    session_handle: str,
    claim: SessionClaim[_T],
    value: _T,
    user_context: Union[None, Dict[str, Any]] = None,
) -> bool:
    from supertokens_python.recipe.session.asyncio import (
        set_claim_value as async_set_claim_value,
    )

    return sync(async_set_claim_value(session_handle, claim, value, user_context))


def get_claim_value(
    session_handle: str,
    claim: SessionClaim[_T],
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[SessionDoesNotExistError, GetClaimValueOkResult[_T]]:
    from supertokens_python.recipe.session.asyncio import (
        get_claim_value as async_get_claim_value,
    )

    return sync(async_get_claim_value(session_handle, claim, user_context))


def remove_claim(
    session_handle: str,
    claim: SessionClaim[Any],
    user_context: Union[None, Dict[str, Any]] = None,
) -> bool:
    from supertokens_python.recipe.session.asyncio import (
        remove_claim as async_remove_claim,
    )

    return sync(async_remove_claim(session_handle, claim, user_context))


def validate_claims_for_session_handle(
    session_handle: str,
    override_global_claim_validators: Optional[
        Callable[
            [List[SessionClaimValidator], SessionInformationResult, Dict[str, Any]],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[SessionDoesNotExistError, ClaimsValidationResult]:
    from supertokens_python.recipe.session.asyncio import (
        validate_claims_for_session_handle as async_validate_claims_for_session_handle,
    )

    return sync(
        async_validate_claims_for_session_handle(
            session_handle, override_global_claim_validators, user_context
        )
    )


def validate_claims_in_jwt_payload(
    user_id: str,
    jwt_payload: JSONObject,
    override_global_claim_validators: Optional[
        Callable[
            [List[SessionClaimValidator], str, Dict[str, Any]],
            MaybeAwaitable[List[SessionClaimValidator]],
        ]
    ] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from supertokens_python.recipe.session.asyncio import (
        validate_claims_in_jwt_payload as async_validate_claims_in_jwt_payload,
    )

    return sync(
        async_validate_claims_in_jwt_payload(
            user_id, jwt_payload, override_global_claim_validators, user_context
        )
    )
