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
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional

from supertokens_python.logger import log_debug_message
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.utils import resolve

from ...types import MaybeAwaitable
from . import session_functions
from .access_token import validate_access_token_structure
from .cookie_and_header import build_front_token
from .exceptions import UnauthorisedError
from .interfaces import (
    AccessTokenObj,
    ClaimsValidationResult,
    GetClaimValueOkResult,
    JSONObject,
    RecipeInterface,
    RegenerateAccessTokenOkResult,
    SessionClaim,
    SessionClaimValidator,
    SessionDoesNotExistError,
    SessionInformationResult,
    SessionObj,
)
from .jwt import ParsedJWTInfo, parse_jwt_without_signature_verification
from .session_class import Session
from .utils import SessionConfig, validate_claims_in_payload

if TYPE_CHECKING:
    from typing import List, Union
    from supertokens_python import AppInfo

from .interfaces import SessionContainer
from .constants import protected_props
from supertokens_python.querier import Querier
from supertokens_python.recipe.multitenancy.constants import DEFAULT_TENANT_ID


class RecipeImplementation(RecipeInterface):  # pylint: disable=too-many-public-methods
    def __init__(self, querier: Querier, config: SessionConfig, app_info: AppInfo):
        super().__init__()
        self.querier = querier
        self.config = config
        self.app_info = app_info

    async def create_new_session(
        self,
        user_id: str,
        access_token_payload: Optional[Dict[str, Any]],
        session_data_in_database: Optional[Dict[str, Any]],
        disable_anti_csrf: Optional[bool],
        tenant_id: str,
        user_context: Dict[str, Any],
    ) -> SessionContainer:
        log_debug_message("createNewSession: Started")

        result = await session_functions.create_new_session(
            self,
            tenant_id,
            user_id,
            disable_anti_csrf is True,
            access_token_payload,
            session_data_in_database,
            user_context=user_context,
        )
        log_debug_message("createNewSession: Finished")

        payload = parse_jwt_without_signature_verification(
            result.accessToken.token
        ).payload

        new_session = Session(
            self,
            self.config,
            result.accessToken.token,
            build_front_token(
                result.session.userId, result.accessToken.expiry, payload
            ),
            result.refreshToken,
            result.antiCsrfToken,
            result.session.handle,
            result.session.userId,
            payload,
            None,
            True,
            tenant_id,
        )

        return new_session

    async def validate_claims(
        self,
        user_id: str,
        access_token_payload: Dict[str, Any],
        claim_validators: List[SessionClaimValidator],
        user_context: Dict[str, Any],
    ) -> ClaimsValidationResult:
        access_token_payload_update = None
        original_access_token_payload = json.dumps(access_token_payload)

        for validator in claim_validators:
            log_debug_message(
                "update_claims_in_payload_if_needed checking should_refetch for %s",
                validator.id,
            )
            if validator.claim is not None and validator.should_refetch(
                access_token_payload, user_context
            ):
                log_debug_message(
                    "update_claims_in_payload_if_needed refetching for %s", validator.id
                )
                value = await resolve(
                    validator.claim.fetch_value(
                        user_id,
                        access_token_payload.get("tId", DEFAULT_TENANT_ID),
                        user_context,
                    )
                )
                log_debug_message(
                    "update_claims_in_payload_if_needed %s refetch result %s",
                    validator.id,
                    json.dumps(value),
                )
                if value is not None:
                    access_token_payload = validator.claim.add_to_payload_(
                        access_token_payload, value, user_context
                    )

        if json.dumps(access_token_payload) != original_access_token_payload:
            access_token_payload_update = access_token_payload

        invalid_claims = await validate_claims_in_payload(
            claim_validators, access_token_payload, user_context
        )

        return ClaimsValidationResult(invalid_claims, access_token_payload_update)

    async def validate_claims_in_jwt_payload(
        self,
        user_id: str,
        jwt_payload: JSONObject,
        claim_validators: List[SessionClaimValidator],
        user_context: Dict[str, Any],
    ) -> ClaimsValidationResult:
        invalid_claims = await validate_claims_in_payload(
            claim_validators,
            jwt_payload,
            user_context,
        )

        return ClaimsValidationResult(invalid_claims)

    async def get_session(
        self,
        access_token: Optional[str],
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
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[SessionContainer]:
        if (
            anti_csrf_check is not False
            and isinstance(self.config.anti_csrf_function_or_string, str)
            and self.config.anti_csrf_function_or_string == "VIA_CUSTOM_HEADER"
        ):
            raise Exception(
                "Since the anti-csrf mode is VIA_CUSTOM_HEADER getSession can't check the CSRF token. Please either use VIA_TOKEN or set anti_csrf_check to false"
            )

        log_debug_message("getSession: Started")

        if access_token is None:
            if session_required is False:
                log_debug_message(
                    "getSession: returning None because access_token is undefined and session_required is False"
                )
                # there is no session that exists here, and the user wants session verification to be optional. So we return None
                return None

            log_debug_message(
                "getSession: UNAUTHORISED because accessToken in request is undefined"
            )
            # we do not clear the session here because of a race condition mentioned in https://github.com/supertokens/supertokens-node/issues/17
            raise UnauthorisedError(
                "Session does not exist. Are you sending the session tokens in the request with the appropriate token transfer method?",
                clear_tokens=False,
            )

        access_token_obj: Optional[ParsedJWTInfo] = None
        try:
            access_token_obj = parse_jwt_without_signature_verification(access_token)
            validate_access_token_structure(
                access_token_obj.payload, access_token_obj.version
            )
        except Exception as _:
            if session_required is False:
                log_debug_message(
                    "getSession: Returning undefined because parsing failed and session_required is False"
                )
                return None

            log_debug_message(
                "getSession: UNAUTHORISED because the accessToken couldn't be parsed or had an invalid structure"
            )
            raise UnauthorisedError("Token parsing failed", clear_tokens=False)

        response = await session_functions.get_session(
            self,
            access_token_obj,
            anti_csrf_token,
            (anti_csrf_check is not False),
            (check_database is True),
            user_context,
        )

        log_debug_message("getSession: Success!")

        if access_token_obj.version >= 3:
            if response.accessToken is not None:
                payload = parse_jwt_without_signature_verification(
                    response.accessToken.token
                ).payload
            else:
                payload = access_token_obj.payload
        else:
            payload = response.session.userDataInJWT

        if response.accessToken is not None:
            access_token_str = response.accessToken.token
            expiry_time = response.accessToken.expiry
            access_token_updated = True
        else:
            access_token_str = access_token
            expiry_time = response.session.expiryTime
            access_token_updated = False

        session = Session(
            self,
            self.config,
            access_token_str,
            build_front_token(response.session.userId, expiry_time, payload),
            None,  # refresh_token
            anti_csrf_token,
            response.session.handle,
            response.session.userId,
            payload,
            None,
            access_token_updated,
            response.session.tenant_id,
        )

        return session

    async def refresh_session(
        self,
        refresh_token: str,
        anti_csrf_token: Optional[str],
        disable_anti_csrf: bool,
        user_context: Dict[str, Any],
    ) -> SessionContainer:
        if (
            disable_anti_csrf is not True
            and isinstance(self.config.anti_csrf_function_or_string, str)
            and self.config.anti_csrf_function_or_string == "VIA_CUSTOM_HEADER"
        ):
            raise Exception(
                "Since the anti-csrf mode is VIA_CUSTOM_HEADER getSession can't check the CSRF token. Please either use VIA_TOKEN or set antiCsrfCheck to false"
            )

        log_debug_message("refreshSession: Started")

        response = await session_functions.refresh_session(
            self,
            refresh_token,
            anti_csrf_token,
            disable_anti_csrf,
            user_context=user_context,
        )

        log_debug_message("refreshSession: Success!")

        payload = parse_jwt_without_signature_verification(
            response.accessToken.token,
        ).payload

        session = Session(
            self,
            self.config,
            response.accessToken.token,
            build_front_token(
                response.session.userId,
                response.accessToken.expiry,
                payload,
            ),
            response.refreshToken,
            response.antiCsrfToken,
            response.session.handle,
            response.session.userId,
            user_data_in_access_token=payload,
            req_res_info=None,
            access_token_updated=True,
            tenant_id=payload["tId"],
        )

        return session

    async def revoke_session(
        self, session_handle: str, user_context: Dict[str, Any]
    ) -> bool:
        return await session_functions.revoke_session(
            self, session_handle, user_context
        )

    async def revoke_all_sessions_for_user(
        self,
        user_id: str,
        tenant_id: Optional[str],
        revoke_across_all_tenants: bool,
        user_context: Dict[str, Any],
    ) -> List[str]:
        return await session_functions.revoke_all_sessions_for_user(
            self, user_id, tenant_id, revoke_across_all_tenants, user_context
        )

    async def get_all_session_handles_for_user(
        self,
        user_id: str,
        tenant_id: Optional[str],
        fetch_across_all_tenants: bool,
        user_context: Dict[str, Any],
    ) -> List[str]:
        return await session_functions.get_all_session_handles_for_user(
            self, user_id, tenant_id, fetch_across_all_tenants, user_context
        )

    async def revoke_multiple_sessions(
        self, session_handles: List[str], user_context: Dict[str, Any]
    ) -> List[str]:
        return await session_functions.revoke_multiple_sessions(
            self, session_handles, user_context
        )

    async def get_session_information(
        self, session_handle: str, user_context: Dict[str, Any]
    ) -> Union[SessionInformationResult, None]:
        return await session_functions.get_session_information(
            self, session_handle, user_context
        )

    async def update_session_data_in_database(
        self,
        session_handle: str,
        new_session_data: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> bool:
        return await session_functions.update_session_data_in_database(
            self, session_handle, new_session_data, user_context
        )

    async def merge_into_access_token_payload(
        self,
        session_handle: str,
        access_token_payload_update: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> bool:
        session_info = await self.get_session_information(session_handle, user_context)
        if session_info is None:
            return False

        new_access_token_payload = session_info.custom_claims_in_access_token_payload
        for k in protected_props:
            if k in new_access_token_payload:
                del new_access_token_payload[k]

        new_access_token_payload = {
            **new_access_token_payload,
            **access_token_payload_update,
        }
        for k in access_token_payload_update.keys():
            if new_access_token_payload[k] is None:
                del new_access_token_payload[k]

        return await session_functions.update_access_token_payload(
            self, session_handle, new_access_token_payload, user_context
        )

    async def fetch_and_set_claim(
        self,
        session_handle: str,
        claim: SessionClaim[Any],
        user_context: Dict[str, Any],
    ) -> bool:
        session_info = await self.get_session_information(session_handle, user_context)
        if session_info is None:
            return False

        access_token_payload_update = await claim.build(
            session_info.user_id, session_info.tenant_id, user_context
        )
        return await self.merge_into_access_token_payload(
            session_handle, access_token_payload_update, user_context
        )

    async def set_claim_value(
        self,
        session_handle: str,
        claim: SessionClaim[Any],
        value: Any,
        user_context: Dict[str, Any],
    ):
        access_token_payload_update = claim.add_to_payload_({}, value, user_context)
        return await self.merge_into_access_token_payload(
            session_handle, access_token_payload_update, user_context
        )

    async def get_claim_value(
        self,
        session_handle: str,
        claim: SessionClaim[Any],
        user_context: Dict[str, Any],
    ) -> Union[SessionDoesNotExistError, GetClaimValueOkResult[Any]]:
        session_info = await self.get_session_information(session_handle, user_context)
        if session_info is None:
            return SessionDoesNotExistError()

        return GetClaimValueOkResult(
            value=claim.get_value_from_payload(
                session_info.custom_claims_in_access_token_payload, user_context
            )
        )

    def get_global_claim_validators(
        self,
        tenant_id: str,
        user_id: str,
        claim_validators_added_by_other_recipes: List[SessionClaimValidator],
        user_context: Dict[str, Any],
    ) -> MaybeAwaitable[List[SessionClaimValidator]]:
        return claim_validators_added_by_other_recipes

    async def remove_claim(
        self,
        session_handle: str,
        claim: SessionClaim[Any],
        user_context: Dict[str, Any],
    ) -> bool:
        access_token_payload = claim.remove_from_payload_by_merge_({}, user_context)
        return await self.merge_into_access_token_payload(
            session_handle, access_token_payload, user_context
        )

    async def regenerate_access_token(
        self,
        access_token: str,
        new_access_token_payload: Union[Dict[str, Any], None],
        user_context: Dict[str, Any],
    ) -> Union[RegenerateAccessTokenOkResult, None]:
        if new_access_token_payload is None:
            new_access_token_payload = {}
        response = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/session/regenerate"),
            {"accessToken": access_token, "userDataInJWT": new_access_token_payload},
            user_context=user_context,
        )
        if response["status"] == "UNAUTHORISED":
            return None
        access_token_obj: Union[None, AccessTokenObj] = None
        if "accessToken" in response:
            access_token_obj = AccessTokenObj(
                response["accessToken"]["token"],
                response["accessToken"]["expiry"],
                response["accessToken"]["createdTime"],
            )
        session = SessionObj(
            response["session"]["handle"],
            response["session"]["userId"],
            response["session"]["userDataInJWT"],
            response["session"]["tenantId"],
        )
        return RegenerateAccessTokenOkResult(session, access_token_obj)
