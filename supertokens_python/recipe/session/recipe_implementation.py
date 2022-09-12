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
from typing import TYPE_CHECKING, Any, Dict, Optional
from supertokens_python.framework.request import BaseRequest
from supertokens_python.logger import log_debug_message
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.process_state import AllowedProcessStates, ProcessState
from supertokens_python.utils import (
    execute_async,
    frontend_has_interceptor,
    get_timestamp_ms,
    normalise_http_method,
    resolve,
)
from . import session_functions
from .cookie_and_header import (
    get_access_token_from_cookie,
    get_anti_csrf_header,
    get_id_refresh_token_from_cookie,
    get_refresh_token_from_cookie,
    get_rid_header,
)
from .exceptions import raise_try_refresh_token_exception, raise_unauthorised_exception
from .interfaces import (
    AccessTokenObj,
    RecipeInterface,
    RegenerateAccessTokenOkResult,
    SessionClaim,
    SessionClaimValidator,
    SessionInformationResult,
    SessionObj,
    ClaimsValidationResult,
    SessionDoesNotExistError,
    JSONObject,
    GetClaimValueOkResult,
)
from .session_class import Session
from ...types import MaybeAwaitable
from .utils import (
    SessionConfig,
    validate_claims_in_payload,
)

if TYPE_CHECKING:
    from typing import List, Union

    from supertokens_python.querier import Querier


from .interfaces import SessionContainer


class HandshakeInfo:
    def __init__(self, info: Dict[str, Any]):
        self.access_token_blacklisting_enabled = info["accessTokenBlacklistingEnabled"]
        self.raw_jwt_signing_public_key_list: List[Dict[str, Any]] = []
        self.anti_csrf = info["antiCsrf"]
        self.access_token_validity = info["accessTokenValidity"]
        self.refresh_token_validity = info["refreshTokenValidity"]

    def set_jwt_signing_public_key_list(self, updated_list: List[Dict[str, Any]]):
        self.raw_jwt_signing_public_key_list = updated_list

    def get_jwt_signing_public_key_list(self) -> List[Dict[str, Any]]:
        time_now = get_timestamp_ms()
        return [
            key
            for key in self.raw_jwt_signing_public_key_list
            if key["expiryTime"] > time_now
        ]


class RecipeImplementation(RecipeInterface):  # pylint: disable=too-many-public-methods
    def __init__(self, querier: Querier, config: SessionConfig):
        super().__init__()
        self.querier = querier
        self.config = config
        self.handshake_info: Union[HandshakeInfo, None] = None

        async def call_get_handshake_info():
            try:
                await self.get_handshake_info()
            except Exception:
                pass

        try:
            execute_async(config.mode, call_get_handshake_info)
        except Exception:
            pass

    async def get_handshake_info(self, force_refetch: bool = False) -> HandshakeInfo:
        if (
            self.handshake_info is None
            or len(self.handshake_info.get_jwt_signing_public_key_list()) == 0
            or force_refetch
        ):
            ProcessState.get_instance().add_state(
                AllowedProcessStates.CALLING_SERVICE_IN_GET_HANDSHAKE_INFO
            )
            response = await self.querier.send_post_request(
                NormalisedURLPath("/recipe/handshake"), {}
            )
            self.handshake_info = HandshakeInfo(
                {**response, "antiCsrf": self.config.anti_csrf}
            )

            self.update_jwt_signing_public_key_info(
                response["jwtSigningPublicKeyList"],
                response["jwtSigningPublicKey"],
                response["jwtSigningPublicKeyExpiryTime"],
            )

        return self.handshake_info

    def update_jwt_signing_public_key_info(
        self,
        key_list: Union[List[Dict[str, Any]], None],
        public_key: str,
        expiry_time: int,
    ):
        if key_list is None:
            key_list = [
                {
                    "publicKey": public_key,
                    "expiryTime": expiry_time,
                    "createdAt": get_timestamp_ms(),
                }
            ]

        if self.handshake_info is not None:
            self.handshake_info.set_jwt_signing_public_key_list(key_list)

    async def create_new_session(
        self,
        request: BaseRequest,
        user_id: str,
        access_token_payload: Union[None, Dict[str, Any]],
        session_data: Union[None, Dict[str, Any]],
        user_context: Dict[str, Any],
    ) -> SessionContainer:
        session = await session_functions.create_new_session(
            self, user_id, access_token_payload, session_data
        )
        access_token = session["accessToken"]
        refresh_token = session["refreshToken"]
        id_refresh_token = session["idRefreshToken"]
        new_session = Session(
            self,
            access_token["token"],
            session["session"]["handle"],
            session["session"]["userId"],
            session["session"]["userDataInJWT"],
        )
        new_session.new_access_token_info = access_token
        new_session.new_refresh_token_info = refresh_token
        new_session.new_id_refresh_token_info = id_refresh_token
        if "antiCsrfToken" in session and session["antiCsrfToken"] is not None:
            new_session.new_anti_csrf_token = session["antiCsrfToken"]
        request.set_session(new_session)
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
                    validator.claim.fetch_value(user_id, user_context)
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
        request: BaseRequest,
        anti_csrf_check: Union[bool, None],
        session_required: bool,
        user_context: Dict[str, Any],
    ) -> Optional[SessionContainer]:
        log_debug_message("getSession: Started")

        log_debug_message(
            "getSession: rid in header: %s", str(frontend_has_interceptor(request))
        )
        log_debug_message("getSession: request method: %s", request.method())

        id_refresh_token = get_id_refresh_token_from_cookie(request)
        if id_refresh_token is None:
            if not session_required:
                log_debug_message(
                    "getSession: returning None because idRefreshToken is undefined and session_required is false"
                )
                return None
            log_debug_message(
                "getSession: UNAUTHORISED because idRefreshToken from cookies is undefined"
            )
            raise_unauthorised_exception(
                "Session does not exist. Are you sending the session tokens in the request as cookies?",
                False,
            )
        access_token: Union[str, None] = get_access_token_from_cookie(request)
        if access_token is None:
            if (
                session_required is True
                or frontend_has_interceptor(request)
                or normalise_http_method(request.method()) == "get"
            ):
                log_debug_message(
                    "getSession: Returning try refresh token because access token from cookies is undefined"
                )
                raise_try_refresh_token_exception(
                    "Access token has expired. Please call the refresh API"
                )
            return None
        anti_csrf_token = get_anti_csrf_header(request)
        if anti_csrf_check is None:
            anti_csrf_check = normalise_http_method(request.method()) != "get"

        log_debug_message(
            "getSession: Value of doAntiCsrfCheck is: %s", str(anti_csrf_check)
        )
        new_session = await session_functions.get_session(
            self,
            access_token,
            anti_csrf_token,
            anti_csrf_check,
            get_rid_header(request) is not None,
        )
        if "accessToken" in new_session:
            access_token = new_session["accessToken"]["token"]

        if access_token is None:
            raise Exception("Should never come here")
        session = Session(
            self,
            access_token,
            new_session["session"]["handle"],
            new_session["session"]["userId"],
            new_session["session"]["userDataInJWT"],
        )

        if "accessToken" in new_session:
            session.new_access_token_info = new_session["accessToken"]

        log_debug_message("getSession: Success!")
        request.set_session(session)
        return request.get_session()

    async def refresh_session(
        self, request: BaseRequest, user_context: Dict[str, Any]
    ) -> SessionContainer:
        log_debug_message("refreshSession: Started")

        id_refresh_token = get_id_refresh_token_from_cookie(request)
        if id_refresh_token is None:
            log_debug_message(
                "refreshSession: UNAUTHORISED because idRefreshToken from cookies is undefined"
            )
            raise_unauthorised_exception(
                "Session does not exist. Are you sending the session tokens in the request "
                "as cookies?",
                False,
            )
        refresh_token = get_refresh_token_from_cookie(request)
        if refresh_token is None:
            log_debug_message(
                "refreshSession: UNAUTHORISED because refresh token from cookies is undefined"
            )
            raise_unauthorised_exception(
                "Refresh token not found. Are you sending the refresh token in the "
                "request as a cookie?"
            )
        anti_csrf_token = get_anti_csrf_header(request)
        new_session = await session_functions.refresh_session(
            self, refresh_token, anti_csrf_token, get_rid_header(request) is not None
        )
        access_token = new_session["accessToken"]
        refresh_token = new_session["refreshToken"]
        id_refresh_token = new_session["idRefreshToken"]
        session = Session(
            self,
            access_token["token"],
            new_session["session"]["handle"],
            new_session["session"]["userId"],
            new_session["session"]["userDataInJWT"],
        )
        session.new_access_token_info = access_token
        session.new_refresh_token_info = refresh_token
        session.new_id_refresh_token_info = id_refresh_token
        if "antiCsrfToken" in new_session and new_session["antiCsrfToken"] is not None:
            session.new_anti_csrf_token = new_session["antiCsrfToken"]

        log_debug_message("refreshSession: Success!")
        request.set_session(session)
        return session

    async def revoke_session(
        self, session_handle: str, user_context: Dict[str, Any]
    ) -> bool:
        return await session_functions.revoke_session(self, session_handle)

    async def revoke_all_sessions_for_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> List[str]:
        return await session_functions.revoke_all_sessions_for_user(self, user_id)

    async def get_all_session_handles_for_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> List[str]:
        return await session_functions.get_all_session_handles_for_user(self, user_id)

    async def revoke_multiple_sessions(
        self, session_handles: List[str], user_context: Dict[str, Any]
    ) -> List[str]:
        return await session_functions.revoke_multiple_sessions(self, session_handles)

    async def get_session_information(
        self, session_handle: str, user_context: Dict[str, Any]
    ) -> Union[SessionInformationResult, None]:
        return await session_functions.get_session_information(self, session_handle)

    async def update_session_data(
        self,
        session_handle: str,
        new_session_data: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> bool:
        return await session_functions.update_session_data(
            self, session_handle, new_session_data
        )

    async def update_access_token_payload(
        self,
        session_handle: str,
        new_access_token_payload: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> bool:

        return await session_functions.update_access_token_payload(
            self, session_handle, new_access_token_payload
        )

    async def get_access_token_lifetime_ms(self, user_context: Dict[str, Any]) -> int:
        return (await self.get_handshake_info()).access_token_validity

    async def get_refresh_token_lifetime_ms(self, user_context: Dict[str, Any]) -> int:
        return (await self.get_handshake_info()).refresh_token_validity

    async def merge_into_access_token_payload(
        self,
        session_handle: str,
        access_token_payload_update: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> bool:
        session_info = await self.get_session_information(session_handle, user_context)
        if session_info is None:
            return False

        new_access_token_payload = {
            **session_info.access_token_payload,
            **access_token_payload_update,
        }
        for k in access_token_payload_update.keys():
            if new_access_token_payload[k] is None:
                del new_access_token_payload[k]

        return await self.update_access_token_payload(
            session_handle, new_access_token_payload, user_context
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
            session_info.user_id, user_context
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
                session_info.access_token_payload, user_context
            )
        )

    def get_global_claim_validators(
        self,
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
        response: Dict[str, Any] = await self.querier.send_post_request(
            NormalisedURLPath("/recipe/session/regenerate"),
            {"accessToken": access_token, "userDataInJWT": new_access_token_payload},
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
        )
        return RegenerateAccessTokenOkResult(session, access_token_obj)
