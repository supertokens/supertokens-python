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
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional

from supertokens_python.framework.request import BaseRequest
from supertokens_python.logger import log_debug_message
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.process_state import AllowedProcessStates, ProcessState
from supertokens_python.utils import (
    execute_async,
    get_timestamp_ms,
    normalise_http_method,
    resolve,
)

from ...framework import BaseResponse
from ...types import MaybeAwaitable
from . import session_functions
from .access_token import validate_access_token_structure
from .cookie_and_header import (
    clear_session,
    get_anti_csrf_header,
    get_rid_header,
    get_token,
    set_cookie,
    set_token,
)
from .exceptions import (
    TokenTheftError,
    UnauthorisedError,
    raise_try_refresh_token_exception,
    raise_unauthorised_exception,
)
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
from .utils import SessionConfig, TokenTransferMethod, validate_claims_in_payload

if TYPE_CHECKING:
    from typing import List, Union
    from supertokens_python import AppInfo
    from supertokens_python.querier import Querier

from .constants import available_token_transfer_methods
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


LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME = "sIdRefreshToken"


class RecipeImplementation(RecipeInterface):  # pylint: disable=too-many-public-methods
    def __init__(self, querier: Querier, config: SessionConfig, app_info: AppInfo):
        super().__init__()
        self.querier = querier
        self.config = config
        self.app_info = app_info
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
        response: BaseResponse,
        user_id: str,
        access_token_payload: Union[None, Dict[str, Any]],
        session_data: Union[None, Dict[str, Any]],
        user_context: Dict[str, Any],
    ) -> SessionContainer:
        log_debug_message("createNewSession: Started")
        output_transfer_method = self.config.get_token_transfer_method(
            request, True, user_context
        )
        if output_transfer_method == "any":
            output_transfer_method = "header"

        log_debug_message(
            "createNewSession: using transfer method %s", output_transfer_method
        )

        disable_anti_csrf = output_transfer_method == "header"

        session = await session_functions.create_new_session(
            self,
            user_id,
            disable_anti_csrf,
            access_token_payload,
            session_data,
        )

        transfer_methods: List[TokenTransferMethod] = available_token_transfer_methods  # type: ignore

        for transfer_method in transfer_methods:
            if (
                transfer_method != output_transfer_method
                and get_token(request, "access", transfer_method) is not None
            ):
                clear_session(self.config, response, transfer_method)

        access_token = session["accessToken"]
        refresh_token = session["refreshToken"]
        # id_refresh_token = session["idRefreshToken"]

        new_session = Session(
            self,
            access_token["token"],
            session["session"]["handle"],
            session["session"]["userId"],
            session["session"]["userDataInJWT"],
            output_transfer_method,
        )
        new_session.new_access_token_info = access_token
        new_session.new_refresh_token_info = refresh_token
        # new_session.new_id_refresh_token_info = id_refresh_token
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
        response: BaseResponse,
        anti_csrf_check: Union[bool, None],
        session_required: bool,
        user_context: Dict[str, Any],
    ) -> Optional[SessionContainer]:
        log_debug_message("getSession: Started")

        # This token isn't handled by getToken to limit the scope of this legacy/migration code
        if request.get_cookie(LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME) is not None:
            # This could create a spike on refresh calls during the update of the backend SDK
            raise_try_refresh_token_exception(
                "using legacy session, please call the refresh API"
            )

        session_optional = not session_required
        log_debug_message("getSession: optional validation: %s", session_optional)

        access_tokens: Dict[TokenTransferMethod, ParsedJWTInfo] = {}

        # FIXME Find a cleaner way. This is unnecessary because of Literal
        transfer_methods: List[TokenTransferMethod] = available_token_transfer_methods  # type: ignore

        # We check all token transfer methods for available access tokens
        for transfer_method in transfer_methods:
            token_string = get_token(request, "access", transfer_method)

            if token_string is not None:
                try:
                    info = parse_jwt_without_signature_verification(token_string)
                    validate_access_token_structure(info.payload)
                    log_debug_message(
                        "getSession: got access token from %s", transfer_method
                    )
                    access_tokens[transfer_method] = info
                except Exception:
                    log_debug_message(
                        "getSession: ignoring token in %s, because it doesn't match our access token structure",
                        transfer_method,
                    )

        allowed_transfer_method = self.config.get_token_transfer_method(
            request, False, user_context
        )
        request_transfer_method: TokenTransferMethod
        access_token: Union[ParsedJWTInfo, None]

        if (
            allowed_transfer_method == "any" or allowed_transfer_method == "header"
        ) and access_tokens.get("header") is not None:
            log_debug_message("getSession: using header transfer method")
            request_transfer_method = "header"
            access_token = access_tokens["header"]
        elif (
            allowed_transfer_method == "any" or allowed_transfer_method == "cookie"
        ) and access_tokens.get("cookie") is not None:
            log_debug_message("getSession: using header transfer method")
            request_transfer_method = "cookie"
            access_token = access_tokens["cookie"]
        else:
            if session_optional:
                log_debug_message(
                    "getSession: returning undefined because access_token is None and session_required is False"
                )
                # there is no session that exists here, and the user wants session verification
                # to be optional. So we return None
                return None

            log_debug_message(
                "getSession: UNAUTHORIZED because access_token in request is None"
            )
            # we do not clear the session here because of a race condition mentioned here: https://github.com/supertokens/supertokens-node/issues/17
            raise_unauthorised_exception(
                "Session does not exist. Are you sending the session tokens in the request as with the appropriate token transfer method?",
                clear_tokens=False,
            )

        try:
            anti_csrf_token = get_anti_csrf_header(request)
            do_anti_csrf_check = anti_csrf_check

            if do_anti_csrf_check is None:
                do_anti_csrf_check = normalise_http_method(request.method()) != "get"
            if request_transfer_method == "header":
                do_anti_csrf_check = False
            log_debug_message(
                "getSession: Value of doAntiCsrfCheck is: %s", do_anti_csrf_check
            )

            new_session = await session_functions.get_session(
                self,
                access_token,
                anti_csrf_token,
                do_anti_csrf_check,
                get_rid_header(request) is not None,
            )

            access_token_string = access_token.raw_token_string
            if new_session.get("accessToken") is not None:
                # We set the expiration to 100 years, because we can't really access the expiration of the refresh token everywhere we are setting it.
                # This should be safe to do, since this is only the validity of the cookie (set here or on the frontend) but we check the expiration of the JWT anyway.
                # Even if the token is expired the presence of the token indicates that the user could have a valid refresh
                # Setting them to infinity would require special case handling on the frontend and just adding 10 years seems enough
                set_token(
                    self.config,
                    response,
                    "access",
                    new_session["acessToken"]["token"],
                    int(datetime.now().timestamp()) + 3153600000000,
                    request_transfer_method,
                )
                access_token_string = new_session["accessToken"]["token"]

            log_debug_message("getSession: Success!")
            session = Session(
                self,
                access_token_string,
                new_session["session"]["handle"],
                new_session["session"]["userId"],
                new_session["session"]["userDataInJWT"],
                request_transfer_method,
            )
            if "accessToken" in new_session:
                session.new_access_token_info = new_session["accessToken"]
            if "refreshToken" in new_session:
                session.new_refresh_token_info = new_session["refreshToken"]

            request.set_session(session)
            return session
        except Exception as e:
            # We can clear the session from all transfer methods here, since we received a valid, non-expired token in the current method
            if isinstance(e, UnauthorisedError):  # FIXME
                log_debug_message(
                    "getSession: Clearing %s because of UNAUTHORISED response from getSession",
                    request_transfer_method,
                )
                clear_session(self.config, response, request_transfer_method)
            raise e

    # In all cases: if sIdRefreshToken token exists (so it's a legacy session) we clear it
    # Check http://localhost:3002/docs/contribute/decisions/session/0008 for further details and a table of expected behaviours
    async def refresh_session(
        self, request: BaseRequest, response: BaseResponse, user_context: Dict[str, Any]
    ) -> SessionContainer:
        log_debug_message("refreshSession: Started")

        if request.get_cookie(LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME) is not None:
            set_cookie(
                self.config,
                response,
                LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME,
                "",
                0,
                "access_token_path",
            )

        refresh_tokens: Dict[TokenTransferMethod, Optional[str]] = {}

        transfer_methods: List[TokenTransferMethod] = available_token_transfer_methods  # type: ignore
        # We check all token transfer methods for available refresh tokens
        # We do this so that we can later clear all we are not overwriting
        for transfer_method in transfer_methods:
            refresh_tokens[transfer_method] = get_token(
                request,
                "refresh",
                transfer_method,
            )
            if refresh_tokens.get(transfer_method) is not None:
                log_debug_message(
                    "refreshSession: got refresh token from %s",
                    transfer_method,
                )
        allowed_transfer_method = self.config.get_token_transfer_method(
            request, False, user_context
        )
        log_debug_message(
            "refreshSession: getTokenTransferMethod returned: %s",
            allowed_transfer_method,
        )

        request_transfer_method: TokenTransferMethod
        refresh_token: Optional[str]

        if (
            allowed_transfer_method == "any" or allowed_transfer_method == "header"
        ) and (refresh_tokens.get("header")):
            log_debug_message("refreshSession: using header transfer method")
            request_transfer_method = "header"
            refresh_token = refresh_tokens["header"]
        elif (
            allowed_transfer_method == "any" or allowed_transfer_method == "cookie"
        ) and (refresh_tokens.get("cookie")):
            log_debug_message("refreshSession: using cookie transfer method")
            request_transfer_method = "cookie"
            refresh_token = refresh_tokens["cookie"]
        else:
            log_debug_message(
                "refreshSession: UNAUTHORIZED because refresh_token in request is None"
            )
            return raise_unauthorised_exception(
                "Refresh token not found. Are you sending the refresh token in the request as a cookie?",
                clear_tokens=False,
            )

        assert refresh_token is not None  # FIXME: Shouldn't be required

        try:
            anti_csrf_token = get_anti_csrf_header(request)
            new_session = await session_functions.refresh_session(
                self,
                refresh_token,
                anti_csrf_token,
                get_rid_header(request) is not None,
                request_transfer_method,
            )
            log_debug_message(
                "refreshSession: Attaching refresh session info as %s",
                request_transfer_method,
            )

            transfer_methods: List[TokenTransferMethod] = available_token_transfer_methods  # type: ignore

            # We clear the tokens in all token transfer methods we are not going to overwrite
            for transfer_method in transfer_methods:
                if (
                    transfer_method != request_transfer_method
                    and refresh_tokens.get(transfer_method) is not None
                ):
                    clear_session(self.config, response, transfer_method)

            access_token = new_session["accessToken"]
            # refresh_token = new_session["refreshToken"]
            # id_refresh_token = new_session["idRefreshToken"]
            session = Session(
                self,
                access_token["token"],
                new_session["session"]["handle"],
                new_session["session"]["userId"],
                new_session["session"]["userDataInJWT"],
                request_transfer_method,
            )
            session.new_access_token_info = access_token
            # session.new_refresh_token_info = refresh_token
            # session.new_id_refresh_token_info = id_refresh_token
            if (
                "antiCsrfToken" in new_session
                and new_session["antiCsrfToken"] is not None
            ):
                session.new_anti_csrf_token = new_session["antiCsrfToken"]

            log_debug_message("refreshSession: Success!")
            request.set_session(session)
            return session
        except Exception as e:
            if (isinstance(e, UnauthorisedError) and e.clear_tokens) or isinstance(
                e, TokenTheftError
            ):
                log_debug_message(
                    "refreshSession: Clearing tokens because of UNAUTHORISED or TOKEN_THEFT response"
                )
                clear_session(self.config, response, request_transfer_method)
            raise e

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
