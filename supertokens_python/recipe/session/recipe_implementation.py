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

from supertokens_python.framework import BaseRequest
from supertokens_python.logger import log_debug_message
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.process_state import AllowedProcessStates, ProcessState
from supertokens_python.utils import (
    execute_async,
    get_timestamp_ms,
    is_an_ip_address,
    normalise_http_method,
    resolve,
)

from ...types import MaybeAwaitable
from . import session_functions
from .access_token import validate_access_token_structure
from .cookie_and_header import (
    anti_csrf_response_mutator,
    clear_session_response_mutator,
    front_token_response_mutator,
    get_anti_csrf_header,
    get_rid_header,
    get_token,
    set_cookie_response_mutator,
    token_response_mutator,
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
    ResponseMutator,
    SessionClaim,
    SessionClaimValidator,
    SessionDoesNotExistError,
    SessionInformationResult,
    SessionObj,
)
from .jwt import ParsedJWTInfo, parse_jwt_without_signature_verification
from .session_class import Session
from .utils import (
    HUNDRED_YEARS_IN_MS,
    SessionConfig,
    TokenTransferMethod,
    validate_claims_in_payload,
)

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

        if (
            (output_transfer_method == "cookie")
            and self.config.cookie_same_site == "none"
            and not self.config.cookie_secure
            and not (
                (
                    self.app_info.top_level_api_domain == "localhost"
                    or is_an_ip_address(self.app_info.top_level_api_domain)
                )
                and (
                    self.app_info.top_level_website_domain == "localhost"
                    or is_an_ip_address(self.app_info.top_level_website_domain)
                )
            )
        ):
            # We can allow insecure cookie when both website & API domain are localhost or an IP
            # When either of them is a different domain, API domain needs to have https and a secure cookie to work
            raise Exception(
                "Since your API and website domain are different, for sessions to work, please use "
                "https on your apiDomain and don't set cookieSecure to false."
            )

        disable_anti_csrf = output_transfer_method == "header"

        result = await session_functions.create_new_session(
            self,
            user_id,
            disable_anti_csrf,
            access_token_payload,
            session_data,
        )

        response_mutators: List[ResponseMutator] = []

        for transfer_method in available_token_transfer_methods:
            request_access_token = get_token(request, "access", transfer_method)

            if (
                transfer_method != output_transfer_method
                and request_access_token is not None
            ):
                response_mutators.append(
                    clear_session_response_mutator(
                        self.config,
                        transfer_method,
                    )
                )

        new_session = Session(
            self,
            self.config,
            result["accessToken"]["token"],
            result["session"]["handle"],
            result["session"]["userId"],
            result["session"]["userDataInJWT"],
            output_transfer_method,
        )

        new_access_token_info: Dict[str, Any] = result["accessToken"]
        new_refresh_token_info: Dict[str, Any] = result["refreshToken"]
        anti_csrf_token: Optional[str] = result.get("antiCsrfToken")

        response_mutators.append(
            front_token_response_mutator(
                new_session.user_id,
                new_access_token_info["expiry"],
                new_session.access_token_payload,
            )
        )
        # We set the expiration to 100 years, because we can't really access the expiration of the refresh token everywhere we are setting it.
        # This should be safe to do, since this is only the validity of the cookie (set here or on the frontend) but we check the expiration of the JWT anyway.
        # Even if the token is expired the presence of the token indicates that the user could have a valid refresh
        # Setting them to infinity would require special case handling on the frontend and just adding 100 years seems enough.
        response_mutators.append(
            token_response_mutator(
                self.config,
                "access",
                new_access_token_info["token"],
                get_timestamp_ms() + HUNDRED_YEARS_IN_MS,
                new_session.transfer_method,
            )
        )
        response_mutators.append(
            token_response_mutator(
                self.config,
                "refresh",
                new_refresh_token_info["token"],
                new_refresh_token_info[
                    "expiry"
                ],  # This comes from the core and is 100 days
                new_session.transfer_method,
            )
        )
        if anti_csrf_token is not None:
            response_mutators.append(anti_csrf_response_mutator(anti_csrf_token))

        new_session.response_mutators.extend(response_mutators)

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

    # In all cases if sIdRefreshToken token exists (so it's a legacy session) we return TRY_REFRESH_TOKEN. The refresh
    # endpoint will clear this cookie and try to upgrade the session.
    # Check https://supertokens.com/docs/contribute/decisions/session/0007 for further details and a table of expected
    # behaviours
    async def get_session(
        self,
        request: BaseRequest,
        anti_csrf_check: Union[bool, None],
        session_required: bool,
        user_context: Dict[str, Any],
    ) -> Optional[SessionContainer]:
        log_debug_message("getSession: Started")

        # This token isn't handled by getToken to limit the scope of this legacy/migration code
        if request.get_cookie(LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME) is not None:
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
        request_access_token: Union[ParsedJWTInfo, None]

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
        else:
            if session_optional:
                log_debug_message(
                    "getSession: returning None because accessToken is undefined and sessionRequired is false"
                )
                # there is no session that exists here, and the user wants session verification
                # to be optional. So we return None
                return None

            log_debug_message(
                "getSession: UNAUTHORISED because access_token in request is None"
            )
            # we do not clear the session here because of a race condition mentioned in:
            # https://github.com/supertokens/supertokens-node/issues/17
            raise_unauthorised_exception(
                "Session does not exist. Are you sending the session tokens in the "
                "request with the appropriate token transfer method?",
                clear_tokens=False,
            )

        anti_csrf_token = get_anti_csrf_header(request)
        do_anti_csrf_check = anti_csrf_check

        if do_anti_csrf_check is None:
            do_anti_csrf_check = normalise_http_method(request.method()) != "get"
        if request_transfer_method == "header":
            do_anti_csrf_check = False
        log_debug_message(
            "getSession: Value of doAntiCsrfCheck is: %s", do_anti_csrf_check
        )

        result = await session_functions.get_session(
            self,
            request_access_token,
            anti_csrf_token,
            do_anti_csrf_check,
            get_rid_header(request) is not None,
        )

        # Default is to respond with the access token obtained from the request
        access_token_string = request_access_token.raw_token_string

        session = Session(
            self,
            self.config,
            access_token_string,
            result["session"]["handle"],
            result["session"]["userId"],
            result["session"]["userDataInJWT"],
            request_transfer_method,
        )

        if "accessToken" in result:
            session.access_token = result["accessToken"]["token"]
            new_access_token_info = result["accessToken"]

            session.response_mutators.append(
                front_token_response_mutator(
                    session.user_id,
                    new_access_token_info["expiry"],
                    session.access_token_payload,
                )
            )
            # We set the expiration to 100 years, because we can't really access the expiration of the refresh token everywhere we are setting it.
            # This should be safe to do, since this is only the validity of the cookie (set here or on the frontend) but we check the expiration of the JWT anyway.
            # Even if the token is expired the presence of the token indicates that the user could have a valid refresh
            # Setting them to infinity would require special case handling on the frontend and just adding 100 years seems enough.
            session.response_mutators.append(
                token_response_mutator(
                    self.config,
                    "access",
                    session.access_token,
                    get_timestamp_ms() + HUNDRED_YEARS_IN_MS,
                    session.transfer_method,
                )
            )

        log_debug_message("getSession: Success!")
        request.set_session(session)
        return session

    # In all cases: if sIdRefreshToken token exists (it's a legacy session) we clear it
    # Check http://localhost:3002/docs/contribute/decisions/session/0008 for further details and
    # a table of expected behaviours
    async def refresh_session(
        self, request: BaseRequest, user_context: Dict[str, Any]
    ) -> SessionContainer:
        log_debug_message("refreshSession: Started")

        response_mutators: List[Callable[[Any], None]] = []
        refresh_tokens: Dict[TokenTransferMethod, Optional[str]] = {}

        # We check all token transfer methods for available refresh tokens
        # We do this so that we can later clear all we are not overwriting
        for transfer_method in available_token_transfer_methods:
            refresh_token = get_token(
                request,
                "refresh",
                transfer_method,
            )
            if refresh_token is not None:
                log_debug_message(
                    "refreshSession: got refresh token from %s", transfer_method
                )

            refresh_tokens[transfer_method] = refresh_token

        allowed_transfer_method = self.config.get_token_transfer_method(
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
                        self.config,
                        LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME,
                        "",
                        0,
                        "access_token_path",
                    )
                )

            log_debug_message(
                "refreshSession: UNAUTHORISED because refresh_token in request is None"
            )
            return raise_unauthorised_exception(
                "Refresh token not found. Are you sending the refresh token in the request?",
                clear_tokens=False,
            )

        assert refresh_token is not None

        try:
            anti_csrf_token = get_anti_csrf_header(request)
            result = await session_functions.refresh_session(
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

            for transfer_method in available_token_transfer_methods:
                if (
                    transfer_method != request_transfer_method
                    and refresh_tokens.get(transfer_method) is not None
                ):
                    response_mutators.append(
                        clear_session_response_mutator(self.config, transfer_method)
                    )

            if request.get_cookie(LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME) is not None:
                log_debug_message(
                    "refreshSession: cleared legacy id refresh token after successful refresh"
                )
                response_mutators.append(
                    set_cookie_response_mutator(
                        self.config,
                        LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME,
                        "",
                        0,
                        "access_token_path",
                    )
                )

            session = Session(
                self,
                self.config,
                result["accessToken"]["token"],
                result["session"]["handle"],
                result["session"]["userId"],
                result["session"]["userDataInJWT"],
                request_transfer_method,
            )
            new_access_token_info = result["accessToken"]
            new_refresh_token_info = result["refreshToken"]
            new_anti_csrf_token = result.get("antiCsrfToken")

            if new_access_token_info is not None:
                response_mutators.append(
                    front_token_response_mutator(
                        session.user_id,
                        new_access_token_info["expiry"],
                        session.access_token_payload,
                    )
                )
                # We set the expiration to 100 years, because we can't really access the expiration of the refresh token everywhere we are setting it.
                # This should be safe to do, since this is only the validity of the cookie (set here or on the frontend) but we check the expiration of the JWT anyway.
                # Even if the token is expired the presence of the token indicates that the user could have a valid refresh
                # Setting them to infinity would require special case handling on the frontend and just adding 100 years seems enough.
                response_mutators.append(
                    token_response_mutator(
                        self.config,
                        "access",
                        new_access_token_info["token"],
                        get_timestamp_ms() + HUNDRED_YEARS_IN_MS,  # 100 years
                        session.transfer_method,
                    )
                )
            if new_refresh_token_info is not None:
                response_mutators.append(
                    token_response_mutator(
                        self.config,
                        "refresh",
                        new_refresh_token_info["token"],
                        new_refresh_token_info[
                            "expiry"
                        ],  # This comes from the core and is 100 days
                        session.transfer_method,
                    )
                )

            anti_csrf_token = new_anti_csrf_token
            if anti_csrf_token is not None:
                response_mutators.append(anti_csrf_response_mutator(anti_csrf_token))

            session.response_mutators.extend(response_mutators)

            log_debug_message("refreshSession: Success!")
            request.set_session(session)
            return session
        except (TokenTheftError, UnauthorisedError) as e:
            if (
                isinstance(e, UnauthorisedError) and e.clear_tokens is True
            ) or isinstance(e, TokenTheftError):
                # This token isn't handled by getToken/setToken to limit the scope of this legacy/migration code
                if request.get_cookie(LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME) is not None:
                    log_debug_message(
                        "refreshSession: cleared legacy id refresh token because refresh token was not found"
                    )
                    response_mutators.append(
                        set_cookie_response_mutator(
                            self.config,
                            LEGACY_ID_REFRESH_TOKEN_COOKIE_NAME,
                            "",
                            0,
                            "access_token_path",
                        )
                    )
                    e.response_mutators.extend(response_mutators)

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
