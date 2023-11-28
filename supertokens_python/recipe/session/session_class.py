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
from typing import Any, Dict, List, Optional, TypeVar, Union

from supertokens_python.recipe.session.exceptions import (
    raise_invalid_claims_exception,
    raise_unauthorised_exception,
)
from .jwt import parse_jwt_without_signature_verification
from .utils import TokenTransferMethod

from .cookie_and_header import (
    clear_session_response_mutator,
    token_response_mutator,
    build_front_token,
    anti_csrf_response_mutator,
    access_token_mutator,
)
from .interfaces import (
    ReqResInfo,
    SessionClaim,
    SessionClaimValidator,
    SessionContainer,
    GetSessionTokensDangerouslyDict,
)
from .constants import protected_props
from ...framework import BaseRequest
from supertokens_python.utils import log_debug_message

_T = TypeVar("_T")


class Session(SessionContainer):
    async def attach_to_request_response(
        self,
        request: BaseRequest,
        transfer_method: TokenTransferMethod,
        user_context: Optional[Dict[str, Any]],
    ) -> None:
        self.req_res_info = ReqResInfo(request, transfer_method)

        if self.access_token_updated:
            self.response_mutators.append(
                access_token_mutator(
                    self.access_token,
                    self.front_token,
                    self.config,
                    transfer_method,
                    request,
                )
            )
            if self.refresh_token is not None:
                self.response_mutators.append(
                    token_response_mutator(
                        self.config,
                        "refresh",
                        self.refresh_token.token,
                        self.refresh_token.expiry,
                        transfer_method,
                        request,
                    )
                )
            if self.anti_csrf_token is not None:
                self.response_mutators.append(
                    anti_csrf_response_mutator(self.anti_csrf_token)
                )

        request.set_session(
            self
        )  # Although this is called in recipe/session/framework/**/__init__.py. It's required in case of python because functions like create_new_session(req, "user-id") can be called in the framework view handler as well

    async def revoke_session(self, user_context: Union[Any, None] = None) -> None:
        if user_context is None:
            user_context = {}

        await self.recipe_implementation.revoke_session(
            self.session_handle, user_context
        )

        if self.req_res_info is not None:
            # we do not check the output of calling revokeSession
            # before clearing the cookies because we are revoking the
            # current API request's session.
            # If we instead clear the cookies only when revokeSession
            # returns true, it can cause this kind of bug:
            # https://github.com/supertokens/supertokens-node/issues/343
            transfer_method: TokenTransferMethod = self.req_res_info.transfer_method  # type: ignore
            self.response_mutators.append(
                clear_session_response_mutator(
                    self.config,
                    transfer_method,
                    self.req_res_info.request,
                )
            )

    async def get_session_data_from_database(
        self, user_context: Union[Dict[str, Any], None] = None
    ) -> Dict[str, Any]:
        if user_context is None:
            user_context = {}
        session_info = await self.recipe_implementation.get_session_information(
            self.session_handle, user_context
        )
        if session_info is None:
            log_debug_message(
                "getSessionDataFromDatabase: Throwing UNAUTHORISED because session does not exist anymore"
            )
            raise_unauthorised_exception("Session does not exist anymore.")

        return session_info.session_data_in_database

    async def update_session_data_in_database(
        self,
        new_session_data: Dict[str, Any],
        user_context: Union[Dict[str, Any], None] = None,
    ) -> None:
        if user_context is None:
            user_context = {}
        updated = await self.recipe_implementation.update_session_data_in_database(
            self.session_handle, new_session_data, user_context
        )
        if not updated:
            log_debug_message(
                "updateSessionDataInDatabase: Throwing UNAUTHORISED because session does not exist anymore"
            )
            raise_unauthorised_exception("Session does not exist anymore.")

    def get_user_id(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        return self.user_id

    def get_tenant_id(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        return self.tenant_id

    def get_access_token_payload(
        self, user_context: Union[Dict[str, Any], None] = None
    ) -> Dict[str, Any]:
        return self.user_data_in_access_token

    def get_handle(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        return self.session_handle

    def get_access_token(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        return self.access_token

    def get_all_session_tokens_dangerously(self) -> GetSessionTokensDangerouslyDict:
        return {
            "accessToken": self.access_token,
            "accessAndFrontTokenUpdated": self.access_token_updated,
            "refreshToken": None
            if self.refresh_token is None
            else self.refresh_token.token,
            "frontToken": self.front_token,
            "antiCsrfToken": self.anti_csrf_token,
        }

    async def get_time_created(
        self, user_context: Union[Dict[str, Any], None] = None
    ) -> int:
        if user_context is None:
            user_context = {}
        session_info = await self.recipe_implementation.get_session_information(
            self.session_handle, user_context
        )
        if session_info is None:
            log_debug_message(
                "getTimeCreated: Throwing UNAUTHORISED because session does not exist anymore"
            )
            raise_unauthorised_exception("Session does not exist anymore.")

        return session_info.time_created

    async def get_expiry(self, user_context: Union[Dict[str, Any], None] = None) -> int:
        if user_context is None:
            user_context = {}
        session_info = await self.recipe_implementation.get_session_information(
            self.session_handle, user_context
        )
        if session_info is None:
            log_debug_message(
                "getExpiry: Throwing UNAUTHORISED because session does not exist anymore"
            )
            raise_unauthorised_exception("Session does not exist anymore.")

        return session_info.expiry

    async def assert_claims(
        self,
        claim_validators: List[SessionClaimValidator],
        user_context: Union[Dict[str, Any], None] = None,
    ) -> None:
        if user_context is None:
            user_context = {}

        validate_claim_res = await self.recipe_implementation.validate_claims(
            self.get_user_id(user_context),
            self.get_access_token_payload(user_context),
            claim_validators,
            user_context,
        )

        if validate_claim_res.access_token_payload_update is not None:
            for k in protected_props:
                try:
                    del validate_claim_res.access_token_payload_update[k]
                except KeyError:
                    pass
            await self.merge_into_access_token_payload(
                validate_claim_res.access_token_payload_update, user_context
            )

        validation_errors = validate_claim_res.invalid_claims
        if len(validation_errors) > 0:
            raise_invalid_claims_exception("INVALID_CLAIMS", validation_errors)

    async def fetch_and_set_claim(
        self, claim: SessionClaim[Any], user_context: Union[Dict[str, Any], None] = None
    ) -> None:
        if user_context is None:
            user_context = {}

        update = await claim.build(
            self.get_user_id(), self.get_tenant_id(), user_context
        )
        return await self.merge_into_access_token_payload(update, user_context)

    async def set_claim_value(
        self,
        claim: SessionClaim[_T],
        value: _T,
        user_context: Union[Dict[str, Any], None] = None,
    ) -> None:
        if user_context is None:
            user_context = {}

        update = claim.add_to_payload_({}, value, user_context)
        return await self.merge_into_access_token_payload(update, user_context)

    async def get_claim_value(
        self, claim: SessionClaim[_T], user_context: Union[Dict[str, Any], None] = None
    ) -> Union[_T, None]:
        if user_context is None:
            user_context = {}

        return claim.get_value_from_payload(
            self.get_access_token_payload(user_context), user_context
        )

    async def remove_claim(
        self, claim: SessionClaim[Any], user_context: Union[Dict[str, Any], None] = None
    ) -> None:
        if user_context is None:
            user_context = {}

        update = claim.remove_from_payload_by_merge_({}, user_context)
        return await self.merge_into_access_token_payload(update, user_context)

    async def merge_into_access_token_payload(
        self,
        access_token_payload_update: Dict[str, Any],
        user_context: Union[Dict[str, Any], None] = None,
    ) -> None:
        if user_context is None:
            user_context = {}

        new_access_token_payload = {**self.get_access_token_payload(user_context)}
        for k in protected_props:
            try:
                del new_access_token_payload[k]
            except KeyError:
                pass

        new_access_token_payload = {
            **new_access_token_payload,
            **access_token_payload_update,
        }

        for k in access_token_payload_update.keys():
            if access_token_payload_update[k] is None:
                del new_access_token_payload[k]

        response = await self.recipe_implementation.regenerate_access_token(
            self.get_access_token(), new_access_token_payload, user_context
        )

        if response is None:
            log_debug_message(
                "mergeIntoAccessTokenPayload: Throwing UNAUTHORISED because session does not exist anymore"
            )
            raise_unauthorised_exception("Session does not exist anymore.")

        if response.access_token is not None:
            resp_token = parse_jwt_without_signature_verification(
                response.access_token.token
            )
            payload = (
                resp_token.payload
                if resp_token.version >= 3
                else response.session.user_data_in_jwt
            )
            self.user_data_in_access_token = payload
            self.access_token = response.access_token.token
            self.front_token = build_front_token(
                self.get_user_id(), response.access_token.expiry, payload
            )
            self.access_token_updated = True
            if self.req_res_info is not None:
                transfer_method: TokenTransferMethod = self.req_res_info.transfer_method  # type: ignore
                self.response_mutators.append(
                    access_token_mutator(
                        self.access_token,
                        self.front_token,
                        self.config,
                        transfer_method,
                        self.req_res_info.request,
                    )
                )
        else:
            # This case means that the access token has expired between the validation and this update
            # We can't update the access token on the FE, as it will need to call refresh anyway but we handle this as a successful update during this request
            # the changes will be reflected on the FE after refresh is called
            self.user_data_in_access_token = {
                **self.get_access_token_payload(),
                **response.session.user_data_in_jwt,
            }
