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
from typing import Any, Dict, List, TypeVar, Union

from supertokens_python.recipe.session.exceptions import (
    raise_invalid_claims_exception,
    raise_unauthorised_exception,
)
from supertokens_python.utils import get_timestamp_ms

from .cookie_and_header import (
    clear_session_response_mutator,
    front_token_response_mutator,
    token_response_mutator,
)
from .interfaces import SessionClaim, SessionClaimValidator, SessionContainer
from .utils import HUNDRED_YEARS_IN_MS

_T = TypeVar("_T")


class Session(SessionContainer):
    async def revoke_session(self, user_context: Union[Any, None] = None) -> None:
        if user_context is None:
            user_context = {}
        await self.recipe_implementation.revoke_session(
            self.session_handle, user_context
        )

        self.response_mutators.append(
            clear_session_response_mutator(
                self.config,
                self.transfer_method,
            )
        )

    async def get_session_data(
        self, user_context: Union[Dict[str, Any], None] = None
    ) -> Dict[str, Any]:
        if user_context is None:
            user_context = {}
        session_info = await self.recipe_implementation.get_session_information(
            self.session_handle, user_context
        )
        if session_info is None:
            raise_unauthorised_exception("Session does not exist anymore.")

        return session_info.session_data

    async def update_session_data(
        self,
        new_session_data: Dict[str, Any],
        user_context: Union[Dict[str, Any], None] = None,
    ) -> None:
        if user_context is None:
            user_context = {}
        updated = await self.recipe_implementation.update_session_data(
            self.session_handle, new_session_data, user_context
        )
        if not updated:
            raise_unauthorised_exception("Session does not exist anymore.")

    async def update_access_token_payload(
        self,
        new_access_token_payload: Dict[str, Any],
        user_context: Union[Dict[str, Any], None] = None,
    ) -> None:
        if user_context is None:
            user_context = {}

        result = await self.recipe_implementation.regenerate_access_token(
            self.access_token, new_access_token_payload, user_context
        )
        if result is None:
            raise_unauthorised_exception("Session does not exist anymore.")

        self.access_token_payload = result.session.user_data_in_jwt
        if result.access_token is not None:
            self.access_token = result.access_token.token

            self.response_mutators.append(
                front_token_response_mutator(
                    self.user_id,
                    result.access_token.expiry,
                    self.access_token_payload,
                )
            )
            # We set the expiration to 100 years, because we can't really access the expiration of the refresh token everywhere we are setting it.
            # This should be safe to do, since this is only the validity of the cookie (set here or on the frontend) but we check the expiration of the JWT anyway.
            # Even if the token is expired the presence of the token indicates that the user could have a valid refresh
            # Setting them to infinity would require special case handling on the frontend and just adding 100 years seems enough.
            self.response_mutators.append(
                token_response_mutator(
                    self.config,
                    "access",
                    result.access_token.token,
                    get_timestamp_ms() + HUNDRED_YEARS_IN_MS,
                    self.transfer_method,
                )
            )

    def get_user_id(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        return self.user_id

    def get_access_token_payload(
        self, user_context: Union[Dict[str, Any], None] = None
    ) -> Dict[str, Any]:
        return self.access_token_payload

    def get_handle(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        return self.session_handle

    def get_access_token(self, user_context: Union[Dict[str, Any], None] = None) -> str:
        return self.access_token

    async def get_time_created(
        self, user_context: Union[Dict[str, Any], None] = None
    ) -> int:
        if user_context is None:
            user_context = {}
        session_info = await self.recipe_implementation.get_session_information(
            self.session_handle, user_context
        )
        if session_info is None:
            raise_unauthorised_exception("Session does not exist anymore.")

        return session_info.time_created

    async def get_expiry(self, user_context: Union[Dict[str, Any], None] = None) -> int:
        if user_context is None:
            user_context = {}
        session_info = await self.recipe_implementation.get_session_information(
            self.session_handle, user_context
        )
        if session_info is None:
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

        update = await claim.build(self.get_user_id(), user_context)
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

        update_payload = {
            **self.get_access_token_payload(user_context),
            **access_token_payload_update,
        }
        for k in access_token_payload_update.keys():
            if access_token_payload_update[k] is None:
                del update_payload[k]

        await self.update_access_token_payload(update_payload, user_context)
