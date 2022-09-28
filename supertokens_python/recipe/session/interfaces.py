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

from abc import ABC, abstractmethod
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    TypeVar,
    Union,
)

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.types import APIResponse, GeneralErrorResponse, MaybeAwaitable

from ...utils import resolve
from .exceptions import ClaimValidationError
from .utils import SessionConfig

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse


class SessionObj:
    def __init__(self, handle: str, user_id: str, user_data_in_jwt: Dict[str, Any]):
        self.handle = handle
        self.user_id = user_id
        self.user_data_in_jwt = user_data_in_jwt


class AccessTokenObj:
    def __init__(self, token: str, expiry: int, created_time: int):
        self.token = token
        self.expiry = expiry
        self.created_time = created_time


class RegenerateAccessTokenOkResult:
    def __init__(self, session: SessionObj, access_token: Union[AccessTokenObj, None]):
        self.session = session
        self.access_token = access_token


class SessionInformationResult:
    def __init__(
        self,
        session_handle: str,
        user_id: str,
        session_data: Dict[str, Any],
        expiry: int,
        access_token_payload: Dict[str, Any],
        time_created: int,
    ):
        self.session_handle: str = session_handle
        self.user_id: str = user_id
        self.session_data: Dict[str, Any] = session_data
        self.expiry: int = expiry
        self.access_token_payload: Dict[str, Any] = access_token_payload
        self.time_created: int = time_created


_T = TypeVar("_T")
JSONObject = Dict[str, Any]

JSONPrimitive = Union[str, int, bool, None, Dict[str, Any]]
JSONPrimitiveList = Union[
    List[str], List[int], List[bool], List[None], List[Dict[str, Any]]
]


class SessionDoesNotExistError:
    pass


class GetClaimValueOkResult(Generic[_T]):
    def __init__(self, value: Optional[_T]):
        self.value = value


class ClaimsValidationResult:
    def __init__(
        self,
        invalid_claims: List[ClaimValidationError],
        access_token_payload_update: Optional[Dict[str, Any]] = None,
    ):
        self.invalid_claims = invalid_claims
        self.access_token_payload_update = access_token_payload_update


class RecipeInterface(ABC):  # pylint: disable=too-many-public-methods
    def __init__(self):
        pass

    @abstractmethod
    async def create_new_session(
        self,
        request: BaseRequest,
        user_id: str,
        access_token_payload: Union[None, Dict[str, Any]],
        session_data: Union[None, Dict[str, Any]],
        user_context: Dict[str, Any],
    ) -> SessionContainer:
        pass

    @abstractmethod
    def get_global_claim_validators(
        self,
        user_id: str,
        claim_validators_added_by_other_recipes: List[SessionClaimValidator],
        user_context: Dict[str, Any],
    ) -> MaybeAwaitable[List[SessionClaimValidator]]:
        pass

    @abstractmethod
    async def get_session(
        self,
        request: BaseRequest,
        anti_csrf_check: Union[bool, None],
        session_required: bool,
        user_context: Dict[str, Any],
    ) -> Union[SessionContainer, None]:
        pass

    @abstractmethod
    async def validate_claims(
        self,
        user_id: str,
        access_token_payload: Dict[str, Any],
        claim_validators: List[SessionClaimValidator],
        user_context: Dict[str, Any],
    ) -> ClaimsValidationResult:
        pass

    @abstractmethod
    async def validate_claims_in_jwt_payload(
        self,
        user_id: str,
        jwt_payload: JSONObject,
        claim_validators: List[SessionClaimValidator],
        user_context: Dict[str, Any],
    ) -> ClaimsValidationResult:
        pass

    @abstractmethod
    async def refresh_session(
        self, request: BaseRequest, user_context: Dict[str, Any]
    ) -> SessionContainer:
        pass

    @abstractmethod
    async def revoke_session(
        self, session_handle: str, user_context: Dict[str, Any]
    ) -> bool:
        pass

    @abstractmethod
    async def revoke_all_sessions_for_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> List[str]:
        pass

    @abstractmethod
    async def get_all_session_handles_for_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> List[str]:
        pass

    @abstractmethod
    async def revoke_multiple_sessions(
        self, session_handles: List[str], user_context: Dict[str, Any]
    ) -> List[str]:
        pass

    @abstractmethod
    async def get_session_information(
        self, session_handle: str, user_context: Dict[str, Any]
    ) -> Union[SessionInformationResult, None]:
        pass

    @abstractmethod
    async def update_session_data(
        self,
        session_handle: str,
        new_session_data: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> bool:
        pass

    @abstractmethod
    async def update_access_token_payload(
        self,
        session_handle: str,
        new_access_token_payload: Dict[str, Any],
        user_context: Dict[str, Any],
    ) -> bool:
        """DEPRECATED: Use merge_into_access_token_payload instead"""

    @abstractmethod
    async def merge_into_access_token_payload(
        self,
        session_handle: str,
        access_token_payload_update: JSONObject,
        user_context: Dict[str, Any],
    ) -> bool:
        pass

    @abstractmethod
    async def get_access_token_lifetime_ms(self, user_context: Dict[str, Any]) -> int:
        pass

    @abstractmethod
    async def get_refresh_token_lifetime_ms(self, user_context: Dict[str, Any]) -> int:
        pass

    @abstractmethod
    async def fetch_and_set_claim(
        self,
        session_handle: str,
        claim: SessionClaim[Any],
        user_context: Dict[str, Any],
    ) -> bool:
        pass

    @abstractmethod
    async def set_claim_value(
        self,
        session_handle: str,
        claim: SessionClaim[_T],
        value: _T,
        user_context: Dict[str, Any],
    ) -> bool:
        pass

    @abstractmethod
    async def get_claim_value(
        self,
        session_handle: str,
        claim: SessionClaim[Any],
        user_context: Dict[str, Any],
    ) -> Union[SessionDoesNotExistError, GetClaimValueOkResult[Any]]:
        pass

    @abstractmethod
    async def remove_claim(
        self,
        session_handle: str,
        claim: SessionClaim[Any],
        user_context: Dict[str, Any],
    ) -> bool:
        pass

    @abstractmethod
    async def regenerate_access_token(
        self,
        access_token: str,
        new_access_token_payload: Union[Dict[str, Any], None],
        user_context: Dict[str, Any],
    ) -> Union[RegenerateAccessTokenOkResult, None]:
        pass


class SignOutOkayResponse(APIResponse):
    def __init__(self):
        self.status = "OK"

    def to_json(self) -> Dict[str, Any]:
        return {"status": self.status}


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: Union[None, BaseResponse],
        recipe_id: str,
        config: SessionConfig,
        recipe_implementation: RecipeInterface,
    ):
        self.request: BaseRequest = request
        self.response: Union[None, BaseResponse] = response
        self.recipe_id: str = recipe_id
        self.config: SessionConfig = config
        self.recipe_implementation: RecipeInterface = recipe_implementation


class APIInterface(ABC):
    def __init__(self):
        self.disable_refresh_post = False
        self.disable_signout_post = False

    # We do not add a GeneralErrorResponse response to this API
    # since it's not something that is directly called by the user on the
    # frontend anyway

    @abstractmethod
    async def refresh_post(
        self, api_options: APIOptions, user_context: Dict[str, Any]
    ) -> SessionContainer:
        pass

    @abstractmethod
    async def signout_post(
        self,
        session: Optional[SessionContainer],
        api_options: APIOptions,
        user_context: Dict[str, Any],
    ) -> Union[SignOutOkayResponse, GeneralErrorResponse]:
        pass

    @abstractmethod
    async def verify_session(
        self,
        api_options: APIOptions,
        anti_csrf_check: Union[bool, None],
        session_required: bool,
        override_global_claim_validators: Optional[
            Callable[
                [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
                MaybeAwaitable[List[SessionClaimValidator]],
            ]
        ],
        user_context: Dict[str, Any],
    ) -> Union[SessionContainer, None]:
        pass


class SessionContainer(ABC):  # pylint: disable=too-many-public-methods
    def __init__(
        self,
        recipe_implementation: RecipeInterface,
        access_token: str,
        session_handle: str,
        user_id: str,
        access_token_payload: Dict[str, Any],
    ):
        self.recipe_implementation = recipe_implementation
        self.access_token = access_token
        self.session_handle = session_handle
        self.access_token_payload = access_token_payload
        self.user_id = user_id
        self.new_access_token_info = None
        self.new_refresh_token_info = None
        self.new_id_refresh_token_info = None
        self.new_anti_csrf_token = None
        self.remove_cookies = False

    @abstractmethod
    async def revoke_session(
        self, user_context: Optional[Dict[str, Any]] = None
    ) -> None:
        pass

    @abstractmethod
    async def get_session_data(
        self, user_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def update_session_data(
        self,
        new_session_data: Dict[str, Any],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        pass

    @abstractmethod
    async def update_access_token_payload(
        self,
        new_access_token_payload: Dict[str, Any],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """DEPRECATED: Use merge_into_access_token_payload instead"""

    @abstractmethod
    async def merge_into_access_token_payload(
        self,
        access_token_payload_update: JSONObject,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        pass

    @abstractmethod
    def get_user_id(self, user_context: Optional[Dict[str, Any]] = None) -> str:
        pass

    @abstractmethod
    def get_access_token_payload(
        self, user_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_handle(self, user_context: Optional[Dict[str, Any]] = None) -> str:
        pass

    @abstractmethod
    def get_access_token(self, user_context: Optional[Dict[str, Any]] = None) -> str:
        pass

    @abstractmethod
    async def get_time_created(
        self, user_context: Optional[Dict[str, Any]] = None
    ) -> int:
        pass

    @abstractmethod
    async def get_expiry(self, user_context: Optional[Dict[str, Any]] = None) -> int:
        pass

    @abstractmethod
    async def assert_claims(
        self,
        claim_validators: List[SessionClaimValidator],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        pass

    @abstractmethod
    async def fetch_and_set_claim(
        self, claim: SessionClaim[Any], user_context: Optional[Dict[str, Any]] = None
    ) -> None:
        pass

    @abstractmethod
    async def set_claim_value(
        self,
        claim: SessionClaim[_T],
        value: _T,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        pass

    @abstractmethod
    async def get_claim_value(
        self, claim: SessionClaim[_T], user_context: Optional[Dict[str, Any]] = None
    ) -> Union[_T, None]:
        pass

    @abstractmethod
    async def remove_claim(
        self,
        claim: SessionClaim[Any],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        pass

    def sync_get_expiry(self, user_context: Optional[Dict[str, Any]] = None) -> int:
        return sync(self.get_expiry(user_context))

    def sync_revoke_session(
        self, user_context: Optional[Dict[str, Any]] = None
    ) -> None:
        return sync(self.revoke_session(user_context=user_context))

    def sync_get_session_data(
        self, user_context: Union[Dict[str, Any], None] = None
    ) -> Dict[str, Any]:
        return sync(self.get_session_data(user_context))

    def sync_get_time_created(
        self, user_context: Optional[Dict[str, Any]] = None
    ) -> int:
        return sync(self.get_time_created(user_context))

    def sync_merge_into_access_token_payload(
        self,
        access_token_payload_update: Dict[str, Any],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        return sync(
            self.merge_into_access_token_payload(
                access_token_payload_update, user_context
            )
        )

    def sync_update_access_token_payload(
        self,
        new_access_token_payload: Dict[str, Any],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        return sync(
            self.update_access_token_payload(new_access_token_payload, user_context)
        )

    def sync_update_session_data(
        self,
        new_session_data: Dict[str, Any],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        return sync(self.update_session_data(new_session_data, user_context))

    # Session claims sync functions:
    def sync_assert_claims(
        self,
        claim_validators: List[SessionClaimValidator],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        return sync(self.assert_claims(claim_validators, user_context))

    def sync_fetch_and_set_claim(
        self, claim: SessionClaim[Any], user_context: Optional[Dict[str, Any]] = None
    ) -> None:
        return sync(self.fetch_and_set_claim(claim, user_context))

    def sync_set_claim_value(
        self,
        claim: SessionClaim[_T],
        value: _T,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        return sync(self.set_claim_value(claim, value, user_context))

    def sync_get_claim_value(
        self, claim: SessionClaim[_T], user_context: Optional[Dict[str, Any]] = None
    ) -> Union[_T, None]:
        return sync(self.get_claim_value(claim, user_context))

    def sync_remove_claim(
        self, claim: SessionClaim[Any], user_context: Optional[Dict[str, Any]] = None
    ) -> None:
        return sync(self.remove_claim(claim, user_context))

    # This is there so that we can do session["..."] to access some of the members of this class
    def __getitem__(self, item: str):
        return getattr(self, item)


class SessionClaim(ABC, Generic[_T]):
    def __init__(
        self,
        key: str,
        fetch_value: Callable[
            [str, Dict[str, Any]],
            MaybeAwaitable[Optional[_T]],
        ],
    ) -> None:
        """
        Args:
            key: The key to use when storing the claim in the payload.
            fetch_value: a method that fetches the current value of this claim for the user.
                A None return value signifies that we don't want to update the claim payload and or the claim value is
                not present in the database. For example, this can happen with a second factor auth claim, where we
                don't want to add the claim to the session automatically
        """
        self.key = key
        self.fetch_value = fetch_value

    @abstractmethod
    def add_to_payload_(
        self,
        payload: JSONObject,
        value: _T,
        user_context: Union[Dict[str, Any], None] = None,
    ) -> JSONObject:
        """Saves the provided value into the payload, by cloning and updating the entire object"""

    @abstractmethod
    def remove_from_payload_by_merge_(
        self, payload: JSONObject, user_context: Optional[Dict[str, Any]] = None
    ) -> JSONObject:
        """Removes the claim from the payload by setting it to None, so merge_into_access_token_payload can clear it"""

    @abstractmethod
    def remove_from_payload(
        self, payload: JSONObject, user_context: Optional[Dict[str, Any]] = None
    ) -> JSONObject:
        """Removes the claim from the payload, by cloning and updating the entire object."""

    @abstractmethod
    def get_value_from_payload(
        self, payload: JSONObject, user_context: Union[Dict[str, Any], None] = None
    ) -> Union[_T, None]:
        """Gets the value of the claim stored in the payload"""

    async def build(
        self, user_id: str, user_context: Optional[Dict[str, Any]] = None
    ) -> JSONObject:
        if user_context is None:
            user_context = {}
        value = await resolve(self.fetch_value(user_id, user_context))

        if value is None:
            return {}

        return self.add_to_payload_({}, value, user_context)


class ClaimValidationResult:
    def __init__(self, is_valid: bool, reason: Optional[Dict[str, Any]] = None):
        self.is_valid = is_valid
        self.reason = {} if is_valid else reason


class SessionClaimValidator(ABC):
    def __init__(
        self,
        id_: str,
    ) -> None:
        self.id = id_
        self.claim: Optional[SessionClaim[Any]] = None

    @abstractmethod
    async def validate(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> ClaimValidationResult:
        pass

    def should_refetch(
        self, payload: JSONObject, user_context: Dict[str, Any]
    ) -> MaybeAwaitable[bool]:
        raise NotImplementedError()
