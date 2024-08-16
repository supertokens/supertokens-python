# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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
from typing import Dict, Any, Union, List, Callable, Awaitable

from supertokens_python.types import AccountLinkingUser

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Union

from ...supertokens import AppInfo

from ...types import GeneralErrorResponse

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest, BaseResponse
    from supertokens_python.recipe.session import SessionContainer
    from .types import MFARequirementList, MultiFactorAuthConfig


class RecipeInterface(ABC):
    @abstractmethod
    async def assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
        self,
        session: SessionContainer,
        factor_id: str,
        mfa_requirements_for_auth: Callable[[], Awaitable[MFARequirementList]],
        factors_set_up_for_user: Callable[[], Awaitable[List[str]]],
        user_context: Dict[str, Any],
    ) -> None:
        pass

    @abstractmethod
    async def get_mfa_requirements_for_auth(
        self,
        tenant_id: str,
        access_token_payload: Dict[str, Any],
        completed_factors: Dict[str, int],
        user: Callable[[], Awaitable[AccountLinkingUser]],
        factors_set_up_for_user: Callable[[], Awaitable[List[str]]],
        required_secondary_factors_for_user: Callable[[], Awaitable[List[str]]],
        required_secondary_factors_for_tenant: Callable[[], Awaitable[List[str]]],
        user_context: Dict[str, Any],
    ) -> MFARequirementList:
        pass

    @abstractmethod
    async def mark_factor_as_complete_in_session(
        self,
        session: SessionContainer,
        factor_id: str,
        user_context: Dict[str, Any],
    ) -> None:
        pass

    @abstractmethod
    async def get_factors_setup_for_user(
        self, user: AccountLinkingUser, user_context: Dict[str, Any]
    ) -> List[str]:
        pass

    @abstractmethod
    async def get_required_secondary_factors_for_user(
        self, user_id: str, user_context: Dict[str, Any]
    ) -> List[str]:
        pass

    @abstractmethod
    async def add_to_required_secondary_factors_for_user(
        self, user_id: str, factor_id: str, user_context: Dict[str, Any]
    ) -> None:
        pass

    @abstractmethod
    async def remove_from_required_secondary_factors_for_user(
        self, user_id: str, factor_id: str, user_context: Dict[str, Any]
    ) -> None:
        pass


class APIOptions:
    def __init__(
        self,
        request: BaseRequest,
        response: BaseResponse,
        recipe_id: str,
        config: MultiFactorAuthConfig,
        recipe_implementation: RecipeInterface,
        app_info: AppInfo,
    ):
        self.request: BaseRequest = request
        self.response: BaseResponse = response
        self.recipe_id: str = recipe_id
        self.config = config
        self.recipe_implementation: RecipeInterface = recipe_implementation
        self.app_info = app_info


class APIInterface:
    def __init__(self):
        self.disable_resync_session_and_fetch_mfa_info_put = False

    @abstractmethod
    async def resync_session_and_fetch_mfa_info_put(
        self,
        api_options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Union[ResyncSessionAndFetchMFAInfoPUTOkResult, GeneralErrorResponse]:
        pass


class NextFactors:
    def __init__(
        self, next: List[str], already_setup: List[str], allowed_to_setup: List[str]
    ):
        self.next = next
        self.already_setup = already_setup
        self.allowed_to_setup = allowed_to_setup


class ResyncSessionAndFetchMFAInfoPUTOkResult:
    def __init__(
        self,
        factors: NextFactors,
        emails: Dict[str, Union[List[str], None]],
        phone_numbers: Dict[str, Union[List[str], None]],
    ):
        self.factors = factors
        self.emails = emails
        self.phone_numbers = phone_numbers

    status: str = "OK"
