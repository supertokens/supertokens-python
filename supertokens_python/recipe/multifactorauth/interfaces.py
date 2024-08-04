from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Awaitable, Dict, List, Optional, Union

if TYPE_CHECKING:
    from supertokens_python.recipe.multifactorauth.types import (
        APIOptions,
        MFARequirementList,
    )

from supertokens_python.recipe.session.interfaces import JSONObject, SessionContainer
from supertokens_python.types import AccountLinkingUser


class RecipeInterface(ABC):
    @abstractmethod
    async def assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
        self,
        session: SessionContainer,
        factor_id: str,
        mfa_requirements_for_auth: Awaitable[MFARequirementList],
        factors_set_up_for_user: Awaitable[List[str]],
        user_context: Dict[str, Any],
    ) -> None:
        pass

    @abstractmethod
    async def get_mfa_requirements_for_auth(
        self,
        tenant_id: str,
        access_token_payload: JSONObject,
        completed_factors: Dict[str, Union[int, None]],
        user: Awaitable[AccountLinkingUser],
        factors_set_up_for_user: Awaitable[List[str]],
        required_secondary_factors_for_user: Awaitable[List[str]],
        required_secondary_factors_for_tenant: Awaitable[List[str]],
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


class APIInterface(ABC):
    @abstractmethod
    def resync_session_and_fetch_mfa_info_put(
        self,
        options: APIOptions,
        session: SessionContainer,
        user_context: Dict[str, Any],
    ) -> Optional[Dict[str, object]]:
        pass
