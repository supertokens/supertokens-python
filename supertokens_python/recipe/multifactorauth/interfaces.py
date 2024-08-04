from abc import ABC, abstractmethod
from typing import Any, Awaitable, Dict, List, Union

from supertokens_python.recipe.multifactorauth.types import MFARequirementList
from supertokens_python.recipe.session.interfaces import JSONObject, SessionContainer
from supertokens_python.types import AccountLinkingUser, User


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
