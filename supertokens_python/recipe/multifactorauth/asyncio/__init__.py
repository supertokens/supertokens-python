import asyncio
from typing import Any, Dict, List, Optional

from supertokens_python.asyncio import get_user
from supertokens_python.recipe.multifactorauth.recipe import (
    MultiFactorAuthRecipe as Recipe,
)
from supertokens_python.recipe.multifactorauth.types import SessionInput
from supertokens_python.recipe.multifactorauth.utils import (
    update_and_get_mfa_related_info_in_session,
)
from supertokens_python.recipe.session import SessionContainer


async def get_factors_setup_for_user(
    user_id: str, user_context: Dict[str, Any]
) -> List[str]:
    user = await get_user(user_id, user_context)
    if user is None:
        raise Exception("Unknown user id")
    return await Recipe.get_instance().recipe_implementation.get_factors_setup_for_user(
        user, user_context
    )


async def assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
    session: SessionContainer,
    factor_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> None:
    ctx = user_context if user_context is not None else {}

    async def get_mfa_requirements_for_auth():
        mfa_info = await update_and_get_mfa_related_info_in_session(
            input=SessionInput(session=session, user_context=ctx)
        )
        return mfa_info.mfa_requirements_for_auth

    factors_setup_for_user = asyncio.create_task(
        get_factors_setup_for_user(session.get_user_id(), ctx)
    )
    await Recipe.get_instance().recipe_implementation.assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
        session=session,
        factor_id=factor_id,
        mfa_requirements_for_auth=asyncio.create_task(get_mfa_requirements_for_auth()),
        user_context=ctx,
        factors_set_up_for_user=factors_setup_for_user,
    )
