from typing import Any, Dict, List, TypedDict

from supertokens_python.recipe.multiFactorAuth.asyncio import MultiFactorAuthRecipe
from supertokens_python.recipe.multitenancy.asyncio import (
    get_tenant_id,
    get_tenant_id_from_user_context,
    get_user,
    get_user_context,
)
from supertokens_python.recipe.multitenancy.exceptions import (
    SuperTokensUnknownUserIdError,
)
from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe
from supertokens_python.recipe.multitenancy.utils import get_user_context
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.asyncio import SessionContainer
from supertokens_python.recipe.session.interfaces import SessionContainer
from supertokens_python.utils import get_user_context

from .recipe import MultiFactorAuth, Recipe
from .utils import update_and_get_mfa_related_info_in_session


async def assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
    session: SessionContainer, factor_id: str, user_context: Dict[str, Any] = None
) -> None:
    ctx = get_user_context(user_context)

    mfa_info = await update_and_get_mfa_related_info_in_session(
        session=session, user_context=ctx
    )
    factors_setup_for_user = await get_factors_setup_for_user(
        session.get_user_id(), ctx
    )
    await Recipe.get_instance().recipe_implementation.assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
        session=session,
        factor_id=factor_id,
        factors_setup_for_user=factors_setup_for_user,
        mfa_requirements_for_auth=mfa_info.mfa_requirements_for_auth,
        user_context=ctx,
    )


async def get_factors_setup_for_user(
    user_id: str, user_context: Dict[str, Any] = None
) -> Any:
    ctx = get_user_context(user_context)
    user = await get_user(user_id, ctx)
    if user is None:
        raise Exception("Unknown user id")

    return await Recipe.get_instance().recipe_implementation.get_factors_setup_for_user(
        user=user, user_context=ctx
    )


async def get_mfa_requirements_for_auth(
    session: SessionContainer, user_context: Dict[str, Any] = None
) -> Dict[str, Any]:
    ctx = get_user_context(user_context)

    mfa_info = await update_and_get_mfa_related_info_in_session(
        session=session, user_context=ctx
    )

    return mfa_info["mfa_requirements_for_auth"]


async def mark_factor_as_complete_in_session(
    session: SessionContainer,
    factor_id: str,
    user_context: Dict[str, Any] | None = None,
) -> None:
    ctx = get_user_context(user_context)
    await MultitenancyRecipe.get_instance().recipe_implementation.mark_factor_as_complete_in_session(
        session=session, factor_id=factor_id, user_context=ctx
    )


async def get_factors_setup_for_user(
    user_id: str, user_context: Dict[str, Any] = None
) -> Any:
    ctx = get_user_context(user_context)
    try:
        user = await get_user(user_id, ctx)
    except SuperTokensUnknownUserIdError:
        raise Exception("Unknown user id")

    recipe_instance = await Recipe.get_instance()
    return await recipe_instance.recipe_implementation.get_factors_setup_for_user(
        {
            "user": user,
            "user_context": ctx,
        }
    )


async def get_required_secondary_factors_for_user(
    user_id: str, user_context: Dict[str, Any] = None
) -> List[str]:
    if user_context is None:
        user_context = {}

    recipe = MultiFactorAuth.get_instance()
    tenant_id = await get_tenant_id(user_context)

    return await recipe.recipe_implementation.get_required_secondary_factors_for_user(
        {"userId": user_id, "tenantId": tenant_id, "userContext": user_context}
    )


async def add_to_required_secondary_factors_for_user(
    user_id: str, factor_id: str, user_context: Dict[str, Any] | None = None
) -> None:
    ctx = get_user_context(user_context)
    recipe = await MultiFactorAuthRecipe.get_instance()
    await recipe.recipe_implementation.add_to_required_secondary_factors_for_user(
        user_id=user_id, factor_id=factor_id, user_context=ctx
    )


async def remove_from_required_secondary_factors_for_user(
    user_id: str, factor_id: str, user_context: Dict[str, Any] | None = None
) -> None:
    ctx = get_user_context(user_context)
    tenant_id = await get_tenant_id_from_user_context(ctx)
    await Recipe.get_instance().recipe_implementation.remove_from_required_secondary_factors_for_user(
        tenant_id=tenant_id, user_id=user_id, factor_id=factor_id, user_context=ctx
    )
