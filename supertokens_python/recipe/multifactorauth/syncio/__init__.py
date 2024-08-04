from typing import Any, Dict, List, Optional

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.recipe.session import SessionContainer


def get_factors_setup_for_user(user_id: str, user_context: Dict[str, Any]) -> List[str]:
    from supertokens_python.recipe.multifactorauth.asyncio import (
        get_factors_setup_for_user,
    )

    return sync(get_factors_setup_for_user(user_id=user_id, user_context=user_context))


def assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
    session: SessionContainer,
    factor_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> None:
    from supertokens_python.recipe.multifactorauth.asyncio import (
        assert_allowed_to_setup_factor_else_throw_invalid_claim_error,
    )

    return sync(
        assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
            session=session, factor_id=factor_id, user_context=user_context
        )
    )
