from __future__ import annotations
from typing import Any, Callable, Coroutine, TYPE_CHECKING

from supertokens_python.framework.litestar.litestar_request import LitestarRequest
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.types import MaybeAwaitable

from ...interfaces import SessionContainer, SessionClaimValidator

if TYPE_CHECKING:
    from litestar import Request


def verify_session(
    anti_csrf_check: bool | None = None,
    session_required: bool = True,
    override_global_claim_validators: Callable[
        [list[SessionClaimValidator], SessionContainer, dict[str, Any]],
        MaybeAwaitable[list[SessionClaimValidator]],
    ]
    | None = None,
    user_context: None | dict[str, Any] = None,
) -> Callable[..., Coroutine[Any, Any, SessionContainer | None]]:
    async def func(request: Request[Any, Any, Any]) -> SessionContainer | None:
        litestar_request = LitestarRequest(request)
        recipe = SessionRecipe.get_instance()
        session = await recipe.verify_session(
            litestar_request,
            anti_csrf_check,
            session_required,
            override_global_claim_validators,
            user_context or {},
        )

        if session:
            litestar_request.set_session(session)
        elif session_required:
            raise RuntimeError("Should never come here")
        else:
            litestar_request.set_session_as_none()

        return litestar_request.get_session()

    return func
