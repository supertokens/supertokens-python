from __future__ import annotations
from typing import Any, Callable, Coroutine, TYPE_CHECKING

from litestar import Request

from supertokens_python.framework.litestar.litestar_request import LitestarRequest
from .litestar_middleware import get_middleware

if TYPE_CHECKING:
    from ...recipe.session import SessionRecipe, SessionContainer
    from ...recipe.session.interfaces import SessionClaimValidator
    from ...types import MaybeAwaitable

__all__ = ['get_middleware']


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
        custom_request = LitestarRequest(request)
        recipe = SessionRecipe.get_instance()
        session = await recipe.verify_session(
            custom_request,
            anti_csrf_check,
            session_required,
            user_context=user_context or {}
            )

        if session:
            custom_request.set_session(session)
        elif session_required:
            raise RuntimeError("Should never come here")
        else:
            custom_request.set_session_as_none()

        return custom_request.get_session()

    return func