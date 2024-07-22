from __future__ import annotations

from typing import TYPE_CHECKING, Any

from supertokens_python.framework.types import Framework

if TYPE_CHECKING:
    from litestar import Request


class LitestarFramework(Framework):
    def wrap_request(self, unwrapped: Request[Any, Any, Any]):
        from supertokens_python.framework.litestar.litestar_request import (
            LitestarRequest,
        )

        return LitestarRequest(unwrapped)