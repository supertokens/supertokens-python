from __future__ import annotations

from typing import TYPE_CHECKING, Any

from supertokens_python.framework.request import BaseRequest

if TYPE_CHECKING:
    from litestar import Request
    from supertokens_python.recipe.session.interfaces import SessionContainer

try:
    from litestar.exceptions import SerializationException
except ImportError:
    SerializationException = Exception  # type: ignore


class LitestarRequest(BaseRequest):
    def __init__(self, request: Request[Any, Any, Any]):
        super().__init__()
        self.request = request

    def get_original_url(self) -> str:
        return self.request.url

    def get_query_param(self, key: str, default: str | None = None) -> Any:
        return self.request.query_params.get(key, default)  # pyright: ignore

    def get_query_params(self) -> dict[str, list[Any]]:
        return self.request.query_params.dict()  # pyright: ignore

    async def json(self) -> Any:
        try:
            return await self.request.json()
        except SerializationException:
            return {}

    def method(self) -> str:
        return self.request.method

    def get_cookie(self, key: str) -> str | None:
        return self.request.cookies.get(key)

    def get_header(self, key: str) -> str | None:
        return self.request.headers.get(key, None)

    def get_session(self) -> SessionContainer | None:
        return self.request.state.supertokens

    def set_session(self, session: SessionContainer):
        self.request.state.supertokens = session

    def set_session_as_none(self):
        self.request.state.supertokens = None

    def get_path(self) -> str:
        return self.request.url.path

    async def form_data(self) -> dict[str, list[Any]]:
        return (await self.request.form()).dict()