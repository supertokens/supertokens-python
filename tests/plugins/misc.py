from typing import Any, Dict, Optional

from supertokens_python.framework.request import BaseRequest
from supertokens_python.framework.response import BaseResponse
from supertokens_python.recipe.session import SessionContainer


class DummyRequest(BaseRequest):
    def get_path(self) -> str:
        return "/auth/plugin1/hello"

    def get_method(self) -> str:
        return "get"

    def get_original_url(self) -> Any:
        raise NotImplementedError

    def get_query_param(self, key: str, default: Optional[str] = None) -> Any:
        raise NotImplementedError

    def get_query_params(self) -> Any:
        raise NotImplementedError

    async def json(self) -> Any:
        raise NotImplementedError

    async def form_data(self) -> Any:
        raise NotImplementedError

    def method(self) -> Any:
        return "get"

    def get_cookie(self, key: str) -> Any:
        raise NotImplementedError

    def get_header(self, key: str) -> Any:
        return None

    def get_session(self) -> Any:
        raise NotImplementedError

    def set_session(self, session: SessionContainer) -> Any:
        raise NotImplementedError

    def set_session_as_none(self) -> Any:
        raise NotImplementedError


class DummyResponse(BaseResponse):
    def __init__(self, content: Dict[str, Any], status_code: int = 200):
        self.content = content
        self.status_code = status_code

    def set_cookie(
        self,
        key: str,
        value: str,
        expires: int,
        path: str = "/",
        domain: Optional[str] = None,
        secure: bool = False,
        httponly: bool = False,
        samesite: str = "lax",
    ) -> Any:
        raise NotImplementedError

    def set_header(self, key: str, value: str) -> None:
        raise NotImplementedError

    def get_header(self, key: str) -> Optional[str]:
        raise NotImplementedError

    def remove_header(self, key: str) -> None:
        raise NotImplementedError

    def set_status_code(self, status_code: int) -> None:
        raise NotImplementedError

    def set_json_content(self, content: Dict[str, Any]) -> Any:
        raise NotImplementedError

    def set_html_content(self, content: str) -> Any:
        raise NotImplementedError

    def redirect(self, url: str) -> Any:
        raise NotImplementedError
