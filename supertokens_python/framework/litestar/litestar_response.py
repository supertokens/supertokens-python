from __future__ import annotations
from typing import Any, TYPE_CHECKING, cast
from typing_extensions import Literal
from supertokens_python.framework.response import BaseResponse

if TYPE_CHECKING:
    from litestar import Response


class LitestarResponse(BaseResponse):
    def __init__(self, response: Response[Any]):
        super().__init__({})
        self.response = response
        self.original = response
        self.parser_checked = False
        self.response_sent = False
        self.status_set = False

    def set_html_content(self, content: str):
        if not self.response_sent:
            body = bytes(content, "utf-8")
            self.set_header("Content-Length", str(len(body)))
            self.set_header("Content-Type", "text/html")
            self.response.content = body
            self.response_sent = True

    def set_cookie(
            self,
            key: str,
            value: str,
            expires: int,
            path: str = "/",
            domain: str | None = None,
            secure: bool = False,
            httponly: bool = False,
            samesite: str = "lax",
    ):
        self.response.set_cookie(
            key=key,
            value=value,
            expires=expires,
            path=path,
            domain=domain,
            secure=secure,
            httponly=httponly,
            samesite=cast(Literal["lax", "strict", "none"], samesite),
        )

    def set_header(self, key: str, value: str):
        self.response.set_header(key, value)

    def get_header(self, key: str) -> str | None:
        return self.response.headers.get(key, None)

    def remove_header(self, key: str):
        del self.response.headers[key]

    def set_status_code(self, status_code: int):
        if not self.status_set:
            self.response.status_code = status_code
            self.status_code = status_code
            self.status_set = True

    def set_json_content(self, content: dict[str, Any]):
        if not self.response_sent:
            from litestar.serialization import encode_json

            body = encode_json(content)
            self.set_header("Content-Type", "application/json; charset=utf-8")
            self.set_header("Content-Length", str(len(body)))
            self.response.content = body
            self.response_sent = True