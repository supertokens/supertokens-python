# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from math import ceil
from typing import Any, Dict, Literal, Optional

from litestar import Response
from litestar.serialization import encode_json

from supertokens_python.framework.response import BaseResponse
from supertokens_python.utils import get_timestamp_ms


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
        domain: Optional[str] = None,
        secure: bool = False,
        httponly: bool = False,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ):
        self.response.set_cookie(
            key=key,
            value=value,
            expires=ceil((expires - get_timestamp_ms()) / 1000),
            path=path,
            domain=domain,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )

    def set_header(self, key: str, value: str):
        self.response.headers[key] = value

    def get_header(self, key: str) -> Optional[str]:
        return self.response.headers.get(key, None)

    def remove_header(self, key: str):
        del self.response.headers[key]

    def set_status_code(self, status_code: int):
        if not self.status_set:
            self.response.status_code = status_code
            self.status_code = status_code
            self.status_set = True

    def set_json_content(self, content: Dict[str, Any]):
        if not self.response_sent:
            body = encode_json(
                content,
            )
            self.set_header("Content-Type", "application/json; charset=utf-8")
            self.set_header("Content-Length", str(len(body)))
            self.response.content = body
            self.response_sent = True

    def redirect(self, url: str) -> BaseResponse:
        if not self.response_sent:
            self.set_header("Location", url)
            self.set_status_code(302)
            self.response_sent = True
        return self
