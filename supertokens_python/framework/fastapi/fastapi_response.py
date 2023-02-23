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
import json
from math import ceil
from typing import Any, Dict, Optional

from supertokens_python.framework.response import BaseResponse
from supertokens_python.utils import get_timestamp_ms


class FastApiResponse(BaseResponse):
    from fastapi import Response

    def __init__(self, response: Response):
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
            self.response.body = body
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
        samesite: str = "lax",
    ):
        # Note: For FastAPI response object, the expires value
        # doesn't mean the absolute time in ms, but the duration in seconds
        # So we need to convert our absolute expiry time (ms) to a duration (seconds)

        # we do ceil because if we do floor, we tests may fail where the access
        # token lifetime is set to 1 second
        self.response.set_cookie(
            key=key,
            value=value,  # Note: Unlike other frameworks, FastAPI wraps the value in quotes in Set-Cookie header
            expires=ceil((expires - get_timestamp_ms()) / 1000),
            path=path,
            domain=domain,  # type: ignore # starlette didn't set domain as optional type but their default value is None anyways
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
            body = json.dumps(
                content,
                ensure_ascii=False,
                allow_nan=False,
                indent=None,
                separators=(",", ":"),
            ).encode("utf-8")
            self.set_header("Content-Type", "application/json; charset=utf-8")
            self.set_header("Content-Length", str(len(body)))
            self.response.body = body
            self.response_sent = True
