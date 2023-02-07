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
from typing import Any, Dict, List, Optional

from supertokens_python.framework.response import BaseResponse


class FlaskResponse(BaseResponse):
    from flask.wrappers import Response

    def __init__(self, response: Response):
        super().__init__({})
        self.response = response
        self.original = response
        self.headers: List[Any] = []
        self.response_sent = False
        self.status_set = False

    def set_html_content(self, content: str):
        if not self.response_sent:
            self.response.data = content
            self.set_header("Content-Type", "text/html")
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
        self.response.set_cookie(
            key,
            value=value,
            expires=expires / 1000,
            path=path,
            domain=domain,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )

    def set_header(self, key: str, value: str):
        self.response.headers.set(key, value)

    def get_header(self, key: str) -> Optional[str]:
        return self.response.headers.get(key)

    def remove_header(self, key: str):
        del self.response.headers[key]

    def set_status_code(self, status_code: int):
        if not self.status_set:
            self.response.status_code = status_code
            self.status_code = status_code
            self.status_set = True

    def get_headers(self):
        return self.response.headers

    def set_json_content(self, content: Dict[str, Any]):
        if not self.response_sent:
            self.set_header("Content-Type", "application/json; charset=utf-8")
            self.response.data = json.dumps(
                content,
                ensure_ascii=False,
                allow_nan=False,
                indent=None,
                separators=(",", ":"),
            ).encode("utf-8")
            self.response_sent = True
