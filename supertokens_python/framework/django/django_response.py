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
from datetime import datetime
from math import ceil
from typing import Any, Dict, Optional

from supertokens_python.framework.response import BaseResponse


class DjangoResponse(BaseResponse):
    from django.http import HttpResponse

    def __init__(self, response: HttpResponse):
        super().__init__({})
        self.response = response
        self.original = response
        self.parser_checked = False
        self.response_sent = False
        self.status_set = False

    def set_html_content(self, content: str):
        if not self.response_sent:
            self.response.content = content
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
            key=key,
            value=value,
            expires=datetime.fromtimestamp(ceil(expires / 1000)).strftime(
                "%a, %d %b %Y %H:%M:%S GMT"
            ),
            path=path,
            domain=domain,
            secure=secure,
            httponly=httponly,
        )
        self.response.cookies[key]["samesite"] = samesite

    def set_status_code(self, status_code: int):
        if not self.status_set:
            self.response.status_code = status_code
            self.status_code = status_code
            self.status_set = True

    def set_header(self, key: str, value: str):
        self.response[key] = value

    def get_header(self, key: str) -> Optional[str]:
        if self.response.has_header(key):
            return self.response[key]
        return None

    def remove_header(self, key: str):
        del self.response[key]

    def set_json_content(self, content: Dict[str, Any]):
        if not self.response_sent:
            self.set_header("Content-Type", "application/json; charset=utf-8")
            self.response.content = json.dumps(
                content,
                ensure_ascii=False,
                allow_nan=False,
                indent=None,
                separators=(",", ":"),
            ).encode("utf-8")
            self.response_sent = True
