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
from time import time

from supertokens_python.framework.response import BaseResponse


class DjangoResponse(BaseResponse):

    def __init__(self, response):
        super().__init__({})
        self.response = response
        self.original = response
        self.parser_checked = False

    def set_cookie(self, key: str, value: str = "", max_age: int = None, expires: int = None, path: str = "/",
                   domain: str = None, secure: bool = False, httponly: bool = False, samesite: str = "lax"):
        self.response.set_cookie(
            key,
            value,
            max_age,
            ceil((expires - int(time() * 1000)) / 1000),
            path,
            domain,
            secure,
            httponly)
        self.response.cookies[key]['samesite'] = samesite

    def set_status_code(self, status_code):
        self.response.status_code = status_code

    def set_header(self, key, value):
        self.response[key] = value

    def get_header(self, key):
        if self.response.has_header(key):
            return self.response[key]
        else:
            return None

    def set_content(self, content):
        self.response.content = json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
        ).encode("utf-8")
