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

from werkzeug.http import dump_cookie

from supertokens_python.framework.response import BaseResponse


class FlaskResponse(BaseResponse):

    def __init__(self, response=None):
        super().__init__({})
        self.response = response
        self.headers = list()
        self.response_sent = False
        self.status_set = False

    def set_html_content(self, content):
        if not self.response_sent:
            self.response.data = content
            self.set_header('Content-Type', 'text/html')
            self.response_sent = True

    def set_cookie(self, key: str, value: str = "", max_age: int = None, expires: int = None, path: str = "/",
                   domain: str = None, secure: bool = False, httponly: bool = False, samesite: str = "lax"):
        if self.response is None:
            self.headers.append(("Set-Cookie",
                                 dump_cookie(
                                     key,
                                     value=value,
                                     max_age=max_age,
                                     expires=expires / 1000,
                                     path=path,
                                     domain=domain,
                                     secure=secure,
                                     httponly=httponly,
                                     samesite=samesite
                                 )))
        else:
            self.response.set_cookie(key, value=value, max_age=max_age, expires=expires / 1000, path=path, domain=domain, secure=secure, httponly=httponly, samesite=samesite)

    def set_header(self, key, value):
        if self.response is None:
            # TODO in the future the headrs must be validated..
            if not isinstance(value, str):
                raise TypeError("Value should be unicode.")
            if u"\n" in value or u"\r" in value:
                raise ValueError(
                    "Detected newline in header value.  This is "
                    "a potential security problem"
                )
            self.headers.append((key, value))
        else:
            self.response.headers.add(key, value)

    def get_header(self, key):
        if self.response is not None:
            return self.response.headers.get(key)
        else:
            for value in self.headers:
                if value[0] == key:
                    return value[1]
            return None

    def set_status_code(self, status_code):
        if not self.status_set:
            self.response.status_code = status_code
            self.status_set = True

    def get_headers(self):
        if self.response is None:
            return self.headers
        else:
            return self.response.headers

    def set_json_content(self, content):
        if not self.response_sent:
            self.set_header('Content-Type', 'application/json; charset=utf-8')
            self.response.data = json.dumps(
                content,
                ensure_ascii=False,
                allow_nan=False,
                indent=None,
                separators=(",", ":"),
            ).encode("utf-8")
            self.response_sent = True
