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
from typing import Any, Dict, Union

from supertokens_python.framework.response import BaseResponse


class FastApiResponse(BaseResponse):
    """FastApiResponse.
    """

    from fastapi import Response

    def __init__(self, response: Response):
        """__init__.

        Parameters
        ----------
        response : Response
            response
        """
        super().__init__({})
        self.response = response
        self.original = response
        self.parser_checked = False
        self.response_sent = False
        self.status_set = False

    def set_html_content(self, content: str):
        """set_html_content.

        Parameters
        ----------
        content : str
            content
        """
        if not self.response_sent:
            self.response.body = bytes(content, "utf-8")
            self.set_header('Content-Type', 'text/html')
            self.response_sent = True

    def set_cookie(self, key: str,
                   value: str,
                   expires: int,
                   path: str = "/",
                   domain: Union[str, None] = None,
                   secure: bool = False,
                   httponly: bool = False,
                   samesite: str = "lax"):
        """set_cookie.

        Parameters
        ----------
        key : str
            key
        value : str
            value
        expires : int
            expires
        path : str
            path
        domain : Union[str, None]
            domain
        secure : bool
            secure
        httponly : bool
            httponly
        samesite : str
            samesite
        """
        if domain is None:
            # we do ceil because if we do floor, we tests may fail where the access
            # token lifetime is set to 1 second
            self.response.set_cookie(key=key, value=value, expires=ceil((expires - int(time() * 1000)) / 1000),
                                     path=path, secure=secure, httponly=httponly, samesite=samesite)
        else:
            # we do ceil because if we do floor, we tests may fail where the access
            # token lifetime is set to 1 second
            self.response.set_cookie(key=key, value=value, expires=ceil((expires - int(time() * 1000)) / 1000),
                                     path=path, domain=domain, secure=secure, httponly=httponly, samesite=samesite)

    def set_header(self, key: str, value: str):
        """set_header.

        Parameters
        ----------
        key : str
            key
        value : str
            value
        """
        self.response.headers[key] = value

    def get_header(self, key: str) -> Union[str, None]:
        """get_header.

        Parameters
        ----------
        key : str
            key

        Returns
        -------
        Union[str, None]

        """
        return self.response.headers.get(key, None)

    def set_status_code(self, status_code: int):
        """set_status_code.

        Parameters
        ----------
        status_code : int
            status_code
        """
        if not self.status_set:
            self.response.status_code = status_code
            self.status_set = True

    def set_json_content(self, content: Dict[str, Any]):
        """set_json_content.

        Parameters
        ----------
        content : Dict[str, Any]
            content
        """
        if not self.response_sent:
            self.set_header('Content-Type', 'application/json; charset=utf-8')
            self.response.body = json.dumps(
                content,
                ensure_ascii=False,
                allow_nan=False,
                indent=None,
                separators=(",", ":"),
            ).encode("utf-8")
            self.response_sent = True
