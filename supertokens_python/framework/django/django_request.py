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
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, Union
from urllib.parse import parse_qsl

from supertokens_python.framework.request import BaseRequest

if TYPE_CHECKING:
    from supertokens_python.recipe.session.interfaces import SessionContainer
    from django.http import HttpRequest


class DjangoRequest(BaseRequest):
    def __init__(self, request: HttpRequest):
        super().__init__()
        self.request = request

    def get_original_url(self) -> str:
        return self.request.get_raw_uri()

    def get_query_param(
        self, key: str, default: Union[str, None] = None
    ) -> Union[str, None]:
        return self.request.GET.get(key, default)

    def get_query_params(self) -> Dict[str, Any]:
        return self.request.GET.dict()

    async def json(self) -> Union[Any, None]:
        try:
            body = json.loads(self.request.body)
            return body
        except Exception:
            return {}

    def method(self) -> str:
        if self.request.method is None:
            raise Exception("Should never come here")
        return self.request.method

    def get_cookie(self, key: str) -> Union[str, None]:
        return self.request.COOKIES.get(key)

    def get_header(self, key: str) -> Union[None, str]:
        key = key.replace("-", "_")
        key = "HTTP_" + key
        return self.request.META.get(key.upper())

    def get_session(self) -> Union[SessionContainer, None]:
        return self.request.supertokens  # type: ignore

    def set_session(self, session: SessionContainer):
        self.request.supertokens = session  # type: ignore

    def set_session_as_none(self):
        self.request.supertokens = None  # type: ignore

    def get_path(self) -> str:
        return self.request.path

    async def form_data(self):
        return dict(parse_qsl(self.request.body.decode("utf-8")))
