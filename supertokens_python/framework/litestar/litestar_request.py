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
from typing import Any, Dict, Union
from urllib.parse import parse_qsl

from litestar import Request
from litestar.exceptions import SerializationException
from supertokens_python.framework.request import BaseRequest
from supertokens_python.recipe.session.interfaces import SessionContainer


class LitestarRequest(BaseRequest):
    def __init__(self, request: Request[Any, Any, Any]):
        super().__init__()
        self.request = request

    def get_original_url(self) -> str:
        print(f"The request url is {self.request.url}")
        print(f"The request url is {self.request.url.from_components()}")
        return str(self.request.url)

    def get_query_param(
        self, key: str, default: Union[str, None] = None
    ) -> Union[str, None]:
        return self.request.query_params.get(key, default)

    def get_query_params(self) -> Dict[str, Any]:
        return dict(self.request.query_params.items())  # type: ignore

    async def json(self) -> Union[Any, None]:
        try:
            return await self.request.json()
        except SerializationException:
            return {}

    def method(self) -> str:
        return self.request.method

    def get_cookie(self, key: str) -> Union[str, None]:
        return self.request.cookies.get(key)

    def get_header(self, key: str) -> Union[str, None]:
        return self.request.headers.get(key, None)

    def get_session(self) -> Union[SessionContainer, None]:
        return self.request.state.supertokens

    def set_session(self, session: SessionContainer):
        self.request.state.supertokens = session

    def set_session_as_none(self):
        self.request.state.supertokens = None

    def get_path(self) -> str:
        print(f"The request url is {self.request.url}")
        return self.request.url.path

    async def form_data(self):
        return dict(parse_qsl((await self.request.body()).decode("utf-8")))
