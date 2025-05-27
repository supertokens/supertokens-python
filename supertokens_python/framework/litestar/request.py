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
from typing import Any, Dict, Union
from urllib.parse import parse_qsl

from litestar import Request
from supertokens_python.framework.request import BaseRequest
from supertokens_python.recipe.session.interfaces import SessionContainer


class LitestarRequest(BaseRequest):
    def __init__(self, request: Request[Any, Any, Any]):
        super().__init__()
        self.request = request

    def get_original_url(self) -> str:
        return str(self.request.url)

    def get_query_param(
        self, key: str, default: Union[str, None] = None
    ) -> Union[str, None]:
        return self.request.query_params.get(key, default)

    def get_query_params(self) -> Dict[str, Any]:
        return dict(self.request.query_params.items())  # type: ignore

    async def json(self) -> dict:
        """
        Read the entire ASGI stream and JSON-decode it,
        sidestepping Litestar’s internal max-body-size logic.
        """
        body_bytes = b"".join([chunk async for chunk in self.request.stream()])
        if not body_bytes:
            return {}
        try:
            return json.loads(body_bytes)
        except json.JSONDecodeError:
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
        return self.request.scope["raw_path"].decode("utf-8")

    async def form_data(self):
        return dict(parse_qsl((await self.request.body()).decode("utf-8")))
