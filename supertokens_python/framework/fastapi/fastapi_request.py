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

from typing import TYPE_CHECKING, Any, Union
from urllib.parse import parse_qsl

from supertokens_python.framework.request import BaseRequest

if TYPE_CHECKING:
    from supertokens_python.recipe.session.interfaces import SessionContainer


class FastApiRequest(BaseRequest):

    from fastapi import Request

    def __init__(self, request: Request):
        super().__init__()
        self.request = request

    def get_query_param(
        self, key: str, default: Union[str, None] = None
    ) -> Union[str, None]:
        return self.request.query_params.get(key, default)

    async def json(self) -> Union[Any, None]:
        try:
            return await self.request.json()
        except Exception:
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
        return self.request.url.path

    async def form_data(self):
        return dict(parse_qsl((await self.request.body()).decode("utf-8")))
