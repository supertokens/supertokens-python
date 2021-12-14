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
from typing import Union

from supertokens_python.framework.request import BaseRequest
from urllib.parse import parse_qsl


class FastApiRequest(BaseRequest):

    def __init__(self, request):
        super().__init__()
        self.request = request

    def get_query_param(self, key, default=None):
        return self.request.query_params.get(key, default)

    async def json(self):
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

    @property
    def url(self):
        return self.request.url

    def get_session(self):
        return self.request.state.supertokens

    def set_session(self, session):
        self.request.state.supertokens = session

    def get_path(self) -> str:
        return self.request.url.path

    async def form_data(self):
        return dict(parse_qsl((await self.request.body()).decode('utf-8')))
