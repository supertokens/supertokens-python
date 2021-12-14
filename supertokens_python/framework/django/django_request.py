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
from typing import Any, Union
from supertokens_python.framework.request import BaseRequest
from urllib.parse import parse_qsl


class DjangoRequest(BaseRequest):

    def __init__(self, request):
        super().__init__()
        self.request = request

    def get_query_param(self, key, default=None):
        return self.request.GET.get(key, default)

    async def json(self):
        try:
            body = json.loads(self.request.body)
            return body
        except Exception:
            return {}

    def method(self) -> str:
        return self.request.method

    def get_cookie(self, key: str) -> Union[str, None]:
        return self.request.COOKIES.get(key)

    def get_header(self, key: str) -> Any:
        key = key.replace('-', '_')
        key = 'HTTP_' + key
        return self.request.META.get(key.upper())

    def url(self):
        return self.request.get_full_path()

    def get_session(self):
        return self.request.supertokens

    def set_session(self, session):
        self.request.supertokens = session

    def get_path(self) -> str:
        return self.request.path

    async def form_data(self):
        return dict(parse_qsl(self.request.body.decode('utf-8')))
