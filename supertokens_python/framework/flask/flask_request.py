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

from typing import TYPE_CHECKING, Any, Dict, Union

from supertokens_python.framework.request import BaseRequest

if TYPE_CHECKING:
    from supertokens_python.recipe.session.interfaces import SessionContainer
    from flask.wrappers import Request


class FlaskRequest(BaseRequest):
    def __init__(self, req: Request):
        super().__init__()
        self.request = req

    def get_original_url(self) -> str:
        return self.request.url

    def get_query_param(self, key: str, default: Union[str, None] = None):
        return self.request.args.get(key, default)

    def get_query_params(self) -> Dict[str, Any]:
        return self.request.args.to_dict()

    async def json(self) -> Union[Any, None]:
        try:
            return self.request.get_json()
        except Exception:
            return {}

    def method(self) -> str:
        if isinstance(self.request, dict):
            temp: str = self.request["REQUEST_METHOD"]
            return temp
        return self.request.method  # type: ignore

    def get_cookie(self, key: str) -> Union[str, None]:
        return self.request.cookies.get(key, None)

    def get_header(self, key: str) -> Union[None, str]:
        if isinstance(self.request, dict):
            return self.request.get(key, None)  # type: ignore
        return self.request.headers.get(key)  # type: ignore

    def get_session(self) -> Union[SessionContainer, None]:
        from flask import g

        if hasattr(g, "supertokens"):
            return g.supertokens
        return None

    def set_session(self, session: SessionContainer):
        from flask import g

        g.supertokens = session

    def set_session_as_none(self):
        from flask import g

        g.supertokens = None

    def get_path(self) -> str:
        if isinstance(self.request, dict):
            temp: str = self.request["PATH_INFO"]
            return temp
        return self.request.base_url

    async def form_data(self) -> Dict[str, Any]:
        return self.request.form.to_dict()
