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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Union

if TYPE_CHECKING:
    from supertokens_python.recipe.session.interfaces import SessionContainer


class BaseRequest(ABC):
    def __init__(self):
        self.wrapper_used = True
        self.request = None

    @abstractmethod
    def get_query_param(
        self, key: str, default: Union[str, None] = None
    ) -> Union[str, None]:
        pass

    @abstractmethod
    async def json(self) -> Union[Any, None]:
        pass

    @abstractmethod
    async def form_data(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def method(self) -> str:
        pass

    @abstractmethod
    def get_cookie(self, key: str) -> Union[str, None]:
        pass

    @abstractmethod
    def get_header(self, key: str) -> Union[None, str]:
        pass

    @abstractmethod
    def get_session(self) -> Union[SessionContainer, None]:
        pass

    @abstractmethod
    def set_session(self, session: SessionContainer):
        pass

    @abstractmethod
    def set_session_as_none(self):
        """
        This function is used to set the request's session variable to None.
        See https://github.com/supertokens/supertokens-python/issues/90
        """

    @abstractmethod
    def get_path(self) -> str:
        pass
