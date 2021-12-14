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

from abc import ABC, abstractmethod

from typing import Any, Union


class BaseRequest(ABC):

    def __init__(self):
        self.wrapper_used = True
        self.request = None

    @abstractmethod
    def get_query_param(self, key, default=None):
        pass

    @abstractmethod
    async def json(self):
        pass

    @abstractmethod
    async def form_data(self):
        pass

    @abstractmethod
    def method(self) -> str:
        pass

    @abstractmethod
    def get_cookie(self, key: str) -> Union[str, None]:
        pass

    @abstractmethod
    def get_header(self, key: str) -> Any:
        pass

    @abstractmethod
    def url(self):
        pass

    @abstractmethod
    def get_session(self):
        pass

    @abstractmethod
    def set_session(self, session):
        pass

    @abstractmethod
    def get_path(self) -> str:
        pass
