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
from typing import Any, Dict, Optional


class BaseResponse(ABC):
    @abstractmethod
    def __init__(self, content: Dict[str, Any], status_code: int = 200):
        self.content = content
        self.status_code = status_code
        self.wrapper_used = True

    @abstractmethod
    def set_cookie(
        self,
        key: str,
        value: str,
        #    max_age: Union[int, None] = None,
        expires: int,
        path: str = "/",
        domain: Optional[str] = None,
        secure: bool = False,
        httponly: bool = False,
        samesite: str = "lax",
    ):
        pass

    @abstractmethod
    def set_header(self, key: str, value: str) -> None:
        pass

    @abstractmethod
    def get_header(self, key: str) -> Optional[str]:
        pass

    @abstractmethod
    def remove_header(self, key: str) -> None:
        pass

    @abstractmethod
    def set_status_code(self, status_code: int):
        pass

    @abstractmethod
    def set_json_content(self, content: Dict[str, Any]):
        pass

    @abstractmethod
    def set_html_content(self, content: str):
        pass
