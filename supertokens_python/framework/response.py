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


class BaseResponse(ABC):

    @abstractmethod
    def __init__(self, content: dict, status_code: int = 200):
        self.content = content
        self.status_code = status_code
        self.wrapper_used = True

    @abstractmethod
    def set_cookie(self, key: str,
                   value: str = "",
                   max_age: int = None,
                   expires: int = None,
                   path: str = "/",
                   domain: str = None,
                   secure: bool = False,
                   httponly: bool = False,
                   samesite: str = "Lax", ):
        pass

    @abstractmethod
    def set_header(self, key, value):
        pass

    @abstractmethod
    def get_header(self, key):
        pass

    @abstractmethod
    def set_status_code(self, status_code):
        pass

    @abstractmethod
    def set_json_content(self, content):
        pass

    @abstractmethod
    def set_html_content(self, content):
        pass
