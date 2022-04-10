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
from typing import Any, Dict, Union


class BaseResponse(ABC):
    """BaseResponse.
    """

    @abstractmethod
    def __init__(self, content: Dict[str, Any], status_code: int = 200):
        """__init__.

        Parameters
        ----------
        content : Dict[str, Any]
            content
        status_code : int
            status_code
        """
        self.content = content
        self.status_code = status_code
        self.wrapper_used = True

    @abstractmethod
    def set_cookie(self, key: str,
                   value: str,
                   #    max_age: Union[int, None] = None,
                   expires: int,
                   path: str = "/",
                   domain: Union[str, None] = None,
                   secure: bool = False,
                   httponly: bool = False,
                   samesite: str = "lax"):
        """set_cookie.

        Parameters
        ----------
        key : str
            key
        value : str
            value
        expires : int
            expires
        path : str
            path
        domain : Union[str, None]
            domain
        secure : bool
            secure
        httponly : bool
            httponly
        samesite : str
            samesite
        """
        pass

    @abstractmethod
    def set_header(self, key: str, value: str):
        """set_header.

        Parameters
        ----------
        key : str
            key
        value : str
            value
        """
        pass

    @abstractmethod
    def get_header(self, key: str) -> Union[str, None]:
        """get_header.

        Parameters
        ----------
        key : str
            key

        Returns
        -------
        Union[str, None]

        """
        pass

    @abstractmethod
    def set_status_code(self, status_code: int):
        """set_status_code.

        Parameters
        ----------
        status_code : int
            status_code
        """
        pass

    @abstractmethod
    def set_json_content(self, content: Dict[str, Any]):
        """set_json_content.

        Parameters
        ----------
        content : Dict[str, Any]
            content
        """
        pass

    @abstractmethod
    def set_html_content(self, content: str):
        """set_html_content.

        Parameters
        ----------
        content : str
            content
        """
        pass
