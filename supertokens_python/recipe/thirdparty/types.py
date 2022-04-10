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
from typing import Callable, Dict, List, Union

from supertokens_python.framework.request import BaseRequest


class ThirdPartyInfo:
    """ThirdPartyInfo.
    """

    def __init__(self, third_party_user_id: str, third_party_id: str):
        """__init__.

        Parameters
        ----------
        third_party_user_id : str
            third_party_user_id
        third_party_id : str
            third_party_id
        """
        self.user_id = third_party_user_id
        self.id = third_party_id


class User:
    """User.
    """

    def __init__(self, user_id: str, email: str, time_joined: int,
                 third_party_info: ThirdPartyInfo):
        """__init__.

        Parameters
        ----------
        user_id : str
            user_id
        email : str
            email
        time_joined : int
            time_joined
        third_party_info : ThirdPartyInfo
            third_party_info
        """
        self.user_id: str = user_id
        self.email: str = email
        self.time_joined: int = time_joined
        self.third_party_info: ThirdPartyInfo = third_party_info


class UserInfoEmail:
    """UserInfoEmail.
    """

    def __init__(self, email: str, email_verified: bool):
        """__init__.

        Parameters
        ----------
        email : str
            email
        email_verified : bool
            email_verified
        """
        self.id: str = email
        self.is_verified: bool = email_verified


class UserInfo:
    """UserInfo.
    """

    def __init__(self, user_id: str, email: Union[UserInfoEmail, None] = None):
        """__init__.

        Parameters
        ----------
        user_id : str
            user_id
        email : Union[UserInfoEmail, None]
            email
        """
        self.user_id: str = user_id
        self.email: Union[UserInfoEmail, None] = email


class AccessTokenAPI:
    """AccessTokenAPI.
    """

    def __init__(self, url: str, params: Dict[str, str]):
        """__init__.

        Parameters
        ----------
        url : str
            url
        params : Dict[str, str]
            params
        """
        self.url = url
        self.params = params


class AuthorisationRedirectAPI:
    """AuthorisationRedirectAPI.
    """

    def __init__(self, url: str,
                 params: Dict[str, Union[Callable[[BaseRequest], str], str]]):
        """__init__.

        Parameters
        ----------
        url : str
            url
        params : Dict[str, Union[Callable[[BaseRequest], str], str]]
            params
        """
        self.url = url
        self.params = params


class SignInUpResponse:
    """SignInUpResponse.
    """

    def __init__(self, user: User, is_new_user: bool):
        """__init__.

        Parameters
        ----------
        user : User
            user
        is_new_user : bool
            is_new_user
        """
        self.user = user
        self.is_new_user = is_new_user


class UsersResponse:
    """UsersResponse.
    """

    def __init__(self, users: List[User],
                 next_pagination_token: Union[str, None]):
        """__init__.

        Parameters
        ----------
        users : List[User]
            users
        next_pagination_token : Union[str, None]
            next_pagination_token
        """
        self.users = users
        self.next_pagination_token = next_pagination_token
