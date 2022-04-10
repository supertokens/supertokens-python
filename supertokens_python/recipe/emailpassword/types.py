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
from typing import Awaitable, Callable, List, Union


class User:
    """User.
    """

    def __init__(self, user_id: str, email: str, time_joined: int):
        """__init__.

        Parameters
        ----------
        user_id : str
            user_id
        email : str
            email
        time_joined : int
            time_joined
        """
        self.user_id: str = user_id
        self.email: str = email
        self.time_joined: int = time_joined
        self.third_party_info: None = None


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


class ErrorFormField:
    """ErrorFormField.
    """

    def __init__(self, id: str, error: str):  # pylint: disable=redefined-builtin
        """__init__.

        Parameters
        ----------
        id : str
            id
        error : str
            error
        """
        self.id = id
        self.error = error


class FormField:
    """FormField.
    """

    def __init__(self, id: str, value: str):  # pylint: disable=redefined-builtin
        """__init__.

        Parameters
        ----------
        id : str
            id
        value : str
            value
        """
        self.id: str = id
        self.value: str = value


class InputFormField:
    """InputFormField.
    """

    def __init__(self, id: str, validate: Union[Callable[[  # pylint: disable=redefined-builtin
                 str], Awaitable[Union[str, None]]], None] = None, optional: Union[bool, None] = None):
        """__init__.

        Parameters
        ----------
        id : str
            id
        validate : Union[Callable[[  # pylint: disable=redefined-builtin
                         str], Awaitable[Union[str, None]]], None]
            validate
        optional : Union[bool, None]
            optional
        """
        self.id = id
        self.validate = validate
        self.optional = optional


class NormalisedFormField:
    """NormalisedFormField.
    """

    def __init__(self, id: str, validate: Callable[[  # pylint: disable=redefined-builtin
                 str], Awaitable[Union[str, None]]], optional: bool):
        """__init__.

        Parameters
        ----------
        id : str
            id
        validate : Callable[[  # pylint: disable=redefined-builtin
                         str], Awaitable[Union[str, None]]]
            validate
        optional : bool
            optional
        """
        self.id = id
        self.validate = validate
        self.optional = optional
