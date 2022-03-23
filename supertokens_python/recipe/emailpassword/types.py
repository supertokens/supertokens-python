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
    """
    Class to hold the User details.

    ...

    Attributes
    ----------
    user_id: `str`
        user id for the given user.

    email: `str`
        email-id for the user.

    time_joined: `int`
        The time when user joined/signed up.
    """

    def __init__(self, user_id: str, email: str, time_joined: int):
        self.user_id: str = user_id
        self.email: str = email
        self.time_joined: int = time_joined
        self.third_party_info: None = None


class UsersResponse:
    """
    Class to hold the User list with pagination response.

    ...

    Attributes
    ----------
    users: `List`[`User`]
        List of the users.

    next_pagination_token: `Union`[`str`, `None`]
        next pagination token

    time_joined: `int`
        The time when user joined/signed up.
    """

    def __init__(self, users: List[User],
                 next_pagination_token: Union[str, None]):
        self.users = users
        self.next_pagination_token = next_pagination_token


class ErrorFormField:
    """
    Class to hold the Form Field with error

    ...

    Attributes
    ----------
    id: `str`
        Field id.

    error: `str`
        error message.
    """

    def __init__(self, id: str, error: str):  # pylint: disable=redefined-builtin
        self.id = id
        self.error = error


class FormField:
    """
    Class to hold the Form Field

    ...

    Attributes
    ----------
    id: `str`
        Field id.

    value: `str`
        Field value.
    """

    def __init__(self, id: str, value: str):  # pylint: disable=redefined-builtin
        self.id: str = id
        self.value: str = value


class InputFormField:
    """
    Class to hold the Input Form Field

    ...

    Attributes
    ----------
    id: `str`
        Field id.

    validate: `Union`[`Callable`[[`str`], `Awaitable`[`Union`[`str`, `None`]]], `None`]
        Validation coroutine

    optional: `Union`[`bool`, `None`]
        If the input form field is optional
    """

    def __init__(self, id: str, validate: Union[Callable[[  # pylint: disable=redefined-builtin
                 str], Awaitable[Union[str, None]]], None] = None, optional: Union[bool, None] = None):
        self.id = id
        self.validate = validate
        self.optional = optional


class NormalisedFormField:
    """
    Class to hold the Normalised Form Field

    ...

    Attributes
    ----------
    id: `str`
        Field id.

    validate: `Union`[`Callable`[[`str`], `Awaitable`[`Union`[`str`, `None`]]], `None`]
        Validation coroutine

    optional: `Union`[`bool`, `None`]
        If the input form field is optional
    """

    def __init__(self, id: str, validate: Callable[[  # pylint: disable=redefined-builtin
                 str], Awaitable[Union[str, None]]], optional: bool):
        self.id = id
        self.validate = validate
        self.optional = optional
