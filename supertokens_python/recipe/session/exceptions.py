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

from typing import Union

from supertokens_python.exceptions import SuperTokensError


def raise_token_theft_exception(user_id: str, session_handle: str):
    """raise_token_theft_exception.

    Parameters
    ----------
    user_id : str
        user_id
    session_handle : str
        session_handle
    """
    raise TokenTheftError(user_id, session_handle)


def raise_try_refresh_token_exception(ex: Union[str, Exception]):
    """raise_try_refresh_token_exception.

    Parameters
    ----------
    ex : Union[str, Exception]
        ex
    """
    if isinstance(ex, SuperTokensError):
        raise ex
    raise TryRefreshTokenError(ex) from None


def raise_unauthorised_exception(msg: str, clear_cookies: bool = True):
    """raise_unauthorised_exception.

    Parameters
    ----------
    msg : str
        msg
    clear_cookies : bool
        clear_cookies
    """
    raise UnauthorisedError(msg, clear_cookies) from None


class SuperTokensSessionError(SuperTokensError):
    """SuperTokensSessionError.
    """

    pass


class TokenTheftError(SuperTokensSessionError):
    """TokenTheftError.
    """

    def __init__(self, user_id: str, session_handle: str):
        """__init__.

        Parameters
        ----------
        user_id : str
            user_id
        session_handle : str
            session_handle
        """
        super().__init__('token theft detected')
        self.user_id = user_id
        self.session_handle = session_handle


class UnauthorisedError(SuperTokensSessionError):
    """UnauthorisedError.
    """

    def __init__(self, msg: str, clear_cookies: bool = True):
        """__init__.

        Parameters
        ----------
        msg : str
            msg
        clear_cookies : bool
            clear_cookies
        """
        super().__init__(msg)
        self.clear_cookies = clear_cookies


class TryRefreshTokenError(SuperTokensSessionError):
    """TryRefreshTokenError.
    """

    pass
