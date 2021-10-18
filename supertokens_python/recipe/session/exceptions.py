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
from supertokens_python.exceptions import SuperTokensError


def raise_token_theft_exception(user_id, session_handle):
    raise TokenTheftError(user_id, session_handle)


def raise_try_refresh_token_exception(msg):
    if isinstance(msg, SuperTokensError):
        raise msg
    raise TryRefreshTokenError(msg) from None


def raise_unauthorised_exception(msg, clear_cookies=True):
    if isinstance(msg, SuperTokensError):
        raise msg
    raise UnauthorisedError(msg, clear_cookies) from None


class SuperTokensSessionError(SuperTokensError):
    pass


class TokenTheftError(SuperTokensSessionError):
    def __init__(self, user_id, session_handle):
        super().__init__('token theft detected')
        self.user_id = user_id
        self.session_handle = session_handle


class UnauthorisedError(SuperTokensSessionError):
    def __init__(self, msg, clear_cookies=True):
        super().__init__(msg)
        self.clear_cookies = clear_cookies


class TryRefreshTokenError(SuperTokensSessionError):
    pass
