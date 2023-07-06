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

from typing import TYPE_CHECKING, Any, Dict, List, NoReturn, Optional, Union

from supertokens_python.exceptions import SuperTokensError

if TYPE_CHECKING:
    from .interfaces import ResponseMutator


def raise_token_theft_exception(user_id: str, session_handle: str) -> NoReturn:
    raise TokenTheftError(user_id, session_handle)


def raise_try_refresh_token_exception(ex: Union[str, Exception]) -> NoReturn:
    if isinstance(ex, SuperTokensError):
        raise ex

    raise TryRefreshTokenError(ex) from None


def raise_unauthorised_exception(
    msg: str,
    clear_tokens: bool = True,
    response_mutators: Optional[List[ResponseMutator]] = None,
) -> NoReturn:
    err = UnauthorisedError(msg, clear_tokens)

    if response_mutators is not None:
        err.response_mutators.extend(response_mutators)

    raise err


class SuperTokensSessionError(SuperTokensError):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.response_mutators: List[ResponseMutator] = []


class TokenTheftError(SuperTokensSessionError):
    def __init__(self, user_id: str, session_handle: str):
        super().__init__("token theft detected")
        self.user_id = user_id
        self.session_handle = session_handle


class UnauthorisedError(SuperTokensSessionError):
    def __init__(self, msg: str, clear_tokens: bool = True):
        super().__init__(msg)
        self.clear_tokens = clear_tokens


class TryRefreshTokenError(SuperTokensSessionError):
    pass


class InvalidClaimsError(SuperTokensSessionError):
    def __init__(self, msg: str, payload: List[ClaimValidationError]):
        super().__init__(msg)
        self.payload = payload


class ClaimValidationError:
    def __init__(self, id_: str, reason: Optional[Dict[str, Any]]):
        self.id = id_
        self.reason = reason

    def to_json(self):
        result: Dict[str, Any] = {"id": self.id}
        if self.reason is not None:
            result["reason"] = self.reason

        return result


def raise_invalid_claims_exception(msg: str, payload: List[ClaimValidationError]):
    raise InvalidClaimsError(msg, payload)
