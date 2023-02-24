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

from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from supertokens_python.recipe.dashboard.interfaces import (
        APIOptions,
        APIInterface,
    )

from supertokens_python.exceptions import (raise_bad_input_exception,
                                           raise_general_exception)

from ..interfaces import VerifyPostOK, VerifyPostInvalidSession, VerifyPostUserSuspended


async def handle_verify(api_implementation: APIInterface, api_options: APIOptions) -> Union[VerifyPostOK, VerifyPostInvalidSession, VerifyPostUserSuspended]:
    sessionIdFromAuthHeader = api_options.request.get_header("Authorization")
    if not sessionIdFromAuthHeader:
        raise_bad_input_exception("Authorization header was not sent")
    response = await api_options.recipe_implementation.verify(sessionIdFromAuthHeader)
    if "status" in response and response["status"] == "OK":
        return VerifyPostOK()
    elif "status" in response and response["statius"] == "USER_SUSPENDED_ERROR":
        return VerifyPostUserSuspended()
    elif "status" in response and response["status"] == "INVAlID_SESSION_ERROR":
        return VerifyPostInvalidSession()
    else:
        raise_general_exception("Core returned invalid value")
