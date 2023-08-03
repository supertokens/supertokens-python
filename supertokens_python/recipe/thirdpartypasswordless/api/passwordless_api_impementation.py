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

from typing import Any, Dict, Union

from supertokens_python.recipe.passwordless.interfaces import APIInterface
from supertokens_python.types import GeneralErrorResponse

from ...passwordless.interfaces import APIOptions as PasswordlessAPIOptions
from ...passwordless.interfaces import (
    ConsumeCodePostExpiredUserInputCodeError,
    ConsumeCodePostIncorrectUserInputCodeError,
    ConsumeCodePostOkResult,
    ConsumeCodePostRestartFlowError,
)
from ...passwordless.types import User
from ..interfaces import APIInterface as ThirdPartyPasswordlessAPIInterface
from ..interfaces import ConsumeCodePostOkResult as ThirdPartyConsumeCodePostOkResult


def get_interface_impl(
    api_implementation: ThirdPartyPasswordlessAPIInterface,
) -> APIInterface:
    implementation = APIInterface()

    implementation.disable_email_exists_get = (
        api_implementation.disable_passwordless_user_email_exists_get
    )
    implementation.disable_resend_code_post = (
        api_implementation.disable_resend_code_post
    )
    implementation.disable_create_code_post = (
        api_implementation.disable_create_code_post
    )
    implementation.disable_consume_code_post = (
        api_implementation.disable_consume_code_post
    )
    implementation.disable_phone_number_exists_get = (
        api_implementation.disable_passwordless_user_phone_number_exists_get
    )

    implementation.email_exists_get = (
        api_implementation.passwordless_user_email_exists_get
    )

    if not implementation.disable_consume_code_post:

        async def consume_code_post(
            pre_auth_session_id: str,
            user_input_code: Union[str, None],
            device_id: Union[str, None],
            link_code: Union[str, None],
            tenant_id: str,
            api_options: PasswordlessAPIOptions,
            user_context: Dict[str, Any],
        ) -> Union[
            ConsumeCodePostOkResult,
            ConsumeCodePostRestartFlowError,
            ConsumeCodePostIncorrectUserInputCodeError,
            ConsumeCodePostExpiredUserInputCodeError,
            GeneralErrorResponse,
        ]:
            result = await api_implementation.consume_code_post(
                pre_auth_session_id,
                user_input_code,
                device_id,
                link_code,
                tenant_id,
                api_options,
                user_context,
            )
            if isinstance(result, ThirdPartyConsumeCodePostOkResult):
                return ConsumeCodePostOkResult(
                    result.created_new_user,
                    User(
                        result.user.user_id,
                        result.user.email,
                        result.user.phone_number,
                        result.user.time_joined,
                        result.user.tenant_ids,
                    ),
                    result.session,
                )
            return result

        implementation.consume_code_post = consume_code_post

    implementation.create_code_post = api_implementation.create_code_post
    implementation.phone_number_exists_get = (
        api_implementation.passwordless_user_phone_number_exists_get
    )
    implementation.resend_code_post = api_implementation.resend_code_post

    return implementation
