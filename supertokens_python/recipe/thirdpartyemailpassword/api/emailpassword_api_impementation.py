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

from typing import Any, Dict, List, Union

from supertokens_python.recipe.emailpassword.interfaces import (
    APIInterface,
    APIOptions,
    SignInPostOkResult,
    SignInPostWrongCredentialsError,
    SignUpPostEmailAlreadyExistsError,
    SignUpPostOkResult,
)
from supertokens_python.recipe.emailpassword.types import FormField, User
from supertokens_python.recipe.thirdpartyemailpassword.interfaces import (
    APIInterface as ThirdPartyEmailPasswordAPIInterface,
)
from supertokens_python.recipe.thirdpartyemailpassword.interfaces import (
    EmailPasswordSignInPostOkResult,
    EmailPasswordSignUpPostOkResult,
)
from supertokens_python.types import GeneralErrorResponse


def get_interface_impl(
    api_implementation: ThirdPartyEmailPasswordAPIInterface,
) -> APIInterface:
    implementation = APIInterface()

    implementation.disable_email_exists_get = (
        api_implementation.disable_email_exists_get
    )
    implementation.disable_generate_password_reset_token_post = (
        api_implementation.disable_generate_password_reset_token_post
    )
    implementation.disable_password_reset_post = (
        api_implementation.disable_password_reset_post
    )
    implementation.disable_sign_in_post = (
        api_implementation.disable_emailpassword_sign_in_post
    )
    implementation.disable_sign_up_post = (
        api_implementation.disable_emailpassword_sign_up_post
    )

    implementation.email_exists_get = api_implementation.emailpassword_email_exists_get
    implementation.generate_password_reset_token_post = (
        api_implementation.generate_password_reset_token_post
    )
    implementation.password_reset_post = api_implementation.password_reset_post
    if not implementation.disable_sign_in_post:

        async def sign_in_post(
            form_fields: List[FormField],
            tenant_id: str,
            api_options: APIOptions,
            user_context: Dict[str, Any],
        ) -> Union[
            SignInPostOkResult, SignInPostWrongCredentialsError, GeneralErrorResponse
        ]:
            result = await api_implementation.emailpassword_sign_in_post(
                form_fields, tenant_id, api_options, user_context
            )
            if isinstance(result, EmailPasswordSignInPostOkResult):
                return SignInPostOkResult(
                    User(
                        result.user.user_id,
                        result.user.email,
                        result.user.time_joined,
                        result.user.tenant_ids,
                    ),
                    result.session,
                )
            return result

        implementation.sign_in_post = sign_in_post

    if not implementation.disable_sign_up_post:

        async def sign_up_post(
            form_fields: List[FormField],
            tenant_id: str,
            api_options: APIOptions,
            user_context: Dict[str, Any],
        ) -> Union[
            SignUpPostOkResult, SignUpPostEmailAlreadyExistsError, GeneralErrorResponse
        ]:
            result = await api_implementation.emailpassword_sign_up_post(
                form_fields, tenant_id, api_options, user_context
            )
            if isinstance(result, EmailPasswordSignUpPostOkResult):
                return SignUpPostOkResult(
                    User(
                        result.user.user_id,
                        result.user.email,
                        result.user.time_joined,
                        result.user.tenant_ids,
                    ),
                    result.session,
                )
            return result

        implementation.sign_up_post = sign_up_post

    return implementation
