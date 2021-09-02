"""
Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.emailverification.recipe import EmailVerificationRecipe

from supertokens_python.exceptions import raise_general_exception, raise_bad_input_exception
from supertokens_python.session import verify_session
from supertokens_python.utils import normalise_http_method


async def handle_email_verify_api(recipe: EmailVerificationRecipe, request: BaseRequest):
    if normalise_http_method(request.method) == 'post':
        body = await request.json()
        if 'token' not in body:
            raise_bad_input_exception(recipe, 'Please provide the email verification token')
        if not isinstance(body['token'], str):
            raise_bad_input_exception(recipe, 'The email verification token must be a string')

        token = body['token']
        user = await recipe.verify_email_using_token(token)

        async def send_email():
            try:
                recipe.config.handle_post_email_verification(user)
            except Exception:
                pass

        asyncio.create_task(send_email())

        return BaseResponse(content={
            'status': 'OK'
        })
    else:
        session = await verify_session()(request)
        if session is None:
            raise_general_exception(recipe, 'Session is undefined. Should not come here.')

        user_id = session.get_user_id()
        email = await recipe.config.get_email_for_user_id(user_id)

        is_verified = await recipe.is_email_verified(user_id, email)
        return BaseResponse(content={
                'status': 'OK',
                'isVerified': is_verified
            })
