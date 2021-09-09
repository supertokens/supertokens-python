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
    from supertokens_python.emailpassword.recipe import EmailPasswordRecipe

from supertokens_python.emailpassword.exceptions import UnknownUserIdError
from .utils import validate_form_fields_or_throw_error
from supertokens_python.emailpassword.constants import FORM_FIELD_EMAIL_ID
from supertokens_python.utils import find_first_occurrence_in_list


async def handle_generate_password_reset_token_api(recipe: EmailPasswordRecipe, request: BaseRequest, response: BaseResponse):
    body = await request.json()
    form_fields_raw = body['formFields'] if 'formFields' in body else []
    form_fields = await validate_form_fields_or_throw_error(recipe,
                                                            recipe.config.reset_token_using_password_feature.form_fields_for_generate_token_form,
                                                            form_fields_raw)
    email = find_first_occurrence_in_list(lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields).value

    user = await recipe.get_user_by_email(email)

    if user is None:
        response.set_content({
            'status': 'OK'
        })
        return response

    try:
        token = await recipe.create_reset_password_token(user.user_id)
    except UnknownUserIdError:
        response.set_content({
            'status': 'OK'
        })
        return response

    password_reset_link = await recipe.config.reset_token_using_password_feature.get_reset_password_url(user) + '?token=' + token + '&rid=' + recipe.get_recipe_id()

    async def send_email():
        try:
            await recipe.config.reset_token_using_password_feature.create_and_send_custom_email(user, password_reset_link)
        except Exception:
            pass

    asyncio.create_task(send_email())

    response.set_content({
        'status': 'OK'
    })
    return response
