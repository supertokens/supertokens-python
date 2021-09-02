"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from supertokens_python.framework.request import BaseRequest
    from supertokens_python.framework.response import BaseResponse
    from supertokens_python.emailpassword.recipe import EmailPasswordRecipe
from .utils import validate_form_fields_or_throw_error
from supertokens_python.emailpassword.constants import FORM_FIELD_PASSWORD_ID, FORM_FIELD_EMAIL_ID
from supertokens_python.utils import find_first_occurrence_in_list, get_filtered_list
from supertokens_python.exceptions import raise_general_exception
from supertokens_python.session import create_new_session


async def handle_sign_up_api(recipe: EmailPasswordRecipe, request: BaseRequest):
    body = await request.json()
    form_fields_raw = body['formFields'] if 'formFields' in body else []
    form_fields = await validate_form_fields_or_throw_error(recipe,
                                                            recipe.config.sign_in_feature.form_fields,
                                                            form_fields_raw)
    password = find_first_occurrence_in_list(lambda x: x.id == FORM_FIELD_PASSWORD_ID, form_fields).value
    email = find_first_occurrence_in_list(lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields).value

    user = await recipe.sign_up(email, password)

    await recipe.config.sign_in_feature.handle_post_sign_up(user, get_filtered_list(
        lambda x: x.id != FORM_FIELD_EMAIL_ID and x.id != FORM_FIELD_PASSWORD_ID, form_fields))

    jwt_payload_promise = recipe.config.session_feature.set_jwt_payload(user, get_filtered_list(
        lambda x: x.id != FORM_FIELD_EMAIL_ID and x.id != FORM_FIELD_PASSWORD_ID, form_fields), 'signup')
    session_data_promise = recipe.config.session_feature.set_session_data(user, get_filtered_list(
        lambda x: x.id != FORM_FIELD_EMAIL_ID and x.id != FORM_FIELD_PASSWORD_ID, form_fields), 'signup')

    jwt_payload = {}
    session_data = {}
    try:
        jwt_payload = await jwt_payload_promise
        session_data = await session_data_promise
    except Exception as e:
        raise_general_exception(recipe, e)

    await create_new_session(request, user.id, jwt_payload, session_data)

    return BaseResponse(content={
        'status': 'OK',
        'user': {
            'id': user.user_id,
            'email': user.email,
            'timeJoined': user.time_joined
        }
    })
