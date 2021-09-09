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
from supertokens_python.exceptions import raise_general_exception
from supertokens_python.session import get_session
from supertokens_python.session.exceptions import UnauthorisedError


async def handle_sign_out_api(recipe: EmailPasswordRecipe, request: BaseRequest, response: BaseResponse):
    try:
        session = await get_session(request)
    except UnauthorisedError:
        response.set_content({
            'status': 'OK'
        })
        return response

    if session is None:
        raise_general_exception(recipe, 'Session is undefined. Should not come here.')

    await session.revoke_session()
    response.set_content({
        'status': 'OK'
    })
    return response
