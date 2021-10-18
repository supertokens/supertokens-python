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
from typing import Union

from supertokens_python.framework.fastapi.fastapi_request import FastApiRequest
from supertokens_python.recipe.session import SessionRecipe, Session


def verify_session(
        anti_csrf_check: Union[bool, None] = None, session_required: bool = True):
    from fastapi.requests import Request

    async def func(request: Request) -> Union[Session, None]:
        request = FastApiRequest(request)
        recipe = SessionRecipe.get_instance()
        session = await recipe.verify_session(request, anti_csrf_check, session_required)

        request.set_session(session)
        return request.get_session()

    return func
