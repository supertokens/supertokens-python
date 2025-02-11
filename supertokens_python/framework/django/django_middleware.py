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

import asyncio
from typing import Any, Optional, Union

from asgiref.sync import async_to_sync

from supertokens_python.framework import BaseResponse


def middleware(get_response: Any):
    from django.http import HttpRequest

    from supertokens_python import Supertokens
    from supertokens_python.exceptions import SuperTokensError
    from supertokens_python.framework.django.django_request import DjangoRequest
    from supertokens_python.framework.django.django_response import DjangoResponse
    from supertokens_python.recipe.session import SessionContainer
    from supertokens_python.supertokens import manage_session_post_response
    from supertokens_python.utils import default_user_context

    if asyncio.iscoroutinefunction(get_response):

        async def __asyncMiddleware(request: HttpRequest):
            st = Supertokens.get_instance()
            custom_request = DjangoRequest(request)
            from django.http import HttpResponse

            response = DjangoResponse(HttpResponse())
            user_context = default_user_context(custom_request)

            try:
                result = await st.middleware(custom_request, response, user_context)
                if result is None:
                    result = await get_response(request)
                    result = DjangoResponse(result)
                if hasattr(request, "supertokens") and isinstance(
                    request.supertokens,  # type: ignore
                    SessionContainer,
                ):
                    manage_session_post_response(
                        request.supertokens,  # type: ignore
                        result,
                        user_context,
                    )
                if isinstance(result, DjangoResponse):
                    return result.response
            except SuperTokensError as e:
                response = DjangoResponse(HttpResponse())
                result = await st.handle_supertokens_error(
                    DjangoRequest(request), e, response, user_context
                )
                if isinstance(result, DjangoResponse):
                    return result.response

            raise Exception("Should never come here")

        return __asyncMiddleware

    def __syncMiddleware(request: HttpRequest):
        st = Supertokens.get_instance()
        custom_request = DjangoRequest(request)
        from django.http import HttpResponse

        response = DjangoResponse(HttpResponse())
        user_context = default_user_context(custom_request)

        try:
            result: Union[BaseResponse, None] = async_to_sync(st.middleware)(
                custom_request, response, user_context
            )

            if result is None:
                result = DjangoResponse(get_response(request))

            if not isinstance(result, DjangoResponse):
                raise Exception("should never happen")

            if hasattr(request, "supertokens") and isinstance(
                request.supertokens,  # type: ignore
                SessionContainer,
            ):
                manage_session_post_response(
                    request.supertokens,  # type: ignore
                    result,
                    user_context,
                )

            return result.response

        except SuperTokensError as e:
            response = DjangoResponse(HttpResponse())
            result: Optional[BaseResponse] = async_to_sync(st.handle_supertokens_error)(
                DjangoRequest(request), e, response, user_context
            )

            if result is not None:
                if not isinstance(result, DjangoResponse):
                    raise Exception("should never happen")

                return result.response
        raise Exception("Should never come here")

    return __syncMiddleware
