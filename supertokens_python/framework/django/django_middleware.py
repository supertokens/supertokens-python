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
from typing import Any, Union

from asgiref.sync import async_to_sync


def middleware(get_response: Any):
    from supertokens_python import Supertokens
    from supertokens_python.exceptions import SuperTokensError
    from supertokens_python.framework.django.django_request import DjangoRequest
    from supertokens_python.framework.django.django_response import DjangoResponse
    from supertokens_python.recipe.session import SessionContainer
    from supertokens_python.supertokens import manage_cookies_post_response

    from django.http import HttpRequest

    if asyncio.iscoroutinefunction(get_response):

        async def __asyncMiddleware(request: HttpRequest):
            st = Supertokens.get_instance()
            custom_request = DjangoRequest(request)
            from django.http import HttpResponse

            response = DjangoResponse(HttpResponse())
            try:
                result = await st.middleware(custom_request, response)
                if result is None:
                    result = await get_response(request)
                    result = DjangoResponse(result)
                if hasattr(request, "supertokens") and isinstance(
                    request.supertokens, SessionContainer  # type: ignore
                ):
                    manage_cookies_post_response(
                        request.supertokens, result  # type: ignore
                    )
                if isinstance(result, DjangoResponse):
                    return result.response
            except SuperTokensError as e:
                response = DjangoResponse(HttpResponse())
                result = await st.handle_supertokens_error(
                    DjangoRequest(request), e, response
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
        try:
            result: Union[DjangoResponse, None] = async_to_sync(st.middleware)(
                custom_request, response
            )

            if result is None:
                result = DjangoResponse(get_response(request))

            if hasattr(request, "supertokens") and isinstance(
                request.supertokens, SessionContainer  # type: ignore
            ):
                manage_cookies_post_response(
                    request.supertokens, result  # type: ignore
                )
            return result.response

        except SuperTokensError as e:
            response = DjangoResponse(HttpResponse())
            result: Union[DjangoResponse, None] = async_to_sync(
                st.handle_supertokens_error
            )(DjangoRequest(request), e, response)
            if result is not None:
                return result.response
        raise Exception("Should never come here")

    return __syncMiddleware
