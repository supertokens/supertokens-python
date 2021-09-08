import asyncio

from asgiref.sync import async_to_sync
from werkzeug import Response

from supertokens_python.framework.django.django_request import DjangoRequest
from supertokens_python.framework.django.django_response import DjangoResponse
from supertokens_python import Supertokens
from supertokens_python.exceptions import SuperTokensError
from supertokens_python.session import Session
from supertokens_python.supertokens import manage_cookies_post_response


def middleware(get_response):
    st = Supertokens.get_instance()

    if asyncio.iscoroutinefunction(get_response):
        async def __middleware(request):
            custom_request = DjangoRequest(request)
            result = await st.middleware(custom_request)

            if result is None:
                result = await get_response(request)
                result = DjangoResponse(result)
            if hasattr(request, "state") and isinstance(request.state, Session):
                manage_cookies_post_response(request.state, result)

            return result.response


    else:
        def __middleware(request):

            custom_request = DjangoRequest(request)
            result = async_to_sync(st.middleware)(custom_request)

            if result is None:
                result = get_response(request)
                result = DjangoResponse(result)

            if hasattr(request.state, "supertokens") and isinstance(request.state.supertokens, Session):
                manage_cookies_post_response(request.state.supertokens, result)

            return result.response



    return __middleware