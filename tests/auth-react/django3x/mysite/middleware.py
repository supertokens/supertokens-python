import asyncio

from django.http import HttpRequest, HttpResponse


def custom_cors_middleware(get_response):  # type: ignore
    if asyncio.iscoroutinefunction(get_response):  # type: ignore

        async def __middleware1(request: HttpRequest):  # type: ignore
            response: HttpResponse = await get_response(request)  # type: ignore
            if request.method == "OPTIONS":
                response.status_code = 204
            return response  # type: ignore

        return __middleware1
    else:

        def __middleware(request: HttpRequest):  # type: ignore
            response: HttpResponse = get_response(request)  # type: ignore

            if request.method == "OPTIONS":
                response.status_code = 204
            return response  # type: ignore

        return __middleware
