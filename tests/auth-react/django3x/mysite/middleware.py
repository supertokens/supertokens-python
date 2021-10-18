import asyncio


def custom_cors_middleware(get_response):
    if asyncio.iscoroutinefunction(get_response):
        async def __middleware(request):
            response = await get_response(request)
            if request.method == 'OPTIONS':
                response.status_code = 204
            return response
    else:
        def __middleware(request):
            response = get_response(request)

            if request.method == 'OPTIONS':
                response.status_code = 204
            return response
    return __middleware
