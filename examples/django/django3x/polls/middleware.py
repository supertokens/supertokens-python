from werkzeug import Response


def simple_middleware(get_response):

    def middleware(request):
        try:
            response = get_response(request)

        except Exception as e:
            print(e)
            r = Response()
            r.status_code = 401
            return r

        # Code to be executed for each request/response after
        # the view is called.

        return response

    return middleware
