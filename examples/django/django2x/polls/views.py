from django.http import HttpResponse, JsonResponse
from supertokens_python.session.framework.django.sync import verify_session

from supertokens_python.session.sync import create_new_session, refresh_session


def create(request):
    session = create_new_session(request, 'user_id')
    return HttpResponse("new session access token = " + session.get_access_token())


@verify_session(session_required=False)
def user(request):
    return HttpResponse("new session access token = " + request.state.get_user_id())
