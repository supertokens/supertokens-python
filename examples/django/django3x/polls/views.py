from django.http import HttpResponse
from supertokens_python.recipe.session.framework.django.asyncio import verify_session

from supertokens_python.recipe.session.asyncio import create_new_session


async def create(request):
    session = await create_new_session(request, 'user_id')
    return HttpResponse("new session access token = " +
                        session.get_access_token())


@verify_session(session_required=False)
async def user(request):
    return HttpResponse("new session access token = " +
                        request.state.get_user_id())
