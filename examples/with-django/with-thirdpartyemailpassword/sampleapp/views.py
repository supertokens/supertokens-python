from django.http import HttpRequest, JsonResponse
from supertokens_python.recipe.session.framework.django.syncio import verify_session
from supertokens_python.recipe.session import SessionContainer


@verify_session()
def get_session_info(request: HttpRequest) -> JsonResponse:
    session_: SessionContainer = request.supertokens  # type: ignore
    return JsonResponse(
        {
            "sessionHandle": session_.get_handle(),
            "userId": session_.get_user_id(),
            "accessTokenPayload": session_.get_access_token_payload(),
            # "sessionData": session_.sync_get_session_data_from_database(),
        }
    )
