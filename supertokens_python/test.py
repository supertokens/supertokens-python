from typing import cast

from django.http import HttpRequest

from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.django.asyncio import verify_session


# highlight-start
@verify_session()
async def some_api(request: HttpRequest):
    session: SessionContainer = cast(SessionContainer, request.supertokens)  # type: ignore This will delete the session from the db and from the frontend (cookies)
    # highlight-end
    await session.revoke_session()
