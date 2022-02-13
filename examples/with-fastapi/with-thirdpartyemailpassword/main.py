import os
import typing
from typing import Union

import uvicorn  # type: ignore
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.datastructures import Headers
from starlette.exceptions import ExceptionMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp
from supertokens_python import (InputAppInfo, SupertokensConfig,
                                get_all_cors_headers, init)
from supertokens_python.framework.fastapi import Middleware
from supertokens_python.recipe import session, thirdpartyemailpassword
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.fastapi import verify_session
from supertokens_python.recipe.thirdpartyemailpassword import (
    Apple, Discord, Github, Google, GoogleWorkspaces)

load_dotenv()

app = FastAPI(debug=True)
app.add_middleware(Middleware)
os.environ.setdefault('SUPERTOKENS_ENV', 'testing')


def get_api_port():
    return '3001'


def get_website_port():
    return '3000'


def get_website_domain():
    return 'http://localhost:' + get_website_port()


init(
    supertokens_config=SupertokensConfig(
        connection_uri='https://try.supertokens.io'
    ),
    app_info=InputAppInfo(
        app_name='Supertokens',
        api_domain='0.0.0.0' + get_api_port(),
        website_domain=get_website_domain()
    ),
    framework='fastapi',
    recipe_list=[
        session.init(),
        thirdpartyemailpassword.init(
            providers=[
                Google(
                    is_default=True,
                    client_id=os.environ.get('GOOGLE_CLIENT_ID'),  # type: ignore
                    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET')  # type: ignore
                ), Google(
                    client_id=os.environ.get('GOOGLE_CLIENT_ID_MOBILE'),  # type: ignore
                    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET')  # type: ignore
                ), Github(
                    is_default=True,
                    client_id=os.environ.get('GITHUB_CLIENT_ID'),  # type: ignore
                    client_secret=os.environ.get('GITHUB_CLIENT_SECRET')  # type: ignore
                ), Github(
                    client_id=os.environ.get('GITHUB_CLIENT_ID_MOBILE'),  # type: ignore
                    client_secret=os.environ.get('GITHUB_CLIENT_SECRET_MOBILE')  # type: ignore
                ), Apple(
                    is_default=True,
                    client_id=os.environ.get('APPLE_CLIENT_ID'),  # type: ignore
                    client_key_id=os.environ.get('APPLE_KEY_ID'),  # type: ignore
                    client_team_id=os.environ.get('APPLE_TEAM_ID'),  # type: ignore
                    client_private_key=os.environ.get('APPLE_PRIVATE_KEY')  # type: ignore
                ), Apple(
                    client_id=os.environ.get('APPLE_CLIENT_ID_MOBILE'),  # type: ignore
                    client_key_id=os.environ.get('APPLE_KEY_ID'),  # type: ignore
                    client_team_id=os.environ.get('APPLE_TEAM_ID'),  # type: ignore
                    client_private_key=os.environ.get('APPLE_PRIVATE_KEY')  # type: ignore
                ), GoogleWorkspaces(
                    is_default=True,
                    client_id=os.environ.get('GOOGLE_WORKSPACES_CLIENT_ID'),  # type: ignore
                    client_secret=os.environ.get('GOOGLE_WORKSPACES_CLIENT_SECRET')  # type: ignore
                ), Discord(
                    is_default=True,
                    client_id=os.environ.get('DISCORD_CLIENT_ID'),  # type: ignore
                    client_secret=os.environ.get('DISCORD_CLIENT_SECRET')  # type: ignore
                )
            ]
        )
    ],
    telemetry=False
)

app.add_middleware(ExceptionMiddleware, handlers=app.exception_handlers)


@app.get('/sessioninfo')
async def get_session_info(session_: SessionContainer = Depends(verify_session())):
    return JSONResponse({
        'sessionHandle': session_.get_handle(),
        'userId': session_.get_user_id(),
        'accessTokenPayload': session_.get_access_token_payload(),
        # 'sessionData': await session_.get_session_data()
    })


@app.exception_handler(405)  # type: ignore
def f_405(_, __: Exception):
    return PlainTextResponse('', status_code=404)


class CustomCORSMiddleware(CORSMiddleware):
    def __init__(
        self,
        app_: ASGIApp,
        allow_origins: typing.Sequence[str] = (),
        allow_methods: typing.Sequence[str] = ("GET",),
        allow_headers: typing.Sequence[str] = (),
        allow_credentials: bool = False,
        allow_origin_regex: Union[str, None] = None,
        expose_headers: typing.Sequence[str] = (),
        max_age: int = 600,
    ) -> None:
        super().__init__(app_, allow_origins, allow_methods, allow_headers, allow_credentials, allow_origin_regex, expose_headers, max_age)  # type: ignore

    def preflight_response(self, request_headers: Headers) -> Response:
        result: Response = super().preflight_response(request_headers)
        if result.status_code == 200:  # type: ignore
            result.headers.__delitem__('content-type')
            result.headers.__delitem__('content-length')
            return Response(status_code=204, headers=dict(result.headers))
        return result


app = CustomCORSMiddleware(  # type: ignore
    app_=app,
    allow_origins=[
        get_website_domain()
    ],
    allow_credentials=True,
    allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type"] + get_all_cors_headers(),
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=get_api_port())  # type: ignore
