import os

import uvicorn  # type: ignore
from dotenv import load_dotenv
from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.exceptions import ExceptionMiddleware
from starlette.middleware.cors import CORSMiddleware

from supertokens_python import (
    InputAppInfo,
    SupertokensConfig,
    get_all_cors_headers,
    init,
)
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import (
    dashboard,
    emailverification,
    session,
    thirdpartyemailpassword,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.fastapi import verify_session
from supertokens_python.recipe.thirdpartyemailpassword import (
    Apple,
    Discord,
    Github,
    Google,
    GoogleWorkspaces,
)

load_dotenv()

app = FastAPI(debug=True)
app.add_middleware(get_middleware())


def get_api_port():
    return "3001"


def get_website_port():
    return "3000"


def get_origin():
    return "http://localhost:" + get_website_port()


init(
    supertokens_config=SupertokensConfig(connection_uri="https://try.supertokens.io"),
    app_info=InputAppInfo(
        app_name="Supertokens",
        api_domain="http://localhost:" + get_api_port(),
        origin=get_origin(),
    ),
    framework="fastapi",
    recipe_list=[
        session.init(),
        dashboard.init(),
        emailverification.init("REQUIRED"),
        thirdpartyemailpassword.init(
            providers=[
                Google(
                    is_default=True,
                    client_id=os.environ.get("GOOGLE_CLIENT_ID"),  # type: ignore
                    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),  # type: ignore
                ),
                Google(
                    client_id=os.environ.get("GOOGLE_CLIENT_ID_MOBILE"),  # type: ignore
                    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),  # type: ignore
                ),
                Github(
                    is_default=True,
                    client_id=os.environ.get("GITHUB_CLIENT_ID"),  # type: ignore
                    client_secret=os.environ.get("GITHUB_CLIENT_SECRET"),  # type: ignore
                ),
                Github(
                    client_id=os.environ.get("GITHUB_CLIENT_ID_MOBILE"),  # type: ignore
                    client_secret=os.environ.get("GITHUB_CLIENT_SECRET_MOBILE"),  # type: ignore
                ),
                Apple(
                    is_default=True,
                    client_id=os.environ.get("APPLE_CLIENT_ID"),  # type: ignore
                    client_key_id=os.environ.get("APPLE_KEY_ID"),  # type: ignore
                    client_team_id=os.environ.get("APPLE_TEAM_ID"),  # type: ignore
                    client_private_key=os.environ.get("APPLE_PRIVATE_KEY"),  # type: ignore
                ),
                Apple(
                    client_id=os.environ.get("APPLE_CLIENT_ID_MOBILE"),  # type: ignore
                    client_key_id=os.environ.get("APPLE_KEY_ID"),  # type: ignore
                    client_team_id=os.environ.get("APPLE_TEAM_ID"),  # type: ignore
                    client_private_key=os.environ.get("APPLE_PRIVATE_KEY"),  # type: ignore
                ),
                GoogleWorkspaces(
                    is_default=True,
                    client_id=os.environ.get("GOOGLE_WORKSPACES_CLIENT_ID"),  # type: ignore
                    client_secret=os.environ.get("GOOGLE_WORKSPACES_CLIENT_SECRET"),  # type: ignore
                ),
                Discord(
                    is_default=True,
                    client_id=os.environ.get("DISCORD_CLIENT_ID"),  # type: ignore
                    client_secret=os.environ.get("DISCORD_CLIENT_SECRET"),  # type: ignore
                ),
            ]
        ),
    ],
    telemetry=False,
)

app.add_middleware(ExceptionMiddleware, handlers=app.exception_handlers)


@app.get("/sessioninfo")
async def get_session_info(session_: SessionContainer = Depends(verify_session())):
    return JSONResponse(
        {
            "sessionHandle": session_.get_handle(),
            "userId": session_.get_user_id(),
            "accessTokenPayload": session_.get_access_token_payload(),
            # "sessionData": await session_.get_session_data_from_database()
        }
    )


@app.exception_handler(405)  # type: ignore
def f_405(_, __: Exception):
    return PlainTextResponse("", status_code=404)


app = CORSMiddleware(  # type: ignore
    app=app,
    allow_origins=[get_origin()],
    allow_credentials=True,
    allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type"] + get_all_cors_headers(),
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=get_api_port())  # type: ignore
