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
    usermetadata,
    thirdparty,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.fastapi import verify_session


load_dotenv()

app = FastAPI(debug=True)
app.add_middleware(get_middleware())


def get_api_port():
    return "3001"


def get_website_port():
    return "3000"


def get_website_domain():
    return "http://localhost:" + get_website_port()


init(
    supertokens_config=SupertokensConfig(connection_uri="https://try.supertokens.io"),
    app_info=InputAppInfo(
        app_name="Supertokens",
        api_domain="http://localhost:" + get_api_port(),
        website_domain=get_website_domain(),
    ),
    framework="fastapi",
    recipe_list=[
        session.init(),
        dashboard.init(),
        emailverification.init("REQUIRED"),
        usermetadata.init(),
        thirdparty.init(
            sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                providers=[
                    thirdparty.ProviderInput(
                        config=thirdparty.ProviderConfig(
                            third_party_id="google",
                            clients=[
                                thirdparty.ProviderClientConfig(
                                    client_id=os.environ["GOOGLE_CLIENT_ID"],
                                    client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
                                    client_type="web",
                                ),
                                thirdparty.ProviderClientConfig(
                                    client_id=os.environ["GOOGLE_CLIENT_ID_MOBILE"],
                                    client_secret=os.environ[
                                        "GOOGLE_CLIENT_SECRET_MOBILE"
                                    ],
                                    client_type="mobile",
                                ),
                            ],
                        ),
                    ),
                    thirdparty.ProviderInput(
                        config=thirdparty.ProviderConfig(
                            third_party_id="github",
                            clients=[
                                thirdparty.ProviderClientConfig(
                                    client_id=os.environ["GITHUB_CLIENT_ID"],
                                    client_secret=os.environ["GITHUB_CLIENT_SECRET"],
                                    client_type="web",
                                ),
                                thirdparty.ProviderClientConfig(
                                    client_id=os.environ["GITHUB_CLIENT_ID_MOBILE"],
                                    client_secret=os.environ[
                                        "GITHUB_CLIENT_SECRET_MOBILE"
                                    ],
                                    client_type="mobile",
                                ),
                            ],
                        )
                    ),
                    thirdparty.ProviderInput(
                        config=thirdparty.ProviderConfig(
                            third_party_id="apple",
                            clients=[
                                thirdparty.ProviderClientConfig(
                                    client_id=os.environ["APPLE_CLIENT_ID"],
                                    client_type="web",
                                    additional_config={
                                        "keyId": os.environ["APPLE_KEY_ID"],
                                        "teamId": os.environ["APPLE_TEAM_ID"],
                                        "privateKey": os.environ["APPLE_PRIVATE_KEY"],
                                    },
                                ),
                                thirdparty.ProviderClientConfig(
                                    client_id=os.environ["APPLE_CLIENT_ID_MOBILE"],
                                    client_type="mobile",
                                    additional_config={
                                        "keyId": os.environ["APPLE_KEY_ID"],
                                        "teamId": os.environ["APPLE_TEAM_ID"],
                                        "privateKey": os.environ["APPLE_PRIVATE_KEY"],
                                    },
                                ),
                            ],
                        )
                    ),
                    thirdparty.ProviderInput(
                        config=thirdparty.ProviderConfig(
                            third_party_id="google-workspaces",
                            clients=[
                                thirdparty.ProviderClientConfig(
                                    client_id=os.environ["GOOGLE_WORKSPACES_CLIENT_ID"],
                                    client_secret=os.environ[
                                        "GOOGLE_WORKSPACES_CLIENT_SECRET"
                                    ],
                                ),
                            ],
                        )
                    ),
                    thirdparty.ProviderInput(
                        config=thirdparty.ProviderConfig(
                            third_party_id="discord",
                            clients=[
                                thirdparty.ProviderClientConfig(
                                    client_id=os.environ["DISCORD_CLIENT_ID"],
                                    client_secret=os.environ["DISCORD_CLIENT_SECRET"],
                                ),
                            ],
                        )
                    ),
                ]
            )
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
    allow_origins=[get_website_domain()],
    allow_credentials=True,
    allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type"] + get_all_cors_headers(),
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=get_api_port())  # type: ignore
