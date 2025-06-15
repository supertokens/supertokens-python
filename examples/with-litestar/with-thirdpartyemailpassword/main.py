import os
from typing import Any

import uvicorn  # type: ignore
from dotenv import load_dotenv
from litestar import Litestar, MediaType, Response, get
from litestar.config.cors import CORSConfig
from litestar.di import Provide
from supertokens_python import (
    InputAppInfo,
    SupertokensConfig,
    get_all_cors_headers,
    init,
)
from supertokens_python.framework.litestar.middleware import LitestarMiddleware
from supertokens_python.recipe import (
    dashboard,
    emailverification,
    session,
    thirdparty,
    usermetadata,
)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.litestar import verify_session

load_dotenv()


def get_api_port():
    return 3001


def get_website_port():
    return "3000"


def get_website_domain():
    return "http://localhost:" + get_website_port()


init(
    supertokens_config=SupertokensConfig(connection_uri="https://try.supertokens.io"),
    app_info=InputAppInfo(
        app_name="Supertokens",
        api_domain="http://localhost:" + str(get_api_port()),
        website_domain=get_website_domain(),
        api_base_path="/auth",
    ),
    framework="litestar",
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


@get(
    "/sessioninfo",
    dependencies={"session": Provide(verify_session())},
)
async def get_session_info(session: SessionContainer) -> Response[Any]:
    return Response(
        {
            "sessionHandle": session.get_handle(),
            "userId": session.get_user_id(),
            "accessTokenPayload": session.get_access_token_payload(),
        }
    )


def f_405(_, __: Exception):
    return Response("", status_code=404, media_type=MediaType.TEXT)


cors = CORSConfig(
    allow_origins=[get_website_domain()],
    allow_credentials=True,
    allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type"] + get_all_cors_headers(),
)

app = Litestar(
    route_handlers=[
        get_session_info,
    ],
    middleware=[
        LitestarMiddleware(),
    ],
    cors_config=cors,
    exception_handlers={
        Exception: f_405,
    },
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=get_api_port())  # type: ignore
