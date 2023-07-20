import os

from dotenv import load_dotenv
from flask import Flask, abort, g, jsonify
from flask_cors import CORS

from supertokens_python import (
    InputAppInfo,
    SupertokensConfig,
    get_all_cors_headers,
    init,
)
from supertokens_python.framework.flask import Middleware
from supertokens_python.recipe import (
    dashboard,
    emailverification,
    session,
    thirdpartyemailpassword,
)
from supertokens_python.recipe.session.framework.flask import verify_session

load_dotenv()


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
    framework="flask",
    recipe_list=[
        session.init(),
        dashboard.init(),
        emailverification.init("REQUIRED"),
        thirdpartyemailpassword.init(
            providers=[
                thirdpartyemailpassword.ProviderInput(
                    config=thirdpartyemailpassword.ProviderConfig(
                        third_party_id="google",
                        clients=[
                            thirdpartyemailpassword.ProviderClientConfig(
                                client_id=os.environ["GOOGLE_CLIENT_ID"],
                                client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
                            ),
                            thirdpartyemailpassword.ProviderClientConfig(
                                client_id=os.environ["GOOGLE_CLIENT_ID_MOBILE"],
                                client_secret=os.environ["GOOGLE_CLIENT_SECRET_MOBILE"],
                            ),
                        ],
                    ),
                ),
                thirdpartyemailpassword.ProviderInput(
                    config=thirdpartyemailpassword.ProviderConfig(
                        third_party_id="github",
                        clients=[
                            thirdpartyemailpassword.ProviderClientConfig(
                                client_id=os.environ["GITHUB_CLIENT_ID"],
                                client_secret=os.environ["GITHUB_CLIENT_SECRET"],
                            ),
                            thirdpartyemailpassword.ProviderClientConfig(
                                client_id=os.environ["GITHUB_CLIENT_ID_MOBILE"],
                                client_secret=os.environ["GITHUB_CLIENT_SECRET_MOBILE"],
                            ),
                        ],
                    )
                ),
                thirdpartyemailpassword.ProviderInput(
                    config=thirdpartyemailpassword.ProviderConfig(
                        third_party_id="apple",
                        clients=[
                            thirdpartyemailpassword.ProviderClientConfig(
                                client_id=os.environ["APPLE_CLIENT_ID"],
                                additional_config={
                                    "keyId": os.environ["APPLE_KEY_ID"],
                                    "teamId": os.environ["APPLE_TEAM_ID"],
                                    "privateKey": os.environ["APPLE_PRIVATE_KEY"],
                                },
                            ),
                            thirdpartyemailpassword.ProviderClientConfig(
                                client_id=os.environ["APPLE_CLIENT_ID_MOBILE"],
                                additional_config={
                                    "keyId": os.environ["APPLE_KEY_ID"],
                                    "teamId": os.environ["APPLE_TEAM_ID"],
                                    "privateKey": os.environ["APPLE_PRIVATE_KEY"],
                                },
                            ),
                        ],
                    )
                ),
                thirdpartyemailpassword.ProviderInput(
                    config=thirdpartyemailpassword.ProviderConfig(
                        third_party_id="googleworkspaces",
                        clients=[
                            thirdpartyemailpassword.ProviderClientConfig(
                                client_id=os.environ["GOOGLE_WORKSPACES_CLIENT_ID"],
                                client_secret=os.environ[
                                    "GOOGLE_WORKSPACES_CLIENT_SECRET"
                                ],
                            ),
                        ],
                    )
                ),
                thirdpartyemailpassword.ProviderInput(
                    config=thirdpartyemailpassword.ProviderConfig(
                        third_party_id="discord",
                        clients=[
                            thirdpartyemailpassword.ProviderClientConfig(
                                client_id=os.environ["DISCORD_CLIENT_ID"],
                                client_secret=os.environ["DISCORD_CLIENT_SECRET"],
                            ),
                        ],
                    )
                ),
            ]
        ),
    ],
    telemetry=False,
)

app = Flask(__name__)
Middleware(app)
CORS(
    app=app,
    supports_credentials=True,
    origins=get_website_domain(),
    allow_headers=["Content-Type"] + get_all_cors_headers(),
)


@app.route("/sessioninfo", methods=["GET"])  # type: ignore
@verify_session()
def get_session_info():
    session_ = g.supertokens
    return jsonify(
        {
            "sessionHandle": session_.get_handle(),
            "userId": session_.get_user_id(),
            "accessTokenPayload": session_.get_access_token_payload(),
            # "sessionData": session_.sync_get_session_data_from_database()
        }
    )


# This is required since if this is not there, then OPTIONS requests for
# the APIs exposed by the supertokens' Middleware will return a 404
@app.route("/", defaults={"u_path": ""})  # type: ignore
@app.route("/<path:u_path>")  # type: ignore
def catch_all(u_path: str):  # pylint: disable=unused-argument
    abort(404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(get_api_port()), debug=True)
