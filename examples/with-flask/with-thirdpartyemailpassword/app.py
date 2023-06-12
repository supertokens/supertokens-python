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
from supertokens_python.recipe.thirdpartyemailpassword import (
    Apple,
    Discord,
    Github,
    Google,
    GoogleWorkspaces,
)

load_dotenv()


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
    framework="flask",
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

app = Flask(__name__)
Middleware(app)
CORS(
    app=app,
    supports_credentials=True,
    origins=get_origin(),
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
