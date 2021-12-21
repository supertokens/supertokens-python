import os
from flask import Flask, jsonify, g, make_response
from dotenv import load_dotenv
from flask_cors import CORS

from supertokens_python.framework.flask import Middleware
from supertokens_python.recipe.session.framework.flask import verify_session

from supertokens_python import init, get_all_cors_headers, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import session, thirdpartyemailpassword
from supertokens_python.recipe.thirdpartyemailpassword import Github, Google, Apple, Discord, GoogleWorkspaces

load_dotenv()

os.environ.setdefault('SUPERTOKENS_ENV', 'testing')


def make_default_options_response():
    _response = make_response()
    _response.status_code = 204
    return _response


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
    framework='flask',
    recipe_list=[
        session.init(),
        thirdpartyemailpassword.init(
            providers=[
                Google(
                    is_default=True,
                    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
                    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET')
                ), Google(
                    client_id=os.environ.get('GOOGLE_CLIENT_ID_MOBILE'),
                    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET')
                ), Github(
                    is_default=True,
                    client_id=os.environ.get('GITHUB_CLIENT_ID'),
                    client_secret=os.environ.get('GITHUB_CLIENT_SECRET')
                ), Github(
                    client_id=os.environ.get('GITHUB_CLIENT_ID_MOBILE'),
                    client_secret=os.environ.get('GITHUB_CLIENT_SECRET_MOBILE')
                ), Apple(
                    is_default=True,
                    client_id=os.environ.get('APPLE_CLIENT_ID'),
                    client_key_id=os.environ.get('APPLE_KEY_ID'),
                    client_team_id=os.environ.get('APPLE_TEAM_ID'),
                    client_private_key=os.environ.get('APPLE_PRIVATE_KEY')
                ), Apple(
                    client_id=os.environ.get('APPLE_CLIENT_ID_MOBILE'),
                    client_key_id=os.environ.get('APPLE_KEY_ID'),
                    client_team_id=os.environ.get('APPLE_TEAM_ID'),
                    client_private_key=os.environ.get('APPLE_PRIVATE_KEY')
                ), GoogleWorkspaces(
                    is_default=True,
                    client_id=os.environ.get('GOOGLE_WORKSPACES_CLIENT_ID'),
                    client_secret=os.environ.get('GOOGLE_WORKSPACES_CLIENT_SECRET')
                ), Discord(
                    is_default=True,
                    client_id=os.environ.get('DISCORD_CLIENT_ID'),
                    client_secret=os.environ.get('DISCORD_CLIENT_SECRET')
                )
            ]
        )
    ],
    telemetry=False
)

app = Flask(__name__)
app.make_default_options_response = make_default_options_response
Middleware(app)
CORS(
    app=app,
    supports_credentials=True,
    origins=get_website_domain(),
    allow_headers=['Content-Type'] + get_all_cors_headers()
)


@app.route('/sessioninfo', methods=['GET'])
@verify_session()
def get_session_info():
    session_ = g.supertokens
    return jsonify({
        'sessionHandle': session_.get_handle(),
        'userId': session_.get_user_id(),
        'accessTokenPayload': session_.get_access_token_payload()
    })


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def index(path):
    return ''


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(get_api_port()), debug=True)
