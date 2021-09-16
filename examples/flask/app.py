from flask import Flask, request, jsonify
from flask_cors import CORS
from supertokens_python import init, session
from supertokens_python.exceptions import SuperTokensError
from supertokens_python.framework.flask import error_handler, Middleware
from supertokens_python.session.framework.flask import verify_session
from supertokens_python.session.sync import create_new_session, refresh_session

app = Flask(__name__)
app.register_error_handler(SuperTokensError, error_handler)
app.wsgi_app = Middleware(app.wsgi_app)
app.app_context().push()
CORS(app, supports_credentials=True)

init({
    'supertokens': {
        'connection_uri': "http://localhost:3567",
    },
    'framework': 'flask',
    'app_info': {
        'app_name': "SuperTokens Demo",
        'api_domain': "127.0.0.1:5000",
        'website_domain': "127.0.0.1:5000",
        'api_base_path': "/auth"
    },
    'recipe_list': [session.init(
        {
            'anti_csrf': 'VIA_TOKEN',
            'cookie_domain': '127.0.0.1:5000'
        }
    )],
})


@app.route('/create')
def hello_world():
    session = create_new_session(request, 'user_id')
    return jsonify(session)


@app.route('/user')
@verify_session(session_required=True)
def user():
    return jsonify({})


if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5000)
