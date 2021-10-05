from flask import Flask, request, jsonify
from flask_cors import CORS
from supertokens_python import init
from supertokens_python.recipe import session
from supertokens_python.exceptions import SuperTokensError
from supertokens_python.framework.flask import error_handler, Middleware
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.session.sync import create_new_session

app = Flask(__name__)
app.register_error_handler(SuperTokensError, error_handler)
app.wsgi_app = Middleware(app.wsgi_app)
# CORS(app, supports_credentials=True)

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
    json = request.get_json()
    print(json)
    return jsonify({})

@app.route('/test_post', methods=['POST'])
def test_post():
    print(request)
    try:
        json = request.json
    except Exception as e:
        print(e)
    print(json)
    return jsonify({}), 200


if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5020, debug=True, threaded=True)
