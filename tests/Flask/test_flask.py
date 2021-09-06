import json

from _pytest.fixtures import fixture
from asgiref.sync import async_to_sync
from flask import Flask, jsonify, make_response, request
from werkzeug import Response

from supertokens_python.exceptions import SuperTokensError
from supertokens_python.framework.flask.flask_middleware import Middleware, error_handler
from supertokens_python import init, session, Supertokens
from supertokens_python.framework.flask.flask_response import FlaskResponse
from supertokens_python.session import get_session
from supertokens_python.session.sync import create_new_session, refresh_session
from tests.Flask.utils import extract_all_cookies


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


# @fixture(scope='function')
# def app():
#     app = Flask(__name__)
#     supertokens = Supertokens(app)
#     init({
#         'supertokens': {
#             'connection_uri': "http://localhost:3567",
#         },
#         'framework' : 'Flask',
#         'app_info': {
#             'app_name': "SuperTokens Demo",
#             'api_domain': "api.supertokens.io",
#             'website_domain': "supertokens.io",
#             'api_base_path': "/auth"
#         },
#         'recipe_list': [session.init(
#             {
#                 'anti_csrf': 'VIA_TOKEN',
#                 'cookie_domain': 'supertokens.io'
#             }
#         )],
#     })
#
#     def ff(e):
#         return jsonify({'error_msg': 'try refresh token'}), 401
#
#     supertokens.set_try_refresh_token_error_handler(ff)
#
#     @app.route('/login')
#     def login():
#         user_id = 'userId'
#         response = make_response(jsonify({'userId': user_id}), 200)
#         create_new_session(response, user_id, {}, {})
#         return response
#
#     @app.route('/refresh', methods=['POST'])
#     def refresh():
#         response = make_response(jsonify({}))
#         refresh_session(response)
#         return response
#
#     @app.route('/info', methods=['GET', 'OPTIONS'])
#     def info():
#         if request.method == 'OPTIONS':
#             return jsonify({'method': 'option'})
#         response = make_response(jsonify({}))
#         get_session(response, True)
#         return response
#
#     @app.route('/handle', methods=['GET', 'OPTIONS'])
#     def handle_api():
#         if request.method == 'OPTIONS':
#             return jsonify({'method': 'option'})
#         session = get_session(None, False)
#         return jsonify({'s': session.get_handle()})
#
#     @app.route('/logout', methods=['POST'])
#     def logout():
#         response = make_response(jsonify({}))
#         supertokens_session = get_session(response, True)
#         supertokens_session.revoke_session()
#         return response
#
#     return app
from tests.utils import set_key_value_in_config, TEST_COOKIE_SAME_SITE_CONFIG_KEY, TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY, \
    TEST_ACCESS_TOKEN_MAX_AGE_VALUE, TEST_ACCESS_TOKEN_PATH_CONFIG_KEY, TEST_ACCESS_TOKEN_PATH_VALUE, \
    TEST_COOKIE_DOMAIN_CONFIG_KEY, TEST_COOKIE_DOMAIN_VALUE, TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY, \
    TEST_REFRESH_TOKEN_MAX_AGE_VALUE, TEST_REFRESH_TOKEN_PATH_CONFIG_KEY, TEST_REFRESH_TOKEN_PATH_KEY_VALUE, \
    TEST_COOKIE_SECURE_CONFIG_KEY, TEST_DRIVER_CONFIG_COOKIE_DOMAIN, \
    TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH, TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH, TEST_DRIVER_CONFIG_COOKIE_SAME_SITE, \
    start_st, reset, clean_st, setup_st


@fixture(scope='function')
def driver_config_app():
    app = Flask(__name__)
    app.app_context().push()
    app.wsgi_app = Middleware(app.wsgi_app)



    app.register_error_handler(SuperTokensError, error_handler)

    # @app.after_request
    # def after_request_anything(response):
    #     print(response)

    app.testing = True
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'Flask',
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN',
                'cookie_domain': 'supertokens.io'
            }
        )],
    })

    @app.route('/test')
    def t():
        print(request)
        return jsonify({})

    def ff(e):
        return jsonify({'error_msg': 'try refresh token'}), 401

    # supertokens.set_try_refresh_token_error_handler(ff)

    @app.route('/login')
    def login():
        user_id = 'userId'
        print(request)

        session = create_new_session(request, user_id, {}, {})
        response = make_response(jsonify({'userId': user_id, 'session': 'ssss'}), 200)

        return response

    @app.route('/refresh', methods=['POST'])
    def custom_refresh():
        response = make_response(jsonify({}))
        refresh_session(request)
        return response

    @app.route('/custom/info', methods=['GET', 'OPTIONS'])
    def custom_info():
        if request.method == 'OPTIONS':
            return jsonify({'method': 'option'})
        response = make_response(jsonify({}))
        get_session(response, True)
        return response

    @app.route('/custom/handle', methods=['GET', 'OPTIONS'])
    def custom_handle_api():
        if request.method == 'OPTIONS':
            return jsonify({'method': 'option'})
        session = get_session(None, False)
        return jsonify({'s': session.get_handle()})

    @app.route('/custom/logout', methods=['POST'])
    def custom_logout():
        response = make_response(jsonify({}))
        supertokens_session = get_session(response, True)
        supertokens_session.revoke_session()
        return response

    return app



def test_cookie_and_header_values_with_driver_config_and_csrf_enabled(driver_config_app):
    start_st()

    set_key_value_in_config(
        TEST_COOKIE_SAME_SITE_CONFIG_KEY,
        'None')
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
        TEST_ACCESS_TOKEN_PATH_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_DOMAIN_CONFIG_KEY,
        TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
        TEST_REFRESH_TOKEN_PATH_KEY_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_SECURE_CONFIG_KEY,
        False)


    # response_2 = driver_config_app.test_client().get('/test')
    #
    #
    response_1 = driver_config_app.test_client().get('/login')
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get('anti-csrf') is not None
    assert cookies_1['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sAccessToken']['httponly']
    assert cookies_1['sRefreshToken']['httponly']
    assert cookies_1['sIdRefreshToken']['httponly']
    assert cookies_1['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sAccessToken']['secure'] is None
    assert cookies_1['sRefreshToken']['secure'] is None
    assert cookies_1['sIdRefreshToken']['secure'] is None




assert get_unix_timestamp(
    cookies_1['sAccessToken']['expires']) - int(time()) in {
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE,
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE - 1
}
assert get_unix_timestamp(
    cookies_1['sRefreshToken']['expires']) - int(time()) in {
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60,
        (TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60) - 1
}
assert cookies_1['sIdRefreshToken']['value'] + \
    ';' == response_1.headers['Id-Refresh-Token'][:-13]
assert int(response_1.headers['Id-Refresh-Token'][-13:-3]) == \
    get_unix_timestamp(cookies_1['sIdRefreshToken']['expires'])
assert response_1.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_ENABLE

request_2 = driver_config_app.test_client()
request_2.set_cookie(
    'localhost',
    'sRefreshToken',
    cookies_1['sRefreshToken']['value'])
response_2 = request_2.post('/custom/refresh', headers={
    'anti-csrf': response_1.headers.get('anti-csrf')})
cookies_2 = extract_all_cookies(response_2)
assert cookies_1['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
assert cookies_1['sRefreshToken']['value'] != cookies_2['sRefreshToken']['value']
assert cookies_1['sIdRefreshToken']['value'] != cookies_2['sIdRefreshToken']['value']
assert response_2.headers.get('anti-csrf') is not None
assert cookies_2['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
assert cookies_2['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
assert cookies_2['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
assert cookies_2['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
assert cookies_2['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
assert cookies_2['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
assert cookies_2['sAccessToken']['httponly']
assert cookies_2['sRefreshToken']['httponly']
assert cookies_2['sIdRefreshToken']['httponly']
assert cookies_2['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
assert cookies_2['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
assert cookies_2['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
assert cookies_2['sAccessToken']['secure']
assert cookies_2['sRefreshToken']['secure']
assert cookies_2['sIdRefreshToken']['secure']
assert get_unix_timestamp(
    cookies_2['sAccessToken']['expires']) - int(time()) in {
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE,
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE - 1
}

assert get_unix_timestamp(
    cookies_2['sRefreshToken']['expires']) - int(time()) in {
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60,
        (TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60) - 1
}
assert cookies_2['sIdRefreshToken']['value'] + \
    ';' == response_2.headers['Id-Refresh-Token'][:-13]
assert int(response_2.headers['Id-Refresh-Token'][-13:-3]) == \
    get_unix_timestamp(cookies_2['sIdRefreshToken']['expires'])
assert response_2.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_ENABLE

request_3 = driver_config_app.test_client()
request_3.set_cookie(
    'localhost',
    'sAccessToken',
    cookies_2['sAccessToken']['value'])
request_3.set_cookie(
    'localhost',
    'sIdRefreshToken',
    cookies_2['sIdRefreshToken']['value'])
response_3 = request_3.get(
    '/custom/info',
    headers={
        'anti-csrf': response_2.headers.get('anti-csrf')})
assert response_3.status_code == 200
cookies_3 = extract_all_cookies(response_3)
assert cookies_3['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
assert response_3.headers.get('anti-csrf') is None
assert cookies_3.get('sRefreshToken') is None
assert cookies_3.get('sIdRefreshToken') is None
assert cookies_3['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
assert cookies_3['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
assert cookies_3['sAccessToken']['httponly']
assert cookies_3['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
assert cookies_3['sAccessToken']['secure']

request_4 = driver_config_app.test_client()
request_4.set_cookie(
    'localhost',
    'sAccessToken',
    cookies_3['sAccessToken']['value'])
request_4.set_cookie(
    'localhost',
    'sIdRefreshToken',
    cookies_2['sIdRefreshToken']['value'])
response_4 = request_4.post(
    '/custom/logout',
    headers={
        'anti-csrf': response_2.headers.get('anti-csrf')})
cookies_4 = extract_all_cookies(response_4)
assert response_4.headers.get('anti-csrf') is None
assert cookies_4['sAccessToken']['value'] == ''
assert cookies_4['sRefreshToken']['value'] == ''
assert cookies_4['sIdRefreshToken']['value'] == ''
assert cookies_4['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
assert cookies_4['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
assert cookies_4['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
assert cookies_4['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
assert cookies_4['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
assert cookies_4['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
assert cookies_4['sAccessToken']['httponly']
assert cookies_4['sRefreshToken']['httponly']
assert cookies_4['sIdRefreshToken']['httponly']
assert cookies_4['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
assert cookies_4['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
assert cookies_4['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
assert cookies_4['sAccessToken']['secure']
assert cookies_4['sRefreshToken']['secure']
assert cookies_4['sIdRefreshToken']['secure']
assert get_unix_timestamp(cookies_4['sAccessToken']['expires']) == 0
assert get_unix_timestamp(cookies_4['sRefreshToken']['expires']) == 0
assert get_unix_timestamp(cookies_4['sIdRefreshToken']['expires']) == 0
assert response_4.headers['Id-Refresh-Token'] == 'remove'


def test_bug(driver_config_app):
    start_st()

    set_key_value_in_config(
        TEST_COOKIE_SAME_SITE_CONFIG_KEY,
        'None')
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
        TEST_ACCESS_TOKEN_PATH_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_DOMAIN_CONFIG_KEY,
        TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
        TEST_REFRESH_TOKEN_PATH_KEY_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_SECURE_CONFIG_KEY,
        False)

    # response_2 = driver_config_app.test_client().get('/test')
    #
    #
    response_1 = driver_config_app.test_client().get('/login')
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get('anti-csrf') is not None
    assert cookies_1['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sAccessToken']['httponly']
    assert cookies_1['sRefreshToken']['httponly']
    assert cookies_1['sIdRefreshToken']['httponly']
    assert cookies_1['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE

    test_client = driver_config_app.test_client()
    test_client.set_cookie('localhost', 'sRefreshToken', cookies_1['sRefreshToken']['value'])
    test_client.set_cookie('localhost', 'sIdRefreshToken', cookies_1['sIdRefreshToken']['value'])
    result = test_client.post('/refresh')
    print(result)
    assert result.status_code == 41
