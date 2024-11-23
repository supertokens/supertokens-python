# import gevent.monkey
# gevent.monkey.patch_all()


# from tests.utils import start_st
# import pytest
# from flask import Flask, g, jsonify, make_response, request
# from supertokens_python import InputAppInfo, SupertokensConfig, init
# from supertokens_python.framework.flask import Middleware
# from typing import Any
# import json
# from typing import Any, Dict, Union
# from base64 import b64encode

# import pytest
# from _pytest.fixtures import fixture
# from flask import Flask, g, jsonify, make_response, request
# from supertokens_python import InputAppInfo, SupertokensConfig, init
# from supertokens_python.framework.flask import Middleware
# from supertokens_python.recipe import emailpassword, session, thirdparty
# from supertokens_python.recipe.emailpassword.interfaces import APIInterface, APIOptions
# from supertokens_python.recipe.session import SessionContainer
# from supertokens_python.recipe.session.framework.flask import verify_session
# from supertokens_python.recipe.session.syncio import (
#     create_new_session,
#     create_new_session_without_request_response,
#     get_session,
#     refresh_session,
#     revoke_session,
# )
# from supertokens_python.types import RecipeUserId
# from tests.Flask.utils import extract_all_cookies
# from tests.utils import (
#     TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
#     TEST_ACCESS_TOKEN_MAX_AGE_VALUE,
#     TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
#     TEST_ACCESS_TOKEN_PATH_VALUE,
#     TEST_COOKIE_DOMAIN_CONFIG_KEY,
#     TEST_COOKIE_DOMAIN_VALUE,
#     TEST_COOKIE_SAME_SITE_CONFIG_KEY,
#     TEST_COOKIE_SECURE_CONFIG_KEY,
#     TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH,
#     TEST_DRIVER_CONFIG_COOKIE_DOMAIN,
#     TEST_DRIVER_CONFIG_COOKIE_SAME_SITE,
#     TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH,
#     TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
#     TEST_REFRESH_TOKEN_MAX_AGE_VALUE,
#     TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
#     TEST_REFRESH_TOKEN_PATH_KEY_VALUE,
#     clean_st,
#     reset,
#     set_key_value_in_config,
#     setup_st,
#     start_st,
#     create_users,
# )
# from supertokens_python.recipe.dashboard import DashboardRecipe, InputOverrideConfig
# from supertokens_python.recipe.dashboard.interfaces import RecipeInterface
# from supertokens_python.framework import BaseRequest
# from supertokens_python.querier import Querier
# from supertokens_python.utils import is_version_gte
# from supertokens_python.recipe.passwordless import PasswordlessRecipe, ContactConfig
# from supertokens_python.recipe.dashboard.utils import DashboardConfig


# @pytest.fixture(scope="function") # type: ignore
# def flask_app():
#     app = Flask(__name__)
#     app.app_context().push()
#     Middleware(app)

#     app.testing = True
#     init(
#         supertokens_config=SupertokensConfig("http://localhost:3567"),
#         app_info=InputAppInfo(
#             app_name="SuperTokens Demo",
#             api_domain="http://api.supertokens.io",
#             website_domain="http://supertokens.io",
#             api_base_path="/auth",
#         ),
#         framework="flask",
#         recipe_list=[
#             session.init(),
#         ],
#     )

#     @app.route("/test")  # type: ignore
#     def t():  # type: ignore
#         return jsonify({})

#     return app


# def test_gevent(flask_app: Any):
#     # init(**{**get_st_init_args([session.init(get_token_transfer_method=lambda *_: "cookie")]), "framework": "flask"})  # type: ignore
#     start_st()
#     client = flask_app.test_client()

#     client.get("/test").json
#     client.get("/test").json
#     client.get("/test").json
#     client.get("/test").json
#     client.get("/test").json
