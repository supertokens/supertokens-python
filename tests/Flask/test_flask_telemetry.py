# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from typing import Any, Dict, Union

from flask import Flask, g, jsonify, make_response, request
import pytest
from supertokens_python import InputAppInfo, Supertokens, SupertokensConfig, init
from supertokens_python.framework.flask import Middleware
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword.interfaces import (APIInterface,
                                                                APIOptions)
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.session.syncio import (create_new_session,
                                                      get_session,
                                                      refresh_session,
                                                      revoke_session)
from tests.utils import (clean_st, reset, setup_st, start_st)


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


def driver_config_app():
    def override_email_password_apis(original_implementation: APIInterface):

        original_func = original_implementation.email_exists_get

        async def email_exists_get(email: str, api_options: APIOptions, user_context: Dict[str, Any]):
            response_dict = {'custom': True}
            api_options.response.set_status_code(203)
            api_options.response.set_json_content(response_dict)
            return await original_func(email, api_options, user_context)

        original_implementation.email_exists_get = email_exists_get
        return original_implementation

    app = Flask(__name__)
    app.app_context().push()
    Middleware(app)

    app.testing = True
    init(
        supertokens_config=SupertokensConfig('http://localhost:3567'),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://api.supertokens.io",
            website_domain="http://supertokens.io",
            api_base_path="/auth"
        ),
        framework='flask',
        recipe_list=[session.init(
            anti_csrf='VIA_TOKEN',
            cookie_domain='supertokens.io'
        ), emailpassword.init(
            override=emailpassword.InputOverrideConfig(
                apis=override_email_password_apis
            )
        )],
        telemetry=True
    )

    @app.route('/test')  # type: ignore
    def t():  # type: ignore
        return jsonify({})

    @app.route('/login')  # type: ignore
    def login():  # type: ignore
        user_id = 'userId'
        create_new_session(request, user_id, {}, {})

        return jsonify({'userId': user_id, 'session': 'ssss'})

    @app.route('/refresh', methods=['POST'])  # type: ignore
    def custom_refresh():  # type: ignore
        response = make_response(jsonify({}))
        refresh_session(request)
        return response

    @app.route('/info', methods=['GET', 'OPTIONS'])  # type: ignore
    def custom_info():  # type: ignore
        if request.method == 'OPTIONS':  # type: ignore
            return jsonify({'method': 'option'})
        response = make_response(jsonify({}))
        get_session(request, True)
        return response

    @app.route('/handle', methods=['GET', 'OPTIONS'])  # type: ignore
    def custom_handle_api():  # type: ignore
        if request.method == 'OPTIONS':  # type: ignore
            return jsonify({'method': 'option'})
        session: Union[None, SessionContainer] = get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        return jsonify({'s': session.get_user_id()})

    @app.route('/handle-session-optional', methods=['GET', 'OPTIONS'])  # type: ignore
    @verify_session(session_required=False)
    def optional_session():  # type: ignore
        if request.method == 'OPTIONS':  # type: ignore
            return jsonify({'method': 'option'})
        session: Union[SessionContainer, None] = g.supertokens  # type: ignore
        if session is None:
            return jsonify({'s': "empty session"})
        return jsonify({'s': session.get_user_id()})

    @app.route('/logout', methods=['POST'])  # type: ignore
    @verify_session(session_required=False)
    def custom_logout():  # type: ignore
        response = make_response(jsonify({}))
        session: Union[None, SessionContainer] = get_session(request, True)
        if session is None:
            raise Exception("Should never come here")
        revoke_session(session.get_user_id())
        return response

    return app


def test_telemetry():
    with pytest.warns(None) as record:
        driver_config_app()
        start_st()

    for warn in record:
        if warn.category is RuntimeWarning:
            assert False, 'Asyncio error'

    assert Supertokens.get_instance()._telemetry_status == 'SKIPPED'  # type: ignore pylint: disable=W0212
