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
from pytest import mark
from unittest.mock import MagicMock
from supertokens_python import InputAppInfo, SupertokensConfig, init, Supertokens
from supertokens_python.normalised_url_domain import NormalisedURLDomain
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.recipe import session
from supertokens_python.recipe.session import SessionRecipe
from supertokens_python.recipe.session.asyncio import create_new_session
from typing import Optional, Dict, Any
from supertokens_python.framework import BaseRequest

from tests.utils import clean_st, reset, setup_st, start_st


def setup_function(_):
    reset()
    clean_st()
    setup_st()


def teardown_function(_):
    reset()
    clean_st()


def testing_URL_path_normalisation():
    def normalise_url_path_or_throw_error(
        input: str,
    ):  # pylint: disable=redefined-builtin
        return NormalisedURLPath(input).get_as_string_dangerous()

    assert (
        normalise_url_path_or_throw_error("exists?email=john.doe%40gmail.com")
        == "/exists"
    )
    assert (
        normalise_url_path_or_throw_error(
            "/auth/email/exists?email=john.doe%40gmail.com"
        )
        == "/auth/email/exists"
    )
    assert normalise_url_path_or_throw_error("exists") == "/exists"
    assert normalise_url_path_or_throw_error("/exists") == "/exists"
    assert (
        normalise_url_path_or_throw_error("/exists?email=john.doe%40gmail.com")
        == "/exists"
    )
    assert normalise_url_path_or_throw_error("http://api.example.com") == ""
    assert normalise_url_path_or_throw_error("https://api.example.com") == ""
    assert normalise_url_path_or_throw_error("http://api.example.com?hello=1") == ""
    assert normalise_url_path_or_throw_error("http://api.example.com/hello") == "/hello"
    assert normalise_url_path_or_throw_error("http://api.example.com/") == ""
    assert normalise_url_path_or_throw_error("http://api.example.com:8080") == ""
    assert normalise_url_path_or_throw_error("api.example.com/") == ""
    assert normalise_url_path_or_throw_error("api.example.com#random") == ""
    assert normalise_url_path_or_throw_error(".example.com") == ""
    assert normalise_url_path_or_throw_error("api.example.com/?hello=1&bye=2") == ""

    assert (
        normalise_url_path_or_throw_error("http://api.example.com/one/two")
        == "/one/two"
    )
    assert normalise_url_path_or_throw_error("http://1.2.3.4/one/two") == "/one/two"
    assert normalise_url_path_or_throw_error("1.2.3.4/one/two") == "/one/two"
    assert (
        normalise_url_path_or_throw_error("https://api.example.com/one/two/")
        == "/one/two"
    )
    assert (
        normalise_url_path_or_throw_error("http://api.example.com/one/two?hello=1")
        == "/one/two"
    )
    assert (
        normalise_url_path_or_throw_error("http://api.example.com/hello/") == "/hello"
    )
    assert (
        normalise_url_path_or_throw_error("http://api.example.com/one/two/")
        == "/one/two"
    )
    assert (
        normalise_url_path_or_throw_error("http://api.example.com/one/two#random2")
        == "/one/two"
    )
    assert normalise_url_path_or_throw_error("api.example.com/one/two") == "/one/two"
    assert normalise_url_path_or_throw_error(".example.com/one/two") == "/one/two"
    assert (
        normalise_url_path_or_throw_error("api.example.com/one/two?hello=1&bye=2")
        == "/one/two"
    )

    assert normalise_url_path_or_throw_error("/one/two") == "/one/two"
    assert normalise_url_path_or_throw_error("one/two") == "/one/two"
    assert normalise_url_path_or_throw_error("one/two/") == "/one/two"
    assert normalise_url_path_or_throw_error("/one") == "/one"
    assert normalise_url_path_or_throw_error("one") == "/one"
    assert normalise_url_path_or_throw_error("one/") == "/one"
    assert normalise_url_path_or_throw_error("/one/two/") == "/one/two"
    assert normalise_url_path_or_throw_error("/one/two?hello=1") == "/one/two"
    assert normalise_url_path_or_throw_error("one/two?hello=1") == "/one/two"
    assert normalise_url_path_or_throw_error("/one/two/#randm,") == "/one/two"
    assert normalise_url_path_or_throw_error("one/two#random") == "/one/two"

    assert normalise_url_path_or_throw_error("localhost:4000/one/two") == "/one/two"
    assert normalise_url_path_or_throw_error("127.0.0.1:4000/one/two") == "/one/two"
    assert normalise_url_path_or_throw_error("127.0.0.1/one/two") == "/one/two"
    assert (
        normalise_url_path_or_throw_error("https://127.0.0.1:80/one/two") == "/one/two"
    )
    assert normalise_url_path_or_throw_error("/") == ""
    assert normalise_url_path_or_throw_error("") == ""

    assert (
        normalise_url_path_or_throw_error("/.netlify/functions/api")
        == "/.netlify/functions/api"
    )
    assert (
        normalise_url_path_or_throw_error("/netlify/.functions/api")
        == "/netlify/.functions/api"
    )
    assert (
        normalise_url_path_or_throw_error("app.example.com/.netlify/functions/api")
        == "/.netlify/functions/api"
    )
    assert (
        normalise_url_path_or_throw_error("app.example.com/netlify/.functions/api")
        == "/netlify/.functions/api"
    )
    assert normalise_url_path_or_throw_error("/app.example.com") == "/app.example.com"


def testing_URL_domain_normalisation():
    def normalise_url_domain_or_throw_error(
        input: str,
    ):  # pylint: disable=redefined-builtin
        return NormalisedURLDomain(input).get_as_string_dangerous()

    assert (
        normalise_url_domain_or_throw_error("http://api.example.com")
        == "http://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("https://api.example.com")
        == "https://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("http://api.example.com?hello=1")
        == "http://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("http://api.example.com/hello")
        == "http://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("http://api.example.com/")
        == "http://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("http://api.example.com#random2")
        == "http://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("http://api.example.com:8080")
        == "http://api.example.com:8080"
    )
    assert (
        normalise_url_domain_or_throw_error("api.example.com/")
        == "https://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("api.example.com")
        == "https://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("api.example.com#random")
        == "https://api.example.com"
    )
    assert normalise_url_domain_or_throw_error(".example.com") == "https://example.com"
    assert (
        normalise_url_domain_or_throw_error("api.example.com/?hello=1&bye=2")
        == "https://api.example.com"
    )
    assert normalise_url_domain_or_throw_error("localhost") == "http://localhost"
    assert (
        normalise_url_domain_or_throw_error("https://localhost") == "https://localhost"
    )

    assert (
        normalise_url_domain_or_throw_error("http://api.example.com/one/two")
        == "http://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("http://1.2.3.4/one/two")
        == "http://1.2.3.4"
    )
    assert (
        normalise_url_domain_or_throw_error("https://1.2.3.4/one/two")
        == "https://1.2.3.4"
    )
    assert normalise_url_domain_or_throw_error("1.2.3.4/one/two") == "http://1.2.3.4"
    assert (
        normalise_url_domain_or_throw_error("https://api.example.com/one/two/")
        == "https://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("http://api.example.com/one/two?hello=1")
        == "http://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("http://api.example.com/one/two#random2")
        == "http://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("api.example.com/one/two")
        == "https://api.example.com"
    )
    assert (
        normalise_url_domain_or_throw_error(".example.com/one/two")
        == "https://example.com"
    )
    assert (
        normalise_url_domain_or_throw_error("localhost:4000") == "http://localhost:4000"
    )
    assert (
        normalise_url_domain_or_throw_error("127.0.0.1:4000") == "http://127.0.0.1:4000"
    )
    assert normalise_url_domain_or_throw_error("127.0.0.1") == "http://127.0.0.1"
    assert (
        normalise_url_domain_or_throw_error("https://127.0.0.1:80/")
        == "https://127.0.0.1:80"
    )

    try:
        normalise_url_domain_or_throw_error("/one/two")
    except Exception as e:
        assert str(e) == "Please provide a valid domain name"

    try:
        normalise_url_domain_or_throw_error("/.netlify/functions/api")
    except Exception as e:
        assert str(e) == "Please provide a valid domain name"


@mark.asyncio
async def test_same_site_values():
    start_st()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[session.init(cookie_same_site="lax")],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "lax"

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[session.init(cookie_same_site="none")],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "none"

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[session.init(cookie_same_site="strict")],
    )

    assert (
        SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "strict"
    )

    reset()

    test_passed = True
    try:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="api.supertokens.io",
                website_domain="supertokens.io",
            ),
            framework="fastapi",
            recipe_list=[session.init(cookie_same_site="random")],  # type: ignore
        )
        test_passed = False
    except Exception as e:
        assert str(e) == 'cookie same site must be one of "strict", "lax", or "none"'

    assert test_passed
    reset()

    test_passed = True
    try:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="api.supertokens.io",
                website_domain="supertokens.io",
            ),
            framework="fastapi",
            recipe_list=[session.init(cookie_same_site=" ")],  # type: ignore
        )
        test_passed = False
    except Exception as e:
        assert str(e) == 'cookie same site must be one of "strict", "lax", or "none"'

    assert test_passed
    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="api.supertokens.io",
            website_domain="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "lax"

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://platform-services-uat.com",
            website_domain="https://platform-ui-uat.com",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "none"

    reset()


@mark.asyncio
async def test_config_values():
    start_st()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="api.supertokens.io",
            website_domain="supertokens.io",
            api_base_path="/",
        ),
        framework="fastapi",
        recipe_list=[session.init(anti_csrf="VIA_CUSTOM_HEADER")],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "lax"
    assert (
        SessionRecipe.get_instance().config.anti_csrf_function_or_string
        == "VIA_CUSTOM_HEADER"
    )
    assert SessionRecipe.get_instance().config.cookie_secure

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://api.supertokens.io",
            website_domain="supertokens.io",
            api_base_path="test/",
            website_base_path="test1/",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "lax"
    anti_csrf = SessionRecipe.get_instance().config.anti_csrf_function_or_string
    assert not isinstance(anti_csrf, str) and anti_csrf(None, {}) == "NONE"
    assert SessionRecipe.get_instance().config.cookie_secure

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="api.supertokens.com",
            website_domain="supertokens.io",
            api_base_path="test/",
            website_base_path="test1/",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "none"
    anti_csrf = SessionRecipe.get_instance().config.anti_csrf_function_or_string
    assert not isinstance(anti_csrf, str) and anti_csrf(None, {}) == "VIA_CUSTOM_HEADER"
    assert SessionRecipe.get_instance().config.cookie_secure

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="api.supertokens.co.uk",
            website_domain="supertokens.co.uk",
            api_base_path="test/",
            website_base_path="test1/",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "lax"
    anti_csrf = SessionRecipe.get_instance().config.anti_csrf_function_or_string
    assert not isinstance(anti_csrf, str) and anti_csrf(None, {}) == "NONE"
    assert SessionRecipe.get_instance().config.cookie_secure

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="127.0.0.1:3000",
            website_domain="127.0.0.1:9000",
            api_base_path="test/",
            website_base_path="test1/",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "lax"
    anti_csrf = SessionRecipe.get_instance().config.anti_csrf_function_or_string
    assert not isinstance(anti_csrf, str) and anti_csrf(None, {}) == "NONE"
    assert not SessionRecipe.get_instance().config.cookie_secure

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="127.0.0.1:3000",
            website_domain="127.0.0.1:9000",
            api_base_path="test/",
            website_base_path="test1/",
        ),
        framework="fastapi",
        recipe_list=[session.init(anti_csrf="VIA_CUSTOM_HEADER")],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "lax"
    assert (
        SessionRecipe.get_instance().config.anti_csrf_function_or_string
        == "VIA_CUSTOM_HEADER"
    )
    assert not SessionRecipe.get_instance().config.cookie_secure

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="api.supertokens.io",
            website_domain="127.0.0.1:9000",
            api_base_path="test/",
            website_base_path="test1/",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "none"
    anti_csrf = SessionRecipe.get_instance().config.anti_csrf_function_or_string
    assert not isinstance(anti_csrf, str) and anti_csrf(None, {}) == "VIA_CUSTOM_HEADER"
    assert SessionRecipe.get_instance().config.cookie_secure

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="127.0.0.1:3000",
            website_domain="127.0.0.1:9000",
            api_base_path="test/",
            website_base_path="test1/",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "lax"
    anti_csrf = SessionRecipe.get_instance().config.anti_csrf_function_or_string
    assert not isinstance(anti_csrf, str) and anti_csrf(None, {}) == "NONE"
    assert not SessionRecipe.get_instance().config.cookie_secure

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://localhost",
            website_domain="http://localhost:3000",
            api_base_path="test/",
            website_base_path="test1/",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "none"
    assert SessionRecipe.get_instance().config.cookie_secure

    reset()


def testing_override_test():
    m = None

    class OI:
        def __init__(self):
            pass

        def some_other_func(self):  # pylint: disable=no-self-use
            nonlocal m
            m = 1

        def some_func(self):
            self.some_other_func()

    class A(OI):
        def some_other_func(self):
            nonlocal m
            m = 2

    b = A()

    def some_other_func():
        nonlocal m
        m = 4

    b.some_other_func = some_other_func

    b.some_func()

    assert m == 4


def testing_super_recipe_tests():
    m = 0

    class EP:
        def __init__(self):
            pass

        def sign_up(self):
            self.get_user()

        def get_user(self):  # pylint: disable=no-self-use
            nonlocal m
            m = 1

    class TPEP:
        def __init__(self):
            ep = EP()
            self.o_sign_up = ep.sign_up
            self.o_get_user = ep.get_user
            dep = DerivedEP(self)
            ep.sign_up = dep.sign_up
            ep.get_user = dep.get_user

        def sign_up(self):
            self.o_sign_up()

        def get_users(self):
            self.o_get_user()

    class DerivedEP(EP):
        def __init__(self, tpep: TPEP):
            super().__init__()
            self.tpep = tpep

        def sign_up(self):
            self.tpep.sign_up()

        def get_user(self):
            self.tpep.get_users()

    def override(tpep: TPEP):
        o_sign_up = tpep.sign_up
        o_get_users = tpep.get_users

        def sign_up():
            o_sign_up()

        def get_users():
            nonlocal m
            m = 5
            o_get_users()
            if m == 1:  # type: ignore
                m = 2

        tpep.sign_up = sign_up
        tpep.get_users = get_users
        return tpep

    base_tpep = TPEP()

    override_tpep = override(base_tpep)

    override_tpep.sign_up()
    assert m == 2

    m = 1
    ep = DerivedEP(override_tpep)

    ep.get_user()

    assert m == 2


@mark.asyncio
async def test_samesite_valid_config():
    domain_combinations = [
        ["http://localhost:3000", "http://localhost:8000"],
        ["http://127.0.0.1:3000", "http://localhost:8000"],
        ["http://localhost:3000", "http://127.0.0.1:8000"],
        ["http://127.0.0.1:3000", "http://127.0.0.1:8000"],
        ["https://localhost:3000", "https://localhost:8000"],
        ["https://127.0.0.1:3000", "https://localhost:8000"],
        ["https://localhost:3000", "https://127.0.0.1:8000"],
        ["https://127.0.0.1:3000", "https://127.0.0.1:8000"],
        ["https://supertokens.io", "https://api.supertokens.io"],
        ["https://supertokens.io", "https://supertokensapi.io"],
        ["http://localhost:3000", "https://supertokensapi.io"],
        ["http://127.0.0.1:3000", "https://supertokensapi.io"],
    ]
    for (website_domain, api_domain) in domain_combinations:
        reset()
        clean_st()
        setup_st()

        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                website_domain=website_domain,
                api_domain=api_domain,
            ),
            framework="fastapi",
            recipe_list=[session.init(cookie_same_site="none")],
        )


@mark.asyncio
async def test_samesite_invalid_config():
    domain_combinations = [
        ["http://localhost:3000", "http://supertokensapi.io"],
        ["http://127.0.0.1:3000", "http://supertokensapi.io"],
        ["http://supertokens.io", "http://localhost:8000"],
        ["http://supertokens.io", "http://127.0.0.1:8000"],
        ["http://supertokens.io", "http://supertokensapi.io"],
    ]
    for (website_domain, api_domain) in domain_combinations:
        reset()
        clean_st()
        setup_st()
        try:
            init(
                supertokens_config=SupertokensConfig("http://localhost:3567"),
                app_info=InputAppInfo(
                    app_name="SuperTokens Demo",
                    website_domain=website_domain,
                    api_domain=api_domain,
                ),
                framework="fastapi",
                recipe_list=[
                    session.init(
                        cookie_same_site="none",
                        get_token_transfer_method=lambda _, __, ___: "cookie",
                    )
                ],
            )
            await create_new_session("public", MagicMock(), "userId", {}, {})
        except Exception as e:
            assert (
                str(e)
                == "Since your API and website domain are different, for sessions to work, please use https on your apiDomain and don't set cookieSecure to false."
            )
        else:
            assert False, "Exception not raised"


@mark.asyncio
async def test_cookie_samesite_with_ec2_public_url():
    start_st()
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="https://ec2-xx-yyy-zzz-0.compute-1.amazonaws.com:3001",
            website_domain="https://blog.supertokens.com",
            api_base_path="/",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    # domain name isn't provided so browser decides to use the same host
    # which will be ec2-xx-yyy-zzz-0.compute-1.amazonaws.com
    assert SessionRecipe.get_instance().config.cookie_domain is None
    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "none"
    assert SessionRecipe.get_instance().config.cookie_secure is True

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://ec2-xx-yyy-zzz-0.compute-1.amazonaws.com:3001",
            website_domain="http://ec2-aa-bbb-ccc-0.compute-1.amazonaws.com:3000",
            api_base_path="/",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    assert SessionRecipe.get_instance().config.cookie_domain is None
    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "none"
    assert SessionRecipe.get_instance().config.cookie_secure is False

    reset()

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://ec2-xx-yyy-zzz-0.compute-1.amazonaws.com:3001",
            website_domain="http://ec2-xx-yyy-zzz-0.compute-1.amazonaws.com:3000",
            api_base_path="/",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(get_token_transfer_method=lambda _, __, ___: "cookie")
        ],
    )

    assert SessionRecipe.get_instance().config.cookie_domain is None
    assert SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "lax"
    assert SessionRecipe.get_instance().config.cookie_secure is False


@mark.asyncio
async def test_samesite_explicit_config():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            origin="http://localhost:3000",
            api_domain="http://localhost:3001",
        ),
        framework="fastapi",
        recipe_list=[
            session.init(
                cookie_same_site="strict",
            )
        ],
    )
    assert (
        SessionRecipe.get_instance().config.get_cookie_same_site(None, {}) == "strict"
    )


@mark.asyncio
async def test_that_exception_is_thrown_if_website_domain_and_origin_are_not_passed():
    try:
        init(
            supertokens_config=SupertokensConfig("http://localhost:3567"),
            app_info=InputAppInfo(
                app_name="SuperTokens Demo",
                api_domain="http://localhost:3001",
            ),
            framework="fastapi",
            recipe_list=[session.init()],
        )
    except Exception as e:
        assert str(e) == "Please provide at least one of website_domain or origin"
    else:
        assert False, "Exception not thrown"


@mark.asyncio
async def test_that_init_works_fine_when_using_origin_string():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://localhost:3001",
            origin="localhost:3000",
        ),
        framework="fastapi",
        recipe_list=[session.init()],
    )

    assert (
        Supertokens.get_instance()
        .app_info.get_origin(None, {})
        .get_as_string_dangerous()
        == "http://localhost:3000"
    )


@mark.asyncio
async def test_that_init_works_fine_when_using_website_domain_string():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://localhost:3001",
            website_domain="localhost:3000",
        ),
        framework="fastapi",
        recipe_list=[session.init()],
    )

    assert (
        Supertokens.get_instance()
        .app_info.get_origin(None, {})
        .get_as_string_dangerous()
        == "http://localhost:3000"
    )


@mark.asyncio
async def test_that_init_works_fine_when_using_origin_function():
    def get_origin(_: Optional[BaseRequest], user_context: Dict[str, Any]) -> str:
        if "input" in user_context:
            return user_context["input"]
        return "localhost:3000"

    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://localhost:3001",
            origin=get_origin,
        ),
        framework="fastapi",
        recipe_list=[session.init()],
    )

    assert (
        Supertokens.get_instance()
        .app_info.get_origin(None, {"input": "localhost:1000"})
        .get_as_string_dangerous()
        == "http://localhost:1000"
    )

    assert (
        Supertokens.get_instance()
        .app_info.get_origin(None, {})
        .get_as_string_dangerous()
        == "http://localhost:3000"
    )


@mark.asyncio
async def test_that_init_chooses_origin_over_website_domain():
    init(
        supertokens_config=SupertokensConfig("http://localhost:3567"),
        app_info=InputAppInfo(
            app_name="SuperTokens Demo",
            api_domain="http://localhost:3001",
            website_domain="localhost:3000",
            origin="supertokens.io",
        ),
        framework="fastapi",
        recipe_list=[session.init()],
    )

    assert (
        Supertokens.get_instance()
        .app_info.get_origin(None, {})
        .get_as_string_dangerous()
        == "https://supertokens.io"
    )
