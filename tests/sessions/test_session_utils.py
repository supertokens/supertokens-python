# Copyright (c) 2024, VRAI Labs and/or its affiliates. All rights reserved.
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

from supertokens_python.recipe.session.utils import normalise_session_scope


class TestNormaliseSessionScope:
    def test_empty_string(self):  # pylint: disable=no-self-use
        try:
            normalise_session_scope("")
            assert False
        except Exception as e:
            assert str(e) == "Please provide a valid session_scope"

    def test_with_leading_dot(self):  # pylint: disable=no-self-use
        result = normalise_session_scope(".example.com")
        assert result == ".example.com"

    def test_without_leading_dot(self):  # pylint: disable=no-self-use
        result = normalise_session_scope("example.com")
        assert result == "example.com"

    def test_with_http_prefix(self):  # pylint: disable=no-self-use
        result = normalise_session_scope("http://example.com")
        assert result == "example.com"

    def test_with_https_prefix(self):  # pylint: disable=no-self-use
        result = normalise_session_scope("https://example.com")
        assert result == "example.com"

    def test_with_ip_address(self):  # pylint: disable=no-self-use
        result = normalise_session_scope("192.168.1.1")
        assert result == "192.168.1.1"

    def test_with_localhost(self):  # pylint: disable=no-self-use
        result = normalise_session_scope("localhost")
        assert result == "localhost"

    def test_with_leading_trailing_whitespace(self):  # pylint: disable=no-self-use
        result = normalise_session_scope("  example.com  ")
        assert result == "example.com"

    def test_with_subdomain(self):  # pylint: disable=no-self-use
        assert normalise_session_scope("sub.example.com") == "sub.example.com"
        assert normalise_session_scope("http://sub.example.com") == "sub.example.com"
        assert normalise_session_scope("https://sub.example.com") == "sub.example.com"
        assert normalise_session_scope(".sub.example.com") == ".sub.example.com"
        assert normalise_session_scope("a.sub.example.com") == "a.sub.example.com"
        assert (
            normalise_session_scope("http://a.sub.example.com") == "a.sub.example.com"
        )
        assert (
            normalise_session_scope("https://a.sub.example.com") == "a.sub.example.com"
        )
        assert normalise_session_scope(".a.sub.example.com") == ".a.sub.example.com"
