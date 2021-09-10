"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""
from functools import wraps
from typing import Union

from supertokens_python.async_to_sync_wrapper import sync
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.session import SessionRecipe
from supertokens_python.utils import FRAMEWORKS, normalise_http_method


def verify_session(recipe: SessionRecipe, anti_csrf_check: Union[bool, None] = None, session_required: bool = True):
    def session_verify(f):
        @wraps(f)
        def wrapped_function(request, *args, **kwargs):
            if not hasattr(request, 'wrapper_used') or not request.wrapper_used:
                request = FRAMEWORKS[recipe.app_info.framework].wrap_request(request)
            method = normalise_http_method(request.method)
            if method == 'options' or method == 'trace':
                return None
            incoming_path = NormalisedURLPath(recipe, request.url.path)
            refresh_token_path = recipe.config.refresh_token_path
            if incoming_path.equals(refresh_token_path) and method == 'post':
                session = sync(recipe.refresh_session)(request)
            else:
                session = sync(recipe.get_session)(request, anti_csrf_check, session_required)
            request.set_session(session)

        return wrapped_function

    return session_verify
