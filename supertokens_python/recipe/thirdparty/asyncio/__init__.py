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

from typing import Any, Dict, Optional, Union

from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.thirdparty.interfaces import (
    EmailChangeNotAllowedError,
    ManuallyCreateOrUpdateUserOkResult,
    SignInUpNotAllowed,
)
from supertokens_python.recipe.thirdparty.recipe import ThirdPartyRecipe
from supertokens_python.types.auth_utils import LinkingToSessionUserFailedError


async def manually_create_or_update_user(
    tenant_id: str,
    third_party_id: str,
    third_party_user_id: str,
    email: str,
    is_verified: bool,
    session: Optional[SessionContainer] = None,
    user_context: Union[None, Dict[str, Any]] = None,
) -> Union[
    ManuallyCreateOrUpdateUserOkResult,
    LinkingToSessionUserFailedError,
    SignInUpNotAllowed,
    EmailChangeNotAllowedError,
]:
    if user_context is None:
        user_context = {}
    return await ThirdPartyRecipe.get_instance().recipe_implementation.manually_create_or_update_user(
        third_party_id=third_party_id,
        third_party_user_id=third_party_user_id,
        email=email,
        is_verified=is_verified,
        session=session,
        tenant_id=tenant_id,
        user_context=user_context,
        should_try_linking_with_session_user=session is not None,
    )


async def get_provider(
    tenant_id: str,
    third_party_id: str,
    client_type: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    if user_context is None:
        user_context = {}
    return await ThirdPartyRecipe.get_instance().recipe_implementation.get_provider(
        third_party_id, client_type, tenant_id, user_context
    )
