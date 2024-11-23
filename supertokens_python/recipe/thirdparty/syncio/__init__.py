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

from supertokens_python.async_to_sync.base import sync


def manually_create_or_update_user(
    tenant_id: str,
    third_party_id: str,
    third_party_user_id: str,
    email: str,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from supertokens_python.recipe.thirdparty.asyncio import (
        manually_create_or_update_user,
    )

    return sync(
        manually_create_or_update_user(
            tenant_id, third_party_id, third_party_user_id, email, user_context
        )
    )


def get_provider(
    tenant_id: str,
    third_party_id: str,
    client_type: Optional[str] = None,
    user_context: Union[None, Dict[str, Any]] = None,
):
    from supertokens_python.recipe.thirdparty.asyncio import get_provider

    return sync(get_provider(tenant_id, third_party_id, client_type, user_context))
