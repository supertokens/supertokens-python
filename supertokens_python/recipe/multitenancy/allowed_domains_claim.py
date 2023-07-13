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
from typing import Any, Callable, Dict, List, Optional, Union
from supertokens_python.recipe.session.claim_base_classes.primitive_array_claim import (
    PrimitiveArrayClaim,
)
from supertokens_python.recipe.session.interfaces import JSONObject
from supertokens_python.utils import get_timestamp_ms

from supertokens_python.recipe.multitenancy.recipe import MultitenancyRecipe


class AllowedDomainsClaimClass(PrimitiveArrayClaim[List[str]]):
    def __init__(self):
        default_max_age_in_sec = 60 * 60 * 24 * 7

        async def fetch_value(
            _: str, tenant_id: str, user_context: Dict[str, Any]
        ) -> Optional[List[str]]:
            recipe = MultitenancyRecipe.get_instance()

            if recipe.get_allowed_domains_for_tenant_id is None:
                # User did not provide a function to get allowed domains, but is using a validator. So we don't allow any domains by default
                return None

            return await recipe.get_allowed_domains_for_tenant_id(
                tenant_id, user_context
            )

        super().__init__("st-t-dmns", fetch_value, default_max_age_in_sec)

    def get_value_from_payload(
        self, payload: JSONObject, user_context: Optional[Dict[str, Any]] = None
    ) -> Optional[List[str]]:
        _ = user_context

        res = payload.get(self.key, {}).get("v")
        if res is None:
            return []
        return res

    def get_last_refetch_time(
        self, payload: JSONObject, user_context: Optional[Dict[str, Any]] = None
    ) -> Optional[int]:
        _ = user_context

        res = payload.get(self.key, {}).get("t")
        if res is None:
            return get_timestamp_ms()

        return res


AllowedDomainsClaim = AllowedDomainsClaimClass()
