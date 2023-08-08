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

from __future__ import annotations

from typing import Any, Dict

from supertokens_python.ingredients.emaildelivery import EmailDeliveryInterface
from supertokens_python.recipe.passwordless.emaildelivery.services.backward_compatibility import (
    BackwardCompatibilityService as PlessBackwardCompatibilityService,
)
from supertokens_python.recipe.thirdpartypasswordless.types import EmailTemplateVars
from supertokens_python.supertokens import AppInfo


class BackwardCompatibilityService(EmailDeliveryInterface[EmailTemplateVars]):
    pless_backward_compatiblity_service: PlessBackwardCompatibilityService

    def __init__(
        self,
        app_info: AppInfo,
    ) -> None:
        self.pless_backward_compatiblity_service = PlessBackwardCompatibilityService(
            app_info
        )

    async def send_email(
        self,
        template_vars: EmailTemplateVars,
        user_context: Dict[str, Any],
    ) -> None:
        await self.pless_backward_compatiblity_service.send_email(
            template_vars, user_context
        )
