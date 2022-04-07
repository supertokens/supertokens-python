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

from typing import Any, Dict, Generic, TypeVar

from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfig, EmailDeliveryInterface)

_T = TypeVar('_T')


class DefaultEmailDeliveryIngredientImp(EmailDeliveryInterface[_T]):
    def __init__(self, config: EmailDeliveryConfig[_T]) -> None:
        self.config = config

    async def send_email(self, email_input: _T, user_context: Dict[str, Any]) -> Any:
        await self.config.service.send_email(email_input, user_context)


class EmailDeliveryIngredient(Generic[_T]):
    ingredient_interface_impl: EmailDeliveryInterface[_T]

    def __init__(self, config: EmailDeliveryConfig[_T]) -> None:
        oi = DefaultEmailDeliveryIngredientImp[_T](config)
        self.ingredient_interface_impl = oi if config.override is None else config.override(oi)
