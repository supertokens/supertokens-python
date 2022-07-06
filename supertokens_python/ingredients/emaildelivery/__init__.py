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

from typing import Generic, TypeVar

from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryConfigWithService,
    EmailDeliveryInterface,
)

_T = TypeVar("_T")


class EmailDeliveryIngredient(Generic[_T]):
    ingredient_interface_impl: EmailDeliveryInterface[_T]

    def __init__(self, config: EmailDeliveryConfigWithService[_T]) -> None:
        self.ingredient_interface_impl = (
            config.service
            if config.override is None
            else config.override(config.service)
        )
