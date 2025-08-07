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
from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, List, Optional, Union

from typing_extensions import Literal

from supertokens_python.recipe.multitenancy.interfaces import TenantConfig
from supertokens_python.types import RecipeUserId, User
from supertokens_python.types.config import (
    BaseConfig,
    BaseNormalisedConfig,
    BaseNormalisedOverrideConfig,
    BaseOverrideConfig,
)

from .interfaces import APIInterface, RecipeInterface

MFARequirementList = List[
    Union[str, Dict[Union[Literal["oneOf"], Literal["allOfInAnyOrder"]], List[str]]]
]


class MFAClaimValue:
    c: Dict[str, int]
    v: bool

    def __init__(self, c: Dict[str, Any], v: bool):
        self.c = c
        self.v = v


MultiFactorAuthOverrideConfig = BaseOverrideConfig[RecipeInterface, APIInterface]
NormalisedMultiFactorAuthOverrideConfig = BaseNormalisedOverrideConfig[
    RecipeInterface, APIInterface
]
OverrideConfig = MultiFactorAuthOverrideConfig
"""Deprecated, use `MultiFactorAuthOverrideConfig` instead."""


class MultiFactorAuthConfig(BaseConfig[RecipeInterface, APIInterface]):
    first_factors: Optional[List[str]] = None


class NormalisedMultiFactorAuthConfig(
    BaseNormalisedConfig[RecipeInterface, APIInterface]
):
    first_factors: Optional[List[str]]


class FactorIds:
    EMAILPASSWORD = "emailpassword"
    OTP_EMAIL = "otp-email"
    OTP_PHONE = "otp-phone"
    LINK_EMAIL = "link-email"
    LINK_PHONE = "link-phone"
    THIRDPARTY = "thirdparty"
    TOTP = "totp"
    WEBAUTHN = "webauthn"

    @staticmethod
    def get_all_factors():
        return [
            FactorIds.EMAILPASSWORD,
            FactorIds.OTP_EMAIL,
            FactorIds.OTP_PHONE,
            FactorIds.LINK_EMAIL,
            FactorIds.LINK_PHONE,
            FactorIds.THIRDPARTY,
            FactorIds.TOTP,
            FactorIds.WEBAUTHN,
        ]


class FactorIdsAndType:
    def __init__(
        self,
        factor_ids: List[str],
        type_: Union[Literal["string"], Literal["oneOf"], Literal["allOfInAnyOrder"]],
    ):
        self.factor_ids = factor_ids
        self.type_ = type_


class GetFactorsSetupForUserFromOtherRecipesFunc:
    def __init__(
        self,
        func: Callable[[User, Dict[str, Any]], Awaitable[List[str]]],
    ):
        self.func = func


class GetAllAvailableSecondaryFactorIdsFromOtherRecipesFunc:
    def __init__(
        self,
        func: Callable[[TenantConfig], Awaitable[List[str]]],
    ):
        self.func = func


class GetEmailsForFactorOkResult:
    status: Literal["OK"] = "OK"

    def __init__(self, factor_id_to_emails_map: Dict[str, List[str]]):
        self.factor_id_to_emails_map = factor_id_to_emails_map


class GetEmailsForFactorUnknownSessionRecipeUserIdResult:
    status: Literal["UNKNOWN_SESSION_RECIPE_USER_ID"] = "UNKNOWN_SESSION_RECIPE_USER_ID"


class GetEmailsForFactorFromOtherRecipesFunc:
    def __init__(
        self,
        func: Callable[
            [User, RecipeUserId],
            Awaitable[
                Union[
                    GetEmailsForFactorOkResult,
                    GetEmailsForFactorUnknownSessionRecipeUserIdResult,
                ]
            ],
        ],
    ):
        self.func = func


class GetPhoneNumbersForFactorsOkResult:
    status: Literal["OK"] = "OK"

    def __init__(self, factor_id_to_phone_number_map: Dict[str, List[str]]):
        self.factor_id_to_phone_number_map = factor_id_to_phone_number_map


class GetPhoneNumbersForFactorsUnknownSessionRecipeUserIdResult:
    status: Literal["UNKNOWN_SESSION_RECIPE_USER_ID"] = "UNKNOWN_SESSION_RECIPE_USER_ID"


class GetPhoneNumbersForFactorsFromOtherRecipesFunc:
    def __init__(
        self,
        func: Callable[
            [User, RecipeUserId],
            Awaitable[
                Union[
                    GetPhoneNumbersForFactorsOkResult,
                    GetPhoneNumbersForFactorsUnknownSessionRecipeUserIdResult,
                ]
            ],
        ],
    ):
        self.func = func
