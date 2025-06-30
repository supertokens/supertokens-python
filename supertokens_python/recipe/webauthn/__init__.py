# Copyright (c) 2025, VRAI Labs and/or its affiliates. All rights reserved.
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

from typing import Optional

from supertokens_python.recipe.webauthn.functions import (
    consume_recover_account_token,
    create_recover_account_link,
    generate_recover_account_token,
    get_credential,
    get_generated_options,
    get_user_from_recover_account_token,
    list_credentials,
    recover_account,
    register_credential,
    register_options,
    remove_credential,
    remove_generated_options,
    send_email,
    send_recover_account_email,
    sign_in,
    sign_in_options,
    sign_up,
    verify_credentials,
)
from supertokens_python.recipe.webauthn.interfaces.api import APIInterface, APIOptions
from supertokens_python.recipe.webauthn.interfaces.recipe import RecipeInterface
from supertokens_python.recipe.webauthn.recipe import WebauthnRecipe
from supertokens_python.recipe.webauthn.types.config import (
    NormalisedWebauthnConfig,
    OverrideConfig,
    WebauthnConfig,
)

# Some Pydantic models need a rebuild to resolve ForwardRefs
# Referencing imports here to prevent lint errors.
# Caveat: These will be available for import from this module directly.
APIInterface  # type: ignore
RecipeInterface  # type: ignore
NormalisedWebauthnConfig  # type: ignore


# APIOptions - ApiInterface -> WebauthnConfig/NormalisedWebauthnConfig -> RecipeInterface
APIOptions.model_rebuild()


def init(config: Optional[WebauthnConfig] = None):
    return WebauthnRecipe.init(config=config)


__all__ = [
    "init",
    "APIInterface",
    "RecipeInterface",
    "OverrideConfig",
    "WebauthnConfig",
    "WebauthnRecipe",
    "consume_recover_account_token",
    "create_recover_account_link",
    "generate_recover_account_token",
    "get_credential",
    "get_generated_options",
    "get_user_from_recover_account_token",
    "list_credentials",
    "recover_account",
    "register_credential",
    "register_options",
    "remove_credential",
    "remove_generated_options",
    "send_email",
    "send_recover_account_email",
    "sign_in",
    "sign_in_options",
    "sign_up",
    "verify_credentials",
]
