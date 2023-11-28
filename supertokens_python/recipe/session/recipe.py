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

from os import environ
from typing import TYPE_CHECKING, Any, Dict, List, Union, Callable, Optional

from supertokens_python.framework.response import BaseResponse
from typing_extensions import Literal

from .cookie_and_header import (
    get_cors_allowed_headers,
)
from .exceptions import (
    SuperTokensSessionError,
    TokenTheftError,
    UnauthorisedError,
    InvalidClaimsError,
)
from ...types import MaybeAwaitable

if TYPE_CHECKING:
    from supertokens_python.framework import BaseRequest
    from supertokens_python.supertokens import AppInfo

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.logger import log_debug_message
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.querier import Querier
from supertokens_python.recipe.openid.recipe import OpenIdRecipe
from supertokens_python.recipe_module import APIHandled, RecipeModule

from .constants import SESSION_REFRESH, SIGNOUT
from .interfaces import (
    APIInterface,
    APIOptions,
    RecipeInterface,
    SessionClaim,
    SessionClaimValidator,
    SessionContainer,
)
from .recipe_implementation import (
    RecipeImplementation,
)
from .api import handle_refresh_api, handle_signout_api
from .utils import (
    InputErrorHandlers,
    InputOverrideConfig,
    TokenTransferMethod,
    validate_and_normalise_user_input,
)
from .cookie_and_header import clear_session_from_all_token_transfer_methods


class SessionRecipe(RecipeModule):
    recipe_id = "session"
    __instance = None

    def __init__(
        self,
        recipe_id: str,
        app_info: AppInfo,
        cookie_domain: Union[str, None] = None,
        cookie_secure: Union[bool, None] = None,
        cookie_same_site: Union[Literal["lax", "none", "strict"], None] = None,
        session_expired_status_code: Union[int, None] = None,
        anti_csrf: Union[
            Literal["VIA_TOKEN", "VIA_CUSTOM_HEADER", "NONE"], None
        ] = None,
        get_token_transfer_method: Union[
            Callable[
                [BaseRequest, bool, Dict[str, Any]],
                Union[TokenTransferMethod, Literal["any"]],
            ],
            None,
        ] = None,
        error_handlers: Union[InputErrorHandlers, None] = None,
        override: Union[InputOverrideConfig, None] = None,
        invalid_claim_status_code: Union[int, None] = None,
        use_dynamic_access_token_signing_key: Union[bool, None] = None,
        expose_access_token_to_frontend_in_cookie_based_auth: Union[bool, None] = None,
    ):
        super().__init__(recipe_id, app_info)
        self.config = validate_and_normalise_user_input(
            app_info,
            cookie_domain,
            cookie_secure,
            cookie_same_site,
            session_expired_status_code,
            anti_csrf,
            get_token_transfer_method,
            error_handlers,
            override,
            invalid_claim_status_code,
            use_dynamic_access_token_signing_key,
            expose_access_token_to_frontend_in_cookie_based_auth,
        )
        self.openid_recipe = OpenIdRecipe(
            recipe_id,
            app_info,
            None,
            None,
            override.openid_feature if override is not None else None,
        )
        log_debug_message(
            "session init: anti_csrf: %s", self.config.anti_csrf_function_or_string
        )
        if self.config.cookie_domain is not None:
            log_debug_message(
                "session init: cookie_domain: %s", self.config.cookie_domain
            )
        else:
            log_debug_message("session init: cookie_domain: None")

        # we check the input cookie_same_site because the normalised version is
        # always a function.
        if cookie_same_site is not None:
            log_debug_message("session init: cookie_same_site: %s", cookie_same_site)
        else:
            log_debug_message("session init: cookie_same_site: function")

        log_debug_message(
            "session init: cookie_secure: %s", str(self.config.cookie_secure)
        )
        log_debug_message(
            "session init: refresh_token_path: %s ",
            self.config.refresh_token_path.get_as_string_dangerous(),
        )
        log_debug_message(
            "session init: session_expired_status_code: %s",
            str(self.config.session_expired_status_code),
        )
        recipe_implementation = RecipeImplementation(
            Querier.get_instance(recipe_id), self.config, self.app_info
        )
        self.recipe_implementation: RecipeInterface = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )

        from .api.implementation import APIImplementation

        api_implementation = APIImplementation()
        self.api_implementation: APIInterface = (
            api_implementation
            if self.config.override.apis is None
            else self.config.override.apis(api_implementation)
        )

        self.claims_added_by_other_recipes: List[SessionClaim[Any]] = []
        self.claim_validators_added_by_other_recipes: List[SessionClaimValidator] = []

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return isinstance(err, SuperTokensError) and (
            isinstance(err, SuperTokensSessionError)
            or self.openid_recipe.is_error_from_this_recipe_based_on_instance(err)
        )

    def get_apis_handled(self) -> List[APIHandled]:
        apis_handled = [
            APIHandled(
                NormalisedURLPath(SESSION_REFRESH),
                "post",
                SESSION_REFRESH,
                self.api_implementation.disable_refresh_post,
            ),
            APIHandled(
                NormalisedURLPath(SIGNOUT),
                "post",
                SIGNOUT,
                self.api_implementation.disable_signout_post,
            ),
        ]
        apis_handled.extend(self.openid_recipe.get_apis_handled())

        return apis_handled

    async def handle_api_request(
        self,
        request_id: str,
        tenant_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> Union[BaseResponse, None]:
        if request_id == SESSION_REFRESH:
            return await handle_refresh_api(
                self.api_implementation,
                APIOptions(
                    request,
                    response,
                    self.recipe_id,
                    self.config,
                    self.recipe_implementation,
                ),
                user_context,
            )
        if request_id == SIGNOUT:
            return await handle_signout_api(
                self.api_implementation,
                APIOptions(
                    request,
                    response,
                    self.recipe_id,
                    self.config,
                    self.recipe_implementation,
                ),
                user_context,
            )
        return await self.openid_recipe.handle_api_request(
            request_id, tenant_id, request, path, method, response, user_context
        )

    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: Dict[str, Any],
    ) -> BaseResponse:
        if (
            isinstance(err, SuperTokensSessionError)
            and err.response_mutators is not None
        ):
            for mutator in err.response_mutators:
                mutator(response, user_context)

        if isinstance(err, UnauthorisedError):
            log_debug_message("errorHandler: returning UNAUTHORISED")
            if err.clear_tokens:
                log_debug_message("Clearing tokens because of UNAUTHORISED response")
                clear_session_from_all_token_transfer_methods(
                    response, self, request, user_context
                )
            return await self.config.error_handlers.on_unauthorised(
                request, str(err), response
            )
        if isinstance(err, TokenTheftError):
            log_debug_message("errorHandler: returning TOKEN_THEFT_DETECTED")
            log_debug_message(
                "Clearing tokens because of TOKEN_THEFT_DETECTED response"
            )
            clear_session_from_all_token_transfer_methods(
                response, self, request, user_context
            )
            return await self.config.error_handlers.on_token_theft_detected(
                request, err.session_handle, err.user_id, response
            )
        if isinstance(err, InvalidClaimsError):
            log_debug_message("errorHandler: returning INVALID_CLAIMS")
            return await self.config.error_handlers.on_invalid_claim(
                self, request, err.payload, response
            )

        log_debug_message("errorHandler: returning TRY_REFRESH_TOKEN")
        return await self.config.error_handlers.on_try_refresh_token(
            request, str(err), response
        )

    def get_all_cors_headers(self) -> List[str]:
        cors_headers = get_cors_allowed_headers()
        cors_headers.extend(self.openid_recipe.get_all_cors_headers())

        return cors_headers

    @staticmethod
    def init(
        cookie_domain: Union[str, None] = None,
        cookie_secure: Union[bool, None] = None,
        cookie_same_site: Union[Literal["lax", "none", "strict"], None] = None,
        session_expired_status_code: Union[int, None] = None,
        anti_csrf: Union[
            Literal["VIA_TOKEN", "VIA_CUSTOM_HEADER", "NONE"], None
        ] = None,
        get_token_transfer_method: Union[
            Callable[
                [BaseRequest, bool, Dict[str, Any]],
                Union[TokenTransferMethod, Literal["any"]],
            ],
            None,
        ] = None,
        error_handlers: Union[InputErrorHandlers, None] = None,
        override: Union[InputOverrideConfig, None] = None,
        invalid_claim_status_code: Union[int, None] = None,
        use_dynamic_access_token_signing_key: Union[bool, None] = None,
        expose_access_token_to_frontend_in_cookie_based_auth: Union[bool, None] = None,
    ):
        def func(app_info: AppInfo):
            if SessionRecipe.__instance is None:
                SessionRecipe.__instance = SessionRecipe(
                    SessionRecipe.recipe_id,
                    app_info,
                    cookie_domain,
                    cookie_secure,
                    cookie_same_site,
                    session_expired_status_code,
                    anti_csrf,
                    get_token_transfer_method,
                    error_handlers,
                    override,
                    invalid_claim_status_code,
                    use_dynamic_access_token_signing_key,
                    expose_access_token_to_frontend_in_cookie_based_auth,
                )
                return SessionRecipe.__instance
            raise_general_exception(
                "Session recipe has already been initialised. Please check your code for bugs."
            )

        return func

    @staticmethod
    def get_instance() -> SessionRecipe:
        if SessionRecipe.__instance is not None:
            return SessionRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def reset():
        if ("SUPERTOKENS_ENV" not in environ) or (
            environ["SUPERTOKENS_ENV"] != "testing"
        ):
            raise_general_exception("calling testing function in non testing env")
        SessionRecipe.__instance = None

    def add_claim_from_other_recipe(self, claim: SessionClaim[Any]):
        # We are throwing here (and not in addClaimValidatorFromOtherRecipe) because if multiple
        # claims are added with the same key they will overwrite each other. Validators will all run
        # and work as expected even if they are added multiple times.
        if claim.key in [c.key for c in self.claims_added_by_other_recipes]:
            raise Exception("Claim added by multiple recipes")

        self.claims_added_by_other_recipes.append(claim)

    def get_claims_added_by_other_recipes(self) -> List[SessionClaim[Any]]:
        return self.claims_added_by_other_recipes

    def add_claim_validator_from_other_recipe(
        self, claim_validator: SessionClaimValidator
    ):
        self.claim_validators_added_by_other_recipes.append(claim_validator)

    def get_claim_validators_added_by_other_recipes(
        self,
    ) -> List[SessionClaimValidator]:
        return self.claim_validators_added_by_other_recipes

    async def verify_session(
        self,
        request: BaseRequest,
        anti_csrf_check: Union[bool, None],
        session_required: bool,
        check_database: bool,
        override_global_claim_validators: Optional[
            Callable[
                [List[SessionClaimValidator], SessionContainer, Dict[str, Any]],
                MaybeAwaitable[List[SessionClaimValidator]],
            ]
        ],
        user_context: Dict[str, Any],
    ):
        _ = user_context

        return await self.api_implementation.verify_session(
            APIOptions(
                request,
                None,
                self.recipe_id,
                self.config,
                self.recipe_implementation,
            ),
            anti_csrf_check,
            session_required,
            check_database,
            override_global_claim_validators,
            user_context,
        )
