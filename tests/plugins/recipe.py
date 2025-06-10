from typing import (
    List,
    Optional,
)

from supertokens_python.exceptions import SuperTokensError, raise_general_exception
from supertokens_python.framework.request import BaseRequest
from supertokens_python.framework.response import BaseResponse
from supertokens_python.normalised_url_path import NormalisedURLPath
from supertokens_python.plugins import OverrideMap, apply_plugins
from supertokens_python.querier import Querier
from supertokens_python.recipe_module import APIHandled, RecipeModule
from supertokens_python.supertokens import (
    AppInfo,
)
from supertokens_python.types.base import UserContext

from .api_implementation import APIImplementation
from .config import (
    NormalizedPluginTestConfig,
    PluginTestConfig,
    validate_and_normalise_user_input,
)
from .recipe_implementation import RecipeImplementation


class PluginTestRecipe(RecipeModule):
    __instance: Optional["PluginTestRecipe"] = None
    recipe_id = "plugin_test"

    config: NormalizedPluginTestConfig
    recipe_implementation: RecipeImplementation
    api_implementation: APIImplementation

    def __init__(
        self, recipe_id: str, app_info: AppInfo, config: Optional[PluginTestConfig]
    ):
        super().__init__(recipe_id=recipe_id, app_info=app_info)
        self.config = validate_and_normalise_user_input(
            app_info=app_info, config=config
        )

        querier = Querier.get_instance(rid_to_core=recipe_id)
        recipe_implementation = RecipeImplementation(
            querier=querier,
            config=self.config,
        )
        self.recipe_implementation = (
            recipe_implementation
            if self.config.override.functions is None
            else self.config.override.functions(recipe_implementation)
        )  # type: ignore

        api_implementation = APIImplementation()
        self.api_implementation = (
            api_implementation
            if self.config.override.apis is None
            else self.config.override.apis(api_implementation)
        )  # type: ignore

    @staticmethod
    def get_instance() -> "PluginTestRecipe":
        if PluginTestRecipe.__instance is not None:
            return PluginTestRecipe.__instance
        raise_general_exception(
            "Initialisation not done. Did you forget to call the SuperTokens.init function?"
        )

    @staticmethod
    def get_instance_optional() -> Optional["PluginTestRecipe"]:
        return PluginTestRecipe.__instance

    @staticmethod
    def init(config: Optional[PluginTestConfig]):
        def func(app_info: AppInfo, plugins: List[OverrideMap]):
            if PluginTestRecipe.__instance is None:
                PluginTestRecipe.__instance = PluginTestRecipe(
                    recipe_id=PluginTestRecipe.recipe_id,
                    app_info=app_info,
                    config=apply_plugins(
                        recipe_id=PluginTestRecipe.recipe_id,
                        config=config,
                        plugins=plugins,
                    ),
                )
                return PluginTestRecipe.__instance
            else:
                raise_general_exception(
                    "PluginTestRecipe has already been initialised. Please check your code for bugs."
                )

        return func

    @staticmethod
    def reset():
        PluginTestRecipe.__instance = None

    def get_all_cors_headers(self) -> List[str]:
        return []

    async def handle_error(
        self,
        request: BaseRequest,
        err: SuperTokensError,
        response: BaseResponse,
        user_context: UserContext,
    ):
        raise err

    async def handle_api_request(
        self,
        request_id: str,
        tenant_id: str,
        request: BaseRequest,
        path: NormalisedURLPath,
        method: str,
        response: BaseResponse,
        user_context: UserContext,
    ):
        return None

    def get_apis_handled(self) -> List[APIHandled]:
        return []

    def is_error_from_this_recipe_based_on_instance(self, err: Exception) -> bool:
        return False


def plugin_test_init(config: Optional[PluginTestConfig] = None):
    return PluginTestRecipe.init(config=config)
