from functools import partial
from typing import Any, Dict, List, Union
from unittest.mock import patch

from pytest import fixture, mark, param, raises
from supertokens_python import (
    InputAppInfo,
    Supertokens,
    SupertokensConfig,
    SupertokensExperimentalConfig,
    init,
)
from supertokens_python.plugins import (
    PluginRouteHandler,
    PluginRouteHandlerFunctionErrorResponse,
    PluginRouteHandlerFunctionOkResponse,
    SuperTokensPlugin,
)
from supertokens_python.post_init_callbacks import PostSTInitCallbacks
from supertokens_python.supertokens import SupertokensPublicConfig

from tests.utils import outputs, reset

from .config import PluginTestConfig, PluginTestOverrideConfig
from .misc import DummyRequest, DummyResponse
from .plugins import (
    Plugin1,
    Plugin2,
    Plugin3Dep1,
    Plugin3Dep2_1,
    Plugin4Dep1,
    Plugin4Dep2,
    Plugin4Dep3__2_1,
    api_override_factory,
    function_override_factory,
    plugin_factory,
)
from .recipe import PluginTestRecipe, plugin_test_init
from .types import RecipeReturnType


@fixture(autouse=True)
def setup_and_teardown():
    reset()
    PluginTestRecipe.reset()
    PostSTInitCallbacks.reset()
    yield
    reset()
    PluginTestRecipe.reset()
    PostSTInitCallbacks.reset()


def recipe_factory(override_functions: bool = False, override_apis: bool = False):
    override = PluginTestOverrideConfig()

    if override_functions:
        override.functions = function_override_factory("override")
    if override_apis:
        override.apis = api_override_factory("override")

    return plugin_test_init(config=PluginTestConfig(override=override))


partial_init = partial(
    init,
    app_info=InputAppInfo(
        app_name="plugin_test",
        api_domain="api.supertokens.io",
        origin="http://localhost:3001",
    ),
    framework="django",
    supertokens_config=SupertokensConfig(
        connection_uri="http://localhost:3567",
    ),
)


@mark.parametrize(
    (
        "recipe_fn_override",
        "recipe_api_override",
        "plugins",
        "recipe_expectation",
        "api_expectation",
    ),
    [
        param(
            False,
            False,
            [],
            outputs(["original"]),
            outputs(["original"]),
            id="fn_ovr=False, api_ovr=False, plugins=[]",
        ),
        param(
            True,
            False,
            [],
            outputs(["override", "original"]),
            outputs(["original"]),
            id="fn_ovr=True, api_ovr=False, plugins=[]",
        ),
        param(
            False,
            True,
            [],
            outputs(["original"]),
            outputs(["override", "original"]),
            id="fn_ovr=False, api_ovr=True, plugins=[]",
        ),
        param(
            True,
            False,
            [plugin_factory("plugin1", override_functions=True)],
            outputs(["override", "plugin1", "original"]),
            outputs(["original"]),
            id="fn_ovr=True, api_ovr=False, plugins=[Plugin1], plugin1=[fn]",
        ),
        param(
            True,
            False,
            [plugin_factory("plugin1", override_apis=True)],
            outputs(["override", "original"]),
            outputs(["plugin1", "original"]),
            id="fn_ovr=True, api_ovr=False, plugins=[Plugin1], plugin1=[api]",
        ),
        param(
            False,
            True,
            [plugin_factory("plugin1", override_functions=True)],
            outputs(["plugin1", "original"]),
            outputs(["override", "original"]),
            id="fn_ovr=False, api_ovr=True, plugins=[Plugin1], plugin1=[fn]",
        ),
        param(
            False,
            True,
            [plugin_factory("plugin1", override_apis=True)],
            outputs(["original"]),
            outputs(["override", "plugin1", "original"]),
            id="fn_ovr=False, api_ovr=True, plugins=[Plugin1], plugin1=[api]",
        ),
        param(
            True,
            False,
            [
                plugin_factory("plugin1", override_functions=True),
                plugin_factory("plugin2", override_functions=True),
            ],
            outputs(["override", "plugin2", "plugin1", "original"]),
            outputs(["original"]),
            id="fn_ovr=True, api_ovr=False, plugins=[Plugin1, Plugin2], plugin1=[fn], plugin2=[fn]",
        ),
        param(
            False,
            True,
            [
                plugin_factory("plugin1", override_apis=True),
                plugin_factory("plugin2", override_apis=True),
            ],
            outputs(["original"]),
            outputs(["override", "plugin2", "plugin1", "original"]),
            id="fn_ovr=True, api_ovr=False, plugins=[Plugin1, Plugin2], plugin1=[api], plugin2=[api]",
        ),
        param(
            True,
            True,
            [
                plugin_factory("plugin1", override_functions=True, override_apis=True),
                plugin_factory("plugin2", override_functions=True, override_apis=True),
            ],
            outputs(["override", "plugin2", "plugin1", "original"]),
            outputs(["override", "plugin2", "plugin1", "original"]),
            id="fn_ovr=True, api_ovr=True, plugins=[Plugin1, Plugin2], plugin1=[fn,api], plugin2=[fn,api]",
        ),
    ],
)
def test_overrides(
    recipe_fn_override: bool,
    recipe_api_override: bool,
    plugins: List[SuperTokensPlugin],
    recipe_expectation: Any,
    api_expectation: Any,
):
    partial_init(
        recipe_list=[
            recipe_factory(
                override_functions=recipe_fn_override, override_apis=recipe_api_override
            ),
        ],
        experimental=SupertokensExperimentalConfig(
            plugins=plugins,
        ),
    )

    with recipe_expectation as expected_stack:
        output = PluginTestRecipe.get_instance().recipe_implementation.sign_in(
            "msg", []
        )
        assert output == RecipeReturnType(
            type="Recipe",
            function="sign_in",
            stack=expected_stack,
            message="msg",
        )

    with api_expectation as expected_stack:
        output = PluginTestRecipe.get_instance().api_implementation.sign_in_post(
            "msg", []
        )
        assert output == RecipeReturnType(
            type="API",
            function="sign_in_post",
            stack=expected_stack,
            message="msg",
        )


# TODO: Figure out a way to add circular dependencies and test them
@mark.parametrize(
    (
        "plugins",
        "recipe_expectation",
        "api_expectation",
        "config_expectation",
        "init_expectation",
    ),
    [
        param(
            [Plugin1, Plugin1],
            outputs(["plugin1", "original"]),
            outputs(["original"]),
            outputs(["original", "plugin1"]),
            outputs(["plugin1"]),
            id="1,1 => 1",
        ),
        param(
            [Plugin1, Plugin2],
            outputs(["plugin2", "plugin1", "original"]),
            outputs(["original"]),
            outputs(["original", "plugin1", "plugin2"]),
            outputs(["plugin1", "plugin2"]),
            id="1,2 => 2,1",
        ),
        param(
            [Plugin3Dep1],
            outputs(["plugin3dep1", "plugin1", "original"]),
            outputs(["original"]),
            outputs(["original", "plugin1", "plugin3dep1"]),
            outputs(["plugin1", "plugin3dep1"]),
            id="3->1 => 3,1",
        ),
        param(
            [Plugin3Dep2_1],
            outputs(["plugin3dep2_1", "plugin1", "plugin2", "original"]),
            outputs(["original"]),
            outputs(["original", "plugin2", "plugin1", "plugin3dep2_1"]),
            outputs(["plugin2", "plugin1", "plugin3dep2_1"]),
            id="3->(2,1) => 3,2,1",
        ),
        param(
            [Plugin3Dep1, Plugin4Dep2],
            outputs(["plugin4dep2", "plugin2", "plugin3dep1", "plugin1", "original"]),
            outputs(["original"]),
            outputs(["original", "plugin1", "plugin3dep1", "plugin2", "plugin4dep2"]),
            outputs(["plugin1", "plugin3dep1", "plugin2", "plugin4dep2"]),
            id="3->1,4->2 => 4,2,3,1",
        ),
        param(
            [Plugin4Dep3__2_1],
            outputs(
                ["plugin4dep3__2_1", "plugin3dep2_1", "plugin1", "plugin2", "original"]
            ),
            outputs(["original"]),
            outputs(
                ["original", "plugin2", "plugin1", "plugin3dep2_1", "plugin4dep3__2_1"]
            ),
            outputs(["plugin2", "plugin1", "plugin3dep2_1", "plugin4dep3__2_1"]),
            id="4->3->(2,1) => 4,3,1,2",
        ),
        param(
            [Plugin3Dep1, Plugin4Dep1],
            outputs(["plugin4dep1", "plugin3dep1", "plugin1", "original"]),
            outputs(["original"]),
            outputs(["original", "plugin1", "plugin3dep1", "plugin4dep1"]),
            outputs(["plugin1", "plugin3dep1", "plugin4dep1"]),
            id="3->1,4->1 => 4,3,1",
        ),
    ],
)
def test_depdendencies_and_init(
    plugins: List[SuperTokensPlugin],
    recipe_expectation: Any,
    api_expectation: Any,
    config_expectation: Any,
    init_expectation: Any,
):
    partial_init(
        recipe_list=[
            recipe_factory(),
        ],
        experimental=SupertokensExperimentalConfig(
            plugins=plugins,
        ),
    )

    with recipe_expectation as expected_stack:
        output = PluginTestRecipe.get_instance().recipe_implementation.sign_in(
            "msg", []
        )
        assert output == RecipeReturnType(
            type="Recipe",
            function="sign_in",
            stack=expected_stack,
            message="msg",
        )

    with api_expectation as expected_stack:
        output = PluginTestRecipe.get_instance().api_implementation.sign_in_post(
            "msg", []
        )
        assert output == RecipeReturnType(
            type="API",
            function="sign_in_post",
            stack=expected_stack,
            message="msg",
        )

    with config_expectation as expected_stack:
        output = PluginTestRecipe.get_instance().config.test_property
        assert output == expected_stack

    with init_expectation as expected_stack:
        assert PluginTestRecipe.init_calls == expected_stack


def test_st_config_override():
    plugin = plugin_factory("plugin1", override_functions=False, override_apis=False)

    def config_override(config: SupertokensPublicConfig) -> SupertokensPublicConfig:
        config.mode = "asgi"
        return config

    plugin.config = config_override

    partial_init(
        recipe_list=[
            recipe_factory(override_functions=False, override_apis=False),
        ],
        experimental=SupertokensExperimentalConfig(
            plugins=[plugin],
        ),
    )

    assert Supertokens.get_instance().app_info.mode == "asgi"


def test_st_config_override_non_public_property():
    plugin = plugin_factory("plugin1", override_functions=False, override_apis=False)

    def config_override(config: SupertokensPublicConfig) -> SupertokensPublicConfig:
        config.recipe_list = []  # type: ignore
        return config

    plugin.config = config_override

    with raises(
        ValueError, match='"SupertokensPublicConfig" object has no field "recipe_list"'
    ):
        partial_init(
            recipe_list=[
                recipe_factory(override_functions=False, override_apis=False),
            ],
            experimental=SupertokensExperimentalConfig(
                plugins=[plugin],
            ),
        )


# NOTE: Returning a string here to make it easier to write/test the handler
async def handler_fn(*_, **__: Dict[str, Any]) -> Any:
    return "plugin1"


plugin_route_handler = PluginRouteHandler(
    method="get",
    path="/auth/plugin1/hello",
    handler=handler_fn,  # type: ignore - returns string for simplicity
    verify_session_options=None,
)


async def test_route_handlers_list():
    plugin = plugin_factory("plugin1", override_functions=False, override_apis=False)

    plugin.route_handlers = [plugin_route_handler]

    partial_init(
        recipe_list=[
            recipe_factory(override_functions=False, override_apis=False),
        ],
        experimental=SupertokensExperimentalConfig(
            plugins=[plugin],
        ),
    )

    st_instance = Supertokens.get_instance()

    res = await st_instance.middleware(
        request=DummyRequest(),
        response=DummyResponse(content={}),
        user_context={},
    )

    assert res == "plugin1"


@mark.parametrize(
    ("handler_response", "expectation"),
    [
        param(
            PluginRouteHandlerFunctionOkResponse(route_handlers=[plugin_route_handler]),
            outputs("plugin1"),
            id="OK response with route handler",
        ),
        param(
            PluginRouteHandlerFunctionErrorResponse(
                message="error",
            ),
            raises(Exception, match="error"),
            id="Error response",
        ),
    ],
)
async def test_route_handlers_callable(handler_response: Any, expectation: Any):
    plugin = plugin_factory("plugin1", override_functions=False, override_apis=False)

    plugin.route_handlers = lambda *_, **__: handler_response  # type: ignore

    with expectation as expected_output:
        partial_init(
            recipe_list=[
                recipe_factory(override_functions=False, override_apis=False),
            ],
            experimental=SupertokensExperimentalConfig(
                plugins=[plugin],
            ),
        )

        st_instance = Supertokens.get_instance()

        res = await st_instance.middleware(
            request=DummyRequest(),
            response=DummyResponse(content={}),
            user_context={},
        )

        assert res == expected_output


@mark.parametrize(
    ("sdk_version", "compatible_versions", "expectation"),
    [
        param(
            "1.5.0",
            ">=1.0.0,<2.0.0",
            outputs(None),
            id="[Valid][1.5.0][>=1.0.0,<2.0.0] as string",
        ),
        param(
            "1.5.0",
            [">=1.0.0", "<2.0.0"],
            outputs(None),
            id="[Valid][1.5.0][>=1.0.0,<2.0.0] as list of strings",
        ),
        param(
            "2.0.0",
            [">=1.0.0,<2.0.0"],
            raises(Exception, match="Incompatible SDK version for plugin plugin1."),
            id="[Invalid][2.0.0][>=1.0.0,<2.0.0]",
        ),
    ],
)
def test_versions(
    sdk_version: str,
    compatible_versions: Union[str, List[str]],
    expectation: Any,
):
    plugin = plugin_factory(
        "plugin1",
        override_functions=False,
        override_apis=False,
        compatible_sdk_versions=compatible_versions,
    )

    with patch("supertokens_python.plugins.VERSION", sdk_version):
        with expectation as _:
            partial_init(
                recipe_list=[
                    recipe_factory(override_functions=False, override_apis=False),
                ],
                experimental=SupertokensExperimentalConfig(
                    plugins=[plugin],
                ),
            )
