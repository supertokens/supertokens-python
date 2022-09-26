from typing import Any, Dict

from pytest import mark

from supertokens_python.framework import BaseRequest
from supertokens_python.recipe.dashboard import InputOverrideConfig
from supertokens_python.recipe.dashboard.interfaces import (
    RecipeInterface as DashboardRI,
    APIInterface,
    APIOptions,
)
from supertokens_python.recipe.dashboard.utils import DashboardConfig
from tests.utils import start_st, setup_function, teardown_function, get_st_init_args

from supertokens_python import init
from supertokens_python.recipe import session, dashboard

_ = setup_function  # type: ignore
_ = teardown_function  # type: ignore

pytestmark = mark.asyncio


async def test_dashboard_recipe():
    def override_dashboard_functions(oi: DashboardRI) -> DashboardRI:
        async def get_dashboard_bundle_location(_user_context: Dict[str, Any]) -> str:
            return ""

        async def should_allow_access(
            _request: BaseRequest,
            _config: DashboardConfig,
            _user_context: Dict[str, Any],
        ) -> bool:
            return False

        oi.get_dashboard_bundle_location = get_dashboard_bundle_location
        oi.should_allow_access = should_allow_access
        return oi

    def override_dashboard_apis(oi: APIInterface) -> APIInterface:
        async def dashboard_get(_: APIOptions, __: Dict[str, Any]) -> str:
            return ""

        oi.dashboard_get = dashboard_get
        return oi

    st_args = get_st_init_args(
        [
            session.init(),
            dashboard.init(
                api_key="",
                override=InputOverrideConfig(
                    functions=override_dashboard_functions,
                    apis=override_dashboard_apis,
                ),
            ),
        ]
    )
    init(**st_args)
    start_st()
    print("Verify that the dashboard recipe works!")
