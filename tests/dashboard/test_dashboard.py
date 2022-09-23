from pytest import mark
from tests.utils import start_st, setup_function, teardown_function, get_st_init_args

from supertokens_python import init
from supertokens_python.recipe import session  # , dashboard

_ = setup_function  # type: ignore
_ = teardown_function  # type: ignore

pytestmark = mark.asyncio


async def test_dashboard_recipe():
    st_args = get_st_init_args(
        [
            session.init(),  # dashboard.init()
        ]
    )
    init(**st_args)
    start_st()
    # TODO:
    print("Verify that the dashboard recipe works!")
