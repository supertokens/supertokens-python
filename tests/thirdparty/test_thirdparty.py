from pytest import fixture, mark
from fastapi import FastAPI
from supertokens_python.framework.fastapi import get_middleware
from starlette.testclient import TestClient

from supertokens_python.recipe import session, thirdparty
from supertokens_python import init

from tests.utils import (
    setup_function,
    teardown_function,
    start_st,
    st_init_common_args,
)


_ = setup_function  # type:ignore
_ = teardown_function  # type:ignore
_ = start_st  # type:ignore


pytestmark = mark.asyncio


@fixture(scope="function")
async def fastapi_client():
    app = FastAPI()
    app.add_middleware(get_middleware())

    return TestClient(app)


async def test_thirdpary_parsing_works(fastapi_client: TestClient):
    st_init_args = {
        **st_init_common_args,
        "recipe_list": [
            session.init(),
            thirdparty.init(
                sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                    providers=[
                        thirdparty.Apple(
                            client_id="4398792-io.supertokens.example.service",
                            client_key_id="7M48Y4RYDL",
                            client_team_id="YWQCXGJRJL",
                            client_private_key="-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
                        )
                    ]
                )
            ),
        ],
    }
    init(**st_init_args)  # type: ignore
    start_st()

    data = {
        "state": "afc596274293e1587315c",
        "code": "c7685e261f98e4b3b94e34b3a69ff9cf4.0.rvxt.eE8rO__6hGoqaX1B7ODPmA",
    }

    res = fastapi_client.post("/auth/callback/apple", data=data)

    assert res.status_code == 200
    assert (
        res.content
        == b'<html><head><script>window.location.replace("http://supertokens.io/auth/callback/apple?state=afc596274293e1587315c&code=c7685e261f98e4b3b94e34b3a69ff9cf4.0.rvxt.eE8rO__6hGoqaX1B7ODPmA");</script></head></html>'
    )
