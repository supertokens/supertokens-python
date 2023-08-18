import respx
import json

from pytest import fixture, mark
from fastapi import FastAPI
from supertokens_python.framework.fastapi import get_middleware
from starlette.testclient import TestClient

from supertokens_python.recipe import session, thirdparty
from supertokens_python import init
from base64 import b64encode

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

respx_mock = respx.MockRouter


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
                        thirdparty.ProviderInput(
                            config=thirdparty.ProviderConfig(
                                third_party_id="apple",
                                clients=[
                                    thirdparty.ProviderClientConfig(
                                        client_id="4398792-io.supertokens.example.service",
                                        additional_config={
                                            "keyId": "7M48Y4RYDL",
                                            "teamId": "YWQCXGJRJL",
                                            "privateKey": "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
                                        },
                                    ),
                                ],
                            )
                        ),
                    ]
                )
            ),
        ],
    }
    init(**st_init_args)  # type: ignore
    start_st()

    state = b64encode(
        json.dumps({"frontendRedirectURI": "http://localhost:3000/redirect"}).encode()
    ).decode()
    code = "testing"

    data = {"state": state, "code": code}
    res = fastapi_client.post("/auth/callback/apple", data=data)

    assert res.status_code == 303
    assert res.content == b""
    assert (
        res.headers["location"]
        == f"http://localhost:3000/redirect?state={state.replace('=', '%3D')}&code={code}"
    )
