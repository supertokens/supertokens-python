import respx
import httpx

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


async def test_apple_provider_can_fetch_keys():
    from supertokens_python.recipe.thirdparty.providers.apple import Apple
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    def api_side_effect(_: httpx.Request):
        return httpx.Response(
            200,
            json={
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "W6WcOKB",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "2Zc5d0-zkZ5AKmtYTvxHc3vRc41YfbklflxG9SWsg5qXUxvfgpktGAcxXLFAd9Uglzow9ezvmTGce5d3DhAYKwHAEPT9hbaMDj7DfmEwuNO8UahfnBkBXsCoUaL3QITF5_DAPsZroTqs7tkQQZ7qPkQXCSu2aosgOJmaoKQgwcOdjD0D49ne2B_dkxBcNCcJT9pTSWJ8NfGycjWAQsvC8CGstH8oKwhC5raDcc2IGXMOQC7Qr75d6J5Q24CePHj_JD7zjbwYy9KNH8wyr829eO_G4OEUW50FAN6HKtvjhJIguMl_1BLZ93z2KJyxExiNTZBUBQbbgCNBfzTv7JrxMw",
                        "e": "AQAB",
                    },
                    {
                        "kty": "RSA",
                        "kid": "fh6Bs8C",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "u704gotMSZc6CSSVNCZ1d0S9dZKwO2BVzfdTKYz8wSNm7R_KIufOQf3ru7Pph1FjW6gQ8zgvhnv4IebkGWsZJlodduTC7c0sRb5PZpEyM6PtO8FPHowaracJJsK1f6_rSLstLdWbSDXeSq7vBvDu3Q31RaoV_0YlEzQwPsbCvD45oVy5Vo5oBePUm4cqi6T3cZ-10gr9QJCVwvx7KiQsttp0kUkHM94PlxbG_HAWlEZjvAlxfEDc-_xZQwC6fVjfazs3j1b2DZWsGmBRdx1snO75nM7hpyRRQB4jVejW9TuZDtPtsNadXTr9I5NjxPdIYMORj9XKEh44Z73yfv0gtw",
                        "e": "AQAB",
                    },
                    {
                        "kty": "RSA",
                        "kid": "YuyXoY",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "1JiU4l3YCeT4o0gVmxGTEK1IXR-Ghdg5Bzka12tzmtdCxU00ChH66aV-4HRBjF1t95IsaeHeDFRgmF0lJbTDTqa6_VZo2hc0zTiUAsGLacN6slePvDcR1IMucQGtPP5tGhIbU-HKabsKOFdD4VQ5PCXifjpN9R-1qOR571BxCAl4u1kUUIePAAJcBcqGRFSI_I1j_jbN3gflK_8ZNmgnPrXA0kZXzj1I7ZHgekGbZoxmDrzYm2zmja1MsE5A_JX7itBYnlR41LOtvLRCNtw7K3EFlbfB6hkPL-Swk5XNGbWZdTROmaTNzJhV-lWT0gGm6V1qWAK2qOZoIDa_3Ud0Gw",
                        "e": "AQAB",
                    },
                ]
            },
        )

    with respx_mock(assert_all_mocked=False) as mocker:
        mocked_route = mocker.get("https://appleid.apple.com/auth/keys").mock(
            side_effect=api_side_effect
        )

        apple = Apple(
            "client-id", "client-key-id", "client-private-key", "client-team-id"
        )
        # pylint: disable=protected-access
        keys = await apple._fetch_apple_public_keys()  # type: ignore

        assert mocked_route.call_count == 1
        assert len(keys) == 3
        assert isinstance(keys[0], RSAPublicKey)
