"""
FastAPI app with SAML + Multitenancy.

Prerequisites:
  - SuperTokens Core running locally on http://localhost:3567
  - Run setup_tenant.py first to create the tenant and SAML client
  - pip install supertokens-python uvicorn fastapi

Usage:
  python main.py
"""

import uvicorn  # type: ignore
from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from supertokens_python import (
    InputAppInfo,
    SupertokensConfig,
    get_all_cors_headers,
    init,
)
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import multitenancy, saml, session, thirdparty
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.fastapi import verify_session

CORE_URL = "http://localhost:3567"
API_DOMAIN = "http://localhost:3001"
WEBSITE_DOMAIN = "http://localhost:3000"

init(
    debug=True,
    supertokens_config=SupertokensConfig(connection_uri=CORE_URL),
    app_info=InputAppInfo(
        app_name="SAML Multitenancy Example",
        api_domain=API_DOMAIN,
        website_domain=WEBSITE_DOMAIN,
    ),
    framework="fastapi",
    mode="asgi",
    recipe_list=[
        session.init(),
        multitenancy.init(),
        saml.init(),
        thirdparty.init(),
    ],
)

app = FastAPI()
app.add_middleware(get_middleware())
app.add_middleware(
    CORSMiddleware,
    allow_origins=[WEBSITE_DOMAIN],
    allow_credentials=True,
    allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type"] + get_all_cors_headers(),
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/sessioninfo")
async def get_session_info(session_: SessionContainer = Depends(verify_session())):
    return JSONResponse(
        {
            "sessionHandle": session_.get_handle(),
            "userId": session_.get_user_id(),
            "accessTokenPayload": session_.get_access_token_payload(),
        }
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3001)
