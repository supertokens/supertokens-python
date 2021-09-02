"""
Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

import sys

sys.path.append('../..')  # noqa: E402
from supertokens_python import init, get_all_cors_headers, session, thirdpartyemailpassword
from supertokens_python.session import Session
# from supertokens_python.thirdparty import Github, Google, Facebook
from fastapi import FastAPI, Depends
from starlette.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from starlette.exceptions import ExceptionMiddleware

index_file = open("./templates/index.html", "r")
file_contents = index_file.read()
index_file.close()

app = FastAPI(debug=False)

init(app, {
    'supertokens': {
        'connection_uri': "https://try.supertokens.io",
    },
    'app_info': {
        'app_name': "SuperTokens Demo",
        'api_domain': "http://localhost:9000",
        'website_domain': "http://localhost:8888",
        'api_base_path': "/auth"
    },
    'recipe_list': [thirdpartyemailpassword.init(), session.init()],
    'telemetry': False
})

app.add_middleware(ExceptionMiddleware, handlers=app.exception_handlers)


@app.get('/index.html')
def send_file():
    return HTMLResponse(content=file_contents)


@app.get('/sessioninfo')
async def get_user(user_session: Session = Depends(session.verify_session())):
    return JSONResponse(content={
        'userId': user_session.get_user_id(),
        'sessionHandle': user_session.get_handle(),
        'jwtPayload': user_session.get_jwt_payload(),
        'sessionData': await user_session.get_session_data()
    })


@app.exception_handler(405)
def f_405(_, e):
    return PlainTextResponse('', status_code=404)


@app.exception_handler(Exception)
def f_500(_, e):
    print(str(e))
    return JSONResponse(status_code=500, content={
        'e': e
    })


# cors middleware added like this due to issue with add_middleware
# ref: https://github.com/tiangolo/fastapi/issues/1663


app = CORSMiddleware(
    app=app,
    allow_origins=[
        "http://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type"] + get_all_cors_headers(),
)
