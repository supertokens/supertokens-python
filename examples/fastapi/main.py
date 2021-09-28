from fastapi import FastAPI, Depends
from starlette.requests import Request
from supertokens_python import session, init
from supertokens_python.framework.fastapi import Middleware
from supertokens_python.session import create_new_session, refresh_session, Session
from supertokens_python.session.framework.fastapi import verify_session

app = FastAPI()

init({
    'supertokens': {
        'connection_uri': "http://localhost:3567",
    },
    'framework': 'fastapi',
    'app_info': {
        'app_name': "SuperTokens Demo",
        'api_domain': "http://127.0.0.1:8000",
        'website_domain': "http://127.0.0.1:8000",
        'api_base_path': "/auth"
    },
    'recipe_list': [session.init(
        {
            'anti_csrf': 'VIA_TOKEN',
            'cookie_domain': '127.0.0.1:8000'
        }
    )],
})

app.add_middleware(Middleware)


@app.get("/create")
async def create(request: Request):
    user_id ='user_id'
    session = await create_new_session(request, user_id, {}, {})
    return {"message": session.get_access_token()}

@app.get("/user")
async def user(session: Session = Depends(verify_session())):
    return {'user_id' : session.get_user_id()}

@app.post("/refresh")
async def refresh(request: Request):
    await refresh_session(request)

