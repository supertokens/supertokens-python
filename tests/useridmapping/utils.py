from supertokens_python import SupertokensConfig, InputAppInfo
from supertokens_python.recipe import emailpassword, session

st_config = {
    "supertokens_config": SupertokensConfig("http://localhost:3567"),
    "app_info": InputAppInfo(
        app_name="SuperTokens Demo",
        api_domain="https://api.supertokens.io",
        website_domain="supertokens.io",
    ),
    "framework": "fastapi",
    "recipe_list": [emailpassword.init(), session.init()],
}
