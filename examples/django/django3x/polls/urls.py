import asyncio

from django.urls import path

from supertokens_python import init
from supertokens_python.recipe import session
from . import views

# just for testing

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)


async def __init():
    init({
        'supertokens': {
            'connection_uri': "http://localhost:3567",
        },
        'framework': 'django3',
        'app_info': {
            'app_name': "SuperTokens Demo",
            'api_domain': "api.supertokens.io",
            'website_domain': "supertokens.io",
            'api_base_path': "/auth"
        },
        'recipe_list': [session.init(
            {
                'anti_csrf': 'VIA_TOKEN',
                'cookie_domain': 'supertokens.io'
            }
        )],
    })
f = __init()
loop.run_until_complete(f)

loop.close()

urlpatterns = [
    path('create', views.create, name='index'),
    path('user', views.user, name='index'),
]
