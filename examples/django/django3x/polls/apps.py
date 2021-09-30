from django.apps import AppConfig
from supertokens_python import init
from supertokens_python.recipe import session


class PollsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'polls'

    verbose_name = "My Application"

    def ready(self):
        init({
            'supertokens': {
                'connection_uri': "http://localhost:3567",
            },
            'framework': 'django',
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
