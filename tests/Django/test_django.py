from django.http import JsonResponse
from django.test import TestCase, RequestFactory


from supertokens_python.framework.django.django_middleware import middleware
from supertokens_python import session, init
from supertokens_python.session import create_new_session
from tests.utils import start_st, reset, clean_st, setup_st, TEST_DRIVER_CONFIG_COOKIE_DOMAIN, \
    TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH, TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH, TEST_DRIVER_CONFIG_COOKIE_SAME_SITE


async def create_new_session_view(request):
    await create_new_session(request, 'user_id')
    return JsonResponse({'foo': 'bar'})


class SupertokensTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        reset()
        clean_st()
        setup_st()

    def tearDown(self):
        reset()
        clean_st()

    async def test_create_get_refresh_session_with_token_theft_ACT_enabled_and_cookie_path(self):
        init({
            'supertokens': {
                'connection_uri': "http://localhost:3567",
            },
            'framework': 'Django',
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

        start_st()

        my_middleware = middleware(create_new_session_view)
        request = self.factory.get('/login', {'user_id': 'user_id'})
        response = await my_middleware(request)
        assert response.headers.get('anti-csrf') is not None
        assert response.cookies.get('sAccessToken')['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
        assert response.cookies.get('sRefreshToken')['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
        assert response.cookies.get('sIdRefreshToken')['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
        assert response.cookies.get('sAccessToken')['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
        assert response.cookies.get('sRefreshToken')['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
        assert response.cookies.get('sIdRefreshToken')['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
        assert response.cookies.get('sAccessToken')['httponly']
        assert response.cookies.get('sRefreshToken')['httponly']
        assert response.cookies.get('sIdRefreshToken')['httponly']
        assert response.cookies.get('sAccessToken')['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
        assert response.cookies.get('sRefreshToken')['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
        assert response.cookies.get('sIdRefreshToken')['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
        assert response.cookies.get('sAccessToken')['secure'] is None or response.cookies.get('sAccessToken')['secure'] == ''
        assert response.cookies.get('sRefreshToken')['secure'] is None or response.cookies.get('sRefreshToken')['secure'] == ''
        assert response.cookies.get('sIdRefreshToken')['secure'] is None or response.cookies.get('sIdRefreshToken')['secure'] == ''
