from django.http import JsonResponse
from django.test import TestCase, RequestFactory

from supertokens_python.framework.django.django_middleware import middleware
from supertokens_python import session, init
from supertokens_python.session import create_new_session, refresh_session, get_session
from tests.utils import start_st, reset, clean_st, setup_st, TEST_DRIVER_CONFIG_COOKIE_DOMAIN, \
    TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH, TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH, TEST_DRIVER_CONFIG_COOKIE_SAME_SITE


def get_cookies(response) -> dict:
    cookies = dict()
    for key, morsel in response.cookies.items():
        cookies[key] = {
            'value': morsel.value,
            'name': key
        }
        for k, v in morsel.items():
            if (k == 'secure' or k == 'httponly') and v == '':
                cookies[key][k] = None
            elif k == 'samesite':
                if len(v) > 0 and v[-1] == ',':
                    v = v[:-1]
                cookies[key][k] = v
            else:
                cookies[key][k] = v
    return cookies


async def create_new_session_view(request):
    await create_new_session(request, 'user_id')
    return JsonResponse({'foo': 'bar'})


async def refresh_view(request):
    await refresh_session(request)
    return JsonResponse({'foo': 'bar'})


async def logout_view(request):
    session = await get_session(request, True)
    await session.revoke_session()
    return JsonResponse({'foo': 'bar'})


async def handle_view(request):
    session = await get_session(request, True)
    return JsonResponse({'s': session.get_handle()})



class SupertokensTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        reset()
        clean_st()
        setup_st()

    def tearDown(self):
        reset()
        clean_st()

    async def test_login_refresh(self):
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

        my_middleware = middleware(refresh_view)
        request = self.factory.get('/refresh', {'user_id': 'user_id'})
        cookies = get_cookies(response)

        assert len(cookies['sAccessToken']['value']) > 0
        assert len(cookies['sIdRefreshToken']['value']) > 0
        assert len(cookies['sRefreshToken']['value']) > 0

        request.COOKIES["sRefreshToken"] = cookies['sRefreshToken']['value']
        request.COOKIES["sIdRefreshToken"] = cookies['sIdRefreshToken']['value']
        request.META['HTTP_ANTI_CSRF'] = response.headers['anti-csrf']
        response = await my_middleware(request)
        print(response)
        refreshed_cookies = get_cookies(response)

        assert refreshed_cookies['sAccessToken']['value'] != cookies['sAccessToken']['value']
        assert refreshed_cookies['sIdRefreshToken']['value'] != cookies['sIdRefreshToken']['value']
        assert refreshed_cookies['sRefreshToken']['value'] != cookies['sRefreshToken']['value']
        assert response.headers['anti-csrf'] is not None
        assert refreshed_cookies['sAccessToken']['domain'] == cookies['sAccessToken']['domain']
        assert refreshed_cookies['sIdRefreshToken']['domain'] == cookies['sIdRefreshToken']['domain']
        assert refreshed_cookies['sRefreshToken']['domain'] == cookies['sRefreshToken']['domain']
        assert refreshed_cookies['sAccessToken']['secure'] == cookies['sAccessToken']['secure']
        assert refreshed_cookies['sIdRefreshToken']['secure'] == cookies['sIdRefreshToken']['secure']
        assert refreshed_cookies['sRefreshToken']['secure'] == cookies['sRefreshToken']['secure']


    async def test_login_logout(self):
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
        cookies = get_cookies(response)

        assert len(cookies['sAccessToken']['value']) > 0
        assert len(cookies['sIdRefreshToken']['value']) > 0
        assert len(cookies['sRefreshToken']['value']) > 0

        my_middleware = middleware(logout_view)
        request = self.factory.post('/logout', {'user_id': 'user_id'})

        request.COOKIES["sAccessToken"] = cookies['sAccessToken']['value']
        request.COOKIES["sIdRefreshToken"] = cookies['sIdRefreshToken']['value']
        request.META['HTTP_ANTI_CSRF'] = response.headers['anti-csrf']
        response = await my_middleware(request)
        logout_cookies = get_cookies(response)
        assert logout_cookies == {}

    async def test_login_handle(self):
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
        cookies = get_cookies(response)

        assert len(cookies['sAccessToken']['value']) > 0
        assert len(cookies['sIdRefreshToken']['value']) > 0
        assert len(cookies['sRefreshToken']['value']) > 0

        my_middleware = middleware(handle_view)
        request = self.factory.get('/handle', {'user_id': 'user_id'})

        request.COOKIES["sAccessToken"] = cookies['sAccessToken']['value']
        request.COOKIES["sIdRefreshToken"] = cookies['sIdRefreshToken']['value']
        request.META['HTTP_ANTI_CSRF'] = response.headers['anti-csrf']
        response = await my_middleware(request)
        handle_cookies = get_cookies(response)
        assert handle_cookies == {}



