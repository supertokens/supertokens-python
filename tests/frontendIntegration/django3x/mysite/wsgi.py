"""
WSGI config for mysite project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")

if True:
    # to help middleware function with uvicorn (to ensure supertokens init is called)
    from polls.views import config

    core_host = os.environ.get("SUPERTOKENS_CORE_HOST", "localhost")
    core_port = os.environ.get("SUPERTOKENS_CORE_PORT", "3567")

    config(
        core_url=f"http://{core_host}:{core_port}",
        enable_anti_csrf=True,
        enable_jwt=False,
        jwt_property_name=None,
    )

application = get_wsgi_application()
