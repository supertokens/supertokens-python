"""
ASGI config for django3x project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")

if True:
    # to help middleware function with uvicorn (to ensure supertokens init is called)
    from polls.views import config

    core_host = os.environ.get("SUPERTOKENS_CORE_HOST", "localhost")
    core_port = os.environ.get("SUPERTOKENS_CORE_PORT", "3571")

    config(
        core_url=f"http://{core_host}:{core_port}",
        enable_anti_csrf=True,
        enable_jwt=False,
        jwt_property_name=None,
    )

application = get_asgi_application()
