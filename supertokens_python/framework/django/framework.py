from supertokens_python.framework.django.django_request import DjangoRequest
from supertokens_python.framework.django.django_response import DjangoResponse
from supertokens_python.framework.types import Framework


class DjangoFramework(Framework):
    def wrap_request(self, unwrapped):
        return DjangoRequest(unwrapped)

    def wrap_response(self, unwrapped):
        return DjangoResponse(unwrapped)
