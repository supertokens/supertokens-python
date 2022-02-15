from django.http import HttpRequest
from supertokens_python.framework.django.django_request import DjangoRequest as DjangoRequest
from supertokens_python.framework.types import Framework as Framework

class DjangoFramework(Framework):
    def wrap_request(self, unwrapped: HttpRequest): ...
