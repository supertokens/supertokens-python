from supertokens_python.framework.django.framework import DjangoFramework
from supertokens_python.framework.fastapi.framework import FastapiFramework
from supertokens_python.framework.flask.framework import FlaskFramework

FRAMEWORKS={
    'Fastapi' : FastapiFramework(),
    'Flask' : FlaskFramework(),
    'Django' : DjangoFramework(),
}