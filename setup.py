from os import path

from setuptools import find_packages, setup

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), mode="r", encoding="utf-8") as f:
    long_description = f.read()

extras_require = {
    'dev': ([
        'pytest==6.2.5',
        'autopep8==1.5.6',
        'PyYAML==5.4.1',
        'uvicorn==0.13.4',
        'requests==2.25.1',
        'pytest-asyncio==0.14.0',
        'nest-asyncio==1.5.1',
        'python-dotenv==0.19.2',
        'pdoc3==0.10.0',
        'tzdata==2021.5',
        'pylint==2.12.2',
        'isort==5.10.1',
        'pyright==0.0.13',
    ]),
    'fastapi': ([
        'respx==0.16.3',
        'Fastapi'
    ]),
    'flask': ([
        'flask_cors',
        'Flask'
    ]),
    'django': ([
        'django-cors-headers==3.11.0',
        'django',
        'django-stubs==1.9.0'
    ]),
    # the unit tests use fastapi testClient,
    # and it only works with this version of starlette
    'unittests': ([
        'starlette==0.14.2'
    ]),
    # we want to fix the versions of the framework that
    # we use to develop the SDK with otherwise we get
    # a bunch of type errors on make dev-install depending
    # on changes in these frameworks
    'development': ([
        'Flask==2.0.2',
        'django==3.2.12',
        'Fastapi==0.68.1'
    ])
}

exclude_list = [
    "tests",
    "examples",
    "hooks",
    ".gitignore",
    ".git",
    "addDevTag",
    "addReleaseTag",
    "frontendDriverInterfaceSupported.json",
    "coreDriverInterfaceSupported.json",
    ".github",
    ".circleci",
    "html",
    "pyrightconfig.json",
    "Makefile",
    ".pylintrc"
]

setup(
    name="supertokens_python",
    version="0.6.0",
    author="SuperTokens",
    license="Apache 2.0",
    author_email="team@supertokens.com",
    description="SuperTokens SDK for Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/supertokens/supertokens-python",
    packages=find_packages(exclude=exclude_list),
    package_data = {'supertokens_python': ['py.typed']},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Intended Audience :: Developers",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="",
    install_requires=[
        "PyJWT==2.0.*",
        "httpx==0.15.*",
        "pycryptodome==3.10.*",
        'jsonschema==3.2.0',
        "tldextract==3.1.0",
        "asgiref==3.4.1",
        'typing_extensions==4.1.1',
        'Deprecated==1.2.13',
        'cryptography==35.0',
        'phonenumbers==8.12'
    ],
    python_requires='>=3.7',
    include_package_data=True,
    extras_require=extras_require
)

