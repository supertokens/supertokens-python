from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), mode="r", encoding="utf-8") as f:
    long_description = f.read()

extras_require = {
    'dev': ([
        'pytest==6.2.3',
        'flake8==3.9.0',
        'autopep8==1.5.6',
        'PyYAML==5.4.1',
        'uvicorn==0.13.4',
        'requests==2.25.1',
        'pytest-asyncio==0.14.0',
        'respx==0.16.3',
        'nest-asyncio==1.5.1',
        'Fastapi==0.68.1',
        'django',
        'Flask==2.0.1',
        'python-dotenv',
        'flask_cors',
        'django-cors-headers',
        'pdoc3',
        'tzdata'
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
    "html"
]

setup(
    name="supertokens_python",
    version="0.3.0",
    author="SuperTokens",
    license="Apache 2.0",
    author_email="team@supertokens.io",
    description="SuperTokens session management solution for Fastapi",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/supertokens/supertokens-fastapi",
    packages=find_packages(exclude=exclude_list),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
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
        "werkzeug==2.0.1",
        'starlette~=0.14.2',
        'typing_extensions==3.10',
        'Deprecated==1.2.13',
        'cryptography==35.0'
    ],
    python_requires='>=3.7',
    extras_require=extras_require
)
