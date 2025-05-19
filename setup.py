from os import path

from setuptools import find_packages, setup

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), mode="r", encoding="utf-8") as f:
    long_description = f.read()

extras_require = {
    # we want to fix the versions of the libraries that
    # we use to develop the SDK with otherwise we get
    # a bunch of type errors on make dev-install depending
    # on changes in these frameworks
    "fastapi": (
        [
            "fastapi",
            "uvicorn",
            "python-dotenv==1.0.1",
        ]
    ),
    "flask": (
        [
            "flask-cors",
            "flask",
            "python-dotenv==1.0.1",
        ]
    ),
    "django": (
        [
            "django-cors-headers",
            "django>=3",
            "django-stubs",
            "uvicorn",
            "python-dotenv==1.0.1",
        ]
    ),
    "django2x": (
        [
            "django-cors-headers==3.11.0",
            "django>=2,<3",
            "django-stubs==1.9.0",
            "gunicorn",
            "python-dotenv==1.0.1",
        ]
    ),
    "drf": (
        [
            "adrf",
            "django-cors-headers",
            "django>=4",
            "django-stubs",
            "djangorestframework",
            "gunicorn",
            "uvicorn",
            "python-dotenv==1.0.1",
            "tzdata",
        ]
    ),
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
    ".pylintrc",
    "dev-requirements.txt",
    "docs-templates",
]

setup(
    name="supertokens_python",
    version="0.28.2",
    author="SuperTokens",
    license="Apache 2.0",
    author_email="team@supertokens.com",
    description="SuperTokens SDK for Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/supertokens/supertokens-python",
    packages=find_packages(exclude=exclude_list),
    package_data={
        "supertokens_python": [
            "py.typed",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Intended Audience :: Developers",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="",
    install_requires=[
        # [crypto] ensures that it installs the `cryptography` library as well
        # based on constraints specified in https://github.com/jpadilla/pyjwt/blob/master/setup.cfg#L50
        "PyJWT[crypto]>=2.5.0,<3.0.0",
        "httpx>=0.15.0,<1.0.0",
        "pycryptodome<3.21.0",
        "tldextract<5.1.3",
        "asgiref>=3.4.1,<4",
        "typing_extensions>=4.1.1,<5.0.0",
        "Deprecated<1.3.0",
        "phonenumbers<9",
        "twilio<10",
        "aiosmtplib>=1.1.6,<4.0.0",
        "pkce<1.1.0",
        "pyotp<3",
        "python-dateutil<3",
    ],
    python_requires=">=3.8",
    include_package_data=True,
    extras_require=extras_require,
)
