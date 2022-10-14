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
            "respx==0.19.2",
            "Fastapi",
            "uvicorn==0.18.2",
            "python-dotenv==0.19.2",
        ]
    ),
    "flask": (
        [
            "flask_cors",
            "Flask",
            "python-dotenv==0.19.2",
        ]
    ),
    "django": (
        [
            "django-cors-headers==3.11.0",
            "django>=3",
            "django-stubs==1.9.0",
            "uvicorn==0.18.2",
            "python-dotenv==0.19.2",
        ]
    ),
    "django2x": (
        [
            "django-cors-headers==3.11.0",
            "django>=2,<3",
            "django-stubs==1.9.0",
            "gunicorn==20.1.0",
            "python-dotenv==0.19.2",
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
    version="0.11.2",
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
        "PyJWT>=2.0.0 ,<2.4.0",
        "httpx>=0.15.0 ,<0.24.0",
        "pycryptodome==3.10.*",
        "jsonschema==3.2.0",
        "tldextract==3.1.0",
        "asgiref>=3.4.1,<4",
        "typing_extensions==4.1.1",
        "Deprecated==1.2.13",
        "cryptography>=35.0,<37.0",
        "phonenumbers==8.12.48",
        # flask depends on this and flask has > '2.0' for this. However, the version before 2.1.0 breaks our lib.
        "Werkzeug>=2.0 ,<2.1.0",
        "twilio==7.9.1",
        "aiosmtplib==1.1.6",
    ],
    python_requires=">=3.7",
    include_package_data=True,
    extras_require=extras_require,
)
