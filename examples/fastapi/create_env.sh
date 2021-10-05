#!/bin/bash

pip install virtualenv
#Create a virtualenv
virtualenv fastapi_example
# shellcheck disable=SC2164
source fastapi_example/bin/activate

touch requirements.txt
echo "fastapi==0.68.1" >> requirements.txt
pip install -r requirements.txt
pip install ../package/supertokens_python-2.0.0-py2.py3-none-any.whl

