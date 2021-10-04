#!/bin/bash

pip install virtualenv

#Create a virtualenv
virtualenv django2x_example
# shellcheck disable=SC2164
source django2x_example/bin/activate

touch requirements.txt
echo "django==2.2.23" >> requirements.txt
pip install -r requirements.txt
pip install ../../package/supertokens_python-2.0.0-py2.py3-none-any.whl

