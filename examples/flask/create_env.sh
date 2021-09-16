#!/bin/bash

pip install virtualenv

#Create a virtualenv
virtualenv flask_example
# shellcheck disable=SC2164
source flask_example/bin/activate

touch requirements.txt
echo "flask==2.0.1" >> requirements.txt
echo "flask_cors==3.0.10" >> requirements.txt
pip install -r requirements.txt
pip install ../package/supertokens_python-2.0.0-py2.py3-none-any.whl

