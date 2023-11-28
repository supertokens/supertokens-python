#!/bin/bash

pip install virtualenv
#Create a virtualenv
virtualenv fastapi_example
# shellcheck disable=SC2164
source fastapi_example/bin/activate

pip install -r requirements.txt

