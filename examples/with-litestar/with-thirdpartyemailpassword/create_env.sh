#!/bin/bash

pip install virtualenv
#Create a virtualenv
virtualenv litestar_example
# shellcheck disable=SC2164
source litestar_example/bin/activate

pip install -r requirements.txt
