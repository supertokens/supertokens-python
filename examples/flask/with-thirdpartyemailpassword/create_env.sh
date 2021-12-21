#!/bin/bash

pip install virtualenv
#Create a virtualenv
virtualenv flask_example
# shellcheck disable=SC2164
source flask_example/bin/activate

pip install -r requirements.txt

