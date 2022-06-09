#!/bin/bash

pip install virtualenv
#Create a virtualenv
virtualenv django_example
# shellcheck disable=SC2164
source django_example/bin/activate

pip install -r requirements.txt
