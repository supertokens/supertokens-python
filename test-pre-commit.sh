#!/bin/bash

python3 -m venv venv
source venv/bin/activate
pip3 install "cython<3.0.0" wheel
pip3 install "PyYAML==5.4.1" --no-build-isolation
make dev-install && rm -rf src
