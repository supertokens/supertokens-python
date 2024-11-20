#!/bin/bash

export NODE_VERSION=$1

curl -fsSL https://deb.nodesource.com/setup_$NODE_VERSION.x | bash -
apt-get install -y nodejs
