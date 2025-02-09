#!/bin/bash

source ./hooks/populate-hook-constants.sh

# Versions come from ./populate-hook-constants.sh
if [[ ${constantsVersion} != ${setupVersion} ]]
then
    printf "Version mismatch ./supertokens_python/constants.py=$constantsVersion, setup.py=$setupVersion"
    exit 1
fi
