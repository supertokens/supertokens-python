#!/bin/bash
constantsVersion=$(sed -n 's/^ *VERSION *= *["]\([0-9\.]*\).*/\1/p' supertokens_python/constants.py)
setupVersion=$(sed -n 's/ *version *= *["]\([0-9\.]*\).*/\1/p' setup.py )

echo $constantsVersion
echo $setupVersion

if [[ ${constantsVersion} != ${setupVersion} ]]
then
    printf "Version mismatch ./supertokens_python/constants.py=$constantsVersion, setup.py=$setupVersion"
    exit 1
fi
