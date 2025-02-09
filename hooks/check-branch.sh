#!/bin/bash

source ./hooks/populate-hook-constants.sh

isVersionBranch=$( if [[ ${currentBranch} =~ ^[0-9]+.[0-9]+$ ]]; then echo true; else echo false; fi )

# Check that the code version matches the branch version if on a versioned branch
# `%.*` strips out the suffix after (and including) the last `.`
if "$isVersionBranch" && [[ "${currentBranch%.*}" != "${newestVersion%.*}" ]]
then
    echo "Code version (${newestVersion%.*}) does not match branch (${currentBranch%.*}), unexpected."
    exit 1
fi
