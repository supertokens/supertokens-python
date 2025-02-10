#!/bin/bash

source ./hooks/populate-hook-constants.sh

isVersionBranch=$( if [[ ${targetBranch} =~ ^[0-9]+.[0-9]+$ ]]; then echo true; else echo false; fi )

# Check that the code version matches the branch version if on a versioned branch
# `%.*` strips out the suffix after (and including) the last `.`
if "$isVersionBranch" && [[ "${targetBranch%.*}" != "${newestVersion%.*}" ]]
then
    echo "Code version (${newestVersion%.*}) does not match branch (${targetBranch%.*}), unexpected."
    exit 1
fi
