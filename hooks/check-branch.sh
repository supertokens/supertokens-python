#!/bin/bash

source ./hooks/populate-hook-constants.sh

isMasterBranch=$( if [ "$currentBranch" = "master" ]; then echo true; else echo false; fi )
isVersionBranch=$( if [[ ${currentBranch} =~ ^[0-9]+.[0-9]+$ ]]; then echo true; else echo false; fi )

if "$isMasterBranch"
then
    echo "Committing to master, unexpected."
    exit 1
fi

# Check that the code version matches the branch version if on a versioned branch
# `%.*` strips out the suffix after (and including) the last `.`
if "$isVersionBranch" && [[ "${currentBranch%.*}" != "${newestVersion%.*}" ]]
then
    echo "Code version (${newestVersion%.*}) does not match branch (${currentBranch%.*}), unexpected."
    exit 1
fi
