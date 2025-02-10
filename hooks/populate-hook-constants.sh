#!/bin/bash

# Look for the version string with additional handling for:
# - Abitrary Spaces: ` *`
# - Extracting the version into a match group: `(...)`
# - Substituting the matched string with the match group: `/\1/`
constantsVersion=$(sed -n 's/^ *VERSION *= *["]\([0-9\.]*\).*/\1/p' supertokens_python/constants.py)
setupVersion=$(sed -n 's/ *version *= *["]\([0-9\.]*\).*/\1/p' setup.py )

newestVersion=$( if [[ "$constantsVersion" > "$setupVersion" ]]; then echo "$constantsVersion"; else echo "$setupVersion"; fi )

# Target branch of the PR.
# Ideally, this is all we want to check.
if [[ "$GITHUB_BASE_REF" != "" ]]
then
    targetBranch="$GITHUB_BASE_REF"
else # Fallback to current branch if not in a PR
    targetBranch=$(git branch --show-current 2> /dev/null) || targetBranch="(unnamed branch)" # Get current branch
fi
targetBranch=${targetBranch##refs/heads/}  # Remove refs/heads/ if present
